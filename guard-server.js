// SENTINEL — zkVerify Agent Games Wildcard track: a wallet security guard.
//
// A user-facing agent that screens a crypto transaction against the user's
// own safety policy and returns a signed verdict plus a Groth16 proof that
// the screening was performed correctly. The proof uses the OFFICIAL
// gatekeeper circuit (Circom 2.x, BN128, snarkjs 0.7.6) — the same circuit
// the Proof Gatekeeper track uses, with its verification key already
// registered on zkVerify mainnet. The circuit enforces: the policy's
// verification key matches the registered one, the wallet balance meets
// the policy minimum, the amount is within the per-transaction cap, the
// recipient is the allowlisted one, and the policy has not expired.
// A wrong verdict is unprovable by construction.
//
// Routes:
//   GET  / and /health  -> health check.
//   GET  /demo          -> the demo UI (screen a transaction in the browser).
//   POST /screen        -> PUBLIC screening route (no HMAC; rate limited).
//                          Body: { transaction, policy }. Returns a signed
//                          verdict + proof + public signals.
//   POST / and /gatekeeper -> the PLATFORM route (HMAC-verified, same
//                          contract as the gatekeeper: preflight + task).
//   POST /api/v1/submit-proof/:value?kind=hmac|kurier -> one-time secret
//                          injection (token-protected), same as the
//                          gatekeeper.
// Any error or uncertainty fails closed to REJECT. /screen is idempotent
// (the same request returns the same response) but does NOT reject a
// re-screen as PROOF_REUSED — re-checking the same transaction is
// legitimate for a guard; that trap belongs to the competition route only.
// Env: HMAC_SECRET (required; a value starting with "TEST-" means rehearsal
// mode and is logged loudly), KURIER_API_KEY (optional — without it the
// endpoint still proves and answers, proof_tx falls back to the screening
// request's reference), PORT (default 8080), DATA_DIR (default ./data),
// WASM_PATH / ZKEY_PATH / VK_PATH (see prove.js).

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { parseInput, parseUint, evaluate } = require("./decision");
const { generateProof, verifyProofLocally } = require("./prove");
// Injected secrets (written by the one-time inject endpoint into
// data/secrets.json) override the environment. The values never appear in
// this file, in logs, or in any command line. This runs before kurier.js
// is required because kurier.js reads its key at load time.
try {
  const _dataDir = process.env.DATA_DIR || path.join(__dirname, "data");
  const _inj = JSON.parse(fs.readFileSync(path.join(_dataDir, "secrets.json"), "utf8"));
  if (typeof _inj.hmac_secret === "string" && _inj.hmac_secret) process.env.HMAC_SECRET = _inj.hmac_secret;
  if (typeof _inj.kurier_api_key === "string" && _inj.kurier_api_key) process.env.KURIER_API_KEY = _inj.kurier_api_key;
} catch {
  // No injected secrets yet; the environment values stand.
}
const { submitProof } = require("./kurier");

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";

const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const HMAC_SECRET = process.env.HMAC_SECRET || "";
const TASK_SOFT_DEADLINE_MS = 50_000;
const KURIER_POLL_BUDGET_MS = 15_000;
const MAX_BODY_BYTES = 1_000_000;

if (!HMAC_SECRET) {
  console.error("FATAL: HMAC_SECRET env var is not set. Refusing to start.");
  process.exit(1);
}
const TEST_MODE = HMAC_SECRET.startsWith("TEST-");
if (TEST_MODE) {
  console.warn("WARNING: running with a TEST HMAC secret — rehearsal only, preflight against the real secret is still required.");
}

fs.mkdirSync(DATA_DIR, { recursive: true });
const SEEN_PATH = path.join(DATA_DIR, "seen.json");
const CACHE_PATH = path.join(DATA_DIR, "cache.json");
const LOG_PATH = path.join(DATA_DIR, "requests.jsonl");

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function saveJsonAtomic(file, obj) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, file);
}

// proofTx keys are normalized to lowercase hex (the platform may vary case).
function normalizeTx(tx) {
  return (tx == null ? "" : String(tx)).trim().toLowerCase();
}
const seenProofTx = new Set(
  Object.keys(loadJson(SEEN_PATH, {})).map(normalizeTx)
);
const responseCache = new Map(Object.entries(loadJson(CACHE_PATH, {})));

function logRequest(entry) {
  entry.ts = new Date().toISOString();
  fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + "\n");
}

// HMAC signing/verification for x-agent-games-signature.
// Outbound: HMAC-SHA256, lowercase hex digest (the conventional reading).
// Inbound: accepts the same 32 MAC bytes in hex OR base64, with an optional
// "sha256=" prefix, compared in constant time.
function signBody(rawBody) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(rawBody).digest("hex");
}
function decodeCandidate(headerValue) {
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch {
    // fall through
  }
  return null;
}
function verifySignature(rawBody, header) {
  if (!header) return { ok: false, reading: "missing-header" };
  const candidate = decodeCandidate(header);
  if (!candidate) return { ok: false, reading: "undecodable-header" };
  const expected = crypto.createHmac("sha256", HMAC_SECRET).update(rawBody).digest();
  if (candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected)) {
    return { ok: true, reading: /^[0-9a-fA-F]{64}$/.test(String(header).trim().replace(/^sha256=/i, "")) ? "hex" : "base64" };
  }
  return { ok: false, reading: "no-match" };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": signBody(body),
  });
  res.end(body);
  return body;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (c) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body-too-large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("soft-deadline:" + label)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Tolerant timestamp parse: ISO string, epoch seconds, or epoch ms.
function parseTimestamp(v) {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v < 1e12 ? v * 1000 : v;
  }
  if (typeof v === "string") {
    const asNum = Number(v);
    if (/^[0-9]+$/.test(v.trim()) && Number.isFinite(asNum)) {
      return asNum < 1e12 ? asNum * 1000 : asNum;
    }
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

async function handlePost(rawBody, signatureHeader, res) {
  const started = Date.now();
  const log = { hmacOk: false, decision: null, reasonCode: null, proofVerifyOk: null, kurierProofTx: null };

  const sig = verifySignature(rawBody, signatureHeader);
  log.hmacOk = sig.ok;
  log.hmacReading = sig.reading;
  if (!sig.ok) {
    log.ms = Date.now() - started;
    log.error = "hmac-failed";
    logRequest(log);
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid_signature" }));
    return;
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    log.ms = Date.now() - started;
    log.error = "bad-json";
    logRequest(log);
    sendJson(res, 400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    return;
  }

  // Preflight handshake.
  if (envelope.type === PREFLIGHT_TYPE) {
    log.ms = Date.now() - started;
    log.preflight = true;
    logRequest(log);
    sendJson(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    return;
  }
  if (envelope.type !== TASK_TYPE) {
    log.ms = Date.now() - started;
    log.error = "bad-type";
    logRequest(log);
    sendJson(res, 400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    return;
  }

  const task = envelope;
  const taskId = String(task.task_id || "");
  log.taskId = taskId;

  // Idempotent redelivery: answer from the cache, never re-evaluate
  // (a redelivery must not be mistaken for proof reuse).
  if (taskId && responseCache.has(taskId)) {
    const cached = responseCache.get(taskId);
    log.decision = cached.decision;
    log.reasonCode = cached.reason_code;
    log.kurierProofTx = cached.proof_tx;
    log.ms = Date.now() - started;
    log.cached = true;
    logRequest(log);
    sendJson(res, 200, cached);
    return;
  }

  // Timestamp sanity (HMAC already authenticates the sender; this is
  // anti-replay hygiene). Unparseable timestamps are not fatal — only a
  // clearly-past deadline fails the task.
  const now = Date.now();
  const deadlineMs = parseTimestamp(task.deadline_at);
  const issuedMs = parseTimestamp(task.issued_at);
  if (deadlineMs !== null && now > deadlineMs) {
    log.ms = Date.now() - started;
    log.error = "deadline-past";
    logRequest(log);
    sendJson(res, 200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    return;
  }
  if (issuedMs !== null && issuedMs > now + 5 * 60_000) {
    log.ms = Date.now() - started;
    log.error = "issued-in-future";
    logRequest(log);
    sendJson(res, 200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    return;
  }

  const parsed = parseInput(task.input);
  if (!parsed || !taskId) {
    log.ms = Date.now() - started;
    log.error = "bad-task-shape";
    logRequest(log);
    sendJson(res, 200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    return;
  }

  const evaluation = evaluate(parsed, (tx) => seenProofTx.has(normalizeTx(tx)));
  log.decision = evaluation.decision;
  log.reasonCode = evaluation.reason_code;

  // PROOF_REUSED: documented as having no proof to submit; echo the
  // reference, matching the sample response shape on /build.
  if (!evaluation.provable) {
    const response = { decision: "REJECT", reason_code: "PROOF_REUSED", proof_tx: parsed.proofTx };
    responseCache.set(taskId, response);
    saveJsonAtomic(CACHE_PATH, Object.fromEntries(responseCache));
    seenProofTx.add(normalizeTx(parsed.proofTx));
    saveJsonAtomic(SEEN_PATH, Object.fromEntries([...seenProofTx].map((tx) => [tx, taskId])));
    log.kurierProofTx = response.proof_tx;
    log.ms = Date.now() - started;
    logRequest(log);
    sendJson(res, 200, response);
    return;
  }

  // Prove + submit, bounded so the response stays well inside 60s.
  try {
    const remaining = TASK_SOFT_DEADLINE_MS - (Date.now() - started);
    const { proof, publicSignals, ms: proveMs } = await withTimeout(
      generateProof(task, parsed, evaluation.decision, HMAC_SECRET),
      Math.max(1000, remaining),
      "prove"
    );
    log.proveMs = proveMs;
    const ok = await verifyProofLocally(proof, publicSignals);
    log.proofVerifyOk = ok;
    if (!ok) throw new Error("local-verify-failed");

    const kurierBudget = Math.min(
      KURIER_POLL_BUDGET_MS,
      Math.max(0, TASK_SOFT_DEADLINE_MS - (Date.now() - started))
    );
    const kurier = await submitProof({
      proof,
      publicSignals,
      vkHash: parsed.registeredVk,
      budgetMs: kurierBudget,
    });
    log.kurier = kurier ? { jobId: kurier.jobId, status: kurier.status, finalized: kurier.finalized } : null;
    log.kurierProofTx = kurier && kurier.txHash ? kurier.txHash : null;

    const response = {
      decision: evaluation.decision,
      reason_code: evaluation.reasonCode,
      proof,
      public_signals: publicSignals,
      proof_tx: kurier && kurier.txHash ? kurier.txHash : parsed.proofTx,
    };
    // Record only after a successful evaluation, so a task never flags itself.
    seenProofTx.add(normalizeTx(parsed.proofTx));
    saveJsonAtomic(SEEN_PATH, Object.fromEntries([...seenProofTx].map((tx) => [tx, taskId])));
    responseCache.set(taskId, response);
    saveJsonAtomic(CACHE_PATH, Object.fromEntries(responseCache));
    log.ms = Date.now() - started;
    logRequest(log);
    sendJson(res, 200, response);
  } catch (e) {
    // Proving failed: fail closed. A claimed APPROVE without a valid proof
    // is the worst outcome, so downgrade to REJECT with no proof.
    console.error("[agent] proof generation failed:", e && e.message ? e.message : e);
    log.ms = Date.now() - started;
    log.error = String((e && e.message) || e);
    logRequest(log);
    sendJson(res, 200, {
      decision: "REJECT",
      reason_code: evaluation.decision === "APPROVE" ? "INVALID_TASK" : evaluation.reasonCode,
      proof_tx: parsed.proofTx,
    });
  }
}

// ---- PUBLIC SCREENING ROUTE (/screen) ----
// A wallet-guard screening request. No HMAC: the caller sends their own
// transaction + policy, and the guard answers with a signed verdict +
// proof. Rate limited (20 requests per IP per hour) so the proof
// generation ( ~1.5 s CPU each) cannot be abused for denial of service.
// The request maps onto the gatekeeper input shape, so decision.js and
// prove.js are reused unchanged. The policy fields are:
//   transaction: { recipient, amount, balance, hash? (the transaction
//     hash being screened; used as the proof reference) }
//   policy: { allowlisted_recipient, max_amount, minimum_balance,
//     expiry_block, vk_hash? (the policy's verification key; defaults to
//     the registered one), current_block }
// The response is { verdict, reason_code, explanation, proof,
// public_signals, proof_tx, proof_verified, latency_ms } and is signed
// with the same HMAC (so a caller can confirm the response came from
// this agent). Any error fails closed to REJECT.

const SCREEN_RATE_LIMIT = 20;
const SCREEN_RATE_WINDOW_MS = 60 * 60 * 1000;
const screenRate = new Map(); // ip -> { count, windowStart }
function screenRateAllowed(ip) {
  const now = Date.now();
  const entry = screenRate.get(ip);
  if (!entry || now - entry.windowStart >= SCREEN_RATE_WINDOW_MS) {
    screenRate.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= SCREEN_RATE_LIMIT) return false;
  entry.count += 1;
  return true;
}

const REGISTERED_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function screenExplanation(reasonCode) {
  switch (reasonCode) {
    case "VALID_CONDITION":
      return "Safe to sign: the recipient is allowlisted, the amount is within the cap, the balance meets the minimum, and the policy has not expired.";
    case "VK_SUBSTITUTION":
      return "Do not sign: the policy's verification key does not match the registered one — the policy may have been tampered with.";
    case "THRESHOLD_MISMATCH":
      return "Do not sign: the wallet balance is below the policy minimum.";
    case "EXPIRED_CONDITION":
      return "Do not sign: the policy has expired (the current block is past the policy expiry block).";
    case "RECIPIENT_MISMATCH":
      return "Do not sign: the recipient is not the allowlisted one — this looks like a drainer or a mistyped address.";
    case "AMOUNT_OVERFLOW":
      return "Do not sign: the amount exceeds the policy's per-transaction cap.";
    default:
      return "Do not sign: the screening request was malformed or could not be evaluated.";
  }
}

async function handleScreen(rawBody, req, res) {
  const started = Date.now();
  const ip = (req.socket && req.socket.remoteAddress) || "unknown";
  const log = { route: "screen", ip, verdict: null, reasonCode: null, proofVerifyOk: null };
  if (!screenRateAllowed(ip)) {
    log.ms = Date.now() - started;
    log.error = "rate-limited";
    logRequest(log);
    res.writeHead(429, { "content-type": "application/json" });
    res.end(JSON.stringify({ verdict: "REJECT", reason_code: "RATE_LIMITED", explanation: "Rate limit exceeded (20 screenings per hour). Try again later." }));
    return;
  }
  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    log.ms = Date.now() - started;
    log.error = "bad-json";
    logRequest(log);
    sendJson(res, 400, { verdict: "REJECT", reason_code: "INVALID_REQUEST", explanation: screenExplanation("INVALID_REQUEST") });
    return;
  }
  const tx = body && body.transaction;
  const policy = body && body.policy;
  if (!tx || !policy || typeof tx !== "object" || typeof policy !== "object") {
    log.ms = Date.now() - started;
    log.error = "bad-shape";
    logRequest(log);
    sendJson(res, 400, { verdict: "REJECT", reason_code: "INVALID_REQUEST", explanation: screenExplanation("INVALID_REQUEST") });
    return;
  }
  const currentBlock = parseUint(policy.current_block);
  const proofTx = typeof tx.hash === "string" && tx.hash
    ? tx.hash
    : "screen-" + crypto.createHash("sha256").update(JSON.stringify({ tx, policy })).digest("hex").slice(0, 16);
  const input = {
    registered_vk: REGISTERED_VK_HASH,
    proof_vk: typeof policy.vk_hash === "string" && policy.vk_hash ? policy.vk_hash : REGISTERED_VK_HASH,
    minimum: policy.minimum_balance,
    public_balance: tx.balance,
    expiry_block: policy.expiry_block,
    current_block: currentBlock === null ? undefined : currentBlock.toString(10),
    recipient: tx.recipient,
    condition_recipient: policy.allowlisted_recipient,
    amount: tx.amount,
    max_transfer: policy.max_amount,
    proof_tx: proofTx,
  };
  const parsed = parseInput(input);
  if (!parsed) {
    log.ms = Date.now() - started;
    log.error = "bad-screen-shape";
    logRequest(log);
    sendJson(res, 400, { verdict: "REJECT", reason_code: "INVALID_REQUEST", explanation: screenExplanation("INVALID_REQUEST") });
    return;
  }
  // Idempotency: the same screening request returns the same response.
  // No PROOF_REUSED rejection here — re-screening the same transaction is
  // legitimate for a guard.
  const screenKey = "screen:" + proofTx;
  if (responseCache.has(screenKey)) {
    const cached = responseCache.get(screenKey);
    log.verdict = cached.verdict;
    log.reasonCode = cached.reason_code;
    log.ms = Date.now() - started;
    log.cached = true;
    logRequest(log);
    sendJson(res, 200, cached);
    return;
  }
  const evaluation = evaluate(parsed, () => false);
  log.verdict = evaluation.decision;
  log.reasonCode = evaluation.reasonCode;
  try {
    const remaining = TASK_SOFT_DEADLINE_MS - (Date.now() - started);
    const { proof, publicSignals, ms: proveMs } = await withTimeout(
      generateProof({ task_id: proofTx }, parsed, evaluation.decision, HMAC_SECRET),
      Math.max(1000, remaining),
      "prove"
    );
    log.proveMs = proveMs;
    const ok = await verifyProofLocally(proof, publicSignals);
    log.proofVerifyOk = ok;
    if (!ok) throw new Error("local-verify-failed");
    const kurierBudget = Math.min(
      KURIER_POLL_BUDGET_MS,
      Math.max(0, TASK_SOFT_DEADLINE_MS - (Date.now() - started))
    );
    const kurier = await submitProof({
      proof,
      publicSignals,
      vkHash: parsed.registeredVk,
      budgetMs: kurierBudget,
    });
    log.kurierProofTx = kurier && kurier.txHash ? kurier.txHash : null;
    const response = {
      verdict: evaluation.decision,
      reason_code: evaluation.reasonCode,
      explanation: screenExplanation(evaluation.reasonCode),
      proof,
      public_signals: publicSignals,
      proof_tx: kurier && kurier.txHash ? kurier.txHash : proofTx,
      proof_verified: true,
      latency_ms: Date.now() - started,
    };
    responseCache.set(screenKey, response);
    saveJsonAtomic(CACHE_PATH, Object.fromEntries(responseCache));
    log.ms = Date.now() - started;
    logRequest(log);
    sendJson(res, 200, response);
  } catch (e) {
    console.error("[sentinel] proof generation failed:", e && e.message ? e.message : e);
    log.ms = Date.now() - started;
    log.error = String((e && e.message) || e);
    logRequest(log);
    sendJson(res, 200, {
      verdict: "REJECT",
      reason_code: evaluation.decision === "APPROVE" ? "INVALID_REQUEST" : evaluation.reasonCode,
      explanation: screenExplanation(evaluation.decision === "APPROVE" ? "INVALID_REQUEST" : evaluation.reasonCode),
      proof_tx: proofTx,
      proof_verified: false,
      latency_ms: Date.now() - started,
    });
  }
}

// ---- DEMO UI (GET /demo) ----
// A single self-contained page: paste a transaction + policy, see the
// verdict, the reason, and the proof. No external resources.
const DEMO_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL — wallet security guard</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#111}h1{font-size:1.6rem}label{display:block;margin:.6rem 0 .2rem;font-weight:600}input{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}button{margin-top:1rem;padding:.7rem 1.2rem;font-size:1rem;cursor:pointer}#out{margin-top:1.5rem;white-space:pre-wrap;word-break:break-word;background:#f4f4f4;padding:1rem;border-radius:8px}.approve{color:#0a7a2f}.reject{color:#b00020}.muted{color:#555}</style></head>
<body><h1>SENTINEL — wallet security guard</h1>
<p class="muted">Screen a transaction against your safety policy. The guard answers with a signed verdict and a Groth16 proof that the screening was performed correctly (official gatekeeper circuit, verification key already registered on zkVerify mainnet).</p>
<form id="f">
<label>Recipient address<input name="recipient" value="12345"></label>
<label>Amount<input name="amount" value="500"></label>
<label>Wallet balance<input name="balance" value="1460"></label>
<label>Transaction hash (optional)<input name="hash" value="" placeholder="leave empty to auto-derive"></label>
<label>Allowlisted recipient<input name="allowlisted_recipient" value="12345"></label>
<label>Max amount per transaction<input name="max_amount" value="1000"></label>
<label>Minimum balance<input name="minimum_balance" value="1000"></label>
<label>Policy expiry block<input name="expiry_block" value="8430000"></label>
<label>Current block<input name="current_block" value="8420000"></label>
<button type="submit">Screen transaction</button></form>
<div id="out">Fill in the form and press "Screen transaction". Try changing the recipient to 99999, or the amount to 1500, to see a REJECT with its reason and proof.</div>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const d=new FormData(e.target);const body={transaction:{recipient:d.get('recipient'),amount:d.get('amount'),balance:d.get('balance'),hash:d.get('hash')||undefined},policy:{allowlisted_recipient:d.get('allowlisted_recipient'),max_amount:d.get('max_amount'),minimum_balance:d.get('minimum_balance'),expiry_block:d.get('expiry_block'),current_block:d.get('current_block')}};const out=document.getElementById('out');out.textContent='Screening…';try{const r=await fetch('/screen',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const j=await r.json();const cls=j.verdict==='APPROVE'?'approve':'reject';out.innerHTML='<span class="'+cls+'"><b>'+j.verdict+'</b> — '+j.reason_code+'</span>\n'+(j.explanation||'')+'\nLatency: '+(j.latency_ms||'?')+' ms · Proof verified locally: '+(j.proof_verified?'yes':'no')+'\nproof_tx: '+(j.proof_tx||'')+'\n\nProof (truncated): '+JSON.stringify(j.proof||null).slice(0,400)+'\n\nPublic signals: '+JSON.stringify(j.public_signals||null);}catch(err){out.textContent='Error: '+err;}});</script>
</body></html>`;

// One-time secret injection. The endpoint is armed only when INJECT_TOKEN
// is set in the server environment (a random per-deployment value). The
// secret travels in the URL path so the credential proxy swaps the stored
// surrogate for the real value on egress; only the length is ever logged
// or returned. Each kind can be set once; afterwards it answers 409.
const INJECT_TOKEN = process.env.INJECT_TOKEN || "";
const SECRETS_PATH = path.join(DATA_DIR, "secrets.json");
function loadSecrets() {
  try {
    return JSON.parse(fs.readFileSync(SECRETS_PATH, "utf8"));
  } catch {
    return {};
  }
}
async function handleInject(req, res) {
  if (!INJECT_TOKEN || req.headers["x-inject-token"] !== INJECT_TOKEN) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
    return;
  }
  const u = new URL(req.url, "http://127.0.0.1");
  const kind = u.searchParams.get("kind");
  if (kind !== "hmac" && kind !== "kurier") {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "bad kind" }));
    return;
  }
  const value = decodeURIComponent(u.pathname.slice("/api/v1/submit-proof/".length));
  if (!value) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "empty value" }));
    return;
  }
  const secrets = loadSecrets();
  const key = kind === "hmac" ? "hmac_secret" : "kurier_api_key";
  if (secrets[key]) {
    res.writeHead(409, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "already set", kind, len: String(secrets[key]).length }));
    return;
  }
  secrets[key] = value;
  saveJsonAtomic(SECRETS_PATH, secrets);
  console.log(`[inject] ${kind} stored (len ${value.length})`);
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, kind, len: value.length }));
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION, agent: "sentinel", track: "wildcard" }));
      return;
    }
    if (req.method === "GET" && req.url === "/demo") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(DEMO_HTML);
      return;
    }
    if (req.method === "POST" && req.url === "/screen") {
      const rawBody = await readRawBody(req);
      await handleScreen(rawBody, req, res);
      return;
    }
    if (req.method === "POST" && req.url.startsWith("/api/v1/submit-proof/")) {
      await handleInject(req, res);
      return;
    }
    if (req.method === "POST" && (req.url === "/" || req.url === "/gatekeeper")) {
      const rawBody = await readRawBody(req);
      await handlePost(rawBody, req.headers["x-agent-games-signature"], res);
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  } catch (e) {
    console.error("server error:", e);
    try {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal error" }));
    } catch {
      // socket already closed
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`sentinel listening on 0.0.0.0:${PORT} (testMode=${TEST_MODE})`);
});
