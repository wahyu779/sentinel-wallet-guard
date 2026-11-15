// Test harness for the SENTINEL wallet-guard endpoint.
// Usage: node guard-harness.js [baseUrl]   (default http://127.0.0.1:8080)
// Env: HMAC_SECRET (the TEST secret the server runs with).
// Checks:
//   - unit: decision.js on the 7 screening variants.
//   - preflight handshake (signed), bad signature -> 401.
//   - live platform route: 7 trap variants (same contract as the gatekeeper).
//   - live /screen route: approve + 5 reject reasons + malformed, with a
//     local Groth16 verify of every returned proof (snarkjs + the VK).
//   - idempotent re-screen (same request twice -> identical body).
//   - rate limit (21 fast malformed requests -> the 21st is 429; run last
//     because it consumes the IP's 20/hour quota).
// With no KURIER_API_KEY the server falls back to the request's own proof
// reference as proof_tx — that still counts as proof_tx present, but the
// run is marked KURIER-FALLBACK, not full.

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const path = require("path");
const { decide } = require("./decision");
const { verifyProofLocally } = require("./prove");

const BASE = process.argv[2] || "http://127.0.0.1:8080";
try {
  const _dataDir = process.env.DATA_DIR || path.join(__dirname, "data");
  const _inj = JSON.parse(fs.readFileSync(path.join(_dataDir, "secrets.json"), "utf8"));
  if (typeof _inj.hmac_secret === "string" && _inj.hmac_secret) process.env.HMAC_SECRET = _inj.hmac_secret;
} catch {
  // No injected secrets yet; the environment value stands.
}
const SECRET = process.env.HMAC_SECRET || "";
if (!SECRET) {
  console.error("HMAC_SECRET env var is not set.");
  process.exit(1);
}

const REGISTERED_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const SCREEN_RATE_LIMIT = 20; // must match guard-server.js SCREEN_RATE_LIMIT (20 /screen requests per IP per hour)

const RUN_TAG = Date.now().toString(16).slice(-8);
function txHex(byte) {
  return "0x" + (byte + RUN_TAG).repeat(32).slice(0, 64);
}

function baseInput(overrides) {
  return {
    registered_vk: REGISTERED_VK,
    proof_vk: REGISTERED_VK,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT,
    amount: "500",
    max_transfer: "1000",
    proof_tx: txHex("a1"),
    ...overrides,
  };
}

const VARIANTS = [
  { name: "VALID_CONDITION", input: baseInput({}), expect: "APPROVE", code: "VALID_CONDITION" },
  { name: "VK_SUBSTITUTION", input: baseInput({ proof_vk: "0x" + "11".repeat(32) }), expect: "REJECT", code: "VK_SUBSTITUTION" },
  { name: "PROOF_REUSED", input: baseInput({}), expect: "REJECT", code: "PROOF_REUSED", reuse: true },
  { name: "THRESHOLD_MISMATCH", input: baseInput({ public_balance: "500", proof_tx: txHex("b2") }), expect: "REJECT", code: "THRESHOLD_MISMATCH" },
  { name: "EXPIRED_CONDITION", input: baseInput({ current_block: 8430000, proof_tx: txHex("c3") }), expect: "REJECT", code: "EXPIRED_CONDITION" },
  { name: "RECIPIENT_MISMATCH", input: baseInput({ recipient: "0xBeef000000000000000000000000000000000001", proof_tx: txHex("d4") }), expect: "REJECT", code: "RECIPIENT_MISMATCH" },
  { name: "AMOUNT_OVERFLOW", input: baseInput({ amount: "1500", proof_tx: txHex("e5") }), expect: "REJECT", code: "AMOUNT_OVERFLOW" },
];

// /screen variants (same 5 checks, expressed as a transaction + policy).
function screenRequest(overrides) {
  const req = {
    transaction: { recipient: RECIPIENT, amount: "500", balance: "1460", hash: txHex("f1") },
    policy: {
      allowlisted_recipient: RECIPIENT,
      max_amount: "1000",
      minimum_balance: "1000",
      expiry_block: 8430000,
      current_block: 8420000,
    },
  };
  if (overrides) {
    if (overrides.transaction) Object.assign(req.transaction, overrides.transaction);
    if (overrides.policy) Object.assign(req.policy, overrides.policy);
  }
  return req;
}

const SCREEN_VARIANTS = [
  { name: "SCREEN_APPROVE", req: screenRequest({}), expect: "APPROVE", code: "VALID_CONDITION" },
  { name: "SCREEN_VK_SUBSTITUTION", req: screenRequest({ transaction: { hash: txHex("f2") }, policy: { vk_hash: "0x" + "11".repeat(32) } }), expect: "REJECT", code: "VK_SUBSTITUTION" },
  { name: "SCREEN_THRESHOLD_MISMATCH", req: screenRequest({ transaction: { hash: txHex("f3"), balance: "500" } }), expect: "REJECT", code: "THRESHOLD_MISMATCH" },
  { name: "SCREEN_EXPIRED", req: screenRequest({ transaction: { hash: txHex("f4") }, policy: { current_block: 8430000 } }), expect: "REJECT", code: "EXPIRED_CONDITION" },
  { name: "SCREEN_RECIPIENT_MISMATCH", req: screenRequest({ transaction: { hash: txHex("f5"), recipient: "0xBeef000000000000000000000000000000000001" } }), expect: "REJECT", code: "RECIPIENT_MISMATCH" },
  { name: "SCREEN_AMOUNT_OVERFLOW", req: screenRequest({ transaction: { hash: txHex("f6"), amount: "1500" } }), expect: "REJECT", code: "AMOUNT_OVERFLOW" },
];

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}

// /screen requests made so far in this run. The server's rate limiter
// counts EVERY /screen request (variants, malformed, cached re-screens),
// so the 429 in the rate-limit section must be expected at request
// (SCREEN_RATE_LIMIT - screenRequestsMade + 1) of that section, not at
// a hardcoded 21st request. (The old expectation assumed a fresh quota
// AND zero prior /screen requests in the run; both were wrong.)
let screenRequestsMade = 0;

function post(path, obj, signatureOverride) {
  if (path === "/screen") screenRequestsMade++;
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(obj);
    const url = new URL(path, BASE);
    const started = Date.now();
    const headers = {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    };
    if (signatureOverride !== null) {
      headers["x-agent-games-signature"] = signatureOverride === undefined ? sign(body) : signatureOverride;
    }
    const req = (url.protocol === "https:" ? https : http).request(
      { hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, ms: Date.now() - started, body: data, sig: res.headers["x-agent-games-signature"] }));
      }
    );
    req.on("error", reject);
    req.setTimeout(65000, () => req.destroy(new Error("harness-timeout")));
    req.end(body);
  });
}

async function main() {
  console.log("== UNIT: decision.js ==");
  const seen = new Set();
  let unitPass = 0;
  for (const v of VARIANTS) {
    const got = decide(v.input, seen);
    const wantDecision = v.expect === "APPROVE" ? 1 : 0;
    const ok = got && got.decision === wantDecision && got.reasonCode === v.code;
    if (v.name === "VALID_CONDITION") seen.add(v.input.proof_tx.toLowerCase());
    console.log(`${ok ? "PASS" : "FAIL"} ${v.name}: got ${got ? (got.decision === 1 ? "APPROVE" : "REJECT") + "/" + got.reasonCode : "null"}`);
    if (ok) unitPass++;
  }
  console.log(`unit: ${unitPass}/7`);

  console.log("== PREFLIGHT ==");
  const pre = await post("/", { type: "agent-games.preflight.v1", issued_at: new Date().toISOString() });
  let preParsed = null;
  try { preParsed = JSON.parse(pre.body); } catch { /* leave null */ }
  const preOk = pre.status === 200 && preParsed && preParsed.ok === true && preParsed.protocolVersion === "v1" && !!pre.sig;
  console.log(`${preOk ? "PASS" : "FAIL"} preflight: http=${pre.status} ms=${pre.ms} body=${pre.body.slice(0, 80)} signed=${!!pre.sig}`);

  console.log("== BAD SIGNATURE (expect 401) ==");
  const bad = await post("/", { type: "agent-games.proof-gatekeeper.v1", task_id: "harness-bad-sig", input: baseInput({}) }, "deadbeef");
  console.log(`${bad.status === 401 ? "PASS" : "FAIL"} bad signature: http=${bad.status} ms=${bad.ms}`);

  console.log("== LIVE PLATFORM: 7 trap variants -> " + BASE + " ==");
  let liveDecision = 0;
  let liveFull = 0;
  let firstBody = null;
  let firstTaskId = null;
  for (const v of VARIANTS) {
    const taskId = "harness-" + v.name.toLowerCase() + "-" + Date.now();
    const task = {
      type: "agent-games.proof-gatekeeper.v1",
      task_id: taskId,
      mode: "competition",
      issued_at: new Date().toISOString(),
      deadline_at: new Date(Date.now() + 60000).toISOString(),
      input: v.input,
    };
    let result;
    try {
      result = await post("/", task);
    } catch (e) {
      console.log(`ERROR ${v.name}: ${e.message}`);
      continue;
    }
    let parsed = null;
    try { parsed = JSON.parse(result.body); } catch { /* leave null */ }
    const decisionOk = parsed && parsed.decision === v.expect && parsed.reason_code === v.code;
    const proofOk = v.name === "PROOF_REUSED"
      ? (parsed && !parsed.proof && !parsed.public_signals)
      : (parsed && parsed.proof && Array.isArray(parsed.public_signals) && parsed.public_signals.length === 13);
    const txOk = parsed && typeof parsed.proof_tx === "string" && parsed.proof_tx.startsWith("0x");
    const status = decisionOk && proofOk && txOk ? "PASS" : decisionOk ? "DEGRADED" : "FAIL";
    if (decisionOk) liveDecision++;
    if (decisionOk && proofOk && txOk) liveFull++;
    if (v.name === "VALID_CONDITION") { firstBody = result.body; firstTaskId = taskId; }
    console.log(
      `${status} ${v.name}: http=${result.status} ms=${result.ms} decision=${parsed ? parsed.decision + "/" + parsed.reason_code : "?"} proof=${!!(parsed && parsed.proof)} signals=${parsed && parsed.public_signals ? parsed.public_signals.length : "?"} proof_tx=${parsed ? String(parsed.proof_tx).slice(0, 18) : "?"}`
    );
  }
  console.log(`live platform decision: ${liveDecision}/7, live full: ${liveFull}/7`);

  console.log("== LIVE /screen: 6 screening variants -> " + BASE + " ==");
  let screenDecision = 0;
  let screenFull = 0;
  let firstScreenBody = null;
  let firstScreenReq = null;
  for (const v of SCREEN_VARIANTS) {
    let result;
    try {
      result = await post("/screen", v.req, null);
    } catch (e) {
      console.log(`ERROR ${v.name}: ${e.message}`);
      continue;
    }
    let parsed = null;
    try { parsed = JSON.parse(result.body); } catch { /* leave null */ }
    const decisionOk = parsed && parsed.verdict === v.expect && parsed.reason_code === v.code;
    let proofOk = false;
    let proofVerified = false;
    if (parsed && parsed.proof && Array.isArray(parsed.public_signals) && parsed.public_signals.length === 13) {
      proofOk = true;
      try {
        proofVerified = await verifyProofLocally(parsed.proof, parsed.public_signals);
      } catch (e) {
        proofVerified = false;
      }
    }
    const txOk = parsed && typeof parsed.proof_tx === "string" && parsed.proof_tx.length > 0;
    const status = decisionOk && proofOk && proofVerified && txOk ? "PASS" : decisionOk ? "DEGRADED" : "FAIL";
    if (decisionOk) screenDecision++;
    if (decisionOk && proofOk && proofVerified && txOk) screenFull++;
    if (v.name === "SCREEN_APPROVE") { firstScreenBody = result.body; firstScreenReq = v.req; }
    console.log(
      `${status} ${v.name}: http=${result.status} ms=${result.ms} verdict=${parsed ? parsed.verdict + "/" + parsed.reason_code : "?"} proof=${!!(parsed && parsed.proof)} verified=${proofVerified} signals=${parsed && parsed.public_signals ? parsed.public_signals.length : "?"} proof_tx=${parsed ? String(parsed.proof_tx).slice(0, 18) : "?"}`
    );
  }
  console.log(`live /screen decision: ${screenDecision}/6, live full (verdict+proof+verified+tx): ${screenFull}/6`);

  console.log("== MALFORMED /screen (expect 400 REJECT) ==");
  const malformed = await post("/screen", { transaction: { recipient: RECIPIENT } }, null);
  let malParsed = null;
  try { malParsed = JSON.parse(malformed.body); } catch { /* leave null */ }
  const malOk = malformed.status === 400 && malParsed && malParsed.verdict === "REJECT" && malParsed.reason_code === "INVALID_REQUEST";
  console.log(`${malOk ? "PASS" : "FAIL"} malformed: http=${malformed.status} ms=${malformed.ms}`);

  console.log("== IDEMPOTENT RE-SCREEN (same request twice) ==");
  const rescreen = await post("/screen", firstScreenReq, null);
  const same = rescreen.body === firstScreenBody;
  console.log(`${same ? "PASS" : "FAIL"} re-screen: identical body=${same} http=${rescreen.status} ms=${rescreen.ms}`);

  console.log("== IDEMPOTENT REDELIVERY (platform, same task_id twice) ==");
  const redelivered = await post("/", {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: firstTaskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: baseInput({}),
  });
  const samePlat = redelivered.body === firstBody;
  console.log(`${samePlat ? "PASS" : "FAIL"} redelivery: identical body=${samePlat} http=${redelivered.status} ms=${redelivered.ms}`);

  // The 429 must land on the request that fills the quota: this run has
  // already made `priorScreen` /screen requests (6 variants + malformed
  // + re-screen = 8), so send (20 - 8 + 1) = 13 requests and expect the
  // 13th to be 429 with the first 12 not 429. `priorScreen` is captured
  // BEFORE this section's requests — the counter keeps incrementing
  // inside post(), so reading it after the loop would print the total
  // (21), not the prior count (8). If the quota was already partly
  // consumed BEFORE this run (e.g. a demo-UI visit in the same hour),
  // the 429 lands earlier and the test FAILs honestly — the printout
  // shows the actual position, so a re-run after a server restart
  // (fresh in-memory quota) is the fix, not a server bug.
  const priorScreen = screenRequestsMade;
  const rateExpectedAt = SCREEN_RATE_LIMIT - priorScreen + 1;
  console.log(`== RATE LIMIT (${SCREEN_RATE_LIMIT}/hour per IP; ${priorScreen} /screen requests already made this run, so the 429 must come at request ${rateExpectedAt} of this section) ==`);
  let rateStatuses = [];
  for (let i = 0; i < rateExpectedAt; i++) {
    const r = await post("/screen", { bad: true }, null);
    rateStatuses.push(r.status);
  }
  const lastIs429 = rateStatuses[rateExpectedAt - 1] === 429;
  const beforeNot429 = rateStatuses.slice(0, rateExpectedAt - 1).every((s) => s !== 429);
  console.log(`${lastIs429 && beforeNot429 ? "PASS" : "FAIL"} rate limit: sent=${rateExpectedAt} (prior /screen this run=${priorScreen}, quota=${SCREEN_RATE_LIMIT}, 429 expected at #${rateExpectedAt}) statuses=${rateStatuses.join(",")}`);

  // Overall result. Force-exit: the process must not linger (the previous
  // run completed all 39 requests but never exited — likely a held event
  // loop — and its buffered output was lost). DEGRADED counts as a
  // failure here (decision right but proof/tx incomplete is not a pass
  // for a proof-carrying guard).
  const failures = (7 - unitPass) + (preOk ? 0 : 1) + (bad.status === 401 ? 0 : 1) + (7 - liveFull) + (6 - screenFull) + (malOk ? 0 : 1) + (same ? 0 : 1) + (samePlat ? 0 : 1) + ((lastIs429 && beforeNot429) ? 0 : 1);
  console.log(failures === 0 ? "HARNESS RESULT: PASS" : `HARNESS RESULT: FAIL (${failures} checks failed)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
