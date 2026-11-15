// Deterministic policy for the Proof Gatekeeper. No model involvement.
// Checks follow the /build Security checklist and map 1:1 onto the trap
// taxonomy on /events/proof-gatekeeper. The gatekeeper circuit enforces
// exactly these comparisons on its public inputs (verified experimentally
// against gatekeeper.wasm): the `decision` input must equal the AND of the
// checks, or witness generation fails. Boundary semantics: balance >=
// minimum passes, amount <= max_transfer passes, current_block <
// expiry_block passes.
//
// Encoding (from the working reference implementation, Andruu21):
// hex values are reduced mod the BN128 field prime (a 32-byte hash does not
// fit the field); reduction preserves equality, which is all the circuit
// checks. Free-form identifiers (e.g. task_id "gk_8d31_x") hash into the
// field with SHA-256. Commitment [0] = Poseidon(taskId, salt).

const crypto = require("crypto");

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function normalizeHex(v) {
  return (v == null ? "" : String(v)).trim().toLowerCase();
}

// Parse a non-negative integer given as a decimal string, hex string, or number.
function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

// Structural validation + parsing. Returns null on any malformed field.
function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null || publicBalance === null || amount === null ||
    maxTransfer === null || expiryBlock === null || currentBlock === null
  ) {
    return null;
  }
  if (
    typeof input.registered_vk !== "string" || !input.registered_vk ||
    typeof input.proof_vk !== "string" || !input.proof_vk ||
    typeof input.recipient !== "string" || !input.recipient ||
    typeof input.condition_recipient !== "string" || !input.condition_recipient ||
    typeof input.proof_tx !== "string" || !input.proof_tx
  ) {
    return null;
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

// Fixed check order (documented; official pages rank no trap above another,
// so the first failure in this order is the reported one).
// provable=false only for PROOF_REUSED: that trap has no proof to submit.
function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reasonCode: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    return { decision: "REJECT", reasonCode: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reasonCode: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reasonCode: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reasonCode: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reasonCode: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reasonCode: "VALID_CONDITION", provable: true };
}

// Convert an envelope value to a BN128 field element (decimal string).
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      // Free-form identifier (e.g. a task_id like "gk_8d31_x"): hash into the field.
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  const reduced = ((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
  return reduced.toString(10);
}

// Circuit inputs for gatekeeper.wasm. Public signals order:
// [commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
//  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//  maxTransfer, decision, taskId]
// where commitment = Poseidon(taskId, salt) is the circuit's only output.
function buildCircuitInputs(taskId, parsed, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

// Thin wrapper kept for the harness unit test: raw input + seen set ->
// { decision: 0|1, reasonCode }. Returns null when the input is malformed.
function decide(input, seenProofTx) {
  const parsed = parseInput(input);
  if (!parsed) return null;
  const ev = evaluate(parsed, (tx) => seenProofTx && seenProofTx.has(String(tx).trim().toLowerCase()));
  return { decision: ev.decision === "APPROVE" ? 1 : 0, reasonCode: ev.reasonCode, provable: ev.provable };
}

module.exports = { parseUint, parseInput, evaluate, toFieldElement, buildCircuitInputs, decide, BN128_PRIME };
