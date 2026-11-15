// Groth16 proof generation with snarkjs from the OFFICIAL gatekeeper circuit.
// WASM + zkey paths come from the environment (WASM_PATH, ZKEY_PATH) or the
// defaults below. Verification key JSON is used for the local verify step.
//
// Circuit semantics (verified empirically against the official wasm):
// decision == 1 iff every check passes. A REJECT proof carries the SAME
// real task inputs with decision = 0 and only proves when at least one
// check actually fails. PROOF_REUSED has no proof.
// Salt is deterministic per task: HMAC(secret, "gatekeeper-salt:"+taskId)
// mod the BN128 prime, so a redelivered task reproduces the same inputs.
// Encoding: see decision.js toFieldElement (hex/decimal mod p, free-form
// identifiers via SHA-256).

const crypto = require("crypto");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildCircuitInputs, BN128_PRIME } = require("./decision");

const WASM_PATH = process.env.WASM_PATH || path.join(__dirname, "circuit", "gatekeeper.wasm");
const ZKEY_PATH = process.env.ZKEY_PATH || path.join(__dirname, "circuit", "gatekeeper_final.zkey");
const VK_PATH = process.env.VK_PATH || path.join(__dirname, "circuit", "verification_key.json");

function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

// Generate a Groth16 proof for one task + decision.
// Returns { proof, publicSignals, ms }. Throws when witness generation
// fails (a wrong decision is unprovable by construction) or when the
// public signals do not match the inputs (a verifying proof alone is not
// enough — the server must confirm what was proven).
async function generateProof(task, parsed, decision, hmacSecret) {
  const salt = deriveSalt(hmacSecret, task.task_id);
  const circuitInput = buildCircuitInputs(task.task_id, parsed, decision, salt);
  const started = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );
  const ms = Date.now() - started;

  // Self-check the public signals against the inputs before anyone trusts
  // this proof: [1] registeredVkHash, [2] proofVkHash, [11] decision,
  // [12] taskId. (Signal [0] is the Poseidon(taskId, salt) commitment and
  // cannot be recomputed without the salt; it is checked by construction.)
  const expect = {
    1: circuitInput.registeredVkHash,
    2: circuitInput.proofVkHash,
    11: circuitInput.decision,
    12: circuitInput.taskId,
  };
  for (const [idx, want] of Object.entries(expect)) {
    if (String(publicSignals[Number(idx)]) !== String(want)) {
      throw new Error(`public-signal mismatch at [${idx}]: got ${publicSignals[Number(idx)]}, want ${want}`);
    }
  }
  return { proof, publicSignals, ms };
}

// Verify a proof locally against the verification key. Returns true/false.
async function verifyProofLocally(proof, publicSignals) {
  const vk = require(VK_PATH);
  return await snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { generateProof, verifyProofLocally, deriveSalt, WASM_PATH, ZKEY_PATH, VK_PATH };
