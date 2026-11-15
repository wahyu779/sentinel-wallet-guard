// Kurier (zkVerify) proof submission — mainnet.
//
// Shape from the /build page and docs.zkverify.io, confirmed against the
// working reference implementation (Andruu21, 4/4 practice correct):
//   POST {KURIER_API_URL}/submit-proof/{KURIER_API_KEY}
//   { proofType: "groth16", vkRegistered: true,
//     proofOptions: { library: "snarkjs", curve: "bn128" },
//     proofData: { proof, publicSignals, vk: <vk_hash> } }
//   -> { jobId, optimisticVerify }
//   GET {KURIER_API_URL}/job-status/{KURIER_API_KEY}/{jobId}
//   lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock ->
//              Finalized | Failed
//   The txHash is already present from the Submitted status onward
//   (measured live: txHash at ~4 s, Finalized at ~27 s), so polling
//   returns as soon as a txHash is known instead of blocking the task
//   response on finalization; the Kurier job keeps finalizing
//   server-side regardless.
//
// The gatekeeper vk_hash is already registered on mainnet, so
// vkRegistered: true and no register-vk call is needed.
//
// This module never throws: any failure returns null and the caller still
// answers the task with the proof + public_signals (proof_tx falls back
// to the task's own proof reference). Without KURIER_API_KEY set, it
// returns null immediately — the endpoint still proves and answers.

const KURIER_API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const GATEKEEPER_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const POLL_INTERVAL_MS = 3000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Submit a proof and poll until a txHash exists or the budget expires.
// Returns null when no API key is configured or on any failure.
async function submitProof({ proof, publicSignals, vkHash, budgetMs }) {
  if (!KURIER_API_KEY) {
    return null;
  }
  const key = KURIER_API_KEY;
  const deadline = Date.now() + Math.max(0, budgetMs || 15000);
  try {
    const submitRes = await fetch(`${KURIER_API_URL}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash || GATEKEEPER_VK_HASH },
      }),
      signal: AbortSignal.timeout(Math.max(1000, deadline - Date.now())),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = await submitRes.json();
    if (!job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }
    // The docs advise checking optimisticVerify before polling: anything
    // other than "success" means the proof artifacts are wrong.
    if (job.optimisticVerify && job.optimisticVerify !== "success") {
      console.error(`[kurier] optimisticVerify=${job.optimisticVerify} — proof artifacts rejected, not polling`);
      return null;
    }

    let status = "Submitted";
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(Math.min(POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
      let statusRes;
      try {
        statusRes = await fetch(`${KURIER_API_URL}/job-status/${key}/${job.jobId}`, {
          signal: AbortSignal.timeout(10000),
        });
      } catch {
        continue;
      }
      if (!statusRes.ok) {
        console.error(`[kurier] job-status HTTP ${statusRes.status}`);
        continue;
      }
      const s = await statusRes.json();
      status = s.status || status;
      const txHash = s.txHash || (s.transactionInfo && s.transactionInfo.txHash);
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") {
        return { jobId: job.jobId, status, txHash, finalized: false };
      }
      if (txHash) {
        // The on-chain transaction exists from Submitted onward; return its
        // hash now and let finalization complete server-side at Kurier.
        return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
      }
    }
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", err && err.message ? err.message : err);
    return null;
  }
}

module.exports = { submitProof, KURIER_API_URL, GATEKEEPER_VK_HASH };
