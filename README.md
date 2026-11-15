# SENTINEL — a wallet security guard (zkVerify Agent Games, Wildcard track)

A user-facing agent that screens a crypto transaction against the user's
own safety policy and returns a signed verdict plus a Groth16 proof that
the screening was performed correctly. The proof is the product: it
attests that the verdict is the right one for these exact inputs, and
anyone can re-verify it against the published verification key.

## Who it helps

Anyone who signs crypto transactions. Wallet drainers and malicious
approvals are the most common way users lose funds: a single bad approval
can empty a wallet. SENTINEL checks every transaction before signing —
recipient, amount, balance, policy expiry — and proves the check was
done, so a wallet (or a dApp) can refuse to sign anything the guard
rejects.

## How it works

1. The user (or their wallet) sends a transaction and a safety policy to
   `POST /screen`: the recipient, the amount, the wallet balance, and the
   policy (allowlisted recipient, per-transaction amount cap, minimum
   balance, policy expiry block, verification-key hash).
2. The guard evaluates the policy deterministically: APPROVE only when
   every check passes; otherwise REJECT with a reason code
   (`VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `EXPIRED_CONDITION`,
   `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`). The same input always gives
   the same output. No language model anywhere near the decision.
3. The verdict is proven with the official gatekeeper circuit (Circom 2.x,
   BN128) using snarkjs 0.7.6. A wrong verdict is unprovable by
   construction: approving a failing transaction and rejecting a valid one
   both fail witness generation. The proof is verified locally before the
   response goes out.
4. The proof is submitted to zkVerify mainnet via Kurier when a key is
   configured; without one the response still carries the proof and public
   signals, and `proof_tx` falls back to the screening request's reference.
5. The response is signed (HMAC-SHA256) so the caller can confirm it came
   from this agent.

The guard also runs the platform route (`POST /`, HMAC-verified preflight
+ task handling, same contract as the Proof Gatekeeper) so it is a real
registered Agent Games agent, not just a demo. The demo UI is at
`GET /demo`.

## The checkable claim (zkVerify)

Claim: "This transaction's verdict is the correct one for the stated
policy." The proof is a Groth16 proof over the official gatekeeper
circuit (verification key already registered on zkVerify mainnet,
vk hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
Anyone can re-verify a returned proof locally:

```sh
snarkjs groth16 verify circuit/verification_key.json public.json proof.json
```

The verification key, the circuit artifacts, and the test vectors are in
`circuit/`.

## Run it

Node 22 or newer.

```sh
npm install
HMAC_SECRET=<secret from the Agent Games dashboard> \
KURIER_API_KEY=<mainnet Kurier key, optional> \
KURIER_API_URL=https://api.kurier.xyz/api/v1 \
GATEKEEPER_VK_HASH=0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0 \
node guard-server.js
```

The server listens on port 8080. `GET /` is the health check,
`GET /demo` is the demo UI, `POST /screen` screens a transaction,
`POST /` answers platform tasks.

Environment:

- `HMAC_SECRET` (required): the 32-byte secret from the Agent Games
  dashboard. A value starting with `TEST-` runs the server in rehearsal
  mode and is logged loudly.
- `KURIER_API_KEY` (optional): mainnet Kurier key. Without it the server
  still answers with the proof and public signals, but `proof_tx` falls
  back to the screening request's reference.
- `KURIER_API_URL` (optional): defaults to `https://api.kurier.xyz/api/v1`.
- `GATEKEEPER_VK_HASH` (optional): defaults to the registered gatekeeper
  verification-key hash.

No secrets are committed in this repo. Secrets come from the environment
only (or the one-time inject endpoint, see below).

## Screen a transaction

```sh
curl -s -X POST http://127.0.0.1:8080/screen \
  -H 'content-type: application/json' \
  -d '{
    "transaction": {"recipient": "12345", "amount": "500", "balance": "1460"},
    "policy": {
      "allowlisted_recipient": "12345",
      "max_amount": "1000",
      "minimum_balance": "1000",
      "expiry_block": 8430000,
      "current_block": 8420000
    }
  }'
```

Response (abbreviated):

```json
{
  "verdict": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "explanation": "Safe to sign: the recipient is allowlisted, ...",
  "proof": { "...": "..." },
  "public_signals": ["3777...", "4836...", "..."],
  "proof_tx": "screen-...",
  "proof_verified": true,
  "latency_ms": 1800
}
```

Try changing the recipient to `99999` (REJECT / RECIPIENT_MISMATCH) or
the amount to `1500` (REJECT / AMOUNT_OVERFLOW).

Limits: `/screen` is rate limited to 20 requests per IP per hour, and any
error fails closed to REJECT. Re-screening the same transaction returns
the same response (idempotent) — re-checking is legitimate for a guard.

## Files

- `guard-server.js` — HTTP server, HMAC verification, screening route,
  demo UI, response signing, one-time secret injection.
- `decision.js` — deterministic policy evaluation + field-element encoding.
- `prove.js` — local Groth16 proving with snarkjs.
- `kurier.js` — Kurier submit/poll client.
- `guard-harness.js` — self-test: unit checks, preflight, bad-signature
  rejection, live platform decisions, live screenings with local proof
  verification, re-screening, rate limiting.
- `circuit/` — the official gatekeeper circuit artifacts (wasm, zkey,
  verification key) and the test vectors.

## Test it

```sh
node guard-harness.js
```

The harness runs unit checks, a signed preflight, a bad-signature
rejection, live decisions for all seven trap types on the platform route,
live screenings for all six screening variants (each proof re-verified
locally), a malformed-request check, a re-screening check, and a rate
limit check.
