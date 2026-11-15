# Wildcard track — research (Phase 1) + idea pick (Phase 2)

Date: 2026-11-15 16:33 WIB (09:33 UTC). Sources are the site's own pages,
fetched this session. Verbatim quotes are copied from those pages.

## Phase 1 — the track, exact

### 1. What "useful" means and how Wildcard is judged

Source: https://agentgames.zkverify.io/events/wildcard

> "A place for every useful agent."
> "If an agent helps someone do something real, it belongs here — on-chain
> or off-chain. Think stablecoin payments, DeFi strategies, or a wallet
> security guard; or an inbox assistant, a research agent, a support bot,
> or a direction no one has tried yet. No required stack, no required
> zkVerify. Just show the agent working and explain who it helps."

Judging ("What reviewers look for"):

> "### Useful problem — Show a clear need, who the agent helps, and why its
> work matters."
> "### Working implementation — Make it possible to understand what you
> built and see the agent in action."
> "### Clear explanation — Explain the workflow, key choices, and what the
> agent can and cannot do."
> "### Verifiability (optional plus) — If zkVerify makes an important claim
> checkable, explain how it helps. Agents without zkVerify remain
> eligible."
> "### Bonus (public share) — Just share your build publicly — what the
> agent is and a public demo. That's it."

No weights are published for these criteria. No scoring rubric is
published. Judging is manual (reviewers), not a leaderboard.

Prize: 100,000 VFY per track (1st 50,000, 2nd 30,000, 3rd 20,000).

Inspiration list on the page (starting points, not a checklist): zkTLS
("prove what your agent saw on the web"), agentic crypto payments, DeFi
trading & treasury, wallet & transaction guard ("An agent that screens
approvals and transactions for scams or risky permissions before
signing"), inbox/scheduling & ops, research & reporting, customer support
& knowledge.

### 2. What a submission needs

Source: https://agentgames.zkverify.io/events/wildcard ("Submission
requirements") + the dashboard's "Your submissions" section (seen by the
user on the My agents page).

> "AGENT LINK — A public repository, demo, or write-up showing the agent
> you built."
> "PUBLIC ENDPOINT — A public HTTPS endpoint for your agent, as requested
> in the submission form."
> "USE CASE — Explain the problem, who the agent helps, and what it
> actually does — any domain, on-chain or off-chain."
> "BUILD CONTEXT — Briefly describe how the agent works and the key
> decisions behind it."
> "ZKVERIFY (OPTIONAL) — If zkVerify strengthens your agent, explain the
> checkable claim and add a proof reference when available."

The dashboard's "Your submissions" section says: "Creator Track and
Wildcard entries — judged separately from the live games. You can enter
more than once." So Wildcard entries are submissions through the
dashboard's "New submission" flow (same as Creator Track), not scored
rounds. Multiple entries per participant are allowed.

Whether the Wildcard submission form REQUIRES the agent to be a
registered roster agent (with an HMAC secret) or accepts any endpoint
URL is NOT stated on the Wildcard page. ASSUMPTION (defensible): register
the second agent in the roster anyway. It gives a roster entry, its own
HMAC secret, and practice-mode testing, and the submission form asks for
the endpoint URL — a registered agent's endpoint satisfies that. The
parent should confirm the exact form fields when submitting (the form is
only visible from the user's own dashboard).

### 3. Deadline and judging

Source: https://agentgames.zkverify.io/events/wildcard + /rules.

All four tracks run 2026-10-21 to 2026-11-21. No separate Wildcard
submission deadline is published. ASSUMPTION (defensible): submissions
close when the season closes (21 Nov 2026). Winners are verified manually
after standings freeze (rules §1.1: "Winners are verified manually after
standings freeze — ensure all profile requirements are met before
competition closes"). Target: ready to register + submit by 20 Nov 2026.

### 4. Second-agent registration (own HMAC + endpoint + repo)

Source: https://agentgames.zkverify.io/rules §1.2, §1.3 + the dashboard
(My agents page, seen by the user).

> §1.2: "An agent is a program you write, host, and maintain. The
> platform does not run your code. You host it at a public HTTPS address
> and register that address during sign-up."
> "An agent must: Be reachable at a public HTTPS endpoint — no localhost,
> no private IP ranges, no custom ports. Respond to signed task requests
> within the deadline stated in each request. Sign its responses with the
> HMAC secret issued at registration. Handle task IDs as idempotency
> keys — the platform may retry after a network failure."

> §1.3: "When you register an agent, the platform generates a 32-byte
> random secret and shows it exactly once. Store it securely. Never
> commit it to a repository."

The dashboard allows up to 3 agents per participant ("Up to 3 agents per
participant — but only one may compete in each automated event (Proof
Gatekeeper, Steal the VFY)."). Registration flow (from the user's own
Gatekeeper registration): Dashboard → My Agents → Register agent → name +
repo URL + endpoint URL (+ event entries) → the HMAC secret is shown
exactly once → copy it immediately. A second agent gets its own HMAC
secret, its own endpoint, and its own repo. The secret is delivered to
the server through the same one-time inject endpoint (the parent has the
flow working).

### 5. Must the agent stay live at judging time?

Not stated explicitly anywhere on the site. The Wildcard page requires
the reviewers to "see the agent in action", and rules §1.4 makes uptime
the owner's responsibility ("If your agent is offline when the platform
delivers a task, you forfeit that task"). ASSUMPTION (defensible): the
endpoint should be live when reviewers check it, which is after the
season closes (21 Nov). A Docker cloud sandbox has a 24-hour hard ceiling
from creation, so the build sandbox will NOT be live at judging time.
Plan: re-create a fresh sandbox and re-deploy the agent on 20–21 Nov for
the judging window (same inject flow as the gatekeeper). The durable parts
of the submission are the public repo, the write-up, and the demo — those
do not expire.

## Phase 2 — the pick: ONE idea

### Chosen: SENTINEL — a wallet security guard

A user-facing agent that screens a crypto transaction (or approval)
against the user's own safety policy and returns a signed verdict plus a
Groth16 proof that the screening was performed correctly. The user is any
wallet holder who signs transactions. The problem is real: wallet
drainers and malicious approvals are the most common way crypto users
lose funds, and a guard that checks every transaction before signing —
with a proof that the check was actually done — is exactly the use case
the Wildcard page lists ("a wallet security guard").

How it maps onto the proven pipeline (no new circuit needed):

| Wallet-guard rule | Gatekeeper circuit check (same, proven) |
|---|---|
| The policy has not been tampered with | proofVkHash == registeredVkHash |
| The wallet can afford it | publicBalance >= minimum |
| The amount is within the per-transaction cap | amount <= maxTransfer |
| The recipient is the allowlisted one | recipient == conditionRecipient |
| The policy has not expired | currentBlock < expiryBlock |

The decision is APPROVE (safe to sign) or REJECT (do not sign), with a
reason code, a Groth16 proof (snarkjs, the official gatekeeper circuit,
VK already registered on zkVerify mainnet), public signals, and a signed
response. The proof is the product: it attests that the verdict is the
correct one for these exact inputs, and anyone can re-verify it locally
against the published verification key in the repo.

Interface: a public HTTPS endpoint with two routes. POST / (the platform
route: HMAC-verified, preflight + task handling, for the registered
agent) and POST /screen (the public demo route: no HMAC — it is a
screening service, the caller sends their own transaction + policy; rate
limited). A demo UI (a static page served by the same server) lets a
reviewer paste a transaction + policy and see the verdict, the reason,
the proof, and the verification status.

Why this is NOT a gatekeeper copy: different user (a wallet holder
protecting their own funds, not the competition platform), different
interface (a screening API + demo UI, not a task envelope), different
value (preventing a real loss, not scoring a game). The proof primitive
is shared because it is the right tool — the circuit proves exactly the
class of claim a guard needs. The Wildcard page explicitly lists a wallet
security guard as an inspiration, so it is in scope by the track's own
definition.

### Why the other ideas are weaker (not built)

- Anonymous voting (nullifier + Merkle membership), proof-of-solvency /
  proof-of-reserves, sealed-bid private auction, selective-disclosure
  identity, anonymous reporting: all need a NEW circom circuit (write,
  compile, trusted setup, VK registration). The gatekeeper circuit was
  downloaded pre-compiled; no circom toolchain is proven in this
  workspace, and a new circuit's VK is not registered on mainnet. The
  sandbox also cannot reach Kurier (egress allowlist: GitHub/npm/PyPI
  only), so a new VK could not be registered from the sandbox anyway.
  Multi-day effort with real risk, not buildable before 20 Nov with
  confidence. Stronger on novelty, weaker on every other criterion.
- zkTLS ("prove what your agent saw on the web"): needs a TLS-notary /
  MPC-TLS integration plus a circuit for the TLS transcript. Heavy
  integration, not buildable in the time.
- Agentic stablecoin payments: needs to move or prepare real funds; the
  user has a standing never-spend-without-approval rule and no funded
  wallet for this. The proof angle is also weak (the transfer is the
  action, not a proof).
- Off-chain research / inbox / support agents (no zkVerify): buildable,
  but the verifiability plus — the differentiator — is absent, and the
  "useful" bar is higher because many entries will be similar generic
  agents. Weaker than the guard on distinctiveness and on the
  verifiability criterion.

### Name
SENTINEL (proposed; the user can change it at registration). The
Gatekeeper agent is UNDERGROUND; SENTINEL is the guard that watches
over it — a second agent for the same account, in a different track.
