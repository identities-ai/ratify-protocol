# Agent-to-Agent Patterns

**Three canonical patterns for agent-to-agent interactions in Ratify Protocol v1.**

Ratify is symmetric in both directions: the same data structures and verifier algorithm cover human-to-agent delegation *and* agent-to-agent transactions. This document walks through the three patterns implementers need in practice, each with a sequence diagram and a worked example using the protocol primitives.

**Prerequisites:** familiarity with [`SPEC.md`](../SPEC.md) §5 (data structures), §8 (hybrid cryptography), §9 (scope vocabulary), and §10 (verifier algorithm).

**Companion reference:** [`EXPLAINED.md`](EXPLAINED.md) §11 covers the performance envelope and when to apply each pattern in real-time vs. continuous workflows.

---

## Why agent-to-agent is a first-class concern

In 2026–2028, the dominant traffic shape of AI interactions is no longer human-to-AI. It is AI-to-AI. When your scheduling agent talks to someone else's scheduling agent about a meeting, when your buyer agent transacts with a seller agent about a purchase, when one MCP server invokes tools on another on behalf of a shared user — none of these have a human in the loop at the moment of the interaction. The trust layer must work without one.

Ratify handles this by making agents first-class cryptographic entities with their own hybrid keypairs. An agent can be a *subject* of a delegation (it receives authority), an *issuer* of a delegation (it sub-delegates), or both simultaneously. The protocol guarantees that any authority passed through the chain cannot exceed what was originally granted — §9.3 effective-scope intersection enforces this.

---

## Pattern 1 — Mutual presentation

Agent A (acting for Alice) interacts with Agent B (acting for Bob). Each side needs cryptographic proof that the other is authorized for this interaction.

### Sequence

```
Alice                                  Bob
  │ (has already signed)                 │ (has already signed)
  │ cert[Alice→A]:                       │ cert[Bob→B]:
  │   scope = meeting:*                  │   scope = meeting:*
  │   expires = +7 days                  │   expires = +7 days
  ▼                                      ▼
Agent A ─── connection setup ───── Agent B
  │                                      │
  │  1. Agent B issues challenge_B       │
  │     ◀──────────────────────          │
  │                                      │
  │  2. Agent A builds bundle_A:         │
  │        agent_id = A                  │
  │        agent_pub_key = A's pub       │
  │        delegations = [cert[Alice→A]] │
  │        challenge = challenge_B       │
  │        challenge_at = now            │
  │        challenge_sig = A.sign(...)   │
  │     ──────────bundle_A──────▶        │
  │                                      │  3. Bob's verifier runs Verify(bundle_A)
  │                                      │     → ✅ A is Alice's authorized agent
  │                                      │
  │  4. Agent A issues challenge_A       │
  │     ──────────────────────▶          │
  │                                      │  5. Agent B builds bundle_B:
  │                                      │        agent_id = B
  │                                      │        agent_pub_key = B's pub
  │                                      │        delegations = [cert[Bob→B]]
  │                                      │        challenge = challenge_A
  │                                      │        challenge_at = now
  │                                      │        challenge_sig = B.sign(...)
  │     ◀──────────bundle_B─────         │
  │                                      │
  │  6. Alice's verifier runs            │
  │     Verify(bundle_B)                 │
  │     → ✅ B is Bob's authorized agent │
  │                                      │
  ▼                                      ▼
  Both sides know who they're            Both sides know who they're
  talking to, cryptographically,         talking to, cryptographically,
  without a trusted intermediary.        without a trusted intermediary.
```

### What it proves

- **Identity binding:** A's claim *"I'm Alice's agent"* is verifiable by Bob's side with no OAuth flow, no platform-level trust, no shared vendor.
- **Scope authority:** Alice's cert says what A is allowed to do; if Alice granted `meeting:*` but this interaction requires `meeting:record`, B rejects A's request.
- **Liveness:** The challenge signatures prove A's (and B's) private keys are live right now. A stolen but revoked cert cannot be used here — revocation check fails.
- **Mutual authentication:** Each side gets the same guarantees about the other. Neither side can impersonate their counterparty even over a compromised channel (the transport is uplifted by the hybrid signatures regardless of TLS state).

### When to use

- AI-to-AI meetings, calls, or real-time collaboration.
- Bilateral data exchanges between agents on different platforms.
- Handshake phase of any agent-agent transaction (Pattern 3).

### What it doesn't solve

Transport confidentiality — use TLS underneath. Metadata privacy — both sides learn each other's `human_id`. Ratify does not attempt to hide *that* Alice is talking to Bob; it only ensures neither can impersonate.

---

## Pattern 2 — Sub-delegation

An organization's tenant admin delegates to a mid-tier agent, which further delegates to a leaf agent that actually performs the work. Each hop narrows the scope.

### Sequence

```
Tenant Admin (human)
  │  signs cert[tenant→org]:
  │    issuer = tenant_admin
  │    subject = org_agent
  │    scope = [comms:*, meeting:*, identity:delegate]
  │    expires = +30 days
  ▼
Org-level Agent
  │  (received cert[tenant→org]; may sub-delegate because identity:delegate ∈ scope)
  │  signs cert[org→dept]:
  │    issuer = org_agent
  │    subject = dept_agent
  │    scope = [comms:email:*, meeting:attend, identity:delegate]
  │    expires = +7 days
  ▼
Dept-level Agent
  │  signs cert[dept→leaf]:
  │    issuer = dept_agent
  │    subject = leaf_agent
  │    scope = [comms:email:send]
  │    expires = +24 hours
  ▼
Leaf Agent
  │  presents ProofBundle to a verifier:
  │    agent_id = leaf_agent_id
  │    agent_pub_key = leaf_pub
  │    delegations = [
  │      cert[dept→leaf],   // index 0 (leaf-facing)
  │      cert[org→dept],    // index 1
  │      cert[tenant→org]   // index 2 (root-facing)
  │    ]
  │    challenge + challenge_sig
  ▼
Verifier runs Verify():
  effective_scope = intersect(
    {comms:email:send},                                         // cert[0]
    {comms:email:read, comms:email:send, identity:delegate},    // cert[1] (expanded)
    {comms:*, meeting:*, identity:delegate}                      // cert[2] (expanded)
  )
  = {comms:email:send}
```

### What's enforced

- **Scope narrowing is monotonic.** No matter what `cert[i]` claims, the effective scope at the leaf is the intersection — cannot exceed the root.
- **`identity:delegate` is required to sub-delegate.** If the tenant admin had not granted `identity:delegate` to the org agent, the org agent could still sign a cert[org→dept], but a conformant verifier rejects the chain with `delegation_not_authorized`. The grant must be explicit; wildcards never introduce `identity:delegate` because it is a sensitive scope.
- **Shorter TTLs at leaf levels are good practice.** Even if the tenant admin issued a 30-day cert, the leaf cert being 24 hours limits the blast radius of leaf-key compromise.
- **Any cert in the chain can be revoked.** Revocation of `cert[org→dept]` at minute 5 invalidates the leaf's ability to present *any* bundle from minute ~6 onward (once the revocation list propagates).

### When to use

- Enterprise deployments where a tenant admin grants broad authority to a platform, which then fans out to specific bots or automation targets.
- Agent frameworks (LangChain, AutoGen) where a parent agent routes subtasks to child agents — the Ratify chain mirrors the task decomposition.
- Multi-tenant SaaS where each customer's admin is the root of trust within their own tenant.

### Chain depth limit

`MAX_DELEGATION_CHAIN_DEPTH = 3` in v1. This bounds the chain length and the verify-time cost (each level adds two hybrid signature verifications). v2 may allow deeper chains; for v1, organizations that need more than three levels should flatten (e.g., have the tenant admin directly delegate to leaves rather than passing through intermediate tiers).

---

## Pattern 3 — Transaction receipt

Two agents conclude a bounded, high-stakes transaction. Both parties want a cryptographic artifact that survives the session — a receipt they can produce months later to prove *who committed to what, when, with what authority.*

### Sequence

```
Alice's buyer agent (A)                    Acme's seller agent (B)
  │  cert[Alice→A]:                          │  cert[Acme→B]:
  │    scope = [transact:purchase,           │    scope = [transact:sell,
  │             payments:send,               │             payments:receive,
  │             custom:acme:max_spend:10000] │             custom:acme:compute]
  │    expires = +24 hours                   │    expires = +30 days
  │                                          │
  │  ───── Pattern 1 mutual presentation ─── │
  │        (both sides verify each other)    │
  │                                          │
  │  Application-layer negotiation:          │
  │    terms = {                             │
  │      "kind": "compute_purchase",         │
  │      "quantity": "100 GPU-hours",        │
  │      "price_usd": 5000,                  │
  │      "delivery_by": 1800100000,          │
  │      "tx_id": "tx-<uuid>"                │
  │    }                                     │
  │                                          │
  │  A: terms_bytes = CanonicalJSON(terms)   │
  │  A: sig_A = signBoth(terms_bytes,        │
  │              A_hybrid_priv)              │
  │     ──────── terms + sig_A ───────▶      │
  │                                          │
  │                                          │  B verifies:
  │                                          │    1. verifyBoth(terms_bytes,
  │                                          │                  sig_A,
  │                                          │                  A_hybrid_pub)
  │                                          │       == null  ✓
  │                                          │    2. Check A's delegation chain
  │                                          │       (was checked in Pattern 1)
  │                                          │    3. Application policy:
  │                                          │       price ≤ A's max? ✓
  │                                          │       B has scope to sell? ✓
  │                                          │
  │                                          │  B: sig_B = signBoth(terms_bytes,
  │                                          │              B_hybrid_priv)
  │     ◀──────── sig_B ─────────            │
  │                                          │
  │  A verifies sig_B analogously            │
  │                                          │
  ▼                                          ▼
  Both sides persist receipt:
    {
      "terms": <terms>,                       // what was agreed
      "signature_A": sig_A,                   // A's commitment
      "signature_B": sig_B,                   // B's commitment
      "cert_chain_A": [cert[Alice→A]],        // A's authority at time of transaction
      "cert_chain_B": [cert[Acme→B]],         // B's authority at time of transaction
      "revocation_state_A": <optional>,       // signed revocation list snapshot
      "revocation_state_B": <optional>,
      "timestamp": 1800005000
    }
```

### What the receipt proves, months later

Six months after the transaction, either party can produce this artifact and a third-party auditor can verify:

- **Who committed:** The ids inside cert_chain_A and cert_chain_B resolve to Alice and Acme respectively.
- **What they committed to:** The exact `terms` JSON — any change produces different canonical bytes, which fails both signatures.
- **With what authority:** The scope on each cert is cryptographically binding. If the terms included something outside cert_chain_A's scope, the application layer should have rejected the transaction at signing time.
- **At what time:** `timestamp` is advisory; the cryptographic anchor is `expires_at` on each cert. If a cert was expired at the moment of transaction, its signature is still mathematically valid but the transaction is disputable.
- **That it wasn't revoked:** If optional revocation-state snapshots are included, the auditor can confirm neither cert was in the revocation list at transaction time.

### What the receipt does NOT prove

- **That the transaction was executed.** That's a separate application concern (delivery confirmation, payment settlement, etc.). Ratify proves authorization and commitment, not performance.
- **That the terms were fair or meaningful.** Alice's buyer agent signed `{price_usd: 5000}`; Ratify guarantees Alice authorized that signature but not that $5000 was a fair price. Application policy (price caps, fraud detection, anomaly monitoring) must be layered on top.
- **That both sides actually received each other's signatures before executing.** Delivery guarantees are transport-layer concerns.

### What the spec defines and what it doesn't

- **Defined:** `HybridSignature` is the authoritative signature primitive for any receipt. `CanonicalJSON(terms)` gives deterministic signable bytes regardless of which language produced the `terms` object. Applications that hash the terms will get the same bytes across implementations.
- **v1.1 envelope:** [`TRANSACTION_RECEIPTS.md`](TRANSACTION_RECEIPTS.md) defines a canonical receipt envelope that binds the transaction ID, schema URI, terms bytes, party set, and every party signature.
- **NOT defined in tagged v1:** the schema of `terms` itself. That's application-specific — a compute-purchase receipt looks different from a calendar-booking receipt. v1 deliberately leaves this open until receipt fixtures and SDK APIs ship.

### When to use

- Agent-driven commerce (payments, purchases, resource allocation).
- Autonomous negotiations with financial or legal consequences.
- Any interaction where a later dispute requires cryptographic evidence of what was agreed.
- Chained receipts in a multi-step workflow (each step signs the previous step's hash).

---

## Common concerns across all three patterns

### Clock skew

Each side's verifier checks `now ∈ [issued_at, expires_at]` using *their own clock*. Significant clock drift between two parties can cause a valid cert to look expired on one side and fresh on the other. Mitigation:

- Run NTP on every Ratify-using process.
- Use `CHALLENGE_WINDOW_SECONDS` (300s) as the effective skew tolerance for challenge freshness.
- Prefer short cert TTLs (hours, not weeks) for high-stakes transactions — skew matters more when the window is short.

### Key rotation mid-interaction

If Alice rotates her root key while Agent A is mid-interaction with Agent B, Agent A's cert is still valid until its own expiry (unless Alice explicitly revoked it). B's verifier will still accept it. If Alice wants rotation to take effect immediately, she must also revoke outstanding certs — key rotation alone does not implicitly revoke prior grants.

### Multi-party agreements

Ratify v1 is pairwise. For three-party agreements (A, B, and C all commit to the same terms), the v1 approach is to produce three pairwise receipts (A-B, A-C, B-C) sharing the same `terms` bytes. A v2 extension may add a native *group signature* construct; until then, three pairwise receipts are the canonical pattern.

### Privacy of counterparty identities

A Ratify proof reveals `human_id` (the root) and `agent_id` of each party. For privacy-sensitive contexts (legal representation, certain financial transactions) this may be too much disclosure. v1 does not provide zero-knowledge alternatives; parties who need unlinkability should either:

- Use short-lived, single-purpose agent identities (each new transaction gets a freshly-generated agent keypair).
- Layer an onion-routing or privacy-preserving protocol on top of the transport.
- Wait for a future v2 zero-knowledge extension.

---

## Reference implementations

The v1 patterns are covered by the canonical test vectors at `testvectors/v1/` as follows:

- **Mutual presentation:** any `happy_path_depth_1` fixture, run twice with swapped roles.
- **Sub-delegation:** `happy_path_depth_2` (tenant → intermediate → leaf) and `happy_path_depth_3` (tenant → org → dept → leaf). The effective scope intersection is verified in every case.
- **Transaction receipt:** v1.1 receipt fixtures cover the canonical envelope, party-set atomicity, and tamper rejection. Ratify still treats the `terms` schema as application-defined; generic verifiers check envelope integrity and dispatch to schema-specific policy only when business-term interpretation is required.

Application developers building on Ratify should construct their own application-specific fixtures for their receipt shapes and include them in their test suite.
