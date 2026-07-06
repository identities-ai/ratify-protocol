# Ratify Protocol™: Explained

**A technical deep-dive into the architecture, threat model, and workflow patterns of the Ratify trust protocol.**

---

## 1. The Core Problem: The Transaction Horizon

In the transition from 2025 to 2026, AI agents are evolving from "assistants" that draft content to "actors" that **transact**. They are beginning to move money, book resources, enter into agreements, and coordinate with other agents in complex workflows without a human in the loop for every step.

As agents cross this "transaction horizon," two structural problems emerge:
1. **The Claim-of-Authorization Gap:** When an agent says, "I am Alice's agent," the receiving party (the verifier) has no cryptographic way to verify that claim. Today, trust reduces to "the AI says so."
2. **Agent-to-Agent Dominance:** As multi-agent systems proliferate, the trust layer must work entirely without a human present at the moment of the transaction.

Ratify is a cryptographic primitive designed to bridge this gap. It produces a signed, verifiable proof of *who authorized what, within which bounds, and for how long* — across voice, video, API, and Physical AI.

---

## 2. The Three Verbs

Ratify operates through three simple, symmetric verbs:

### DELEGATE: The principal authorizes the agent.
A principal (human or another agent) signs a **DelegationCert**. This certificate binds the principal's identity to the agent's identity and specifies a set of **Scopes** (allowed actions), **Constraints** (conditions like "only for amount < $100"), and an expiration date.

### PRESENT: The agent proves its authorization.
When the agent wants to perform an action, it collects its delegation certs and signs a fresh **Challenge** from the verifier using its own private key. This collection—the delegation chain plus the fresh signature—is a **ProofBundle**.

### VERIFY: The third party checks the proof.
The verifier runs the Ratify verifier algorithm on the ProofBundle. If the signatures match, the timestamps are valid, the scopes cover the requested action, and the liveness check (the challenge) passes, the verifier returns a deterministic **YES**.

---

## 3. Hybrid Cryptography: Quantum-Safe by Design

The "harvest now, decrypt later" threat is real. Any authorization proof signed today might be archived by an adversary and forged decades from now if today's cryptographic assumptions fail.

Ratify defends against this by requiring **hybrid signatures** for every object in the protocol:
- **Ed25519 (RFC 8032):** High-performance, classical elliptic-curve signatures.
- **ML-DSA-65 (NIST FIPS 204):** Post-quantum lattice-based signatures.

**Both signatures must verify.** If a quantum computer eventually breaks Ed25519, the ML-DSA-65 signature remains an unforgeable barrier. If a flaw is found in the newer ML-DSA-65 algorithm, the Ed25519 signature still holds the line.

---

## 4. Workflow Patterns

### Human-to-Agent (The Root)
Alice uses her master identity ("HumanRoot") to sign a delegation to her personal agent. This is the "root" of trust. Alice's private key material never leaves her secure device.

### Agent-to-Agent (Sub-delegation)
Alice's agent needs to hire a specialized "Travel Agent" to book a flight. Alice's agent sub-delegates a subset of its own scopes to the Travel Agent. The Travel Agent now carries a two-hop delegation chain: `Alice → Alice's Agent → Travel Agent`.

### Multi-hop Verifiability
When the Travel Agent presents the proof to the Airline, the Airline can see the entire chain. They don't just know that Alice's agent authorized the Travel Agent; they can cryptographically verify that *Alice herself* authorized the root agent to begin with.

---

## 5. Threat Model & Defenses

| Threat | Ratify Defense |
| :--- | :--- |
| **Replay Attacks** | Every ProofBundle includes a fresh, signed **Challenge** from the verifier. A bundle used 5 minutes ago is invalid now. |
| **Credential Theft** | Agent keys are short-lived or stored in secure enclaves. If an agent's key is stolen, the principal can revoke the delegation cert. |
| **Scope Creep** | The **Effective Scope** of a chain is the *intersection* of every link. An agent cannot grant more rights than it was given. |
| **Quantum Adversary** | Hybrid ML-DSA-65 signatures ensure that archived proofs cannot be forged even by a quantum-capable attacker. |
| **Privacy / Tracking** | While v1 uses persistent IDs for debuggability, the protocol supports ephemeral agent keys to minimize correlation across verifiers. |

---

## 6. SDK Provider Interfaces

The verifier's cryptographic core (chain check, hybrid signature, scope intersection, constraint evaluation) is universal — every conformant SDK implements it identically, and the same 62 fixtures regenerate byte-identical across languages.

But three of the verifier's responsibilities are inherently operational, and a single static spec cannot pin them down:

1. **Revocation freshness** — a CRL file polled once an hour is fine for a low-throughput verifier; a high-throughput payment endpoint needs sub-second push propagation.
2. **Policy evaluation** — quotas, geo-tagged kill switches, runtime overrides. These are stateful and verifier-local; they don't belong in a signed cert.
3. **Audit retention** — a developer's local log file is enough for staging; SOC2/ISO compliance requires a signed, append-only ledger.

The SDKs expose three pluggable hooks for these — `RevocationProvider`, `PolicyProvider`, `AuditProvider` — defined in SPEC §17. Each SDK ships with a no-op default; commercial verifiers (such as Ratify Verify) supply higher-performance, stateful implementations against the same interface. Bundles verified against one provider stack and bundles verified against another are byte-identical: the wire format does not change.

This is the build-vs-buy boundary, in one diagram:

```
[ open ] ProofBundle wire format ──────────  same bytes everywhere
[ open ] hybrid sig + chain walk + scope ─── same algorithm everywhere
[ open ] cert-bound Constraints ─────────── same evaluation everywhere
─────────────────────────────────────────── deterministic verifier core
[ hook ] RevocationProvider     ↔ local file  /  push-sync edge cache
[ hook ] PolicyProvider         ↔ none        /  Rego/OPA + quota
[ hook ] AuditProvider          ↔ stdout      /  signed immutable archive
[ opt  ] ConstraintEvaluator    ↔ none        /  extension type registry
[ opt  ] PolicyVerdict          ↔ none        /  HMAC-cached allow/deny
[ opt  ] AnchorResolver         ↔ none        /  SSO-bound identity lookup
[ opt  ] VerificationReceipt    ↔ none        /  signed audit chain
```

A bundle moves freely across all five SDKs. Where verifiers differ is in operational surface — latency, compliance posture, integration ergonomics — not in cryptography.

### Surface adapters (out of scope for this repository)

The integration code that turns a `ProofBundle` into a "Zoom auth gate," "Twilio SIP attestation," "AWS API Gateway authorizer," etc. — the **surface adapters** — lives in separate repositories (`ratify/zoom-sdk`, `ratify/voice-sdk`, …). Those are the home of proprietary "last-mile" integration code and are not addressed by this specification.

The protocol's contract stops at the `ProofBundle` wire format and the verifier algorithm. Anything above that — how a third-party platform's signaling layer is intercepted, how middleware is wired into a specific framework, how an incumbent product's auth model is mapped onto Ratify scopes — is integration work, not protocol work. Ratify Verify ships those adapters as commercial product; the specification does not prevent a third party from writing their own.

---

## 7. Implementation Status

Ratify is an open protocol. Reference implementations exist in **Go**, **TypeScript**, **Python**, **Rust**, and **C/C++**. The 62 canonical test vectors in the `testvectors/v1/` suite ensure that any conformant implementation is byte-for-byte interoperable. Each SDK also ships a provider-test suite covering the three SPEC §17 hooks.

For the normative specification, see [`SPEC.md`](../SPEC.md).
