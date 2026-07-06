# Ratify Protocol — Roadmap

Companion to [`SPEC.md`](../SPEC.md), [`EXPLAINED.md`](EXPLAINED.md), and [`AGENT_TO_AGENT.md`](AGENT_TO_AGENT.md).

---

This roadmap has three buckets: **shipped** (in the current release), **planned** (backward-compatible, next releases), and **v2** (wire-breaking). Anything not listed is either in [Not planned](#not-planned-explicit-scope-boundary) or hasn't been proposed yet — see [How to propose additions](#how-to-propose-additions).

---

## Shipped

All v1.1 features below are backward-compatible with v1.0 and shipped in v1.0.0-alpha.5; the C/C++ SDK and its full conformance landed across alpha.8–alpha.10. Legacy v1.0 bundles continue to verify in v1.1 verifiers. The canonical test-vector suite (`testvectors/v1/`) proves cross-SDK conformance across Go, TypeScript, Python, Rust, and C/C++ — see [`CHANGELOG.md`](../CHANGELOG.md) for the count at each release.

### Continuous real-time interactions

| Feature | Spec | What it solves | Fixtures |
|---------|------|---------------|----------|
| **Session binding** | §5.8, §6.4.2 | A 32-byte `session_context` in the challenge signable binds a bundle to one verifier. Prevents stolen bundles from being replayed at a different endpoint. | 2 |
| **Stream sequence numbers** | §5.8, §6.4.2 | `stream_id` + `stream_seq` in the challenge signable detect replay, reorder, and omission within a multi-turn conversation. | 6 |
| **Session cert cache** | §5.13, §6.4.8 | After a full chain verification, the verifier issues an HMAC-based `SessionToken`. Subsequent turns verify the token + a fresh challenge signature — no chain re-verification. ~95% reduction in per-turn crypto work. | 5 |
| **Push-based revocation** | §5.11, §6.4.5 | Signed `RevocationPush` delta payload lets issuers push revocations to subscribed verifiers in real time. `ForceRevocationCheck` option forces a fresh check on high-stakes endpoints. | 1 |
| **Challenge forwarding defense** | §15.1 | Session binding (above) defeats the attack where a malicious verifier V2 relays V1's challenge to an agent. The agent signs with V2's context; V1 rejects the mismatch. | 1 |

### Tamper-evident transaction streams

| Feature | Spec | What it solves | Fixtures |
|---------|------|---------------|----------|
| **Transaction receipt envelope** | §5.14, §6.4.7 | Canonical `TransactionReceipt` where every party signs the same signable (terms + sorted party set + transaction ID). Generic verifier checks the envelope; app-specific verifiers interpret the terms. | 5 |
| **Multi-party receipt atomicity** | §5.14, §6.4.7 | Because the signable includes the full sorted party set, adding, removing, or changing any party invalidates every existing signature. No partial-valid state. | (same) |
| **Witness append-only log** | §5.12, §6.4.6 | Signed `WitnessEntry` defines the hash-chain shape for append-only audit logs. Any party can operate a witness. v1.1 defines the shape; operating a scalable witness is a deployment concern. | 1 |
| **Key rotation statement** | §5.15, §6.4.4 | `KeyRotationStatement` signed by both old and new root keys. Auditors and registries can verify identity continuity across key rotations. | 2 |

---

## What v1.0 already guarantees (baseline)

- **Hybrid quantum-safe signatures** (Ed25519 + ML-DSA-65). Harvest-now-decrypt-later attacks don't work.
- **Per-interaction liveness** via challenge-response (≤5 minute window, single-use challenge).
- **Chain authorization** with scope intersection. An intermediate cannot grant what it did not receive.
- **Explicit revocation** with signed revocation lists. Verifiers cache and fail-closed on unreachability.
- **Cryptographic tamper-evidence** per object. Every `DelegationCert`, `ProofBundle`, and `RevocationList` is signed; byte-level modification is detected.
- **54 canonical scopes** organized by domain, plus wildcards and a `custom:` extension pattern.
- **First-class constraints** (geo, time-window, speed, amount, rate) evaluated at verify time against caller-supplied context.
- **Three key-custody modes** — self-custody (device-held keys), custodial (server-side envelope encryption), and delegated custody (enterprise IdP as root). Self-custody is the strongest mode; custodial users can upgrade to self-custody via `KeyRotationStatement` at any time. See `SPEC.md` §15.2.

---

## Planned — next releases (backward-compatible)

### v1.0.0-alpha.11 — docs & spec hardening (RELEASED 2026-07-06; no wire change, no protocol or SDK code change)

- README truth pass: representative demo transcript, surface the shipped v1.1 feature set, accurate repository layout.
- SPEC additions: §15.4 trust anchors and public-key discovery, §15.5 revocation freshness, §15.6 verifier clock discipline, §15.7 constraint attestation limits, threat T12 (key substitution), SessionToken lifetime and multi-instance guidance (§5.13), crypto-agility note (§12).
- Local test gate (`scripts/test-all.sh`) now runs the C/C++ SDK, matching what CI and `docs/RELEASES.md` already claimed.
- All 59 canonical fixtures (the count at the time) byte-identical to alpha.10.

### v1.0.0-alpha.12 — protocol additions (below)

The two items below are scopes and features identified through production adapter design. No wire format change required — new `scope.go` entries, updated SPEC §9/§4, and new test fixtures. Adding fixtures changes the canonical fixture count; the release includes a full sweep of the documented count plus a fixture-count check in `scripts/check-release-sync.sh`.

---

### No-expiry sentinel — `ExpiresAt = 4070908799`

**Status:** Implemented — ships in v1.0.0-alpha.12. Normative in SPEC §5.1 + §5.7; fixture `no_expiry_cert`; no-expiry sentinel constant + helper in every SDK (Go `NoExpirySentinel`/`IsNoExpiry()`, TS `NO_EXPIRY_SENTINEL`/`isNoExpiry()`, Python/Rust `NO_EXPIRY_SENTINEL`/`is_no_expiry()`, C `ratify_no_expiry_sentinel()`/`ratify_expires_at_is_no_expiry()`).

**Problem:** `DelegationCert.ExpiresAt` is `int64` (Unix timestamp). The struct has no null/optional representation. Users of the Ratify Verify managed platform can grant delegations with "no expiry (until revoked)," which the platform stores as `NULL` in the database. The cert that gets signed must still have a finite `ExpiresAt` value for protocol compliance.

**Current implementation:** The Ratify platform uses `4070908799` (2099-12-31 23:59:59 UTC) as a sentinel for "no expiry" in the signed cert. The platform layer:
- Writes `NULL` in `ratify_delegation_certs.expires_at` (the canonical no-expiry signal)
- Writes `ExpiresAt = 4070908799` in the signed `DelegationCert` struct
- Treats `expires_at IS NULL` as "never expires" for verification liveness

**Problem for SDK consumers:** Offline verifiers using only the protocol SDK see `ExpiresAt = 4070908799` and have no way to distinguish "no expiry" from a cert that legitimately expires in 2099. They may apply organizational policy caps incorrectly.

**Proposed normalization:**
1. Define `4070908799` as a normative sentinel in SPEC §4.3 with required display and policy behavior.
2. Require all conformant SDKs to treat `ExpiresAt == 4070908799` as "no expiry (until revoked)" in display and policy evaluation — not as a literal 2099 expiry.
3. Add a conformance fixture: `no_expiry_cert.json` with `ExpiresAt = 4070908799`, verify that all SDKs accept it as valid without treating it as expired.

**Alternative (v2.0):** Add `NoExpiry bool` or `ExpiresAt *int64` to `DelegationCert`. This is a wire-breaking change and belongs in v2.0 rather than a v1.x patch.

**Until this ships:** Platforms consuming the offline SDK should treat `ExpiresAt > (now + 50 years)` as "no expiry" for display purposes, and rely on Ratify's managed revocation rather than local expiry checks for these certs.

---

### `presence:represent` — agent representation of a human

**Status:** Implemented — ships in v1.0.0-alpha.12. SPEC §9.1; fixtures `presence_represent_allowed` + `reject_presence_sensitive_wildcard`.

**Problem it solves:**

The current scope vocabulary covers what an agent *does* (attend a meeting, speak, record). It does not cover what an agent *is* in a given context — specifically, an agent that is attending and interacting *as a proxy for* a named human principal, not merely alongside them.

Three scenarios, all requiring a distinct scope:

| Scenario | Current scopes | Gap |
|---|---|---|
| **Attendee bot** — Otter joins Marcus's meeting, takes notes | `meeting:attend`, `meeting:speak` | No gap — covered |
| **Representative agent** — Marcus's AI agent attends on his behalf, speaks and acts as his representative (does not look like him) | `meeting:attend` + `meeting:speak` | No scope asserts "this agent IS Marcus's representative" |
| **Likeness agent** — Tavus agent that looks, sounds, and responds like Marcus, trained on his knowledge | `generate:deepfake` + `meeting:video` + `meeting:speak` | `generate:deepfake` covers content generation, not real-time identity representation. A verifier cannot tell from scopes alone that this agent is presenting as Marcus. |

**Why `generate:deepfake` is not sufficient:**

`generate:deepfake` means "generate content imitating a real person." It is a content-creation scope. Representation is a presence and identity scope — it describes the agent's relationship to the principal in a real-time interaction, not the content it generates. An agent could hold `generate:deepfake` without representing the principal in a meeting, and could represent the principal without generating likeness content.

**Proposed scope:**

```
presence:represent   (sensitive)
```

Semantics: "This agent is authorized to attend and interact as a direct representative of the principal. Other parties in the interaction may be interacting with this agent as if it were the principal."

Sensitive by design — requires explicit human confirmation beyond standard delegation, because the scope asserts identity representation, not just task execution.

**Companion disclosure flag — considered and rejected (2026-07-06):**

An earlier draft proposed a boolean `requires_disclosure` constraint (default `true`) on certs carrying this scope, with the protocol defining the constraint and applications enforcing it. Rejected — see the locked decisions below: a verify-time constraint cannot verify that disclosure actually happened, so it would assert an obligation the protocol is structurally unable to check. Disclosure is platform policy, carried in the SPEC as a non-normative expectation.

**Wire impact:** None. New scope string + `sensitiveScopes` entry + `validScopes` entry. Fully backward-compatible. v1.0 verifiers that don't know this scope treat it as unknown and may reject it (correct fail-closed behavior for unknown sensitive scopes).

**Design decisions (locked 2026-07-06):**
- **No implication.** `presence:represent` does NOT imply `identity:prove`. Issuers grant both explicitly when both are needed. Scope lists stay literal — effective authority is exactly the chain intersection, with no hidden expansion table for verifiers or auditors to consult.
- **One scope, no sub-qualifiers.** `presence:represent:voice` / `presence:represent:likeness` are deferred until real adapter pressure proves the distinction is needed at the protocol layer. Fidelity distinctions live in platform-layer constraints for now. Adding sub-qualifier scopes later is a backward-compatible minor version; retiring a wrongly guessed one is not, and no scope-deprecation process exists yet.
- **Disclosure is platform policy, not a protocol constraint.** A `requires_disclosure` constraint would assert an obligation the verifier cannot verify at verify time — disclosure happens in the application UI after verification. The SPEC scope entry will carry a non-normative note that verifiers accepting this scope are expected to surface the representation relationship to other participants. If disclosure ever needs protocol-level teeth, the right mechanism is a disclosure attestation in the receipt/audit layer, designed against an actual compliance requirement.

---

### Agent-to-agent in real-time meeting surfaces

**Status:** Design decision recorded 2026-04-27. Not yet implemented.

**Problem it solves:**

The `AGENT_TO_AGENT.md` doc covers mutual presentation patterns for API-layer interactions. The meetings adapter introduces a distinct scenario: two agents from different organizations both attend the same Zoom meeting, each representing their respective human principals. The agents may interact with each other (Agent A speaking to Agent B) without either human present.

Current protocol handles this via mutual presentation (Pattern 1 in `AGENT_TO_AGENT.md`), but the meetings adapter needs to surface this clearly in the policy and dashboard layer: "Agent A (authorized by Alice at CorpX) spoke with Agent B (authorized by Bob at CorpY). Neither human was present."

This is not a protocol gap — the chain verification handles it. It is a scope and audit surfacing decision. Recording here so the meetings adapter dashboard design accounts for agent-to-agent sessions explicitly.

---

## v2.0 — future (wire-breaking, not yet started)

These features require changes to the wire format or new cryptographic primitives. They will not land until v2.0.0.

| Feature | Why v2 | Design intent |
|---------|--------|--------------|
| **Session-key derivation** | Requires X25519/ML-KEM hybrid key exchange — a new crypto primitive not in v1 | Pair Ratify proof-of-authorization with a hybrid KEX so both sides derive a shared session key in the same round-trip as verification. Analogous to TLS 1.3 combining certs + ECDHE. |
| **Multi-sig / threshold delegation** | Changes `DelegationCert` wire format — breaks all v1 SDKs | `MultiSigDelegationCert` with a signer list + threshold. At least `threshold` distinct signers must produce valid hybrid signatures. For enterprise 2-of-3 quorum on high-value delegations. |
| **Transparency log** | Significant operational scope — Certificate-Transparency-style infrastructure | Append-only log of revocation-list updates, operated by the issuer + external witnesses. Clients subscribe to the log and detect divergent views (selective suppression). |
| **Deeper chains** | Production data needed | Consider lifting `MAX_DELEGATION_CHAIN_DEPTH` from 3 to 5 based on real-world delegation topologies. |
| **CBOR wire format** | Bandwidth optimization | For mobile, IoT, and bandwidth-sensitive paths. JSON remains canonical for v1. |

v2 will ship with `testvectors/v2/` alongside v1 fixtures. A migration window of at least 12 months will let implementers support both.

---

## Not planned (explicit scope boundary)

The following are reasonable questions about Ratify's scope; v1 and v2 do NOT attempt them, by design:

- **Zero-knowledge selective disclosure.** *"Prove Alice authorized me without revealing her identity."* Research-level; pair with an external ZK layer if needed.
- **Confidential transaction amounts.** `TransactionReceipt.terms` is opaque to Ratify; hiding values is an application concern.
- **Agent-to-human authentication.** Ratify proves agents to verifiers. It does not prove humans to agents (biometric / World ID territory).
- **Arbitrary programmable policy language.** Use first-class `Constraint` objects for common bounds (geo, time, speed, amount, rate). For application-specific conditions (IP reputation, account state, inventory), use app policy around `Verify()`.

---

## How to propose additions

See [`RELEASES.md`](RELEASES.md). In short:

- **Clarification to an existing concept:** PR to SPEC.
- **Backward-compatible addition:** issue + design doc + PR with SDK updates and new fixtures. Minor version bump.
- **Wire-breaking:** issue + RFC-style design doc + 30-day discussion + reference implementation + full SDK coverage. Major version bump.

New gaps discovered through production deployment should be filed as issues with the `gap-analysis` label.
