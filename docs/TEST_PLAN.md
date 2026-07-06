# Ratify Protocol Test Plan

**Companion to [`SPEC.md`](../SPEC.md) and [`SDKS.md`](SDKS.md). Defines how Ratify v1 is validated — from unit tests through external audit, and how every new language SDK proves it is conformant with the reference.**

**Last updated:** 2026-04-18
**Scope:** Ratify Protocol v1 (hybrid Ed25519 + ML-DSA-65 delegation, JSON wire format)

---

## Principles

1. **Every cryptographic check has an adversarial test.** If we check it, we prove it catches the attack.
2. **Test vectors are the ground truth.** Cross-implementation interop depends on a canonical set of inputs with known outputs, versioned alongside the spec. The fixtures at `testvectors/v1/` ARE the spec in runnable form.
3. **Fail-closed in the tests mirrors fail-closed in the verifier.** Ambiguous cases resolve to invalid, and the test fixture enforces that.
4. **Hybrid means both.** A signature is valid only if the Ed25519 AND the ML-DSA-65 component verify. Tests MUST cover single-component-failure cases — a tampered Ed25519 with a valid ML-DSA, and vice versa — and reject both.
5. **Cross-language interop is tested continuously.** Every PR in any SDK reruns the fixture suite; any drift between languages is a bug in at least one of them, not a spec ambiguity.
6. **Production telemetry is a test surface.** Verification counts, error code distributions, and latency percentiles are testable properties of the system.

---

## Layer 1 — Unit Tests (Go)

Location: `ratify/ratify_test.go` (6 tests shipped; this plan expands to ~35).

### 1.1 Happy path — extend current `TestDelegationRoundTrip`

- Depth-1 chain (current)
- Depth-2 chain (human → intermediate → agent)
- Depth-3 chain (human → org → department → agent)
- Wildcard scope granted, specific scope required

### 1.2 Cryptographic failures

- Tampered cert body (current `TestTamperedSignature`) — expand to per-field tampering (every field in `delegationSignable`)
- Wrong issuer public key in cert (mismatches signature)
- Signature from different private key
- Empty signature
- Truncated signature (< 64 bytes)
- Extended signature (> 64 bytes)

### 1.3 Chain validation

- `broken_chain` — cert[0].IssuerID ≠ cert[1].SubjectID
- `broken_chain_keys` — issuer key differs from previous subject key
- Chain depth 0 (empty `Delegations`)
- Chain depth > 3 (`MaxDelegationChainDepth`)
- Chain with loop (A → B → A)
- Chain with duplicate cert (same CertID twice)

### 1.4 Temporal validation

- `expired` (current `TestExpiredCert`)
- `not_yet_valid` (cert with IssuedAt in future)
- Challenge age = `ChallengeWindowSeconds` exactly (edge — accept)
- Challenge age = `ChallengeWindowSeconds + 1` (reject)
- Challenge with negative age (reject — future challenge)
- Clock skew: verifier clock 30s fast vs. signer

### 1.5 Revocation

- `revoked` (current `TestRevokedCert`)
- Revocation callback returns true only for intermediate cert (revocation must reject the whole bundle)
- Revocation callback nil (no check)
- Revocation callback panics (must not crash verifier; decide: propagate or catch and fail-closed — **spec gap**, see §8 Open Questions)

### 1.6 Agent / key binding

- `key_mismatch` — bundle.AgentPubKey ≠ cert[0].SubjectPubKey
- `id_mismatch` — bundle.AgentID ≠ cert[0].SubjectID
- Agent pubkey wrong length (`invalid_agent_key`)
- Agent signs challenge with *human's* private key (must fail)

### 1.7 Scope validation

- `TestScopeRejection` (current)
- `TestScopeWildcard` (current — meeting:* expansion)
- All four wildcard expansions (`meeting:*`, `comms:*`, `comms:message:*`, `comms:email:*`)
- Sensitive scope in a wildcard (must be rejected — `meeting:record` must not ride `meeting:*`)
- Unknown scope string (`ValidateScopes` rejects)
- Empty scope list with non-empty required scope (reject)
- Scope narrowing in multi-cert chain — **see Critical Security Test in §6**

### 1.8 Serialization round-trips

- Round-trip every public type through JSON: HumanRoot, AgentIdentity, DelegationCert, ProofBundle, VerifyResult, RevocationList, Anchor
- Round-trip with empty optional fields (Anchors=nil, etc.)
- Round-trip with UTF-8 strings in Name field

### 1.9 DeriveID

- Same pubkey → same ID
- 32-byte input → 32-char hex output (16 bytes of SHA-256)
- Different pubkeys → different IDs (basic collision sanity)

---

## Layer 2 — Property-Based / Fuzz Tests

Go 1.18+ native fuzzing.

### 2.1 Verifier never panics

```go
func FuzzVerify(f *testing.F) {
    f.Fuzz(func(t *testing.T, bundleJSON []byte) {
        var b ProofBundle
        _ = json.Unmarshal(bundleJSON, &b)
        _ = Verify(&b, VerifyOptions{}) // must not panic
    })
}
```

### 2.2 Any modified byte invalidates

For a valid bundle, flipping any single byte in any signed field must result in an invalid VerifyResult.

### 2.3 Canonical serialization is deterministic

For a given cert, `delegationSignBytes` must produce byte-identical output across 1000 calls.

### 2.4 Scope expansion is idempotent

`ExpandScopes(ExpandScopes(s)) == ExpandScopes(s)` for all scope lists.

### 2.5 ValidateScopes + ExpandScopes composition

Every output of `ExpandScopes` must satisfy `ValidateScopes` without error.

---

## Layer 3 — Canonical Test Vectors

This is the single highest-leverage test artifact for the open-source launch. Without cross-language test vectors, no JS or Python implementation can be verified correct.

**Status:** ✅ Implemented on `main` — **63 fixtures** generated and committed at `testvectors/v1/*.json`. Generator: `cmd/ratify-testvectors/main.go`. Conformance test: `TestConformanceVectors` in `ratify_test.go` loads every fixture and validates `Verify()` output; mirrored in each SDK's conformance harness (TS / Python / Rust). The v1.1 fixtures are not part of a public protocol tag until the next release.

### 3.1 Location

`testvectors/v1/*.json` — each file is a self-contained test case. All five SDKs read from the same directory.

### 3.2 Format

```json
{
  "name": "happy_path_depth_1_meeting_attend",
  "description": "Depth-1 delegation with meeting:attend scope, valid challenge.",
  "fixture": {
    "human_private_key_hex": "...",
    "human_public_key_hex": "...",
    "agent_private_key_hex": "...",
    "agent_public_key_hex": "...",
    "now": 1800000000,
    "challenge_at": 1800000000
  },
  "inputs": {
    "cert": { /* DelegationCert */ },
    "bundle": { /* ProofBundle */ }
  },
  "expected": {
    "delegation_sign_bytes_hex": "...",
    "challenge_sign_bytes_hex": "...",
    "verify_result": { /* VerifyResult */ }
  }
}
```

### 3.3 Current vectors

All **63 fixtures** present, generated deterministically, and passing conformance across Go / TypeScript / Python / Rust / C:

**Core v1 — 20 fixtures**

| Name | Kind | Purpose |
|---|---|---|
| `happy_path_depth_1` | verify | Basic positive case |
| `happy_path_depth_2` | verify | Chain verification |
| `happy_path_depth_3` | verify | Max depth |
| `reject_chain_too_deep` | verify | depth > 3 rejected |
| `reject_expired` | verify | Post-expiry |
| `reject_not_yet_valid` | verify | Pre-IssuedAt |
| `reject_stale_challenge` | verify | Challenge > 300s old |
| `reject_future_challenge` | verify | Negative age |
| `reject_tampered_scope` | verify | Scope appended post-signature |
| `reject_tampered_expiry` | verify | Expiry extended post-signature |
| `reject_wrong_key` | verify | Wrong signing key |
| `reject_broken_chain` | verify | IssuerID ≠ next.SubjectID |
| `reject_key_mismatch` | verify | bundle pubkey ≠ cert subject pubkey |
| `reject_bad_challenge_sig` | verify | Challenge signature forged |
| `reject_sensitive_wildcard` | verify | `meeting:record` not in `meeting:*` (parent holds `identity:delegate` so scope-semantics is the actual reason for rejection) |
| `reject_scope_escalation_depth_2` | verify | Intermediate claims more than it received (parent holds `identity:delegate`; rejected via `scope_denied` on required scope) |
| `revocation_middle_cert` | verify | Intermediate cert revoked (parent holds `identity:delegate`) |
| `wildcard_expansion_meeting` | scope | `meeting:*` expansion deterministic |
| `reject_unknown_scope` | scope | Scope outside canonical vocabulary and not a `custom:` extension |
| `revocation_list_signature_valid` | revocation | RevocationList signed by issuer |

**Sub-delegation gate — 2 fixtures (P0-1)**

| Name | Purpose |
|---|---|
| `sub_delegation_allowed` | Non-root parent grants `identity:delegate`; child cert accepted. |
| `sub_delegation_denied` | Non-root parent lacks `identity:delegate`; child cert rejected with `delegation_not_authorized`. |

**Constraint evaluation — 12 fixtures (P0-2 + unknown-type gate)**

| Name | Constraint type | Expected |
|---|---|---|
| `constraint_geo_circle_inside` | `geo_circle` | valid (inside radius) |
| `constraint_geo_circle_outside` | `geo_circle` | `constraint_denied` |
| `constraint_geo_circle_equator_origin` | `geo_circle` | valid; zero-valued lat/lon are real coordinates, not missing data |
| `constraint_geo_polygon_inside` | `geo_polygon` | valid (ray-casting) |
| `constraint_geo_bbox_denied` | `geo_bbox` | `constraint_denied` |
| `constraint_geo_bbox_antimeridian_inside` | `geo_bbox` | valid across a bbox that wraps the anti-meridian |
| `constraint_time_window_denied` | `time_window` | `constraint_denied` (non-wrapping) |
| `constraint_time_window_wrap_inside` | `time_window` | valid (22:00–06:00 wrap) |
| `constraint_max_amount_exceeds` | `max_amount` | `constraint_denied` |
| `constraint_max_speed_mps_denied` | `max_speed_mps` | `constraint_denied` |
| `constraint_max_rate_denied` | `max_rate` | `constraint_denied` |
| `constraint_unknown_denied` | (unknown type) | `constraint_unknown` — proves verifier fails closed on unrecognized constraint types |

**Session-bound challenge — 2 fixtures (v1.1)**

| Name | Purpose |
|---|---|
| `session_bound_challenge` | Challenge signature includes a 32-byte `session_context`; verifier accepts only when the same context is supplied. |
| `reject_session_context_mismatch` | Same bundle rejected when the verifier supplies a different session context. |

**Key rotation — 2 fixtures (v1.1)**

| Name | Purpose |
|---|---|
| `key_rotation_valid` | `KeyRotationStatement` signed by both old and new root keys verifies. |
| `reject_key_rotation_tampered` | Tampered statement fails verification after canonical sign-byte comparison still matches the tampered object. |

**Stream sequence numbers — 6 fixtures (v1.1)**

| Name | Purpose |
|---|---|
| `stream_bound_first_turn` | First accepted stream turn with `stream_seq=1`. |
| `stream_bound_next_turn` | Next accepted stream turn with `stream_seq=last_seen+1`. |
| `reject_stream_replay` | Reused stream sequence is rejected. |
| `reject_stream_seq_skip` | Skipped sequence number is rejected. |
| `reject_stream_id_mismatch` | Verifier stream ID mismatch is rejected. |
| `reject_stream_context_unverifiable` | Stream-bound bundle without verifier stream context is rejected. |

**Session cert cache — 5 fixtures (v1.1)**

| Name | Purpose |
|---|---|
| `session_token_valid` | Verifier-local token MAC and fresh challenge signature verify. |
| `reject_session_token_expired` | Expired session token is rejected. |
| `reject_session_token_tampered` | Token field tampering invalidates the MAC. |
| `reject_session_token_wrong_secret` | Token from another verifier secret is rejected. |
| `reject_session_token_bad_challenge_sig` | Fresh challenge signature failure rejects the streamed turn. |

**Transaction receipts — 5 fixtures (v1.1)**

| Name | Purpose |
|---|---|
| `transaction_receipt_two_party_valid` | Two-party receipt verifies with both party proofs and signatures. |
| `reject_transaction_receipt_missing_party_signature` | Missing party signature invalidates the receipt. |
| `reject_transaction_receipt_party_tampered` | Party-set tampering invalidates receipt signatures. |
| `reject_transaction_receipt_terms_tampered` | Terms tampering invalidates receipt signatures. |
| `reject_transaction_receipt_wrong_party_key` | Party key mismatch is rejected. |

**Revocation push, Witness, and challenge forwarding — 3 fixtures (v1.1)**

| Name | Purpose |
|---|---|
| `revocation_push_valid` | Signed revocation delta verifies against issuer key. |
| `witness_entry_valid` | Signed witness log entry verifies against witness key. |
| `reject_challenge_forwarding` | Session-context verifier binding rejects forwarded challenges. |

### 3.4 Test vector generator

`cmd/ratify-testvectors/main.go` — regenerates all vectors from fixed 32-byte seeds (`0x01…` for human root, `0x02…` for agent, etc.). Timestamps are fixed (`1800000000` = 2027-01-15 UTC). Challenges are SHA-256 of the fixture name. **Determinism is a required property:** `go run ./cmd/ratify-testvectors` produces byte-identical output to committed fixtures; any drift fails the conformance test.

Run to regenerate in place:

```bash
go run ./cmd/ratify-testvectors -out testvectors/v1
go test -run TestConformanceVectors ./...
```

### 3.5 Cross-language harness

`testvectors/run.sh` accepts a language binary (go, js, py) and runs every vector through it, comparing outputs. Part of the open-source repo.

---

## Layer 4 — Cross-language interop

**Status:** Go ↔ TypeScript ↔ Python ↔ Rust ↔ C all proven. All **63 fixtures** byte-identical across every pairing.

### 4.1 The NxN conformance matrix

Every SDK must pass the **63 canonical fixtures** when acting as a verifier against bundles produced by every other SDK (including itself). For N implementations the matrix is NxN:

|   | Go verifier | TS verifier | Python verifier | Rust verifier | C verifier |
|---|---|---|---|---|---|
| **Go signer** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **TS signer** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Python signer** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Rust signer** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **C signer** | ✅ | ✅ | ✅ | ✅ | ✅ |

All five SDKs produce byte-identical canonical JSON and parse each other's fixtures without drift. The fixture count of 63 breaks down by kind as: 46 verify + 2 scope + 5 session-token + 5 transaction-receipt + 2 key-rotation + 1 revocation-list + 1 revocation-push + 1 witness-entry. The v1.x additions (no-expiry sentinel, presence:represent) contribute 4 verify fixtures.

Each cell assertion: *given a signer in language A and a verifier in language B, for every one of the 63 fixtures, the verifier's `VerifyResult` matches the fixture's expected result byte-for-byte.* Any failure is canonical-serialization drift — the fix is always to make the two implementations produce identical signable bytes.

### 4.2 The single-component tamper test

Hybrid signatures introduce a new failure mode: a bundle where the Ed25519 component is valid but the ML-DSA-65 component is tampered (or vice versa). The fixture `reject_bad_challenge_sig` flips the last byte of both components; the verifier rejects with `bad_challenge_sig`. Every SDK MUST also pass targeted tests where:

- Only the Ed25519 component of `cert.signature` is tampered → verifier rejects with "Ed25519 signature invalid".
- Only the ML-DSA-65 component of `cert.signature` is tampered → verifier rejects with "ML-DSA-65 signature invalid".
- Only the Ed25519 component of `challenge_sig` is tampered → verifier rejects.
- Only the ML-DSA-65 component of `challenge_sig` is tampered → verifier rejects.

These tests are not yet canonical fixtures but SHOULD be added to each SDK's local test suite. A future v1.x fixture expansion should add these as shipped fixtures.

### 4.3 Determinism regression test

Every SDK with a fixture generator (currently only Go) MUST verify that regenerating fixtures produces byte-identical output to the committed set. Go CI runs:

```
go run ./cmd/ratify-testvectors -out /tmp/regen
diff -rq testvectors/v1/ /tmp/regen/        # MUST be empty
```

### 4.4 Continuous integration

The `.github/workflows/ci.yml` in this repo runs the following on every push and PR:

- Go vet + go test.
- Determinism check (generator rerun + diff).
- TypeScript typecheck + conformance suite.
- DCO sign-off enforcement on all commits.

When Python / Rust / other SDKs land, their CI jobs append to the same workflow, and cross-implementation assertions expand to fill the NxN matrix above.

---

## Layer 5 — API Integration Tests

Location: `api/ratify_handlers_test.go` (to be written).

### 5.1 Full lifecycle

- `POST /v1/ratify/challenge` → challenge returned, TTL verified
- `POST /v1/ratify/verify` with bundle signed against challenge → VerifyResult
- `POST /v1/ratify/verify` with same bundle again → reject (challenge consumed)

### 5.2 Challenge store behavior

- Challenge expires after 300s
- Store unavailable → challenge issuance fails cleanly (5xx with error code)
- Store unavailable mid-verify → fail-closed

### 5.3 Persistence behavior

- Root registration creates a record in the identity store
- Revocation creates a record in the revocation store; subsequent verify rejects
- Verification log — inserts at correct partition

### 5.4 Authentication

- Authenticated endpoints reject requests without JWT
- Authenticated endpoints reject expired JWTs
- Correct JWT → operation succeeds

---

## Layer 6 — Security / Adversarial Tests

### 6.1 Scope narrowing in multi-cert chains ✅ Resolved

**Status:** Fixed in `verify.go` — effective granted scope is the intersection of every cert's expanded scope set via `IntersectScopes`. Sensitive scopes never ride wildcards through any level. Four tests in `ratify_test.go` cover the adversarial and positive cases:

- `TestScopeNarrowingDepth2Escalation` — intermediate grants `files:write` without receiving it; rejected
- `TestScopeNarrowingDepth2Legitimate` — human grants `meeting:*`, intermediate narrows to `meeting:attend`; valid
- `TestScopeNarrowingWildcardSensitive` — intermediate attempts `meeting:record` with only `meeting:*` received; rejected
- `TestScopeNarrowingDepth3` — three-level chain with scope drops at each hop; only scopes surviving all three hops are granted

### 6.2 Replay attacks

- Replay a used server-issued challenge (must fail — enforced by single-use challenge store)
- Replay a bundle against a different session_id (must fail if the verifier binds to session)
- Replay a bundle after revocation (must fail)

### 6.3 Downgrade attacks

- Present v1 cert to v2 verifier (expected behavior documented)
- Present v2 cert to v1 verifier (rejected — `version_mismatch`)

### 6.4 Key confusion

- Human and agent use same pubkey (reject — self-delegation blocked)
- Challenge signed by human key instead of agent key (reject)

### 6.5 Encoding attacks

- Cert with leading/trailing whitespace in JSON (canonical bytes must be identical)
- Cert with Unicode in Name field (round-trip safe)
- Cert with maximum-length strings (no buffer overflow at server)

### 6.6 Timing attacks

- Signature verification must be constant-time (Go's `ed25519.Verify` already is, but add lint to prevent comparison shortcuts)

### 6.7 Resource exhaustion

- ProofBundle with 1 MB Challenge field (server limit enforced)
- ProofBundle with 1000 delegations (rejected — chain_too_deep)
- Concurrent challenge requests from single IP (rate limited)

---

## Layer 7 — Fuzzing

### 7.1 Go native fuzz targets

- `FuzzVerify` — random bytes → parsed bundle → Verify. No panic.
- `FuzzExpandScopes` — random strings → ExpandScopes. No panic, no infinite loop.
- `FuzzDelegationSignBytes` — random cert → serialize. Deterministic.

### 7.2 Continuous fuzzing

OSS-Fuzz submission for the open-source repo post v1.0 tag. Gets 24/7 fuzzing at Google's scale for free.

### 7.3 Corpus

Seeded from test vectors. Fuzz evolves new edge cases over time.

---

## Layer 8 — Load / Performance Tests

Tool: k6 or vegeta against a dev deployment.

### 8.1 Verify throughput SLO

- **Target:** 10,000 verifies/sec sustained at <100 ms p95
- Hot path: in-memory crypto + cache lookup + database revocation check
- Cold path: add verification log insert — verify doesn't block on it (async queue)

### 8.2 Revocation list size scaling

- 1K revoked certs — constant-time lookup
- 100K revoked certs — still constant-time (indexed database query or in-memory bloom filter?)
- 1M revoked certs — measure actual latency

### 8.3 Challenge endpoint burst

- 1000 challenge requests in 1 second from single verifier
- 100 verifiers × 100 challenges/sec = 10k RPS on `/v1/ratify/challenge`
- Challenge store handles it; Go HTTP server handles it

### 8.4 Memory envelope

- Single bundle verification: < 1 MB allocated
- No leaks over 1M verifications

---

## Layer 9 — External Audit

Post v1.0 tag, before category launch.

### 9.1 Target firms

- **Trail of Bits** — strong crypto and Go expertise, known for Signal-level protocol reviews
- **NCC Group** — broad security review, cheaper
- **Cure53** — fast turnaround, good for open-source

### 9.2 Scope

- Protocol design review (threat model, crypto choices, canonical serialization)
- Reference implementation code review (Go)
- API implementation review (handlers, auth, storage integration)

### 9.3 Budget and timeline

- $50–100k
- 4–6 weeks
- Report published publicly alongside v1.1 (industry standard)

### 9.4 Academic review

In parallel, an external academic cryptography reviewer audits the spec for peer-review-grade correctness. Blocks a formal white paper, not the v1.0 public release.

---

## Layer 10 — Public Conformance Suite

A web tool at `ratify.dev/test` (or similar) where any implementer can submit a ProofBundle JSON and see which checks pass / fail with detailed explanations.

Precedents: `webauthn.me`, `jwt.io`, `oauth.tools`. This is a proven adoption accelerator.

### 10.1 Implementation

- Static site + serverless function
- Uses the Go reference verifier
- Shows step-by-step check trace (structure → signatures → temporal → revocation → scope)
- Downloadable test vector library

### 10.2 Public availability

Ship alongside the v1.0 open-source announcement.

---

## Layer 11 — Production Telemetry

The `ratify_verification_log` table already exists. Build dashboards from it.

### 11.1 Required dashboards

- **Verify latency:** p50, p95, p99 per route
- **Error code distribution:** counts by `error_reason` over time
- **Cert age distribution:** IssuedAt → verification time
- **Revocation hit rate:** % of verifies that hit a revoked cert
- **Challenge-to-verify latency:** time from challenge issuance to verified bundle
- **Chain depth distribution:** % at depth 1, 2, 3

### 11.2 Alerts

- p95 verify latency > 100 ms (5 min window)
- Error rate > 1% (sustained 10 min)
- Revocation hit rate > 0.1% (possible attack signal)
- Challenge store unavailable > 30s

---

## Layer 12 — Real-World Pilot

Final proving ground. Everything above is artificial.

### 12.1 First pilot

- **Deployment:** One enterprise executive-protection deployment (the first verifier adoption)
- **Duration:** 90 days
- **Metrics:** verifications/day, error types observed in production, operator feedback on false positives/negatives

### 12.2 Second pilot — agent platform

Protocol conformance validated against multiple third-party agent platform integrations.

---

## Summary — Test Pyramid

```
                        ┌────────────────────┐
                        │ Real-world pilots  │  months
                        └────────────────────┘
                       ┌──────────────────────┐
                       │  External audit      │  weeks
                       └──────────────────────┘
                      ┌────────────────────────┐
                      │  Load / perf tests     │  days
                      └────────────────────────┘
                    ┌────────────────────────────┐
                    │  Interop / conformance     │  hours
                    └────────────────────────────┘
                  ┌────────────────────────────────┐
                  │  Security / adversarial tests  │  hours
                  └────────────────────────────────┘
                ┌────────────────────────────────────┐
                │  API integration tests             │  minutes
                └────────────────────────────────────┘
              ┌────────────────────────────────────────┐
              │  Property / fuzz tests                 │  minutes
              └────────────────────────────────────────┘
            ┌────────────────────────────────────────────┐
            │  Unit tests + test vectors                 │  seconds
            └────────────────────────────────────────────┘
```

---

## Known Open Questions (track to resolution before v1.0 public tag)

1. ~~**Scope narrowing semantics.** Effective granted scope = intersection of all chain scopes.~~ ✅ Resolved — implemented via `IntersectScopes`; see §6.1.
2. **Revocation callback panic behavior.** Catch and fail-closed, or propagate? Recommended: fail-closed with logged error.
3. **Revocation list freshness.** Max age before verifier fetches a new list? Recommended: 60 seconds, with webhook push for real-time revocation.
4. **Canonical JSON library for non-Go implementers.** Adopt RFC 8785 JCS or document implicit rules? Recommended: RFC 8785 for safety, but document Go's current `encoding/json` behavior as the reference for migration.
5. **Clock skew tolerance.** How much skew between issuer, agent, verifier? Recommended: ±60 seconds on IssuedAt, enforced via explicit `NotBefore` field in v1.1.
