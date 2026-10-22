# Protocol v2 test vectors

These public files contain fixed inputs and expected outputs for SDK conformance.
Any private seeds included in a vector are deterministic test data only. They
must never be used as production keys.

`delegation-signature.json` pins canonical signable bytes, the complete signing
transcript and ML-DSA context, hybrid keys and signatures, a full v2 key ID,
the external signer `tr` and `mu` bytes, deterministic test seeds, and common
negative mutations. Recompute the external signer bytes with
`python3 testvectors/v2/derive-external-mu.py`; the TypeScript test also binds
`mu` to the deterministic ML-DSA signature through its external-μ verifier.
`operation-session-context.json`
pins the shared operation and session-context encodings and their Verify API
representations. `challenge-claim.json` pins the challenge digest and claim ID
with its verifier namespace and replay epoch, including UTF-8 byte length,
embedded NUL, epoch zero, and the maximum safe epoch. `key-rotation-signature.json`
pins the v2 rotation body,
signature-independent chain digest, old-key and new-key signing contexts,
deterministic signatures, and complete wire bytes.

## Generated corpus

The following files are produced by `go run ./cmd/ratify-v2-vectors` from the
repository root (source: `internal/v2vectors`). Output is deterministic: Ed25519
is deterministic and ML-DSA-65 is signed without hedging. Expected results are
written in the generator from SPEC-v2 rules, not read back from the verifier;
`v2_conformance_test.go` then requires the Go reference to agree with every
vector, and `internal/v2vectors` fails if any committed file differs from the
generator output. `key-rotation-signature.json` is also produced by this
generator (byte-identical to its first publication);
`go run ./cmd/ratify-v2-rotation-vectors` still regenerates only that file.
`delegation-signature.json`, `operation-session-context.json`, and
`challenge-claim.json` are hand-maintained and checked by their own Go and SDK
tests.

| File | Contents |
| --- | --- |
| `keys.json` | 18 fixture keys (seeds, public keys, full 256-bit `key_id_v2`, the v1 128-bit ID of the same key) and 6 invalid v2 key IDs that MUST be rejected wherever a v2 key ID is required. |
| `objects.json` | 10 positive objects covering all nine codes (14 signatures): wire bytes that MUST re-encode identically, the exact signable projection, `M`, ML-DSA context, external-μ `tr`/`mu`, both signature components, and `delegation_digest`, `BundleHashV2`, `session_context`, `ChallengeClaimDigest`, claim ID with replay epoch, `StatusEvidenceDigest`, `StatementBodyDigest`, the receipt outbox body, and transaction context, party request hash, and party session context. |
| `object-negatives.json` | 273 single-fault negatives with a language-neutral `expected_error_class`: a mutation of every signed field of every object, each signature component broken separately, component swaps, cross-code and unregistered-code (`0x0000`, `0x000a`, `0xffff`) signatures, wrong ML-DSA contexts, canonical Ed25519 rejections (S+L, identity A and R, non-canonical A, mixed-order A with a cofactored-valid signature), v1 objects and 128-bit IDs, ID/key mismatch, old-key substitution, new-key proof failure, duplicate `(issuer_id, cert_id)`, swapped chain, wrong challenge and session-context lengths, non-canonical encodings, transaction hash/context/signature-set failures, receipt decision/status inconsistencies, and receipt/bundle binding mismatches, and the closed v2 constraint registry (v1 float members, fractions and exponents, out-of-range integers, bad `HH:MM` and `tz`, audience bounds, reserved geo types with v1 members), and every wire timestamp one second past 253402300799 and below 0 (`malformed` at decode). |
| `verifier-ordering.json` | 163 end-to-end live-verifier cases (53 pre-claim, 2 replay, 106 committed, 2 evaluating), including 10 Middleware Custody Profile cases (SPEC-v2 §7.15) whose session context binds a swapped tenant, session, invocation, receiver, agent, scope, operation, resource, path, or payload, with scripted Part B dependencies: decode before configuration bounds and supplied request context (amount and currency) rejected before claim, pre-claim checks, `time_window` against the pinned IANA tzdata `2025c` (configured `tzdb_version` absent or mismatched, unknown zone, exact local-minute horizon, midnight wrap, a horizon clamped to the end of the timestamp domain), `resource_path` evaluation order for every `path_prefix` form against every request form, `max_amount` micro-units, the delegation lifetime bound, replay, signed status evidence applied through an anchored `SecurityJournalV2` (provider, batch, journal including one bounded compare-and-swap retry, and role-separation failures including a status key equal to the verifier key), trust outcomes including `ambiguous`, the post-claim context-policy mismatch, exclusive status and challenge deadlines, and the claim store's finalization compare-and-set rules. Each names the expected stage (`preflight`, `replay`, `evaluating`, `committed`), error class or committed tuple, the exact receipt outbox body, `verified_at`, allow horizon, sealed rate batch, and the number of times every callback ran, including evaluation-progress writes. A committed outcome is not a released decision. |
| `status-sequences.json` | 22 status-reducer scenarios (112 steps) covering the state-to-result table, including exclusive `next_update` and status-age deadlines. |
| `security-journal.json` | `SecurityJournalV2` logical snapshot known answers (SPEC-v2 §6.6): the genesis snapshot and digest, 2 transition scenarios (17 steps, each with the anchored head and exact canonical snapshot), version 1 migration, and 6 import negatives. Snapshot bytes after each transition come from the Go reference reducer; digests are recomputed independently. |
| `lifecycle-scenarios.json` | 26 Part B scripts (127 steps) and, under `profile_scenarios`, 18 profile scripts (175 steps) for the single-device offline profile (SPEC-v2 §7.13: power loss either side of acknowledgement, primary rollback, digest mismatch, full component storage, staged status going stale, clock regression, offline recovery and upload) and the dual-root composition profile (§7.14: either root missing, duplicate root, replay, mismatched action, committed but unreleased, concurrent completion, expiry before execution), over 22 requests, replayed against each SDK's in-memory reference store: commit, publication, acknowledgement and release (`released`, `pending`, `withheld`, `rejected`), late acknowledgement, release at both exact deadlines, real signer failure and same-body retry, head-of-line blocking, corrupt or foreign receipts, wrong acknowledgement, forged committed outcome, clock regression at claim, during evaluation, and at release, crash after claim with lease-expiry recovery from recorded evaluation progress, lease expiry during the status lookup, late-evaluator fencing after recovery, receipt abandonment, exact-state restore, lost-state restore with a replay-epoch bump, `max_rate` admission at finalization, proof conflict, and stream-sequence first/duplicate/gap/reorder/concurrent rules. |
| `transaction-verification.json` | 12 composed transaction-receipt verification cases (SPEC-v2 §5.7) with the verifier-ordering provider and journal inputs: all current, untrusted, ambiguous and absent trust, a revoked leaf, an unconfigured status issuer, an expired and a future-issued leaf (with `delegation_expires_at`), a parent without `identity:delegate`, an uncovered scope, and two configuration failures. Each gives the exact per-party result. |
| `log-sequences.json` | Witness-log and verification-receipt-log sequences: append, idempotent replay including new signature bytes over the same body, gap, orphan, cross-log replay, key substitution, fork freeze, and recovery to a new log ID. |
| `limits.json` | 32 byte-boundary, count-boundary and timestamp-domain cases: every v2 decoder at its byte limit and limit+1 (including the status evidence batch), revoked-reference counts for lists and pushes, status evidence batch entries at 64 and 65, witness `entry_data`, and signed timestamps at 253402300799 and one second past it. Large inputs are given as exact construction recipes (`pad`, `repeat_items`, `repeat_item`) with the expected length and SHA-256. |
| `hedged-signatures.json` | 10 objects from `objects.json`, each with 2 variants whose ML-DSA-65 components were produced by hedged (randomized) signing. Verifiers must accept every variant, derive identical projections and body digests, and treat a re-signed accepted log entry as a replay. Not reproducible: written only by `go run ./cmd/ratify-v2-vectors -hedged`. |
| `annex-a.json` | Annex A (`SPEC-v2-ANNEX-A.md`): the 3 copied v1 clauses pinned by byte length and SHA-256; 8 canonical JSON cases (UTF-8 byte key order, minimal escaping, U+2028 and U+2029, safe-integer bounds, no Unicode normalization); 16 strict-decode rejections (fraction, exponent, `-0`, out-of-range integers, duplicate keys including escaped spellings, unpaired surrogates, invalid UTF-8, trailing content); the 54-scope vocabulary with its 22 sensitive scopes and 14 wildcard expansions; 17 certificate scope-list validations, 6 expansions, and 8 chain intersections, including `custom:` behavior. |
| `rotation-sequences.json` | AcceptRotation journal: genesis, repeat signatures, skipped sequence, continuation, fork freeze, frozen rejection, invalid recoveries, recovery epoch increase, and rejection of old-epoch statements. |

## Required for 2.0.0-beta.1

[SPEC-v2 §8](../../SPEC-v2.md#8-conformance-and-release-gates) requires every
SDK to pass every file above. The beta requirements map onto this corpus as
follows; the last column names what is still missing.

| Requirement | SPEC-v2 | Where it is covered | Still missing |
| --- | --- | --- | --- |
| Incorporated v1 text: value model, canonical JSON, scope vocabulary | §2.1, Annex A | `annex-a.json` | |
| Byte and count limits | §2.6 | `limits.json` | |
| Numeric bounds, exclusive deadlines, clock regression | §2.5, §7.2 | `limits.json`, `object-negatives.json`, `verifier-ordering.json`, `status-sequences.json`, `lifecycle-scenarios.json` | Checked-arithmetic overflow vectors beyond the timestamp domain |
| Constraint registry and evaluation | §5.2 | `objects.json`, `object-negatives.json`, `verifier-ordering.json` | |
| `SecurityJournalV2` snapshots, transitions, migration | §6.6 | `security-journal.json` | Invariant-failure vectors |
| Status provenance | §6.5 | `verifier-ordering.json`, `limits.json` | |
| Provider failures, cancellation, interrupted assessments | §6.7, §6.11 | `verifier-ordering.json`, `lifecycle-scenarios.json` | Cancellation is a Go test, not a shared vector |
| Trust resolution | §6.1 | `verifier-ordering.json` (provider outcomes) | A shared registry resolver producing ambiguity |
| Stream sequence | §7.4 | `lifecycle-scenarios.json` | Concurrency runs as Go tests on the reference store |
| Part B profiles | §7.13 to §7.15, §8.6 | `lifecycle-scenarios.json` (`profile_scenarios`), `verifier-ordering.json` (`custody_profile_*`) | Profile scripts run only in Go |
| Claim lifecycle and release | §6.9, §7.3 to §7.9 | `lifecycle-scenarios.json` | Outbox retention past challenge expiry; receiver action idempotency (managed Verify only) |
| Composed transaction verification | §5.7 | `transaction-verification.json`, `object-negatives.json` | |
| Archival results | §6.10 | `object-negatives.json` (proof bundle), Go unit tests | Per-object shared vectors |
| External signer | §3.2 | `objects.json` (`tr`, `mu`), `hedged-signatures.json`, Go unit tests | Key-binding and invalid-component shared vectors |
| Cross-SDK fixtures | §8.1 | | `cross-sdk/` fixtures from every SDK |

Error classes are the closed list of SPEC-v2 §2.7, declared in `errors_v2.go` (`V2ErrorClass`). Precedence for a
single object is: strict decode and field format (`malformed`), then key-ID
derivation (`key_id_mismatch`), then delegation digest, duplicate
CertificateRef, and chain linkage, then signatures. Each vector file documents
its exact procedure and harness rules in its `description`, `procedure_by_kind`,
`semantics`, `operations`, or `head_rules` member.

## Coverage

Audit of the Go reference against the SPEC-v2 §4 registry, §5 wire schemas,
and §6 verifier requirements. "Before" is the reference as found at the start
of this pass; "After" is the reference with this corpus.

| Code | Object | Strict decode | Canonical encode | Sign | Verify | Required negative behavior | Shared vectors (before → after) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `0x0001` | Delegation certificate | Yes; ID format now checked before key-ID derivation | Yes | Yes | Before: only inside a bundle. After: also `VerifyDelegationCertV2Signature` | Before: unclassified errors; a 128-bit ID surfaced as a key mismatch. After: classified | primitive-only signature vector → objects + 59 negatives + ordering |
| `0x0002` | Challenge presentation / proof bundle | Yes | Yes | Yes | Before: structure and signatures interleaved per certificate; no composed live verifier. After: all structural checks precede any signature; `VerifyProofBundleV2` runs the full §6 order | Classified | none → objects + 35 negatives + 81 ordering cases |
| `0x0003` | Revocation list | Yes | Yes | Yes | Yes (bound issuer and status key) | Classified | none → objects + 19 negatives + status scenarios |
| `0x0004` / `0x0009` | Key rotation (old key / new-key possession) | Yes | Yes | Yes | Stateless verify: yes. Before: no AcceptRotation state machine. After: `AcceptKeyRotationStatementV2`, `RecoverKeyRotationV2` | Classified | legacy positive file → + 29 negatives + journal sequence |
| `0x0005` | Revocation push | Yes | Yes | Yes | Yes | Classified | none → objects + 10 negatives + status scenarios |
| `0x0006` | Witness entry | Yes | Yes | Yes | Yes (caller head; idempotency, gap, orphan, fork) | Classified | none → objects + 15 negatives + log sequence |
| `0x0007` | Transaction party statement | Yes | Yes | Yes | Yes (signatures, bundle hashes and signatures, party bindings, transaction-derived context) | Classified | none → objects + 21 negatives |
| `0x0008` | Verification receipt | Yes | Yes | Yes | Yes (caller key and head) | Classified | none → objects + 33 negatives + 3 binding + log sequence |

| SPEC-v2 §6 requirement | Before | After |
| --- | --- | --- |
| Pre-claim order: decode, required scope, key IDs, digest, duplicates, linkage, then signatures | Partial (per-certificate interleaving) | Yes |
| ExpectedChallenge namespace, replay epoch, verifier ID, bytes, time, expiry, max age | Yes (staged API) | Yes, classified, vectors |
| Pure application receiver-binding hook before claim | No | Yes (`V2VerifyCallbacks.ReceiverBinding`) |
| No trust/status/audience/rate callback before claim or on any pre-claim failure | Enforced by the staged token API, untested end to end | Vectors assert callback counts |
| Generic verifier with no context policy (`action_context_unverified`, null digest) | Not reachable (preflight required a policy) | Reachable through `VerifyProofBundleV2` only; `PreflightProofBundleV2` still requires a policy |
| Status for every CertificateRef before local policy; revoked > unavailable > stale | Yes | Yes, vectors |
| Constraint aggregation independent of link order (denied > unknown > unverifiable) across audience and non-audience constraints | Bug: a local unknown/unverifiable constraint skipped audience evaluation, so a proven audience mismatch on another link was not `constraint_denied` | Fixed in `ResolveClaimProofBundleV2AfterStatus`/`AfterAudience`; vectors in both link orders |
| `max_rate` only after current status and passing local policy | Yes | Yes, vectors (sealed batch, issuer-scoped counters) |
| Terminal receipt tuple and outbox body from the evaluated result | No composed mapping | `VerifyProofBundleV2` builds and validates the exact body |
| Language-neutral failure classes | No | `V2ErrorClass`, `V2ErrorClassOf` |

### Not covered by this corpus

- The items in the "Still missing" column above.
- Fuzzed decode and concurrency tests outside Go. Per-SDK coverage of this
  corpus is recorded in
  [`docs/V2_REFERENCE_COMPATIBILITY.md`](../../docs/V2_REFERENCE_COMPATIBILITY.md).

This is still not a v2 conformance badge. `2.0.0-beta.1` requires every SDK to
pass the complete corpus, including every file required for beta, together
with the other SDK gates and the internal adversarial review closure in
[SPEC-v2 §8.1](../../SPEC-v2.md#8-conformance-and-release-gates). `2.0.0`
additionally requires external interoperability, an external independent
review, and a soak (SPEC-v2 §8.2).
