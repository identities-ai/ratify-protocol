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
| `object-negatives.json` | 224 single-fault negatives with a language-neutral `expected_error_class`: a mutation of every signed field of every object, each signature component broken separately, component swaps, cross-code and unregistered-code (`0x0000`, `0x000a`, `0xffff`) signatures, wrong ML-DSA contexts, canonical Ed25519 rejections (S+L, identity A and R, non-canonical A, mixed-order A with a cofactored-valid signature), v1 objects and 128-bit IDs, ID/key mismatch, old-key substitution, new-key proof failure, duplicate `(issuer_id, cert_id)`, swapped chain, wrong challenge and session-context lengths, non-canonical encodings, transaction hash/context/signature-set failures, receipt decision/status inconsistencies, and receipt/bundle binding mismatches. |
| `verifier-ordering.json` | 113 end-to-end live-verifier cases with scripted Part B dependencies: configuration bounds, pre-claim checks, replay, signed status evidence applied through an anchored `SecurityJournalV2` (provider, batch, journal and role-separation failures), trust outcomes including `ambiguous`, exclusive status and challenge deadlines, and authoritative-clock rules at finalization. Each names the expected stage (`preflight`, `replay`, `evaluating`, `committed`), error class or committed tuple, the exact receipt outbox body, `verified_at`, allow horizon, sealed rate batch, and the number of times every callback ran. A committed outcome is not a released decision. |
| `status-sequences.json` | 22 status-reducer scenarios covering the state-to-result table, including exclusive `next_update` and status-age deadlines. |
| `security-journal.json` | `SecurityJournalV2` logical snapshot known answers (SPEC-v2 §6.6): the genesis snapshot and digest, 2 transition scenarios (17 steps, each with the anchored head and exact canonical snapshot), version 1 migration, and 6 import negatives. Snapshot bytes after each transition come from the Go reference reducer; digests are recomputed independently. |
| `lifecycle-scenarios.json` | 17 Part B scripts (78 steps over 9 requests) replayed against each SDK's in-memory reference store: commit, publication, acknowledgement and release (`released`, `pending`, `withheld`, `rejected`), late acknowledgement, release at both exact deadlines, signer failure and retry, corrupt or foreign receipts, wrong acknowledgement, forged committed outcome, clock regression, crash after claim with lease-expiry recovery, proof conflict, and stream-sequence first/duplicate/gap/reorder/concurrent rules. |
| `log-sequences.json` | Witness-log and verification-receipt-log sequences: append, idempotent replay including new signature bytes over the same body, gap, orphan, cross-log replay, key substitution, fork freeze, and recovery to a new log ID. |
| `rotation-sequences.json` | AcceptRotation journal: genesis, repeat signatures, skipped sequence, continuation, fork freeze, frozen rejection, invalid recoveries, recovery epoch increase, and rejection of old-epoch statements. |

Error classes are defined in `errors_v2.go` (`V2ErrorClass`). Precedence for a
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

- Lifecycle items without shared vectors: late-worker fencing after recovery,
  receipt-log head-of-line blocking, outbox retention, `receipt_abandoned`,
  restore with and without epoch bump, rate admission at finalization, and
  receiver action idempotency. Concurrent claims are covered by Go tests on
  the reference store, not by a shared vector.
- A post-claim Protocol context-policy `mismatch` cannot be produced through the
  Go API because preflight already compares the expected session context.
- Trust ambiguity is vectored only as a provider outcome; there is no shared
  registry resolver that produces it.
- External-μ provider integration is pinned only as `tr`/`mu` bytes.
- Fuzzed decode and concurrency tests outside Go. Per-SDK coverage of this
  corpus is recorded in
  [`docs/V2_REFERENCE_COMPATIBILITY.md`](../../docs/V2_REFERENCE_COMPATIBILITY.md).

This is still not a v2 conformance badge: a public v2 release also requires the
corpus to run in every public SDK, byte parity across independent
implementations, all version and package gates, and the independent review
specified by [SPEC-v2 §8](../../SPEC-v2.md#8-conformance-and-release-gates).
