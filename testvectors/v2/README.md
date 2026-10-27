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
| `objects.json` | 13 positive objects covering all nine codes (19 signatures), including a signed verification receipt carrying `constraint_evaluators` and a signed certificate, alone and in a proof bundle, whose unregistered constraint's `params` use protocol byte-field member names with values that are not base64 (only the JSON value model applies inside `params`, SPEC-v2 §2.1, §5.2): wire bytes that MUST re-encode identically, the exact signable projection, `M`, ML-DSA context, external-μ `tr`/`mu`, both signature components, and `delegation_digest`, `BundleHashV2`, `session_context`, `ChallengeClaimDigest`, claim ID with replay epoch, `StatusEvidenceDigest`, `StatementBodyDigest`, the receipt outbox body, and transaction context, party request hash, and party session context. |
| `object-negatives.json` | 433 single-fault negatives with a language-neutral `expected_error_class`: a mutation of every signed field of every object, each signature component broken separately, component swaps, cross-code and unregistered-code (`0x0000`, `0x000a`, `0xffff`) signatures, wrong ML-DSA contexts, canonical Ed25519 rejections (S+L, identity A and R, non-canonical A, mixed-order A with a cofactored-valid signature), v1 objects and 128-bit IDs, ID/key mismatch, old-key substitution, new-key proof failure, duplicate `(issuer_id, cert_id)`, swapped chain, wrong challenge and session-context lengths, non-canonical encodings, transaction hash/context/signature-set failures, a party `proof_bundle_hash` of the wrong shape (uppercase hex or prefix, 95 characters, a non-hex character: `malformed`, before any hash comparison), `terms_canonical_json` that is not a JSON object (integer, string, `null`, boolean, array, empty array: `malformed`), a nested proof bundle that is malformed or not canonical (`malformed`, never `bundle_hash_mismatch`), non-canonical spellings of the canonical-only kinds (witness entry, verification receipt, transaction receipt: a trailing newline, a leading space, a reordered member, an escaped member name, and an escaped value, all `malformed`, SPEC-v2 §2.1), and party bundles that do not belong to their signed party (`transaction_party_mismatch`: an empty chain and another `verifier_id`, each consistently hashed and signed), receipt decision/status inconsistencies, the optional receipt member `constraint_evaluators` (added after signing, empty, unsorted, duplicate, bad digest, closed-registry type, extra member), an exact `custom:` required scope accepted while `custom:*` and the bare prefix are rejected, and receipt/bundle binding mismatches, and the closed v2 constraint registry (v1 float members, fractions and exponents, out-of-range integers, bad `HH:MM` and `tz`, audience bounds, reserved geo types with v1 members, extension `params` that is not a JSON object: array, string, integer, boolean, `null`), every wire timestamp one second past 253402300799 and below 0 (`malformed` at decode), and 118 `strict_shape/` negatives derived from one positive object of every kind (SPEC-v2 §2.1): `{}` for every required structure, `null` as an array element and for a non-nullable key or signature component, byte strings spelled as arrays of numbers, and member names that differ only by ASCII case (renamed, or beside the exact name) or by Unicode case folding, at the top level, in a nested structure, and in an array element, all `malformed` at decode. |
| `verifier-ordering.json` | 485 end-to-end live-verifier cases (135 pre-claim, 2 replay, 346 committed, 2 evaluating, including 10 Middleware Custody Profile cases, SPEC-v2 §7.15) with scripted Part B dependencies: the configured verifier key ID and namespace (`configured_verifier_id` is required; an absent or non-canonical ID and an empty namespace are `configuration_invalid` at step 2, and an `ExpectedChallenge` or proof naming another verifier is `verifier_id_mismatch` before claim, SPEC-v2 §2.4, §6.1), an `ExpectedChallenge` or audience membership with `issued_at >= expires_at` (`configuration_invalid` before claim, `constraint_unverifiable` after it, SPEC-v2 §2.5), status-key epoch transitions through the verifier (`journal.setup`: a revocation retained across rotation, a new-epoch bootstrap with and without the retained deny union, a list signed by the retired key, a stale caller epoch), paired pre-claim and post-claim failures, status journal sequences (rollback below the floor, forks, contiguous pushes, a push before bootstrap, future-dated and at-skew lists, heartbeats, push and snapshot conflicts), `tz` names in and out of tzdata `2025c`, `resource_path` spellings, audience membership shapes, decode before configuration bounds and before the claim-store presence check (`claim_store` `absent`: a truncated bundle without a claim store is `malformed`, a valid one `configuration_invalid`, with no callback), two-fault pre-claim and post-claim ordering (every adjacent §6.2 step pair, the internal order of steps 2, 4 and 6, and the post-claim order of §6.4), one future skew (a status policy skew that differs from `future_skew_seconds` is `configuration_invalid`; status freshness follows the shared skew), a configured replay epoch above 2^53−1 and an expected session context that is not 32 bytes rejected at step 2, an expected agent key without its ID, checked arithmetic (SPEC-v2 §2.5: verifier time, future skew, challenge maximum age, status age and list lifetime, and an expected-challenge expiry at 2^53−1 are `configuration_invalid` before claim; every configured bound at its maximum at the end of the timestamp domain allows with a clamped horizon; a whole-domain delegation lifetime is `proof_invalid`) and supplied request context (amount and currency) rejected before claim, pre-claim checks, `time_window` against the pinned IANA tzdata `2025c` (configured `tzdb_version` absent or mismatched, unknown zone, exact local-minute horizon, midnight wrap, a horizon clamped to the end of the timestamp domain, and the next UTC offset change after a zone's last explicit transition: leap-year and year-end bounds that are not offset changes, a southern-hemisphere zone in DST across the year end, footer spring-forward and fall-back caps in 2040, and a zone with no further change), `resource_path` evaluation order for every `path_prefix` form against every request form, `max_amount` micro-units, exact `custom:` required scopes (an exact grant allows; a canonical-only grant, a different spelling, and a parent without the grant deny; `custom:*` and the bare prefix fail before claim), extension evaluator profiles (both standard profiles, a reference type bound to a standard profile, a profile-version digest change, unregistered types, precedence, evaluator error, panic, timeout and invalid output, evaluator horizons, invalid extension request context, and the sealed `constraint_evaluators` receipt member), the delegation lifetime bound, replay, signed status evidence applied through an anchored `SecurityJournalV2` (provider, batch, journal including one bounded compare-and-swap retry, and role-separation failures including a status key equal to the verifier key), trust outcomes including `ambiguous` and the reference candidate-record trust registry (`trust.mode` `registry`, SPEC-v2 §6.1: a duplicate record, two candidates sharing a component, and a component-only candidate fail closed as `trust_unavailable`; no candidate is untrusted), the post-claim context-policy mismatch and its interaction with earlier rows, receiver-audience membership age, expiry, receiver and skew boundaries at `T_claim`, rate batches and the results after which no reservation occurs, extension evaluators that never run on early failures, status batch order independence, same-sequence forks, duplicates and gaps, batch objects that the batch decoder accepts but that fail authentication (`{}`, a nested `null`, a list labelled code 5, and one such entry beside a valid list), each making the issuer unavailable, scope wildcard and sensitive-scope intersection, `tz` names that differ from a pinned zone only by letter case (`constraint_unverifiable`), tzdb edge cases (half-hour DST, explicit transitions after 2037, negative DST, a fold), exclusive status and challenge deadlines, and the claim store's finalization compare-and-set rules. Each names the expected stage (`preflight`, `replay`, `evaluating`, `committed`), error class or committed tuple, the exact receipt outbox body, `verified_at`, allow horizon, sealed rate batch, and the number of times every callback ran, including evaluation-progress writes. A committed outcome is not a released decision. |
| `status-sequences.json` | 22 status-reducer scenarios (112 steps) covering the state-to-result table, including exclusive `next_update` and status-age deadlines. Each apply step that records an observation carries `expect_body_digest`: the observation's unlabelled `body_digest`, SHA-384 of the canonical signable body (§6.6). |
| `security-journal.json` | `SecurityJournalV2` logical snapshot known answers (SPEC-v2 §6.6): the genesis snapshot and digest, 2 transition scenarios (17 steps, each with the anchored head and exact canonical snapshot), version 1 migration, 20 import negatives (including integers above 2^53−1 in `max_observed_sequence`, `fork_sequence`, and `status_key_epoch`, a member-name case variant, a `null` array element, and 9 `invariant_` snapshots that violate an invariant of §6.6, all `malformed`), and 6 `transition_negatives`: valid snapshot pairs whose transition is `status_object_rejected` (a skipped generation, a wrong predecessor, an unadvanced generation, a removed key-role binding, a shrinking deny union, and a rollback to an earlier status-key epoch). Snapshot bytes after each transition come from the Go reference reducer; digests are recomputed independently. |
| `lifecycle-scenarios.json` | 83 Part B scripts (447 steps) and, under `profile_scenarios`, 29 profile scripts (283 steps) for the single-device offline profile (SPEC-v2 §7.13: power loss either side of acknowledgement, primary rollback, digest mismatch, rollbacks with an unchanged receipt prefix that lose a consumed challenge, a stream advance, staged journal state, a rate commit, or a release record, a release record planted or altered in primary storage, full component storage, staged status going stale, clock regression, offline recovery and upload; the component anchors the primary's complete-state digest before every durable change) and the dual-root composition profile (§7.14: either root missing, duplicate root, replay, mismatched action, committed but unreleased, concurrent completion, expiry before execution, cross-set reuse, same set ID with a different action, an approval context naming another verifier, a set naming another verifier; the ledger derives each set's session context from its authenticated fields), over 29 requests, replayed against each SDK's in-memory reference store: commit, publication, acknowledgement and release (`released`, `pending`, `withheld`, `rejected`), late acknowledgement, release at both exact deadlines, real signer failure and same-body retry, head-of-line blocking, corrupt or foreign receipts, wrong acknowledgement, a planted release record and a repeated release that both re-verify the acknowledgement, forged committed outcome, clock regression at claim, during evaluation, and at release, crash after claim with lease-expiry recovery from recorded evaluation progress, lease expiry during the status lookup, late-evaluator fencing after recovery, receipt abandonment, exact-state restore, lost-state restore with a replay-epoch bump, release of a handoff whose claim the restored store does not hold (`rejected / release_state_mismatch`, never `pending`), `max_rate` admission at finalization (the single-store implementation of SPEC-v2 §7.6: admission and its window, all-or-none across two counters, an exact retry and a changed signed batch counted once, admissions that keep blocking across a clock rollback, and no count for indeterminate or recovered claims), proof conflict, stream-sequence first/duplicate/gap/reorder/concurrent rules, cancellation before the claim (`evaluation_cancelled` before claim, nothing to recover: `claim_not_found`) and during the status lookup (`evaluation_cancelled`, recovered as `evaluation_interrupted`), two concurrent stream advances with the same sequence (`verify_concurrent`: exactly one commits), a receipt outbox entry retained and appended past challenge expiry, release permanence (SPEC-v2 §6.9: a withheld result is recorded and answered right after the committed-state step, so it never becomes `released`, even after the clock recovers, without a receipt, or with a mismatched acknowledgement; a withheld call after a recorded release records nothing; `rejected` is per call, so the genuine receipt or checkpoint then releases), an independent checkpoint that freezes a log after a fork (a different entry hash at an acknowledged sequence; the next correctly linked entry is never acknowledged, SPEC-v2 §7.8) and does not freeze it on an out-of-order refusal, through the new `acknowledge` step, and finalization through the claim store's `finalize` step that refuses a receipt body differing from the sealed claim in each bound member (`verifier_id`, `agent_id`, `bundle_hash`, `issuer_ids`, `required_scope`, `context_policy_digest`, `constraint_evaluators`) or a terminal result naming another decision (`configuration_invalid`, nothing committed; SPEC-v2 §7.5), an allow finalized without an allow horizon or a non-allow finalized with one (`configuration_invalid`, SPEC-v2 §6.8), a body with a null `context_policy_digest` after context was evaluated for a claim sealed with a context policy (`configuration_invalid`), and a body with a non-null digest and `context_assessment: not_evaluated` (`malformed`), and lease-expiry recovery through the claim store's `recover_direct` step, which validates the result and body exactly as finalization does and accepts only `indeterminate / evaluation_interrupted`: it refuses a body that is not a canonical receipt body (`malformed`), a body for another claim (`configuration_invalid`), a non-null digest with `context_assessment: not_evaluated` (`malformed`), another decision bound to the claim (`configuration_invalid`), a terminal result naming another decision (`configuration_invalid`), and a terminal result that is not exactly the RatifyCanonicalJSON of the body's `decision`, `decision_reason` and `identity_status` (further members, a leading space, no `identity_status`, or another `identity_status`; `configuration_invalid`, SPEC-v2 §7.13), each committing nothing, and commits the canonical interrupted body, which the recovery helper then reproduces byte for byte, and resumption of committed work through the `resume` step (SPEC-v2 §7.11): a result committed by a direct finalize, which has no handoff, is resumed, published and released; a resumed allow keeps its allow horizon and releases once; resumption answers `claim_not_found`, `claim_lease_live` and `claim_lease_lost` and resumes a recovered interrupted result; resuming a claim whose receipt was abandoned returns its handoff, publication then fails `log_frozen`, and release answers `withheld / receipt_abandoned`; and a `resume` step with `claim_record_b64` has the claim store answer with a committed record taken from the vector, so every SDK feeds the same damaged records through its resume function: a record relabelled with another claim's ID, another claim's well-formed record (only the requested-ID check catches it), a claim ID that does not derive from the replay key, an uppercase or non-`sha384:` challenge digest, a body bound to another agent, a terminal result that differs from the body, an allow with horizon 0 or beyond the timestamp domain, a non-allow with a horizon, and (for the C ABI, whose store returns record bytes; `mode: record_bytes`) non-canonical claim record bytes, each `claim_store_unavailable`; a valid interrupted record with horizon 0 is accepted, and the honest record's handoff publishes and releases exactly as a returned one. |
| `transaction-verification.json` | 13 composed transaction-receipt verification cases (SPEC-v2 §5.7) with the verifier-ordering provider and journal inputs: all current, untrusted, ambiguous and absent trust, a revoked leaf, an unconfigured status issuer, an expired and a future-issued leaf (with `delegation_expires_at`), a parent without `identity:delegate`, an uncovered scope, and two configuration failures. Each gives the exact per-party result. |
| `log-sequences.json` | Witness-log and verification-receipt-log sequences: append, idempotent replay including new signature bytes over the same body, gap, orphan, cross-log replay, key substitution, fork freeze, and recovery to a new log ID. |
| `limits.json` | 76 byte-boundary, count-boundary, identifier-length, batch-envelope and timestamp-domain cases: every v2 decoder at its byte limit and limit+1 (including the status evidence batch), revoked-reference counts for lists and pushes, a revoked `cert_id` at 512 bytes and 513 bytes (ASCII and two-byte characters) in a list and a push, the status evidence batch envelope (SPEC-v2 §2.1, §6.5 step 3: a nested object's schema is opaque, so `{}`, a nested `null` member or array element, unknown or case-variant nested members, missing required members, a nested byte field spelled as non-canonical base64, as text that is not base64, or as an array of numbers, and a list labelled code 5 decode; the JSON value model applies to the whole document, so a nested duplicate member (also through an escape), fraction, exponent, unsafe integer, `-0`, unpaired surrogate escape, invalid UTF-8, or nesting beyond 16 levels counted from the batch array is `malformed`, and exactly 16 levels decode; a non-array, a `null` entry or object, an array object, a missing object, an extra, case-variant or duplicate entry member, code 4, and a code spelled `"3"` or `3.0` are `malformed`), status evidence batch entries at 64 and 65, witness `entry_data`, and signed timestamps at 253402300799 and one second past it. Large inputs are given as exact construction recipes (`pad`, `repeat_items`, `repeat_item`) with the expected length and SHA-256. |
| `hedged-signatures.json` | 10 objects from `objects.json`, each with 2 variants whose ML-DSA-65 components were produced by hedged (randomized) signing. Verifiers must accept every variant, derive identical projections and body digests, and treat a re-signed accepted log entry as a replay. Not reproducible: written only by `go run ./cmd/ratify-v2-vectors -hedged`. |
| `annex-a.json` | Annex A (`SPEC-v2-ANNEX-A.md`): the 3 copied v1 clauses pinned by byte length and SHA-256; 8 canonical JSON cases (UTF-8 byte key order, minimal escaping, U+2028 and U+2029, safe-integer bounds, no Unicode normalization); 16 strict-decode rejections (fraction, exponent, `-0`, out-of-range integers, duplicate keys including escaped spellings, unpaired surrogates, invalid UTF-8, trailing content); the 54-scope vocabulary with its 22 sensitive scopes and 14 wildcard expansions; 17 certificate scope-list validations, 6 expansions, and 8 chain intersections, including `custom:` behavior. |
| `issuer-duties.json` | 11 unsigned delegation certificates and whether a conforming typed signer signs them (SPEC-v2 §3.2, §5.1): equal and reversed timestamps, the lifetime boundary, distinct resource IDs, disjoint and byte-but-not-segment prefixes, an invalid prefix, and the satisfiable counterparts. A refusal invokes no signer method. |
| `challenge-issuance.json` | 10 challenge issuance helper scenarios (36 steps, SPEC-v2 §7.3) against an issuance store and the Part B claim store: issuance then presentation and replay, a crash after commit before exposure, a failure before commit, duplicate issuance that never overwrites, a repeating random source, invalid requests, wrong agent, session context, verifier ID and `challenge_at`, an unknown challenge, exclusive expiry, concurrent identical and conflicting presentations, and an expiry that lands exactly on the last timestamp (one second later is `configuration_invalid`). |
| `status-publisher.json` | 13 signed-status publisher scenarios (39 steps, SPEC-v2 §5.4) with journal ingestion: genesis list, heartbeats including a refused non-advancing one, a revoked entry by push and by list, refused revocations, a missed sequence, offline expiry at `next_update` and recovery, and construction from the authenticated role configuration: refused status-key reuse of the issuer, an intermediate, an unlisted root, an agent, and a verifier key, a status key never configured for the issuer or configured for another issuer, and an issuer missing from the role configuration. Produced objects are described by their signed fields because ML-DSA-65 signing may be hedged. |
| `evaluator-profiles.json` | Exhaustive semantics of the two standard extension evaluator profiles (SPEC-v2 §5.2): 34 `com.ratifyprotocol.max_count/v1` and 36 `com.ratifyprotocol.allowed_values/v1` cases giving params, extension request context, and the one required outcome (boundaries at 0 and 2^53−1, 64 allowed values and 512-byte values, every out-of-shape params form and wrong JSON type, missing context including an entry only in the other map, exact-byte matching without normalization, params checked before context; a case whose params is `null` or not a JSON object is marked `direct_api_only`, because a certificate cannot carry it and only a direct invocation reaches it), each profile's descriptor digest, and 13 request-context bound cases checked before claim. A matching `profile_digest` names a profile; passing this file is the evidence that an SDK implements the standard profiles identically. |
| `device-state.json` | 6 single-device offline complete-state projection known answers (SPEC-v2 §7.13): an empty primary with the genesis journal snapshot, a just-created stream-bound claim, a primary holding every record kind listed out of order (a released allow with a rate batch, evaluator snapshot, and appended receipt; a committed deny not yet appended; a claim interrupted after lease expiry with recorded progress; streams whose namespaces sort differently in UTF-8 and UTF-16; issuance records with bound and unbound context policies, an expected agent key, and a namespace containing U+2028; several rate counters), the same primary without its release record, the same primary with a recorded withheld result in place of the release (release records carry `outcome` and `reason`, SPEC-v2 §6.9), and an abandoned receipt in a frozen log at the maximum safe replay epoch. Each gives the exact canonical bytes and SHA-384 of every member, the projection object, and the complete-state digest; `v2reference/device_state_vectors_internal_test.go` loads each state into the Go reference primary and reproduces every byte. |
| `rotation-sequences.json` | AcceptRotation journal: genesis, repeat signatures, skipped sequence, continuation, fork freeze, frozen rejection, invalid recoveries, recovery epoch increase, and rejection of old-epoch statements; caller clock bounds: `now` one past the timestamp domain and negative (`configuration_invalid`) and at its end (accepted), a future skew of 301 (`configuration_invalid`), and a skew of 300 at the boundary. |
| `archival.json` | 19 archival verification cases (SPEC-v2 §6.10) covering every signed object kind: the exact result object for a proof bundle (two-link, expired leaf, empty chain, and a bad challenge signature with its `error_class`) and for a certificate, list, push, rotation statement, witness entry, verification receipt and transaction receipt, each with at least one failing case (`invalid_signature`, `status_key_binding_mismatch`, `key_id_mismatch`). |
| `external-signer.json` | 17 external signer cases (SPEC-v2 §3.2) against a scripted provider for a delegation certificate, a revocation list and a proof bundle: the exact direct-mode and external-mu requests, key-binding mismatch before any request (`key_id_mismatch`, or `status_key_binding_mismatch` for a status key), corrupted, missing, foreign-key and wrong-code components (`invalid_signature`), a provider error (`configuration_invalid`), and cancellation before and during the call (`evaluation_cancelled`). |
| `digest-functions.json` | 16 cases for `StatementBodyDigest` and `StatusEvidenceDigest` (SPEC-v2 §4): `StatementBodyDigest` of a signable body for each of the five codes it is defined for (`0x0003`, `0x0004`, `0x0005`, `0x0006`, `0x0008`), `StatusEvidenceDigest` of a signed revocation list, the registered codes `0x0001`, `0x0002`, `0x0007` and `0x0009` for `StatementBodyDigest`, and codes `0x0000`, `0x000a` and `0xffff` outside the registry for both functions, all `unsupported_object_type`. |
| `concurrency-scenarios.json` | 17 concurrent workloads (118 participants) against each SDK's in-memory Part B reference store, built from the `lifecycle-scenarios.json` requests (`inputs`), each run `default_iterations` times (20) with the runtime's real concurrency: a setup script, participants that all start at once (verify, claim, finalize, direct and helper recovery, resumption, release, acknowledge, a clock advance, caller cancellation), outcome invariants (`allowed`, `count`, `all_equal`, `one_winner`, `receipt_log_contiguous`), and an after script that may branch on a participant's outcome (`expect_by_outcome`). Covered: a same-challenge claim storm end to end and at the claim store, two different proofs for one challenge (SPEC-v2 §7.3), owner finalization racing lease expiry and direct recovery, recoveries racing after the owner committed, late finalizations after helper recovery, identical concurrent finalizations and recoveries (§7.5), caller cancellation racing evaluation (§6.11), releases while the acknowledgement lands and concurrent releases of one decision (§6.9, §7.8), concurrent stream advances (§7.4), resumption racing the owner's finalization and lease-expiry recovery and concurrent resumptions and releases of one allow (§7.11), and `max_rate` admission at finalization under contention for one counter and for an all-or-none two-counter batch (§7.6). Invariants constrain only outcomes, since interleavings differ by runtime: exactly one commit, the losing proof's error class, a resumption that returns only the committed result, at most one terminal result per claim, receipt sequences 1..k with no orphaned outbox entry, equal release results, and admitted allows equal to the counter limit. |

## cross-sdk/

[SPEC-v2 §8.1](../../SPEC-v2.md#8-conformance-and-release-gates) requires
fixtures produced by every SDK to be verified by every other SDK. Each SDK
writes one file, `cross-sdk/<sdk>.json`, where `<sdk>` is one of `go`,
`typescript`, `python`, `rust`, or `c`. Each SDK's conformance suite verifies
every file present in the directory, including its own, and fails on any
error. A missing file from another SDK is not a failure; that SDK's
column in the cross-SDK matrix of
[`docs/V2_REFERENCE_COMPATIBILITY.md`](../../docs/V2_REFERENCE_COMPATIBILITY.md)
simply stays empty.

Fixtures are not reproducible by design. The producing SDK generates fresh
random keys and signs every ML-DSA-65 component with hedged (randomized)
FIPS 204 signing; Ed25519 is deterministic. Every other field, including
timestamps relative to the fixed evaluation time `1800000000`, follows the
values below so verifiers can recompute every digest. The producer MUST
verify its own output before writing it. The Go fixture is written by
`go run ./cmd/ratify-v2-cross-sdk -out testvectors/v2/cross-sdk/go.json` and
verified by `TestV2CrossSDKFixtures` (`cross_sdk_v2_test.go`).

### File schema

```
{
  "version": 2,
  "description": string,
  "sdk": "<sdk>",                 // equals the file name without .json
  "sdk_version": string,          // exact package version or source revision
  "generator": string,            // command or note that produced the file
  "kind_object_type_codes": { same map as objects.json },
  "keys":    [ keys.json "keys" entries ],
  "objects": [ objects.json "objects" entries ],
  "scenario_configuration": { ... },   // fixed values, below
  "scenarios": [ scenario, ... ]       // verifier and release scenarios, below
}
```

- `keys` uses the entry schema of `keys.json` `keys`: `name`,
  `ed25519_seed_hex`, `ml_dsa_65_seed_hex`, `public_key` (`ed25519`,
  `ml_dsa_65`, Base64), `key_id_v2`, and `v1_key_id_128`. Seeds are throwaway
  test data. The file MUST define these 11 names: `root`, `intermediate`,
  `agent`, `verifier`, `status_root`, `status_intermediate`, `witness`,
  `party_b_root`, `party_b_agent`, `rotation_genesis`, `rotation_second`.
- `objects` uses the object schema of `objects.json`: `name`, `kind`,
  `description`, `wire_b64`, `verify`, `signatures`, and `digests`, with one
  optional addition, `bundle_b64`, used only by kind `receipt_bundle_binding`.
  Each signature record has the objects.json fields `field`,
  `object_type_code`, `signer`, `signer_key_id_v2`, `signable_b64`,
  `signable_sha384_hex`, `message_b64`, `mldsa_context`, `mldsa_tr_b64`,
  `mldsa_mu_b64`, and `signature` (`ed25519`, `ml_dsa_65`). Signer and
  `verify` key names (`status_key`, `witness_key`, `verifier_key`,
  `rotation_state.current_key`) resolve to this file's `keys`, never to
  `keys.json`.
- `verify` and `digests` use exactly the objects.json conventions. The digest
  names are `issuer_key_id_v2`, `subject_key_id_v2`, `delegation_digest_hex`,
  `bundle_hash_v2`, `session_context_hex`, `challenge_claim_digest_hex`,
  `claim_id`, `claim_verifier_namespace`, `claim_replay_epoch`,
  `status_evidence_digest`, `statement_body_digest_hex`,
  `receipt_outbox_body_b64`, `transaction_context_hex`, and
  `<party_id>.transaction_party_request_hash_hex`,
  `<party_id>.session_context_hex`, `<party_id>.proof_bundle_hash`.
  `session_context_hex` is the objects.json fixture request: workspace
  `00000000-0000-4000-8000-000000000001`, session `session-01`, invocation
  `invocation-01`, and the operation context of `data:read`, `records.get`,
  `customer/123`, `/v1/customers/123` with no payload, bound to the bundle's
  `verifier_id` and `agent_id`.

### Required objects

A fixture MUST contain at least one object of every kind below; the Go
fixture contains exactly these 15:

| Name | Kind | Content |
| --- | --- | --- |
| `delegation_root_to_intermediate` | `delegation_certificate` | `root` to `intermediate`, `cert-root`, scope `data:read`, `files:read`, `identity:delegate` |
| `delegation_every_registered_constraint_and_extension` | `delegation_certificate` | `intermediate` to `agent`, `cert-leaf-constrained`, scope `data:read`, constraints: every closed-registry type (`max_rate`, `ratify.receiver_audience`, `resource_path`, `time_window`, `max_amount`) and the extension evaluator type `com.ratifyprotocol.max_count` with params `{"counter":"nodes","max":10}` |
| `proof_bundle_two_link_bound_context` | `proof_bundle` | `[cert-leaf, cert-root]` (`cert-leaf`: `intermediate` to `agent`, `data:read`, `files:read`), bound session context, challenge bytes `0xa0..0xbf`, claim digests for namespace `verify-test` and replay epoch 3 |
| `proof_bundle_constrained_chain` | `proof_bundle` | `[cert-leaf-constrained, cert-root]`, bound session context, challenge bytes `0xb0..0xcf` |
| `proof_bundle_empty_chain_stream_bound` | `proof_bundle` | empty chain, null session context, stream ID 32 bytes of `0x5a` at sequence 1 |
| `revocation_list_root` | `revocation_list` | `status_root` for `root`, sequence 7, revokes `cert-a`, `cert-b` |
| `revocation_list_intermediate_empty` | `revocation_list` | `status_intermediate` for `intermediate`, sequence 1, empty |
| `revocation_push` | `revocation_push` | `status_root` for `root`, sequence 8, revokes `cert-c` |
| `key_rotation_genesis` | `key_rotation_statement` | `rotation_genesis` to `rotation_second`, codes `0x0004` and `0x0009`, genesis rotation state |
| `witness_entry_genesis` | `witness_entry` | `witness`, log `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1`, sequence 1, genesis head |
| `transaction_receipt_two_parties` | `transaction_receipt` | parties `party-a` (`agent`, rooted at `root`) and `party-b` (`party_b_agent`, rooted at `party_b_root`) as in objects.json |
| `verification_receipt_allow_genesis` | `verification_receipt` | allow receipt by `verifier` for `proof_bundle_two_link_bound_context`, log `cccccccccccccccccccccccccccccc01`, status evidence from both revocation lists |
| `verification_receipt_allow_genesis/bundle_binding` | `receipt_bundle_binding` | that receipt (`wire_b64`) with its bundle (`bundle_b64`) |
| `verification_receipt_constraint_evaluators` | `verification_receipt` | allow receipt for `proof_bundle_constrained_chain`, log `cccccccccccccccccccccccccccccc02`, `constraint_evaluators` naming `com.ratifyprotocol.max_count` with the `com.ratifyprotocol.max_count/v1` profile digest |
| `verification_receipt_constraint_evaluators/bundle_binding` | `receipt_bundle_binding` | that receipt with its bundle |

Signatures under all nine codes `0x0001` to `0x0009` MUST appear.

### Verification procedure

For every file in `cross-sdk/`, a conforming SDK MUST:

1. Strictly decode the file, check `version` is 2 and `sdk` equals the file
   name, and derive each public key and `key_id_v2` from its seeds.
2. For every object other than `receipt_bundle_binding`, run the objects.json
   positive procedure: decode `wire_b64`, re-encode to identical bytes, verify
   with `verify` (per-kind procedure of `object-negatives.json`
   `procedure_by_kind`), and for each signature check the signable projection,
   its SHA-384, the 77-byte `M`, the ML-DSA context, `tr` and `mu` against the
   signer's public key, the signer key ID, and that both pinned signature
   components are the ones carried by the wire object. Then reproduce every
   digest.
3. For `receipt_bundle_binding`, decode and byte-identically re-encode
   `wire_b64` as a verification receipt and `bundle_b64` as a proof bundle,
   and pass the receipt/bundle binding check (`bundle_hash`, `verifier_id`,
   `agent_id`, `issuer_ids`). `signatures` and `digests` are empty.
4. Fail if a kind listed above, any of the nine signature codes, a delegation
   certificate with every registered constraint type and an extension type, or
   a verification receipt with `constraint_evaluators` is missing.
5. Never compare ML-DSA-65 signature bytes with anything but the wire object.
6. Replay every scenario as specified below and fail on any difference. Fail
   if a fixture has no `scenario_configuration` or no `scenarios`.

### Verifier and release scenarios

SPEC-v2 §8.1 requires each SDK's fixture to carry verifier and release
scenarios. The producing SDK builds every input below with the keys of its own
file (fresh keys, hedged ML-DSA-65), runs each scenario through its own live
verifier, reference Part B store, receipt publisher, checkpoint and
`ReleaseV2Decision`, and records what it observed. Every SDK replays every
file's scenarios through its own implementation and must observe the same
results. Key names resolve to the file's `keys`.

`scenario_configuration` has exactly these members and values; a replaying
SDK rejects a file whose values differ:

```
{
  "verifier_namespace": "verify-test",
  "replay_epoch": 3,
  "verifier_key": "verifier",                        // key name; signs receipts, configured for release
  "receipt_log_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
  "lease_seconds": 30,
  "max_challenge_age_seconds": 300,
  "future_skew_seconds": 5,
  "status_policy": {"max_list_lifetime_seconds": 7200, "max_status_age_seconds": 3660, "clock_skew_seconds": 5},
  "tzdb_version": "2025c"
}
```

Each scenario has exactly these members:

```
{
  "name": string,
  "description": string,
  "bundle_b64": string,                  // the presented proof bundle, signed by the producer
  "required_scope": string,
  "expected_challenge": {...},           // verifier-ordering.json expected_challenge schema
  "context_policy": {...},               // verifier-ordering.json context_policy schema
  "trust_root_key": string,              // key name the trust provider returns as trusted
  "status_keys": {"<issuer_id>": {"epoch": integer, "key": string}},
  "status_evidence": {"<issuer_id>": [{"object_type_code": 3 | 5, "wire_b64": string}]},
  "verify_time": integer,
  "publish_time": integer,
  "release_time": integer,
  "expected": {
    "receipt_body_b64": string,          // exact sealed receipt outbox body
    "allow_horizon": integer | null,     // handoff allow_horizon; null unless allow
    "signed_receipt_b64": string,        // the producer's signed receipt, log receipt_log_id, sequence 1
    "release": {
      "status": "released" | "pending" | "withheld" | "rejected",
      "reason": string | null,           // null when released
      "decision": string | null,         // the released decision; null unless released
      "release_time": integer | null     // null unless released
    }
  }
}
```

Replay procedure for one scenario:

1. Create a fresh reference Part B store (claim store with the authoritative
   clock at `verify_time`, receipt publisher signing with the private key
   derived from the `verifier_key` seeds, and independent checkpoint) with
   `lease_seconds` and `receipt_log_id`, and a fresh anchored
   `SecurityJournalV2` store on which `ConfigureStatusKeyEpoch` runs for every
   `status_keys` entry in ascending `issuer_id` order.
2. Run `VerifyProofBundleV2` at `now = verify_time` with the configuration
   above, the scenario's request members, a trust provider that returns
   `trusted` with the complete public key of `trust_root_key`, and a status
   provider that returns `status_evidence[issuer_id]` (an empty batch for an
   issuer not listed). No receiver-binding hook, audience provider, rate store
   or extension evaluator is configured. The stage MUST be `committed`, the
   sealed outbox body MUST equal `receipt_body_b64`, and the handoff
   `allow_horizon` MUST equal `allow_horizon`.
3. Set the clock to `publish_time` and publish the committed outcome through
   the reference publisher, so the checkpoint acknowledges sequence 1 at
   `publish_time`.
4. Set the clock to `release_time` and call `ReleaseV2Decision` with the
   handoff, `signed_receipt_b64` (the producer's receipt, not the one just
   published; both have the same signable body and therefore the same entry
   hash), and the configured verifier public key, `receipt_log_id`, store and
   checkpoint. The result MUST equal `release`.

A fixture MUST contain these four scenarios; the Go fixture contains exactly
these, each with its own challenge (first byte `0xa1`, `0xa2`, `0xa3`, or `0xa4`,
then bytes `0xa1..0xbf`) issued at 1799999990 and expiring at 1800000290, the default two-link chain of
`proof_bundle_two_link_bound_context` (scope `data:read`, `files:read`), the
objects.json fixture session context, and the Verify session-context policy:

| Name | Status evidence (all signed by the producer's status keys) | Times | Release |
| --- | --- | --- | --- |
| `allow_released` | root and intermediate lists, sequence 1, `updated_at` 1799999940, `next_update` 1800003600 | all 1800000000 | `released`, `allow` at 1800000000 |
| `deny_revoked_released` | as above, the intermediate list revokes `cert-leaf` | all 1800000000 | `released`, `deny` (`delegation_revoked`) |
| `indeterminate_status_unavailable_released` | the root list only | all 1800000000 | `released`, `indeterminate` (`status_unavailable`) |
| `allow_withheld_past_horizon` | the root list's `next_update` is 1800000060 | verify 1800000000, publish and release 1800000060 | `withheld` / `allow_horizon_passed` |

`go run ./cmd/ratify-v2-cross-sdk` replays its own scenarios before writing,
and `TestV2CrossSDKFixtures` replays every file's scenarios.

## Required for 2.0.0-beta.1

[SPEC-v2 §8](../../SPEC-v2.md#8-conformance-and-release-gates) requires every
SDK to pass every file above. The beta requirements map onto this corpus as
follows; the last column records each gap the corpus once listed and the
vectors that closed it, or what remains open.

| Requirement | SPEC-v2 | Where it is covered | Gap status |
| --- | --- | --- | --- |
| Incorporated v1 text: value model, canonical JSON, scope vocabulary | §2.1, Annex A | `annex-a.json` | |
| Byte and count limits | §2.6 | `limits.json` | |
| Numeric bounds, exclusive deadlines, clock regression | §2.5, §7.2 | `limits.json`, `object-negatives.json`, `verifier-ordering.json`, `status-sequences.json`, `lifecycle-scenarios.json`, `challenge-issuance.json` | Closed: checked-arithmetic overflow beyond the timestamp domain, 8 `verifier-ordering.json` `overflow_*` cases (6 pre-claim, 2 committed) and `challenge-issuance.json` `expiry_at_timestamp_domain_end` (3 steps) |
| Constraint registry and evaluation | §5.2 | `objects.json`, `object-negatives.json`, `verifier-ordering.json` | |
| Extension evaluator profiles | §5.2, §5.8 | `evaluator-profiles.json`, `verifier-ordering.json`, `object-negatives.json`, `objects.json` | Closed: positive signed receipt carrying `constraint_evaluators`, `objects.json` `verification_receipt_constraint_evaluators` (1 object) |
| Issuer duties, challenge issuance, status publisher | §5.1, §5.4, §7.3 | `issuer-duties.json`, `challenge-issuance.json`, `status-publisher.json` | |
| `SecurityJournalV2` snapshots, transitions, migration, invariants | §6.6 | `security-journal.json` | Closed: invariant failures, 9 `invariant_` import negatives and 6 `transition_negatives` |
| Status provenance | §6.5 | `verifier-ordering.json`, `limits.json` | |
| Provider failures, cancellation, interrupted assessments | §6.7, §6.11 | `verifier-ordering.json`, `lifecycle-scenarios.json` | Closed: shared cancellation, `lifecycle-scenarios.json` `cancel_before_claim_consumes_nothing` (5 steps) and `cancel_after_claim_keeps_claim_recoverable` (7 steps) |
| Trust resolution | §6.1, §8.1 | `verifier-ordering.json` (provider outcomes and the reference trust registry) | Closed: registry ambiguity, 5 `verifier-ordering.json` `trust_registry_*` cases through each SDK's reference `TrustRegistry` |
| Stream sequence | §7.4 | `lifecycle-scenarios.json` | Closed: shared concurrent advances, `lifecycle-scenarios.json` `concurrent_stream_advances` (4 steps, `verify_concurrent`) |
| Concurrency against the Part B reference stores | §6.9, §6.11, §7.3 to §7.8, §8.1 item 3 | `concurrency-scenarios.json`, `lifecycle-scenarios.json` (`verify_concurrent`), `challenge-issuance.json` | Closed: one shared definition of the concurrent claim, finalization and recovery, resumption, cancellation, stream, release and rate workloads, `concurrency-scenarios.json` (17 scenarios), run by every SDK. Open by scope: concurrent journal compare-and-swap (§8.1 item 3) stays in each SDK's own suite |
| Part B profiles | §7.13 to §7.15, §8.6 | `lifecycle-scenarios.json` (`profile_scenarios`), `device-state.json`, `verifier-ordering.json` (`custody_profile_*`) | |
| Claim lifecycle and release | §6.9, §7.3 to §7.9 | `lifecycle-scenarios.json` | Closed: outbox retention past challenge expiry, `lifecycle-scenarios.json` `outbox_retained_past_challenge_expiry` (6 steps). Open by scope: receiver action idempotency belongs to managed Verify (§1.2, §7.3), not to the SDK surface |
| Composed transaction verification | §5.7 | `transaction-verification.json`, `object-negatives.json` | |
| Archival results | §6.10 | `archival.json`, `object-negatives.json` (proof bundle) | Closed: per-object shared vectors, `archival.json` (19 cases, every object kind) |
| External signer | §3.2 | `external-signer.json`, `objects.json` (`tr`, `mu`), `hedged-signatures.json` | Closed: key-binding and invalid-component shared scenarios, `external-signer.json` (17 cases) |
| Cross-SDK fixtures | §8.1 | `cross-sdk/go.json`, `typescript.json`, `python.json`, `rust.json`, and `c.json`, each verified by all five SDKs | Closed: every fixture carries the 4 verifier and release scenarios (see cross-sdk/), and every SDK replays every fixture's scenarios |
| Error classes | §2.7 | every file; `digest-functions.json` (16 cases) | Closed: a shared vector for every one of the 49 classes, previously missing for `unsupported_object_type` (`digest-functions.json`), `claim_not_found` and `evaluation_cancelled` (`lifecycle-scenarios.json`), and `transaction_party_mismatch` (`object-negatives.json`); `TestV2CorpusAssertsEveryErrorClass` fails if a class loses its last vector |

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

- The items still marked open in the "Gap status" column above.
- Concurrency beyond the shared workloads of `concurrency-scenarios.json`,
  the concurrent presentations of `challenge-issuance.json`, and the
  concurrent stream advance of `lifecycle-scenarios.json`, such as concurrent
  journal compare-and-swap, which each SDK tests in its own suite. A shared
  scenario pins outcomes, not interleavings: each SDK's runner repeats it to
  exercise its own runtime's scheduling.
- Fuzzed decode. Each SDK runs its own: Go fuzz targets
  (`scripts/fuzz-v2.sh`), TypeScript `decoders_fuzz.test.ts`, Python
  Hypothesis tests, and Rust proptest and `cargo fuzz` targets; the C ABI has
  no fuzz harness of its own and wraps the Rust decoders. Per-SDK coverage of
  this corpus is recorded in
  [`docs/V2_REFERENCE_COMPATIBILITY.md`](../../docs/V2_REFERENCE_COMPATIBILITY.md).

This is still not a v2 conformance badge. `2.0.0-beta.1` requires every SDK to
pass the complete corpus, including every file required for beta, together
with the other SDK gates and the internal adversarial review closure in
[SPEC-v2 §8.1](../../SPEC-v2.md#8-conformance-and-release-gates). `2.0.0`
additionally requires external interoperability, an external independent
review, and a soak (SPEC-v2 §8.2).
