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
| `object-negatives.json` | 281 single-fault negatives with a language-neutral `expected_error_class`: a mutation of every signed field of every object, each signature component broken separately, component swaps, cross-code and unregistered-code (`0x0000`, `0x000a`, `0xffff`) signatures, wrong ML-DSA contexts, canonical Ed25519 rejections (S+L, identity A and R, non-canonical A, mixed-order A with a cofactored-valid signature), v1 objects and 128-bit IDs, ID/key mismatch, old-key substitution, new-key proof failure, duplicate `(issuer_id, cert_id)`, swapped chain, wrong challenge and session-context lengths, non-canonical encodings, transaction hash/context/signature-set failures, receipt decision/status inconsistencies, the optional receipt member `constraint_evaluators` (added after signing, empty, unsorted, duplicate, bad digest, closed-registry type, extra member), an exact `custom:` required scope accepted while `custom:*` and the bare prefix are rejected, and receipt/bundle binding mismatches, and the closed v2 constraint registry (v1 float members, fractions and exponents, out-of-range integers, bad `HH:MM` and `tz`, audience bounds, reserved geo types with v1 members), and every wire timestamp one second past 253402300799 and below 0 (`malformed` at decode). |
| `verifier-ordering.json` | 194 end-to-end live-verifier cases (57 pre-claim, 2 replay, 133 committed, 2 evaluating, including 10 Middleware Custody Profile cases, SPEC-v2 §7.15) with scripted Part B dependencies: decode before configuration bounds and supplied request context (amount and currency) rejected before claim, pre-claim checks, `time_window` against the pinned IANA tzdata `2025c` (configured `tzdb_version` absent or mismatched, unknown zone, exact local-minute horizon, midnight wrap, a horizon clamped to the end of the timestamp domain), `resource_path` evaluation order for every `path_prefix` form against every request form, `max_amount` micro-units, exact `custom:` required scopes (an exact grant allows; a canonical-only grant, a different spelling, and a parent without the grant deny; `custom:*` and the bare prefix fail before claim), extension evaluator profiles (both standard profiles, a reference type bound to a standard profile, a profile-version digest change, unregistered types, precedence, evaluator error, panic, timeout and invalid output, evaluator horizons, invalid extension request context, and the sealed `constraint_evaluators` receipt member), the delegation lifetime bound, replay, signed status evidence applied through an anchored `SecurityJournalV2` (provider, batch, journal including one bounded compare-and-swap retry, and role-separation failures including a status key equal to the verifier key), trust outcomes including `ambiguous`, the post-claim context-policy mismatch, exclusive status and challenge deadlines, and the claim store's finalization compare-and-set rules. Each names the expected stage (`preflight`, `replay`, `evaluating`, `committed`), error class or committed tuple, the exact receipt outbox body, `verified_at`, allow horizon, sealed rate batch, and the number of times every callback ran, including evaluation-progress writes. A committed outcome is not a released decision. |
| `status-sequences.json` | 22 status-reducer scenarios (112 steps) covering the state-to-result table, including exclusive `next_update` and status-age deadlines. |
| `security-journal.json` | `SecurityJournalV2` logical snapshot known answers (SPEC-v2 §6.6): the genesis snapshot and digest, 2 transition scenarios (17 steps, each with the anchored head and exact canonical snapshot), version 1 migration, and 6 import negatives. Snapshot bytes after each transition come from the Go reference reducer; digests are recomputed independently. |
| `lifecycle-scenarios.json` | 28 Part B scripts (140 steps) and, under `profile_scenarios`, 29 profile scripts (279 steps) for the single-device offline profile (SPEC-v2 §7.13: power loss either side of acknowledgement, primary rollback, digest mismatch, rollbacks with an unchanged receipt prefix that lose a consumed challenge, a stream advance, staged journal state, a rate commit, or a release record, a release record planted or altered in primary storage, full component storage, staged status going stale, clock regression, offline recovery and upload; the component anchors the primary's complete-state digest before every durable change) and the dual-root composition profile (§7.14: either root missing, duplicate root, replay, mismatched action, committed but unreleased, concurrent completion, expiry before execution, cross-set reuse, same set ID with a different action, an approval context naming another verifier, a set naming another verifier; the ledger derives each set's session context from its authenticated fields), over 23 requests, replayed against each SDK's in-memory reference store: commit, publication, acknowledgement and release (`released`, `pending`, `withheld`, `rejected`), late acknowledgement, release at both exact deadlines, real signer failure and same-body retry, head-of-line blocking, corrupt or foreign receipts, wrong acknowledgement, a planted release record and a repeated release that both re-verify the acknowledgement, forged committed outcome, clock regression at claim, during evaluation, and at release, crash after claim with lease-expiry recovery from recorded evaluation progress, lease expiry during the status lookup, late-evaluator fencing after recovery, receipt abandonment, exact-state restore, lost-state restore with a replay-epoch bump, `max_rate` admission at finalization, proof conflict, and stream-sequence first/duplicate/gap/reorder/concurrent rules. |
| `transaction-verification.json` | 12 composed transaction-receipt verification cases (SPEC-v2 §5.7) with the verifier-ordering provider and journal inputs: all current, untrusted, ambiguous and absent trust, a revoked leaf, an unconfigured status issuer, an expired and a future-issued leaf (with `delegation_expires_at`), a parent without `identity:delegate`, an uncovered scope, and two configuration failures. Each gives the exact per-party result. |
| `log-sequences.json` | Witness-log and verification-receipt-log sequences: append, idempotent replay including new signature bytes over the same body, gap, orphan, cross-log replay, key substitution, fork freeze, and recovery to a new log ID. |
| `limits.json` | 32 byte-boundary, count-boundary and timestamp-domain cases: every v2 decoder at its byte limit and limit+1 (including the status evidence batch), revoked-reference counts for lists and pushes, status evidence batch entries at 64 and 65, witness `entry_data`, and signed timestamps at 253402300799 and one second past it. Large inputs are given as exact construction recipes (`pad`, `repeat_items`, `repeat_item`) with the expected length and SHA-256. |
| `hedged-signatures.json` | 10 objects from `objects.json`, each with 2 variants whose ML-DSA-65 components were produced by hedged (randomized) signing. Verifiers must accept every variant, derive identical projections and body digests, and treat a re-signed accepted log entry as a replay. Not reproducible: written only by `go run ./cmd/ratify-v2-vectors -hedged`. |
| `annex-a.json` | Annex A (`SPEC-v2-ANNEX-A.md`): the 3 copied v1 clauses pinned by byte length and SHA-256; 8 canonical JSON cases (UTF-8 byte key order, minimal escaping, U+2028 and U+2029, safe-integer bounds, no Unicode normalization); 16 strict-decode rejections (fraction, exponent, `-0`, out-of-range integers, duplicate keys including escaped spellings, unpaired surrogates, invalid UTF-8, trailing content); the 54-scope vocabulary with its 22 sensitive scopes and 14 wildcard expansions; 17 certificate scope-list validations, 6 expansions, and 8 chain intersections, including `custom:` behavior. |
| `issuer-duties.json` | 11 unsigned delegation certificates and whether a conforming typed signer signs them (SPEC-v2 §3.2, §5.1): equal and reversed timestamps, the lifetime boundary, distinct resource IDs, disjoint and byte-but-not-segment prefixes, an invalid prefix, and the satisfiable counterparts. A refusal invokes no signer method. |
| `challenge-issuance.json` | 9 challenge issuance helper scenarios (33 steps, SPEC-v2 §7.3) against an issuance store and the Part B claim store: issuance then presentation and replay, a crash after commit before exposure, a failure before commit, duplicate issuance that never overwrites, a repeating random source, invalid requests, wrong agent, session context, verifier ID and `challenge_at`, an unknown challenge, exclusive expiry, and concurrent identical and conflicting presentations. |
| `status-publisher.json` | 13 signed-status publisher scenarios (39 steps, SPEC-v2 §5.4) with journal ingestion: genesis list, heartbeats including a refused non-advancing one, a revoked entry by push and by list, refused revocations, a missed sequence, offline expiry at `next_update` and recovery, and construction from the authenticated role configuration: refused status-key reuse of the issuer, an intermediate, an unlisted root, an agent, and a verifier key, a status key never configured for the issuer or configured for another issuer, and an issuer missing from the role configuration. Produced objects are described by their signed fields because ML-DSA-65 signing may be hedged. |
| `evaluator-profiles.json` | Exhaustive semantics of the two standard extension evaluator profiles (SPEC-v2 §5.2): 34 `com.ratifyprotocol.max_count/v1` and 36 `com.ratifyprotocol.allowed_values/v1` cases giving params, extension request context, and the one required outcome (boundaries at 0 and 2^53−1, 64 allowed values and 512-byte values, every out-of-shape params form and wrong JSON type, missing context including an entry only in the other map, exact-byte matching without normalization, params checked before context), each profile's descriptor digest, and 13 request-context bound cases checked before claim. A matching `profile_digest` names a profile; passing this file is the evidence that an SDK implements the standard profiles identically. |
| `rotation-sequences.json` | AcceptRotation journal: genesis, repeat signatures, skipped sequence, continuation, fork freeze, frozen rejection, invalid recoveries, recovery epoch increase, and rejection of old-epoch statements. |

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
  "objects": [ objects.json "objects" entries ]
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
| Extension evaluator profiles | §5.2, §5.8 | `evaluator-profiles.json`, `verifier-ordering.json`, `object-negatives.json` | A positive signed receipt carrying `constraint_evaluators` in `objects.json`; a second SDK passing `evaluator-profiles.json` |
| Issuer duties, challenge issuance, status publisher | §5.1, §5.4, §7.3 | `issuer-duties.json`, `challenge-issuance.json`, `status-publisher.json` | |
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
| Cross-SDK fixtures | §8.1 | `cross-sdk/go.json`, verified by Go | Fixtures from TypeScript, Python, Rust, and C, and every SDK verifying every other's fixture |

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
