# Changelog

All notable changes to the Ratify Protocol are documented here. This project follows [Semantic Versioning](https://semver.org/).

For the release process and SDK coordination, see [`docs/RELEASES.md`](docs/RELEASES.md).

---

## v2.0.0-beta.1 (unreleased)

The first beta of Protocol v2 ([`SPEC-v2.md`](SPEC-v2.md)), a breaking,
separately versioned protocol line. It freezes the v2 wire format and SDK API
in Go, TypeScript, Python, Rust and C. Protocol v1 is unchanged and remains
available; its released tags and artifacts are not moved or replaced. Upgrade
guide: [`docs/PROTOCOL_V2_MIGRATION.md`](docs/PROTOCOL_V2_MIGRATION.md).

**Review status.** This is a prerelease. Review so far is internal
adversarial review of the specification, the shared vectors and every SDK.
External independent review has not happened; releasing the beta without it
is an accepted risk (SPEC-v2 §8.1). External review, interoperability with an
implementation outside this repository, and a soak are gates for `2.0.0`
(SPEC-v2 §8.2). No v2 release carries a production security claim yet.

### Breaking (relative to Protocol v1)

- **Not backward compatible.** New signed bytes, key IDs, challenge signing,
  status references and verifier ordering. A v2 verifier rejects v1 objects
  and never falls back; migration is a clean re-enrollment with fresh v2 keys
  and new delegations.
- **Signing transcript.** Ed25519 and ML-DSA-65 sign
  `M = "ratify-protocol-signature" || 0x00 || 0x02 || uint16_be(type_code) || SHA-384(signable)`,
  with the ML-DSA-65 context `ratify-protocol/2/<type_code>`. Both signatures
  must verify.
- **Key IDs** are the full 256-bit `key_id_v2` (64 hex characters), and trust
  is pinned to complete public keys.
- **Integers only.** No floating-point value anywhere on the wire; amounts use
  `max_amount_micros`.
- **Finite expiry.** Every delegation has a real `expires_at`, at most
  315360000 seconds after `issued_at`.

### Added

- **Crash, stress and shared concurrency tests.** The Go reference is
  crashed before and after every durable store write of five flows and
  restarted under two restart models; every crash point must keep the
  safety invariants and complete its work. The edge sentinel reference's
  test builds can exit at each durable write (`edge/tests/crash.sh`); no
  crash point fires the actuator twice or for a request that was not
  released. A multi-threaded C program stresses the C ABI with C store
  callbacks under AddressSanitizer, UndefinedBehaviorSanitizer and
  ThreadSanitizer (`sdks/c/scripts/test-v2-c-stress.sh`). The new shared
  vector file `concurrency-scenarios.json` gives every SDK the same
  concurrent workloads and outcome invariants.
- **Verify, then release.** `VerifyProofBundleV2` commits a terminal result
  and a receipt body that are not actionable; `ReleaseV2Decision` returns the
  only actionable decision after the signed receipt is appended and
  acknowledged by an independent checkpoint and the exclusive deadlines are
  still current.
- **Signed status** under a role-separated status key, applied through the
  anchored `SecurityJournalV2`, and a minimal status publisher (genesis,
  heartbeat, revoke) in every SDK.
- **Verification receipts** for every terminal result in a hash-chained log
  with checkpoint acknowledgements.
- **Challenge issuance helper** that persists each challenge before it is
  returned, and atomic challenge claims with replay epochs.
- **Exact `custom:` required scopes:** one exact `custom:<name>`, listed by
  every certificate in the chain; `custom:*` is invalid.
- **Extension evaluator profiles** in a caller-authenticated registry, with
  the standard `com.ratifyprotocol.max_count/v1` and
  `com.ratifyprotocol.allowed_values/v1`; the profiles a chain uses are
  signed into the receipt as `constraint_evaluators`.
- **A closed constraint registry:** `time_window` (pinned IANA tzdata
  `2025c`), `max_amount`, `max_rate`, `resource_path`,
  `ratify.receiver_audience`.
- **Typed signers only,** and an external signer interface (direct or
  external-mu mode) whose returned signatures are verified before use.
- **Wire limits** checked before parsing, and a closed table of 49 error
  classes.
- **Deployment profiles:** single-device offline (§7.13), dual-root
  composition (§7.14), middleware custody (§7.15).
- v2 rotation statements, witness entries, transaction receipts with
  composed verification, and archival verification (never actionable).
- **Shared corpus** `testvectors/v2` (25 vector files plus cross-SDK
  fixtures), run in full by every SDK, with every SDK verifying the fixtures
  every other SDK produces.
- **Runnable examples** in [`examples/v2/`](examples/v2/) for all five
  languages (quickstart, signed status, custom scope with `max_count/v1`,
  external signer), with identical output checked in CI. They use the
  test-only in-memory reference stores.

### Release and Part B store changes before the beta

These change the Part B interfaces every SDK implements; SDKs are ported to
match before the beta.

- **Finalization binds the receipt body to the sealed claim** (SPEC-v2 §7.5).
  The finalize helper and the reference claim store refuse a receipt body
  whose `verifier_id`, `agent_id`, `bundle_hash`, `issuer_ids`,
  `required_scope`, `context_policy_digest` or `constraint_evaluators`
  differs from the sealed claim (`configuration_invalid`; `malformed` for a
  body that does not decode). Go adds `ValidateV2FinalizationPayload` for
  claim-store implementers. Vectors: `lifecycle-scenarios.json`
  `finalize_rejects_body_with_other_*`, with the new `finalize` step.
- **Withheld is permanent; rejected is per call** (SPEC-v2 §6.9). When
  release is withheld at step 7 or 8 and no release is recorded, it records
  the withheld result through the same claim-store record call, and every
  later release of the claim returns that result right after step 1. If the
  store is unavailable while recording, the call is still withheld. A
  `rejected` result describes only that call and records nothing. Interface
  change: `V2ReleaseRecord` gains `Outcome` (`released` or `withheld`) and
  `Reason`; claim stores persist and return both, and compare them for the
  first-record-wins rule. Go adds `ValidV2ReleaseRecordOutcome`. The
  single-device complete-state projection's `release` member gains `outcome`
  and `reason` (SPEC-v2 §7.13). The reference checkpoint now timestamps
  acknowledgements from the store's authoritative clock and its high-water
  mark (SPEC-v2 §7.2). Vectors: `lifecycle-scenarios.json`
  `clock_regression_at_release_is_withheld` (extended),
  `recorded_withheld_answers_before_receipt_checks`,
  `withheld_after_recorded_release_records_nothing`,
  `corrupt_receipt_signature_is_rejected`,
  `receipt_of_another_claim_is_rejected` and
  `acknowledgement_for_another_entry_is_rejected` (extended),
  `device_rtc_regression` (now stays withheld); `device-state.json`
  `every_record_kind_with_withheld_record`.
- **`max_rate` admission is specified for the SDK surface** (SPEC-v2 §7.1,
  §7.2, §7.6). The reference claim store is the single-store
  implementation: it admits the sealed rate batch inside the terminal
  compare-and-set, all counters or none, counts only an `allow`, and its
  provisional `ReserveV2RateBatch` is never called and always fails. A
  separate rate store that cannot share the claim store's transaction is a
  managed-deployment option outside the SDK reference surface for beta. No
  interface change. Vectors: `lifecycle-scenarios.json`
  `rate_admission_is_all_or_none`,
  `rate_retry_and_changed_batch_count_once`,
  `rate_clock_rollback_keeps_admissions_blocking`, `rate_counts_only_allow`.
- **Journal head mismatch class** (SPEC-v2 §2.7): `log_state_mismatch` also
  covers a canonical `SecurityJournalV2` snapshot whose generation or digest
  does not match the anchored head, as every SDK and
  `security-journal.json` (`head_digest_mismatch`,
  `head_generation_mismatch`) already report. Specification text only.
- **The reference checkpoint freezes a log after a fork** (SPEC-v2 §7.8): a
  different entry hash at an acknowledged sequence is refused and no later
  sequence of that log is acknowledged. Vectors: `lifecycle-scenarios.json`
  `checkpoint_fork_freezes_log` and
  `checkpoint_refusal_without_fork_does_not_freeze`, with the new
  `acknowledge` step.
- **Rust and C interfaces for these changes.** Rust: `V2ReleaseRecord` gains
  `outcome` and `reason` (and no longer implements `Default`), with
  `valid_v2_release_record_outcome` and `validate_v2_finalization_payload`.
  C: `RATIFY_V2_ABI_VERSION` is 3. `RatifyV2ReleaseRecord` gains `outcome`
  (a `RatifyV2ReleaseStatus`) and `reason`, `RatifyV2TerminalClaim` gains
  `release_outcome` and `release_reason`, and the store helpers
  `ratify_v2_validate_finalization_payload` and
  `ratify_v2_valid_release_record_outcome` are exported. A C program built
  against ABI version 2 must be rebuilt.

### Changed in pre-release review

- **One future skew in the live verifier.** Status freshness uses
  `future_skew_seconds` (SPEC-v2 §6.1). A verify request whose status policy
  carries a different `clock_skew_seconds` is `configuration_invalid` before
  claim; previously the status policy skew silently governed status
  freshness. The status policy member remains for the standalone reducer.
- **Configured replay epoch** outside 0 through 2^53−1 is
  `configuration_invalid` at §6.2 step 2, before signatures; previously it
  surfaced later as `stale_replay_epoch`.
- **Expected session context length.** An `ExpectedChallenge` whose
  `expected_session_context` is present but not exactly 32 bytes is
  `configuration_invalid` at §6.2 step 2; previously, with no context policy,
  it surfaced later as `session_context_mismatch`.
- **Revoked `cert_id` length.** A revocation list or push whose revoked
  `cert_id` exceeds 512 UTF-8 bytes is `malformed` (SPEC-v2 §2.6); decoders
  previously accepted it.
- **Rotation verification clock bounds.** `now` outside 0 through
  253402300799 or a future skew outside 0 through 300 is
  `configuration_invalid` (SPEC-v2 §2.5, §5.5); previously any skew up to
  2^53−1 was accepted.
- **One future skew in transaction verification.** `VerifyTransactionReceiptV2`
  rejects a status policy whose `clock_skew_seconds` differs from
  `future_skew_seconds` with `configuration_invalid` (SPEC-v2 §5.7), as the
  live verifier does. Vector: `transaction-verification.json`
  `configuration_invalid_status_skew_differs`.
- **Standalone preflight replay epoch.** `ValidateProofBundleV2Preflight` and
  `PreflightProofBundleV2` report a configured replay epoch outside 0 through
  2^53−1 as `configuration_invalid`, like `VerifyProofBundleV2`.
- **Transaction receipt nested bundles** are strictly decoded, and must be
  canonical, before their hash is compared, so a malformed nested bundle is
  `malformed` rather than `bundle_hash_mismatch` (SPEC-v2 §5.7).
- **Finalization binds a null `context_policy_digest`** (all SDKs). The
  finalization helper and every reference claim store compared only a
  non-null receipt-body digest with the sealed claim, so a body that dropped
  the configured policy's digest was committed. Once `context_assessment` is
  other than `not_evaluated`, the body's digest must now equal the sealed
  claim's (null only for a claim sealed without a context policy); otherwise
  the finalization is `configuration_invalid` and commits nothing (SPEC-v2
  §7.5). Vectors: `lifecycle-scenarios.json`
  `finalize_rejects_body_with_null_context_policy_digest_unverified`,
  `..._unbound`, and `finalize_rejects_body_with_context_policy_digest_not_evaluated`
  (`malformed`, as §5.8 already requires a null digest there).
- **Status evidence batch: one rule for nested objects** (all SDKs). The
  JSON value model (UTF-8, duplicate member names, number grammar and
  safe-integer range, `-0`, unpaired surrogate escapes, nesting depth
  counted from the batch array) applies to the whole batch document,
  nested objects included; object schema rules (member names and case
  variants, nullability, required members, base64 spelling of byte fields)
  apply to a nested object only when it is decoded under its code during
  authentication (SPEC-v2 §2.1, §6.5). Every SDK already applied the value
  model to nested objects and left their schema alone, except that it
  rejected a nested byte field such as `ed25519` or `challenge` spelled as
  non-canonical base64; such a batch now decodes and the object fails
  authentication instead, with the same `unavailable` status result.
  Vectors: 19 new `limits.json` `status_evidence_batch/nested_*` cases.
- **Python: claim_already_terminal carries no store state.** The Python
  reference store re-raised `claim_already_terminal` from inside the handler
  of an internal exception that held the live claim record, so the error's
  `__context__` reached it. The error is now raised with no chained
  exception, as in the other SDKs (SPEC-v2 §7.3).
- **Edge sentinel reference: recovery validates what it commits.** The
  reference's own C claim store committed any lease-expiry recovery result;
  it now validates the result and body as its finalization does and accepts
  only `indeterminate / evaluation_interrupted` (SPEC-v2 §7.5). Its
  finalization also refuses an allow horizon that does not match the
  decision (§6.8).
- **C: callback text must be valid UTF-8, and the release-record predicate
  fails closed.** A string a callback answers with (a claim ID, log ID,
  digest, reason, receiver or trust-domain ID) that is not valid UTF-8 now
  fails that provider or store closed instead of being compared as a lossy
  copy. `ratify_v2_valid_release_record_outcome` returns 0 for a NULL or
  non-UTF-8 reason (SPEC-v2 §1.3). `ratify_error_free` documents that it
  frees every v1 and v2 `err_out` string.
- **The allow horizon matches the decision at finalization** (all SDKs).
  A reference claim store refuses an `allow` receipt body finalized without
  a positive `allow_valid_until`, and any other decision finalized with one,
  as `configuration_invalid` (SPEC-v2 §6.8, §7.5). Before, an allow with no
  horizon skipped the horizon check and `max_rate` admission (release then
  withheld it), and a non-allow with a horizon was counted against the rate
  limit. A non-allow must carry exactly 0 and an allow a horizon no later
  than 253402300799. Vectors: `lifecycle-scenarios.json`
  `finalize_rejects_allow_without_allow_horizon`,
  `finalize_rejects_allow_horizon_on_non_allow`,
  `finalize_rejects_negative_allow_horizon_on_non_allow` and
  `finalize_rejects_allow_horizon_beyond_timestamp_domain`.
- **Recovery accepts what finalization accepts** (Go, Rust, C). The Go and
  Rust reference stores required the recovered terminal result to hold only
  string members, which finalization does not require, so the same bytes
  committed through finalize but not through recovery. Recovery now reads
  the decision and reason from the validated receipt body, as TypeScript and
  Python already did (SPEC-v2 §7.5). Vector:
  `recover_direct_accepts_terminal_result_with_other_members`.
- **Lease-expiry recovery validates what it commits** (all SDKs). Every
  reference claim store's recovery operation accepted any terminal result
  whose decision and reason were `indeterminate / evaluation_interrupted`,
  with any receipt body, so a body that was not a receipt body (for example
  `{"decision":"allow","verifier_id":"forged"}`) or that named another
  claim was sealed as the terminal result: the claim could then never
  publish, and a canonical recovery failed `claim_already_terminal`.
  Recovery now validates the result and body exactly as finalization does
  (`malformed` for a body that is not a canonical receipt body,
  `configuration_invalid` for one that does not bind the sealed claim) and
  requires `indeterminate / evaluation_interrupted`
  (`configuration_invalid`, previously an unclassified error); a refused
  recovery commits nothing (SPEC-v2 §7.5). The recovery helpers already
  built the canonical body and are unchanged. Vectors: 6 new
  `lifecycle-scenarios.json` scripts through a new `recover_direct` step.
- **Extension `params` are application data at every depth** (all SDKs).
  The strict wire check applied canonical-base64 validation to any string
  member named like a protocol byte field (`challenge`, `ed25519`,
  `session_context`, ...) at any depth, including inside a constraint's
  `params` object, so a correctly signed certificate whose unregistered
  constraint carried `params: {"challenge":"!"}` was `malformed` in every
  SDK. Inside `params` only the JSON value model applies (SPEC-v2 §2.1,
  §5.2; the text now says so explicitly), as it already did for nulls and
  member-name case. Vectors: `objects.json`
  `delegation_extension_params_byte_field_names` and
  `proof_bundle_extension_params_byte_field_names`.
- **Bounded decode runs before every configuration check** (all SDKs).
  The verifier checked for a missing claim store before decoding the
  bundle, so a malformed bundle with no claim store was
  `configuration_invalid` instead of `malformed`, contrary to the SPEC-v2
  §6.2 order. Decoding now runs first, and step 2 lists the claim store
  among the configuration it checks; no callback runs in either case.
  Vectors: `verifier-ordering.json` `pre_malformed_and_claim_store_absent`
  and `pre_claim_store_absent`, with a new `claim_store` mode `absent`.
- **C ABI return conventions stated exactly** (SPEC-v2 §1.3). The text said
  every C function returns an integer status and every export returns the
  internal-failure code after a caught panic, but the version, string,
  predicate and free functions do not return a status. §1.3 now lists the
  four forms with their result after a failure or caught panic: version
  numbers return 0, strings return a fixed library-owned string,
  predicates return their fail-closed value, and free functions return
  nothing (a NULL pointer is a no-op and a poisoned handle is still freed).
  Text only; the library already behaved this way.
- **The live verifier takes the configured verifier key ID** (all SDKs).
  SPEC-v2 §2.4 and §6.1 require the ExpectedChallenge and the proof bundle
  to name the caller-authenticated verifier key ID, but no SDK took that
  value, so a proof and an ExpectedChallenge that both named another
  verifier committed an `allow` (release then refused it). The value is now
  required configuration: an empty or non-canonical verifier key ID is
  `configuration_invalid` at §6.2 step 2, and an ExpectedChallenge or proof
  naming another verifier is `verifier_id_mismatch` at step 6, before claim.
  API changes: Go `V2VerifyRequest.VerifierID`, and a `configuredVerifierID`
  parameter after `configuredReplayEpoch` in `PreflightProofBundleV2` and
  `ValidateProofBundleV2Preflight`; TypeScript `V2VerifyRequest.verifierID`
  and the same parameter in `preflightProofBundleV2` and
  `validateProofBundleV2Preflight`; Python `V2VerifyRequest.verifier_id` and
  a `configured_verifier_id` parameter in `preflight_proof_bundle_v2` and
  `validate_proof_bundle_v2_preflight`; Rust `V2VerifyRequest::verifier_id`
  and a `configured_verifier_id: &str` parameter in
  `preflight_proof_bundle_v2` and `validate_proof_bundle_v2_preflight`; C:
  the `request_json` of `ratify_v2_verify_proof_bundle` and
  `ratify_v2_claim_proof_bundle` gains the required member `verifier_id`
  (no C struct or signature changes, so `RATIFY_V2_ABI_VERSION` stays 3; a
  request without it is now a preflight `configuration_invalid`). Vectors:
  `verifier-ordering.json` `configured_verifier_id` in every case,
  `pre_verifier_id_*`, `pre_namespace_before_verifier_id` and
  `config_verifier_id_*`.
- **An empty configured namespace is `configuration_invalid`** at §6.2 step 2
  (all SDKs); it was reported as `namespace_mismatch` at step 6. The vector
  formerly named `pre_empty_configured_namespace` emptied the
  ExpectedChallenge namespace, not the configured one, and is renamed
  `pre_empty_expected_namespace`. Vectors: `config_namespace_empty` and
  `config_namespace_empty_before_expected_challenge`.
- **Release of a handoff whose claim the store does not hold is rejected**
  (all SDKs). Release step 1 returned `pending / claim_store_unavailable`
  for every load failure, so a claim the store answered it did not hold
  (`claim_not_found`) was reported as retryable forever. It is now
  `rejected / release_state_mismatch`; only an unavailable store is
  `pending` (SPEC-v2 §6.9). Vector: `lifecycle-scenarios.json`
  `release_of_claim_the_store_does_not_hold`.
- **`issued_at < expires_at` for challenge records and membership
  evidence** is stated in SPEC-v2 §2.5, §5.2 and §6.2 step 6, as every SDK
  already enforced it: an ExpectedChallenge that violates it is
  `configuration_invalid` before claim even when each freshness inequality
  holds, and audience membership evidence that violates it is
  `constraint_unverifiable`. Vectors:
  `pre_expires_before_issued_within_skew`,
  `aud_membership_expires_before_issued` and
  `aud_membership_expires_equals_issued`.
- **Transaction receipt party `proof_bundle_hash` shape** (all SDKs). A value
  that is not `sha384:` followed by 96 lowercase hex characters (for example
  uppercase hex) is `malformed` at decode, before the hash is compared; it
  was `bundle_hash_mismatch` (SPEC-v2 §5.7, §2.7). Vectors:
  `object-negatives.json` `transaction_receipt/party_bundle_hash_*`.
- **Transaction terms are one JSON object** (SPEC-v2 §5.7), as every SDK
  already required. Text, plus vectors
  `object-negatives.json` `transaction_receipt/terms_not_object_*`.
- **More verifier ordering cases** (`verifier-ordering.json`, 342 to 485
  cases, and to 515 below): status-key epoch transitions through the live verifier, with a
  new optional `journal.setup` member that lists explicit journal setup
  steps; paired pre-claim and post-claim failures; status journal
  sequences; `tz` names in and out of tzdata `2025c`; `resource_path`
  spellings; audience membership shapes; scope wildcards; and the
  configured verifier identity above. Every SDK harness, including the
  plain C program, runs them.
- **Journal snapshot fuzzing in TypeScript and Python.** The randomized
  decoder suites now cover the `SecurityJournalV2` snapshot importer (SPEC-v2
  §8.1 item 2) with arbitrary bytes, arbitrary JSON, mutations of a populated
  snapshot and the size and depth limits; an import that succeeds must
  re-export the identical bytes. Go and Rust already fuzzed it.
- **Transaction receipt canonical form is checked first** (every SDK; the C
  ABI uses the Rust decoder). A non-canonical transaction receipt is
  `malformed` whatever else is wrong with it (SPEC-v2 §2.1). Decoders
  compared the bytes with the canonical encoding last, so a receipt that was
  also badly signed, mis-hashed or mis-bound reported `invalid_signature`,
  `bundle_hash_mismatch`, `transaction_context_mismatch` or
  `transaction_signature_set_invalid`, and a non-canonical receipt of up to
  5 MiB was fully signature-verified before it was refused. The outer
  receipt is compared before any nested proof bundle is decoded, with each
  bundle in its canonical form and `parties` and `party_signatures` in
  `party_id` order, so a bundle fault such as `key_id_mismatch` does not mask
  a non-canonical bundle or array order either. Vectors:
  `object-negatives.json` `transaction_receipt/noncanonical_*` and
  `transaction_receipt/unsorted_*`.
- **A repeated party is `malformed` first; a repeated signature record is a
  signature set fault** (every SDK). The canonical check that runs before
  any nested bundle is decoded requires `parties` in strictly ascending,
  unique `party_id` order. A repeated signature record stays
  `transaction_signature_set_invalid`, and the signature set is checked after
  every nested bundle is decoded and its hash compared, so a bundle fault
  beside it is reported first. SPEC-v2 §5.7 now states this order. Vectors:
  `object-negatives.json` `transaction_receipt/duplicate_party_and_*` and
  `transaction_receipt/signature_duplicate_and_*`.
- **Cross-SDK fixtures from the beta.** The five `testvectors/v2/cross-sdk`
  fixtures are regenerated by each SDK at `2.0.0-beta.1` (Python `2.0.0b1`),
  and every SDK verifies all five. The release-sync check now refuses a
  fixture whose `sdk_version` is not the release being prepared.
- **Faster TypeScript decoding of large transaction receipts.** The
  canonical encoder writes a string that needs no escape as it is, and
  SHA-384 over a receipt's signable bytes and terms uses Node's native hash
  when the runtime provides it, with `@noble/hashes` as the fallback. A
  5 MiB receipt decodes in about a fifth of the time. Output bytes are
  unchanged.
- **A sealed terminal result is exactly its canonical form** (every SDK and
  the C ABI). Finalization, lease-expiry recovery and resumption now require
  the terminal-result bytes to be the RatifyCanonicalJSON of the receipt
  body's `decision`, `decision_reason` and `identity_status` (SPEC-v2 §7.5,
  §7.13), and refuse anything else as `configuration_invalid`. They compared
  only the decision and reason, so a result with further members, another
  spelling, no `identity_status`, or a contradicting `identity_status` could
  be committed. Release always acted on the signed receipt, so no decision
  changed. Finalization also validates the payload before comparing it with
  the local evaluation, so a body that is not a receipt body stays
  `malformed`. Vectors: `lifecycle-scenarios.json`
  `recover_rejects_terminal_result_*`,
  `finalize_rejects_body_with_other_terminal_*` and
  `resume_rejects_record_terminal_result_*`, replacing the scenario that
  accepted further members. A store written by an earlier alpha that holds a
  terminal result in another form no longer resumes.
- **C ABI evaluator registrations need an implementation.** A custom
  registration whose `evaluate` callback is NULL is `configuration_invalid`
  before the challenge is claimed, as in Go, TypeScript and Python. The C
  ABI built the registry anyway and failed only when the evaluator ran, after
  the claim, so the challenge was consumed and the result was
  `deny / constraint_unverifiable`.
- **Specification clarifications.** An empty `expected_receiver_id` at
  issuance names no receiver, as in the device-state encoding, so a named
  receiver ID is 1 to 512 bytes (§7.3). An `ExpectedChallenge` `replay_epoch`
  outside 0 through 2^53−1 is `stale_replay_epoch` (§6.2 step 6). Every SDK
  already behaved this way.
- **More shared vectors.** `verifier-ordering.json` 485 to 515 cases, and
  every ordering vector now lists the exact status-provider requests (issuer,
  references in chain order, status key epoch and ID), which every SDK
  harness asserts: ascending issuer order that differs from chain order,
  repeated issuers, trust answers, extension registries, an exact audience
  match with a failing provider, configured verifier ID forms and §2.5
  bounds. `object-negatives.json` 433 to 476: fully re-signed wire-layer
  cases (small-order and mixed-order Ed25519 keys that satisfy the
  cofactorless equation, ML-DSA under another context, UTF-16 key-order
  traps, escape spellings, byte fields at wrong lengths). `limits.json` 76 to
  80 (a valid transaction receipt at exactly 5 MiB, chains of 8 and 9).
  `digest-functions.json` 16 to 25. `challenge-issuance.json` 10 to 11 (the
  receiver ID byte bound). `lifecycle-scenarios.json` 80 to 108 Part B
  scripts (a withheld result whose record fails or conflicts, substituted and
  forged committed records refused at release, resumption record checks,
  clock classes at resumption and recovery). `concurrency-scenarios.json`
  17 to 18 (resumption racing an allow finalization). The C ABI program
  feeds every ordering vector trust outcomes and claim dispositions outside
  their enums and requires them to act as a failing provider. The edge crash
  test now checks release records after the restart in every flow and adds a
  withheld flow.

### Fixed

- **Committed work is resumed from the claim store after a lost handoff**
  (every SDK and the C ABI). A process that ended after the terminal
  compare-and-set but before the verifier returned lost the only handoff of
  the committed result: the retry was a terminal replay with no handoff and
  recovery accepted only an interrupted result, so the receipt was never
  published, the decision never released, and every later receipt of the
  log waited behind it. Safety held; progress did not. SPEC-v2 §7.11 now
  requires resumption by claim ID from the persisted record. New
  `ResumeCommittedClaimV2` (Go), `resumeCommittedClaimV2` (TypeScript),
  `resume_committed_claim_v2` (Python and Rust) and
  `ratify_v2_resume_committed_claim` (C) load the record through a new
  one-method store interface (`LoadV2CommittedClaim` and its counterparts;
  in C a new `RatifyV2CommittedStoreCallbacks`, leaving existing structs
  unchanged), apply the terminal commit's checks (claim key, finalization
  payload, allow horizon; a failure is `claim_store_unavailable`) and return
  the committed handoff for publication and release. The store answers
  `claim_not_found`, `claim_lease_live` or `claim_lease_lost` for a claim
  without a committed record. The reference stores implement it, and shared
  lifecycle scenarios pin the `resume` step in every SDK.
- **LangChain reference: the receiver parses a signed presentation header
  however it arrives.** The presentation travels in one HTTP header of about
  38 KB, larger than the 16 KiB of incomplete headers the server's HTTP
  parser buffers by default. When the headers arrived in several reads, as
  under heavy load, the receiver answered `400` before its own boundary saw
  the request; this was the intermittent gate failure. The parser now
  buffers every header the boundary admits (64 KiB for the presentation)
  plus the other headers, and a test sends a maximum-size header in small
  pieces. The v1 copy under `references/langchain/v1/` is dated history
  and is unchanged.
- **Reference claim stores refuse a claim ID that is not derived from its
  replay key** (Go, TypeScript, Python and Rust, the C reference store
  over Rust, the plain C test store and the edge sentinel store). SPEC-v2 §7.3 makes the claim store unique by namespace, replay
  epoch and challenge digest; the stores keyed their records by the supplied
  claim ID without checking it, so a caller that called the store directly
  with another ID could create a second claim for one challenge. The verifier
  always derives the ID and was not affected. A mismatched ID, or a challenge
  digest that is not a `sha384:` digest, is now `configuration_invalid` and
  creates nothing. The `device-state.json` projections now carry derived
  claim IDs, so every vector state is one a store can hold. A C store keyed
  by claim ID applies the same check through the new predicate
  `ratify_v2_claim_id_matches_key`.
- **C: evaluation progress records are validated before they are stored.**
  The new predicate `ratify_v2_valid_evaluation_progress` is the check the
  Go, TypeScript, Python and Rust reference stores apply (SPEC-v2 §7.5). The
  plain C test store and the edge sentinel reference store now reject an
  invalid record as `RatifyV2Malformed`; the edge store used to keep it, and
  lease-expiry recovery of that claim then failed instead of committing
  `evaluation_interrupted`. The C ABI also named the evidence member
  `status_evidence`; a progress record now carries `status_evidence_digests`
  as §7.5 requires, and the predicate accepts only the RatifyCanonicalJSON
  form with all five members, so a record without `context_policy_digest`
  or with another encoding is malformed. Lease-expiry recovery applies the
  same check to the progress and claim records a C store returns, so a
  record the store altered is refused as `RatifyV2Malformed` instead of
  being sealed; that includes a claim record whose `claim_id` no longer
  derives from its challenge digest. The plain C test store's recovery now
  validates the result as its finalization does, so an invalid recovery
  payload commits nothing. `ratify_v2_claim_id_matches_key` also requires
  every scalar field of the claim view to equal the sealed record's, so a
  store's freshness rule cannot read a later expiry than the claim carries
  and create an expired claim. A slice a C callback returns with a NULL
  pointer and a non-zero length is now refused instead of being read as
  empty; recovery used to seal the initial progress for it. The same holds
  for an audience membership's `trust_domain_ids`: a NULL list with a
  non-zero length is a provider failure (`constraint_unverifiable`), not an
  empty list (`constraint_denied`). The C claim record is now exactly the §7.13 sealed claim
  object (`stream_id`, and `null` for a policy-less
  `context_policy_digest`).
- **Release withholds a finalization time outside the timestamp domain**
  (Go, TypeScript, Python, Rust, and C through Rust). Step 7 required
  `T_final <= ack.timestamp <= T_release` but never checked that `T_final`
  was a timestamp, so a claim store answering a negative finalization time
  for a committed allow had it released. Release now returns
  `withheld / clock_regressed` (SPEC-v2 §6.9 step 7 states the domain
  requirement for `T_final` and `ack.timestamp`).
- **Reference authoritative clocks stay in the timestamp domain** (Go,
  TypeScript, Python, Rust, and the plain C test store). A reading past
  253402300799 is refused as `claim_store_unavailable` instead of returned.
  The plain C test store's evaluator capability is now random, and the edge
  sentinel checkpoint answers a retry only when its predecessor hash matches
  as well. The edge checkpoint answers an acknowledged sequence before it
  reads its clock, so an identical retry returns the original acknowledgement
  even when the current time is unusable.
- **Reference checkpoints keep every acknowledgement in the timestamp domain**
  (Go, TypeScript, Python, Rust, and the edge sentinel). A reference
  checkpoint whose clock was past 253402300799 still acknowledged an entry
  with that time; it now refuses, as SPEC-v2 §7.8 requires. Release already
  refused such an acknowledgement. The edge sentinel checkpoint also refused
  an identical retry of an earlier acknowledgement once a fork had frozen
  the log; it now returns the original acknowledgement, and the plain C
  test store's checkpoint acknowledges in order only and freezes on a fork.
- **v1 `max_rate` fails closed when the rate count is unavailable** (Go, Rust,
  C, TypeScript and Python). A negative count from the invocation counter is now
  `constraint_unverifiable` instead of passing. Through the C ABI, a
  `cert_id` containing U+0000 used to skip `rate_fn` and pass `max_rate`; it
  now fails closed the same way without calling the callback.
- **Python: store failures are contained like any other failure.** The
  claim store (claim, progress write, finalization, lease-expiry recovery,
  release load and record, and the release clock), the rate store and the
  `SecurityJournalV2` store adapters caught only `Exception`, so a store
  that raised another `BaseException` escaped the verifier instead of
  failing closed as Go does for a store panic. Every `BaseException` is now
  classified exactly as an `Exception` failure; `KeyboardInterrupt` and
  `SystemExit` are the caller's own cancellation and propagate.
- **C: `ratify_v2_release_decision` sets `*released_out` to NULL on entry.**
  A successful call that did not release left the output unwritten, so a
  reused caller variable could still hold an earlier released handle.
- **C: `ratify_v2_object_decode` decodes a status evidence batch at the
  envelope only** (SPEC-v2 §6.5 step 3), as the Go, TypeScript, Python and
  Rust batch decoders do. It used to decode and re-encode every nested
  object, so it rejected batches the other SDKs accept. A non-NULL
  `canonical_out` is the §6.5 canonical batch encoding, byte for byte what
  the other SDKs' batch encoders produce: each nested object is decoded and
  re-encoded, and one that does not decode under its code makes the call
  `malformed`.
- **C: identifiers containing U+0000 are never stripped before a
  callback.** The callback adapters removed the NUL, so a C store keyed
  `"lab\0x"` and `"labx"` (or rate counters for `"x\0y"` and `"xy"`) to the
  same record. A configured `verifier_namespace` containing U+0000 is now
  `configuration_invalid`; any other such identifier fails the call closed
  as that provider or store being unavailable, without calling it.
- **C: `ratify_set_entropy_source` is declared only under
  `RATIFY_CUSTOM_ENTROPY`.** It is exported only by a `custom-entropy`
  build, but the header declared it unconditionally, so a default-build
  program that referenced it failed to link. The C ABI test now links every
  function the header declares by default against the default build.
- **C: provider answers are bounded before they are copied.** A status
  batch over 64 objects or 8 MiB is refused before any object is copied
  (the verifier rejected it only after copying, so a large answer cost its
  full size in memory). The audience adapter copies only memberships for a
  deferred constraint, at most two per constraint, which leaves the result
  unchanged.
- **C: forged lengths and counts no longer abort the process.** A length
  or count over `PTRDIFF_MAX` bytes in total, passed by a caller or returned
  by a callback, used to reach `slice::from_raw_parts`, which aborts instead
  of unwinding into the panic guard. `ratify_v2_object_decode(kind, p,
  SIZE_MAX, out)` was one such call; an audience answer with
  `count = SIZE_MAX` was another. Every v1 and v2 export now checks the
  length before reading. An input with a SPEC-v2 §2.6 byte limit (every
  strict decoder input, including the bundle and receipt the verifiers
  decode) is reported exactly as a real oversized input (`malformed` before
  parsing, after any check the operation makes first) and is never read;
  any other byte input or count is `bad_argument` (v1:
  `RatifyErrBadArgument`). An audience answer whose membership or domain
  count is over the bound is `constraint_unverifiable`, any other callback
  answer fails closed as that provider or store failing, and an evaluator
  registry over 32 entries is `configuration_invalid` before any entry is
  read.
- **C: `ratify_v2_verify_object` rejects unknown context members**
  (`bad_argument`), as the README states for every structured input. It
  used to ignore them, so a misspelled member was silently dropped.
- **C: `ratify_v2_challenge_time_current` fails closed on out-of-range
  configuration.** A maximum age outside 1 to 300 seconds or a skew outside
  0 to 300 seconds returns 0. Inside those bounds the result matches the
  documented formula; with a negative skew it used to contradict it.
- **C: documentation corrections.** `RatifyV2ErrCancelled` and the README
  now give its effect per callback (it is not always
  `evaluation_cancelled`); callback output pointers must stay valid until
  the library copies them, never on the callback's stack; the claim store's
  `now` is not called during verification.
- **TypeScript: a `claim_already_terminal` error carries no store state.**
  The reference store attached its live claim record to the error, and the
  verifier returns that error in `V2VerifyOutcome.error`, so a caller could
  change the stored allow horizon or abandonment of a committed claim
  (SPEC-v2 §7.3). The error is now a plain classified error.
- **TypeScript: large byte fields no longer exhaust the stack.** The
  canonical base64 check used a backtracking pattern that overflowed the V8
  stack at about 4.47 million characters, so a valid transaction receipt
  with terms over about 3.35 MB was `malformed` in TypeScript only. The
  check is now a linear scan with the same accepted shapes.
- **C: request configuration failures are reported after the bundle
  decodes** (SPEC-v2 §6.2). A configured `verifier_namespace` containing
  U+0000, or a `context_policy` that cannot be built, failed
  `ratify_v2_verify_proof_bundle` as a call before the bundle was decoded,
  so a malformed bundle reported `configuration_invalid` with no outcome.
  Both are now a preflight outcome at step 2, after decode, as in the other
  SDKs: `configuration_invalid`, or `expected_challenge_unavailable` for
  such a policy without a challenge record. No callback runs.
  `ratify_v2_claim_proof_bundle` also decodes first.
- **Python: `release_v2_decision` classifies a receipt that is not bytes.**
  A `str` or other non-bytes signed receipt raised `TypeError` from
  release step 2; it is now `rejected / receipt_invalid`, as in the other
  SDKs. An `int`, which `bytes()` turned into zero bytes, gets the same
  result without being converted.

### Not carried into v2

The no-expiry sentinel, an empty required scope, floating-point constraint
values, the identity enrollment objects, the `PolicyProvider`,
`AuditProvider` and `PolicyVerdict` hooks, `AnchorResolver` inside
verification, unsigned or boolean revocation inputs and
`ForceRevocationCheck`, and self-issued live challenges.

### v1-only until 2.1

The SessionToken fast path, the A2A mutual presentation profile, the HTTP and
registry bindings, and the geo and speed constraints have no v2.0
equivalent. They are planned for Protocol 2.1, together with activation
constraints; until then, claims that depend on them are v1 claims.

### Packages

| SDK | Package |
| --- | --- |
| Go | module `github.com/identities-ai/ratify-protocol/v2` |
| TypeScript | `@identities-ai/ratify-protocol` 2.x, dist-tag `next` (`latest` stays on v1 until `2.0.0`) |
| Python | `ratify-protocol` 2.x, module `ratify_protocol.v2`, with the `protocol-v2` extra for the signing backend `ratify-protocol-native-v2` |
| Rust | crate `ratify-protocol` 2.x, module `ratify_protocol::v2` |
| C/C++ | `ratify-c` 2.x, `ratify_v2_*` ABI with `ratify_v2_abi_version()` |

- **Python ships both lines in one distribution.** Protocol v2 is
  `ratify_protocol.v2` in `ratify-protocol` 2.0.0b1, as TypeScript and Rust
  already carry it, instead of a separate `ratify-protocol-v2` distribution,
  which is never published. The v1 API at `ratify_protocol` is unchanged and
  never imports `ratify_protocol.v2`. The base requirements stay v1's; v2's
  come with the extra: `pip install "ratify-protocol[protocol-v2]==2.0.0b1"`
  adds `ratify-protocol-native-v2==2.0.0b1` and `tzdata==2025.3`. Every
  published version is a prerelease, so pip treats 2.0.0b1 as the newest
  release for an install or upgrade without a pin; a v1 user who upgrades
  lands on it with v1's requirements intact. To stay on the v1 release line,
  pin `ratify-protocol<2` or `ratify-protocol==1.0.0a21`, the v1 maintenance
  release `v1.0.0-alpha.21`. The extra is named `protocol-v2` rather than
  `v2` because an extra name that parses as a version makes pip 25.0 fail to
  resolve the package.

### Known limits

- The in-memory reference stores are for tests and examples only; production
  needs durable Part B stores and an independent checkpoint.
- The external signer interface makes no claim about any particular KMS or
  HSM.
- Embedded v2 targets other than armv7 Linux are untested.

## v1.0.0-alpha.20 (2026-09-01)

Completes the C SDK's context-binding surface. No canonical bytes, fixture
contents, wire format or verifier behavior change, and the protocol version
remains 1. The Go, Rust, Python and TypeScript SDKs are unchanged in this
release; their versions move only to keep the release line synchronized.

### Added

- **C: `ratify_proof_bundle_create_with_context`.** Every other reference
  implementation could already build a ProofBundle bound to a 32-byte session
  context: Go through `SignChallengeWithSessionContext`, Rust through
  `sign_challenge_with_session_context`, and Python and TypeScript through the
  optional `session_context` argument on their challenge signing functions. The
  C SDK could not, so a C caller could verify a context-bound proof but never
  produce one, and any C integration needing that binding had to reach outside
  the published surface.

  The new function mirrors `ratify_proof_bundle_create` with two extra
  parameters, and follows the Go and Rust shape of a separate entry point
  rather than an optional argument, which C cannot express. Both the challenge
  and the session context must be exactly 32 bytes; any other length returns
  `RatifyErrBadArgument` and produces no bundle. Existing symbols are
  unchanged, so the addition is ABI-compatible for callers already linked
  against alpha.19.

## v1.0.0-alpha.19 (2026-08-30)

A security release for the TypeScript SDK. No canonical bytes, fixture
contents, wire format or verifier behavior change, and the protocol version
remains 1.

### Fixed

- **TypeScript: quadratic backtracking when stripping base64 padding.** The
  fallback decoder in `sdks/typescript/src/canonical.ts` stripped trailing `=`
  with the regular expression `/=+$/`. Against a run of `n` padding characters
  followed by any non-terminal character, that expression backtracks
  polynomially: measured at 52 ms for 10 000 characters, 847 ms for 40 000 and
  3.4 s for 80 000, which extrapolates to several seconds of blocked event loop
  at the 128 KiB `MAX_PROOF_BUNDLE_BYTES` ceiling. The decoder is exported and
  its input is not always size-checked before the call, so one crafted bundle
  could stall a verifier.

  The strip now scans backwards, which is linear and measured below a
  millisecond at every size above.

  This affects only the path taken where `Buffer` is undefined: browsers, Deno
  without node compatibility, and edge runtimes. Node.js uses `Buffer` and was
  never exposed. Decoded output is unchanged and the canonical fixtures still
  pass byte-identically.

### Changed

- **CI workflow token scoped to read-only.** `.github/workflows/ci.yml` declared
  no `permissions` block, so its token inherited the repository default, which
  may grant write. Every job in that workflow only checks out and runs tests.
  Publishing lives in `release.yml`, which grants its own scopes.

---

## v1.0.0-alpha.18 (2026-08-30)

An SDK surface release. No canonical bytes, fixture contents, wire format or
verifier behavior change, and the protocol version remains 1.

### Added

- **Deterministic key generation in Rust and C.** `docs/SDKS.md` requires every
  SDK to export `HybridKeypairFromSeeds`, and neither the Rust SDK nor the C ABI
  had it. Without it an application cannot reconstruct an identity it created,
  so a C or Rust issuer could mint a key and publish its public half but never
  load it back, and any verifier pinning that identity broke on the next
  restart. Seeds are the portable unit of private key material: the protocol
  specifies no private-key serialization format, so storing two 32-byte seeds
  and rebuilding is the supported way to persist an issuer identity.
- **Remaining minimum-surface entries in the C ABI:** `ratify_derive_id`,
  `ratify_canonical_json`, `ratify_delegation_sign_bytes_hex`,
  `ratify_challenge_sign_bytes_hex`, `ratify_verify_delegation_signature`,
  `ratify_agent_sign_challenge`, `ratify_verify_challenge_signature`,
  `ratify_generate_hybrid_keypair`, `ratify_human_root_from_seeds`,
  `ratify_agent_from_seeds`, `ratify_agent_pub_key_json`, and the operation- and
  session-context byte helpers. Four entries take a different shape because the
  ABI has no value types; each is documented in `docs/SDKS.md`.
- **A deterministic keygen known-answer vector** asserted by the Go, Rust, C and
  TypeScript suites. The canonical fixtures carry no seeds, so nothing held the
  seeded implementations to each other: one could have been deterministic and
  deterministically different from the rest with every existing test passing.

### Fixed

- **The native extra's pyo3 dependency carried three security advisories.**
  `ratify-protocol-native` was introduced pinned to pyo3 0.22, which is subject
  to GHSA advisories for an out-of-bounds read in `PyList`/`PyTuple` iterator
  `nth`/`nth_back` (high), a missing `Sync` bound on
  `PyCFunction::new_closure` (moderate), and a buffer overflow risk in
  `PyString::from_object` (low). The extension calls none of those APIs, so
  none was reachable through it, but a package in this project's supply chain
  should not ship against known advisories. Now pinned to pyo3 0.29, which
  patches all three. `PyBytes::new_bound`, the transitional name from pyo3's
  Bound migration, is now `PyBytes::new`. Key generation output is unchanged
  and still matches the cross-SDK vector byte for byte.

- **Python: `time_window` constraints were denied on any host without a system
  IANA time zone database.** `zoneinfo` reads the operating system's copy where
  one exists and falls back to the `tzdata` package where it does not. Windows
  ships no system database and minimal Linux containers often omit theirs, so on
  those hosts every `time_window` constraint resolved no zone and failed closed
  with `constraint_denied: unknown timezone`. The same proof bundle therefore
  verified on one machine and was rejected on another. `tzdata` is now a
  dependency. Affects every published Python release to date; no other SDK is
  affected, and nothing about the wire format or the fixtures changes.

- **The C conformance suite did not assert two requirements it claimed to meet.**
  `docs/SDKS.md` requires that for every `Kind = verify` fixture an SDK's
  delegation signing bytes match `expected.delegation_sign_bytes_hex` and its
  challenge signing bytes match `expected.challenge_sign_bytes_hex`. The Go and
  Rust suites assert both. The C suite asserted neither, because the ABI did not
  expose the helpers, so it was structurally narrower than the contract. Both
  assertions now run across all canonical verify fixtures.
- **The generated C header could go stale.** `sdks/c/build.rs` declared
  `rerun-if-changed` for `src/lib.rs` only, while most of the ABI lives in
  `src/advanced.rs`. A change confined to that file regenerated nothing, so the
  committed `include/ratify.h` kept its previous contents: a newly added symbol
  was compiled into the library but never declared for callers, and a removed
  one stayed declared and would fail at link time.

### Added

- **Optional native extra for Python deterministic key generation.**
  `pip install 'ratify-protocol[native]'` installs `ratify-protocol-native`, a
  separate distribution that supplies seed-based key generation through the
  Ratify Rust core. With it, the same two seeds produce the same identity in
  Python as in every other SDK, and Python asserts the same cross-SDK keygen
  vector as the Go, Rust, C and TypeScript suites.

  It is a separate distribution on purpose: `ratify-protocol` itself remains a
  pure-Python `py3-none-any` wheel that installs on any platform and any
  supported CPython, and a release check asserts that it stays that way. The
  extra ships abi3 wheels, so one wheel per platform covers every CPython from
  3.10 up. Installing it is only necessary for seed portability across
  languages: verifying proofs, issuing delegations, signing challenges, and
  persisting an identity by storing its key bytes all work without it. Signing
  and verification always use `pqcrypto` and are unaffected.

### Changed

- **Python `hybrid_keypair_from_seeds` now raises `NotImplementedError` when the
  native extra is absent.**
  It previously accepted an ML-DSA seed, validated that it was exactly 32 bytes,
  and then discarded it: the `pqcrypto` binding calls PQClean's
  `crypto_sign_keypair`, which reads the OS RNG. Callers passing identical seeds
  received different keypairs with no error and no warning at the call site, so
  anyone persisting seeds to restore an identity silently received a new one and
  discovered it only when verification failed elsewhere. This is a behavioral
  change for any caller of that one function; every other Python entry point is
  unaffected. Install the `native` extra above, or derive identities from seeds
  with the Go, Rust, TypeScript or C SDK.

---

## v1.0.0-alpha.17 (2026-08-24)

A packaging and documentation release. No SDK behavior, canonical bytes or fixture
contents change, and the protocol version remains 1.

### Fixed

- **Python SDK dependency bound.** `pqcrypto` 1.0.0, published 2026-08-15, changed ML-DSA-65
  behavior, and hybrid signatures do not verify against it. The Python package declared
  `pqcrypto>=0.3.4` with no upper bound, so any installation made after that date produced a
  verifier that rejected valid signatures, including the canonical fixtures. The dependency is
  now bounded to `>=0.3.4,<1.0`. No other SDK depends on `pqcrypto`, and Go, TypeScript, Rust
  and C were unaffected. Signed objects, canonical bytes, fixture contents and the verifier
  algorithm are unchanged; this is a packaging repair rather than a protocol change. Anyone who
  installed `1.0.0a16` between 2026-08-15 and this release should upgrade, or pin
  `pqcrypto<1.0` alongside it.

### Changed

- **Extension type namespaces:** newly defined extension constraint types now
  use a reverse-domain prefix controlled by the defining organization. Ratify
  profiles use `com.ratifyprotocol.<profile>.<type>`. Existing signed names,
  verifier behavior, SDK APIs, and canonical fixture bytes are unchanged.

---

## v1.0.0-alpha.16 (2026-08-05)

The "resource-bound authority" release: delegations can now name *where* a scope applies, not just *what* it permits.

### Added — specification (implementation follows in the same release)

- **`resource_path` constraint** (SPEC §5.7.2, §5.7.3): binds a delegation to an opaque `resource_id` (exact byte equality, never dereferenced or normalized) and an optional `path_prefix` under segment-boundary matching — deliberately a prefix, not a glob. Absolute logical POSIX-style path model with dot-segments, backslashes, and empty interior segments rejected outright; percent-encoding does not exist in the path model, and post-verification path transformation is forbidden. NFC pre-normalization is the issuer's obligation; the verifier compares bytes exactly (a mixed-form pair fails closed; byte identity, not visual identity, is the boundary). Chain evaluation is conjunctive: effective authority can stay the same or narrow but never widen (a child may carry a broader prefix on the same resource and still verify, gaining nothing because every upstream constraint still applies), and jointly unsatisfiable constraint sets — different resources, or same-resource prefixes that don't nest — must be rejected at issuance (decoders still accept them; verification fails closed).
- **Resource-identifier profiles** (SPEC §5.7.4, `docs/RESOURCE_PROFILES.md`): the shared recipes that make an opaque `resource_id` interoperable. Git profile v1 (repository identity — never a branch, commit, or checkout; renames and transfers fail closed) with known-answer and negative vectors. Profiles for platform-owned resources are authored by the platforms themselves and linked when published.
- **Extension-constraint `params`** (SPEC §5.7.1, §17.7): parameterized extension constraints are now representable in signed certificates under a restricted, cross-language-deterministic value model. Type-only extension constraints serialize exactly as before; existing signed certs remain byte-stable. Closes the wire-format limitation documented in alpha.15.
- **Input bounds** (SPEC §5.1): `MAX_PROOF_BUNDLE_BYTES` (128 KiB, applied to the received wire representation and enforced before parsing), `MAX_JSON_NESTING_DEPTH`, and per-cert scope/constraint count and length limits. Violations route to the existing `invalid` status. §5.1 also notes that the byte ceiling and `MAX_DELEGATION_CHAIN_DEPTH` are independent and can bind near the same point: a chain within the depth limit can still be rejected by the wire decoder for exceeding `MAX_PROOF_BUNDLE_BYTES` before depth is evaluated, so operational depth choices should budget for the deployment's maximum expected per-certificate content.
- **Conformance suite** grows from 63 to 79 canonical vectors: 16 new verify-kind fixtures (14 `resource_path` accept/deny/unverifiable/narrowing/escape/traversal/percent-literal/root/trailing-slash/whole-resource/unsatisfiable-pair, 1 extension-`params`, 1 depth-8), with `reject_chain_too_deep` regenerated at depth 9. Byte-identical across all five SDKs.
- **`VerifierContext` resource fields** (SPEC §5.16): `RequestedResourceID`, `RequestedPath`, `HasResource`, with the standard fail-closed absence semantics.
- **Confinement guidance** (SPEC §15.7): a verified `resource_path` is lexical authorization, not filesystem confinement. Stated as normative properties rather than a prescribed mechanism: the deployment states its concurrent-mutation attacker model; a confinement or policy refusal leaves no operation-created effect inside or outside the boundary (with identity-safe cleanup that never touches objects a concurrent principal substituted); execution causes no effect outside the boundary; write atomicity is a separate contract; and refusal tests must attribute effects to the operation rather than assert blanket snapshot equality. Descriptor-relative traversal is the illustrative mechanism, not a mandate.

### Changed

- **`MAX_DELEGATION_CHAIN_DEPTH` raised from 3 to 8** (SPEC §5.1) for multi-hop agent topologies. The ceiling is a wire-determinism and denial-of-service bound, not cryptography; the new byte/count/length limits bound the work that depth alone does not.

### Fixed

- **Cross-SDK constrained-bundle hashing**: `bundle_hash` serialized a delegation's constraints in their raw in-memory form instead of the canonical per-kind wire form, so any bundle whose cert carried a constraint (for example a `resource_path` constraint) produced a digest that diverged from the Go reference. Python diverged on every constrained bundle; TypeScript carried the same issue latently, surfacing only for a programmatically constructed constraint. Both SDKs now map constraints through the canonical per-kind form (`to_canonical_dict` / `canonicalConstraintDict`), and a constrained cross-SDK byte-equivalence vector plus a TypeScript raw-object regression test prevent recurrence. Identity verification and signature validity were unaffected; Go, Rust, and C were already correct.

---

## v1.0.0-alpha.15 (2026-07-25)

The "integration readiness" release: everything an integrator needs to adopt the SDKs over a real transport without hand-written glue, driven by the Agent Relay integration spike. No fixture changes — all 63 canonical vectors are byte-identical to alpha.13.

### Added — public wire codecs and vocabulary parity (#39, #40)

- TypeScript and Python gain public, strict wire codecs: `encode`/`decode` for `DelegationCert`, `ProofBundle`, and `SessionToken`. Round-trip identity is fixture-tested and cross-SDK transport parity is asserted byte-for-byte in both directions.
- Strict wire acceptance across all five SDKs: duplicated keys, out-of-domain integers, invalid UTF-8, and unknown fields are rejected before verification, and the normative JSON integer domain is stated in the SPEC.
- `Vocabulary()` and `ScopeWildcards()` accessors in TypeScript, Python, Rust, and C, matching Go, with a cross-SDK parity vector.

### Added — single-use challenge acceptance (#41)

- `ChallengeStore` interface (`Issue`/`Validate`/`Consume`) with an in-memory implementation in every SDK (C: `ratify_challenge_store_*`). Consume atomically removes the issuance record, so store capacity counts pending challenges only; concurrent consumption admits exactly one winner.
- SPEC §10 makes single-use acceptance normative for challenge-issuing verifiers (steps 2b and 9b): the store is consulted without consuming before signature work and atomically consumed after the challenge signature verifies, before authorization — so a forged presentation never burns a challenge and a denied caller cannot probe authorization with one liveness proof. Every store failure normalizes to one canonical `unknown_challenge` response (response-level indistinguishability; the timing channel of the early lookup is explicitly out of scope).
- Threat-model row T1 corrected: freshness alone bounds replay to the window; single-use eliminates it at issuing verifiers; self-issued challenges need request-level deduplication.

### Added — streamed-turn verification with options (#42)

- Options-object streamed-turn verifier in every SDK (Go `VerifyStreamedTurnWithOptions`, C `ratify_verify_streamed_turn_opts`) taking a dedicated `StreamedVerifyOptions`: required scope (checked against `token.granted_scope`), challenge store (single-use on the fast path), session context, stream state, and clock override — and nothing else. Full-verifier options cannot be passed and silently ignored: distinct types at compile time in Go/Rust/C, runtime fail-closed rejection in TypeScript and Python.
- Stream state is documented as a caller-owned snapshot with an atomic-advance requirement; the token-HMAC-first order is stated normatively in §5.13. The positional streamed verifiers are deprecated (still callable).

### Added — operation-context and session-context constructions (#43)

- SPEC §6.4.9: canonical, domain-separated, length-prefixed constructions. `OperationContextBytes` binds the action (scope, operation, resource, path, payload digest) into a 32-byte `request_hash`; `SessionContextBytes` binds verifier/workspace/agent/session/invocation identifiers plus that hash into the 32-byte `session_context`. Implemented in all five SDKs with shared known-answer vectors proving byte-identical hashes; ill-formed Unicode is rejected everywhere.
- SPEC §15.2.1: the named **Middleware Custody Profile** for deployments where platform middleware holds agent keys — every presentation session-bound with these constructions, `request_hash` derived from the specific action, receipts binding the hash and never the preimage.

### Changed — documentation accuracy (#44)

- Per-SDK verify-latency matrix and wire-size table in `docs/BENCHMARKS.md`; every sub-millisecond claim is qualified to the Go/Rust/C SDKs; session tokens are repositioned as the default pattern for repeated interactions with accurate one-vs-N+1 signature-count framing (an earlier ~95% claim is corrected everywhere, including per-SDK READMEs and a changelog erratum below); §17.7 gains the type-only extension-constraint limitation note; allocation attribution is profile-backed.

---

## v1.0.0-alpha.13 (2026-07-06)

### Added — SPEC §13.1: registry read binding (optional)

- Defines the open lookup contract for registry-mode key discovery (§15.4): `GET /v1/registry/principals/{human_id}` returning the current root key, the full `KeyRotationStatement` chain (oldest → newest), the optional `Anchor`, and `updated_at`. TLS mandatory; no enumeration endpoint; constant-shape 404s; short cache lifetimes.
- Resolver requirements are fail-closed on every branch (network, schema, chain order, dual-signature validity, link contiguity, final-key match, pinned-key continuity, staleness). Historical-root bundles are rejected by default after rotation. The contract states plainly that rotation proves continuity **after** first trust — first key acquisition is the trust decision — and that the v1 trust model is registry operator + TLS, with signed responses / witness-logged registries as the designated future hardening.
- A reference resolver in `cmd/ratify-verifier` implements the resolver requirements — fail-closed on every branch, TLS-only, pins keyed by the pinned key's own derived id, pin checks re-evaluated on cache hits — with TLS-server test coverage. Both deployment modes are demonstrated end to end: `--registry` (registry trust: operator + TLS) and `--registry-pins` + `--registry-require-pinned` (pin-plus-registry: only first-trusted principals and their rotation successors, via `ResolveRootDescendedFromAnyPin`). No SDK API surface, no fixtures, no wire change.

### Fixed — C SDK version pipeline

- `sdks/c` was invisible to the release pipeline: `bump_versions` never touched its manifests (crate stuck at alpha.10 in-tree — meaning `ratify_version()` in the alpha.11/alpha.12 release binaries reported alpha.10), the CI crates job never published it (crates.io `ratify-c` frozen at alpha.8 since publishing moved off the manual flow), and `check-release-sync.sh` never checked it. All three fixed: the bump now covers `sdks/c/Cargo.toml` (crate version + `ratify-protocol` dependency pin), `Cargo.lock`, and the cbindgen header banner; the sync gate asserts all three match; the CI crates job publishes `ratify-c` after `ratify-protocol` indexes; the tag-coherence gate checks the C version. C crate bumped to alpha.12 in-tree.
- Remaining count-stale CI step/job names made count-free ("Python SDK (102 tests)", "TS full test suite (101 tests)", "C/C++ SDK (63 fixtures + API tests)", "Python full test suite (102 tests)"). Note for consumers of required status checks: the required context "Python SDK (102 tests)" is renamed to "Python SDK".

### Changed — ROADMAP

- No-expiry sentinel section rewritten from "proposed / until this ships" to shipped-in-alpha.12 behavior (and its stale SPEC §4.3 reference corrected to §5.1/§5.7).

---

## v1.0.0-alpha.12 (2026-07-06)

### Added — no-expiry sentinel (normative)

- `NO_EXPIRY_SENTINEL = 4070908799` (2099-12-31 23:59:59 UTC): a cert whose `expires_at` equals the sentinel means **"no expiry (until revoked)"**. Implementations MUST treat it that way in display and policy evaluation — never as a literal 2099 expiry. Verification is unchanged (the sentinel is a future timestamp); revocation is the sole termination mechanism. SPEC §5.1 + §5.7; Go reference adds `NoExpirySentinel` and `DelegationCert.IsNoExpiry()`; mirrored in TS (`NO_EXPIRY_SENTINEL`/`isNoExpiry`), Python (`NO_EXPIRY_SENTINEL`/`is_no_expiry`), Rust (`NO_EXPIRY_SENTINEL`/`is_no_expiry`), and the C ABI (`ratify_no_expiry_sentinel()`, `ratify_expires_at_is_no_expiry()`). Fixture: `no_expiry_cert`.
- Closes a live gap: the Ratify Verify platform already signs sentinel certs; offline SDK verifiers previously had no way to distinguish "no expiry" from a cert legitimately expiring in 2099.

### Added — `presence:represent` scope (sensitive)

- New canonical scope (54 total): the agent is authorized to attend and interact as a **direct representative of the principal** — other parties may be interacting with the agent as if it were the principal. Covers non-likeness representatives and full likeness agents.
- Design as locked 2026-07-06: does NOT imply `identity:prove` (grant both explicitly; no implication table); one scope, no fidelity sub-qualifiers; disclosure of the representation relationship is platform policy with a non-normative SPEC note — not a protocol constraint. SPEC §9.1.
- There is deliberately no `presence:*` wildcard — sensitive scopes never ride wildcards. Fixtures: `presence_represent_allowed`, `reject_presence_sensitive_wildcard`.

### Added — verifier scope-vocabulary validation (`invalid_scope`)

- The verifier now enforces SPEC §9 at verification time, not just at issuance: any cert granting a scope that is not canonical, not a wildcard, and not a `custom:` extension is rejected with the new identity status `invalid_scope`, before any effective-scope arithmetic. Previously invalid vocabulary was silently carried into the intersection and only failed by non-membership — meaning an unknown string could in principle become an effective grant. New verifier step §10 7.a2; `identity_status` enum extended (§5.9 — a closed set, extended via this spec bump). Mirrored in all SDKs; pinned by the `reject_presence_sensitive_wildcard` fixture.

### Changed — conformance suite: 59 → 63 canonical fixtures

- Four new fixtures (above). All 59 pre-existing fixtures are byte-identical to alpha.11.
- `scripts/check-release-sync.sh` now also gates SPEC.md and the TypeScript/Go/C READMEs on the fixture count, and adds a **scope-count check** derived from `scope.go` — documented counts can no longer silently drift from the vocabulary.

### Changed — release process: no more direct pushes to main

- The single-step `make release` (which committed the version bump directly to main via a ruleset bypass) is removed. Releases are now two-phase: `make release-prepare VERSION=…` creates a `release/<version>` branch, bumps versions, runs the full cross-SDK gate, and opens a PR; after it merges through the normal path (CI + DCO), `make release-tag VERSION=…` verifies main carries the bump and pushes the coordinated tags. See `docs/RELEASES.md` §4.
- `release.sh` pushes the protocol tag on its own before the `sdk-*` tags: GitHub creates no push event when more than three tags arrive in one push, which had silently prevented the tag-triggered Release workflow from ever firing (see `docs/RELEASES.md` §5.3.1).
- `release-prepare` now stamps the `(unreleased)` changelog entry with the release date.

---

## v1.0.0-alpha.11 (2026-07-06)

### Changed — docs & spec truth pass (no wire change, no protocol or SDK code change)

**Wire format unchanged. All 59 canonical test vectors are byte-identical to alpha.10. No protocol or SDK code was modified — the only executable change is to the local test-gate script (see Fixed below).**

**README credibility pass.** The README described the alpha.4-era one-shot protocol; the shipped protocol is larger.

- New "Beyond one-shot verify" section surfaces the shipped v1.1 feature set: session-bound challenges, stream sequence numbers, SessionToken fast path, push-based revocation, transaction receipts, witness append-only logs, key rotation statements — each linked to its SPEC section.
- Demo section now shows representative `go run ./demos/go` output (signatures and timestamps vary per run) and describes the narrative accurately (one positive end-to-end flow + four rejection scenarios; previously mislabeled "nine-scenario — five positive").
- Repository layout tree updated: adds `streamed_verify.go`, `receipt_verify.go`, the benchmark/cross-SDK/lever/provider test files, `Makefile`, `scripts/`, `sdks/go/`, `docs/BENCHMARKS.md`, `docs/ATTRIBUTION.md`; relabels `docs/TRANSACTION_RECEIPTS.md` as normative-companion rather than "v1.1 design."
- Fixture-count note: 59 canonical fixtures; `cross_sdk_vectors.json` is a separate byte-equivalence corpus.
- The "under a millisecond" claim now links to [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
- All five SDK READMEs gained the same "beyond one-shot verify" summary so registry pages (npm, PyPI, crates.io) tell the full story.

### Added — SPEC security-considerations hardening (guidance only, no normative wire change)

- **§15.4 Trust anchors and public-key discovery** — the five supported key-bootstrap modes (pinned keys, enterprise IdP root, registry lookup, self-published + rotation continuity, witness-backed evidence); verifiers MUST NOT treat in-band keys as trust roots.
- **Threat T12 — key-substitution attacker** added to the §15.0 threat model: signature verification proves key possession, not key ownership; trust bootstrap is a required deployment decision.
- **§15.5 Revocation freshness** — fail-closed requirement restated, staleness bounds by risk tier, `ForceRevocationCheck` guidance, push-gap recovery (full `RevocationList` refetch after a missed-delta gap).
- **§15.6 Verifier clock discipline** — NTS/NTP guidance, ±30s budget, drift-compensated challenge windows for offline/edge verifiers; temporal bounds stay strict in v1 (slack belongs at issuance, not verification).
- **§15.7 Constraint attestation limits** — constraints defend the principal against agent overreach at an honest verifier; verifier-supplied context is asserted, not proven; bind evaluated context into `VerificationReceipt`/`TransactionReceipt.terms` for auditable claims.
- **§5.13 SessionToken operational guidance** — token lifetimes by risk tier (≤5 min high-stakes, ≤15 min conversational), eviction triggers, and multi-instance `session_secret` handling for load-balanced verifiers.
- **§12 crypto agility** — why v1 fixes the algorithm pair instead of negotiating, and the migration path if a component weakens.
- **§5.16** — one-line pointer to §15.7 on what constraint evaluation does and does not prove.

### Fixed — local test gate now covers all five SDKs

- `scripts/test-all.sh` now runs the C/C++ SDK conformance and API tests. Previously the local `make test-all` / `make release` gate covered only four of the five SDKs — CI tested C/C++ on every push, but the local release preflight did not, contradicting `docs/RELEASES.md` §4.2 step 5.

### Changed — ROADMAP restructured into three buckets

Shipped (alpha.10) / planned backward-compatible (alpha.11 docs pass, alpha.12 protocol additions) / v2 wire-breaking. `presence:represent` design locked (2026-07-06): no scope implication, single scope without sub-qualifiers, disclosure as platform policy with a non-normative SPEC note. No-expiry sentinel (`4070908799`) scheduled for alpha.12.

---

## v1.0.0-alpha.10 (2026-05-17)

### Added — C/C++ SDK: full 59/59 conformance + pre-built release binaries

**C ABI surface expanded.** 13 new exported functions added to `advanced.rs`:

- `ratify_revocation_list_sign_bytes_hex`, `ratify_revocation_push_sign_bytes_hex`, `ratify_key_rotation_sign_bytes_hex`, `ratify_session_token_sign_bytes_hex`, `ratify_transaction_receipt_sign_bytes_hex`, `ratify_witness_entry_sign_bytes_hex` — canonical sign-bytes as lowercase hex for all signed types
- `ratify_revocation_push_sig_ed25519_hex`, `ratify_revocation_push_sig_ml_dsa_65_hex`, `ratify_witness_entry_sig_ed25519_hex`, `ratify_witness_entry_sig_ml_dsa_65_hex` — signature component hex accessors
- `ratify_verify_streamed_turn` — session-token fast-path multi-turn verification via C ABI
- `ratify_transaction_receipt_verify_full` — receipt verify with explicit `valid` + `error_reason` outputs
- `ratify_session_token_mac_hex` — token MAC as hex for conformance testing

**Conformance test rewritten.** `tests/conformance.rs` now exercises all 59 canonical fixtures across all 8 fixture kinds (verify, scope, revocation, revocation_push, key_rotation, session_token, transaction_receipt, witness_entry). Previously only verify fixtures (42) ran through the C ABI; all 17 non-verify kinds were skipped. Now 59/59 pass.

**Pre-built library release assets.** CI now builds and publishes `.tar.gz` archives for Linux (x86-64, ARM64, ARM32) and macOS (Intel, Apple Silicon), and `.zip` for Windows x86-64 as part of every release. C/C++ consumers no longer need the Rust toolchain.

**Wire format unchanged.** All 59 canonical test vectors regenerate byte-identical to alpha.9.

---

## v1.0.0-alpha.9 (2026-05-15)

### Changed — SDK READMEs and registry publishing

- All five SDK READMEs (Go, TypeScript, Python, Rust, C/C++) now include a "What is Ratify Protocol?" introduction, the post-quantum line, and consistent cross-language interop framing
- All relative links in SDK READMEs replaced with absolute GitHub URLs (broken on npm, PyPI, and crates.io package pages)
- npm package homepage updated to `docs.identities.ai`
- npm publishing switched from long-lived `NPM_TOKEN` to OIDC Trusted Publisher — no stored secret required
- `publish.sh` auto-detects prerelease tag from version string

---

## v1.0.0-alpha.8 (2026-05-13)

### Added — Fifth Reference SDK: C / C++ (`sdks/c/`)

A new C reference implementation (`sdks/c/`) ships as the fifth SDK. Licensed Apache-2.0.

**Artifacts:**
- Static library: `libratify_c.a`
- Shared library: `libratify_c.so`
- Auto-generated header: `ratify.h` (produced by cbindgen)

**Operations supported:** Delegate, Present, Verify (all three verbs), session tokens, verification receipts, revocation, key rotation, scope utilities, policy verdicts, and transaction receipts — full parity with the other four SDKs.

**Embedded target support:** `no_std` + alloc. The C SDK compiles for embedded RTOS targets (Cortex-M4/M7) with no heap allocator requirement beyond a caller-supplied alloc. Custom entropy via `ratify_set_entropy_source()` for hardware RNG on RTOS targets.

**Conformance:** 100 new tests in the C SDK. All five SDKs pass all 59 canonical test vectors byte-identical.

### Changed — Rust SDK

- **`fips204` (pure Rust) replaces `pqcrypto-mldsa` (C FFI).** The Rust SDK's ML-DSA-65 implementation is now `fips204`, a pure-Rust, `no_std`-compatible FIPS 204 implementation. Eliminates the C FFI dependency entirely.
- **`#![no_std]` + alloc support.** The Rust SDK now compiles for embedded Cortex-M4/M7 RTOS targets. Requires only `alloc`; no `std` dependency.
- **Eliminated `serde_json` from the canonical signing path.** The canonical serializer no longer touches `serde_json` in the hot path, removing a source of potential non-determinism and improving embedded portability.

### Wire format

Unchanged. All five SDKs produce and accept the same wire format as alpha.7. All 59 canonical test vectors regenerate byte-identical.

---

## v1.0.0-alpha.7 (2026-05-11)

### Added — SDK Provider Interfaces (SPEC §17)

A new SDK-architecture surface that brackets the deterministic verifier core with pluggable hooks. The protocol wire format, signable bytes, and verifier algorithm are unchanged — all 59 canonical test vectors regenerate byte-identical to alpha.6. The provider surface is purely additive: existing v1 callers continue to work with no changes.

**Provider hooks (§17.1–§17.4):**

- **`RevocationProvider` (§17.1)** — pluggable revocation lookup. Returns `(bool, error)` instead of a bare bool; errors are fail-closed (`revocation_error`). Takes precedence over the legacy `IsRevoked` closure when both are configured.
- **`PolicyProvider` (§17.2)** — verifier-local, stateful policy evaluation that runs AFTER all cryptographic / temporal / revocation / constraint / scope checks pass. Deny → `scope_denied`. Provider error → `policy_error`.
- **`AuditProvider` (§17.3)** — verification-receipt persistence hook. Invoked on every `Verify` (success AND failure). Provider errors are swallowed — auditing cannot alter the verdict.

**Crypto primitives & extension surfaces (§17.5–§17.8):**

- **`VerificationReceipt` (§17.5)** — verifier-signed attestation that a specific `ProofBundle` was verified at a specific time with a specific outcome. Hybrid-signed; chains by `prev_hash` so missing or backdated entries are detectable. Optional: the protocol does not auto-issue. SDK API: `BundleHash`, `IssueVerificationReceipt`, `VerifyVerificationReceipt`, `ReceiptHash`.
- **`PolicyVerdict` (§17.6)** — HMAC-bound cached policy decision. Same shape as `SessionToken`: issued once by a policy backend, accepted locally for the rest of `valid_until`. Context-bound: `context_hash` is SHA-256 of the canonical `VerifierContext`, so a verdict cached for one context cannot leak into another. Wired into `verify_bundle` as a fast-path that skips the live `Policy` provider; stale verdicts fall back without failing.
- **`ConstraintEvaluator` registry (§17.7)** — per-Verify map of extension constraint-type evaluators. Built-in types (§5.7.2) are handled by the SDK directly; unknown types fall through to the registry; types with no registered evaluator still fail closed with `constraint_unknown`. Naming convention: `verify.<type>` for Verify-managed types, `<vendor>.<type>` for deployment / third-party types.
- **`AnchorResolver` (§17.8)** — resolves verified `human_id` → `Anchor` (the external-identity binding registered when the HumanRoot was minted) on every successful verification. Populates `VerifyResult.Anchor` so downstream `AuditProvider`s observe identity-bound receipts. Resolver errors are non-fatal.

**Deprecation (§17.11):**

- `VerifyOptions.IsRevoked` (the legacy `func(string) bool` closure) is **deprecated** and slated for removal in `v1.0.0-beta.1`. New code MUST use `Revocation` (§17.1). The closure remains functional through all `v1.0.0-*` releases; when both fields are set, `Revocation` wins. Each SDK marks the field with its language's idiomatic deprecation mechanism.

### Why this matters

These hook points are the integration boundary between the open-source protocol and operational services that wrap it (revocation push, no-code policy UI, immutable audit ledgers, identity-directory lookups). The verifier's deterministic core stays universal and offline-capable; everything that requires global state, mutable rules, server-side state, or compliance-grade retention is delegated to a provider the deployment configures.

Bundles verified with any provider stack are byte-identical to bundles verified with no providers at all. The 59 fixtures continue to exercise only the deterministic core; providers are tested per-SDK.

### Conformance

All four reference SDKs ship matching interfaces with consistent cross-language naming (§17.4 + §17.9).

Per-SDK provider + lever test suites:
- **Go:** 12 provider + 22 lever + 4 receipt-composition tests; FuzzVerifyWithProvidersNeverPanics fuzz harness exercises provider error paths across millions of inputs.
- **TypeScript:** 12 provider + 20 lever tests.
- **Python:** 13 provider + 20 lever tests.
- **Rust:** 11 provider + 20 lever tests.

Total alpha.7 test additions: **134 tests**, all green; **59/59 canonical fixtures** regenerate byte-identical to alpha.6.

### Spec changes

- **§5.17 VerifyOptions** — table extended with `Revocation`, `Policy`, `Audit`, `ConstraintEvaluators`, `PolicyVerdict`, `PolicySecret`, and `AnchorResolver` fields, with precedence rules between the legacy `IsRevoked` closure and the new `Revocation` provider.
- **§17 (new section)** — Provider Interfaces, including:
  - §17.0 conformance and wire-format invariance
  - §17.1–§17.3 the three core providers
  - §17.4 cross-language naming table
  - §17.5 `VerificationReceipt`
  - §17.6 `PolicyVerdict`
  - §17.7 `ConstraintEvaluator` extension registry
  - §17.8 `AnchorResolver`
  - §17.9 cross-language naming for §17.5–§17.8
  - §17.10 surface adapters (intentionally out of scope)
  - §17.11 deprecation of legacy `IsRevoked`

### Wire format

Unchanged. v1.0.0-alpha.7 verifiers accept v1.0.0-alpha.6 bundles and vice versa.

## v1.0.0-alpha.5 (2026-05-10)

### Changed
- Renamed from Fabric Protocol to Ratify Protocol.
- No wire-format or behavioral changes.
- Updated all SDKs, documentation, and metadata to reflect the new brand.
- Patent pending and trademark notices updated.

## v1.0.0-alpha.4 (2026-04-22)

### Added — v1.1 features (all backward-compatible with v1.0)

**Continuous real-time interactions:**
- **Session binding** — optional 32-byte `session_context` in the challenge signable binds a bundle to one verifier/session. Prevents stolen bundles from being replayed at a different endpoint.
- **Stream sequence numbers** — `stream_id` + `stream_seq` in the challenge signable detect replay, reorder, and omission within multi-turn conversations.
- **Session cert cache** — HMAC-based `SessionToken` lets verifiers skip chain re-verification on subsequent turns (one hybrid signature verification per turn instead of N+1; an earlier revision of this entry overstated the reduction as ~95%).
- **Push-based revocation** — signed `RevocationPush` delta payload for real-time revocation propagation. `ForceRevocationCheck` verify option for high-stakes endpoints.
- **Challenge forwarding defense** — session binding defeats cross-verifier challenge relay attacks.

**Tamper-evident transaction streams:**
- **Transaction receipt envelope** — canonical `TransactionReceipt` where every party signs the same signable (terms + sorted party set + transaction ID). No partial-valid receipt state.
- **Witness append-only log** — signed `WitnessEntry` hash-chain shape for append-only audit logs.
- **Key rotation statement** — `KeyRotationStatement` signed by both old and new root keys for identity continuity.

**Security hardening:**
- Formal threat model table in SPEC §15.0 (11 adversary scenarios + 4 out-of-scope).
- Hybrid single-component-corruption fixtures proving the both-must-verify guarantee.
- Go native fuzz tests (verifier, canonical JSON, scope expansion — millions of inputs, zero panics).
- Reference verifier hardened with per-IP rate limiting, optional API key auth, and challenge store cap.
- Tiered key-custody model (self-custody, custodial, delegated) with self-custody upgrade path via `KeyRotationStatement`.

**SDK support:** all features implemented in Go, TypeScript, Python, and Rust with 59 canonical test vectors.

### Changed
- Documentation scrubbed for open-source readiness (no commercial product references).
- SPEC expanded: §5.16 VerifierContext, §5.17 VerifyOptions, §10 verifier algorithm expanded from 7 to 11 steps, §6.5 reference API fully categorized, §15.2 key-custody model, §15.3 root key compromise.

## v1.0.0-alpha.3 (2026-04-18)

### Added
- First-class constraints: `geo_circle`, `geo_polygon`, `geo_bbox`, `time_window`, `max_speed_mps`, `max_amount`, `max_rate` with 12 constraint fixtures.
- Sub-delegation gate: `identity:delegate` scope required for intermediates to sub-delegate.
- Session binding: optional `session_context` field on ProofBundle (v1.1 preview).
- Key rotation: `KeyRotationStatement` type and fixtures.
- Release tooling: `make release` with coordinated SDK tags and `make release-check` for metadata sync.

**SDK support:** Go, TypeScript, Python, Rust — 38 canonical test vectors.

## v1.0.0-alpha.2 (2026-04-14)

### Added
- Python and Rust SDK implementations.
- Cross-SDK conformance suite.
- Deterministic test-vector generator (`cmd/ratify-testvectors`).

## v1.0.0-alpha.1 (2026-04-10)

### Added
- Initial protocol specification (SPEC.md).
- Go reference implementation with hybrid Ed25519 + ML-DSA-65.
- TypeScript SDK.
- 20 canonical test vectors.
- CLI tool (`cmd/ratify`): init, delegate, verify, agent-init, agent-bundle, challenge, scopes.
- HTTP reference verifier (`cmd/ratify-verifier`).
