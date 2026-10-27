# ratify-protocol-v2

Python SDK for Ratify Protocol v2 (pre-release).

```bash
pip install ratify-protocol-v2==2.0.0b1
```

This is a separate distribution from the v1 SDK. It imports as
`ratify_protocol_v2`, so it can be installed next to `ratify-protocol`
(`ratify_protocol`) in the same environment. Existing v1 pins are unaffected.

## Signing and verification

Key generation and signing run only in the required native extension
`ratify-protocol-native-v2` (constant-time Ed25519 and ML-DSA-65), which pip
installs with this package. There is no pure-Python signing path: without the
extension every signer raises `ImportError`. Hybrid signature verification
also runs in the extension by default, through the Rust core's strict v2
verifier. Verification handles only public data, so the package keeps a
pure-Python verifier as a fallback: a verify-only install without the
extension uses it, and `RATIFY_V2_PURE_VERIFY=1` selects it explicitly
(`signing_v2.native_verify_enabled()` reports which is active). The test suite
replays every signature check in the shared corpus through both verifiers and
requires identical verdicts and error classes. The pure-Python verifier is
about 35 times slower per signature; see [Performance](#performance). The extension is
versioned in lockstep with this package, and importing `ratify_protocol_v2`
fails if a mismatched extension, or one built without native verification, is
installed.

Every object is signed through a typed signer (`sign_delegation_cert_v2`,
`sign_proof_bundle_v2`, `sign_revocation_list_v2`, `sign_revocation_push_v2`,
`sign_key_rotation_statement_v2`, `sign_witness_entry_v2`,
`sign_transaction_receipt_party_v2`, `sign_verification_receipt_v2`), each
with a `*_with_signer(ctx, ..., signer)` variant (`sign_key_rotation_statement_v2_with_signers` for the two rotation keys) that accepts an external
signer (`SignerV2`) in direct mode (it receives the 77-byte message `M` and
the registered ML-DSA context) or external-μ mode (it receives only `mu`).
The SDK checks the signer's complete public key against the object before
any signer call, and verifies every returned signature before using it. No
function signs caller-selected bytes, codes, or contexts, and no local
`SignerV2` is exported: an in-process key signs only through the typed
signers, and the status publisher takes it through
`status_publisher_v2.new_v2_status_publisher_with_key`. Production signing
is hedged; byte-reproducible signing for the shared vectors is available only
to tests through `ratify_protocol_v2._testing.deterministic_test_vector_signing()`.

## Live verification and release

`verify_v2.verify_proof_bundle_v2(ctx, request, callbacks)` runs the SPEC-v2
§6 order: bounded strict decode, configuration bounds, every structural and
signature check, the authenticated challenge binding, the receiver-binding
hook, the atomic claim, and only then trust, local authorization, status
evidence applied through an anchored `SecurityJournalV2`, receiver audience,
`max_rate`, and finalization at a fresh authoritative time. It returns a
stage (`preflight`, `replay`, `evaluating`, `committed`) with an error class
from the closed list of SPEC-v2 §2.7.

A committed outcome is not a decision. `release_v2.release_v2_decision`
checks the published receipt, its checkpoint acknowledgement, the
authoritative clock and the exclusive deadlines, and returns a
`V2ReleasedDecision` only when every step passes. That class has no public
constructor, holds no state of its own, and cannot be subclassed or pickled;
only the exact instance `release_v2_decision` returned is in its release
registry, which lives in a closure rather than a module attribute, so a copy
or a hand-built instance is never actionable.
`decision.allowed(ctx, clock)` is the only value an application may use to
gate a side effect. This guards against API misuse and accidental
construction. It does not defend against hostile code in the same
interpreter (for example `gc` or closure introspection, or monkeypatching the
module), which could read the application's keys and stores anyway.

Every function whose Go counterpart takes a `context.Context` takes a
`context_v2.Context` as its first argument (`context_v2.background()`,
`with_cancel`, `with_timeout`).

The Part B storage contracts (`ClaimStoreV2`, `V2RateReservationStore`,
`V2RateAtFinalizationStore`, `V2ReleaseClaimStore`, `V2ReceiptPublisher`,
`V2ReceiptCheckpoint`, `SecurityJournalStoreV2`, `V2ChallengeIssuanceStore`)
are abstract classes. A deployment supplies durable implementations; the
in-memory stores under `ratify_protocol_v2.v2reference` exist only for tests
and conformance scenarios and must never be used in production.

`time_window` constraints are evaluated only against the IANA tzdata release
`2025c` from the pinned `tzdata` package; the host time-zone database is
never consulted, and a verifier must configure `tzdb_version="2025c"`.

## Conformance

The shared vectors live in `testvectors/v2/` of the protocol repository. The
test suite runs every file there and fails if a file has no runner. To run
the suite against an installed wheel, set `RATIFY_V2_VECTOR_DIR` to that
directory. Set `RATIFY_REQUIRE_NATIVE=1` to make a missing native extension a
hard error instead of skipping the signing tests.

This is a prerelease. Review so far is internal adversarial review; external
independent review is a gate for `2.0.0` (SPEC-v2 §8), and v2 carries no
production security claim yet. The per-SDK record is in
[`docs/V2_REFERENCE_COMPATIBILITY.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/V2_REFERENCE_COMPATIBILITY.md).

## Performance

`bench/bench_v2.py` measures, on the in-memory reference stores: one hybrid
verification (`verify_v2_statement`); `verify_delegation_cert_v2_signature`
(structure and key-ID checks plus one verification); one complete decision on
the quickstart flow (verify with signed status, commit, publish the receipt,
checkpoint acknowledgement, release); and a dual-root call (two such decisions
under independent roots, one with a two-certificate chain). Challenge issuance
and presentation signing happen before the clock starts. `bench/go` and
`bench/rust` run the same flow on the Go and Rust SDKs.

```bash
python bench/bench_v2.py              # table; --json out.json; --check (CI floors)
go run ./sdks/python-v2/bench/go      # from the repository root
cd bench/rust && cargo run --release
```

Measured on 2026-10-22 on an Apple M2 Pro (10 cores, 16 GB, macOS 26.6),
Python 3.12.10, Go 1.27.3, Rust 1.95.0, one process at a time on an otherwise
idle host. Operations per second, single thread:

| Measurement | Python, before | Python, pure fallback | Python, native | Go | Rust |
| --- | ---: | ---: | ---: | ---: | ---: |
| hybrid verify | 83 | 82 | 3,130 | n/a | n/a |
| certificate signature verify | n/a | 81 | 2,628 | 2,066 | 2,574 |
| decision | 5.4 | 6.7 | 68.7 | 63.0 | 99.7 |
| dual-root decision | 2.1 | 2.4 | 21.7 | 17.1 | 27.8 |

"Before" is the previous release line, which verified in pure Python and
encoded canonical JSON strings character by character. "Pure fallback" is the
current code with `RATIFY_V2_PURE_VERIFY=1`. Go does not export a raw hybrid
verifier, so the SDKs are compared on the certificate call.

With native verification a decision spends most of its time in Python
protocol logic: loading, validating and digesting the reference security
journal snapshot during the status stage, canonical JSON encoding, and strict
wire decoding. Signature verification is under a tenth of it.

The Google ADK reference's dual-root scale benchmark (8 worker threads, 76 KB
presentations) went from 1.3 / 1.6 / 1.6 calls/s to 13.2 / 15.6 / 14.2 calls/s
for the 10 / 100 / 1,000-call tiers on the same host. The earlier run shared
the host with other work for part of its duration.

CI runs `bench/bench_v2.py --check`, which fails if verification is not
native or any measurement falls below a floor set between a tenth and a
quarter of the native numbers above, and above the pure-Python ones.

## Examples and upgrading

Runnable programs live in
[`examples/v2/python`](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2/python):
a quickstart (keys, delegation, challenge from the issuance helper, proof,
verify, receipt, checkpoint, release, `allowed`), signed status with a
revocation, an exact `custom:` scope with the `max_count/v1` evaluator
profile, and an external signer. They print the same output as the other
SDKs' programs, and CI checks it. They use the in-memory reference stores and
are development-only. Upgrading from v1 is covered in
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).
