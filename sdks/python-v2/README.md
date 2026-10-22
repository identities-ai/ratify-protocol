# ratify-protocol-v2

Python SDK for Ratify Protocol v2 (pre-release).

```bash
pip install ratify-protocol-v2==2.0.0a1
```

This is a separate distribution from the v1 SDK. It imports as
`ratify_protocol_v2`, so it can be installed next to `ratify-protocol`
(`ratify_protocol`) in the same environment. Existing v1 pins are unaffected.

## Signing and verification

Key generation and signing run only in the required native extension
`ratify-protocol-native-v2` (constant-time Ed25519 and ML-DSA-65), which pip
installs with this package. There is no pure-Python signing path: without the
extension every signer raises `ImportError`. Verification handles only public
data, is pure Python, and works without the extension. The extension is
versioned in lockstep with this package, and importing `ratify_protocol_v2`
fails if a mismatched extension is installed.

Every object is signed through a typed signer (`sign_delegation_cert_v2`,
`sign_proof_bundle_v2`, `sign_revocation_list_v2`, `sign_revocation_push_v2`,
`sign_key_rotation_statement_v2`, `sign_witness_entry_v2`,
`sign_transaction_receipt_party_v2`, `sign_verification_receipt_v2`), each
with a `*_with_signer(ctx, ..., signer)` variant that accepts an external
signer (`SignerV2`) in direct mode (it receives the 77-byte message `M` and
the registered ML-DSA context) or external-μ mode (it receives only `mu`).
The SDK checks the signer's complete public key against the object before
any signer call, and verifies every returned signature before using it. No
function signs caller-selected bytes, codes, or contexts. Production signing
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
constructor; `decision.allowed(ctx, clock)` is the only value an application
may use to gate a side effect.

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

This alpha is not a v2 conformance claim; the remaining gates are listed in
SPEC-v2 §8 of the protocol repository.
