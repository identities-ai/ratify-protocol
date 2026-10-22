# ratify-protocol-v2

Python SDK for Ratify Protocol v2 (pre-release).

```bash
pip install ratify-protocol-v2==2.0.0a1
```

This is a separate distribution from the v1 SDK. It imports as
`ratify_protocol_v2`, so it can be installed next to `ratify-protocol`
(`ratify_protocol`) in the same environment. Existing v1 pins are unaffected.

Key generation and signing run only in the required native extension
`ratify-protocol-native-v2` (constant-time Ed25519 and ML-DSA-65), which pip
installs with this package. There is no pure-Python signing path: without the
extension every signer raises `ImportError`. Each signature the extension
returns is checked by the SDK's pure-Python verifier before it is used.
Verification handles only public data, is pure Python, and works without the
extension. The extension is versioned in lockstep with this package, and
importing `ratify_protocol_v2` fails if a mismatched extension is installed.

Production signing is always hedged. The typed signers take no
`deterministic` argument; byte-reproducible signing for the shared vectors is
available only to tests, through
`ratify_protocol_v2._testing.deterministic_test_vector_signing()`.

The v2 API covers strict decoding and canonical encoding of every v2 signed
object, hybrid signature verification with full 256-bit v2 key IDs, the
stateful live verifier `verify_proof_bundle_v2`, the revocation status reducer,
witness and verification-receipt log heads, key rotation acceptance, and the
operation, session-context, and challenge-claim helpers. Callers still supply
authenticated challenge issuance and an atomic durable claim store.

The shared conformance vectors live in `testvectors/v2/` of the protocol
repository, and the test suite runs every file there, including the verifier
ordering, status, log, and rotation sequences. To run the suite against an
installed wheel, set `RATIFY_V2_VECTOR_DIR` to that directory. This alpha is
not a v2 conformance claim; the remaining gates are listed in SPEC-v2 §8 of
the protocol repository.
