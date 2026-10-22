# ratify-protocol-native-v2

Native key generation, hybrid signing and hybrid verification for
[`ratify-protocol-v2`](https://pypi.org/project/ratify-protocol-v2/), which
requires it. Install the SDK and this extension comes with it:

```bash
pip install ratify-protocol-v2==2.0.0a1
```

Every private-key operation in the v2 Python SDK runs here: key generation
from seeds, public-key derivation from a private key, and Ed25519 + ML-DSA-65
signing. ML-DSA-65 comes from the constant-time `fips204` crate and Ed25519 from
`ed25519-dalek`, the same implementations the Ratify Rust core uses. There is
no pure-Python signing path.

The SDK computes the 77-byte v2 signing message and the ML-DSA context and
passes both to the internal `HybridSigningKey._sign` method. The extension
checks that they name the same registered object type, then signs exactly those
bytes. `_sign` is not public API and the SDK never re-exports it: applications
sign only through the SDK's typed signing functions. A compiled module cannot
hide a method from code in the same interpreter, so code that already holds a
`HybridSigningKey`, and therefore the private key, can still call it; that is
outside the SDK's API guarantee. ML-DSA-65 signing
is hedged with fresh OS randomness. The keyword-only
`deterministic_for_test_vectors=True` flag selects the FIPS 204 deterministic
variant, which is how the shared test vectors are generated; it is for
conformance tests only.

Signing is not wire verification. The SDK verifies every signature returned
here with its ordinary verifier before using it.

Verification: the internal `_verify_hybrid` function checks one hybrid
signature over an SDK-computed 77-byte transcript and its ML-DSA context with
the Rust core's strict v2 verifier (`ratify_protocol::v2::verify_v2_message`):
canonical, non-identity, prime-order Ed25519 `A` and `R`, canonical `S < L`,
the cofactorless Ed25519 equation, and FIPS 204 ML-DSA-65 verification under the
per-type context. It handles only public data and releases the GIL while it
runs. The SDK uses it for every signature check by default and keeps its
pure-Python verifier as an explicit fallback (`RATIFY_V2_PURE_VERIFY=1`, or a
verify-only environment without this extension); the SDK's test suite runs the
whole shared signature corpus through both and requires identical results.

Key material: `HybridSigningKey` keeps the parsed keys in native memory and
zeroizes them on drop. The SDK's `HybridPrivateKey` is bytes-backed, so private
key bytes cross from Python into the extension on each signing call, and back
out from key generation (`hybrid_keypair_from_seeds_py`,
`HybridSigningKey.private_key_bytes`). Python `bytes` cannot be wiped.

It is versioned in lockstep with `ratify-protocol-v2`. Importing
`ratify_protocol_v2` fails if this extension's `version()` does not match.

It is a separate distribution and module from the v1 extension
(`ratify-protocol-native` / `ratify_protocol_native`), so both can be installed
in one environment.
