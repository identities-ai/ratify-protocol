# ratify-protocol-native-v2

Native key generation and hybrid signing for
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
passes both to `HybridSigningKey.sign`. The extension checks that they name the
same registered object type, then signs exactly those bytes. ML-DSA-65 signing
is hedged with fresh OS randomness. The keyword-only
`deterministic_for_test_vectors=True` flag selects the FIPS 204 deterministic
variant, which is how the shared test vectors are generated; it is for
conformance tests only.

This is not a wire verifier. The SDK verifies every signature returned here
with its ordinary pure-Python verifier before using it.

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
