# ratify-protocol-native

Optional native companion to the [`ratify-protocol`](https://pypi.org/project/ratify-protocol/)
Python SDK. It provides one thing: deterministic hybrid key generation from two
32-byte seeds.

```sh
pip install 'ratify-protocol[native]'
```

You do not need this package to verify proofs, issue delegations, sign
challenges, or persist an identity. The Python SDK does all of that in pure
Python, and an application that wants to keep an identity across restarts can
store the key bytes directly. Install this only if you need the same two seeds
to produce the same identity in Python as in the Go, Rust, TypeScript, or C
SDKs.

## Why it exists

`pqcrypto`'s ML-DSA-65 binding calls PQClean's `crypto_sign_keypair`, which
reads the OS RNG and ignores a caller-supplied seed, so the Python SDK cannot
implement `hybrid_keypair_from_seeds` on its own. The pure-Python ML-DSA
implementations that are available carry explicit warnings against use in
cryptographic applications, so the deterministic path runs through the Ratify
Rust core instead.

Keeping it in a separate distribution means `ratify-protocol` itself stays
pure-Python and installs on any platform, including ones this package has no
wheel for.

## Scope

Key generation only. Signing and verification stay on `pqcrypto` in the Python
SDK and are not affected by installing this.

Both seeds are key material. Anyone holding them holds the identity: store them
with the protection you would give a private key.

## Verifying it works

With the extra installed, the Python SDK reproduces the cross-SDK vector:

```python
from ratify_protocol import hybrid_keypair_from_seeds, derive_id

ed_seed = bytes(range(32))
ml_seed = bytes((0xA0 + i) & 0xFF for i in range(32))
public, _ = hybrid_keypair_from_seeds(ed_seed, ml_seed)

assert derive_id(public) == "3823136b5a5fc4c755b22704474172c0"
```

The same seeds produce that identity in every Ratify SDK.
