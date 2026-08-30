# ratify-protocol-native

**You almost certainly do not need this package.**

Install [`ratify-protocol`](https://pypi.org/project/ratify-protocol/) instead.
That is the Python SDK: it verifies proofs, issues delegations, signs
challenges, and stores identities, in pure Python, on every platform.

This package is a small optional add-on to that SDK. It exists to provide
**one function**, and nothing else.

---

## What this package does

It provides deterministic key generation: turning two 32-byte seeds into the
same Ratify identity every time, and the same identity that the Go, Rust,
TypeScript, and C SDKs derive from those seeds.

That is the whole scope. It contains no verification logic, no signing logic,
and no protocol implementation. Installing it does not change how anything else
in the Python SDK behaves.

## Do you need it?

**No, if** you are verifying proofs, issuing delegations, signing challenges, or
saving an identity to reuse later. All of that works in `ratify-protocol` with
nothing extra. To persist an identity, store its key bytes and load them back.

**Yes, if** you need the *same seeds* to produce the *same identity* in Python
as in another language. For example: a Go service generates an identity from
seeds it holds, and a Python process must reconstruct that identity from the
same seeds.

If you are not sure, you do not need it.

## Install

```sh
pip install 'ratify-protocol[native]'
```

Install it through the extra rather than by name. The extra pins the two
packages to matching versions, which is what keeps them compatible.

Once installed, nothing changes in how you write code. The function that
previously raised now works:

```python
from ratify_protocol import hybrid_keypair_from_seeds, derive_id

ed_seed = bytes(range(32))
ml_seed = bytes((0xA0 + i) & 0xFF for i in range(32))
public, private = hybrid_keypair_from_seeds(ed_seed, ml_seed)

# The same identity every SDK derives from these seeds.
assert derive_id(public) == "3823136b5a5fc4c755b22704474172c0"
```

Without this package, that call raises `NotImplementedError` with instructions.
It never returns a wrong answer.

## Why it has to be a separate package

`ratify-protocol` is pure Python and ships a single wheel that installs on any
platform and any supported CPython. Keeping it that way matters for a library
whose main job is verifying proofs inside other people's applications.

Deterministic ML-DSA-65 key generation cannot be done in pure Python here.
`pqcrypto`, the library the SDK uses for post-quantum signing, calls PQClean's
`crypto_sign_keypair`, which reads the operating system's random number
generator and ignores any seed the caller supplies. The pure-Python ML-DSA
implementations that exist carry explicit warnings against use in cryptographic
applications, so they are not an option either.

So this one operation runs through the Ratify Rust core, compiled into a small
extension. Because compiled code is platform-specific, it lives here instead of
in the SDK. If your platform has no wheel for this package, `ratify-protocol`
still installs and works; you simply do not get this one function.

## What is inside

A single Rust function exposed to Python through PyO3, calling the same
`hybrid_keypair_from_seeds` that the Ratify Rust SDK exposes. Signing and
verification are untouched and continue to use `pqcrypto`.

Wheels are built with the `abi3` stable ABI, so one wheel per platform covers
CPython 3.10 and every later version.

## Handling seeds

Both seeds are key material. Anyone holding them can reconstruct the identity
and act as it. Store them with the same protection you would give a private
key, and generate them from a cryptographically secure source.

## Links

- The SDK this belongs to: [`ratify-protocol`](https://pypi.org/project/ratify-protocol/)
- Protocol specification: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- SDK contract and the reason this package exists: [docs/SDKS.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/SDKS.md)
- Source: [github.com/identities-ai/ratify-protocol](https://github.com/identities-ai/ratify-protocol)

Apache-2.0.
