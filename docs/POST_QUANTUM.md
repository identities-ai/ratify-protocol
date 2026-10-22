# Post-quantum hybrid signatures in Ratify Protocol

**Every Ratify signature pairs Ed25519 with ML-DSA-65 (NIST FIPS 204), and it
verifies only when both verify, so a forger must break both, including with a
future quantum computer.**

This page explains what that means, what it protects, and what it does not.

## What a quantum computer threatens

A large enough quantum computer running Shor's algorithm breaks the mathematics
behind today's common public-key signatures: RSA and elliptic curves, including
Ed25519. Someone with such a machine could derive a private key from a public
key and forge signatures. For Ratify, a forgery would mean a fake delegation
("this principal authorized this agent") or a fake agent proof.

Two parts of Ratify are not meaningfully threatened:

- **Hash functions.** Ratify uses SHA-256 and SHA-384 for key IDs, digests, and
  the hash chains in logs and journals. The best known quantum attack (Grover's
  algorithm) roughly halves their effective strength, and SHA-384 keeps a large
  margin.
- **ML-DSA-65.** NIST standardized ML-DSA in 2024 as FIPS 204. It rests on
  lattice problems for which no efficient quantum algorithm is known. The
  ML-DSA-65 parameter set is in NIST security category 3.

## How the hybrid construction works

Each signature is a pair: an Ed25519 signature and an ML-DSA-65 signature over
the same exact message. A verifier accepts the signature only when both
components are valid. Protocol v2 enforces this strictly: there is no fallback
to a single algorithm, the signed message is a typed transcript that binds the
object type and protocol version, and Ed25519 verification rejects
non-canonical and small-order encodings (see [SPEC-v2](../SPEC-v2.md) §2 and §3).

To forge, an attacker must break both algorithms:

- **A quantum attacker** can break Ed25519, but ML-DSA-65 still holds, so
  forgery remains infeasible.
- **An undiscovered weakness in ML-DSA**, a young standard built on less
  battle-tested mathematics, is covered by Ed25519, so forgery still fails.

The construction is therefore at least as strong as the stronger of its two
parts.

## What this does not cover

Post-quantum signatures protect the authenticity of Ratify objects. They are one
part of a deployment's security, not all of it:

- **Key custody.** A private key that leaks from a device or a misconfigured
  service is not protected by any signature algorithm. See SPEC-v2 §9 for
  custody guidance.
- **Transport and storage.** Ratify proves delegated authority; it does not
  encrypt traffic or data. A connection protected by classical TLS is a separate
  concern for the deployment.
- **Implementations.** Correct use still depends on correct code and correct
  configuration. The hybrid design hedges against a weakness in one algorithm,
  not against every possible bug.

"Harvest now, decrypt later" is an encryption threat: recording ciphertext today
to decrypt it once quantum computers exist. Ratify signs; it does not encrypt.
The relevant signature threat is forgery once quantum computers exist, which the
hybrid construction addresses.

## Why we say "post-quantum"

"Post-quantum" names a property of the algorithms: they are designed to resist
quantum attackers. It is the term used by NIST, the IETF, and CISA, and it is
precisely true of Ratify's signatures. We do not describe Ratify, or any
deployment, as immune to all quantum risk, because security also depends on key
custody, transport, and implementation, as described above.

## Further reading

- [SPEC-v2.md](../SPEC-v2.md): §2 (keys and key IDs), §3 (typed signing
  transcript), §9 (security considerations).
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
