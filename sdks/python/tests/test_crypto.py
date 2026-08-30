"""Key generation surface.

`docs/SDKS.md` requires every SDK to export `hybrid_keypair_from_seeds`. Python
can only honour it with the optional native extra, because pqcrypto's ML-DSA-65
binding ignores a caller-supplied seed.

Both states are tested. Which one applies is decided by whether the extra is
installed, and CI must not be allowed to drift into testing neither: set
RATIFY_REQUIRE_NATIVE=1 and the absence of the extension becomes a failure
rather than a skip.
"""
from __future__ import annotations

import os

import pytest

from ratify_protocol import (
    derive_id,
    generate_hybrid_keypair,
    hybrid_keypair_from_seeds,
    sign_challenge,
    verify_challenge_signature,
)
from ratify_protocol.crypto import _native_seed_keypair

NATIVE = _native_seed_keypair is not None
REQUIRED = os.environ.get("RATIFY_REQUIRE_NATIVE") == "1"

# The guard that keeps a green suite honest. Without it, a CI job that meant to
# install the extra but did not would skip every test below that matters and
# still report success.
if REQUIRED and not NATIVE:
    raise RuntimeError(
        "RATIFY_REQUIRE_NATIVE=1 but ratify_protocol_native did not import; "
        "the native extra is expected in this environment"
    )

requires_native = pytest.mark.skipif(
    not NATIVE, reason="native extra not installed (set RATIFY_REQUIRE_NATIVE=1 to require it)"
)


def test_generate_hybrid_keypair_returns_a_usable_hybrid_keypair():
    """The random path is pure Python and must work with or without the extra."""
    pub, priv = generate_hybrid_keypair()
    assert len(pub.ed25519) == 32
    assert len(pub.ml_dsa_65) == 1952
    assert len(priv.ed25519) == 32


def test_hybrid_keypair_from_seeds_validates_seed_lengths_first():
    """A malformed seed reports the specific fault in either configuration."""
    with pytest.raises(ValueError, match="Ed25519 seed must be 32 bytes"):
        hybrid_keypair_from_seeds(b"short", bytes(32))
    with pytest.raises(ValueError, match="ML-DSA-65 seed must be 32 bytes"):
        hybrid_keypair_from_seeds(bytes(32), b"short")


@pytest.mark.skipif(NATIVE, reason="native extra is installed")
def test_without_the_extra_it_refuses_rather_than_returning_wrong_keys():
    """Refusing is the honest behaviour when the deterministic path is absent.

    Returning a keypair would break the single property the function exists
    for: the same seeds would yield a different identity on every call, and a
    caller persisting seeds to restore an identity would silently get a new one.
    """
    with pytest.raises(NotImplementedError, match="native extra"):
        hybrid_keypair_from_seeds(bytes(32), bytes(32))


@requires_native
def test_seeded_keygen_matches_the_cross_sdk_vector():
    """The same vector asserted by the Go, Rust, C, and TypeScript suites.

    Determinism alone is not enough: an implementation could be deterministic
    and deterministically different from the other SDKs, which is exactly the
    failure this vector exists to catch.
    """
    ed_seed = bytes(range(32))
    ml_seed = bytes((0xA0 + i) & 0xFF for i in range(32))

    pub, priv = hybrid_keypair_from_seeds(ed_seed, ml_seed)

    assert pub.ed25519.hex() == (
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    )
    assert len(pub.ml_dsa_65) == 1952
    assert pub.ml_dsa_65[:32].hex() == (
        "1963d47ac0e93110e3add0354e0333e31c75de34038909ec8833eb6e2aaa7218"
    )
    assert derive_id(pub) == "3823136b5a5fc4c755b22704474172c0"

    # bytes, not a list or memoryview: these flow straight into signing and
    # canonical encoding, both of which are byte-exact.
    assert isinstance(pub.ed25519, bytes)
    assert isinstance(pub.ml_dsa_65, bytes)
    assert isinstance(priv.ml_dsa_65, bytes)


@requires_native
def test_seeded_keygen_is_stable_across_calls():
    """The property the entry exists for: seeds rebuild the same identity."""
    ed_seed = bytes(range(32))
    ml_seed = bytes((0xA0 + i) & 0xFF for i in range(32))

    first, _ = hybrid_keypair_from_seeds(ed_seed, ml_seed)
    second, _ = hybrid_keypair_from_seeds(ed_seed, ml_seed)
    assert derive_id(first) == derive_id(second)
    assert first.ml_dsa_65 == second.ml_dsa_65


@requires_native
def test_natively_derived_key_signs_through_the_pqcrypto_path():
    """The extension generates keys; pqcrypto still signs and verifies them.

    These are different ML-DSA implementations, so their private-key encodings
    must agree. If they ever diverge, a key derived from seeds would produce
    signatures no other SDK accepts, and this is where that shows up.
    """
    ed_seed = bytes(range(32))
    ml_seed = bytes((0xA0 + i) & 0xFF for i in range(32))
    pub, priv = hybrid_keypair_from_seeds(ed_seed, ml_seed)

    challenge = bytes([7]) * 32
    ts = 1_800_000_000
    sig = sign_challenge(challenge, ts, priv)
    assert verify_challenge_signature(challenge, ts, sig, pub)
