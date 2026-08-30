"""Keygen surface tests.

`docs/SDKS.md` §4 requires every SDK to export `hybrid_keypair_from_seeds` with
equivalent semantics. Python cannot honour the ML-DSA half of that contract, so
these tests pin the refusal: the failure must be loud, and it must not be
mistaken for a working deterministic keygen.
"""
from __future__ import annotations

import pytest

from ratify_protocol import (
    generate_hybrid_keypair,
    hybrid_keypair_from_seeds,
)


def test_generate_hybrid_keypair_returns_a_usable_hybrid_keypair():
    """Guards the random path, which shares a body shape with the seeded one."""
    pub, priv = generate_hybrid_keypair()
    assert len(pub.ed25519) == 32
    assert len(pub.ml_dsa_65) == 1952
    assert len(priv.ed25519) == 32


def test_hybrid_keypair_from_seeds_refuses_rather_than_returning_nondeterministic_keys():
    """Returning a keypair here would be worse than refusing.

    pqcrypto's ML-DSA binding ignores a caller-supplied seed, so the same seeds
    would produce a different identity on every call with no error. A caller
    persisting seeds to restore an identity would silently get a new one and
    only discover it when verification failed somewhere else.
    """
    with pytest.raises(NotImplementedError, match="not available in the Python SDK"):
        hybrid_keypair_from_seeds(bytes(32), bytes(32))


def test_hybrid_keypair_from_seeds_validates_seed_lengths_first():
    """A malformed seed still reports the specific fault, not the refusal."""
    with pytest.raises(ValueError, match="Ed25519 seed must be 32 bytes"):
        hybrid_keypair_from_seeds(b"short", bytes(32))
    with pytest.raises(ValueError, match="ML-DSA-65 seed must be 32 bytes"):
        hybrid_keypair_from_seeds(bytes(32), b"short")
