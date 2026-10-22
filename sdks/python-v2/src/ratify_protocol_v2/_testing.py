"""Test-only helpers for reproducing the shared Protocol v2 vectors.

Not part of the public API. Production signing is always hedged.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from .signing_v2 import _DETERMINISTIC_FOR_TEST_VECTORS


@contextmanager
def deterministic_test_vector_signing() -> Iterator[None]:
    """Within this block, typed signers use the FIPS 204 deterministic ML-DSA
    variant (all-zero ``rnd``), as the vector generators do, so signatures
    are byte-reproducible. Never use it for production signatures."""
    token = _DETERMINISTIC_FOR_TEST_VECTORS.set(True)
    try:
        yield
    finally:
        _DETERMINISTIC_FOR_TEST_VECTORS.reset(token)
