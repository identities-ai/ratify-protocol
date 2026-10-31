"""Test-only helpers for reproducing the shared Protocol v2 vectors.

Not part of the public API. Production signing is always hedged.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from . import signing_v2
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


@contextmanager
def pure_python_verification() -> Iterator[None]:
    """Within this block, hybrid signatures are verified by the pure-Python
    fallback verifier instead of the native extension, so tests can compare
    the two. It switches a process-wide setting: do not use it while other
    threads verify."""
    saved = signing_v2._NATIVE_VERIFY
    signing_v2._NATIVE_VERIFY = None
    try:
        yield
    finally:
        signing_v2._NATIVE_VERIFY = saved
