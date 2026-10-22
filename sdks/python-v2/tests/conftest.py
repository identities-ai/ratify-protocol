"""RATIFY_REQUIRE_NATIVE=1 turns a missing ratify-protocol-native-v2 into a
hard error instead of skipped signing tests.

RATIFY_V2_RECORD_VERIFY=<path> records every hybrid signature check the run
performs (inputs and verdict) to ``path``; test_verify_backends_v2.py uses it
to replay the signature corpus through both verifiers."""
from __future__ import annotations

import os
import pickle

from ratify_protocol_v2 import _native, signing_v2
from ratify_protocol_v2.errors_v2 import V2Error
from ratify_protocol_v2.types import HybridPublicKey, HybridSignature

_RECORDS: dict = {}


def _recording(verify):
    def wrapper(code, signable, sig, pub):
        key = None
        if (
            isinstance(signable, (bytes, bytearray)) and isinstance(sig, HybridSignature)
            and isinstance(pub, HybridPublicKey)
            and all(isinstance(v, (bytes, bytearray)) for v in (sig.ed25519, sig.ml_dsa_65, pub.ed25519, pub.ml_dsa_65))
        ):
            key = (code, bytes(signable), bytes(sig.ed25519), bytes(sig.ml_dsa_65), bytes(pub.ed25519), bytes(pub.ml_dsa_65))
        try:
            verify(code, signable, sig, pub)
        except Exception as exc:
            if key is not None:
                _RECORDS[key] = exc.error_class if isinstance(exc, V2Error) else "invalid_signature"
            raise
        if key is not None:
            _RECORDS[key] = "ok"

    return wrapper


def pytest_configure(config):
    if os.environ.get("RATIFY_REQUIRE_NATIVE") == "1" and not _native.AVAILABLE:
        raise RuntimeError("RATIFY_REQUIRE_NATIVE=1 but ratify-protocol-native-v2 is not installed")
    if os.environ.get("RATIFY_V2_RECORD_VERIFY"):
        signing_v2._verify_unclassified = _recording(signing_v2._verify_unclassified)


def pytest_unconfigure(config):
    path = os.environ.get("RATIFY_V2_RECORD_VERIFY")
    if path:
        with open(path, "wb") as fh:
            pickle.dump(_RECORDS, fh)
