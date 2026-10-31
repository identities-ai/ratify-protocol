"""Shared helpers for the Protocol v2 conformance corpus (testvectors/v2).

CONSUMERS names, for every file in the corpus directory, the test module that
runs it. test_corpus_files.py fails when a file has no consumer, when a
consumer module is missing, or when a consumer module never loads its file.
"""
from __future__ import annotations

import base64
import json
import os
from functools import lru_cache
from pathlib import Path

from ratify_protocol.v2.types import HybridPublicKey, HybridSignature

TESTS_DIR = Path(__file__).resolve().parent

# RATIFY_V2_VECTOR_DIR lets the runner be pointed at a tampered copy of the
# corpus (mutation testing) or at the corpus of an installed checkout.
V2_DIR = Path(os.environ.get("RATIFY_V2_VECTOR_DIR") or TESTS_DIR.parents[2] / "testvectors" / "v2")
CROSS_SDK_DIR = V2_DIR / "cross-sdk"

# Every file in testvectors/v2 and the test module that consumes it.
CONSUMERS = {
    "README.md": None,  # documentation, not a vector file
    "keys.json": "test_v2_conformance.py",
    "objects.json": "test_v2_conformance.py",
    "object-negatives.json": "test_v2_conformance.py",
    "log-sequences.json": "test_v2_conformance.py",
    "rotation-sequences.json": "test_v2_conformance.py",
    "delegation-signature.json": "test_v2_conformance.py",
    "operation-session-context.json": "test_v2_conformance.py",
    "challenge-claim.json": "test_v2_conformance.py",
    "key-rotation-signature.json": "test_v2_conformance.py",
    "derive-external-mu.py": "test_v2_conformance.py",
    "hedged-signatures.json": "test_hedged_signatures_v2.py",
    "limits.json": "test_limits_v2.py",
    "annex-a.json": "test_annex_a_v2.py",
    "issuer-duties.json": "test_issuer_duties_v2.py",
    "status-sequences.json": "test_status_sequences_v2.py",
    "security-journal.json": "test_security_journal_v2.py",
    "status-publisher.json": "test_status_publisher_v2.py",
    "evaluator-profiles.json": "test_evaluator_profiles_v2.py",
    "verifier-ordering.json": "test_verifier_ordering_v2.py",
    "lifecycle-scenarios.json": "test_lifecycle_scenarios_v2.py",
    "concurrency-scenarios.json": "test_concurrency_scenarios_v2.py",
    "challenge-issuance.json": "test_challenge_issuance_v2.py",
    "transaction-verification.json": "test_transaction_verification_v2.py",
    "device-state.json": "test_device_state_v2.py",
    "archival.json": "test_archival_signer_digest_v2.py",
    "external-signer.json": "test_archival_signer_digest_v2.py",
    "digest-functions.json": "test_archival_signer_digest_v2.py",
}


@lru_cache(maxsize=None)
def _load_text(name: str) -> str:
    return (V2_DIR / name).read_text(encoding="utf-8")


def load(name: str):
    """Parse one corpus file. Each call returns a fresh object."""
    return json.loads(_load_text(name))


def b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def pubkey(d: dict) -> HybridPublicKey:
    return HybridPublicKey(ed25519=b64(d["ed25519"]), ml_dsa_65=b64(d["ml_dsa_65"]))


def sig(d: dict) -> HybridSignature:
    return HybridSignature(ed25519=b64(d["ed25519"]), ml_dsa_65=b64(d["ml_dsa_65"]))
