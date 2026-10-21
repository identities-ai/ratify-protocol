"""Cross-SDK known answers and fail-closed replay identifier inputs."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ratify_protocol_v2 import (
    challenge_claim_digest_v2,
    protocol_claim_id_v2,
    protocol_claim_id_from_digest_v2,
)

V2_DIR = Path(os.environ.get("RATIFY_V2_VECTOR_DIR") or Path(__file__).resolve().parents[3] / "testvectors" / "v2")
VECTOR = json.loads((V2_DIR / "challenge-claim.json").read_text())
CHALLENGE = bytes.fromhex(VECTOR["challenge_hex"])


def test_claim_digest_and_id_match_shared_go_vectors():
    digest = challenge_claim_digest_v2(CHALLENGE)
    assert digest.hex() == VECTOR["expected_challenge_claim_digest_hex"]
    main = VECTOR["claim_id_input"]
    assert protocol_claim_id_v2(main["verifier_namespace"], main["replay_epoch"], CHALLENGE) == VECTOR["expected_claim_id"]
    assert protocol_claim_id_from_digest_v2(main["verifier_namespace"], main["replay_epoch"], digest) == VECTOR["expected_claim_id"]
    for case in VECTOR["additional_claim_id_cases"]:
        assert protocol_claim_id_v2(case["verifier_namespace"], case["replay_epoch"], CHALLENGE) == case["expected_claim_id"]
        assert protocol_claim_id_from_digest_v2(case["verifier_namespace"], case["replay_epoch"], digest) == case["expected_claim_id"]


def test_claim_identifiers_reject_invalid_bytes_namespace_and_epoch():
    for value in (b"", b"x" * 31, b"x" * 33, "x" * 32, bytearray(32)):
        with pytest.raises(ValueError, match="exactly 32"):
            challenge_claim_digest_v2(value)
    for namespace in ("", "\ud800", 123):
        with pytest.raises(ValueError, match="namespace"):
            protocol_claim_id_v2(namespace, 7, CHALLENGE)
    for epoch in (-1, 0.5, True, 2**53):
        with pytest.raises(ValueError, match="safe integer"):
            protocol_claim_id_v2("verify-prod", epoch, CHALLENGE)
    for digest in (b"", b"x" * 47, b"x" * 49, "x" * 48):
        with pytest.raises(ValueError, match="exactly 48"):
            protocol_claim_id_from_digest_v2("verify-prod", 7, digest)
    with pytest.raises(ValueError, match="namespace"):
        protocol_claim_id_from_digest_v2("\udc00", 7, b"x" * 48)


