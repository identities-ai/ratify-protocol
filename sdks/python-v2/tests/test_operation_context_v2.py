"""Shared-fixture checks for Protocol v2 request and session binding."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ratify_protocol_v2.operation_context_v2 import (
    decode_payload_digest,
    operation_context_v2_hash,
    session_context_v2_hash,
)

VECTOR_PATH = (
    Path(os.environ.get("RATIFY_V2_VECTOR_DIR") or Path(__file__).resolve().parents[3] / "testvectors" / "v2")
    / "operation-session-context.json"
)


def vector() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def test_v2_operation_and_session_hashes_match_shared_vector():
    v = vector()
    session = v["input"]
    operation = v["operation_input"]
    assert operation_context_v2_hash(
        operation["required_scope"], operation["operation"], operation["resource_id"],
        operation["requested_path"], bytes.fromhex(operation["payload_digest_hex"]),
    ).hex() == v["expected_request_hash_hex"]
    request_hash = bytes.fromhex(session["request_hash_hex"])
    assert session_context_v2_hash(
        session["verifier_id"], session["workspace_id"], session["agent_id"],
        session["session_id"], session["invocation_id"], request_hash,
    ).hex() == v["expected_session_context_hex"]

    empty = v["empty_payload_operation_input"]
    empty_hash = operation_context_v2_hash(
        empty["required_scope"], empty["operation"], empty["resource_id"],
        empty["requested_path"], None,
    )
    assert empty_hash.hex() == v["expected_empty_request_hash_hex"]
    assert session_context_v2_hash(
        session["verifier_id"], session["workspace_id"], session["agent_id"],
        session["session_id"], session["invocation_id"], empty_hash,
    ).hex() == v["expected_empty_session_context_hex"]


def test_verify_api_payload_digest_decoding_matches_shared_cases():
    for case in vector()["verify_api_payload_digest_decode_cases"]:
        if case["valid"]:
            decoded = decode_payload_digest(case["encoded"])
            assert (decoded or b"").hex() == case["expected_hex"]
        else:
            with pytest.raises(ValueError):
                decode_payload_digest(case["encoded"])


def test_session_context_rejects_malformed_identifiers_and_hash_size():
    v = vector()["input"]
    args = [v["verifier_id"], v["workspace_id"], v["agent_id"], v["session_id"], v["invocation_id"], b"\x11" * 32]
    for index, malformed in ((0, "A" + args[0][1:]), (1, "not-a-uuid"), (2, "z" + args[2][1:])):
        changed = args.copy()
        changed[index] = malformed
        with pytest.raises(ValueError):
            session_context_v2_hash(*changed)
    args[-1] = b"short"
    with pytest.raises(ValueError, match="request hash"):
        session_context_v2_hash(*args)


def test_context_rejects_unpaired_unicode_and_noncanonical_digest_text():
    with pytest.raises(ValueError, match="well-formed Unicode"):
        operation_context_v2_hash(required_scope="data:read", operation="\ud800")
    with pytest.raises(ValueError):
        decode_payload_digest("sha256:" + "a" * 62 + " a")


def test_operation_context_rejects_noncanonical_required_scopes():
    for scope in vector()["invalid_required_scopes"]:
        with pytest.raises(ValueError, match="required scope"):
            operation_context_v2_hash(required_scope=scope)
