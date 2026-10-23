"""SPEC-v2 §2.5 and §2.6 boundaries from "limits.json": every per-object byte
limit at limit and limit+1, count limits, and the timestamp domain. The
pre-parse size gate must be the first check: an over-limit input fails with
the named limit, and an at-limit input never does."""
from __future__ import annotations

import base64
import hashlib

import pytest

from corpus import load
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import limits_v2
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import status_batch_v2 as sb
from ratify_protocol_v2 import transaction_receipt_v2 as txv2
from ratify_protocol_v2 import verification_receipt_v2 as vrv2
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2.clock_bounds_v2 import V2_MAX_TIMESTAMP_SECONDS
from ratify_protocol_v2.errors_v2 import error_class_of

LIMITS = load("limits.json")

DECODERS = {
    "delegation_certificate": pv2.decode_delegation_cert_v2,
    "proof_bundle": pv2.decode_proof_bundle_v2,
    "key_rotation_statement": kr.decode_key_rotation_statement_v2,
    "revocation_list": pv2.decode_revocation_list_v2,
    "revocation_push": pv2.decode_revocation_push_v2,
    "witness_entry": wv2.decode_witness_entry_v2,
    "verification_receipt": vrv2.decode_verification_receipt_v2,
    "verification_receipt_body": vrv2.decode_verification_receipt_body_v2,
    "transaction_receipt": txv2.decode_transaction_receipt_v2,
    "status_evidence_batch": sb.decode_v2_status_evidence_batch,
}


def build_limit_bytes(c: dict) -> bytes:
    """Go ``v2vectors.BuildLimitBytes``."""
    d = base64.b64decode
    method = c["method"]
    if method == "inline":
        return d(c["wire_b64"])
    if method == "pad":
        base = d(c["base_b64"])
        assert base
        return base[:-1] + b" " * c["pad_count"] + base[-1:]
    if method == "repeat_items":
        items = (f"{c['item_prefix']}{i:0{c['item_index_digits']}d}{c['item_suffix']}".encode()
                 for i in range(c["count"]))
        return d(c["prefix_b64"]) + b",".join(items) + d(c["suffix_b64"])
    if method == "repeat_item":
        return d(c["prefix_b64"]) + b",".join([d(c["item_b64"])] * c["count"]) + d(c["suffix_b64"])
    pytest.fail(f"unknown construction {method!r}")


def test_limits_table_matches_the_sdk():
    table = LIMITS["limits"]
    assert table["MAX_TIMESTAMP_SECONDS_V2"] == V2_MAX_TIMESTAMP_SECONDS
    for name, value in table.items():
        if name == "MAX_TIMESTAMP_SECONDS_V2":
            continue
        assert getattr(limits_v2, name) == value, name
    assert len(LIMITS["vectors"]) == 57
    assert set(LIMITS["procedure_by_kind"]) == set(DECODERS)


@pytest.mark.parametrize("v", LIMITS["vectors"], ids=lambda v: v["name"])
def test_limit_vector(v):
    assert LIMITS["limits"][v["limit"]] == v["limit_value"]
    data = build_limit_bytes(v["construction"])
    assert len(data) == v["length"] and hashlib.sha256(data).hexdigest() == v["sha256_hex"]
    err = None
    try:
        DECODERS[v["kind"]](data)
    except Exception as exc:  # noqa: BLE001
        err = exc
    if v["expected"] == "accept":
        assert err is None, f"at-limit input rejected: {err!r}"
    elif v["expected"] == "reject":
        assert err is not None and error_class_of(err) == v["expected_error_class"], err
    else:
        pytest.fail(f"unknown expectation {v['expected']!r}")
    size_gate_failed = err is not None and f"exceeds {v['limit']} (" in str(err) and "rejected before parsing" in str(err)
    assert (v["size_gate"] == "fail") == size_gate_failed, err
