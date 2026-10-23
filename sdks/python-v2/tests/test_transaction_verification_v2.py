"""transaction-verification.json: composed transaction-receipt verification
(SPEC-v2 §5.7) with the verifier-ordering provider and journal inputs
(mirrors Go TestV2ConformanceTransactionVerification)."""
from __future__ import annotations

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, build_verify_request

from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.transaction_verify_v2 import (
    TransactionVerifyRequestV2,
    TransactionVerifySourcesV2,
    verify_transaction_receipt_v2,
)

FILE = load("transaction-verification.json")
VECTORS = FILE["vectors"]


def test_transaction_verification_corpus_shape():
    assert len(VECTORS) == 13


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_transaction_verification(v):
    req, cb, _ = build_verify_request(v, None, Counts())
    sources = TransactionVerifySourcesV2(status_evidence=cb.status_evidence, status_journal=cb.status_journal,
                                         status_keys=req.status_keys, status_policy=req.status_policy)
    if v.get("trust") is not None:
        sources.trust = cb.trust
    try:
        got, err = verify_transaction_receipt_v2(BACKGROUND, TransactionVerifyRequestV2(
            receipt=b64(v["receipt_b64"]), now=v.get("now", 0), future_skew_seconds=v.get("future_skew_seconds", 0)), sources), None
    except Exception as exc:  # noqa: BLE001
        got, err = None, exc
    want = v["expected"]
    if want.get("error_class"):
        assert error_class_of(err) == want["error_class"], err
        return
    assert err is None, err
    assert got.actionable is False
    assert got.to_json_dict() == want["result"]
