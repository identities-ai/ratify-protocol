"""verifier-ordering.json: the live verifier's stage, error class, committed
tuple, exact receipt outbox body, allow horizon, rate batch, and every
callback count (mirrors Go TestV2ConformanceVerifierOrdering)."""
from __future__ import annotations

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, ScriptedClaimStore, build_verify_request, expected_counts

from ratify_protocol_v2.release_v2 import receipt_outbox_digest_v2
from ratify_protocol_v2.verification_receipt_v2 import decode_verification_receipt_body_v2
from ratify_protocol_v2.verify_v2 import verify_proof_bundle_v2

FILE = load("verifier-ordering.json")
VECTORS = FILE["vectors"]


def test_ordering_corpus_shape():
    assert len(VECTORS) == 484
    stages = {}
    for v in VECTORS:
        stages[v["expected"]["stage"]] = stages.get(v["expected"]["stage"], 0) + 1
    assert stages == {"preflight": 134, "replay": 2, "committed": 346, "evaluating": 2}


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_verifier_ordering(v):
    bundle = b64(FILE["bundles_b64"][v["bundle"]])
    counts = Counts()
    req, cb, rate = build_verify_request(v, bundle, counts)
    claimed_at = v["now"] + v.get("claim_time_offset", 0)
    store = ScriptedClaimStore(v.get("claim_store", ""), claimed_at, claimed_at + v.get("finalize_time_offset", 0), counts)
    # claim_store "absent": no claim store is configured.
    cb.claim_store = None if v.get("claim_store") == "absent" else store

    outcome = verify_proof_bundle_v2(BACKGROUND, req, cb)
    want = v["expected"]
    assert outcome.stage == want["stage"], (outcome.error_class, outcome.error)
    assert (outcome.error is not None) == (want["stage"] in ("preflight", "evaluating"))
    assert outcome.error_class == want.get("error_class", ""), outcome.error
    if want.get("disposition"):
        assert outcome.disposition == want["disposition"]
    assert counts.as_dict() == expected_counts(want.get("callback_counts", {}))
    if want["stage"] != "committed":
        assert outcome.committed is None
        return
    committed = outcome.committed
    assert committed is not None
    body = committed.receipt_body()
    r = decode_verification_receipt_body_v2(body)
    got = [r.decision, r.decision_reason, r.identity_status, r.trust_assessment, r.status_assessment, r.context_assessment]
    exp = [want["decision"], want["decision_reason"], want["identity_status"], want["trust_assessment"],
           want["status_assessment"], want["context_assessment"]]
    assert got == exp
    assert r.verified_at == want["verified_at"]
    want_body = b64(want["receipt_body_b64"])
    assert body == want_body
    assert store.final_body == body
    assert committed.receipt_body_digest() == receipt_outbox_digest_v2(want_body)
    assert committed.claim_id() != ""
    horizon, ok = committed.allow_horizon()
    assert ok == (want["decision"] == "allow")
    assert horizon == want.get("allow_valid_until", 0)
    if want.get("rate_batch"):
        assert rate is not None and rate.batch is not None
        assert [(g.issuer_id, g.cert_id, g.window_s, g.limit) for g in rate.batch] == [
            (w["issuer_id"], w["cert_id"], w["window_s"], w["limit"]) for w in want["rate_batch"]]
