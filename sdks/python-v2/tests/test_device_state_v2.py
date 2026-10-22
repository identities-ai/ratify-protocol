"""device-state.json: the single-device offline complete-state projection
(SPEC-v2 §7.13). Each case is loaded into a reference primary, which must
reproduce every canonical member byte string, member digest, the projection
object, and the complete-state digest exactly (mirrors Go
TestDeviceStateProjectionVectors)."""
from __future__ import annotations

import hashlib

import pytest

from corpus import b64, load, pubkey
from v2_harness import keys

from ratify_protocol_v2 import _native
from ratify_protocol_v2.challenge_claim_v2 import challenge_claim_digest_v2
from ratify_protocol_v2.claim_store_v2 import V2ChallengeClaim
from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol_v2.evaluation_progress_v2 import V2EvaluationProgress
from ratify_protocol_v2.rate_reservation_v2 import V2RateReservation
from ratify_protocol_v2.release_v2 import V2ReleaseRecord
from ratify_protocol_v2.security_journal_v2 import SecurityJournalHeadV2
from ratify_protocol_v2.types_v2 import ConstraintEvaluatorRefV2, StatusEvidenceEntryV2
from ratify_protocol_v2.verify_v2_preflight import ExpectedChallengeV2
from ratify_protocol_v2.v2reference import device_state as ds
from ratify_protocol_v2.v2reference.challenges import _issuance_key
from ratify_protocol_v2.v2reference.store import Store, _ClaimRecord, _OutboxEntry

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

FILE = load("device-state.json")
CASES = FILE["cases"]
MEMBERS = ("claims", "streams", "rate_counters", "receipt_log", "issuance_records")


def _opt_b64(value):
    return b"" if value is None else b64(value)


def _sealed_claim(sc: dict) -> V2ChallengeClaim:
    return V2ChallengeClaim(
        claim_id=sc["claim_id"], namespace=sc["namespace"], replay_epoch=sc["replay_epoch"],
        challenge_digest=sc["challenge_digest"], proof_digest=sc["proof_digest"], bundle_hash=sc["bundle_hash"],
        issuer_ids=list(sc["issuer_ids"]), required_scope=sc["required_scope"],
        context_policy_digest=sc["context_policy_digest"] or "", verifier_id=sc["verifier_id"],
        agent_id=sc["agent_id"], requires_rate=sc["requires_rate"],
        rate_batch=[V2RateReservation(issuer_id=r["issuer_id"], cert_id=r["cert_id"], window_s=r["window_s"],
                                      limit=r["limit"]) for r in sc["rate_batch"]],
        issued_at=sc["issued_at"], expires_at=sc["expires_at"], max_age_seconds=sc["max_age_seconds"],
        clock_skew_seconds=sc["clock_skew_seconds"],
        stream_id=None if sc["stream_id"] is None else b64(sc["stream_id"]), stream_seq=sc["stream_seq"],
        constraint_evaluators=[ConstraintEvaluatorRefV2(profile_digest=e["profile_digest"], type=e["type"])
                               for e in sc["constraint_evaluators"]],
    )


def _progress(p: dict) -> V2EvaluationProgress:
    return V2EvaluationProgress(
        trust_assessment=p["trust_assessment"], status_assessment=p["status_assessment"],
        context_assessment=p["context_assessment"], context_policy_digest=p["context_policy_digest"],
        status_evidence=[StatusEvidenceEntryV2(issuer_id=e["issuer_id"], status_key_id=e["status_key_id"],
                                               sequence=e["sequence"], object_type=e["object_type_code"],
                                               digest=e["digest"]) for e in p["status_evidence_digests"]],
    )


def load_case(case: dict) -> ds.DevicePrimaryTestOnly:
    """A primary holding exactly the case's records."""
    state = case["state"]
    store = Store(1_800_000_000, 30, state["log_id"], keys().priv("verifier"))
    for c in state["claims"]:
        release = None
        if c["release"] is not None:
            r = c["release"]
            release = V2ReleaseRecord(claim_id=r["claim_id"], entry_hash=b64(r["entry_hash"]), ack_timestamp=r["ack_timestamp"])
        store._claims[c["claim_id"]] = _ClaimRecord(
            claim=_sealed_claim(c["claim"]), owner_digest=b64(c["owner_digest"]), lease_expires_at=c["lease_expires_at"],
            state=c["state"], claimed_at=c["claimed_at"], progress=_progress(c["progress"]),
            terminal=_opt_b64(c["terminal_b64"]), receipt_body=_opt_b64(c["receipt_body_b64"]),
            allow_horizon=c["allow_horizon"], finalized_at=c["finalized_at"], release=release, abandoned=c["abandoned"],
            outbox_index=-1 if c["log_sequence"] is None else c["log_sequence"] - 1,
        )
    for s in state["streams"]:
        store._streams[(s["namespace"], s["agent_id"], b64(s["stream_id"]))] = s["last_sequence"]
    for r in state["rate_counters"]:
        store._rate_commits[(r["issuer_id"], r["cert_id"], r["window_s"])] = list(r["commits"])
    for e in state["receipt_log"]["entries"]:
        store._outbox.append(_OutboxEntry(claim_id=e["claim_id"], body=b64(e["body_b64"]), digest=_opt_b64(e["entry_hash"])))
    store._log_frozen = state["receipt_log"]["frozen"]
    primary = ds.DevicePrimaryTestOnly(store, state["replay_epoch"])
    journal = primary.journal.inner
    journal._head = SecurityJournalHeadV2(generation=state["security_journal"]["generation"], digest=journal._head.digest)
    journal._snapshot = b64(state["security_journal"]["snapshot_b64"])
    for r in state["issuance_records"]:
        policy = None
        if r["context_policy"] is not None:
            p = r["context_policy"]
            policy = new_v2_context_policy(p["profile"], p["require_bound"], p["required_fields"],
                                           None if p["expected_session_context"] is None else b64(p["expected_session_context"]))
        record = ExpectedChallengeV2(
            value=b64(r["value"]), issued_at=r["issued_at"], expires_at=r["expires_at"],
            verifier_namespace=r["verifier_namespace"], replay_epoch=r["replay_epoch"], verifier_id=r["verifier_id"],
            expected_agent_id=r["expected_agent_id"],
            expected_agent_public_key=None if r["expected_agent_pub_key"] is None else pubkey(r["expected_agent_pub_key"]),
            expected_receiver_id=r["expected_receiver_id"],
            expected_session_context=None if r["expected_session_context"] is None else b64(r["expected_session_context"]),
            context_policy=policy,
        )
        key = _issuance_key(record.verifier_namespace, record.replay_epoch, challenge_claim_digest_v2(record.value))
        primary.issuance.inner._records[key] = record
    return primary


def test_device_state_corpus_shape():
    assert FILE["label"] == ds.DEVICE_STATE_LABEL.decode("ascii")
    assert FILE["version"] == ds.DEVICE_STATE_VERSION
    assert [c["name"] for c in CASES] == ["empty_primary", "evaluating_claim", "every_record_kind",
                                         "every_record_kind_without_release", "abandoned_frozen_log"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_device_state_projection(case):
    primary = load_case(case)
    want = case["expect"]
    with primary.store._lock:
        claims, streams, rates, receipt_log = ds._store_members_locked(primary.store)
        store_state = ds._state_digests_locked(primary.store)
    issuance = primary._issuance_member_locked()
    got = {"claims": claims, "streams": streams, "rate_counters": rates, "receipt_log": receipt_log,
           "issuance_records": issuance}
    for name in MEMBERS:
        assert got[name].decode("utf-8") == want[f"{name}_canonical_json"], name
        assert hashlib.sha384(got[name]).hexdigest() == want[f"{name}_sha384"], name
    projection = primary._projection_locked(store_state, hashlib.sha384(issuance).hexdigest())
    assert projection.decode("utf-8") == want["projection_canonical_json"]
    digest = primary.complete_state_digest_test_only()
    assert digest.hex() == want["complete_state_digest_hex"]
    assert digest == hashlib.sha384(FILE["label"].encode("ascii") + b"\x00" + projection).digest()
