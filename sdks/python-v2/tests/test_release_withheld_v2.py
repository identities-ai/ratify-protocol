"""Release permanence (SPEC-v2 §6.9) and the reference checkpoint and rate
store (§7.6, §7.8). Mirrors Go release_v2_withheld_test.go,
v2reference/checkpoint_test.go and v2reference/store_test.go."""
from __future__ import annotations

import copy

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, build_verify_request, keys

from ratify_protocol_v2 import _native
from ratify_protocol_v2.claim_store_v2 import V2ChallengeClaim
from ratify_protocol_v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol_v2.evaluation_progress_v2 import v2_evaluation_interrupted_result
from ratify_protocol_v2.rate_reservation_v2 import V2RateReservation
from ratify_protocol_v2.release_v2 import (
    V2_RELEASE_REJECTED,
    V2_RELEASE_RELEASED,
    V2_RELEASE_WITHHELD,
    AcknowledgementNotFoundErrorV2,
    ReleaseStateMismatchErrorV2,
    V2ReleaseConfig,
    V2ReleaseRecord,
    release_v2_decision,
    valid_v2_release_record_outcome,
)
from ratify_protocol_v2.signing_v2 import generate_keypair_v2, key_id_v2
from ratify_protocol_v2.v2reference.store import NotAcknowledgedError, Store
from ratify_protocol_v2.verification_receipt_v2 import decode_verification_receipt_v2, verification_receipt_v2_digest
from ratify_protocol_v2.verify_v2 import V2_STAGE_COMMITTED, verify_proof_bundle_v2

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

LIFECYCLE = load("lifecycle-scenarios.json")
NOW = 1800000000


def release_fixture():
    """Commit and publish lifecycle request A against a fresh reference store
    and return what release needs."""
    fx = keys()
    request = copy.deepcopy(LIFECYCLE["requests"]["A"])
    verifier_key = LIFECYCLE["verifier_key"]
    store = Store(request["now"], LIFECYCLE["lease_seconds"], LIFECYCLE["log_id"], fx.priv(verifier_key))
    req, cb, _ = build_verify_request(request, b64(LIFECYCLE["bundles_b64"][request["bundle"]]), Counts())
    cb.claim_store = store
    outcome = verify_proof_bundle_v2(BACKGROUND, req, cb)
    assert outcome.stage == V2_STAGE_COMMITTED, (outcome.error_class, outcome.error)
    wire = store.publish_v2_receipt(BACKGROUND, outcome.committed.claim_id(), outcome.committed.receipt_body())
    config = V2ReleaseConfig(verifier_public_key=fx.pub[verifier_key], log_id=LIFECYCLE["log_id"], claim_store=store,
                             checkpoint=store)
    return store, outcome.committed, wire, config


class RecordFailingStore:
    """The reference store with every record_v2_release failing with ``err``."""

    def __init__(self, inner: Store, err: Exception):
        self.inner, self.err, self.calls = inner, err, 0

    def record_v2_release(self, ctx, record):
        self.calls += 1
        raise self.err

    def __getattr__(self, name):
        return getattr(self.inner, name)


def test_withheld_when_recording_withheld_fails():
    # A withheld result must never become released. If recording it fails,
    # the call is still withheld: failing open to pending would let a later
    # call with a recovered clock release a decision already withheld.
    store, committed, wire, config = release_fixture()
    failing = RecordFailingStore(store, RuntimeError("store unavailable"))
    config.claim_store = failing
    store.set_time(committed.challenge_expires_at())
    result = release_v2_decision(BACKGROUND, committed, wire, config)
    assert (result.status, result.reason, result.decision, failing.calls) == (V2_RELEASE_WITHHELD, "challenge_expired", None, 1)


def test_withheld_record_conflict_is_rejected():
    # The first record wins: a different record already present when release
    # tries to record its withheld result is a state mismatch.
    store, committed, wire, config = release_fixture()
    config.claim_store = RecordFailingStore(store, ReleaseStateMismatchErrorV2())
    store.set_time(committed.challenge_expires_at())
    result = release_v2_decision(BACKGROUND, committed, wire, config)
    assert (result.status, result.reason) == (V2_RELEASE_REJECTED, "release_state_mismatch")


def test_recorded_withheld_is_answered_first():
    # A recorded withheld result is returned right after the committed-state
    # step, before any receipt or acknowledgement is consulted.
    store, committed, wire, config = release_fixture()
    store.set_time(committed.challenge_expires_at())
    result = release_v2_decision(BACKGROUND, committed, wire, config)
    assert (result.status, result.reason) == (V2_RELEASE_WITHHELD, "challenge_expired")
    config.checkpoint = None
    assert release_v2_decision(BACKGROUND, committed, None, config).status == V2_RELEASE_REJECTED
    config.checkpoint = store
    result = release_v2_decision(BACKGROUND, committed, None, config)
    assert (result.status, result.reason) == (V2_RELEASE_WITHHELD, "challenge_expired")
    # The clock recovering does not turn it into a release.
    store.set_time(committed.challenge_expires_at() - 1)
    assert release_v2_decision(BACKGROUND, committed, wire, config).status == V2_RELEASE_WITHHELD


def test_reference_store_records_withheld_first_wins():
    # An identical repeat is a no-op, a different outcome or reason is a state
    # mismatch, and an outcome that is not a release record is refused before
    # anything is stored.
    store, committed, wire, _ = release_fixture()
    entry = bytes(verification_receipt_v2_digest(decode_verification_receipt_v2(wire)))
    claim_id = committed.claim_id()

    def record(outcome="", reason=""):
        return V2ReleaseRecord(claim_id=claim_id, entry_hash=entry, ack_timestamp=7, outcome=outcome, reason=reason)

    for name, invalid in {
        "no outcome": record(),
        "released with reason": record(V2_RELEASE_RELEASED, "clock_regressed"),
        "withheld, other cause": record(V2_RELEASE_WITHHELD, "receipt_invalid"),
        "rejected outcome": record(V2_RELEASE_REJECTED, "receipt_invalid"),
    }.items():
        with pytest.raises(Exception) as raised:
            store.record_v2_release(BACKGROUND, invalid)
        assert error_class_of(raised.value) == V2ErrorClass.CONFIGURATION_INVALID, name
    withheld = record(V2_RELEASE_WITHHELD, "clock_regressed")
    store.record_v2_release(BACKGROUND, withheld)
    store.record_v2_release(BACKGROUND, withheld)
    for name, other in {"released": record(V2_RELEASE_RELEASED),
                        "other reason": record(V2_RELEASE_WITHHELD, "challenge_expired")}.items():
        with pytest.raises(ReleaseStateMismatchErrorV2):
            store.record_v2_release(BACKGROUND, other)
    loaded = store.load_v2_terminal_claim(BACKGROUND, claim_id)
    assert (loaded.release.outcome, loaded.release.reason) == (V2_RELEASE_WITHHELD, "clock_regressed")


def test_valid_release_record_outcomes():
    assert valid_v2_release_record_outcome(V2_RELEASE_RELEASED, "")
    for reason in ("clock_regressed", "challenge_expired", "allow_horizon_passed"):
        assert valid_v2_release_record_outcome(V2_RELEASE_WITHHELD, reason)
    for outcome, reason in (("", ""), (V2_RELEASE_RELEASED, "clock_regressed"), (V2_RELEASE_WITHHELD, ""),
                            (V2_RELEASE_WITHHELD, "receipt_abandoned"), (V2_RELEASE_REJECTED, "receipt_invalid")):
        assert not valid_v2_release_record_outcome(outcome, reason), (outcome, reason)


# ---------------------------------------------------------------------------
# Reference checkpoint


def committed_receipt_store(n: int):
    """A reference store holding n claims whose interrupted results were
    committed by lease-expiry recovery, in log order, so their receipts can
    be published without a live evaluation."""
    pub, priv = generate_keypair_v2()
    verifier_id = key_id_v2(pub)
    store = Store(NOW, 30, "dddddddddddddddddddddddddddddd01", priv)
    ids = []
    for i in range(n):
        digest = "sha384:" + "0" * 95 + chr(ord("1") + i)
        claim = V2ChallengeClaim(claim_id="claim-" + chr(ord("a") + i), namespace="ns", agent_id="a" * 64,
                                 proof_digest=digest, bundle_hash=digest, issuer_ids=["b" * 64],
                                 required_scope="data:read", verifier_id=verifier_id, issued_at=NOW - 10,
                                 expires_at=NOW + 290, max_age_seconds=300, clock_skew_seconds=5)
        store.claim_v2(BACKGROUND, claim)
        ids.append(claim.claim_id)
    store.set_time(NOW + 30)
    for claim_id in ids:
        loaded = store.load_v2_interrupted_claim(BACKGROUND, claim_id)
        terminal, body = v2_evaluation_interrupted_result(loaded.claim, loaded.claimed_at, loaded.progress)
        store.recover_interrupted_v2_claim(BACKGROUND, claim_id, terminal, body)
    return store, ids


def published_tuple(store: Store, claim_id: str):
    record = store.load_v2_interrupted_claim(BACKGROUND, claim_id)
    _, body = v2_evaluation_interrupted_result(record.claim, record.claimed_at, record.progress)
    receipt = decode_verification_receipt_v2(store.publish_v2_receipt(BACKGROUND, claim_id, body))
    return receipt, bytes(verification_receipt_v2_digest(receipt))


def test_checkpoint_freezes_log_after_fork():
    # A different entry hash at an acknowledged sequence is a fork (SPEC-v2
    # §7.8). If the checkpoint kept acknowledging after it, a forked log could
    # keep releasing decisions; it must acknowledge nothing further for it.
    store, ids = committed_receipt_store(2)
    first, first_entry = published_tuple(store, ids[0])
    store.set_acknowledgement_withheld(True)
    second, second_entry = published_tuple(store, ids[1])
    store.set_time(NOW + 40)
    forked = bytearray(first_entry)
    forked[0] ^= 1
    with pytest.raises(NotAcknowledgedError):
        store.acknowledge_v2_receipt(BACKGROUND, first.log_id, 1, first.previous_receipt_hash, bytes(forked))
    ack = store.acknowledge_v2_receipt(BACKGROUND, first.log_id, 1, first.previous_receipt_hash, first_entry)
    assert ack.timestamp == NOW + 30
    store.set_acknowledgement_withheld(False)
    with pytest.raises(NotAcknowledgedError):
        store.acknowledge_v2_receipt(BACKGROUND, second.log_id, 2, first_entry, second_entry)
    with pytest.raises(AcknowledgementNotFoundErrorV2):
        store.get_v2_acknowledgement(BACKGROUND, second.log_id, 2)
    assert bytes(second.previous_receipt_hash) == first_entry


def test_checkpoint_refusal_without_fork_does_not_freeze():
    # A refusal that is not a fork, such as an out-of-order sequence, must not
    # freeze the log.
    store, ids = committed_receipt_store(2)
    store.set_acknowledgement_withheld(True)
    first, first_entry = published_tuple(store, ids[0])
    second, second_entry = published_tuple(store, ids[1])
    with pytest.raises(NotAcknowledgedError):
        store.acknowledge_v2_receipt(BACKGROUND, second.log_id, 2, first_entry, second_entry)
    store.acknowledge_v2_receipt(BACKGROUND, first.log_id, 1, first.previous_receipt_hash, first_entry)
    store.acknowledge_v2_receipt(BACKGROUND, second.log_id, 2, first_entry, second_entry)


def test_rate_at_finalization_store_never_reserves_provisionally():
    # The reference store admits max_rate inside its terminal compare-and-set
    # (SPEC-v2 §7.1, §7.6). Its provisional reservation call exists only to
    # satisfy the rate-store interface and must never report capacity.
    store, _ = committed_receipt_store(0)
    rate_store = store.with_rate_at_finalization()
    with pytest.raises(Exception):
        rate_store.reserve_v2_rate_batch(BACKGROUND, "claim", bytes(32), "sha384:x",
                                         [V2RateReservation(issuer_id="i", cert_id="c", window_s=60, limit=1)])
