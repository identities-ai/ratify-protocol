"""Resumption of committed work from the claim store (SPEC-v2 §7.11).
Mirrors Go resume_committed_v2_test.go."""
from __future__ import annotations

import copy

import pytest

from test_release_withheld_v2 import LIFECYCLE, release_fixture
from v2_harness import BACKGROUND, keys

from ratify_protocol_v2 import _native
from ratify_protocol_v2.challenge_claim_v2 import protocol_claim_id_from_digest_v2
from ratify_protocol_v2.clock_bounds_v2 import V2_MAX_TIMESTAMP_SECONDS
from ratify_protocol_v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol_v2.evaluation_progress_v2 import (
    V2CommittedClaim,
    initial_v2_evaluation_progress,
    resume_committed_claim_v2,
    v2_evaluation_interrupted_result,
)
from ratify_protocol_v2.release_v2 import V2_RELEASE_RELEASED, release_v2_decision
from ratify_protocol_v2.v2reference.store import Store

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")


class StoreFailure(BaseException):
    """Not an Exception: the Python counterpart of a Go panic."""


class CommittedRecordStore:
    """The reference store answering load_v2_committed_claim through
    ``edit``, so a test can stand in for a claim store that returns a damaged
    record."""

    def __init__(self, inner: Store, edit):
        self.inner, self.edit = inner, edit

    def load_v2_committed_claim(self, ctx, claim_id):
        record = self.inner.load_v2_committed_claim(ctx, claim_id)
        return self.edit(record) or record

    def __getattr__(self, name):
        return getattr(self.inner, name)


def test_resume_returns_the_committed_handoff():
    # SPEC-v2 §7.11: a service whose handoff died after the terminal commit
    # resumes it from the store, and the resumed handoff is the committed
    # one: release answers it exactly as the original.
    store, committed, wire, config = release_fixture()
    resumed = resume_committed_claim_v2(BACKGROUND, store, committed.claim_id())
    horizon, ok = committed.allow_horizon()
    assert ok
    assert resumed.claim_id() == committed.claim_id()
    assert resumed.receipt_body() == committed.receipt_body()
    assert resumed.challenge_expires_at() == committed.challenge_expires_at()
    assert resumed.allow_horizon() == (horizon, ok)
    result = release_v2_decision(BACKGROUND, resumed, wire, config)
    assert result.status == V2_RELEASE_RELEASED and result.decision is not None and result.decision.decision() == "allow"
    again = release_v2_decision(BACKGROUND, committed, wire, config)
    assert again.status == V2_RELEASE_RELEASED, "release of the original handoff after resumption is idempotent"


def _class_of(run):
    with pytest.raises(Exception) as raised:
        run()
    return error_class_of(raised.value)


def test_resume_refuses_a_claim_with_no_committed_record():
    # The store's answers for a claim with no committed record pass through
    # with their class; resumption commits nothing.
    store, committed, _, _ = release_fixture()
    assert _class_of(lambda: resume_committed_claim_v2(BACKGROUND, store, "unknown-claim")) == V2ErrorClass.CLAIM_NOT_FOUND
    record = store.load_v2_committed_claim(BACKGROUND, committed.claim_id())
    lease = 30
    evaluating = Store(store.now(), lease, "ab" * 16, keys().priv(LIFECYCLE["verifier_key"]))
    evaluating.claim_v2(BACKGROUND, record.claim)
    claim_id = record.claim.claim_id
    assert _class_of(lambda: resume_committed_claim_v2(BACKGROUND, evaluating, claim_id)) == V2ErrorClass.CLAIM_LEASE_LIVE
    evaluating.set_time(evaluating.now() + lease)
    assert _class_of(lambda: resume_committed_claim_v2(BACKGROUND, evaluating, claim_id)) == V2ErrorClass.CLAIM_LEASE_LOST
    assert not evaluating.load_v2_terminal_claim(BACKGROUND, claim_id).terminal, "resumption committed a result"
    assert _class_of(lambda: resume_committed_claim_v2(BACKGROUND, None, committed.claim_id())) == V2ErrorClass.CONFIGURATION_INVALID
    assert _class_of(lambda: resume_committed_claim_v2(BACKGROUND, store, "")) == V2ErrorClass.CONFIGURATION_INVALID


def _interrupted_terminal(r: V2CommittedClaim):
    r.terminal_result, r.receipt_body = v2_evaluation_interrupted_result(r.claim, r.claim.issued_at,
                                                                         initial_v2_evaluation_progress())


def _set(attr, value):
    def edit(r):
        setattr(r, attr, value)
    return edit


def _claim_set(attr, value):
    def edit(r):
        setattr(r.claim, attr, value(r.claim) if callable(value) else value)
    return edit


def _different_claim(r: V2CommittedClaim):
    r.claim.replay_epoch += 1
    digest = bytes.fromhex(r.claim.challenge_digest.removeprefix("sha384:"))
    r.claim.claim_id = protocol_claim_id_from_digest_v2(r.claim.namespace, r.claim.replay_epoch, digest)


def _raise(exc_type):
    def edit(_r):
        raise exc_type("disk read failed")
    return edit


# Resumption applies the terminal compare-and-set's checks to the record the
# store returns (§7.3, §7.5, §6.8). A record that fails one is the store's
# failure, never a handoff, so no damaged record can reach release.
DAMAGED = {
    "record for another claim": _claim_set("claim_id", lambda c: "0" * len(c.claim_id)),
    "well-formed record of a different claim": _different_claim,
    "claim ID not derived from the replay key": _claim_set("replay_epoch", lambda c: c.replay_epoch + 1),
    "challenge digest not a sha384 digest": _claim_set("challenge_digest", lambda c: c.challenge_digest.upper()),
    "body for another agent": _claim_set("agent_id", lambda c: c.agent_id + "x"),
    "terminal result differs from the body":
        lambda r: setattr(r, "terminal_result", r.terminal_result.replace(b'"allow"', b'"deny"', 1)),
    "allow with no horizon": _set("allow_horizon", 0),
    "allow horizon outside the timestamp domain": _set("allow_horizon", V2_MAX_TIMESTAMP_SECONDS + 1),
    "interrupted result with an allow horizon": _interrupted_terminal,
    "store failure without a class": _raise(RuntimeError),
    "store panics": _raise(StoreFailure),
    # Python only: what Go's static types already exclude.
    "allow horizon of the wrong type": _set("allow_horizon", True),
    "record of the wrong type": lambda r: copy.copy(r.claim),
}


@pytest.mark.parametrize("edit", DAMAGED.values(), ids=DAMAGED.keys())
def test_resume_refuses_a_record_that_fails_its_checks(edit):
    base, committed, _, _ = release_fixture()
    store = CommittedRecordStore(base, edit)
    with pytest.raises(BaseException) as raised:
        resume_committed_claim_v2(BACKGROUND, store, committed.claim_id())
    assert error_class_of(raised.value) == V2ErrorClass.CLAIM_STORE_UNAVAILABLE, repr(raised.value)


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
def test_resume_store_cancellation_propagates(exc_type):
    # The caller's own cancellation is not a store failure.
    base, committed, _, _ = release_fixture()
    with pytest.raises(exc_type):
        resume_committed_claim_v2(BACKGROUND, CommittedRecordStore(base, _raise(exc_type)), committed.claim_id())


def test_resume_accepts_a_valid_interrupted_record():
    # The interrupted result itself, with no horizon, is a valid record.
    base, committed, _, _ = release_fixture()

    def edit(r):
        _interrupted_terminal(r)
        r.allow_horizon = 0

    resumed = resume_committed_claim_v2(BACKGROUND, CommittedRecordStore(base, edit), committed.claim_id())
    assert resumed.allow_horizon() == (0, False)
