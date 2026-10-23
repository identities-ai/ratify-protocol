"""Store containment: a claim store, rate store or SecurityJournalV2 store
that raises any BaseException is handled exactly as one that raises an
Exception, as Go recovers a store panic (claimV2Safely,
recordV2ProgressSafely, finalizeV2Safely, v2SafeRateStore,
callV2JournalSafely, loadV2InterruptedSafely, recoverV2Safely,
loadV2TerminalClaimSafely, recordV2ReleaseSafely, readV2AuthoritativeTime).
KeyboardInterrupt and SystemExit are the caller's own cancellation and
propagate."""
from __future__ import annotations

import pytest

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, ScriptedClaimStore, build_verify_request

from ratify_protocol_v2 import _native
from ratify_protocol_v2 import evaluation_progress_v2 as ep
from ratify_protocol_v2.claim_store_v2 import V2ChallengeClaim
from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.release_v2 import release_v2_decision
from ratify_protocol_v2.verification_receipt_v2 import decode_verification_receipt_body_v2
from ratify_protocol_v2.verify_v2 import verify_proof_bundle_v2

ORDERING = load("verifier-ordering.json")


class StoreFailure(BaseException):
    """Not an Exception: the Python counterpart of a Go panic that ordinary
    ``except Exception`` would let escape."""


# An ordinary Exception, the store failure every adapter already contains.
# Each BaseException must be classified the same way.
FAILURES = [RuntimeError, StoreFailure]
CANCELLATIONS = [KeyboardInterrupt, SystemExit]


class Failing:
    """Delegates to ``inner`` except that ``method`` raises ``exc_type``."""

    def __init__(self, inner, method: str, exc_type):
        self._inner, self._method, self._exc_type = inner, method, exc_type

    def __getattr__(self, name):
        if name == self._method:
            def fail(*args, **kwargs):
                raise self._exc_type(f"scripted {name} failure")
            return fail
        return getattr(self._inner, name)


def _vector(name: str) -> dict:
    return next(v for v in ORDERING["vectors"] if v["name"] == name)


def _verify(vector: str, component: str, method: str, exc_type):
    v = _vector(vector)
    counts = Counts()
    req, cb, _ = build_verify_request(v, b64(ORDERING["bundles_b64"][v["bundle"]]), counts)
    claimed_at = v["now"] + v.get("claim_time_offset", 0)
    cb.claim_store = ScriptedClaimStore("create", claimed_at, claimed_at + v.get("finalize_time_offset", 0), counts)
    setattr(cb, component, Failing(getattr(cb, component), method, exc_type))
    outcome = verify_proof_bundle_v2(BACKGROUND, req, cb)
    result = (outcome.stage, outcome.error_class)
    if outcome.committed is not None:
        body = decode_verification_receipt_body_v2(outcome.committed.receipt_body())
        result += (body.decision, body.decision_reason, body.status_assessment)
    return result


# (vector, callback attribute, failing method, expected outcome).
VERIFY_SITES = {
    "claim": ("claim_store_unavailable", "claim_store", "claim_v2", ("preflight", "claim_store_unavailable")),
    "progress": ("rate_store_panic", "claim_store", "record_v2_evaluation_progress",
                 ("evaluating", "claim_store_unavailable")),
    "finalize": ("rate_store_panic", "claim_store", "finalize_v2_claim", ("evaluating", "claim_store_unavailable")),
    "rate": ("rate_store_panic", "rate", "reserve_v2_rate_batch",
             ("committed", "", "deny", "constraint_unverifiable", "current")),
    "journal_load": ("status_journal_load_error", "status_journal", "load",
                     ("committed", "", "indeterminate", "status_unavailable", "unavailable")),
    "journal_cas": ("status_journal_cas_conflict", "status_journal", "compare_and_swap",
                    ("committed", "", "indeterminate", "status_unavailable", "unavailable")),
}


@pytest.mark.parametrize("exc_type", FAILURES)
@pytest.mark.parametrize("site", VERIFY_SITES)
def test_verify_store_failure_is_contained(site, exc_type):
    vector, component, method, want = VERIFY_SITES[site]
    assert _verify(vector, component, method, exc_type) == want


@pytest.mark.parametrize("exc_type", CANCELLATIONS)
@pytest.mark.parametrize("site", VERIFY_SITES)
def test_verify_store_cancellation_propagates(site, exc_type):
    vector, component, method, _ = VERIFY_SITES[site]
    with pytest.raises(exc_type):
        _verify(vector, component, method, exc_type)


class InterruptedStore:
    """A claim store for lease-expiry recovery whose ``method`` raises."""

    def __init__(self, method: str, exc_type):
        self.method, self.exc_type = method, exc_type

    def load_v2_interrupted_claim(self, ctx, claim_id):
        if self.method == "load_v2_interrupted_claim":
            raise self.exc_type("scripted recovery load failure")
        return ep.V2InterruptedClaim(claim=V2ChallengeClaim(claim_id=claim_id), claimed_at=1)

    def recover_interrupted_v2_claim(self, ctx, claim_id, terminal_result, receipt_body):
        raise self.exc_type("scripted recovery failure")


def _recover(method: str, exc_type, monkeypatch):
    # The recovery body is not under test; only the store calls are.
    monkeypatch.setattr(ep, "v2_evaluation_interrupted_result", lambda claim, claimed_at, progress: (b"{}", b"{}"))
    ep.recover_interrupted_claim_v2(BACKGROUND, InterruptedStore(method, exc_type), "claim")


@pytest.mark.parametrize("exc_type", FAILURES)
@pytest.mark.parametrize("method", ["load_v2_interrupted_claim", "recover_interrupted_v2_claim"])
def test_recovery_store_failure_is_claim_store_unavailable(method, exc_type, monkeypatch):
    with pytest.raises(BaseException) as raised:
        _recover(method, exc_type, monkeypatch)
    assert error_class_of(raised.value) == "claim_store_unavailable"


@pytest.mark.parametrize("exc_type", CANCELLATIONS)
@pytest.mark.parametrize("method", ["load_v2_interrupted_claim", "recover_interrupted_v2_claim"])
def test_recovery_store_cancellation_propagates(method, exc_type, monkeypatch):
    with pytest.raises(exc_type):
        _recover(method, exc_type, monkeypatch)


needs_native = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

# (failing claim-store method, expected release result). A failed record of
# a release leaves the call pending.
RELEASE_SITES = {
    "load_v2_terminal_claim": ("pending", "claim_store_unavailable"),
    "record_v2_release": ("pending", "claim_store_unavailable"),
    "authoritative_time_v2": ("pending", "clock_unavailable"),
}


def _release(method: str, exc_type):
    from test_release_withheld_v2 import release_fixture

    store, committed, wire, config = release_fixture()
    config.claim_store = Failing(store, method, exc_type)
    result = release_v2_decision(BACKGROUND, committed, wire, config)
    return result.status, result.reason


@needs_native
@pytest.mark.parametrize("exc_type", FAILURES)
@pytest.mark.parametrize("method", RELEASE_SITES)
def test_release_store_failure_is_contained(method, exc_type):
    assert _release(method, exc_type) == RELEASE_SITES[method]


@needs_native
@pytest.mark.parametrize("exc_type", CANCELLATIONS)
@pytest.mark.parametrize("method", RELEASE_SITES)
def test_release_store_cancellation_propagates(method, exc_type):
    with pytest.raises(exc_type):
        _release(method, exc_type)
