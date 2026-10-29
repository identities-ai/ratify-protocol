"""Concurrency against the reference Part B store: one creator per claim,
one stream advance per sequence, one terminal commit per claim, one use of
an evaluator capability, and an identical verification raced from many
threads commits exactly once."""
from __future__ import annotations

import copy
import threading

from corpus import b64, load
from v2_harness import BACKGROUND, Counts, build_verify_request, keyed_claim, keys

from ratify_protocol.v2.authorization_v2 import V2LocalAuthorizationOptions, evaluate_proof_bundle_v2_local_authorization
from ratify_protocol.v2.claim_store_v2 import (
    V2_CLAIM_CREATED,
    V2ChallengeClaim,
    claim_proof_bundle_v2,
    finalize_claim_proof_bundle_v2,
)
from ratify_protocol.v2.errors_v2 import V2Error, V2ErrorClass, error_class_of
from ratify_protocol.v2.evaluation_progress_v2 import initial_v2_evaluation_progress
from ratify_protocol.v2.protocol_v2 import decode_proof_bundle_v2
from ratify_protocol.v2.rate_reservation_v2 import V2RateLimitExceededError
from ratify_protocol.v2.v2reference.store import Store
from ratify_protocol.v2.verification_receipt_v2 import VerificationReceiptV2, verification_receipt_v2_body
from ratify_protocol.v2.verify_v2 import _build_v2_terminal_result, _V2EvaluationProgress, verify_proof_bundle_v2
from ratify_protocol.v2.verify_v2_preflight import preflight_proof_bundle_v2

import pytest  # noqa: E402
from ratify_protocol.v2 import _native  # noqa: E402

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="the reference store signs receipts; signing needs ratify-protocol-native-v2")

LIFECYCLE = load("lifecycle-scenarios.json")
THREADS = 16
START = 1800000000


def _race(n, fn):
    barrier = threading.Barrier(n)
    results = [None] * n

    def run(i):
        barrier.wait()
        try:
            results[i] = ("ok", fn(i))
        except Exception as exc:  # noqa: BLE001
            results[i] = ("err", exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _store():
    return Store(START, LIFECYCLE["lease_seconds"], LIFECYCLE["log_id"], keys().priv("verifier"))


def _claim(claim_id: str, stream_seq=None, stream_id=None) -> V2ChallengeClaim:
    return keyed_claim(V2ChallengeClaim(claim_id="", namespace="verify-test", replay_epoch=3, challenge_digest="", proof_digest="p",
                            bundle_hash="b", issuer_ids=[], required_scope="data:read", verifier_id="v", agent_id="a" * 64,
                            issued_at=START - 10, expires_at=START + 290, max_age_seconds=300, clock_skew_seconds=5,
                            stream_id=stream_id, stream_seq=stream_seq), claim_id)


def test_identical_claims_create_exactly_once():
    store = _store()
    results = _race(THREADS, lambda i: store.claim_v2(BACKGROUND, _claim("same")))
    dispositions = [r[1].disposition for r in results if r[0] == "ok"]
    assert all(r[0] == "ok" for r in results)
    assert dispositions.count(V2_CLAIM_CREATED) == 1
    assert sum(1 for r in results if r[1].owner_token) == 1


def test_stream_sequence_advances_once_per_sequence():
    store = _store()
    stream = bytes(range(32))
    results = _race(THREADS, lambda i: store.claim_v2(BACKGROUND, _claim(f"c{i}", stream_seq=1, stream_id=stream)))
    created = [r for r in results if r[0] == "ok"]
    rejected = [r for r in results if r[0] == "err"]
    assert len(created) == 1
    assert all(error_class_of(r[1]) == V2ErrorClass.STREAM_SEQUENCE_MISMATCH for r in rejected)
    # The next sequence is again won by exactly one claimant.
    results = _race(THREADS, lambda i: store.claim_v2(BACKGROUND, _claim(f"d{i}", stream_seq=2, stream_id=stream)))
    assert sum(1 for r in results if r[0] == "ok") == 1


def _bound_claim(claim_id: str) -> V2ChallengeClaim:
    # A claim whose sealed members a receipt body can carry (SPEC-v2 §7.5).
    claim = _claim(claim_id)
    claim.verifier_id, claim.agent_id = "1" * 64, "2" * 64
    claim.bundle_hash = claim.proof_digest = "sha384:" + "3" * 96
    claim.issuer_ids = ["4" * 64]
    return claim


_UNAUTHORIZED_TERMINAL = b'{"decision":"deny","decision_reason":"unauthorized","identity_status":"unauthorized"}'


def _unauthorized_body(claim: V2ChallengeClaim, verified_at: int = START) -> bytes:
    """The receipt outbox body of an unauthorized deny bound to ``claim``."""
    return verification_receipt_v2_body(VerificationReceiptV2(
        version=2, verifier_id=claim.verifier_id, agent_id=claim.agent_id, bundle_hash=claim.bundle_hash,
        issuer_ids=list(claim.issuer_ids), decision="deny", decision_reason="unauthorized",
        identity_status="unauthorized", trust_assessment="untrusted", status_assessment="not_evaluated",
        challenge_assessment="current", context_assessment="not_evaluated", context_policy_digest=None,
        verified_at=verified_at, required_scope=claim.required_scope, granted_scope=[], status_evidence=[],
    ))


def test_identical_finalization_commits_once():
    store = _store()
    claim = _bound_claim("fin")
    created = store.claim_v2(BACKGROUND, claim)
    terminal = _UNAUTHORIZED_TERMINAL
    body = _unauthorized_body(claim)
    results = _race(THREADS, lambda i: store.finalize_v2_claim(BACKGROUND, claim.claim_id, created.owner_token, terminal, body, 0))
    assert all(r[0] == "ok" for r in results)
    assert [r[1] for r in results].count(True) == 1
    assert store.log_length() == 0 and len(store._outbox) == 1


def test_competing_finalizations_one_wins():
    store = _store()
    claim = _bound_claim("compete")
    created = store.claim_v2(BACKGROUND, claim)

    def finalize(i):
        # Every payload binds the sealed claim; they differ in verified_at.
        body = _unauthorized_body(claim, START + i)
        return store.finalize_v2_claim(BACKGROUND, claim.claim_id, created.owner_token, _UNAUTHORIZED_TERMINAL, body, 0)

    results = _race(THREADS, finalize)
    winners = [r for r in results if r[0] == "ok" and r[1] is True]
    losers = [r for r in results if r[0] == "err"]
    assert len(winners) == 1 and len(losers) == THREADS - 1
    assert all(error_class_of(r[1]) == V2ErrorClass.CLAIM_ALREADY_TERMINAL for r in losers)


def test_claim_already_terminal_error_exposes_no_store_state():
    # SPEC-v2 §7.3: a committed claim is immutable. A late finalize or
    # progress write fails with claim_already_terminal, and nothing reachable
    # from that error (its cause, context or attributes) is the store's record.
    from ratify_protocol.v2.evaluation_progress_v2 import initial_v2_evaluation_progress

    store = _store()
    claim = _bound_claim("late")
    created = store.claim_v2(BACKGROUND, claim)
    assert store.finalize_v2_claim(BACKGROUND, claim.claim_id, created.owner_token, _UNAUTHORIZED_TERMINAL, _unauthorized_body(claim), 0)
    record = store._claims[claim.claim_id]
    calls = [
        lambda: store.finalize_v2_claim(BACKGROUND, claim.claim_id, created.owner_token, _UNAUTHORIZED_TERMINAL,
                                        _unauthorized_body(claim, START + 1), 0),
        lambda: store.record_v2_evaluation_progress(BACKGROUND, claim.claim_id, created.owner_token,
                                                    initial_v2_evaluation_progress()),
    ]
    for call in calls:
        with pytest.raises(Exception) as err:
            call()
        assert error_class_of(err.value) == V2ErrorClass.CLAIM_ALREADY_TERMINAL
        seen, todo = set(), [err.value]
        while todo:
            e = todo.pop()
            if e is None or id(e) in seen:
                continue
            seen.add(id(e))
            assert all(v is not record for v in vars(e).values())
            todo += [e.__cause__, e.__context__]
        assert err.value.__context__ is None and err.value.__cause__ is None


def _request(name="A"):
    request = copy.deepcopy(LIFECYCLE["requests"][name])
    request["now"] = START
    return request


def test_evaluator_capability_is_single_use_under_races():
    store = _store()
    request = _request()
    bundle = decode_proof_bundle_v2(b64(LIFECYCLE["bundles_b64"][request["bundle"]]))
    req, _, _ = build_verify_request(request, None, Counts())
    pre = preflight_proof_bundle_v2(bundle, req.expected, req.context_policy, req.required_scope, req.verifier_namespace,
                                    req.replay_epoch, req.verifier_id, START, req.max_challenge_age_seconds, req.future_skew_seconds)
    _, disposition, token = claim_proof_bundle_v2(BACKGROUND, store, bundle, pre, req.verifier_namespace, req.replay_epoch, START)
    assert disposition == V2_CLAIM_CREATED
    opts = V2LocalAuthorizationOptions(future_skew_seconds=req.future_skew_seconds, required_scope=req.required_scope,
                                       context=req.context, tzdb_version=req.tzdb_version, context_policy=req.context_policy,
                                       claim_token=token, trust_configured=False)
    results = _race(THREADS, lambda i: evaluate_proof_bundle_v2_local_authorization(bundle, opts))
    reasons = [r[1].reason for r in results]
    assert reasons.count("claim_in_progress") == THREADS - 1
    assert sum(1 for reason in reasons if reason != "claim_in_progress") == 1


def test_finalization_rate_exhaustion_is_claim_store_unavailable():
    # Go FinalizeClaimProofBundleV2 classifies a store's rate exhaustion as
    # claim_store_unavailable while errors.Is still finds the sentinel; every
    # SDK reports that one SPEC-v2 §2.7 class for this refusal.
    class Exhausted(Store):
        def finalize_v2_claim(self, *args):
            raise V2RateLimitExceededError()

    store = Exhausted(START, LIFECYCLE["lease_seconds"], LIFECYCLE["log_id"], keys().priv("verifier"))
    request = _request()
    bundle = decode_proof_bundle_v2(b64(LIFECYCLE["bundles_b64"][request["bundle"]]))
    req, _, _ = build_verify_request(request, None, Counts())
    pre = preflight_proof_bundle_v2(bundle, req.expected, req.context_policy, req.required_scope, req.verifier_namespace,
                                    req.replay_epoch, req.verifier_id, START, req.max_challenge_age_seconds, req.future_skew_seconds)
    claim, _, token = claim_proof_bundle_v2(BACKGROUND, store, bundle, pre, req.verifier_namespace, req.replay_epoch, START)
    opts = V2LocalAuthorizationOptions(future_skew_seconds=req.future_skew_seconds, required_scope=req.required_scope,
                                       context=req.context, tzdb_version=req.tzdb_version, context_policy=req.context_policy,
                                       claim_token=token, trust_configured=False)
    assessment = evaluate_proof_bundle_v2_local_authorization(bundle, opts)
    assert assessment.reason == "trust_unavailable"
    progress = initial_v2_evaluation_progress()
    progress.trust_assessment = "unavailable"
    _, terminal, body = _build_v2_terminal_result(bundle, assessment, _V2EvaluationProgress(persisted=progress), claim, START)
    with pytest.raises(V2RateLimitExceededError) as raised:
        finalize_claim_proof_bundle_v2(BACKGROUND, store, token, terminal, body)
    assert error_class_of(raised.value) == V2ErrorClass.CLAIM_STORE_UNAVAILABLE


def test_racing_identical_verifications_commit_once():
    store = _store()
    request = _request()
    bundle = b64(LIFECYCLE["bundles_b64"][request["bundle"]])

    def verify(i):
        req, cb, _ = build_verify_request(request, bundle, Counts())
        cb.claim_store = store
        return verify_proof_bundle_v2(BACKGROUND, req, cb)

    results = _race(8, verify)
    assert all(r[0] == "ok" for r in results)
    stages = sorted(r[1].stage for r in results)
    assert stages.count("committed") == 1
    assert all(stage in ("committed", "replay") for stage in stages)
    assert len(store._outbox) == 1


def test_claim_id_not_derived_from_its_replay_key_is_refused():
    # SPEC-v2 §7.3: the store is unique by (namespace, replay_epoch,
    # ChallengeClaimDigest), so no caller can open a second claim for one
    # challenge by choosing another ID.
    store = _store()
    claim = _claim("key")
    with pytest.raises(V2Error) as err:
        store.claim_v2(BACKGROUND, _with_id(claim, "f" * 64))
    assert err.value.error_class == V2ErrorClass.CONFIGURATION_INVALID
    assert store.claim_v2(BACKGROUND, claim).disposition == V2_CLAIM_CREATED
    race = _claim("race")
    results = _race(128, lambda i: store.claim_v2(BACKGROUND, _with_id(race, f"{i:064x}") if i % 2 else race))
    created = sum(1 for r in results if r[0] == "ok" and r[1].disposition == V2_CLAIM_CREATED)
    refused = sum(1 for r in results if r[0] == "err" and error_class_of(r[1]) == V2ErrorClass.CONFIGURATION_INVALID)
    assert (created, refused) == (1, 64)


def _with_id(claim: V2ChallengeClaim, claim_id: str) -> V2ChallengeClaim:
    import dataclasses
    return dataclasses.replace(claim, claim_id=claim_id)
