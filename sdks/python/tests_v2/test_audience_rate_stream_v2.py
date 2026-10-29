"""Receiver audience, max_rate batches, context policy, stream sequence, and
the evaluator registry: ported from Go audience_v2_test.go,
rate_reservation_v2_test.go, context_policy_v2_test.go, and the stream and
evaluator rules of SPEC-v2 §5.2, §6.8 and §7.4."""
from __future__ import annotations

import dataclasses
import threading
import time

import pytest

from ratify_protocol.v2 import constraint_evaluator_v2 as ce
from ratify_protocol.v2.audience_v2 import V2AudienceMembership, evaluate_receiver_audience_v2
from ratify_protocol.v2.constraints_v2 import ConstraintContextV2, ConstraintDeniedError, ConstraintUnverifiableError, ConstraintV2
from ratify_protocol.v2.context_policy_v2 import (
    VERIFY_SESSION_CONTEXT_FIELDS_V2,
    VERIFY_SESSION_CONTEXT_PROFILE_V2,
    V2ContextPolicy,
    V2DeferredConstraint,
    clone_v2_context_policy,
    evaluate_proof_bundle_v2_context_policy,
    new_v2_context_policy,
    same_v2_context_policy,
)
from ratify_protocol.v2.errors_v2 import V2Error, V2ErrorClass, error_class_of
from ratify_protocol.v2.rate_reservation_v2 import (
    V2RateLimitExceededError,
    V2RateReservation,
    build_v2_rate_reservation_batch,
    encode_constraint_canonical_v2 as encode_constraint_v2,
)
from ratify_protocol.v2.stream_sequence_v2 import check_v2_stream_sequence

DIGEST_A = "sha384:" + "a" * 96
DIGEST_B = "sha384:" + "b" * 96


def audience(exact, domains, age, delegation_index=0, constraint_index=0) -> V2DeferredConstraint:
    params = {"exact_receiver_ids": list(exact or []), "trust_domain_ids": list(domains)}
    if domains:
        params["max_membership_age_seconds"] = age
    encoded = encode_constraint_v2(ConstraintV2(type="ratify.receiver_audience", params=params))
    return V2DeferredConstraint(delegation_index=delegation_index, constraint_index=constraint_index, issuer_id="",
                                cert_id="", type="ratify.receiver_audience", canonical_json=encoded)


# --- audience ----------------------------------------------------------------


def test_audience_intersects_links_and_uses_minimum_age():
    first = audience([], ["domain-a"], 300)
    second = audience([], ["domain-b"], 30, delegation_index=1)
    memberships = [
        # Exclusive age deadline: issued 71 with minimum age 30 is current at
        # 100 (100 < 101); issued 70 reaches the deadline exactly.
        V2AudienceMembership(receiver_id="receiver-1", trust_domain_ids=("domain-a",), issued_at=71, expires_at=200, evidence_digest=DIGEST_A),
        V2AudienceMembership(delegation_index=1, receiver_id="receiver-1", trust_domain_ids=("domain-b",), issued_at=80, expires_at=200, evidence_digest=DIGEST_B),
    ]
    got = evaluate_receiver_audience_v2([first, second], "receiver-1", memberships, 100, 0)
    assert got.status == "passed" and got.evidence_digests == [DIGEST_A, DIGEST_B]
    assert got.fresh_until == 101
    memberships[0] = dataclasses.replace(memberships[0], issued_at=70)
    got = evaluate_receiver_audience_v2([first, second], "receiver-1", memberships, 100, 0)
    assert got.status == "constraint_unverifiable"


def test_audience_denial_beats_unavailable_in_either_order():
    unavailable = audience([], ["domain-a"], 30)
    denied = audience([], ["domain-b"], 30, delegation_index=1)
    membership = V2AudienceMembership(delegation_index=1, receiver_id="receiver-1", trust_domain_ids=("domain-c",),
                                      issued_at=90, expires_at=110, evidence_digest=DIGEST_A)
    for links in ([unavailable, denied], [denied, unavailable]):
        assert evaluate_receiver_audience_v2(links, "receiver-1", [membership], 100, 0).status == "constraint_denied"


@pytest.mark.parametrize("edit", [
    dict(receiver_id="receiver-2"), dict(expires_at=100), dict(issued_at=69), dict(issued_at=102), dict(evidence_digest=""),
], ids=["wrong receiver", "expired", "stale", "future", "missing digest"])
def test_audience_rejects_unbound_or_stale_evidence(edit):
    constraint = audience(["receiver-2"], ["domain-a"], 30)
    base = V2AudienceMembership(receiver_id="receiver-1", trust_domain_ids=("domain-a",), issued_at=90, expires_at=110, evidence_digest=DIGEST_A)
    for domains in (("domain-a",), ("domain-z",)):
        membership = dataclasses.replace(base, trust_domain_ids=domains, **edit)
        assert evaluate_receiver_audience_v2([constraint], "receiver-1", [membership], 100, 0).status == "constraint_unverifiable"
    assert evaluate_receiver_audience_v2([constraint], "receiver-1", [base], 100, 0).status == "passed"


def test_audience_rejects_ambiguous_or_mutated_inputs():
    constraint = audience(None, ["domain-a"], 30)
    valid = V2AudienceMembership(receiver_id="receiver-1", trust_domain_ids=("domain-a",), issued_at=90, expires_at=110, evidence_digest=DIGEST_A)
    duplicated = dataclasses.replace(valid, trust_domain_ids=("domain-a", "domain-a"))
    for memberships in ([valid, valid], [duplicated]):
        assert evaluate_receiver_audience_v2([constraint], "receiver-1", memberships, 100, 0).status == "constraint_unverifiable"
    with pytest.raises(ValueError):
        evaluate_receiver_audience_v2([constraint, constraint], "receiver-1", [valid], 100, 0)
    case_variant = dataclasses.replace(
        constraint, canonical_json=constraint.canonical_json.replace(b"max_membership_age_seconds", b"MAX_MEMBERSHIP_AGE_SECONDS", 1))
    with pytest.raises(ValueError):
        evaluate_receiver_audience_v2([case_variant], "receiver-1", [valid], 100, 0)
    wrong_position = dataclasses.replace(valid, constraint_index=1)
    assert evaluate_receiver_audience_v2([constraint], "receiver-1", [wrong_position], 100, 0).status == "constraint_unverifiable"


def test_audience_exact_match_needs_no_membership():
    constraint = audience(["receiver-1"], ["domain-a"], 30)
    assert evaluate_receiver_audience_v2([constraint], "receiver-1", None, 100, 0).status == "passed"
    invalid = audience(["receiver-2"], [], 0)
    with pytest.raises(ValueError):
        evaluate_receiver_audience_v2([invalid], "receiver-1", None, 100, 0)
    invalid = dataclasses.replace(invalid, canonical_json=invalid.canonical_json.replace(b'receiver-2', b'receiver-2","extra":1', 1))
    with pytest.raises(ValueError):
        evaluate_receiver_audience_v2([invalid], "receiver-1", None, 100, 0)


def test_audience_rejects_invalid_security_time_and_bool_integers():
    constraint = audience(["receiver-1"], [], 0)
    for now, skew in ((-1, 0), (100, -1), (100, 301), (True, 0), (100, False)):
        with pytest.raises(ValueError):
            evaluate_receiver_audience_v2([constraint], "receiver-1", None, now, skew)
    with pytest.raises(ValueError):
        evaluate_receiver_audience_v2([constraint], "", None, 100, 0)


# --- max_rate batches ----------------------------------------------------------


def rate(issuer, cert, index, count, window, delegation_index=0) -> V2DeferredConstraint:
    encoded = encode_constraint_v2(ConstraintV2(type="max_rate", count=count, window_s=window))
    return V2DeferredConstraint(delegation_index=delegation_index, constraint_index=index, issuer_id=issuer,
                                cert_id=cert, type="max_rate", canonical_json=encoded)


def test_rate_batch_groups_signed_limits_without_issuer_collision():
    a, b = "a" * 64, "b" * 64
    deferred = [rate(b, "shared-cert", 0, 7, 60, delegation_index=1), rate(a, "shared-cert", 0, 5, 60),
                rate(a, "shared-cert", 1, 2, 60), rate(a, "shared-cert", 2, 3, 120)]
    want = [V2RateReservation(a, "shared-cert", 60, 2), V2RateReservation(a, "shared-cert", 120, 3),
            V2RateReservation(b, "shared-cert", 60, 7)]
    assert build_v2_rate_reservation_batch(deferred) == want
    assert build_v2_rate_reservation_batch(list(reversed(deferred))) == want


def test_rate_batch_rejects_malformed_or_duplicated_signed_constraints():
    issuer = "a" * 64
    valid = rate(issuer, "cert", 0, 2, 60)
    bad = [
        dataclasses.replace(valid, canonical_json=b'{"count":0,"type":"max_rate","window_s":60}'),
        dataclasses.replace(valid, canonical_json=b'{"count":2,"type":"max_rate","window_s":0}'),
        dataclasses.replace(valid, canonical_json=b'{"count":2,"type":"max_rate","window_s":86401}'),
        dataclasses.replace(valid, issuer_id="a" * 32),
        dataclasses.replace(valid, cert_id=""),
        dataclasses.replace(valid, cert_id="x" * 513),
        dataclasses.replace(valid, canonical_json=b'{"COUNT":2,"type":"max_rate","window_s":60}'),
        dataclasses.replace(valid, type="ratify.receiver_audience"),
        dataclasses.replace(valid, type="", canonical_json=b'{"type":""}'),
        dataclasses.replace(valid, delegation_index=True),
    ]
    for item in bad:
        with pytest.raises(ValueError):
            build_v2_rate_reservation_batch([item])
    with pytest.raises(ValueError):
        build_v2_rate_reservation_batch([valid, valid])


def test_rate_limit_sentinel_is_unclassified():
    assert error_class_of(V2RateLimitExceededError()) == V2ErrorClass.UNCLASSIFIED


# --- context policy ------------------------------------------------------------


class _Bundle:
    def __init__(self, session_context=None):
        self.session_context = session_context


def test_context_policy_digest_and_outcomes():
    unbound = new_v2_context_policy("ratify.test.context/v1", False, None, None)
    want, other = bytes([0x51]) * 32, bytes([0x52]) * 32
    bound = new_v2_context_policy(VERIFY_SESSION_CONTEXT_PROFILE_V2, True, list(VERIFY_SESSION_CONTEXT_FIELDS_V2), want)
    # Go testV2ContextPolicyDigest: the Verify session-context policy digest,
    # which excludes the per-invocation expected context.
    assert bound.digest == (
        "sha384:610c40faa472aa2a4f905988899733758cccf30f243aed35f1f42433228a28dbab1725cb2a4a6811029a8109da0b9b29")
    mismatch = new_v2_context_policy("ratify.test.session-context/v1", True, ["session"], other)
    cases = [
        (_Bundle(), None, "authorization_unverified", "unbound", False),
        (_Bundle(want), None, "authorization_unverified", "unverified", False),
        (_Bundle(), unbound, "passed", "not_required", True),
        (_Bundle(want), bound, "passed", "bound", True),
        (_Bundle(want), mismatch, "constraint_denied", "mismatch", True),
        (_Bundle(None), bound, "authorization_unverified", "unverified", True),
    ]
    for bundle, policy, status, assessment, has_digest in cases:
        got = evaluate_proof_bundle_v2_context_policy(bundle, policy)
        assert (got.status, got.assessment, got.policy_digest is not None) == (status, assessment, has_digest)
        if got.status == "constraint_denied":
            assert got.reason == "constraint_denied"


def test_unvalidated_context_policy_cannot_pass():
    valid = new_v2_context_policy("ratify.test.context/v1", False, None, None)
    forged = clone_v2_context_policy(valid)
    forged._valid = False
    got = evaluate_proof_bundle_v2_context_policy(_Bundle(), forged)
    assert (got.status, got.reason, got.assessment, got.policy_digest) == (
        "authorization_unverified", "action_context_unverified", "unbound", None)
    assert not same_v2_context_policy(forged, valid)
    assert same_v2_context_policy(valid, clone_v2_context_policy(valid))
    assert not V2ContextPolicy()._valid
    direct = V2ContextPolicy(profile="x", digest=valid.digest)
    assert evaluate_proof_bundle_v2_context_policy(_Bundle(), direct).status == "authorization_unverified"


@pytest.mark.parametrize("args", [
    ("", False, None, None),
    ("p", False, ["a", "a"], None),
    ("p", False, [""], None),
    ("p", True, [], bytes(32)),
    ("p", True, ["a"], bytes(31)),
    ("p", False, None, bytes(32)),
    (VERIFY_SESSION_CONTEXT_PROFILE_V2, True, ["verifier_id"], bytes(32)),
    (VERIFY_SESSION_CONTEXT_PROFILE_V2, False, list(VERIFY_SESSION_CONTEXT_FIELDS_V2), None),
])
def test_context_policy_constructor_rejects_invalid_policies(args):
    with pytest.raises((ValueError, TypeError)):
        new_v2_context_policy(*args)


# --- stream sequence -------------------------------------------------------------


@pytest.mark.parametrize("has_last,last,seq,cls", [
    (False, 0, 1, ""),
    (False, 0, 2, V2ErrorClass.STREAM_SEQUENCE_MISMATCH),
    (True, 4, 5, ""),
    (True, 4, 4, V2ErrorClass.STREAM_SEQUENCE_MISMATCH),
    (True, 4, 3, V2ErrorClass.STREAM_SEQUENCE_MISMATCH),
    (True, 4, 6, V2ErrorClass.STREAM_SEQUENCE_MISMATCH),
    (True, 2**53 - 1, 2**53 - 1, V2ErrorClass.STREAM_SEQUENCE_MISMATCH),
    (False, 0, 0, V2ErrorClass.MALFORMED),
    (False, 0, 2**53, V2ErrorClass.MALFORMED),
    (True, 0, 1, V2ErrorClass.MALFORMED),
    (False, 0, True, V2ErrorClass.MALFORMED),
])
def test_stream_sequence_rule(has_last, last, seq, cls):
    try:
        check_v2_stream_sequence(has_last, last, seq)
        err = None
    except V2Error as exc:
        err = exc
    assert error_class_of(err) == cls


# --- evaluator registry ------------------------------------------------------------


def _input(kind, params=None, **ctx):
    return ce.ConstraintEvaluationInputV2(type=kind, params_json=params, delegation_index=0, constraint_index=0,
                                          issuer_id="i", cert_id="c", context=ConstraintContextV2(**ctx), evaluation_time=100)


def _registry(evaluate, timeout=0.2, kind="com.example.custom"):
    descriptor = ce.ConstraintProfileDescriptorV2(profile="com.example.custom/v1", type=kind)
    return ce.new_constraint_evaluator_registry_v2(timeout, ce.ConstraintEvaluatorRegistrationV2(descriptor, evaluate))


def _unverifiable(exc) -> bool:
    return isinstance(exc, ConstraintUnverifiableError)


@pytest.mark.parametrize("timeout", [0, -1, 10.5, True, "1"])
def test_registry_rejects_invalid_timeout(timeout):
    with pytest.raises(V2Error) as exc:
        ce.new_constraint_evaluator_registry_v2(timeout, ce.standard_max_count_evaluator_v2())
    assert exc.value.error_class == V2ErrorClass.CONFIGURATION_INVALID


def test_registry_rejects_bad_registrations():
    good = ce.standard_max_count_evaluator_v2()
    bad_type = ce.ConstraintEvaluatorRegistrationV2(ce.ConstraintProfileDescriptorV2("a.b/v1", "ratify.x.y"), good.evaluate)
    bad_profile = ce.ConstraintEvaluatorRegistrationV2(ce.ConstraintProfileDescriptorV2("a.b/v01", "com.example.x"), good.evaluate)
    no_impl = ce.ConstraintEvaluatorRegistrationV2(good.descriptor, None)
    for regs in ([good, good], [bad_type], [bad_profile], [no_impl], [good] * 33):
        with pytest.raises(V2Error) as exc:
            ce.new_constraint_evaluator_registry_v2(1.0, *regs)
        assert exc.value.error_class == V2ErrorClass.CONFIGURATION_INVALID
    assert not ce.ConstraintEvaluatorRegistryV2()._valid


def test_run_evaluator_maps_outcomes_horizons_and_faults():
    def answer(result):
        return lambda _ctx, _in: result

    def run(evaluate, timeout=0.2):
        registry = _registry(evaluate, timeout)
        return ce.run_constraint_evaluator_v2(registry._entries["com.example.custom"], timeout, _input("com.example.custom"))

    R = ce.ConstraintEvaluationResultV2
    assert run(answer(R("pass"))) == 0
    assert run(answer(R("pass", valid_until=150))) == 150
    assert run(answer(R("pass", valid_until=10**15))) == 253402300799
    for faulty in (R("pass", valid_until=100), R("denied", valid_until=5), R("unverifiable", valid_until=5),
                   R("maybe"), R("pass", valid_until=True), None, "pass"):
        with pytest.raises(Exception) as exc:
            run(answer(faulty))
        assert _unverifiable(exc.value)
    with pytest.raises(Exception) as exc:
        run(answer(R("denied", detail="no")))
    assert isinstance(exc.value, ConstraintDeniedError) and "denied" in str(exc.value)
    with pytest.raises(Exception) as exc:
        run(answer(R("unverifiable")))
    assert _unverifiable(exc.value)

    def boom(_ctx, _in):
        raise RuntimeError("panic")

    with pytest.raises(Exception) as exc:
        run(boom)
    assert _unverifiable(exc.value)

    release = threading.Event()

    def slow(ctx, _in):
        release.wait(5)
        return R("pass")

    started = time.monotonic()
    with pytest.raises(Exception) as exc:
        run(slow, timeout=0.05)
    assert _unverifiable(exc.value) and time.monotonic() - started < 2
    release.set()


def test_evaluator_input_is_a_copy():
    seen = {}

    def mutate(_ctx, in_):
        in_.context.extension_counts["n"] = 99
        seen["counts"] = in_.context.extension_counts
        return ce.ConstraintEvaluationResultV2("pass")

    registry = _registry(mutate)
    in_ = _input("com.example.custom", extension_counts={"n": 1})
    ce.run_constraint_evaluator_v2(registry._entries["com.example.custom"], 0.2, in_)
    assert in_.context.extension_counts == {"n": 1} and seen["counts"]["n"] == 99


def test_snapshot_seals_only_types_present_in_the_chain():
    registry = ce.new_constraint_evaluator_registry_v2(
        1.0, ce.standard_max_count_evaluator_v2(), ce.standard_allowed_values_evaluator_v2())

    class Cert:
        def __init__(self, types):
            self.constraints = [ConstraintV2(type=t, params={}) for t in types]

    class Bundle:
        def __init__(self, *certs):
            self.delegations = list(certs)

    used, refs, timeout = ce.snapshot_constraint_evaluators_v2(registry, Bundle(Cert(["com.ratifyprotocol.max_count", "com.other.x.y"])))
    assert list(used) == ["com.ratifyprotocol.max_count"] and [r.type for r in refs] == ["com.ratifyprotocol.max_count"]
    assert timeout == 1.0 and ce.valid_constraint_evaluator_refs_v2(refs)
    assert ce.snapshot_constraint_evaluators_v2(registry, Bundle(Cert([]))) == (None, None, 0.0)
    assert ce.snapshot_constraint_evaluators_v2(None, Bundle()) == (None, None, 0.0)
