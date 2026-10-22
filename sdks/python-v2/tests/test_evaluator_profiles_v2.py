"""evaluator-profiles.json: the standard extension evaluator profiles.

The profile digest only names the profile; these outcomes are what make two
SDKs' implementations of one standard profile interchangeable (SPEC-v2 §5.2).
"""
from __future__ import annotations

import pytest

from corpus import load
from ratify_protocol_v2 import _v2json
from ratify_protocol_v2 import constraint_evaluator_v2 as ce
from ratify_protocol_v2.constraints_v2 import ConstraintContextV2
from ratify_protocol_v2.context_v2 import background
from ratify_protocol_v2.errors_v2 import error_class_of

VECTORS = load("evaluator-profiles.json")
STANDARD = {
    ce.PROFILE_MAX_COUNT_V2: ce.standard_max_count_evaluator_v2(),
    ce.PROFILE_ALLOWED_VALUES_V2: ce.standard_allowed_values_evaluator_v2(),
}
CASES = [(suite, case) for suite in VECTORS["profiles"] for case in suite["cases"]]


def _context(c: dict) -> ConstraintContextV2:
    return ConstraintContextV2(
        extension_counts=c.get("extension_counts"), extension_values=c.get("extension_values")
    )


def test_file_shape_and_digests():
    assert VECTORS["version"] == 1
    assert len(VECTORS["profiles"]) == len(STANDARD)
    assert len(VECTORS["context_bounds"]) == 13
    counts = {suite["profile"]: len(suite["cases"]) for suite in VECTORS["profiles"]}
    assert counts == {ce.PROFILE_MAX_COUNT_V2: 34, ce.PROFILE_ALLOWED_VALUES_V2: 36}
    for suite in VECTORS["profiles"]:
        registration = STANDARD[suite["profile"]]
        assert registration.descriptor.type == suite["type"]
        assert ce.constraint_profile_digest_v2(registration.descriptor) == suite["profile_digest"]
        outcomes = {case["outcome"] for case in suite["cases"]}
        assert outcomes == {"pass", "denied", "unverifiable"}


@pytest.mark.parametrize("suite,case", CASES, ids=[f"{s['profile']}/{c['name']}" for s, c in CASES])
def test_profile_case(suite, case):
    registration = STANDARD[suite["profile"]]
    if case.get("params_absent"):
        params = None
    else:
        assert "params" in case, "case has neither params nor params_absent"
        params = _v2json.canonical(case["params"])
    ctx = _context(case["context"])
    ce.validate_v2_extension_context(ctx)
    result = registration.evaluate(
        background(),
        ce.ConstraintEvaluationInputV2(
            type=registration.descriptor.type, params_json=params, delegation_index=0, constraint_index=0,
            issuer_id="issuer-1", cert_id="cert-1", context=ctx, evaluation_time=1_000,
        ),
    )
    assert result.outcome == case["outcome"], result.detail
    assert result.valid_until == 0


@pytest.mark.parametrize("case", VECTORS["context_bounds"], ids=[c["name"] for c in VECTORS["context_bounds"]])
def test_context_bound(case):
    try:
        ce.validate_v2_extension_context(_context(case["context"]))
        err = None
    except Exception as exc:  # noqa: BLE001 - compared by class
        err = exc
    assert error_class_of(err) == (case.get("error_class") or "")


def test_profiles_run_through_the_registry():
    registry = ce.new_constraint_evaluator_registry_v2(1.0, *STANDARD.values())
    refs = registry.refs()
    assert [r.type for r in refs] == sorted(r.type for r in refs)
    assert {r.profile_digest for r in refs} == {s["profile_digest"] for s in VECTORS["profiles"]}
    entry = registry._entries[ce.CONSTRAINT_MAX_COUNT_V2]
    ctx = ConstraintContextV2(extension_counts={"nodes": 5})
    base = dict(type=ce.CONSTRAINT_MAX_COUNT_V2, delegation_index=0, constraint_index=0, issuer_id="i",
                cert_id="c", context=ctx, evaluation_time=10)
    assert ce.run_constraint_evaluator_v2(entry, 1.0, ce.ConstraintEvaluationInputV2(
        params_json=b'{"counter":"nodes","max":5}', **base)) == 0
    with pytest.raises(Exception) as denied:
        ce.run_constraint_evaluator_v2(entry, 1.0, ce.ConstraintEvaluationInputV2(
            params_json=b'{"counter":"nodes","max":4}', **base))
    assert "denied" in str(denied.value)
