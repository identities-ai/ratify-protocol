"""Property tests for the evaluation-side decoders and validators.

The standard profile params decoders and the extension request-context
validator take untrusted input: they must never crash, must classify every
rejection, and must be deterministic.
"""
from __future__ import annotations

import json
import types

from hypothesis import given, settings
from hypothesis import strategies as st

from ratify_protocol_v2 import constraint_evaluator_v2 as ce
from ratify_protocol_v2.context_v2 import background
from ratify_protocol_v2.errors_v2 import V2Error, V2ErrorClass
from ratify_protocol_v2.stream_sequence_v2 import check_v2_stream_sequence

NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_.:-"
names = st.text(alphabet=NAME_CHARS, min_size=1, max_size=130) | st.text(max_size=10)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**60), max_value=2**60) | st.text(max_size=20),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4),
    max_leaves=12,
)


def _params_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_params_decoders_never_crash_on_bytes(data):
    for decode in (ce.decode_max_count_params_v2, ce.decode_allowed_values_params_v2):
        try:
            decode(data)
        except ValueError:
            pass


@settings(max_examples=300, deadline=None)
@given(st.dictionaries(st.sampled_from(["counter", "max", "allowed", "field", "x"]), json_values, max_size=4))
def test_params_decoders_accept_only_their_exact_shape(params):
    data = _params_bytes(params)
    try:
        counter, maximum = ce.decode_max_count_params_v2(data)
    except ValueError:
        pass
    else:
        assert set(params) == {"counter", "max"}
        assert ce.valid_extension_context_name_v2(counter)
        assert type(maximum) is int and 0 <= maximum <= 2**53 - 1
    try:
        field, allowed = ce.decode_allowed_values_params_v2(data)
    except ValueError:
        pass
    else:
        assert set(params) == {"allowed", "field"}
        assert ce.valid_extension_context_name_v2(field)
        assert 1 <= len(allowed) <= 64 and len(set(allowed)) == len(allowed)


@settings(max_examples=300, deadline=None)
@given(
    st.dictionaries(names, st.integers(min_value=-5, max_value=2**54) | st.booleans(), max_size=70),
    st.dictionaries(names, st.text(max_size=600) | st.integers(), max_size=70),
)
def test_extension_context_validation_is_classified_and_deterministic(counts, values):
    ctx = types.SimpleNamespace(extension_counts=counts, extension_values=values)

    def outcome():
        try:
            ce.validate_v2_extension_context(ctx)
            return None
        except V2Error as exc:
            assert exc.error_class == V2ErrorClass.CONFIGURATION_INVALID
            return exc.error_class

    first = outcome()
    assert outcome() == first
    within = (
        len(counts) <= 64 and len(values) <= 64
        and all(ce.valid_extension_context_name_v2(k) and type(v) is int and 0 <= v <= 2**53 - 1 for k, v in counts.items())
        and all(ce.valid_extension_context_name_v2(k) and isinstance(v, str) and len(v.encode("utf-8", "surrogatepass")) <= 512
                and not any(0xD800 <= ord(c) <= 0xDFFF for c in v) for k, v in values.items())
    )
    assert (first is None) == within


@settings(max_examples=200, deadline=None)
@given(json_values, st.dictionaries(names, st.integers(min_value=0, max_value=2**53 - 1), max_size=3),
       st.dictionaries(names, st.text(max_size=20), max_size=3))
def test_standard_profiles_always_answer_one_outcome(params, counts, values):
    ctx = types.SimpleNamespace(extension_counts=counts, extension_values=values)
    for registration in (ce.standard_max_count_evaluator_v2(), ce.standard_allowed_values_evaluator_v2()):
        result = registration.evaluate(background(), ce.ConstraintEvaluationInputV2(
            type=registration.descriptor.type, params_json=_params_bytes(params), delegation_index=0,
            constraint_index=0, issuer_id="i", cert_id="c", context=ctx, evaluation_time=1))
        assert result.outcome in ("pass", "denied", "unverifiable") and result.valid_until == 0


@settings(max_examples=300, deadline=None)
@given(st.booleans(), st.integers(min_value=-3, max_value=2**53 + 3), st.integers(min_value=-3, max_value=2**53 + 3))
def test_stream_sequence_accepts_only_the_successor(has_last, last, seq):
    try:
        check_v2_stream_sequence(has_last, last, seq)
    except V2Error as exc:
        assert exc.error_class in (V2ErrorClass.MALFORMED, V2ErrorClass.STREAM_SEQUENCE_MISMATCH)
        assert seq != (last + 1 if has_last else 1) or exc.error_class == V2ErrorClass.MALFORMED or last == 2**53 - 1
    else:
        assert seq == (last + 1 if has_last else 1)
