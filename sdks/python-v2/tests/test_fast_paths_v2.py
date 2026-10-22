"""The fast canonical-JSON string escaper and nesting-depth check must accept
and produce exactly what the original character-by-character versions did.

Both sit under every signature transcript and every wire decode, so a
divergence would change signed bytes or wire acceptance. The reference
implementations below are the pre-optimization code, kept verbatim.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ratify_protocol_v2._v2json import _check_depth
from ratify_protocol_v2.canonical import _encode_string
from ratify_protocol_v2.limits_v2 import MAX_JSON_NESTING_DEPTH

_SHORT = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def reference_encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        short = _SHORT.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif cp == 0x2028:
            out.append("\\u2028")
        elif cp == 0x2029:
            out.append("\\u2029")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def reference_check_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise ValueError(f"wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH ({MAX_JSON_NESTING_DEPTH})")
        elif c in "]}":
            depth -= 1


def _depth_outcome(fn, text):
    try:
        fn(text)
    except ValueError as exc:
        return str(exc)
    return None


# Characters that matter to either function, mixed with arbitrary text
# (including lone surrogates, which the encoder passes through unchanged).
_INTERESTING = st.sampled_from(list('"\\[]{}\b\f\n\r\t\x00\x1f\x7f\u2028\u2029 a\ud800'))
_TEXT = st.lists(st.one_of(_INTERESTING, st.characters()), max_size=200).map("".join)


@settings(max_examples=3000, deadline=None)
@given(_TEXT)
def test_encode_string_matches_reference(s):
    assert _encode_string(s) == reference_encode_string(s)


def test_encode_string_every_bmp_scalar():
    for cp in range(0x10000):
        ch = chr(cp)
        assert _encode_string(ch) == reference_encode_string(ch), hex(cp)


@settings(max_examples=3000, deadline=None)
@given(_TEXT)
def test_check_depth_matches_reference(text):
    assert _depth_outcome(_check_depth, text) == _depth_outcome(reference_check_depth, text)


@pytest.mark.parametrize("text", [
    "[" * MAX_JSON_NESTING_DEPTH + "]" * MAX_JSON_NESTING_DEPTH,
    "[" * (MAX_JSON_NESTING_DEPTH + 1),
    '["' + "[" * 100 + '"]',
    '{"a":"\\"' + "{" * 100 + '"}',
    '"unterminated ' + "[" * 100,
    '"unterminated \\',
    '"\\\\"' + "[" * (MAX_JSON_NESTING_DEPTH + 1),
    "]]]" + "[" * (MAX_JSON_NESTING_DEPTH + 3),
])
def test_check_depth_edge_cases_match_reference(text):
    assert _depth_outcome(_check_depth, text) == _depth_outcome(reference_check_depth, text)
