"""RatifyCanonicalJSON string escaping (SPEC-v2 Annex A §A.3).

Minimal escaping: ``"`` and ``\\``, the short escapes ``\\b \\f \\n \\r \\t``,
other control characters below U+0020 as ``\\u00xx``, and U+2028 / U+2029 as
``\\u2028`` / ``\\u2029``. No HTML escaping; every other scalar passes through
as UTF-8. The full encoder is :func:`ratify_protocol_v2._v2json.canonical`.
"""
from __future__ import annotations

import re

_SHORT = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}

# Every character the encoding escapes; everything else passes through.
_NEEDS_ESCAPE = re.compile('[\x00-\x1f"\\\\\u2028\u2029]')


def _escape(match: re.Match) -> str:
    cp = ord(match.group())
    short = _SHORT.get(cp)
    if short is not None:
        return short
    # Remaining control characters below U+0020, and U+2028 / U+2029.
    return f"\\u{cp:04x}"


def _encode_string(s: str) -> str:
    if _NEEDS_ESCAPE.search(s) is None:
        return '"' + s + '"'
    return '"' + _NEEDS_ESCAPE.sub(_escape, s) + '"'
