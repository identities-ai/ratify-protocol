"""RatifyCanonicalJSON string escaping (SPEC-v2 Annex A §A.3).

Minimal escaping: ``"`` and ``\\``, the short escapes ``\\b \\f \\n \\r \\t``,
other control characters below U+0020 as ``\\u00xx``, and U+2028 / U+2029 as
``\\u2028`` / ``\\u2029``. No HTML escaping; every other scalar passes through
as UTF-8. The full encoder is :func:`ratify_protocol_v2._v2json.canonical`.
"""
from __future__ import annotations

_SHORT = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _encode_string(s: str) -> str:
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
