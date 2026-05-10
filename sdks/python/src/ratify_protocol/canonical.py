"""Canonical JSON serialization per Ratify Protocol SPEC §6.

Every implementation MUST produce byte-identical output for the same input
or signatures will not verify across languages.

Rules:
  - Object members in lex order (byte order on UTF-8), RECURSIVELY.
  - No whitespace between tokens. No trailing newline.
  - UTF-8 encoding.
  - Integers as shortest decimal (no leading zeros, no exponent).
  - bytes-type values encoded as base64-standard strings with padding.
  - '<', '>', '&' pass through unmodified (NO HTML escaping).
  - U+2028 / U+2029 escaped as \\u2028 / \\u2029 (matches Go behavior).
  - Minimum string escaping per RFC 8259.
"""
from __future__ import annotations

import base64
from dataclasses import is_dataclass, fields
from typing import Any


_ESCAPE_MAP = {
    ord('"'): b'\\"',
    ord('\\'): b'\\\\',
    0x08: b'\\b',
    0x0c: b'\\f',
    0x0a: b'\\n',
    0x0d: b'\\r',
    0x09: b'\\t',
}


def canonical_json(value: Any) -> bytes:
    """Canonical JSON-encode a value. Returns UTF-8 bytes."""
    text = _encode(value)
    return text.encode("utf-8")


def _encode(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    if isinstance(v, float):
        # Shouldn't appear in v1 signable objects; fall back to repr-like
        if v.is_integer():
            return str(int(v))
        return repr(v)
    if isinstance(v, str):
        return _encode_string(v)
    if isinstance(v, (bytes, bytearray)):
        # Project convention: base64-standard encoding.
        return _encode_string(base64.b64encode(bytes(v)).decode("ascii"))
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_encode(x) for x in v) + "]"
    if isinstance(v, dict):
        return _encode_object(v)
    if is_dataclass(v):
        return _encode_dataclass(v)
    raise TypeError(f"canonical_json: unsupported type {type(v).__name__}")


def _encode_object(obj: dict) -> str:
    keys = sorted(obj.keys())
    parts = []
    for k in keys:
        val = obj[k]
        if val is None:
            # Skip None values — matches Go's omitempty for optional fields
            continue
        parts.append(_encode_string(k) + ":" + _encode(val))
    return "{" + ",".join(parts) + "}"


def _encode_dataclass(obj: Any) -> str:
    """Serialize a dataclass as a JSON object.

    Uses the dataclass field *definition* order as the input set, then sorts
    by JSON key (field name) for canonical output. Omits fields whose value
    is None or, for list[str] scope-like fields, empty — to match Go's
    omitempty behavior on optional fields.
    """
    entries: dict[str, Any] = {}
    for f in fields(obj):
        val = getattr(obj, f.name)
        if val is None:
            continue
        # Convert nested bytes to the right shape; strings / lists pass through.
        entries[f.name] = val
    return _encode_object(entries)


def _encode_string(s: str) -> str:
    """Encode a string per Ratify canonical rules.

    No HTML escaping. U+2028/U+2029 escape as \\u2028/\\u2029. Control chars
    below U+0020 escape as \\u00XX. Standard RFC 8259 escapes for ", \\, etc.
    Everything else passes through.
    """
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp == 0x22:  # "
            out.append('\\"')
        elif cp == 0x5c:  # \
            out.append('\\\\')
        elif cp == 0x08:
            out.append('\\b')
        elif cp == 0x09:
            out.append('\\t')
        elif cp == 0x0a:
            out.append('\\n')
        elif cp == 0x0c:
            out.append('\\f')
        elif cp == 0x0d:
            out.append('\\r')
        elif cp < 0x20:
            out.append(f'\\u{cp:04x}')
        elif cp == 0x2028:
            out.append('\\u2028')
        elif cp == 0x2029:
            out.append('\\u2029')
        else:
            # Everything else passes through as UTF-8 (no HTML escape).
            out.append(ch)
    out.append('"')
    return "".join(out)


def base64_standard_encode(data: bytes) -> str:
    """Base64-standard encoding with padding (A-Za-z0-9+/=)."""
    return base64.b64encode(data).decode("ascii")


def base64_standard_decode(s: str) -> bytes:
    """Decode base64-standard (padded or unpadded)."""
    # Add padding if needed
    pad = (-len(s)) % 4
    if pad:
        s = s + "=" * pad
    return base64.b64decode(s)


def hex_encode(data: bytes) -> str:
    """Lowercase hex."""
    return data.hex()


def hex_decode(s: str) -> bytes:
    """Lower- or upper-case hex."""
    return bytes.fromhex(s)
