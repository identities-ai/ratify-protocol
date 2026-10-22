"""Strict wire JSON acceptance and canonical encoding for Protocol v2.

``check_wire_json`` mirrors Go ``checkWireJSON`` in strict v2 mode: valid
UTF-8, no unpaired UTF-16 surrogate escape, no duplicate keys (compared after
escapes are decoded), integer-only numbers inside the safe range with no
``-0`` spelling and no fraction or exponent, a single document, nesting of at
most ``MAX_JSON_NESTING_DEPTH`` containers, and canonical padded base64 for
protocol byte fields.

``canonical`` is RatifyCanonicalJSON (SPEC-v2 Annex A §A.3) for v2 values:
object keys sorted by UTF-8 bytes, ``None`` encodes as ``null``, ``bytes``
encode as padded standard base64, no floating point.

Every rejection raises ``ValueError``; decoders classify it as ``malformed``.
"""
from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .canonical import _encode_string
from .limits_v2 import MAX_JSON_NESTING_DEPTH

MAX_SAFE_INTEGER = 2**53 - 1
# The longest integer token a safe integer can have: "-9007199254740991".
_MAX_INTEGER_TOKEN = 17

WIRE_BYTE_FIELDS = frozenset({
    "bundle_hash", "chain_hash", "challenge", "context_hash", "ed25519",
    "entry_data", "mac", "ml_dsa_65", "prev_hash", "session_context",
    "stream_id", "terms_canonical_json",
})


def _parse_int(text: str) -> int:
    # Bound the token before int() so an adversarial digit string costs O(n).
    if len(text) > _MAX_INTEGER_TOKEN:
        raise ValueError(f"wire: integer token of {len(text)} characters is outside the safe-integer range")
    if text == "-0":
        raise ValueError("wire: negative zero is not a canonical number")
    value = int(text)
    if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
        raise ValueError(f"wire: integer {text} outside the safe-integer range [-(2^53-1), 2^53-1]")
    return value


def _parse_float(text: str) -> Any:
    if text.startswith("-") and set(text[1:]) <= set("0.eE+-"):
        raise ValueError("wire: negative zero is not a canonical number")
    raise ValueError(f"wire: number {text[:32]} is not an integer; v2 forbids floating point")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"wire: invalid JSON literal {name}")


def _pairs(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'wire: duplicate key "{key}" in JSON object')
        out[key] = value
    return out


_DECODER = json.JSONDecoder(
    object_pairs_hook=_pairs,
    parse_int=_parse_int,
    parse_float=_parse_float,
    parse_constant=_reject_constant,
)


def _hex_unit(text: str, start: int):
    if start + 4 > len(text):
        return None
    chunk = text[start:start + 4]
    if not all(c in "0123456789abcdefABCDEF" for c in chunk):
        return None
    return int(chunk, 16)


def reject_unpaired_surrogate_escapes(text: str) -> None:
    """Go ``rejectUnpairedSurrogateEscapes`` over the raw JSON text."""
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if not in_string:
            if c == '"':
                in_string = True
            i += 1
            continue
        if c == '"':
            in_string = False
        elif c == "\\":
            if i + 1 >= n:
                return
            if text[i + 1] != "u":
                i += 2
                continue
            unit = _hex_unit(text, i + 2)
            if unit is None:
                return
            if 0xD800 <= unit <= 0xDBFF:
                if i + 11 < n and text[i + 6] == "\\" and text[i + 7] == "u":
                    low = _hex_unit(text, i + 8)
                    if low is not None and 0xDC00 <= low <= 0xDFFF:
                        i += 12
                        continue
                raise ValueError("wire: unpaired UTF-16 surrogate escape")
            if 0xDC00 <= unit <= 0xDFFF:
                raise ValueError("wire: unpaired UTF-16 surrogate escape")
            i += 6
            continue
        i += 1


def _check_depth(text: str) -> None:
    """Reject nesting beyond MAX_JSON_NESTING_DEPTH before the recursive parser runs."""
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


def parse(data: bytes | bytearray | str) -> Any:
    """Parse one JSON document under the strict v2 rules."""
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("wire: invalid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise ValueError("wire: JSON input must be bytes")
    if "\\" in text:
        reject_unpaired_surrogate_escapes(text)
    _check_depth(text)
    try:
        return _DECODER.decode(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"wire: invalid JSON: {exc}") from exc
    except RecursionError as exc:  # pragma: no cover - bounded by _check_depth
        raise ValueError("wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH") from exc


def check_canonical_base64(key: str, value: str) -> None:
    """Go ``checkCanonicalBase64``: strict padded base64 that re-encodes identically."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f'wire: field "{key}": malformed or non-canonical base64') from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f'wire: field "{key}": non-canonical base64')


def _walk(value: Any, depth: int, top_bytes: frozenset, top_text: frozenset) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                if depth == 0:
                    is_byte = (key in WIRE_BYTE_FIELDS and key not in top_text) or key in top_bytes
                else:
                    is_byte = key in WIRE_BYTE_FIELDS
                if is_byte:
                    check_canonical_base64(key, item)
            else:
                _walk(item, depth + 1, top_bytes, top_text)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, top_bytes, top_text)


def check_wire_json(
    data: Any,
    top_level_byte_fields: tuple[str, ...] | frozenset = (),
    top_level_text_fields: tuple[str, ...] | frozenset = (),
) -> Any:
    """Go ``checkWireJSONV2`` / ``checkWireJSONV2WithTextTopLevel``; returns
    the parsed value for reuse."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("wire data must be bytes")
    value = parse(data)
    _walk(value, 0, frozenset(top_level_byte_fields), frozenset(top_level_text_fields))
    return value


# ---------------------------------------------------------------------------
# Canonical encoding


class RawJSON:
    """Pre-encoded canonical JSON embedded verbatim (Go json.RawMessage)."""

    __slots__ = ("data",)

    def __init__(self, data: bytes):
        self.data = bytes(data)


def _encode(value: Any, out: list) -> None:
    if isinstance(value, RawJSON):
        out.append(value.data.decode("utf-8"))
    elif value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
            raise ValueError(f"canonical JSON: integer {value} outside the safe-integer range [-(2^53-1), 2^53-1]")
        out.append(str(int(value)))
    elif isinstance(value, float):
        raise ValueError("canonical JSON: v2 values carry no floating point")
    elif isinstance(value, str):
        out.append(_encode_string(value))
    elif isinstance(value, (bytes, bytearray)):
        out.append('"' + base64.b64encode(bytes(value)).decode("ascii") + '"')
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value, key=lambda k: k.encode("utf-8", "surrogatepass")):
            if not isinstance(key, str):
                raise ValueError("canonical JSON: object keys must be strings")
            if not first:
                out.append(",")
            first = False
            out.append(_encode_string(key))
            out.append(":")
            _encode(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode(item, out)
        out.append("]")
    else:
        to_dict = getattr(value, "to_canonical_dict", None)
        if to_dict is None:
            raise TypeError(f"canonical JSON: unsupported type {type(value).__name__}")
        _encode(to_dict(), out)


def canonical(value: Any) -> bytes:
    """RatifyCanonicalJSON bytes for a v2 value."""
    out: list = []
    _encode(value, out)
    text = "".join(out)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("canonical JSON: strings must be valid Unicode scalar values") from exc


def raw_member_spans(text: str, start: int = 0) -> dict[str, tuple[int, int]]:
    """Return {key: (start, end)} text spans of the members of the object
    beginning at ``text[start]``. The text must already be valid JSON."""
    decoder = json.JSONDecoder()
    ws = " \t\r\n"
    i = start
    while text[i] in ws:
        i += 1
    if text[i] != "{":
        raise ValueError("wire: expected JSON object")
    i += 1
    spans: dict[str, tuple[int, int]] = {}
    while True:
        while text[i] in ws:
            i += 1
        if text[i] == "}":
            return spans
        key, i = decoder.raw_decode(text, i)
        while text[i] in ws:
            i += 1
        i += 1  # ':'
        while text[i] in ws:
            i += 1
        _, end = decoder.raw_decode(text, i)
        spans[key] = (i, end)
        i = end
        while text[i] in ws:
            i += 1
        if text[i] == ",":
            i += 1


def raw_array_spans(text: str, start: int) -> list[tuple[int, int]]:
    decoder = json.JSONDecoder()
    ws = " \t\r\n"
    i = start
    while text[i] in ws:
        i += 1
    if text[i] != "[":
        raise ValueError("wire: expected JSON array")
    i += 1
    spans: list[tuple[int, int]] = []
    while True:
        while text[i] in ws:
            i += 1
        if text[i] == "]":
            return spans
        _, end = decoder.raw_decode(text, i)
        spans.append((i, end))
        i = end
        while text[i] in ws:
            i += 1
        if text[i] == ",":
            i += 1
