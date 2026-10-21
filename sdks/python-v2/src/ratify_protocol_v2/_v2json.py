"""Strict wire JSON acceptance and Go-compatible canonical encoding for v2.

``check_wire_json`` mirrors Go ``checkWireJSON``: valid UTF-8, no duplicate
keys (after escapes are decoded), integers inside the safe range, a single
document, bounded nesting, and canonical base64 for protocol byte fields.

``canonical`` mirrors ``ratify.CanonicalJSON`` for v2 values: object keys are
sorted, ``None`` encodes as ``null`` (v2 values carry explicit nulls; callers
omit ``omitempty`` members themselves), bytes encode as padded standard
base64, and floats use Go's encoding/json formatting.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
from decimal import Decimal
from typing import Any

from .canonical import _JsonNull, _encode_string
from .types import MAX_JSON_NESTING_DEPTH

MAX_SAFE_INTEGER = 2**53 - 1

WIRE_BYTE_FIELDS = frozenset({
    "bundle_hash", "chain_hash", "challenge", "context_hash", "ed25519",
    "entry_data", "mac", "ml_dsa_65", "prev_hash", "session_context",
    "stream_id", "terms_canonical_json",
})


class _Float(float):
    """A JSON number token written with a fraction or exponent."""


def _reject_negative_zero(text: str) -> None:
    # Only a value equal to negative zero is rejected; -0.5 is a valid float.
    if text.startswith("-") and float(text) == 0:
        raise ValueError("wire: negative zero is not a canonical number")


def _parse_int(text: str) -> int:
    _reject_negative_zero(text)
    value = int(text)
    if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
        raise ValueError(
            f"wire: integer {text} outside the safe-integer range [-(2^53-1), 2^53-1]"
        )
    return value


def _parse_float(text: str) -> float:
    _reject_negative_zero(text)
    value = float(text)
    if math.isinf(value) or math.isnan(value):
        raise ValueError(f"wire: number {text} is out of range")
    return _Float(value)


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
_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|.)", re.DOTALL)


def reject_unpaired_surrogate_escapes(text: str) -> None:
    """Go ``rejectUnpairedSurrogateEscapes``: a lenient decoder maps an
    unpaired surrogate escape to U+FFFD, so v2 rejects it on the raw text."""
    pending_high = False
    last_end = -1
    for match in _ESCAPE.finditer(text):
        unit_text = match.group(1)
        unit = int(unit_text, 16) if unit_text is not None else None
        adjacent = match.start() == last_end
        if pending_high:
            if adjacent and unit is not None and 0xDC00 <= unit <= 0xDFFF:
                pending_high = False
                last_end = match.end()
                continue
            raise ValueError("wire: unpaired UTF-16 surrogate escape")
        if unit is not None and 0xD800 <= unit <= 0xDBFF:
            pending_high = True
        elif unit is not None and 0xDC00 <= unit <= 0xDFFF:
            raise ValueError("wire: unpaired UTF-16 surrogate escape")
        last_end = match.end()
    if pending_high:
        raise ValueError("wire: unpaired UTF-16 surrogate escape")


def parse(data: bytes | str) -> Any:
    """Parse one JSON document under the strict number and key rules."""
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("wire: invalid UTF-8") from exc
    else:
        text = data
    if "\\" in text:
        reject_unpaired_surrogate_escapes(text)
    try:
        value = _DECODER.decode(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"wire: invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise ValueError("wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH") from exc
    return value


def _check_canonical_base64(key: str, value: str) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f'wire: field "{key}": malformed or non-canonical base64') from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f'wire: field "{key}": non-canonical base64')


def _walk(value: Any, depth: int, top_bytes: frozenset, top_text: frozenset) -> None:
    if isinstance(value, dict):
        if depth >= MAX_JSON_NESTING_DEPTH:
            raise ValueError(
                f"wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH ({MAX_JSON_NESTING_DEPTH})"
            )
        for key, item in value.items():
            if isinstance(item, str):
                if depth == 0:
                    is_byte = (key in WIRE_BYTE_FIELDS and key not in top_text) or key in top_bytes
                else:
                    is_byte = key in WIRE_BYTE_FIELDS
                if is_byte:
                    _check_canonical_base64(key, item)
            else:
                _walk(item, depth + 1, top_bytes, top_text)
    elif isinstance(value, list):
        if depth >= MAX_JSON_NESTING_DEPTH:
            raise ValueError(
                f"wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH ({MAX_JSON_NESTING_DEPTH})"
            )
        for item in value:
            _walk(item, depth + 1, top_bytes, top_text)


def check_wire_json(
    data: bytes,
    top_level_byte_fields: tuple[str, ...] | frozenset = (),
    top_level_text_fields: tuple[str, ...] | frozenset = (),
) -> Any:
    """Go ``checkWireJSON``; returns the parsed value for reuse."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("wire data must be bytes")
    value = parse(data)
    _walk(value, 0, frozenset(top_level_byte_fields), frozenset(top_level_text_fields))
    return value


# ---------------------------------------------------------------------------
# Canonical encoding


def go_float(value: float) -> str:
    """Format a float64 exactly as Go encoding/json does."""
    if math.isinf(value) or math.isnan(value):
        raise ValueError("canonical JSON: unsupported float value")
    if value == 0:
        return "-0" if math.copysign(1.0, value) < 0 else "0"
    magnitude = abs(value)
    text = repr(float(value))
    if magnitude < 1e-6 or magnitude >= 1e21:
        mantissa, _, exponent = text.partition("e")
        if not exponent:
            mantissa, exponent = _to_exponent(text)
        sign = "-" if exponent.startswith("-") else "+"
        digits = exponent.lstrip("+-").lstrip("0") or "0"
        if len(digits) < 2:
            digits = "0" + digits
        if mantissa.endswith(".0"):
            mantissa = mantissa[:-2]
        out = f"{mantissa}e{sign}{digits}"
        # Go cleans e-09 to e-9 (only for negative two-digit exponents).
        if sign == "-" and digits.startswith("0"):
            out = f"{mantissa}e-{digits[1:]}"
        return out
    fixed = format(Decimal(text), "f")
    if "." in fixed:
        fixed = fixed.rstrip("0").rstrip(".")
    return fixed


def _to_exponent(text: str) -> tuple[str, str]:
    mantissa, exponent = format(Decimal(text).normalize(), "e").split("e")
    return mantissa, exponent


class RawJSON:
    """Pre-encoded canonical JSON embedded verbatim (Go json.RawMessage)."""

    __slots__ = ("data",)

    def __init__(self, data: bytes):
        self.data = bytes(data)


def _encode(value: Any, out: list) -> None:
    if isinstance(value, RawJSON):
        out.append(value.data.decode("utf-8"))
    elif value is None or isinstance(value, _JsonNull):
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
            raise ValueError(
                f"canonical JSON: integer {value} outside the safe-integer range [-(2^53-1), 2^53-1]"
            )
        out.append(str(value))
    elif isinstance(value, float):
        if value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
            pass
        elif value.is_integer() and abs(value) < 1e21:
            raise ValueError(
                f"canonical JSON: integer {value} outside the safe-integer range [-(2^53-1), 2^53-1]"
            )
        out.append(go_float(value))
    elif isinstance(value, str):
        out.append(_encode_string(value))
    elif isinstance(value, (bytes, bytearray)):
        out.append('"' + base64.b64encode(bytes(value)).decode("ascii") + '"')
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value):
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
    """Ratify canonical JSON bytes for a v2 value."""
    out: list = []
    _encode(value, out)
    return "".join(out).encode("utf-8")


def go_marshal_strings(values: list[str]) -> bytes:
    """Go ``json.Marshal([]string)`` including its default HTML escaping."""
    parts = []
    for value in values:
        encoded = _encode_string(value)
        encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        parts.append(encoded)
    return ("[" + ",".join(parts) + "]").encode("utf-8")


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
