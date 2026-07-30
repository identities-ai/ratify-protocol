"""Resource-bound authority — the resource_path constraint's path model,
segment-boundary matching, and the extension-constraint params value model
(SPEC §5.7.1, §5.7.3). Mirrors the Go reference resource_path.go exactly.

Paths are absolute logical POSIX-style paths: they name a location inside the
resource's own namespace, not filesystem paths on any machine. The verifier
compares bytes exactly — no Unicode normalization, no percent decoding, no
case folding. Issuers and adapters pre-normalize (NFC) and pre-decode BEFORE
constructing constraints and verifier context; nothing transforms a path
after verification.

CROSS-SDK: Go / TypeScript / Python / Rust / C MUST implement identical
semantics; adapters use these helpers rather than reimplementing matching.
"""
from __future__ import annotations

import math
from typing import Any

from .types import MAX_IDENTIFIER_LENGTH_BYTES, MAX_JSON_NESTING_DEPTH

# The IEEE-754 safe-integer magnitude (2^53 - 1). params integers beyond this
# range travel as decimal strings (SPEC §5.7.1).
_MAX_SAFE_INTEGER = 2**53 - 1

# Canonical v1 constraint kinds (SPEC §5.7.2). params is permitted only on
# non-canonical (extension) types.
_CANONICAL_CONSTRAINT_TYPES = frozenset({
    "geo_circle", "geo_polygon", "geo_bbox", "time_window",
    "max_speed_mps", "max_amount", "max_rate", "resource_path",
})


def is_canonical_constraint_type(t: str) -> bool:
    """True iff ``t`` is one of the canonical v1 constraint kinds (SPEC §5.7.2)."""
    return t in _CANONICAL_CONSTRAINT_TYPES


def normalize_resource_path(p: str) -> str:
    """Validate ``p`` against the logical path model (SPEC §5.7.3) and return
    its comparison form: at most one trailing "/" trimmed, except the root
    path "/" itself. Raises ValueError when ``p`` is not a valid logical path:

      - must begin with "/" ("/" is the only separator)
      - no NUL byte, no backslash (rejected, never translated)
      - no "." or ".." segment (rejected outright, never resolved)
      - no empty interior segment ("/a//b" is invalid; "/" is valid)

    "%" is an ordinary literal byte: the path model has no percent-encoding.
    """
    if p == "":
        raise ValueError("path is empty")
    if not p.startswith("/"):
        raise ValueError("path must begin with '/'")
    if "\x00" in p:
        raise ValueError("path contains a NUL byte")
    if "\\" in p:
        raise ValueError("path contains a backslash; '/' is the only separator")
    if p == "/":
        return "/"
    # Trim at most one trailing slash before segment validation, per the path
    # model: "/docs/" == "/docs", while "/docs//" leaves an empty interior
    # segment after the trim and is invalid.
    trimmed = p[:-1] if p.endswith("/") else p
    for seg in trimmed[1:].split("/"):
        if seg == "":
            raise ValueError("path contains an empty segment")
        if seg in (".", ".."):
            raise ValueError(
                "path contains a dot-segment; dot-segments are rejected, "
                "never resolved"
            )
    return trimmed


def resource_path_matches(path_prefix: str, requested_path: str) -> bool:
    """Report whether ``requested_path`` is at or below ``path_prefix`` under
    segment-boundary prefix matching (SPEC §5.7.3). Both inputs are normalized
    first; an invalid input never matches. This is NOT glob matching and NOT
    plain string-prefix matching: "/src" matches "/src" and "/src/a.ts", never
    "/src-old/a.ts" or "/srcx"."""
    try:
        prefix = normalize_resource_path(path_prefix)
        path = normalize_resource_path(requested_path)
    except ValueError:
        return False
    if prefix == "/":
        # The root prefix matches every valid path.
        return True
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def _resource_paths_nested(a: str, b: str) -> bool:
    """Report whether two valid prefixes are comparable under the prefix
    relation (one at or below the other). An absent prefix orders as "/"
    (SPEC §5.7.3 issuance rule)."""
    if a == "":
        a = "/"
    if b == "":
        b = "/"
    return resource_path_matches(a, b) or resource_path_matches(b, a)


def validate_resource_constraints(constraints: Any) -> None:
    """Enforce the issuance rule of SPEC §5.7.3: a certificate's resource_path
    constraints must be jointly satisfiable. Rejects constraint sets naming
    different resource_ids, and same-resource sets whose prefixes do not form a
    nested chain under the prefix relation. Individual constraints are also
    validated (non-empty resource_id within MAX_IDENTIFIER_LENGTH_BYTES;
    well-formed path_prefix). Raises ValueError on violation.

    Decoders do NOT call this — wire compatibility is not conditioned on
    issuance hygiene; verification denies unsatisfiable sets fail-closed."""
    resource_id = ""
    prefixes: list[str] = []
    for i, c in enumerate(constraints or []):
        if c.type != "resource_path":
            continue
        if not c.resource_id:
            raise ValueError(
                f"constraint[{i}]: resource_path requires a non-empty resource_id"
            )
        if len(c.resource_id.encode("utf-8")) > MAX_IDENTIFIER_LENGTH_BYTES:
            raise ValueError(
                f"constraint[{i}]: resource_id is "
                f"{len(c.resource_id.encode('utf-8'))} bytes, exceeding "
                f"MAX_IDENTIFIER_LENGTH_BYTES ({MAX_IDENTIFIER_LENGTH_BYTES})"
            )
        if c.path_prefix:
            try:
                normalize_resource_path(c.path_prefix)
            except ValueError as e:
                raise ValueError(
                    f"constraint[{i}]: invalid path_prefix: {e}"
                ) from e
        if resource_id == "":
            resource_id = c.resource_id
        elif c.resource_id != resource_id:
            raise ValueError(
                f"constraint[{i}]: certificate carries resource_path "
                f"constraints naming different resource_ids — jointly "
                f"unsatisfiable (SPEC §5.7.3); issue separate certificates"
            )
        for prev in prefixes:
            if not _resource_paths_nested(prev, c.path_prefix):
                raise ValueError(
                    f"constraint[{i}]: same-resource path_prefix values "
                    f"{prev!r} and {c.path_prefix!r} do not nest — jointly "
                    f"unsatisfiable (SPEC §5.7.3); narrow to one prefix or "
                    f"issue separate certificates"
                )
        prefixes.append(c.path_prefix)


def validate_params_value(v: Any, depth: int) -> None:
    """Enforce the extension-constraint params value model (SPEC §5.7.1):
    null, booleans, strings, safe integers (|n| <= 2^53-1), and arrays/objects
    of these. Floats and non-integer numbers are prohibited; integers beyond
    the safe range travel as decimal strings. ``depth`` is the container
    nesting already consumed; nesting beyond MAX_JSON_NESTING_DEPTH is
    rejected. Raises ValueError on violation."""
    if depth > MAX_JSON_NESTING_DEPTH:
        raise ValueError(
            f"params nesting exceeds MAX_JSON_NESTING_DEPTH ({MAX_JSON_NESTING_DEPTH})"
        )
    if v is None or isinstance(v, str):
        return
    if isinstance(v, bool):
        # bool is a subclass of int; check it before the int branch.
        return
    if isinstance(v, int):
        if v > _MAX_SAFE_INTEGER or v < -_MAX_SAFE_INTEGER:
            raise ValueError(
                "params integer exceeds the safe-integer range; carry it as a "
                "decimal string"
            )
        return
    if isinstance(v, float):
        # JSON decoding yields a Python float for any number with a fractional
        # part or exponent. Integral values within the safe range are integers
        # on the wire; anything else is outside the value model.
        if math.isnan(v) or math.isinf(v) or v != math.trunc(v):
            raise ValueError(
                "params values must be safe integers, not floats (carry "
                "non-integers as strings)"
            )
        if abs(v) > _MAX_SAFE_INTEGER:
            raise ValueError(
                "params integer exceeds the safe-integer range; carry it as a "
                "decimal string"
            )
        return
    if isinstance(v, (list, tuple)):
        for item in v:
            validate_params_value(item, depth + 1)
        return
    if isinstance(v, dict):
        for item in v.values():
            validate_params_value(item, depth + 1)
        return
    raise ValueError(
        f"params value of type {type(v).__name__} is outside the restricted "
        f"value model"
    )
