"""The resource_path logical path model and the params value model
(Go resource_path.go; SPEC-v2 §5.2, Annex A).

Paths are absolute logical POSIX-style paths compared byte for byte: no
Unicode normalization, no percent decoding, no case folding. Issuers and
adapters pre-normalize and pre-decode before constructing constraints and
verifier context.
"""
from __future__ import annotations

from typing import Any

from .limits_v2 import MAX_JSON_NESTING_DEPTH

_MAX_SAFE_INTEGER = 2**53 - 1


def normalize_resource_path(p: str) -> str:
    """Go ``NormalizeResourcePath``: validate ``p`` and return its comparison
    form (at most one trailing "/" trimmed, except for "/"). Raises
    ``ValueError`` for an invalid path."""
    if not isinstance(p, str):
        raise ValueError("path must be a string")
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
    trimmed = p[:-1] if p.endswith("/") else p
    for seg in trimmed[1:].split("/"):
        if seg == "":
            raise ValueError("path contains an empty segment")
        if seg in (".", ".."):
            raise ValueError("path contains a dot-segment; dot-segments are rejected, never resolved")
    return trimmed


def resource_path_matches(path_prefix: str, requested_path: str) -> bool:
    """Go ``ResourcePathMatches``: segment-boundary prefix matching."""
    try:
        prefix = normalize_resource_path(path_prefix)
        path = normalize_resource_path(requested_path)
    except ValueError:
        return False
    if prefix == "/":
        return True
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def resource_paths_nested(a: str, b: str) -> bool:
    """Go ``resourcePathsNested``: one prefix at or below the other; an absent
    prefix orders as "/"."""
    a = a or "/"
    b = b or "/"
    return resource_path_matches(a, b) or resource_path_matches(b, a)


def validate_params_value(v: Any, depth: int) -> None:
    """Go ``ValidateParamsValue`` over the restricted value model: null,
    booleans, strings, safe integers, and arrays and objects of these, at
    most MAX_JSON_NESTING_DEPTH deep. Raises ``ValueError``."""
    if depth > MAX_JSON_NESTING_DEPTH:
        raise ValueError(f"params nesting exceeds MAX_JSON_NESTING_DEPTH ({MAX_JSON_NESTING_DEPTH})")
    if v is None or isinstance(v, (bool, str)):
        return
    if isinstance(v, int):
        if v > _MAX_SAFE_INTEGER or v < -_MAX_SAFE_INTEGER:
            raise ValueError("params integer exceeds the safe-integer range; carry it as a decimal string")
        return
    if isinstance(v, float):
        raise ValueError("params values must be safe integers, not floats (carry non-integers as strings)")
    if isinstance(v, list):
        for item in v:
            validate_params_value(item, depth + 1)
        return
    if isinstance(v, dict):
        for key, item in v.items():
            if not isinstance(key, str):
                raise ValueError("params object keys must be strings")
            validate_params_value(item, depth + 1)
        return
    raise ValueError(f"params value of type {type(v).__name__} is outside the value model")
