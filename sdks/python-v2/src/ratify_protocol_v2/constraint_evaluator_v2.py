"""Protocol v2 extension constraint evaluator profiles (SPEC-v2 §5.2).

Mirrors Go constraint_evaluator_v2.go. A certificate may carry a constraint
whose type is outside the closed v2 registry. Without configuration it fails
closed as ``constraint_unknown``. A verifier may register, in
caller-authenticated configuration, an evaluator profile for an exact
extension type. The profile is identified by a digest over a canonical
descriptor that names the type and a versioned profile identifier; the digest
identifies the profile and proves nothing about an implementation. The
certificate and the proof never select a profile or code. The registry
entries used by a chain are sealed with the challenge claim and recorded,
sorted by type, in the signed receipt member ``constraint_evaluators``.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import threading
from dataclasses import dataclass
from hashlib import sha384
from typing import Any, Callable, Optional

from . import _v2json
from .context_v2 import Context, background, with_timeout
from .errors_v2 import V2Error, V2ErrorClass, classify
from .types_v2 import (
    MAX_CONSTRAINT_EVALUATORS_V2,
    MAX_EXTENSION_TYPE_BYTES_V2,
    MAX_PROFILE_ID_BYTES_V2,
    MAX_SAFE_INTEGER,
    ConstraintEvaluatorRefV2,
    clone_constraint_evaluator_refs_v2,
    is_int,
    valid_constraint_evaluator_refs_v2,
    valid_extension_type_v2,
    valid_prefixed_digest_v2,
    valid_profile_id_v2,
)

__all__ = [
    "CONSTRAINT_MAX_COUNT_V2", "CONSTRAINT_ALLOWED_VALUES_V2",
    "PROFILE_MAX_COUNT_V2", "PROFILE_ALLOWED_VALUES_V2",
    "MAX_CONSTRAINT_EVALUATORS_V2", "MAX_EXTENSION_TYPE_BYTES_V2", "MAX_PROFILE_ID_BYTES_V2",
    "MAX_EXTENSION_CONTEXT_ENTRIES_V2", "MAX_EXTENSION_CONTEXT_NAME_BYTES_V2",
    "MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2", "MAX_ALLOWED_VALUES_V2",
    "MAX_CONSTRAINT_EVALUATOR_TIMEOUT_V2",
    "ConstraintProfileDescriptorV2", "ConstraintEvaluatorRefV2", "ConstraintEvaluationInputV2",
    "CONSTRAINT_OUTCOME_PASS_V2", "CONSTRAINT_OUTCOME_DENIED_V2", "CONSTRAINT_OUTCOME_UNVERIFIABLE_V2",
    "ConstraintEvaluationResultV2", "ConstraintEvaluatorRegistrationV2", "ConstraintEvaluatorRegistryV2",
    "new_constraint_evaluator_registry_v2", "constraint_profile_digest_v2",
    "valid_extension_type_v2", "valid_profile_id_v2", "valid_extension_context_name_v2",
    "validate_v2_extension_context", "clone_constraint_context_v2",
    "snapshot_constraint_evaluators_v2", "valid_constraint_evaluator_refs_v2",
    "clone_constraint_evaluator_refs_v2", "run_constraint_evaluator_v2",
    "standard_max_count_evaluator_v2", "standard_allowed_values_evaluator_v2",
    "decode_max_count_params_v2", "decode_allowed_values_params_v2", "extension_params_json_v2",
]

CONSTRAINT_MAX_COUNT_V2 = "com.ratifyprotocol.max_count"
CONSTRAINT_ALLOWED_VALUES_V2 = "com.ratifyprotocol.allowed_values"
PROFILE_MAX_COUNT_V2 = "com.ratifyprotocol.max_count/v1"
PROFILE_ALLOWED_VALUES_V2 = "com.ratifyprotocol.allowed_values/v1"

MAX_EXTENSION_CONTEXT_ENTRIES_V2 = 64
MAX_EXTENSION_CONTEXT_NAME_BYTES_V2 = 128
MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2 = 512
MAX_ALLOWED_VALUES_V2 = 64
# Go MaxConstraintEvaluatorTimeoutV2 (10s), in seconds.
MAX_CONSTRAINT_EVALUATOR_TIMEOUT_V2 = 10.0

_PROFILE_DIGEST_LABEL_V2 = b"ratify-protocol-constraint-profile-v2"

CONSTRAINT_OUTCOME_PASS_V2 = "pass"
CONSTRAINT_OUTCOME_DENIED_V2 = "denied"
CONSTRAINT_OUTCOME_UNVERIFIABLE_V2 = "unverifiable"


def _unverifiable(reason: str) -> Exception:
    """The constraint_unverifiable error of the v2 constraint error model
    (Go ``errConstraintUnverifiable``), declared in constraints_v2."""
    from . import constraints_v2

    factory = getattr(constraints_v2, "err_constraint_unverifiable", None) or getattr(
        constraints_v2, "_err_constraint_unverifiable"
    )
    return factory(reason)


@dataclass(frozen=True)
class ConstraintProfileDescriptorV2:
    """The canonical object whose digest identifies an evaluator profile:
    ``{"profile":<id>,"type":<type>}``."""

    profile: str
    type: str

    def to_canonical_dict(self) -> dict:
        return {"profile": self.profile, "type": self.type}


@dataclass(frozen=True)
class ConstraintEvaluationInputV2:
    """Everything an evaluator may read. It is a copy; changing it changes
    nothing in the verifier. ``evaluation_time`` is T_claim."""

    type: str
    params_json: Optional[bytes]  # canonical params object, or None when absent
    delegation_index: int
    constraint_index: int
    issuer_id: str
    cert_id: str
    context: Any  # constraints_v2.ConstraintContextV2
    evaluation_time: int


@dataclass(frozen=True)
class ConstraintEvaluationResultV2:
    """An evaluator's answer. ``valid_until`` is an optional exclusive horizon
    for a pass (0 = none); it must be later than the evaluation time."""

    outcome: str
    valid_until: int = 0
    detail: str = ""


# ConstraintEvaluatorFuncV2: (ctx, ConstraintEvaluationInputV2) -> ConstraintEvaluationResultV2.
# It must be pure: no I/O, no clock, no randomness. An exception, a timeout,
# or an invalid result is unverifiable. The verifier stops waiting at the
# registry timeout; an implementation must also return once ctx is done.
ConstraintEvaluatorFuncV2 = Callable[[Context, ConstraintEvaluationInputV2], ConstraintEvaluationResultV2]


@dataclass(frozen=True)
class ConstraintEvaluatorRegistrationV2:
    """Binds one profile descriptor to its implementation."""

    descriptor: ConstraintProfileDescriptorV2
    evaluate: Optional[ConstraintEvaluatorFuncV2]


@dataclass(frozen=True)
class _RegisteredConstraintEvaluatorV2:
    ref: ConstraintEvaluatorRefV2
    evaluate: ConstraintEvaluatorFuncV2


_REGISTRY_TOKEN = object()


class ConstraintEvaluatorRegistryV2:
    """Caller-authenticated verifier configuration. Immutable once built;
    only :func:`new_constraint_evaluator_registry_v2` builds a valid one."""

    __slots__ = ("_valid", "_timeout", "_entries")

    def __init__(self, *_args, **_kwargs):
        token = _kwargs.pop("_token", None)
        self._valid = token is _REGISTRY_TOKEN
        self._timeout = float(_kwargs.pop("_timeout", 0.0)) if self._valid else 0.0
        self._entries: dict = dict(_kwargs.pop("_entries", {})) if self._valid else {}

    @property
    def timeout(self) -> float:
        return self._timeout

    def refs(self) -> list:
        """The registered ``{type, profile_digest}`` pairs sorted by type."""
        return sorted((entry.ref for entry in self._entries.values()), key=lambda r: r.type.encode("utf-8"))


def constraint_profile_digest_v2(d: ConstraintProfileDescriptorV2) -> str:
    """``"sha384:"`` and the lowercase hex SHA-384 of
    ``"ratify-protocol-constraint-profile-v2" || 0x00 ||
    RatifyCanonicalJSON({"profile","type"})``."""
    if not isinstance(d, ConstraintProfileDescriptorV2):
        raise TypeError("descriptor must be a ConstraintProfileDescriptorV2")
    if not valid_extension_type_v2(d.type):
        raise ValueError(f"v2 constraint profile type {d.type!r} is not a registrable extension type")
    if not valid_profile_id_v2(d.profile):
        raise ValueError(f"v2 constraint profile identifier {d.profile!r} is invalid")
    body = _v2json.canonical(d.to_canonical_dict())
    return "sha384:" + sha384(_PROFILE_DIGEST_LABEL_V2 + b"\x00" + body).hexdigest()


def new_constraint_evaluator_registry_v2(
    timeout: float, *registrations: ConstraintEvaluatorRegistrationV2
) -> ConstraintEvaluatorRegistryV2:
    """Validate and freeze a registry. Every type must be a registrable
    extension type and appear once; every descriptor must name a valid
    versioned profile identifier; ``timeout`` (seconds) must be in
    (0, 10]. A violation is ``configuration_invalid``."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not (
        0 < timeout <= MAX_CONSTRAINT_EVALUATOR_TIMEOUT_V2
    ):
        raise V2Error(
            V2ErrorClass.CONFIGURATION_INVALID,
            f"v2 constraint evaluator timeout must be in (0, {MAX_CONSTRAINT_EVALUATOR_TIMEOUT_V2}s]",
        )
    if len(registrations) > MAX_CONSTRAINT_EVALUATORS_V2:
        raise V2Error(
            V2ErrorClass.CONFIGURATION_INVALID,
            f"v2 constraint evaluator registry holds at most {MAX_CONSTRAINT_EVALUATORS_V2} profiles",
        )
    entries: dict = {}
    for i, registration in enumerate(registrations):
        if not isinstance(registration, ConstraintEvaluatorRegistrationV2) or not callable(registration.evaluate):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, f"v2 constraint evaluator {i} has no implementation")
        try:
            digest = constraint_profile_digest_v2(registration.descriptor)
        except (ValueError, TypeError) as exc:
            raise classify(V2ErrorClass.CONFIGURATION_INVALID, exc) from exc
        kind = registration.descriptor.type
        if kind in entries:
            raise V2Error(
                V2ErrorClass.CONFIGURATION_INVALID, f"v2 constraint type {kind!r} is registered more than once"
            )
        entries[kind] = _RegisteredConstraintEvaluatorV2(
            ref=ConstraintEvaluatorRefV2(profile_digest=digest, type=kind), evaluate=registration.evaluate
        )
    return ConstraintEvaluatorRegistryV2(_token=_REGISTRY_TOKEN, _timeout=float(timeout), _entries=entries)


def valid_extension_context_name_v2(name: object) -> bool:
    """1 to 128 bytes of [a-z0-9_.:-]."""
    if not isinstance(name, str) or name == "" or len(name) > MAX_EXTENSION_CONTEXT_NAME_BYTES_V2:
        return False
    return all(("a" <= c <= "z") or ("0" <= c <= "9") or c in "_.:-" for c in name)


def _valid_utf8_text(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def validate_v2_extension_context(c: Any) -> None:
    """Check the extension request context before claim
    (``configuration_invalid`` on failure)."""
    counts = getattr(c, "extension_counts", None)
    values = getattr(c, "extension_values", None)
    if counts is None:
        counts = {}
    if values is None:
        values = {}
    if not isinstance(counts, dict) or not isinstance(values, dict):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 extension request context maps must be dicts")
    if len(counts) > MAX_EXTENSION_CONTEXT_ENTRIES_V2 or len(values) > MAX_EXTENSION_CONTEXT_ENTRIES_V2:
        raise V2Error(
            V2ErrorClass.CONFIGURATION_INVALID,
            f"v2 extension request context holds at most {MAX_EXTENSION_CONTEXT_ENTRIES_V2} counts and "
            f"{MAX_EXTENSION_CONTEXT_ENTRIES_V2} values",
        )
    for name, count in counts.items():
        if not valid_extension_context_name_v2(name) or not is_int(count) or count < 0 or count > MAX_SAFE_INTEGER:
            raise V2Error(
                V2ErrorClass.CONFIGURATION_INVALID,
                f"v2 extension count {name!r} must be named by 1 to {MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes "
                f"of [a-z0-9_.:-] and be 0..{MAX_SAFE_INTEGER}",
            )
    for name, value in values.items():
        if (
            not valid_extension_context_name_v2(name)
            or not isinstance(value, str)
            or not _valid_utf8_text(value)
            or len(value.encode("utf-8")) > MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2
        ):
            raise V2Error(
                V2ErrorClass.CONFIGURATION_INVALID,
                f"v2 extension value {name!r} must be named by 1 to {MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes "
                f"of [a-z0-9_.:-] and be valid UTF-8 of at most {MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2} bytes",
            )


def clone_constraint_context_v2(c: Any) -> Any:
    """A copy whose extension maps are independent of ``c``."""
    counts = getattr(c, "extension_counts", None)
    values = getattr(c, "extension_values", None)
    changes = {
        "extension_counts": None if counts is None else dict(counts),
        "extension_values": None if values is None else dict(values),
    }
    if dataclasses.is_dataclass(c) and not isinstance(c, type):
        return dataclasses.replace(c, **changes)
    out = copy.copy(c)
    for key, value in changes.items():
        setattr(out, key, value)
    return out


def snapshot_constraint_evaluators_v2(registry: Optional[ConstraintEvaluatorRegistryV2], bundle: Any):
    """The registry entries for the extension types present in the chain,
    keyed by type, their refs sorted by type, and the registry timeout.
    Returns ``(None, None, 0.0)`` when nothing is sealed."""
    if not isinstance(registry, ConstraintEvaluatorRegistryV2) or not registry._valid or bundle is None:
        return None, None, 0.0
    used: dict = {}
    for cert in bundle.delegations or ():
        for constraint in cert.constraints or ():
            entry = registry._entries.get(constraint.type)
            if entry is not None:
                used[constraint.type] = entry
    if not used:
        return None, None, 0.0
    refs = sorted((entry.ref for entry in used.values()), key=lambda r: r.type.encode("utf-8"))
    return used, refs, registry._timeout


def run_constraint_evaluator_v2(
    entry: _RegisteredConstraintEvaluatorV2, timeout: float, in_: ConstraintEvaluationInputV2
) -> int:
    """Invoke one sealed evaluator under its timeout with exception
    containment and map its answer to the constraint error model: return the
    pass horizon (0 = none), raise a denial error, or raise an unverifiable
    error. Missing context is the evaluator's own unverifiable verdict."""
    ctx = with_timeout(background(), timeout)
    evaluation_input = dataclasses.replace(in_, context=clone_constraint_context_v2(in_.context))
    box: dict = {}
    done = threading.Event()

    def worker() -> None:
        try:
            box["result"] = entry.evaluate(ctx, evaluation_input)
        except BaseException as exc:  # noqa: BLE001 - Go recovers every panic
            box["error"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=worker, name=f"ratify-v2-evaluator:{in_.type}", daemon=True)
    thread.start()
    finished = done.wait(timeout)
    ctx.cancel()
    if not finished:
        raise _unverifiable(f"{in_.type} evaluator did not answer within {timeout}s")
    if "error" in box:
        raise _unverifiable(f"{in_.type} evaluator failed: {box['error']}")
    got = box.get("result")
    if not isinstance(got, ConstraintEvaluationResultV2) or not is_int(got.valid_until):
        raise _unverifiable(f"{in_.type} evaluator returned an invalid outcome")
    if got.outcome == CONSTRAINT_OUTCOME_PASS_V2:
        if got.valid_until == 0:
            return 0
        if got.valid_until <= in_.evaluation_time:
            raise _unverifiable(f"{in_.type} evaluator returned a pass horizon not after the evaluation time")
        from .clock_bounds_v2 import V2_MAX_TIMESTAMP_SECONDS

        return min(got.valid_until, V2_MAX_TIMESTAMP_SECONDS)
    if got.outcome == CONSTRAINT_OUTCOME_DENIED_V2:
        if got.valid_until != 0:
            raise _unverifiable(f"{in_.type} evaluator returned a horizon with a denial")
        raise ValueError(f"{in_.type} denied: {got.detail}")
    if got.outcome == CONSTRAINT_OUTCOME_UNVERIFIABLE_V2:
        if got.valid_until != 0:
            raise _unverifiable(f"{in_.type} evaluator returned a horizon with an unverifiable result")
        raise _unverifiable(f"{in_.type} unverifiable: {got.detail}")
    raise _unverifiable(f"{in_.type} evaluator returned an invalid outcome")


# ---------------------------------------------------------------------------
# Standard profiles (SPEC-v2 §5.2).


def standard_max_count_evaluator_v2() -> ConstraintEvaluatorRegistrationV2:
    """The standard count profile ``com.ratifyprotocol.max_count/v1``.
    params is exactly ``{"counter":<name>,"max":<integer 0..2^53-1>}``; the
    request supplies the quantity in ``extension_counts[counter]``. Absent
    quantity: unverifiable. Above max: denied. Params outside this shape:
    denied. Otherwise pass, with no horizon."""
    return ConstraintEvaluatorRegistrationV2(
        descriptor=ConstraintProfileDescriptorV2(profile=PROFILE_MAX_COUNT_V2, type=CONSTRAINT_MAX_COUNT_V2),
        evaluate=_evaluate_max_count_v2,
    )


def standard_allowed_values_evaluator_v2() -> ConstraintEvaluatorRegistrationV2:
    """The standard exact-value profile
    ``com.ratifyprotocol.allowed_values/v1``. params is exactly
    ``{"allowed":[1 to 64 unique strings of 1 to 512 bytes],"field":<name>}``;
    the request supplies the value in ``extension_values[field]``. Absent
    value: unverifiable. A value byte-equal to no allowed entry: denied.
    Params outside this shape: denied. Otherwise pass, with no horizon."""
    return ConstraintEvaluatorRegistrationV2(
        descriptor=ConstraintProfileDescriptorV2(profile=PROFILE_ALLOWED_VALUES_V2, type=CONSTRAINT_ALLOWED_VALUES_V2),
        evaluate=_evaluate_allowed_values_v2,
    )


def _evaluate_max_count_v2(_ctx: Context, in_: ConstraintEvaluationInputV2) -> ConstraintEvaluationResultV2:
    try:
        counter, maximum = decode_max_count_params_v2(in_.params_json)
    except ValueError as exc:
        return ConstraintEvaluationResultV2(outcome=CONSTRAINT_OUTCOME_DENIED_V2, detail=str(exc))
    counts = getattr(in_.context, "extension_counts", None) or {}
    if counter not in counts:
        return ConstraintEvaluationResultV2(
            outcome=CONSTRAINT_OUTCOME_UNVERIFIABLE_V2,
            detail=f"no authenticated count {counter!r} in the request context",
        )
    count = counts[counter]
    if count > maximum:
        return ConstraintEvaluationResultV2(
            outcome=CONSTRAINT_OUTCOME_DENIED_V2,
            detail=f"count {counter!r} is {count}, above the signed maximum {maximum}",
        )
    return ConstraintEvaluationResultV2(outcome=CONSTRAINT_OUTCOME_PASS_V2)


def _evaluate_allowed_values_v2(_ctx: Context, in_: ConstraintEvaluationInputV2) -> ConstraintEvaluationResultV2:
    try:
        field, allowed = decode_allowed_values_params_v2(in_.params_json)
    except ValueError as exc:
        return ConstraintEvaluationResultV2(outcome=CONSTRAINT_OUTCOME_DENIED_V2, detail=str(exc))
    values = getattr(in_.context, "extension_values", None) or {}
    if field not in values:
        return ConstraintEvaluationResultV2(
            outcome=CONSTRAINT_OUTCOME_UNVERIFIABLE_V2,
            detail=f"no authenticated value {field!r} in the request context",
        )
    if values[field] not in allowed:
        return ConstraintEvaluationResultV2(
            outcome=CONSTRAINT_OUTCOME_DENIED_V2, detail=f"value of {field!r} is not an allowed value"
        )
    return ConstraintEvaluationResultV2(outcome=CONSTRAINT_OUTCOME_PASS_V2)


class _Number:
    """A JSON number kept as its exact token (Go json.RawMessage)."""

    __slots__ = ("token",)

    def __init__(self, token: str):
        self.token = token


class _Literal:
    """A JSON true/false/null kept distinct from Python values."""

    __slots__ = ("token",)

    def __init__(self, token: str):
        self.token = token


def _reject_constant(name: str):
    raise ValueError(f"invalid JSON literal {name}")


def _unique_pairs(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON object key {key!r}")
        out[key] = value
    return out


_PARAMS_DECODER = json.JSONDecoder(
    object_pairs_hook=_unique_pairs,
    parse_int=_Number,
    parse_float=_Number,
    parse_constant=_reject_constant,
)


def _go_string(value: str) -> str:
    """Go json decodes an unpaired surrogate escape as U+FFFD."""
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        return "".join("�" if 0xD800 <= ord(c) <= 0xDFFF else c for c in value)
    return value


def _decode_standard_params_v2(data: Optional[bytes], *members: str) -> dict:
    """Strictly decode a params object with exactly the named members,
    rejecting duplicates (at any depth) and trailing data, with numbers kept
    as their exact JSON tokens."""
    if data is None:
        raise ValueError("params are required")
    try:
        text = bytes(data).decode("utf-8")
    except (UnicodeDecodeError, TypeError) as exc:
        raise ValueError("params are not valid UTF-8") from exc
    try:
        fields = _PARAMS_DECODER.decode(text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("params must be one JSON object without duplicate members") from exc
    if not isinstance(fields, dict):
        raise ValueError("params must be one JSON object without duplicate members")
    if len(fields) != len(members) or any(name not in fields for name in members):
        raise ValueError(f"params must have exactly the members {list(members)}")
    return fields


def _v2_integer_token(value: Any) -> int:
    """Go ``v2IntegerField`` on an exact token."""
    if not isinstance(value, _Number):
        raise ValueError("integer is required")
    token = value.token
    digits = token[1:] if token.startswith("-") else token
    if digits == "" or (len(digits) > 1 and digits[0] == "0"):
        raise ValueError(f"integer {token!r} is not canonical")
    if not all("0" <= c <= "9" for c in digits):
        raise ValueError(f"integer {token!r} is not a JSON integer")
    if token == "-0":
        raise ValueError("negative zero is not a canonical integer")
    n = int(token)
    if n > MAX_SAFE_INTEGER or n < -MAX_SAFE_INTEGER:
        raise ValueError(f"integer {token!r} is outside the safe-integer range")
    return n


def _v2_string_value(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("string is required")
    return _go_string(value)


def decode_max_count_params_v2(data: Optional[bytes]) -> tuple[str, int]:
    """Go ``decodeMaxCountParamsV2``: ``(counter, max)`` or ValueError."""
    fields = _decode_standard_params_v2(data, "counter", "max")
    try:
        counter = _v2_string_value(fields["counter"])
    except ValueError:
        counter = None
    if counter is None or not valid_extension_context_name_v2(counter):
        raise ValueError(f"counter must be 1 to {MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes of [a-z0-9_.:-]")
    try:
        maximum = _v2_integer_token(fields["max"])
    except ValueError:
        maximum = -1
    if maximum < 0:
        raise ValueError(f"max must be an integer in 0..{MAX_SAFE_INTEGER}")
    return counter, maximum


def decode_allowed_values_params_v2(data: Optional[bytes]) -> tuple[str, list]:
    """Go ``decodeAllowedValuesParamsV2``: ``(field, allowed)`` or ValueError."""
    fields = _decode_standard_params_v2(data, "allowed", "field")
    try:
        field = _v2_string_value(fields["field"])
    except ValueError:
        field = None
    if field is None or not valid_extension_context_name_v2(field):
        raise ValueError(f"field must be 1 to {MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes of [a-z0-9_.:-]")
    items = fields["allowed"]
    if not isinstance(items, list):
        raise ValueError("allowed must be an array of strings")
    if len(items) == 0 or len(items) > MAX_ALLOWED_VALUES_V2:
        raise ValueError(f"allowed must hold 1 to {MAX_ALLOWED_VALUES_V2} strings")
    allowed: list = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(
                f"allowed values must be unique strings of 1 to {MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2} bytes"
            )
        value = _go_string(item)
        if value == "" or len(value.encode("utf-8")) > MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2 or value in allowed:
            raise ValueError(
                f"allowed values must be unique strings of 1 to {MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2} bytes"
            )
        allowed.append(value)
    return field, allowed


def extension_params_json_v2(c: Any) -> Optional[bytes]:
    """The canonical params object of an extension constraint, or None when
    it carries none."""
    params = getattr(c, "params", None)
    if params is None:
        return None
    return _v2json.canonical(params)


# Imported here so the evaluator registry stays importable on its own.
_ = (valid_prefixed_digest_v2,)
