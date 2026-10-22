"""Protocol v2 closed constraint registry (Go constraints_v2.go, SPEC-v2 §5.2).

v2 defines its own constraint schemas and carries no floating point. The
registered types and their exact wire members are::

    time_window              {"end","start","tz","type"}
    max_amount               {"currency","max_amount_micros","type"}
    max_rate                 {"count","type","window_s"}
    resource_path            {"path_prefix"?,"resource_id","type"}
    ratify.receiver_audience {"params","type"}

Every other type, including the v1 geo and speed types, is unregistered: it
may carry only ``type`` and an optional ``params`` object, decodes, and fails
closed as ``constraint_unknown`` unless an extension evaluator profile is
configured for it. v1 member names on an unregistered type are malformed.

``evaluate_constraint_v2`` evaluates one locally decidable constraint and
signals its outcome with exceptions: :class:`ConstraintUnverifiableError`
(required authenticated input is unavailable), :class:`UnknownConstraintError`
(unregistered type), and :class:`ConstraintDeniedError` (a proven denial).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import _tzdb_v2
from .clock_bounds_v2 import V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS, V2_MAX_RATE_WINDOW_SECONDS
from .errors_v2 import V2ErrorClass, classified
from .limits_v2 import MAX_IDENTIFIER_LENGTH_BYTES
from .resource_path import normalize_resource_path, resource_path_matches, validate_params_value
from .types_v2 import MAX_SAFE_INTEGER, is_int

CONSTRAINT_TIME_WINDOW = "time_window"
CONSTRAINT_MAX_AMOUNT = "max_amount"
CONSTRAINT_MAX_RATE = "max_rate"
CONSTRAINT_RESOURCE_PATH = "resource_path"
CONSTRAINT_RECEIVER_AUDIENCE = "ratify.receiver_audience"

# MaxAudienceIDsV2 bounds each receiver-audience ID array.
MAX_AUDIENCE_IDS_V2 = 64

# TZDBVersionV2: the IANA tzdata release every time_window evaluation uses.
TZDB_VERSION_V2 = _tzdb_v2.TZDB_VERSION_V2

_STRUCTURED = (CONSTRAINT_TIME_WINDOW, CONSTRAINT_MAX_AMOUNT, CONSTRAINT_MAX_RATE, CONSTRAINT_RESOURCE_PATH)


class ConstraintError(Exception):
    """Base class of constraint evaluation outcomes other than pass."""


class ConstraintDeniedError(ConstraintError):
    """A constraint was evaluated and denies the request (constraint_denied)."""


class ConstraintUnverifiableError(ConstraintError):
    """Go ``errConstraintUnverifiable``: required authenticated input is
    unavailable (constraint_unverifiable)."""

    def __init__(self, reason: str):
        super().__init__("constraint_unverifiable: " + reason)
        self.reason = reason


class UnknownConstraintError(ConstraintError):
    """Go ``unknownConstraintError``: an unregistered constraint type
    (constraint_unknown)."""

    def __init__(self, kind: str):
        super().__init__(f'constraint_unknown: unknown constraint type "{kind}"')
        self.kind = kind


@dataclass
class ConstraintV2:
    """One entry of a v2 certificate's ``constraints`` array. Only the
    members of the registered schema for ``type`` are encoded."""

    type: str
    # time_window
    start: str = ""
    end: str = ""
    tz: str = ""
    # max_amount
    currency: str = ""
    max_amount_micros: int = 0
    # max_rate
    count: int = 0
    window_s: int = 0
    # resource_path
    resource_id: str = ""
    path_prefix: str = ""
    # ratify.receiver_audience and unregistered types
    params: Optional[dict] = None

    @classified(V2ErrorClass.MALFORMED)
    def to_canonical_dict(self) -> dict:
        """Go ``ConstraintV2.MarshalJSON``; raises ``ValueError`` when the
        result is not a valid v2 constraint."""
        if not isinstance(self.type, str):
            raise ValueError("constraint type must be a string")
        out: dict[str, Any] = {"type": self.type}
        t = self.type
        if t == CONSTRAINT_TIME_WINDOW:
            out.update(start=self.start, end=self.end, tz=self.tz)
        elif t == CONSTRAINT_MAX_AMOUNT:
            out.update(currency=self.currency, max_amount_micros=self.max_amount_micros)
        elif t == CONSTRAINT_MAX_RATE:
            out.update(count=self.count, window_s=self.window_s)
        elif t == CONSTRAINT_RESOURCE_PATH:
            out["resource_id"] = self.resource_id
            if self.path_prefix != "":
                out["path_prefix"] = self.path_prefix
        elif self.params is not None:
            out["params"] = self.params
        if self.params is not None and t in _STRUCTURED:
            raise ValueError(f"v2 constraint type {t!r} must not carry params")
        validate_v2_constraint_fields(out)
        return out


@dataclass
class ConstraintContextV2:
    """Verifier-authenticated action inputs for registered constraints.

    ``requested_amount_micros`` uses the 10^-6 major-unit scale of
    ``max_amount_micros``. Resource inputs are compared byte for byte after
    the caller applies every decoding and normalization step. Extension maps
    feed registered extension evaluator profiles (SPEC-v2 §5.2)."""

    requested_amount_micros: int = 0
    requested_currency: str = ""
    has_amount: bool = False
    requested_resource_id: str = ""
    requested_path: str = ""
    has_resource: bool = False
    extension_counts: Optional[dict] = None
    extension_values: Optional[dict] = None


def is_registered_constraint_type_v2(t: str) -> bool:
    """Go ``IsRegisteredConstraintTypeV2``."""
    return t in _STRUCTURED or t == CONSTRAINT_RECEIVER_AUDIENCE


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


def _check_v2_nulls(value: Any) -> None:
    """Go ``checkV2Nulls``: no JSON null anywhere outside ``params``."""
    if value is None:
        raise ValueError("null is not allowed in this v2 object")
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "params":
                continue
            _check_v2_nulls(item)
    elif isinstance(value, list):
        for item in value:
            _check_v2_nulls(item)


def _string_field(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("string is required")
    return value


def _integer_field(value: Any) -> int:
    if not is_int(value) or value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
        raise ValueError("integer is required")
    return value


def valid_iso4217_alpha_v2(code: Any) -> bool:
    """Go ``validISO4217AlphaV2``: exactly three ASCII capitals."""
    return isinstance(code, str) and len(code) == 3 and all("A" <= c <= "Z" for c in code)


def valid_time_zone_id_v2(tz: Any) -> bool:
    """Go ``validTimeZoneIDV2``: 1 to 64 bytes of '/'-separated segments of
    [A-Za-z0-9_+-], with no empty, "." or ".." segment."""
    if not isinstance(tz, str) or len(tz) == 0 or _utf8_len(tz) > 64:
        return False
    for segment in tz.split("/"):
        if segment in ("", ".", ".."):
            return False
        for c in segment:
            if not ("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c in "_+-"):
                return False
    return True


def parse_hhmm_v2(s: Any) -> int:
    """Go ``parseHHMMV2``: exactly two-digit hours 00..23 and minutes 00..59;
    returns minutes since midnight. Raises ``ValueError``."""
    if not isinstance(s, str) or len(s) != 5 or s[2] != ":":
        raise ValueError(f"expected HH:MM, got {s!r}")
    for i in (0, 1, 3, 4):
        if not "0" <= s[i] <= "9":
            raise ValueError(f"expected HH:MM, got {s!r}")
    h = int(s[0:2])
    m = int(s[3:5])
    if h > 23 or m > 59:
        raise ValueError(f"out-of-range HH:MM {s!r}")
    return h * 60 + m


def _exact(fields: dict, t: str, required: tuple, optional: tuple = ()) -> None:
    for key in fields:
        if key != "type" and key not in required and key not in optional:
            raise ValueError(f"field {key!r} is not allowed for constraint type {t!r}")
    for name in required:
        if name not in fields:
            raise ValueError(f"constraint type {t!r} requires field {name!r}")


def _validate_v2_receiver_audience(params: Any) -> None:
    if not isinstance(params, dict):
        raise ValueError("receiver audience requires params object")
    for key in params:
        if key not in ("exact_receiver_ids", "trust_domain_ids", "max_membership_age_seconds"):
            raise ValueError(f"unknown receiver audience parameter {key!r}")
    exact = params.get("exact_receiver_ids")
    domains = params.get("trust_domain_ids")
    if not isinstance(exact, list) or not isinstance(domains, list):
        raise ValueError("receiver audience requires exact_receiver_ids and trust_domain_ids arrays")
    # Go decodes a JSON null array element into "" and a non-string fails.
    for values in (exact, domains):
        for value in values:
            if value is not None and not isinstance(value, str):
                raise ValueError("receiver audience requires exact_receiver_ids and trust_domain_ids arrays")
    exact = ["" if v is None else v for v in exact]
    domains = ["" if v is None else v for v in domains]
    if len(exact) + len(domains) == 0:
        raise ValueError("receiver audience must name an exact receiver or trust domain")
    for values in (exact, domains):
        if len(values) > MAX_AUDIENCE_IDS_V2:
            raise ValueError(f"receiver audience arrays hold at most {MAX_AUDIENCE_IDS_V2} IDs")
        seen = set()
        for value in values:
            if value == "" or _utf8_len(value) > MAX_IDENTIFIER_LENGTH_BYTES or value in seen:
                raise ValueError(f"receiver audience IDs must be unique and 1 to {MAX_IDENTIFIER_LENGTH_BYTES} bytes")
            seen.add(value)
    has_age = "max_membership_age_seconds" in params
    age = params.get("max_membership_age_seconds")
    if domains and (not has_age or age is None):
        raise ValueError("receiver audience trust domains require max_membership_age_seconds")
    if has_age:
        if not is_int(age) or age <= 0 or age > V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS:
            raise ValueError(
                f"max_membership_age_seconds must be an integer in 1..{V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS}")
    if not domains and has_age:
        raise ValueError("receiver audience without trust domains must omit max_membership_age_seconds")


def validate_v2_constraint_fields(fields: Any) -> None:
    """Go ``validateV2ConstraintFields`` over one decoded constraint object.
    Raises ``ValueError``."""
    _check_v2_nulls(fields)
    if not isinstance(fields, dict):
        raise ValueError("constraint must be an object")
    kind = fields.get("type")
    if not isinstance(kind, str) or kind == "":
        raise ValueError("constraint type must be a non-empty string")
    t = kind
    if t == CONSTRAINT_TIME_WINDOW:
        _exact(fields, t, ("start", "end", "tz"))
        for name in ("start", "end"):
            value = fields[name]
            if not isinstance(value, str):
                raise ValueError(f"time_window {name} must be a string")
            parse_hhmm_v2(value)
        if not isinstance(fields["tz"], str) or not valid_time_zone_id_v2(fields["tz"]):
            raise ValueError("time_window tz must be 1 to 64 bytes of /-separated [A-Za-z0-9_+-] segments")
    elif t == CONSTRAINT_MAX_AMOUNT:
        _exact(fields, t, ("currency", "max_amount_micros"))
        if not valid_iso4217_alpha_v2(fields["currency"]):
            raise ValueError("max_amount currency must be an ISO-4217 alphabetic code")
        amount = fields["max_amount_micros"]
        if not is_int(amount) or amount < 0 or amount > MAX_SAFE_INTEGER:
            raise ValueError("max_amount_micros must be a nonnegative safe integer")
    elif t == CONSTRAINT_MAX_RATE:
        _exact(fields, t, ("count", "window_s"))
        count = fields["count"]
        if not is_int(count) or count <= 0 or count > MAX_SAFE_INTEGER:
            raise ValueError("max_rate count must be a positive safe integer")
        window = fields["window_s"]
        if not is_int(window) or window <= 0 or window > V2_MAX_RATE_WINDOW_SECONDS:
            raise ValueError(f"max_rate window_s must be an integer in 1..{V2_MAX_RATE_WINDOW_SECONDS}")
    elif t == CONSTRAINT_RESOURCE_PATH:
        _exact(fields, t, ("resource_id",), ("path_prefix",))
        rid = fields["resource_id"]
        if not isinstance(rid, str) or rid == "" or _utf8_len(rid) > MAX_IDENTIFIER_LENGTH_BYTES:
            raise ValueError("resource_path resource_id must be a non-empty string within MAX_IDENTIFIER_LENGTH_BYTES")
        if "path_prefix" in fields:
            prefix = fields["path_prefix"]
            if not isinstance(prefix, str) or prefix == "":
                raise ValueError("resource_path path_prefix must be a non-empty string when present")
    elif t == CONSTRAINT_RECEIVER_AUDIENCE:
        _exact(fields, t, ("params",))
        _validate_v2_receiver_audience(fields["params"])
    else:
        if _utf8_len(kind) > MAX_IDENTIFIER_LENGTH_BYTES:
            raise ValueError("unregistered constraint type exceeds MAX_IDENTIFIER_LENGTH_BYTES")
        _exact(fields, t, (), ("params",))
        if "params" in fields:
            params = fields["params"]
            if not isinstance(params, dict):
                raise ValueError("unregistered constraint params must be an object")
            validate_params_value(params, 0)


@classified(V2ErrorClass.MALFORMED)
def constraint_v2_from_fields(fields: Any) -> ConstraintV2:
    """Go ``ConstraintV2.UnmarshalJSON``: validate, then decode."""
    validate_v2_constraint_fields(fields)
    t = fields["type"]
    c = ConstraintV2(type=t)
    if t == CONSTRAINT_TIME_WINDOW:
        c.start, c.end, c.tz = fields["start"], fields["end"], fields["tz"]
    elif t == CONSTRAINT_MAX_AMOUNT:
        c.currency, c.max_amount_micros = fields["currency"], fields["max_amount_micros"]
    elif t == CONSTRAINT_MAX_RATE:
        c.count, c.window_s = fields["count"], fields["window_s"]
    elif t == CONSTRAINT_RESOURCE_PATH:
        c.resource_id = fields["resource_id"]
        c.path_prefix = fields.get("path_prefix", "")
    elif "params" in fields:
        c.params = fields["params"]
    return c


# ---------------------------------------------------------------------------
# Time zones


@dataclass(frozen=True)
class V2LocalTime:
    """Local wall-clock time of a Unix second in a pinned IANA zone (Go
    ``now.In(loc)``, ``Zone()`` and ``ZoneBounds()``). ``zone_end`` is the Unix
    second at which the current zone period ends, or ``None`` when it has no
    end (Go's zero ``ZoneBounds`` end)."""

    year: int
    month: int
    day: int
    hour: int
    minute: int
    second: int
    utc_offset_seconds: int
    zone_end: Optional[int]


def load_v2_time_zone(configured_version: str, tz: str) -> _tzdb_v2.TimeZoneV2:
    """Go ``loadV2TimeZone``: check the configured tzdb version, then load
    the zone from the pinned database. Raises ``ValueError``."""
    if not isinstance(configured_version, str) or configured_version == "":
        raise ValueError("no tzdb_version is configured")
    if configured_version != TZDB_VERSION_V2:
        raise ValueError(
            f"configured tzdb_version {configured_version!r} differs from the loaded IANA tzdata {TZDB_VERSION_V2}")
    if not valid_time_zone_id_v2(tz):
        raise ValueError(f"time zone {tz!r} is not in IANA tzdata {TZDB_VERSION_V2}")
    return _tzdb_v2.load_zone(tz)


def local_time_in_zone_v2(zone: _tzdb_v2.TimeZoneV2, unix_now: int) -> V2LocalTime:
    """The wall-clock reading of ``unix_now`` in ``zone``."""
    _, offset, _, end, _ = zone.lookup(unix_now)
    local = unix_now + offset
    year, month, day = _tzdb_v2.civil_from_days(local // 86400)
    rem = local % 86400
    return V2LocalTime(year, month, day, rem // 3600, (rem % 3600) // 60, rem % 60, offset,
                       None if end == _tzdb_v2._OMEGA else end)


def local_time_v2(tzdb_version: str, tz: str, unix_now: int) -> V2LocalTime:
    """Load ``tz`` exactly as :func:`load_v2_time_zone` does and return the
    local time of ``unix_now`` there. Raises :class:`ConstraintUnverifiableError`
    when the zone cannot be evaluated."""
    if not is_int(unix_now):
        raise ConstraintUnverifiableError("evaluation time must be an integer")
    try:
        zone = load_v2_time_zone(tzdb_version, tz)
    except ValueError as exc:
        raise ConstraintUnverifiableError(f"time zone {tz!r} cannot be evaluated: {exc}") from exc
    return local_time_in_zone_v2(zone, unix_now)


def days_from_civil_v2(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01; month and day normalize like Go ``time.Date``."""
    return _tzdb_v2.days_from_civil(year, month, day)


# ---------------------------------------------------------------------------
# Evaluation


def evaluate_constraint_v2(c: ConstraintV2, ctx: ConstraintContextV2, tzdb_version: str, now: int) -> None:
    """Go ``evaluateConstraintV2``. Returns ``None`` on pass; raises
    :class:`ConstraintUnverifiableError`, :class:`UnknownConstraintError`, or
    :class:`ConstraintDeniedError`. ``max_rate`` and
    ``ratify.receiver_audience`` belong to their dedicated stages and are
    unverifiable here."""
    t = c.type
    if t == CONSTRAINT_RESOURCE_PATH:
        # The signed path_prefix is checked before any request input.
        if c.path_prefix != "":
            try:
                normalize_resource_path(c.path_prefix)
            except ValueError as exc:
                raise ConstraintDeniedError(f"malformed path_prefix: {exc}") from exc
        if not ctx.has_resource or ctx.requested_resource_id == "":
            raise ConstraintUnverifiableError("no requested resource in context")
        if ctx.requested_resource_id != c.resource_id:
            raise ConstraintDeniedError("requested resource does not match the authorized resource")
        if c.path_prefix == "":
            return
        if ctx.requested_path == "":
            raise ConstraintUnverifiableError("no requested path in context")
        try:
            normalize_resource_path(ctx.requested_path)
        except ValueError as exc:
            raise ConstraintDeniedError(f"invalid requested path: {exc}") from exc
        if not resource_path_matches(c.path_prefix, ctx.requested_path):
            raise ConstraintDeniedError(
                f'requested path "{ctx.requested_path}" is outside the authorized prefix "{c.path_prefix}"')
        return
    if t == CONSTRAINT_TIME_WINDOW:
        local = local_time_v2(tzdb_version, c.tz, now)
        try:
            start = parse_hhmm_v2(c.start)
            end = parse_hhmm_v2(c.end)
        except ValueError as exc:
            raise ConstraintDeniedError(str(exc)) from exc
        cur = local.hour * 60 + local.minute
        if (start <= end and (cur < start or cur > end)) or (start > end and cur < start and cur > end):
            raise ConstraintDeniedError(
                f"current {local.hour:02d}:{local.minute:02d} is outside [{c.start}, {c.end}] {c.tz}")
        return
    if t == CONSTRAINT_MAX_AMOUNT:
        if not ctx.has_amount:
            raise ConstraintUnverifiableError("no requested amount in context")
        amount = ctx.requested_amount_micros
        if not is_int(amount) or amount < 0 or amount > MAX_SAFE_INTEGER or not valid_iso4217_alpha_v2(ctx.requested_currency):
            raise ConstraintUnverifiableError(
                "requested amount is not a nonnegative safe integer in ISO-4217 micro-units")
        if ctx.requested_currency != c.currency:
            raise ConstraintDeniedError(
                f"currency mismatch: requested {ctx.requested_currency!r}, constraint {c.currency!r}")
        if amount > c.max_amount_micros:
            raise ConstraintDeniedError(f"amount {amount} exceeds max {c.max_amount_micros} micro-units of {c.currency}")
        return
    if t in (CONSTRAINT_MAX_RATE, CONSTRAINT_RECEIVER_AUDIENCE):
        raise ConstraintUnverifiableError(f"{t} requires its dedicated post-status stage")
    raise UnknownConstraintError(t)


__all__ = [
    "CONSTRAINT_MAX_AMOUNT", "CONSTRAINT_MAX_RATE", "CONSTRAINT_RECEIVER_AUDIENCE", "CONSTRAINT_RESOURCE_PATH",
    "CONSTRAINT_TIME_WINDOW", "MAX_AUDIENCE_IDS_V2", "TZDB_VERSION_V2", "ConstraintContextV2",
    "ConstraintDeniedError", "ConstraintError", "ConstraintUnverifiableError", "ConstraintV2", "UnknownConstraintError",
    "V2LocalTime", "constraint_v2_from_fields", "days_from_civil_v2", "evaluate_constraint_v2",
    "is_registered_constraint_type_v2", "load_v2_time_zone", "local_time_in_zone_v2", "local_time_v2",
    "parse_hhmm_v2", "valid_iso4217_alpha_v2", "valid_time_zone_id_v2", "validate_v2_constraint_fields",
]
