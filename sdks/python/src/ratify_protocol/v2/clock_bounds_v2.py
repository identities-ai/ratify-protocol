"""Protocol v2 configuration and clock bounds (Go clock_bounds_v2.go, SPEC-v2 §2.5).

Every time value is an integer number of Unix seconds. Every deadline is
exclusive: a value is current only while ``now < deadline``.
"""
from __future__ import annotations

from .errors_v2 import V2Error, V2ErrorClass
from .types_v2 import is_int

V2_MAX_TIMESTAMP_SECONDS = 253402300799
V2_MAX_FUTURE_SKEW_SECONDS = 300
V2_MAX_CHALLENGE_AGE_SECONDS = 300
V2_MAX_STATUS_LIFETIME_SECONDS = 86400
V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS = 86400
V2_MAX_RATE_WINDOW_SECONDS = 86400
V2_MAX_DELEGATION_LIFETIME_SECONDS = 315360000


def valid_v2_timestamp(t: object) -> bool:
    """Go ``validV2Timestamp``: an integer in 0..253402300799."""
    return is_int(t) and 0 <= t <= V2_MAX_TIMESTAMP_SECONDS


def checked_add_v2(a: int, b: int) -> tuple[int, bool]:
    """Go ``checkedAddV2``: (sum, ok); ok is False outside the timestamp domain."""
    if not is_int(a) or not is_int(b) or a < 0 or b < 0 or a > V2_MAX_TIMESTAMP_SECONDS or b > V2_MAX_TIMESTAMP_SECONDS:
        return 0, False
    return a + b, True


def v2_challenge_time_current(now: int, issued_at: int, expires_at: int, max_age: int, future_skew: int) -> bool:
    """Go ``v2ChallengeTimeCurrent`` (exclusive deadlines)."""
    if not valid_v2_timestamp(now) or not valid_v2_timestamp(issued_at) or not valid_v2_timestamp(expires_at):
        return False
    if issued_at > now and issued_at - now > future_skew:
        return False
    age_deadline, ok = checked_add_v2(issued_at, max_age)
    return ok and now < expires_at and now < age_deadline


def validate_v2_freshness_configuration(now: int, max_age_seconds: int, future_skew_seconds: int) -> None:
    """Go ``validateV2FreshnessConfiguration`` (configuration_invalid)."""
    if not valid_v2_timestamp(now):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, f"v2 verifier time is outside 0..{V2_MAX_TIMESTAMP_SECONDS}")
    if not is_int(max_age_seconds) or max_age_seconds < 1 or max_age_seconds > V2_MAX_CHALLENGE_AGE_SECONDS:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                      f"v2 challenge maximum age must be 1..{V2_MAX_CHALLENGE_AGE_SECONDS} seconds")
    if not is_int(future_skew_seconds) or future_skew_seconds < 0 or future_skew_seconds > V2_MAX_FUTURE_SKEW_SECONDS:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                      f"v2 future skew must be 0..{V2_MAX_FUTURE_SKEW_SECONDS} seconds")
