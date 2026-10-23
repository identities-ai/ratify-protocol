"""The closed v2 constraint registry and its local evaluation (SPEC-v2 §5.2,
Go constraints_v2.go), including time_window evaluation against the pinned
IANA tzdata 2025c package."""
from __future__ import annotations

import pytest

from ratify_protocol_v2 import _tzdb_v2
from ratify_protocol_v2 import constraints_v2 as c2


def ctx(**kw) -> c2.ConstraintContextV2:
    return c2.ConstraintContextV2(**kw)


def outcome(constraint, context, tzdb=c2.TZDB_VERSION_V2, now=1800000000):
    try:
        c2.evaluate_constraint_v2(constraint, context, tzdb, now)
    except c2.ConstraintUnverifiableError:
        return "unverifiable"
    except c2.UnknownConstraintError:
        return "unknown"
    except c2.ConstraintDeniedError:
        return "denied"
    return "pass"


def test_pinned_tzdata_release():
    import tzdata

    assert c2.TZDB_VERSION_V2 == "2025c" == tzdata.IANA_VERSION


@pytest.mark.parametrize("fields", [
    {"type": "time_window", "start": "09:00", "end": "17:00", "tz": "UTC"},
    {"type": "max_amount", "currency": "USD", "max_amount_micros": 0},
    {"type": "max_rate", "count": 1, "window_s": 86400},
    {"type": "resource_path", "resource_id": "r"},
    {"type": "resource_path", "resource_id": "r", "path_prefix": "/a"},
    {"type": "ratify.receiver_audience", "params": {"exact_receiver_ids": ["x"], "trust_domain_ids": []}},
    {"type": "com.example.thing"},
    {"type": "geo_circle", "params": {"anything": [1, "x", None]}},
])
def test_registry_accepts(fields):
    constraint = c2.constraint_v2_from_fields(fields)
    assert constraint.to_canonical_dict() == fields


@pytest.mark.parametrize("fields", [
    {"type": "time_window", "start": "9:00", "end": "17:00", "tz": "UTC"},
    {"type": "time_window", "start": "09:00", "end": "24:00", "tz": "UTC"},
    {"type": "time_window", "start": "09:00", "end": "17:00", "tz": "../etc"},
    {"type": "max_amount", "currency": "usd", "max_amount_micros": 1},
    {"type": "max_amount", "currency": "USD", "max_amount": 1},
    {"type": "max_amount", "currency": "USD", "max_amount_micros": True},
    {"type": "max_rate", "count": 0, "window_s": 60},
    {"type": "max_rate", "count": 1, "window_s": 86401},
    {"type": "resource_path", "resource_id": ""},
    {"type": "resource_path", "resource_id": "r", "path_prefix": ""},
    {"type": "ratify.receiver_audience", "params": {"exact_receiver_ids": [], "trust_domain_ids": []}},
    {"type": "ratify.receiver_audience", "params": {"exact_receiver_ids": [], "trust_domain_ids": ["d"]}},
    {"type": "geo_circle", "lat": 1},
    {"type": "time_window", "start": "09:00", "end": "17:00", "tz": "UTC", "params": {}},
    {"type": ""},
    {"type": "x", "params": None},
])
def test_registry_rejects(fields):
    with pytest.raises(ValueError):
        c2.constraint_v2_from_fields(fields)


def test_resource_path_precedence():
    c = c2.ConstraintV2(type="resource_path", resource_id="customer/123", path_prefix="/v1/customers")
    assert outcome(c, ctx()) == "unverifiable"
    assert outcome(c, ctx(has_resource=True, requested_resource_id="other", requested_path="/v1/customers/1")) == "denied"
    assert outcome(c, ctx(has_resource=True, requested_resource_id="customer/123")) == "unverifiable"
    assert outcome(c, ctx(has_resource=True, requested_resource_id="customer/123", requested_path="/v1/customers/1")) == "pass"
    assert outcome(c, ctx(has_resource=True, requested_resource_id="customer/123", requested_path="/v1/customers-x")) == "denied"
    assert outcome(c, ctx(has_resource=True, requested_resource_id="customer/123", requested_path="/v1//x")) == "denied"
    bad_prefix = c2.ConstraintV2(type="resource_path", resource_id="customer/123", path_prefix="v1")
    # The signed prefix is checked before any request input.
    assert outcome(bad_prefix, ctx()) == "denied"


def test_max_amount_uses_integer_micro_units():
    c = c2.ConstraintV2(type="max_amount", currency="USD", max_amount_micros=2500000)
    assert outcome(c, ctx()) == "unverifiable"
    assert outcome(c, ctx(has_amount=True, requested_amount_micros=2500000, requested_currency="USD")) == "pass"
    assert outcome(c, ctx(has_amount=True, requested_amount_micros=2500001, requested_currency="USD")) == "denied"
    assert outcome(c, ctx(has_amount=True, requested_amount_micros=1, requested_currency="EUR")) == "denied"
    assert outcome(c, ctx(has_amount=True, requested_amount_micros=1.0, requested_currency="USD")) == "unverifiable"
    assert outcome(c, ctx(has_amount=True, requested_amount_micros=2**53, requested_currency="USD")) == "unverifiable"


def test_deferred_and_unknown_types():
    assert outcome(c2.ConstraintV2(type="max_rate", count=1, window_s=1), ctx()) == "unverifiable"
    assert outcome(c2.ConstraintV2(type="ratify.receiver_audience", params={}), ctx()) == "unverifiable"
    assert outcome(c2.ConstraintV2(type="com.example.x"), ctx()) == "unknown"


def test_time_window_requires_the_pinned_tzdb_version():
    c = c2.ConstraintV2(type="time_window", start="00:00", end="23:59", tz="America/New_York")
    assert outcome(c, ctx()) == "pass"
    assert outcome(c, ctx(), tzdb="") == "unverifiable"
    assert outcome(c, ctx(), tzdb="2025b") == "unverifiable"
    assert outcome(c2.ConstraintV2(type="time_window", start="00:00", end="23:59", tz="Mars/Olympus_Mons"), ctx()) == "unverifiable"
    assert outcome(c2.ConstraintV2(type="time_window", start="00:00", end="23:59", tz="Local"), ctx()) == "unverifiable"
    assert outcome(c2.ConstraintV2(type="time_window", start="00:00", end="23:59", tz="America"), ctx()) == "unverifiable"


def test_installed_tzdata_of_another_release_fails_closed(monkeypatch):
    import tzdata

    monkeypatch.setattr(_tzdb_v2, "_cache", {})
    monkeypatch.setattr(tzdata, "IANA_VERSION", "2024a")
    c = c2.ConstraintV2(type="time_window", start="00:00", end="23:59", tz="UTC")
    assert outcome(c, ctx()) == "unverifiable"


def test_time_window_local_minutes_and_midnight_wrap():
    # 1800000000 is 2027-01-15T08:00:00Z, 03:00 in New York (EST, UTC-5).
    local = c2.local_time_v2("2025c", "America/New_York", 1800000000)
    assert (local.year, local.month, local.day, local.hour, local.minute) == (2027, 1, 15, 3, 0)
    assert local.utc_offset_seconds == -5 * 3600
    wrap = c2.ConstraintV2(type="time_window", start="22:00", end="06:00", tz="America/New_York")
    assert outcome(wrap, ctx()) == "pass"
    day = c2.ConstraintV2(type="time_window", start="09:00", end="17:00", tz="America/New_York")
    assert outcome(day, ctx()) == "denied"
    edge = c2.ConstraintV2(type="time_window", start="03:00", end="03:00", tz="America/New_York")
    assert outcome(edge, ctx(), now=1800000000 + 59) == "pass"
    assert outcome(edge, ctx(), now=1800000000 + 60) == "denied"


def test_zone_transitions_match_the_go_reference():
    # 2026-03-08 07:00 UTC is the US spring-forward instant (Go tzdbv2 test).
    before = c2.local_time_v2("2025c", "America/New_York", 1772953199)
    assert before.utc_offset_seconds == -5 * 3600 and before.zone_end == 1772953200
    after = c2.local_time_v2("2025c", "America/New_York", 1772953200)
    assert after.utc_offset_seconds == -4 * 3600
    assert c2.local_time_v2("2025c", "UTC", 1800000000).zone_end is None
    # The last instant of the timestamp domain still evaluates.
    assert c2.local_time_v2("2025c", "Pacific/Kiritimati", 253402300799).year == 10000


@pytest.mark.parametrize("tz", ["america/new_york", "AMERICA/NEW_YORK", "America/New_york", "utc", "us/eastern"])
def test_time_window_zone_names_match_exactly(tz):
    # A zone name that differs only in case is not in the database (SPEC-v2
    # §5.2). The lookup must not depend on a case-insensitive filesystem
    # (macOS, Windows): a window that would pass in America/New_York is
    # unverifiable under any case variant.
    window = c2.ConstraintV2(type="time_window", start="02:00", end="03:30", tz=tz)
    assert outcome(window, ctx()) == "unverifiable"
    exact = c2.ConstraintV2(type="time_window", start="02:00", end="03:30", tz="America/New_York")
    assert outcome(exact, ctx()) == "pass"


def test_days_from_civil_normalizes_like_go():
    assert c2.days_from_civil_v2(1970, 1, 1) == 0
    assert c2.days_from_civil_v2(2027, 1, 32) == c2.days_from_civil_v2(2027, 2, 1)
    assert c2.days_from_civil_v2(2027, 13, 1) == c2.days_from_civil_v2(2028, 1, 1)
