"""Constraint evaluation — mirrors Go's constraints.go exactly.

Every semantic must produce the same verdict for the same inputs, or
cross-language conformance fails.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .types import Constraint, DelegationCert, VerifierContext


def evaluate_constraints(
    cert: DelegationCert,
    ctx: VerifierContext | None,
    now_sec: int,
) -> str | None:
    """Run every Constraint on cert against the caller-supplied
    VerifierContext. Return None iff all pass; error message otherwise.

    Fail-closed: unknown Type or missing required context field causes
    rejection.
    """
    if ctx is None:
        ctx = VerifierContext()
    for i, c in enumerate(cert.constraints or []):
        err = _evaluate_constraint(c, cert.cert_id, ctx, now_sec)
        if err is not None:
            return f"constraint[{i}] ({c.type}): {err}"
    return None


def _evaluate_constraint(
    c: Constraint,
    cert_id: str,
    ctx: VerifierContext,
    now_sec: int,
) -> str | None:
    t = c.type
    if t == "geo_circle":
        if ctx.current_lat is None or ctx.current_lon is None:
            return "constraint_unverifiable: no current location in context"
        d = _haversine_meters(ctx.current_lat, ctx.current_lon, c.lat, c.lon)
        if d > c.radius_m:
            return f"outside allowed radius: {d:.1f}m > {c.radius_m:.1f}m"
        return None

    if t == "geo_polygon":
        if ctx.current_lat is None or ctx.current_lon is None:
            return "constraint_unverifiable: no current location in context"
        if not c.points or len(c.points) < 3:
            return "polygon has fewer than 3 points"
        # v1 polygon is defined over equirectangular projection — correct
        # for small regions, incorrect for anti-meridian-crossing shapes.
        # Fail closed rather than silently return wrong answers. SPEC §5.7.2
        # documents the v1 small-region limitation; geodesic semantics are v2.
        if _polygon_spans_antimeridian(c.points):
            return "geo_polygon spans >180° longitude — v1 semantics are undefined for anti-meridian-crossing polygons (see SPEC §5.7.2)"
        if not _point_in_polygon(ctx.current_lat, ctx.current_lon, c.points):
            return "outside allowed polygon"
        return None

    if t == "geo_bbox":
        if ctx.current_lat is None or ctx.current_lon is None:
            return "constraint_unverifiable: no current location in context"
        # Format mirrors Go's %.6f — cross-SDK error_reason parity requires it.
        if ctx.current_lat < c.min_lat or ctx.current_lat > c.max_lat:
            return f"latitude {ctx.current_lat:.6f} outside [{c.min_lat:.6f}, {c.max_lat:.6f}]"
        # Anti-meridian-aware longitude check (SPEC §5.7.2).
        #   min_lon <= max_lon → ordinary bbox, lon must be in [min_lon, max_lon]
        #   min_lon >  max_lon → bbox wraps the 180° meridian (e.g.,
        #     min_lon=170, max_lon=-170 = "from 170°E through 180 to -170°W")
        #     — inside iff lon >= min_lon OR lon <= max_lon.
        if c.min_lon <= c.max_lon:
            if ctx.current_lon < c.min_lon or ctx.current_lon > c.max_lon:
                return f"longitude {ctx.current_lon:.6f} outside [{c.min_lon:.6f}, {c.max_lon:.6f}]"
        else:
            if ctx.current_lon < c.min_lon and ctx.current_lon > c.max_lon:
                return f"longitude {ctx.current_lon:.6f} outside wrapped [{c.min_lon:.6f}, {c.max_lon:.6f}]"
        has_alt = c.min_alt_m != 0.0 or c.max_alt_m != 0.0
        if has_alt:
            if ctx.current_alt_m is None:
                return "constraint_unverifiable: no altitude in context but bbox has altitude bounds"
            if ctx.current_alt_m < c.min_alt_m or ctx.current_alt_m > c.max_alt_m:
                return f"altitude {ctx.current_alt_m:.1f}m outside [{c.min_alt_m:.1f}m, {c.max_alt_m:.1f}m]"
        return None

    if t == "time_window":
        if not c.tz or not c.start or not c.end:
            return "malformed time_window: tz/start/end required"
        start = _parse_hhmm(c.start)
        end = _parse_hhmm(c.end)
        if start is None:
            return f"bad start time: {c.start}"
        if end is None:
            return f"bad end time: {c.end}"
        try:
            zone = ZoneInfo(c.tz)
        except ZoneInfoNotFoundError:
            return f'unknown timezone "{c.tz}"'
        local = datetime.fromtimestamp(now_sec, tz=timezone.utc).astimezone(zone)
        cur = local.hour * 60 + local.minute
        if start <= end:
            if cur < start or cur > end:
                return f"current {local.hour:02d}:{local.minute:02d} outside [{c.start}, {c.end}] {c.tz}"
        else:
            # Wrapping window (e.g. 22:00 to 06:00).
            if cur < start and cur > end:
                return f"current {local.hour:02d}:{local.minute:02d} outside wrapped [{c.start}, {c.end}] {c.tz}"
        return None

    if t == "max_speed_mps":
        if ctx.current_speed_mps is None:
            return "constraint_unverifiable: no current speed in context"
        if ctx.current_speed_mps > c.max_mps:
            return f"speed {ctx.current_speed_mps:.2f}mps exceeds max {c.max_mps:.2f}mps"
        return None

    if t == "max_amount":
        if ctx.requested_amount is None or ctx.requested_currency is None:
            return "constraint_unverifiable: no requested amount in context"
        if ctx.requested_currency != c.currency:
            return f'currency mismatch: requested "{ctx.requested_currency}", constraint "{c.currency}"'
        if ctx.requested_amount > c.max_amount:
            return f"amount {ctx.requested_amount:.2f} {ctx.requested_currency} exceeds max {c.max_amount:.2f} {c.currency}"
        return None

    if t == "max_rate":
        if ctx.invocations_in_window is None:
            return "constraint_unverifiable: no rate counter in context"
        if c.count <= 0 or c.window_s <= 0:
            return "malformed max_rate: count and window_s must be positive"
        got = ctx.invocations_in_window(cert_id, c.window_s)
        if got >= c.count:
            return f"rate limit exceeded: {got} invocations in last {c.window_s}s (max {c.count})"
        return None

    # Sentinel prefix lets verify.py route to identity_status=constraint_unknown.
    # Matches Go reference unknownConstraintError shape.
    return f'constraint_unknown: unknown constraint type "{t}"'


# ---- helpers ----


def _haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance on a sphere (WGS-84 mean radius)."""
    earth_radius_m = 6371000.0
    rad = math.pi / 180
    d_lat = (lat2 - lat1) * rad
    d_lon = (lon2 - lon1) * rad
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(lat1 * rad) * math.cos(lat2 * rad) * math.sin(d_lon / 2) ** 2
    )
    return 2 * earth_radius_m * math.asin(min(1.0, math.sqrt(a)))


def _polygon_spans_antimeridian(points: list[list[float]]) -> bool:
    """Return True if the polygon's longitudes span more than 180°.

    The only way to span more than half the globe in longitude is to
    cross the anti-meridian, and equirectangular ray-casting can't handle
    that — so we refuse these polygons up-front (fail-closed) rather than
    silently compute wrong inclusion. Mirrors Go's polygonSpansAntimeridian.
    """
    if len(points) < 3:
        return False
    min_lon = points[0][1]
    max_lon = points[0][1]
    for p in points:
        if p[1] < min_lon:
            min_lon = p[1]
        if p[1] > max_lon:
            max_lon = p[1]
    return (max_lon - min_lon) > 180


def _point_in_polygon(lat: float, lon: float, poly: list[list[float]]) -> bool:
    """Ray casting in equirectangular projection. Fine for small polygons."""
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        yi, xi = poly[i][0], poly[i][1]  # lat, lon
        yj, xj = poly[j][0], poly[j][1]
        if ((yi > lat) != (yj > lat)) and lon < (xj - xi) * (lat - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def _parse_hhmm(s: str) -> int | None:
    if len(s) != 5 or s[2] != ":":
        return None
    try:
        h = int(s[:2])
        m = int(s[3:])
    except ValueError:
        return None
    if h < 0 or h > 23 or m < 0 or m > 59:
        return None
    return h * 60 + m
