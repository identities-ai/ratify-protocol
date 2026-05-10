// Constraint evaluation — mirrors the Go reference constraints.go exactly.
// Every semantic must produce the same verdict for the same inputs, or
// cross-language conformance fails.

import type {
  Constraint,
  DelegationCert,
  VerifierContext,
} from "./types.js";

/**
 * Run every Constraint on cert against the caller-supplied VerifierContext.
 * Returns null iff all pass; an error string otherwise.
 * Fail-closed: an unknown Type or a constraint whose required context field
 * is absent causes rejection.
 */
export function evaluateConstraints(
  cert: DelegationCert,
  ctx: VerifierContext,
  nowSec: number,
): string | null {
  const list = cert.constraints ?? [];
  for (let i = 0; i < list.length; i++) {
    const err = evaluateConstraint(list[i]!, cert.cert_id, ctx, nowSec);
    if (err !== null) {
      return `constraint[${i}] (${list[i]!.type}): ${err}`;
    }
  }
  return null;
}

function evaluateConstraint(
  c: Constraint,
  certID: string,
  ctx: VerifierContext,
  nowSec: number,
): string | null {
  switch (c.type) {
    case "geo_circle": {
      if (ctx.current_lat === undefined || ctx.current_lon === undefined) {
        return "constraint_unverifiable: no current location in context";
      }
      if (c.lat === undefined || c.lon === undefined || c.radius_m === undefined) {
        return "malformed geo_circle: lat/lon/radius_m required";
      }
      const d = haversineMeters(ctx.current_lat, ctx.current_lon, c.lat, c.lon);
      if (d > c.radius_m) {
        return `outside allowed radius: ${d.toFixed(1)}m > ${c.radius_m.toFixed(1)}m`;
      }
      return null;
    }

    case "geo_polygon": {
      if (ctx.current_lat === undefined || ctx.current_lon === undefined) {
        return "constraint_unverifiable: no current location in context";
      }
      if (!c.points || c.points.length < 3) {
        return "polygon has fewer than 3 points";
      }
      // v1 polygon is defined over equirectangular projection — correct
      // for small regions, incorrect for anti-meridian-crossing shapes.
      // Fail closed rather than silently return wrong answers. SPEC §5.7.2
      // documents the v1 small-region limitation; geodesic semantics are v2.
      if (polygonSpansAntimeridian(c.points)) {
        return "geo_polygon spans >180° longitude — v1 semantics are undefined for anti-meridian-crossing polygons (see SPEC §5.7.2)";
      }
      if (!pointInPolygon(ctx.current_lat, ctx.current_lon, c.points)) {
        return "outside allowed polygon";
      }
      return null;
    }

    case "geo_bbox": {
      if (ctx.current_lat === undefined || ctx.current_lon === undefined) {
        return "constraint_unverifiable: no current location in context";
      }
      if (
        c.min_lat === undefined ||
        c.min_lon === undefined ||
        c.max_lat === undefined ||
        c.max_lon === undefined
      ) {
        return "malformed geo_bbox: min/max lat/lon required";
      }
      // Format mirrors Go's %.6f — cross-SDK error_reason parity requires it.
      if (ctx.current_lat < c.min_lat || ctx.current_lat > c.max_lat) {
        return `latitude ${ctx.current_lat.toFixed(6)} outside [${c.min_lat.toFixed(6)}, ${c.max_lat.toFixed(6)}]`;
      }
      // Anti-meridian-aware longitude check (SPEC §5.7.2).
      //   min_lon <= max_lon → ordinary bbox, lon must be in [min_lon, max_lon]
      //   min_lon >  max_lon → bbox wraps the 180° meridian (e.g.,
      //     min_lon=170, max_lon=-170 = "from 170°E through 180 to -170°W")
      //     — inside iff lon >= min_lon OR lon <= max_lon.
      if (c.min_lon <= c.max_lon) {
        if (ctx.current_lon < c.min_lon || ctx.current_lon > c.max_lon) {
          return `longitude ${ctx.current_lon.toFixed(6)} outside [${c.min_lon.toFixed(6)}, ${c.max_lon.toFixed(6)}]`;
        }
      } else {
        if (ctx.current_lon < c.min_lon && ctx.current_lon > c.max_lon) {
          return `longitude ${ctx.current_lon.toFixed(6)} outside wrapped [${c.min_lon.toFixed(6)}, ${c.max_lon.toFixed(6)}]`;
        }
      }
      const hasAlt = (c.min_alt_m ?? 0) !== 0 || (c.max_alt_m ?? 0) !== 0;
      if (hasAlt) {
        const alt = ctx.current_alt_m ?? Number.NaN;
        if (Number.isNaN(alt)) {
          return "constraint_unverifiable: no altitude in context but bbox has altitude bounds";
        }
        if (alt < (c.min_alt_m ?? 0) || alt > (c.max_alt_m ?? 0)) {
          return `altitude ${alt.toFixed(1)}m outside [${(c.min_alt_m ?? 0).toFixed(1)}m, ${(c.max_alt_m ?? 0).toFixed(1)}m]`;
        }
      }
      return null;
    }

    case "time_window": {
      if (!c.tz || !c.start || !c.end) {
        return "malformed time_window: tz/start/end required";
      }
      const start = parseHHMM(c.start);
      const end = parseHHMM(c.end);
      if (start === null) return `bad start time: ${c.start}`;
      if (end === null) return `bad end time: ${c.end}`;
      // Get current local time in the declared zone.
      let parts: Intl.DateTimeFormatPart[];
      try {
        parts = new Intl.DateTimeFormat("en-US", {
          timeZone: c.tz,
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        }).formatToParts(new Date(nowSec * 1000));
      } catch {
        return `unknown timezone "${c.tz}"`;
      }
      let h = Number(parts.find((p) => p.type === "hour")?.value ?? -1);
      const m = Number(parts.find((p) => p.type === "minute")?.value ?? -1);
      if (h < 0 || m < 0) return "time_window: could not resolve local time";
      // Some ICU builds format midnight as 24:00 for en-US + hour12:false.
      // Go reports 00:00, and conformance requires stable error text.
      if (h === 24) h = 0;
      const cur = h * 60 + m;
      if (start <= end) {
        if (cur < start || cur > end) {
          return `current ${fmtHHMM(h, m)} outside [${c.start}, ${c.end}] ${c.tz}`;
        }
      } else {
        // Wrapping window (e.g. 22:00 to 06:00).
        if (cur < start && cur > end) {
          return `current ${fmtHHMM(h, m)} outside wrapped [${c.start}, ${c.end}] ${c.tz}`;
        }
      }
      return null;
    }

    case "max_speed_mps": {
      if (ctx.current_speed_mps === undefined) {
        return "constraint_unverifiable: no current speed in context";
      }
      if (c.max_mps === undefined) {
        return "malformed max_speed_mps: max_mps required";
      }
      if (ctx.current_speed_mps > c.max_mps) {
        return `speed ${ctx.current_speed_mps.toFixed(2)}mps exceeds max ${c.max_mps.toFixed(2)}mps`;
      }
      return null;
    }

    case "max_amount": {
      if (
        ctx.requested_amount === undefined ||
        ctx.requested_currency === undefined
      ) {
        return "constraint_unverifiable: no requested amount in context";
      }
      if (c.max_amount === undefined || !c.currency) {
        return "malformed max_amount: max_amount/currency required";
      }
      if (ctx.requested_currency !== c.currency) {
        return `currency mismatch: requested "${ctx.requested_currency}", constraint "${c.currency}"`;
      }
      if (ctx.requested_amount > c.max_amount) {
        return `amount ${ctx.requested_amount.toFixed(2)} ${ctx.requested_currency} exceeds max ${c.max_amount.toFixed(2)} ${c.currency}`;
      }
      return null;
    }

    case "max_rate": {
      if (!ctx.invocations_in_window) {
        return "constraint_unverifiable: no rate counter in context";
      }
      if (!c.count || !c.window_s || c.count <= 0 || c.window_s <= 0) {
        return "malformed max_rate: count and window_s must be positive";
      }
      const got = ctx.invocations_in_window(certID, c.window_s);
      if (got >= c.count) {
        return `rate limit exceeded: ${got} invocations in last ${c.window_s}s (max ${c.count})`;
      }
      return null;
    }

    default:
      // Sentinel prefix so the verifier can route to
      // identity_status=constraint_unknown. Matches the Go reference's
      // unknownConstraintError shape.
      return `constraint_unknown: unknown constraint type "${String((c as { type: unknown }).type)}"`;
  }
}

// ---- helpers ----

function haversineMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const earthRadiusM = 6371000;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * earthRadiusM * Math.asin(Math.min(1, Math.sqrt(a)));
}

/**
 * Returns true if the polygon's longitudes span more than 180°. The only
 * way to span more than half the globe in longitude is to cross the
 * anti-meridian, and equirectangular ray-casting can't handle that — so
 * we refuse these polygons up-front (fail-closed) rather than silently
 * compute wrong inclusion. Mirrors Go's polygonSpansAntimeridian.
 */
function polygonSpansAntimeridian(points: [number, number][]): boolean {
  if (points.length < 3) return false;
  let minLon = points[0]![1];
  let maxLon = points[0]![1];
  for (const p of points) {
    if (p[1] < minLon) minLon = p[1];
    if (p[1] > maxLon) maxLon = p[1];
  }
  return maxLon - minLon > 180;
}

function pointInPolygon(
  lat: number,
  lon: number,
  poly: [number, number][],
): boolean {
  let inside = false;
  const n = poly.length;
  for (let i = 0, j = n - 1; i < n; j = i++) {
    const [yi, xi] = poly[i]!; // [lat, lon]
    const [yj, xj] = poly[j]!;
    if (
      ((yi > lat) !== (yj > lat)) &&
      lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi
    ) {
      inside = !inside;
    }
  }
  return inside;
}

function parseHHMM(s: string): number | null {
  if (s.length !== 5 || s[2] !== ":") return null;
  const h = Number(s.slice(0, 2));
  const m = Number(s.slice(3, 5));
  if (!Number.isFinite(h) || !Number.isFinite(m)) return null;
  if (h < 0 || h > 23 || m < 0 || m > 59) return null;
  return h * 60 + m;
}

function fmtHHMM(h: number, m: number): string {
  return `${h.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}`;
}
