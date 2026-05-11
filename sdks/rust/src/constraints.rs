//! Constraint evaluation — mirrors Go's constraints.go exactly.
//!
//! Every semantic must produce the same verdict for the same inputs, or
//! cross-language conformance fails.

use crate::types::{Constraint, ConstraintEvaluator, DelegationCert, VerifierContext};

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use std::collections::HashMap;

/// Run every Constraint on cert against the caller-supplied VerifierContext.
/// Return `Ok(())` iff all pass; an error string otherwise.
/// Fail-closed: unknown Type or missing required context field causes rejection.
/// (SPEC §17.7) Unknown built-in types fall through to `ext_evaluators`
/// before failing closed.
pub fn evaluate_constraints<'a>(
    cert: &DelegationCert,
    ctx: &VerifierContext,
    now_sec: i64,
    ext_evaluators: Option<&HashMap<String, Box<dyn ConstraintEvaluator + 'a>>>,
) -> Result<(), String> {
    for (i, c) in cert.constraints.iter().enumerate() {
        let mut err = evaluate_constraint(c, &cert.cert_id, ctx, now_sec);
        if let Err(ref msg) = err {
            if msg.starts_with("constraint_unknown:") {
                if let Some(map) = ext_evaluators {
                    if let Some(ev) = map.get(&c.kind) {
                        err = ev.evaluate(c, &cert.cert_id, ctx, now_sec);
                    }
                }
            }
        }
        if let Err(e) = err {
            return Err(format!("constraint[{}] ({}): {}", i, c.kind, e));
        }
    }
    Ok(())
}

fn evaluate_constraint(
    c: &Constraint,
    cert_id: &str,
    ctx: &VerifierContext,
    now_sec: i64,
) -> Result<(), String> {
    match c.kind.as_str() {
        "geo_circle" => {
            let (lat, lon) = match (ctx.current_lat, ctx.current_lon) {
                (Some(a), Some(b)) => (a, b),
                _ => return Err("constraint_unverifiable: no current location in context".into()),
            };
            let d = haversine_meters(lat, lon, c.lat, c.lon);
            if d > c.radius_m {
                return Err(format!(
                    "outside allowed radius: {:.1}m > {:.1}m",
                    d, c.radius_m
                ));
            }
            Ok(())
        }
        "geo_polygon" => {
            let (lat, lon) = match (ctx.current_lat, ctx.current_lon) {
                (Some(a), Some(b)) => (a, b),
                _ => return Err("constraint_unverifiable: no current location in context".into()),
            };
            if c.points.len() < 3 {
                return Err("polygon has fewer than 3 points".into());
            }
            // v1 polygon is defined over equirectangular projection — correct
            // for small regions, incorrect for anti-meridian-crossing shapes.
            // Fail closed rather than silently return wrong answers. SPEC §5.7.2
            // documents the v1 small-region limitation; geodesic semantics are v2.
            if polygon_spans_antimeridian(&c.points) {
                return Err("geo_polygon spans >180° longitude — v1 semantics are undefined for anti-meridian-crossing polygons (see SPEC §5.7.2)".into());
            }
            if !point_in_polygon(lat, lon, &c.points) {
                return Err("outside allowed polygon".into());
            }
            Ok(())
        }
        "geo_bbox" => {
            let (lat, lon) = match (ctx.current_lat, ctx.current_lon) {
                (Some(a), Some(b)) => (a, b),
                _ => return Err("constraint_unverifiable: no current location in context".into()),
            };
            if lat < c.min_lat || lat > c.max_lat {
                // Format must match Go's %.6f (fixed 6 decimals) so cross-SDK
                // error_reason strings are byte-identical. Don't change.
                return Err(format!(
                    "latitude {:.6} outside [{:.6}, {:.6}]",
                    lat, c.min_lat, c.max_lat
                ));
            }
            // Anti-meridian-aware longitude check (SPEC §5.7.2).
            //   min_lon <= max_lon → ordinary bbox, lon must be in [min_lon, max_lon]
            //   min_lon >  max_lon → bbox wraps the 180° meridian (e.g.,
            //     min_lon=170, max_lon=-170 = "from 170°E through 180 to -170°W")
            //     — inside iff lon >= min_lon OR lon <= max_lon.
            if c.min_lon <= c.max_lon {
                if lon < c.min_lon || lon > c.max_lon {
                    return Err(format!(
                        "longitude {:.6} outside [{:.6}, {:.6}]",
                        lon, c.min_lon, c.max_lon
                    ));
                }
            } else if lon < c.min_lon && lon > c.max_lon {
                return Err(format!(
                    "longitude {:.6} outside wrapped [{:.6}, {:.6}]",
                    lon, c.min_lon, c.max_lon
                ));
            }
            let has_alt = c.min_alt_m != 0.0 || c.max_alt_m != 0.0;
            if has_alt {
                let alt = ctx.current_alt_m.ok_or_else(|| {
                    "constraint_unverifiable: no altitude in context but bbox has altitude bounds"
                        .to_string()
                })?;
                if alt < c.min_alt_m || alt > c.max_alt_m {
                    return Err(format!(
                        "altitude {:.1}m outside [{:.1}m, {:.1}m]",
                        alt, c.min_alt_m, c.max_alt_m
                    ));
                }
            }
            Ok(())
        }
        "time_window" => {
            if c.tz.is_empty() || c.start.is_empty() || c.end.is_empty() {
                return Err("malformed time_window: tz/start/end required".into());
            }
            let start =
                parse_hhmm(&c.start).ok_or_else(|| format!("bad start time: {}", c.start))?;
            let end = parse_hhmm(&c.end).ok_or_else(|| format!("bad end time: {}", c.end))?;
            let zone: Tz =
                c.tz.parse()
                    .map_err(|_| format!("unknown timezone \"{}\"", c.tz))?;
            let utc = DateTime::<Utc>::from_timestamp(now_sec, 0)
                .ok_or_else(|| "time_window: invalid now_sec".to_string())?;
            let local = utc.with_timezone(&zone);
            let cur = (local.format("%H").to_string().parse::<i32>().unwrap_or(0)) * 60
                + local.format("%M").to_string().parse::<i32>().unwrap_or(0);
            if start <= end {
                if cur < start || cur > end {
                    return Err(format!(
                        "current {} outside [{}, {}] {}",
                        local.format("%H:%M"),
                        c.start,
                        c.end,
                        c.tz
                    ));
                }
            } else {
                // Wrapping window (e.g. 22:00 to 06:00).
                if cur < start && cur > end {
                    return Err(format!(
                        "current {} outside wrapped [{}, {}] {}",
                        local.format("%H:%M"),
                        c.start,
                        c.end,
                        c.tz
                    ));
                }
            }
            Ok(())
        }
        "max_speed_mps" => {
            let speed = ctx.current_speed_mps.ok_or_else(|| {
                "constraint_unverifiable: no current speed in context".to_string()
            })?;
            if speed > c.max_mps {
                return Err(format!(
                    "speed {:.2}mps exceeds max {:.2}mps",
                    speed, c.max_mps
                ));
            }
            Ok(())
        }
        "max_amount" => {
            let amount = ctx.requested_amount.ok_or_else(|| {
                "constraint_unverifiable: no requested amount in context".to_string()
            })?;
            let req_ccy = ctx.requested_currency.as_deref().ok_or_else(|| {
                "constraint_unverifiable: no requested currency in context".to_string()
            })?;
            if req_ccy != c.currency {
                return Err(format!(
                    "currency mismatch: requested \"{}\", constraint \"{}\"",
                    req_ccy, c.currency
                ));
            }
            if amount > c.max_amount {
                return Err(format!(
                    "amount {:.2} {} exceeds max {:.2} {}",
                    amount, req_ccy, c.max_amount, c.currency
                ));
            }
            Ok(())
        }
        "max_rate" => {
            let counter = ctx
                .invocations_in_window
                .as_ref()
                .ok_or_else(|| "constraint_unverifiable: no rate counter in context".to_string())?;
            if c.count <= 0 || c.window_s <= 0 {
                return Err("malformed max_rate: count and window_s must be positive".into());
            }
            let got = counter(cert_id, c.window_s);
            if got >= c.count {
                return Err(format!(
                    "rate limit exceeded: {} invocations in last {}s (max {})",
                    got, c.window_s, c.count
                ));
            }
            Ok(())
        }
        other => Err(format!(
            // Sentinel prefix routes the verifier to identity_status=constraint_unknown.
            "constraint_unknown: unknown constraint type \"{}\"",
            other
        )),
    }
}

// ---- helpers ----

fn haversine_meters(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let earth_radius_m = 6371000.0_f64;
    let rad = std::f64::consts::PI / 180.0;
    let d_lat = (lat2 - lat1) * rad;
    let d_lon = (lon2 - lon1) * rad;
    let a = (d_lat / 2.0).sin().powi(2)
        + (lat1 * rad).cos() * (lat2 * rad).cos() * (d_lon / 2.0).sin().powi(2);
    2.0 * earth_radius_m * a.sqrt().min(1.0).asin()
}

/// Returns true if the polygon's longitudes span more than 180°. The only
/// way to span more than half the globe in longitude is to cross the
/// anti-meridian, and equirectangular ray-casting can't handle that — so
/// we refuse these polygons up-front (fail-closed). Mirrors Go's
/// polygonSpansAntimeridian.
fn polygon_spans_antimeridian(points: &[[f64; 2]]) -> bool {
    if points.len() < 3 {
        return false;
    }
    let mut min_lon = points[0][1];
    let mut max_lon = points[0][1];
    for p in points {
        if p[1] < min_lon {
            min_lon = p[1];
        }
        if p[1] > max_lon {
            max_lon = p[1];
        }
    }
    (max_lon - min_lon) > 180.0
}

fn point_in_polygon(lat: f64, lon: f64, poly: &[[f64; 2]]) -> bool {
    let mut inside = false;
    let n = poly.len();
    let mut j = n - 1;
    for i in 0..n {
        let (yi, xi) = (poly[i][0], poly[i][1]); // lat, lon
        let (yj, xj) = (poly[j][0], poly[j][1]);
        if ((yi > lat) != (yj > lat)) && lon < (xj - xi) * (lat - yi) / (yj - yi) + xi {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn parse_hhmm(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    if b.len() != 5 || b[2] != b':' {
        return None;
    }
    let h: i32 = s[0..2].parse().ok()?;
    let m: i32 = s[3..5].parse().ok()?;
    if !(0..=23).contains(&h) || !(0..=59).contains(&m) {
        return None;
    }
    Some(h * 60 + m)
}
