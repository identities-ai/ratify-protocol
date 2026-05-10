package ratify

import (
	"fmt"
	"math"
	"time"
)

// evaluateConstraints runs every Constraint on cert against the caller-supplied
// VerifierContext. Returns nil iff all pass; a descriptive error otherwise.
// Fail-closed: an unknown Type or a constraint whose required context field
// is absent causes rejection.
func evaluateConstraints(cert *DelegationCert, ctx VerifierContext, now time.Time) error {
	for i, c := range cert.Constraints {
		if err := evaluateConstraint(c, cert.CertID, ctx, now); err != nil {
			return fmt.Errorf("constraint[%d] (%s): %w", i, c.Type, err)
		}
	}
	return nil
}

func evaluateConstraint(c Constraint, certID string, ctx VerifierContext, now time.Time) error {
	switch c.Type {
	case ConstraintGeoCircle:
		if !ctx.HasLocation {
			return errConstraintUnverifiable("no current location in context")
		}
		d := haversineMeters(ctx.CurrentLat, ctx.CurrentLon, c.Lat, c.Lon)
		if d > c.RadiusM {
			return fmt.Errorf("outside allowed radius: %.1fm > %.1fm", d, c.RadiusM)
		}
		return nil

	case ConstraintGeoPolygon:
		if !ctx.HasLocation {
			return errConstraintUnverifiable("no current location in context")
		}
		if len(c.Points) < 3 {
			return fmt.Errorf("polygon has fewer than 3 points")
		}
		// v1 polygon is defined over equirectangular projection — correct
		// for small regions, incorrect for anti-meridian-crossing shapes.
		// Fail closed rather than silently return wrong answers. SPEC §5.7.2
		// documents the v1 small-region limitation; geodesic semantics are v2.
		if polygonSpansAntimeridian(c.Points) {
			return fmt.Errorf("geo_polygon spans >180° longitude — v1 semantics are undefined for anti-meridian-crossing polygons (see SPEC §5.7.2)")
		}
		if !pointInPolygon(ctx.CurrentLat, ctx.CurrentLon, c.Points) {
			return fmt.Errorf("outside allowed polygon")
		}
		return nil

	case ConstraintGeoBBox:
		if !ctx.HasLocation {
			return errConstraintUnverifiable("no current location in context")
		}
		if ctx.CurrentLat < c.MinLat || ctx.CurrentLat > c.MaxLat {
			return fmt.Errorf("latitude %.6f outside [%.6f, %.6f]", ctx.CurrentLat, c.MinLat, c.MaxLat)
		}
		// Anti-meridian-aware longitude check (SPEC §5.7.2).
		//   MinLon <= MaxLon → ordinary bbox, lon must be in [MinLon, MaxLon]
		//   MinLon >  MaxLon → bbox wraps the 180° meridian (e.g.,
		//     MinLon=170, MaxLon=-170 = "from 170°E through 180 to -170°W")
		//     — inside iff lon >= MinLon OR lon <= MaxLon.
		if c.MinLon <= c.MaxLon {
			if ctx.CurrentLon < c.MinLon || ctx.CurrentLon > c.MaxLon {
				return fmt.Errorf("longitude %.6f outside [%.6f, %.6f]",
					ctx.CurrentLon, c.MinLon, c.MaxLon)
			}
		} else {
			if ctx.CurrentLon < c.MinLon && ctx.CurrentLon > c.MaxLon {
				return fmt.Errorf("longitude %.6f outside wrapped [%.6f, %.6f]",
					ctx.CurrentLon, c.MinLon, c.MaxLon)
			}
		}
		// Altitude bounds are ignored when both are zero.
		if c.MinAltM != 0 || c.MaxAltM != 0 {
			if ctx.CurrentAltM < c.MinAltM || ctx.CurrentAltM > c.MaxAltM {
				return fmt.Errorf("altitude %.1fm outside [%.1fm, %.1fm]", ctx.CurrentAltM, c.MinAltM, c.MaxAltM)
			}
		}
		return nil

	case ConstraintTimeWindow:
		if c.TZ == "" || c.Start == "" || c.End == "" {
			return fmt.Errorf("malformed time_window: tz/start/end required")
		}
		loc, err := time.LoadLocation(c.TZ)
		if err != nil {
			return fmt.Errorf("unknown timezone %q", c.TZ)
		}
		start, err := parseHHMM(c.Start)
		if err != nil {
			return fmt.Errorf("bad start time: %w", err)
		}
		end, err := parseHHMM(c.End)
		if err != nil {
			return fmt.Errorf("bad end time: %w", err)
		}
		local := now.In(loc)
		cur := local.Hour()*60 + local.Minute()
		if start <= end {
			// Non-wrapping window.
			if cur < start || cur > end {
				return fmt.Errorf("current %02d:%02d outside [%s, %s] %s",
					local.Hour(), local.Minute(), c.Start, c.End, c.TZ)
			}
		} else {
			// Wrapping window (e.g. 22:00 to 06:00).
			if cur < start && cur > end {
				return fmt.Errorf("current %02d:%02d outside wrapped [%s, %s] %s",
					local.Hour(), local.Minute(), c.Start, c.End, c.TZ)
			}
		}
		return nil

	case ConstraintMaxSpeedMps:
		if !ctx.HasSpeed {
			return errConstraintUnverifiable("no current speed in context")
		}
		if ctx.CurrentSpeedMps > c.MaxMps {
			return fmt.Errorf("speed %.2fmps exceeds max %.2fmps", ctx.CurrentSpeedMps, c.MaxMps)
		}
		return nil

	case ConstraintMaxAmount:
		if !ctx.HasAmount {
			return errConstraintUnverifiable("no requested amount in context")
		}
		if ctx.RequestedCurrency != c.Currency {
			return fmt.Errorf("currency mismatch: requested %q, constraint %q", ctx.RequestedCurrency, c.Currency)
		}
		if ctx.RequestedAmount > c.MaxAmount {
			return fmt.Errorf("amount %.2f %s exceeds max %.2f %s",
				ctx.RequestedAmount, ctx.RequestedCurrency, c.MaxAmount, c.Currency)
		}
		return nil

	case ConstraintMaxRate:
		if ctx.InvocationsInWindow == nil {
			return errConstraintUnverifiable("no rate counter in context")
		}
		if c.Count <= 0 || c.WindowS <= 0 {
			return fmt.Errorf("malformed max_rate: count and window_s must be positive")
		}
		got := ctx.InvocationsInWindow(certID, c.WindowS)
		if got >= c.Count {
			return fmt.Errorf("rate limit exceeded: %d invocations in last %ds (max %d)",
				got, c.WindowS, c.Count)
		}
		return nil

	default:
		return unknownConstraintError{kind: string(c.Type)}
	}
}

// ---- helpers ----

type unverifiableError struct{ reason string }

func (e unverifiableError) Error() string { return "constraint_unverifiable: " + e.reason }

func errConstraintUnverifiable(reason string) error { return unverifiableError{reason: reason} }

// unknownConstraintError is the sentinel for unknown constraint types. The
// verifier routes to IdentityStatusConstraintUnknown on it rather than
// collapsing to IdentityStatusConstraintDenied, so a cert that carries a
// constraint shape a given verifier version does not understand fails
// explicitly (fail-closed, visible in audit) instead of silently.
type unknownConstraintError struct{ kind string }

func (e unknownConstraintError) Error() string {
	return "constraint_unknown: unknown constraint type " + fmtQuoted(e.kind)
}

// fmtQuoted wraps a string in double quotes for stable error text without
// pulling in strconv's escaping surprises — the constraint-type string is
// always safe ASCII by v1 spec.
func fmtQuoted(s string) string { return "\"" + s + "\"" }

// haversineMeters — great-circle distance on a sphere (WGS-84 mean radius).
// Accurate enough for bounded-radius geofence checks at the meter scale.
func haversineMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusM = 6371000.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusM * math.Asin(math.Min(1.0, math.Sqrt(a)))
}

// polygonSpansAntimeridian returns true if the polygon's longitudes span
// more than 180°. The only way to span more than half the globe in
// longitude is to cross the anti-meridian, and the equirectangular
// ray-casting below can't handle that — so we refuse these polygons
// up-front (fail-closed) rather than silently compute wrong inclusion.
func polygonSpansAntimeridian(points [][2]float64) bool {
	if len(points) < 3 {
		return false
	}
	minLon, maxLon := points[0][1], points[0][1]
	for _, p := range points {
		if p[1] < minLon {
			minLon = p[1]
		}
		if p[1] > maxLon {
			maxLon = p[1]
		}
	}
	return (maxLon - minLon) > 180
}

// pointInPolygon — standard ray-casting algorithm in equirectangular
// projection. Fine for small polygons (<~100 km diameter); for very large
// polygons use geodesic inclusion instead.
func pointInPolygon(lat, lon float64, poly [][2]float64) bool {
	inside := false
	n := len(poly)
	for i, j := 0, n-1; i < n; i++ {
		xi, yi := poly[i][1], poly[i][0] // lon, lat
		xj, yj := poly[j][1], poly[j][0]
		if ((yi > lat) != (yj > lat)) &&
			(lon < (xj-xi)*(lat-yi)/(yj-yi)+xi) {
			inside = !inside
		}
		j = i
	}
	return inside
}

// parseHHMM — "HH:MM" 24-hour clock → minutes-since-midnight.
func parseHHMM(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("out-of-range HH:MM %q", s)
	}
	return h*60 + m, nil
}
