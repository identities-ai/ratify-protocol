package ratify

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestConstraintV2CanonicalRoundTrip(t *testing.T) {
	for _, c := range []ConstraintV2{
		{Type: ConstraintTimeWindow, Start: "22:00", End: "06:00", TZ: "Europe/Paris"},
		{Type: ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 0},
		{Type: ConstraintMaxAmount, Currency: "JPY", MaxAmountMicros: maxSafeInteger},
		{Type: ConstraintMaxRate, Count: 1, WindowS: V2MaxRateWindowSeconds},
		{Type: ConstraintResourcePath, ResourceID: "a<b>&c"},
		{Type: ConstraintResourcePath, ResourceID: "r", PathPrefix: "/x/"},
		{Type: ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"r"}, "trust_domain_ids": []any{}}},
		{Type: ConstraintGeoCircle, Params: map[string]any{"radius_mm": float64(5)}},
		{Type: "vendor.example"},
	} {
		encoded, err := CanonicalJSON(c)
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		var back ConstraintV2
		if err := json.Unmarshal(encoded, &back); err != nil {
			t.Fatalf("%s: %v", encoded, err)
		}
		again, _ := CanonicalJSON(back)
		if string(again) != string(encoded) {
			t.Fatalf("round trip changed %s to %s", encoded, again)
		}
	}
	if encoded, _ := CanonicalJSON(ConstraintV2{Type: ConstraintResourcePath, ResourceID: "a<b>&c"}); string(encoded) != `{"resource_id":"a<b>&c","type":"resource_path"}` {
		t.Fatalf("v2 constraints must not HTML-escape: %s", encoded)
	}
	for _, bad := range []ConstraintV2{
		{Type: ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: -1},
		{Type: ConstraintMaxRate, Count: 1, WindowS: V2MaxRateWindowSeconds + 1},
		{Type: ConstraintTimeWindow, Start: "7:00", End: "08:00", TZ: "UTC"},
		{Type: ConstraintMaxRate, Count: 1, WindowS: 60, Params: map[string]any{}},
		{Type: ""},
	} {
		if encoded, err := CanonicalJSON(bad); err == nil {
			t.Fatalf("invalid constraint encoded: %s", encoded)
		}
	}
}

func TestEvaluateConstraintV2(t *testing.T) {
	noon := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	amount := ConstraintV2{Type: ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 10}
	usd := func(micros int64) ConstraintContextV2 {
		return ConstraintContextV2{HasAmount: true, RequestedAmountMicros: micros, RequestedCurrency: "USD"}
	}
	isDenied := func(err error) bool {
		return err != nil && !errors.Is(err, ErrConstraintUnverifiable) && !isUnknownV2Constraint(err)
	}
	cases := []struct {
		name  string
		c     ConstraintV2
		ctx   ConstraintContextV2
		check func(error) bool
	}{
		{"amount at limit", amount, usd(10), func(err error) bool { return err == nil }},
		{"amount over limit", amount, usd(11), isDenied},
		{"amount other currency", amount, ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 1, RequestedCurrency: "EUR"}, isDenied},
		{"amount absent", amount, ConstraintContextV2{}, func(err error) bool { return errors.Is(err, ErrConstraintUnverifiable) }},
		{"amount negative request", amount, usd(-1), func(err error) bool { return errors.Is(err, ErrConstraintUnverifiable) }},
		{"window inside", ConstraintV2{Type: ConstraintTimeWindow, Start: "11:00", End: "12:00", TZ: "UTC"}, ConstraintContextV2{}, func(err error) bool { return err == nil }},
		{"window outside", ConstraintV2{Type: ConstraintTimeWindow, Start: "13:00", End: "14:00", TZ: "UTC"}, ConstraintContextV2{}, isDenied},
		{"window unknown zone", ConstraintV2{Type: ConstraintTimeWindow, Start: "00:00", End: "23:59", TZ: "Mars/Olympus_Mons"}, ConstraintContextV2{}, func(err error) bool { return errors.Is(err, ErrConstraintUnverifiable) }},
		{"window host Local zone", ConstraintV2{Type: ConstraintTimeWindow, Start: "00:00", End: "23:59", TZ: "Local"}, ConstraintContextV2{}, func(err error) bool { return errors.Is(err, ErrConstraintUnverifiable) }},
		{"geo_circle unregistered", ConstraintV2{Type: ConstraintGeoCircle}, ConstraintContextV2{}, isUnknownV2Constraint},
		{"max_speed_mps unregistered", ConstraintV2{Type: ConstraintMaxSpeedMps}, ConstraintContextV2{}, isUnknownV2Constraint},
	}
	for _, tc := range cases {
		if err := evaluateConstraintV2(tc.c, tc.ctx, TZDBVersionV2, noon); !tc.check(err) {
			t.Errorf("%s: unexpected result %v", tc.name, err)
		}
	}
	// A window that would pass is unverifiable unless the verifier configured
	// exactly the embedded tzdata release: rules differ between releases.
	inside := ConstraintV2{Type: ConstraintTimeWindow, Start: "11:00", End: "12:00", TZ: "UTC"}
	for _, version := range []string{"", "2024a", TZDBVersionV2 + " "} {
		if err := evaluateConstraintV2(inside, ConstraintContextV2{}, version, noon); !errors.Is(err, ErrConstraintUnverifiable) {
			t.Errorf("tzdb_version %q: got %v, want constraint_unverifiable", version, err)
		}
	}
}
