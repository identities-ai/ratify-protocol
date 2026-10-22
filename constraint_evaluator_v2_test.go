package ratify

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// The standard profile digests are normative (SPEC-v2 §5.2). They are
// recomputed here from the formula, not from ConstraintProfileDigestV2.
func TestStandardConstraintProfileDigestsV2(t *testing.T) {
	independent := func(profile, kind string) string {
		h := sha512.New384()
		h.Write([]byte("ratify-protocol-constraint-profile-v2\x00"))
		h.Write([]byte(`{"profile":"` + profile + `","type":"` + kind + `"}`))
		return "sha384:" + hex.EncodeToString(h.Sum(nil))
	}
	for _, c := range []struct {
		reg  ConstraintEvaluatorRegistrationV2
		want string
	}{
		{StandardMaxCountEvaluatorV2(), "sha384:27e6c6b37856ce4eed4c0923641d45a59d06e138b38893d850f8f0f1356200286fdb2e2e8d36cc69e4b550f9b2443e2b"},
		{StandardAllowedValuesEvaluatorV2(), "sha384:2c9b719e7477c342038f4900461db15c12d8d0d4131026cb4b820a3ee8e566e49d882a62c9846fa5047d606163bd8015"},
	} {
		got, err := ConstraintProfileDigestV2(c.reg.Descriptor)
		if err != nil || got != c.want || got != independent(c.reg.Descriptor.Profile, string(c.reg.Descriptor.Type)) {
			t.Errorf("%s digest = %s (%v), want %s", c.reg.Descriptor.Profile, got, err, c.want)
		}
	}
}

func TestConstraintEvaluatorRegistryV2RejectsBadConfiguration(t *testing.T) {
	pass := func(context.Context, ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error) {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2}, nil
	}
	reg := func(kind, profile string) ConstraintEvaluatorRegistrationV2 {
		return ConstraintEvaluatorRegistrationV2{Descriptor: ConstraintProfileDescriptorV2{Profile: profile, Type: ConstraintType(kind)}, Evaluate: pass}
	}
	many := make([]ConstraintEvaluatorRegistrationV2, MaxConstraintEvaluatorsV2+1)
	for i := range many {
		many[i] = reg("com.example.t"+strings.Repeat("x", i), "com.example.p/v1")
	}
	cases := map[string]struct {
		timeout time.Duration
		regs    []ConstraintEvaluatorRegistrationV2
	}{
		"zero timeout":           {0, nil},
		"timeout too long":       {MaxConstraintEvaluatorTimeoutV2 + 1, nil},
		"registered v2 type":     {time.Second, []ConstraintEvaluatorRegistrationV2{reg("max_rate", "com.example.p/v1")}},
		"reserved namespace":     {time.Second, []ConstraintEvaluatorRegistrationV2{reg("ratify.receiver_audience.x", "com.example.p/v1")}},
		"two labels":             {time.Second, []ConstraintEvaluatorRegistrationV2{reg("example.count", "com.example.p/v1")}},
		"uppercase type":         {time.Second, []ConstraintEvaluatorRegistrationV2{reg("com.Example.count", "com.example.p/v1")}},
		"reserved geo name":      {time.Second, []ConstraintEvaluatorRegistrationV2{reg("geo_circle", "com.example.p/v1")}},
		"profile without /v":     {time.Second, []ConstraintEvaluatorRegistrationV2{reg("com.example.count", "com.example.p")}},
		"profile version zero":   {time.Second, []ConstraintEvaluatorRegistrationV2{reg("com.example.count", "com.example.p/v0")}},
		"profile leading zero":   {time.Second, []ConstraintEvaluatorRegistrationV2{reg("com.example.count", "com.example.p/v01")}},
		"duplicate type":         {time.Second, []ConstraintEvaluatorRegistrationV2{reg("com.example.count", "com.example.p/v1"), reg("com.example.count", "com.example.p/v2")}},
		"missing implementation": {time.Second, []ConstraintEvaluatorRegistrationV2{{Descriptor: ConstraintProfileDescriptorV2{Profile: "com.example.p/v1", Type: "com.example.count"}}}},
		"too many profiles":      {time.Second, many},
	}
	for name, c := range cases {
		if _, err := NewConstraintEvaluatorRegistryV2(c.timeout, c.regs...); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
			t.Errorf("%s: class %q (%v), want configuration_invalid", name, V2ErrorClassOf(err), err)
		}
	}
	registry, err := NewConstraintEvaluatorRegistryV2(time.Second, StandardAllowedValuesEvaluatorV2(), StandardMaxCountEvaluatorV2())
	if err != nil {
		t.Fatal(err)
	}
	refs := registry.Refs()
	if len(refs) != 2 || refs[0].Type != ConstraintAllowedValuesV2 || refs[1].Type != ConstraintMaxCountV2 {
		t.Fatalf("refs are not sorted by type: %+v", refs)
	}
	// A registry not built by the constructor is rejected before claim.
	if err := validateV2VerifyConfiguration(V2VerifyRequest{Now: 1, MaxChallengeAgeSeconds: 1, ConstraintEvaluators: &ConstraintEvaluatorRegistryV2{},
		StatusPolicy: RevocationStatusPolicyV2{MaxListLifetimeSeconds: 1, MaxStatusAgeSeconds: 1}}); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Fatalf("zero-value registry: %v", err)
	}
}

// TestRunConstraintEvaluatorV2MapsEveryOutcome pins the evaluator result
// model: pass with an optional later horizon; a denial; and unverifiable for
// an unverifiable verdict, an error, a panic, a timeout, or invalid output.
func TestRunConstraintEvaluatorV2MapsEveryOutcome(t *testing.T) {
	const now = 1800000000
	entry := func(f ConstraintEvaluatorFuncV2) registeredConstraintEvaluatorV2 {
		return registeredConstraintEvaluatorV2{ref: ConstraintEvaluatorRefV2{Type: "com.example.t"}, evaluate: f}
	}
	result := func(r ConstraintEvaluationResultV2, err error) ConstraintEvaluatorFuncV2 {
		return func(context.Context, ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error) {
			return r, err
		}
	}
	in := ConstraintEvaluationInputV2{Type: "com.example.t", EvaluationTime: now}
	type want int
	const (
		pass want = iota
		denied
		unverifiable
	)
	cases := map[string]struct {
		f       ConstraintEvaluatorFuncV2
		want    want
		horizon int64
	}{
		"pass":                  {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2}, nil), pass, 0},
		"pass with horizon":     {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2, ValidUntil: now + 1}, nil), pass, now + 1},
		"pass horizon clamped":  {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2, ValidUntil: V2MaxTimestampSeconds + 5}, nil), pass, V2MaxTimestampSeconds},
		"pass horizon at claim": {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2, ValidUntil: now}, nil), unverifiable, 0},
		"pass horizon negative": {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2, ValidUntil: -1}, nil), unverifiable, 0},
		"denied":                {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeDeniedV2}, nil), denied, 0},
		"denied with horizon":   {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeDeniedV2, ValidUntil: now + 1}, nil), unverifiable, 0},
		"unverifiable":          {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeUnverifiableV2}, nil), unverifiable, 0},
		"error":                 {result(ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2}, errors.New("boom")), unverifiable, 0},
		"unknown outcome":       {result(ConstraintEvaluationResultV2{Outcome: "maybe"}, nil), unverifiable, 0},
		"empty outcome":         {result(ConstraintEvaluationResultV2{}, nil), unverifiable, 0},
		"panic":                 {func(context.Context, ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error) { panic("x") }, unverifiable, 0},
		"timeout ignores cancel": {func(context.Context, ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error) {
			time.Sleep(200 * time.Millisecond)
			return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2}, nil
		}, unverifiable, 0},
	}
	for name, c := range cases {
		horizon, err := runConstraintEvaluatorV2(entry(c.f), 50*time.Millisecond, in)
		var got want
		switch {
		case err == nil:
			got = pass
		case errors.Is(err, ErrConstraintUnverifiable):
			got = unverifiable
		default:
			got = denied
		}
		if got != c.want || horizon != c.horizon {
			t.Errorf("%s: got %d horizon %d (%v), want %d horizon %d", name, got, horizon, err, c.want, c.horizon)
		}
	}
}

func TestStandardConstraintProfileParamsV2(t *testing.T) {
	counter, max, err := decodeMaxCountParamsV2([]byte(`{"counter":"nodes","max":10}`))
	if err != nil || counter != "nodes" || max != 10 {
		t.Fatalf("max_count params: %q %d %v", counter, max, err)
	}
	for _, bad := range []string{``, `null`, `[]`, `{}`, `{"counter":"nodes"}`, `{"counter":"nodes","max":10,"x":1}`, `{"counter":"Nodes","max":1}`,
		`{"counter":"nodes","max":-1}`, `{"counter":"nodes","max":1.5}`, `{"counter":"nodes","max":9007199254740992}`, `{"counter":"nodes","max":"1"}`,
		`{"counter":"nodes","counter":"x","max":1}`, `{"counter":"nodes","max":1} {}`, `{"counter":"","max":1}`} {
		if _, _, err := decodeMaxCountParamsV2([]byte(bad)); err == nil {
			t.Errorf("max_count accepted %s", bad)
		}
	}
	field, allowed, err := decodeAllowedValuesParamsV2([]byte(`{"allowed":["inspection","maintenance"],"field":"work_order_category"}`))
	if err != nil || field != "work_order_category" || len(allowed) != 2 {
		t.Fatalf("allowed_values params: %q %v %v", field, allowed, err)
	}
	tooMany := `{"allowed":[`
	for i := 0; i <= MaxAllowedValuesV2; i++ {
		if i > 0 {
			tooMany += ","
		}
		tooMany += `"v` + strings.Repeat("x", i) + `"`
	}
	tooMany += `],"field":"f"}`
	for _, bad := range []string{`{"allowed":[],"field":"f"}`, `{"allowed":["a","a"],"field":"f"}`, `{"allowed":[""],"field":"f"}`, `{"allowed":[1],"field":"f"}`,
		`{"allowed":"a","field":"f"}`, `{"allowed":["a"]}`, `{"allowed":["` + strings.Repeat("a", MaxExtensionContextValueBytesV2+1) + `"],"field":"f"}`, tooMany} {
		if _, _, err := decodeAllowedValuesParamsV2([]byte(bad)); err == nil {
			t.Errorf("allowed_values accepted %.80s", bad)
		}
	}
}

func TestV2ExtensionRequestContextValidation(t *testing.T) {
	ok := []ConstraintContextV2{
		{ExtensionCounts: map[string]int64{"nodes": 0, "a.b:c-d_e": maxSafeInteger}},
		{ExtensionValues: map[string]string{"work_order_category": strings.Repeat("é", MaxExtensionContextValueBytesV2/2)}},
	}
	for _, c := range ok {
		if err := validateV2RequestContext(c); err != nil {
			t.Errorf("rejected valid extension context: %v", err)
		}
	}
	many := map[string]int64{}
	for i := 0; i <= MaxExtensionContextEntriesV2; i++ {
		many["c"+strings.Repeat("x", i)] = 1
	}
	bad := []ConstraintContextV2{
		{ExtensionCounts: map[string]int64{"nodes": -1}},
		{ExtensionCounts: map[string]int64{"nodes": maxSafeInteger + 1}},
		{ExtensionCounts: map[string]int64{"": 1}},
		{ExtensionCounts: map[string]int64{"Nodes": 1}},
		{ExtensionCounts: map[string]int64{strings.Repeat("a", MaxExtensionContextNameBytesV2+1): 1}},
		{ExtensionCounts: many},
		{ExtensionValues: map[string]string{"f": "\xff"}},
		{ExtensionValues: map[string]string{"f": strings.Repeat("a", MaxExtensionContextValueBytesV2+1)}},
		{ExtensionValues: map[string]string{"f g": "x"}},
	}
	for i, c := range bad {
		if err := validateV2RequestContext(c); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
			t.Errorf("case %d: class %q, want configuration_invalid", i, V2ErrorClassOf(err))
		}
	}
}

// TestV2InterruptedReceiptCarriesSealedEvaluators: lease-expiry recovery
// builds its receipt from the claim's sealed snapshot, so a crash during or
// after an evaluator call reports the same profiles without re-running it.
func TestV2InterruptedReceiptCarriesSealedEvaluators(t *testing.T) {
	refs := []ConstraintEvaluatorRefV2{
		{Type: ConstraintAllowedValuesV2, ProfileDigest: "sha384:2c9b719e7477c342038f4900461db15c12d8d0d4131026cb4b820a3ee8e566e49d882a62c9846fa5047d606163bd8015"},
		{Type: ConstraintMaxCountV2, ProfileDigest: "sha384:27e6c6b37856ce4eed4c0923641d45a59d06e138b38893d850f8f0f1356200286fdb2e2e8d36cc69e4b550f9b2443e2b"},
	}
	id := strings.Repeat("ab", 32)
	claim := V2ChallengeClaim{VerifierID: id, AgentID: strings.Repeat("cd", 32), BundleHash: "sha384:" + strings.Repeat("0", 96),
		IssuerIDs: []string{strings.Repeat("ef", 32)}, RequiredScope: "data:read", ConstraintEvaluators: refs}
	progress := InitialV2EvaluationProgress()
	progress.TrustAssessment = "trusted"
	_, body, err := V2EvaluationInterruptedResult(claim, 1800000000, progress)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeVerificationReceiptBodyV2(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.ConstraintEvaluators) != 2 || decoded.ConstraintEvaluators[0] != refs[0] || decoded.ConstraintEvaluators[1] != refs[1] {
		t.Fatalf("interrupted receipt evaluators = %+v", decoded.ConstraintEvaluators)
	}
	if !strings.Contains(string(body), `"constraint_evaluators":[{"profile_digest":`) {
		t.Fatalf("receipt body does not carry the canonical member: %s", body)
	}
	claim.ConstraintEvaluators = nil
	_, body, err = V2EvaluationInterruptedResult(claim, 1800000000, progress)
	if err != nil || strings.Contains(string(body), "constraint_evaluators") {
		t.Fatalf("a claim without evaluators must omit the member: %s %v", body, err)
	}
}
