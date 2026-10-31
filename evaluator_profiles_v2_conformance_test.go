package ratify

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestV2ConformanceEvaluatorProfiles runs testvectors/v2/evaluator-profiles.json
// against the standard profile implementations (SPEC-v2 §5.2). The profile
// digest only names the profile; these outcomes are what make two SDKs'
// implementations of one standard profile interchangeable.
func TestV2ConformanceEvaluatorProfiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testvectors", "v2", "evaluator-profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	type contextJSON struct {
		ExtensionCounts map[string]int64  `json:"extension_counts"`
		ExtensionValues map[string]string `json:"extension_values"`
	}
	var f struct {
		Version  int `json:"version"`
		Profiles []struct {
			Profile       string `json:"profile"`
			Type          string `json:"type"`
			ProfileDigest string `json:"profile_digest"`
			Cases         []struct {
				Name          string          `json:"name"`
				Params        json.RawMessage `json:"params"`
				Absent        bool            `json:"params_absent"`
				DirectAPIOnly bool            `json:"direct_api_only"`
				Context       contextJSON     `json:"context"`
				Outcome       string          `json:"outcome"`
			} `json:"cases"`
		} `json:"profiles"`
		ContextBounds []struct {
			Name       string      `json:"name"`
			Context    contextJSON `json:"context"`
			ErrorClass string      `json:"error_class"`
		} `json:"context_bounds"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	standard := map[string]ConstraintEvaluatorRegistrationV2{
		ProfileMaxCountV2:      StandardMaxCountEvaluatorV2(),
		ProfileAllowedValuesV2: StandardAllowedValuesEvaluatorV2(),
	}
	if f.Version != 1 || len(f.Profiles) != len(standard) || len(f.ContextBounds) == 0 {
		t.Fatalf("evaluator-profiles.json: version %d, %d profiles, %d context bounds", f.Version, len(f.Profiles), len(f.ContextBounds))
	}
	for _, suite := range f.Profiles {
		registration, ok := standard[suite.Profile]
		if !ok || string(registration.Descriptor.Type) != suite.Type {
			t.Fatalf("unknown standard profile %s for %s", suite.Profile, suite.Type)
		}
		digest, err := ConstraintProfileDigestV2(registration.Descriptor)
		if err != nil || digest != suite.ProfileDigest {
			t.Fatalf("%s digest %s (%v), want %s", suite.Profile, digest, err, suite.ProfileDigest)
		}
		outcomes := map[string]int{}
		for _, c := range suite.Cases {
			t.Run(suite.Profile+"/"+c.Name, func(t *testing.T) {
				var params []byte
				if !c.Absent {
					if len(c.Params) == 0 {
						t.Fatal("case has neither params nor params_absent")
					}
					var value any
					decoder := json.NewDecoder(bytes.NewReader(c.Params))
					decoder.UseNumber()
					if err := decoder.Decode(&value); err != nil {
						t.Fatal(err)
					}
					if params, err = CanonicalJSON(value); err != nil {
						t.Fatal(err)
					}
					// SPEC-v2 §5.2: a certificate can carry these params only
					// when they are a JSON object; direct_api_only says not.
					typeJSON, _ := json.Marshal(suite.Type)
					var carried ConstraintV2
					wireErr := json.Unmarshal([]byte(`{"params":`+string(params)+`,"type":`+string(typeJSON)+`}`), &carried)
					if (wireErr != nil) != c.DirectAPIOnly {
						t.Fatalf("direct_api_only %t, but a certificate constraint with these params decodes with error %v", c.DirectAPIOnly, wireErr)
					}
				}
				ctx := ConstraintContextV2{ExtensionCounts: c.Context.ExtensionCounts, ExtensionValues: c.Context.ExtensionValues}
				if err := validateV2RequestContext(ctx); err != nil {
					t.Fatalf("case context is outside the request-context bounds: %v", err)
				}
				result, err := registration.Evaluate(context.Background(), ConstraintEvaluationInputV2{
					Type: registration.Descriptor.Type, ParamsJSON: params, CertID: "cert-1", IssuerID: "issuer-1", Context: ctx, EvaluationTime: 1_000,
				})
				if err != nil {
					t.Fatalf("standard profile returned an error: %v", err)
				}
				if string(result.Outcome) != c.Outcome || result.ValidUntil != 0 {
					t.Fatalf("outcome %s (horizon %d, %s), want %s with no horizon", result.Outcome, result.ValidUntil, result.Detail, c.Outcome)
				}
			})
			outcomes[c.Outcome]++
		}
		if outcomes["pass"] == 0 || outcomes["denied"] == 0 || outcomes["unverifiable"] == 0 {
			t.Fatalf("%s cases do not cover every outcome: %v", suite.Profile, outcomes)
		}
	}
	for _, c := range f.ContextBounds {
		t.Run("context_bounds/"+c.Name, func(t *testing.T) {
			err := validateV2RequestContext(ConstraintContextV2{ExtensionCounts: c.Context.ExtensionCounts, ExtensionValues: c.Context.ExtensionValues})
			if string(V2ErrorClassOf(err)) != c.ErrorClass {
				t.Fatalf("error class %q (%v), want %q", V2ErrorClassOf(err), err, c.ErrorClass)
			}
		})
	}
}
