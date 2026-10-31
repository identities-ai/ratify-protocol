package ratify

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

// FuzzV2ConstraintEvaluatorParams decodes arbitrary params through both the
// v2 constraint decoder and the standard evaluator profiles. Neither may
// panic; an accepted params object must satisfy the profile bounds; and the
// standard evaluators only ever return pass, denied, or unverifiable for a
// decoded constraint, whatever its params.
func FuzzV2ConstraintEvaluatorParams(f *testing.F) {
	for _, seed := range []string{
		`{"counter":"nodes","max":10}`,
		`{"counter":"nodes","max":0}`,
		`{"counter":"nodes","max":9007199254740991}`,
		`{"counter":"nodes","max":-1}`,
		`{"counter":"nodes","max":1.5}`,
		`{"counter":"nodes","counter":"x","max":1}`,
		`{"allowed":["inspection","maintenance"],"field":"work_order_category"}`,
		`{"allowed":[],"field":"f"}`,
		`{"allowed":["a","a"],"field":"f"}`,
		`{"allowed":[{"x":[1,2,{"y":null}]}],"field":"f"}`,
		`{}`, `[]`, `null`, `"x"`, `{"a":{"b":{"c":{"d":{}}}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if counter, max, err := decodeMaxCountParamsV2(data); err == nil {
			if !validExtensionContextNameV2(counter) || max < 0 || max > maxSafeInteger {
				t.Fatalf("accepted out-of-profile count params %q %d", counter, max)
			}
		}
		if field, allowed, err := decodeAllowedValuesParamsV2(data); err == nil {
			if !validExtensionContextNameV2(field) || len(allowed) == 0 || len(allowed) > MaxAllowedValuesV2 {
				t.Fatalf("accepted out-of-profile allowed params %q %d", field, len(allowed))
			}
			for i, v := range allowed {
				if v == "" || len(v) > MaxExtensionContextValueBytesV2 || slices.Contains(allowed[:i], v) {
					t.Fatalf("accepted an invalid allowed value %q", v)
				}
			}
		}
		for _, kind := range []ConstraintType{ConstraintMaxCountV2, ConstraintAllowedValuesV2} {
			wire := append(append([]byte(`{"params":`), data...), []byte(`,"type":"`+string(kind)+`"}`)...)
			var c ConstraintV2
			if json.Unmarshal(wire, &c) != nil {
				continue
			}
			params, err := extensionParamsJSONV2(c)
			if err != nil {
				continue
			}
			in := ConstraintEvaluationInputV2{Type: kind, ParamsJSON: params, EvaluationTime: 1800000000,
				Context: ConstraintContextV2{ExtensionCounts: map[string]int64{"nodes": 3}, ExtensionValues: map[string]string{"work_order_category": "maintenance"}}}
			for _, reg := range []ConstraintEvaluatorRegistrationV2{StandardMaxCountEvaluatorV2(), StandardAllowedValuesEvaluatorV2()} {
				result, err := reg.Evaluate(context.Background(), in)
				if err != nil {
					t.Fatalf("standard evaluator returned an error: %v", err)
				}
				switch result.Outcome {
				case ConstraintOutcomePassV2, ConstraintOutcomeDeniedV2, ConstraintOutcomeUnverifiableV2:
				default:
					t.Fatalf("standard evaluator returned outcome %q", result.Outcome)
				}
				if result.ValidUntil != 0 {
					t.Fatal("standard evaluators never set a horizon")
				}
			}
		}
	})
}
