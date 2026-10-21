package ratify

import "testing"

// Negative zero is rejected on v2 paths, but ordinary negative floats such
// as a geo coordinate of -0.5 are accepted.
func TestV2WireNegativeZeroOnly(t *testing.T) {
	for _, accepted := range []string{`{"a":-0.5}`, `{"a":-1}`, `{"a":-0.000001}`, `{"a":0}`} {
		if err := checkWireJSONV2([]byte(accepted)); err != nil {
			t.Errorf("%s rejected: %v", accepted, err)
		}
	}
	for _, rejected := range []string{`{"a":-0}`, `{"a":-0.0}`, `{"a":-0e5}`, `{"a":-0E0}`} {
		if err := checkWireJSONV2([]byte(rejected)); err == nil {
			t.Errorf("%s accepted", rejected)
		}
	}
	// v1 behavior is unchanged.
	if err := CheckWireJSON([]byte(`{"a":-0}`)); err != nil {
		t.Errorf("v1 decoding changed: %v", err)
	}
}
