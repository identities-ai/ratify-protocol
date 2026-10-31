package ratify

import "testing"

// Protocol v2 forbids floating point on the wire: every fractional or
// exponent spelling is rejected, as is the integer spelling -0. v1 decoding
// is unchanged and still accepts float constraint bounds.
func TestV2WireRejectsFloatsAndNegativeZero(t *testing.T) {
	for _, accepted := range []string{`{"a":-1}`, `{"a":0}`, `{"a":9007199254740991}`} {
		if err := checkWireJSONV2([]byte(accepted)); err != nil {
			t.Errorf("%s rejected: %v", accepted, err)
		}
	}
	for _, rejected := range []string{`{"a":-0}`, `{"a":-0.0}`, `{"a":-0e5}`, `{"a":-0E0}`, `{"a":-0.5}`, `{"a":1.0}`, `{"a":1e3}`, `{"a":[0.000001]}`, `{"params":{"x":2.5}}`} {
		if err := checkWireJSONV2([]byte(rejected)); err == nil {
			t.Errorf("%s accepted", rejected)
		}
	}
	// v1 behavior is unchanged.
	for _, v1 := range []string{`{"a":-0}`, `{"a":-0.5}`, `{"lat":37.77}`} {
		if err := CheckWireJSON([]byte(v1)); err != nil {
			t.Errorf("v1 decoding changed for %s: %v", v1, err)
		}
	}
}
