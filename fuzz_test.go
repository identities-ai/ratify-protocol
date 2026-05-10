package ratify_test

import (
	"encoding/json"
	"testing"

	. "github.com/identities-ai/ratify-protocol"
)

// FuzzVerifyNeverPanics feeds arbitrary bytes into the verifier. The verifier
// MUST return a valid VerifyResult (valid=false is fine) and MUST NOT panic
// on any input, no matter how malformed.
func FuzzVerifyNeverPanics(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"agent_id":"x","delegations":[]}`))
	f.Add([]byte(`null`))
	f.Add([]byte{0xFF, 0xFE, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		var b ProofBundle
		if err := json.Unmarshal(data, &b); err != nil {
			return // unparseable input is fine — we're testing the verifier, not the parser
		}
		result := Verify(&b, VerifyOptions{})
		if result.IdentityStatus == "" {
			t.Error("VerifyResult.IdentityStatus must never be empty")
		}
	})
}

// FuzzCanonicalJSONNeverPanics feeds arbitrary Go values through the
// canonical JSON encoder. It must never panic.
func FuzzCanonicalJSONNeverPanics(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":"hello"}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return
		}
		_, _ = CanonicalJSON(v) // must not panic
	})
}

// FuzzDelegationSignBytesNeverPanics feeds arbitrary cert JSON into the
// delegation signable-bytes helper. It must never panic.
func FuzzDelegationSignBytesNeverPanics(f *testing.F) {
	f.Add([]byte(`{"cert_id":"x","version":1,"issuer_id":"a","subject_id":"b","scope":[],"constraints":[],"issued_at":0,"expires_at":0}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c DelegationCert
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		_, _ = DelegationSignBytes(&c) // must not panic
	})
}

// FuzzExpandScopesIdempotent verifies that ExpandScopes(ExpandScopes(s)) == ExpandScopes(s).
func FuzzExpandScopesIdempotent(f *testing.F) {
	f.Add("meeting:*")
	f.Add("comms:*")
	f.Add("meeting:attend")
	f.Add("custom:acme:foo")
	f.Add("unknown:scope")
	f.Fuzz(func(t *testing.T, scope string) {
		once := ExpandScopes([]string{scope})
		twice := ExpandScopes(once)
		if len(once) != len(twice) {
			t.Errorf("ExpandScopes is not idempotent for %q: once=%v twice=%v", scope, once, twice)
		}
		for i := range once {
			if once[i] != twice[i] {
				t.Errorf("ExpandScopes drift at index %d for %q", i, scope)
			}
		}
	})
}
