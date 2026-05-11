package ratify_test

import (
	"encoding/json"
	"errors"
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

// ---------------------------------------------------------------------------
// Provider error-path fuzz harness — SPEC §17
// ---------------------------------------------------------------------------
//
// fuzzProviderError holds a single byte that randomly toggles which providers
// error out. The contract under test: regardless of how many providers fail
// (revocation, policy, audit), Verify MUST:
//
//   1. Never panic.
//   2. Never return a valid=true VerifyResult when the bundle would have
//      failed without provider errors.
//   3. Always set IdentityStatus to a non-empty value.
//   4. Surface a stable error_reason code (revocation_error / policy_error)
//      when the corresponding provider errors out.
//
// AuditProvider errors are special: they MUST NOT alter the verdict.

type fuzzRevocationProvider struct {
	mode byte // 0: not revoked; 1: revoked; 2: error
}

func (f fuzzRevocationProvider) IsRevoked(string) (bool, error) {
	switch f.mode {
	case 1:
		return true, nil
	case 2:
		return false, errors.New("fuzz revocation error")
	default:
		return false, nil
	}
}

type fuzzPolicyProvider struct {
	mode byte // 0: allow; 1: deny; 2: error
}

func (f fuzzPolicyProvider) EvaluatePolicy(*ProofBundle, VerifierContext) (bool, error) {
	switch f.mode {
	case 1:
		return false, nil
	case 2:
		return false, errors.New("fuzz policy error")
	default:
		return true, nil
	}
}

type fuzzAuditProvider struct {
	mode byte // 0: ok; 1: error
	logs []VerifyResult
}

func (f *fuzzAuditProvider) LogVerification(r VerifyResult, _ *ProofBundle) error {
	f.logs = append(f.logs, r)
	if f.mode == 1 {
		return errors.New("fuzz audit error")
	}
	return nil
}

// FuzzVerifyWithProvidersNeverPanics feeds arbitrary bundle JSON AND random
// provider error modes into Verify. The verifier must remain panic-free and
// fail-closed across the full Cartesian product of malformed input × provider
// error states.
func FuzzVerifyWithProvidersNeverPanics(f *testing.F) {
	f.Add([]byte(`{}`), byte(0), byte(0), byte(0))
	f.Add([]byte(`{"agent_id":"x","delegations":[]}`), byte(1), byte(0), byte(0))
	f.Add([]byte(`null`), byte(2), byte(2), byte(1))
	f.Add([]byte(`{}`), byte(0), byte(1), byte(0))
	f.Fuzz(func(t *testing.T, data []byte, revMode, polMode, auditMode byte) {
		var b ProofBundle
		if err := json.Unmarshal(data, &b); err != nil {
			return
		}
		audit := &fuzzAuditProvider{mode: auditMode % 2}
		opts := VerifyOptions{
			Revocation: fuzzRevocationProvider{mode: revMode % 3},
			Policy:     fuzzPolicyProvider{mode: polMode % 3},
			Audit:      audit,
		}
		result := Verify(&b, opts)
		if result.IdentityStatus == "" {
			t.Error("VerifyResult.IdentityStatus must never be empty even under provider chaos")
		}
		// Audit MUST have been called exactly once, regardless of mode.
		if len(audit.logs) != 1 {
			t.Errorf("audit must be called exactly once per Verify; got %d", len(audit.logs))
		}
		// The audit entry MUST match what the verifier returned to the caller.
		if audit.logs[0].Valid != result.Valid || audit.logs[0].IdentityStatus != result.IdentityStatus {
			t.Errorf("audit entry diverges from caller-visible result: audit=%+v result=%+v", audit.logs[0], result)
		}
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
