package ratify_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	. "github.com/identities-ai/ratify-protocol"
)

// providerBundle builds a known-good single-cert ProofBundle used as the
// fixture for every provider test below. Verified against the verifier
// with no options, it MUST produce Valid=true — that's the precondition
// the provider tests build on.
func providerBundle(t *testing.T) (*ProofBundle, string) {
	t.Helper()
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}
	agent, agentPriv, err := GenerateAgentKeypair("Provider Bot", "custom")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}

	now := time.Now()
	cert := &DelegationCert{
		CertID:        "provider-cert-001",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}

	challenge, _ := GenerateChallenge()
	challengeAt := now.Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	return &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}, cert.CertID
}

// ---------------------------------------------------------------------------
// RevocationProvider — SPEC §17.1
// ---------------------------------------------------------------------------

type fakeRevocation struct {
	revoked map[string]bool
	err     error
	calls   int
}

func (f *fakeRevocation) IsRevoked(certID string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[certID], nil
}

func TestRevocationProvider_Revoked(t *testing.T) {
	bundle, certID := providerBundle(t)
	provider := &fakeRevocation{revoked: map[string]bool{certID: true}}

	res := Verify(bundle, VerifyOptions{Revocation: provider})
	if res.Valid {
		t.Fatal("expected revoked cert to fail")
	}
	if res.IdentityStatus != "revoked" {
		t.Errorf("IdentityStatus = %q, want revoked", res.IdentityStatus)
	}
	if provider.calls != 1 {
		t.Errorf("provider.calls = %d, want 1", provider.calls)
	}
}

func TestRevocationProvider_NotRevoked(t *testing.T) {
	bundle, _ := providerBundle(t)
	provider := &fakeRevocation{revoked: map[string]bool{}}

	res := Verify(bundle, VerifyOptions{Revocation: provider})
	if !res.Valid {
		t.Fatalf("expected valid, got reason=%s", res.ErrorReason)
	}
}

func TestRevocationProvider_LookupError(t *testing.T) {
	bundle, _ := providerBundle(t)
	provider := &fakeRevocation{err: errors.New("upstream timeout")}

	res := Verify(bundle, VerifyOptions{Revocation: provider})
	if res.Valid {
		t.Fatal("provider error must fail closed")
	}
	if !strings.Contains(res.ErrorReason, "revocation_error") {
		t.Errorf("ErrorReason = %q, want it to contain revocation_error", res.ErrorReason)
	}
}

func TestRevocationProvider_TakesPrecedenceOverClosure(t *testing.T) {
	bundle, certID := providerBundle(t)
	provider := &fakeRevocation{revoked: map[string]bool{certID: true}}

	closureCalled := false
	res := Verify(bundle, VerifyOptions{
		Revocation: provider,
		IsRevoked: func(string) bool {
			closureCalled = true
			return false
		},
	})
	if res.Valid {
		t.Fatal("provider should still revoke")
	}
	if closureCalled {
		t.Error("legacy IsRevoked closure must not be called when Revocation provider is set")
	}
}

func TestForceRevocationCheck_AcceptsProvider(t *testing.T) {
	bundle, _ := providerBundle(t)
	provider := &fakeRevocation{revoked: map[string]bool{}}

	// ForceRevocationCheck used to require IsRevoked closure; provider must
	// also satisfy it.
	res := Verify(bundle, VerifyOptions{
		Revocation:           provider,
		ForceRevocationCheck: true,
	})
	if !res.Valid {
		t.Fatalf("expected valid; got %s: %s", res.IdentityStatus, res.ErrorReason)
	}
}

// ---------------------------------------------------------------------------
// PolicyProvider — SPEC §17.2
// ---------------------------------------------------------------------------

type fakePolicy struct {
	allow bool
	err   error
	calls int
}

func (f *fakePolicy) EvaluatePolicy(_ *ProofBundle, _ VerifierContext) (bool, error) {
	f.calls++
	return f.allow, f.err
}

func TestPolicyProvider_Allow(t *testing.T) {
	bundle, _ := providerBundle(t)
	policy := &fakePolicy{allow: true}

	res := Verify(bundle, VerifyOptions{Policy: policy})
	if !res.Valid {
		t.Fatalf("expected valid; got %s: %s", res.IdentityStatus, res.ErrorReason)
	}
	if policy.calls != 1 {
		t.Errorf("policy.calls = %d, want 1", policy.calls)
	}
}

func TestPolicyProvider_Deny(t *testing.T) {
	bundle, _ := providerBundle(t)
	policy := &fakePolicy{allow: false}

	res := Verify(bundle, VerifyOptions{Policy: policy})
	if res.Valid {
		t.Fatal("expected denied bundle")
	}
	if res.IdentityStatus != "scope_denied" {
		t.Errorf("IdentityStatus = %q, want scope_denied", res.IdentityStatus)
	}
}

func TestPolicyProvider_Error(t *testing.T) {
	bundle, _ := providerBundle(t)
	policy := &fakePolicy{err: errors.New("opa eval crashed")}

	res := Verify(bundle, VerifyOptions{Policy: policy})
	if res.Valid {
		t.Fatal("policy provider error must fail closed")
	}
	if !strings.Contains(res.ErrorReason, "policy_error") {
		t.Errorf("ErrorReason = %q, want it to contain policy_error", res.ErrorReason)
	}
}

func TestPolicyProvider_OnlyRunsAfterCryptoChecks(t *testing.T) {
	bundle, _ := providerBundle(t)
	// Tamper challenge so the crypto check fails first.
	bundle.Challenge = []byte("tampered")
	policy := &fakePolicy{allow: true}

	res := Verify(bundle, VerifyOptions{Policy: policy})
	if res.Valid {
		t.Fatal("tampered bundle must fail")
	}
	if policy.calls != 0 {
		t.Errorf("policy must not be evaluated when crypto fails; calls=%d", policy.calls)
	}
}

// ---------------------------------------------------------------------------
// AuditProvider — SPEC §17.3
// ---------------------------------------------------------------------------

type fakeAudit struct {
	results []VerifyResult
	err     error
}

func (f *fakeAudit) LogVerification(result VerifyResult, _ *ProofBundle) error {
	f.results = append(f.results, result)
	return f.err
}

func TestAuditProvider_LogsSuccess(t *testing.T) {
	bundle, _ := providerBundle(t)
	audit := &fakeAudit{}

	res := Verify(bundle, VerifyOptions{Audit: audit})
	if !res.Valid {
		t.Fatalf("expected valid; got %s", res.ErrorReason)
	}
	if len(audit.results) != 1 {
		t.Fatalf("audit.results = %d, want 1", len(audit.results))
	}
	if !audit.results[0].Valid {
		t.Error("audit should record the success result")
	}
}

func TestAuditProvider_LogsFailure(t *testing.T) {
	bundle, _ := providerBundle(t)
	bundle.Challenge = []byte("tampered")
	audit := &fakeAudit{}

	res := Verify(bundle, VerifyOptions{Audit: audit})
	if res.Valid {
		t.Fatal("tampered bundle must fail")
	}
	if len(audit.results) != 1 {
		t.Fatalf("audit must record the failure too; got %d results", len(audit.results))
	}
	if audit.results[0].Valid {
		t.Error("logged result should reflect failure")
	}
}

func TestAuditProvider_ErrorsDoNotAlterVerdict(t *testing.T) {
	bundle, _ := providerBundle(t)
	audit := &fakeAudit{err: errors.New("audit store offline")}

	res := Verify(bundle, VerifyOptions{Audit: audit})
	if !res.Valid {
		t.Fatalf("audit error must not flip verdict; got %s: %s", res.IdentityStatus, res.ErrorReason)
	}
}
