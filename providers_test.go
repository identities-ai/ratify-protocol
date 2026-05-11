package ratify_test

import (
	"bytes"
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

// ---------------------------------------------------------------------------
// Provider composition with VerifyTransactionReceipt — SPEC §5.14 + §17
// ---------------------------------------------------------------------------
//
// Receipt verification calls Verify(bundle, ...) per party. Providers attached
// to a party's options must therefore compose — a party-scoped revocation
// provider that returns true must fail the receipt; a party-scoped audit
// provider must capture each party's individual VerifyResult.

func twoPartyReceipt(t *testing.T) (*TransactionReceipt, time.Time) {
	t.Helper()
	human, humanPriv, _ := GenerateHumanRootKeypair()
	buyer, buyerPriv, _ := GenerateAgentKeypair("Buyer", "voice_agent")
	seller, sellerPriv, _ := GenerateAgentKeypair("Seller", "voice_agent")
	now := time.Now()

	mkCert := func(subjID string, subjPub HybridPublicKey, scope []string) DelegationCert {
		c := DelegationCert{
			CertID:        "cert-" + subjID,
			Version:       ProtocolVersion,
			IssuerID:      human.ID,
			IssuerPubKey:  human.PublicKey,
			SubjectID:     subjID,
			SubjectPubKey: subjPub,
			Scope:         scope,
			IssuedAt:      now.Add(-1 * time.Hour).Unix(),
			ExpiresAt:     now.Add(1 * time.Hour).Unix(),
		}
		if err := IssueDelegation(&c, humanPriv); err != nil {
			t.Fatalf("IssueDelegation: %v", err)
		}
		return c
	}
	buyerCert := mkCert(buyer.ID, buyer.PublicKey, []string{ScopePaymentsSend})
	sellerCert := mkCert(seller.ID, seller.PublicKey, []string{ScopeTransactSell})

	buyerCh := bytes.Repeat([]byte{0x01}, 32)
	buyerSig, _ := SignChallenge(buyerCh, now.Unix(), buyerPriv)
	sellerCh := bytes.Repeat([]byte{0x02}, 32)
	sellerSig, _ := SignChallenge(sellerCh, now.Unix(), sellerPriv)

	receipt := &TransactionReceipt{
		Version:            ProtocolVersion,
		TransactionID:      "tx-providers",
		CreatedAt:          now.Unix(),
		TermsSchemaURI:     "ratify://schemas/receipt/test/v1",
		TermsCanonicalJSON: []byte(`{"amount":100}`),
		Parties: []ReceiptParty{
			{PartyID: "party-buyer", Role: "buyer", AgentID: buyer.ID, AgentPubKey: buyer.PublicKey, ProofBundle: ProofBundle{
				AgentID: buyer.ID, AgentPubKey: buyer.PublicKey,
				Delegations: []DelegationCert{buyerCert},
				Challenge:   buyerCh, ChallengeAt: now.Unix(), ChallengeSig: buyerSig,
			}},
			{PartyID: "party-seller", Role: "seller", AgentID: seller.ID, AgentPubKey: seller.PublicKey, ProofBundle: ProofBundle{
				AgentID: seller.ID, AgentPubKey: seller.PublicKey,
				Delegations: []DelegationCert{sellerCert},
				Challenge:   sellerCh, ChallengeAt: now.Unix(), ChallengeSig: sellerSig,
			}},
		},
	}
	bSig, _ := SignTransactionReceiptParty(receipt, "party-buyer", buyerPriv)
	sSig, _ := SignTransactionReceiptParty(receipt, "party-seller", sellerPriv)
	receipt.PartySignatures = []ReceiptPartySignature{bSig, sSig}
	return receipt, now
}

func TestReceiptProviders_RevocationPerRole(t *testing.T) {
	receipt, now := twoPartyReceipt(t)
	// Revoke the seller's cert only; buyer should NOT be touched.
	rev := &fakeRevocation{revoked: map[string]bool{"cert-" + receipt.Parties[1].AgentID: true}}

	r := VerifyTransactionReceipt(receipt, VerifyReceiptOptions{
		Now: now,
		PartyVerifyOptions: func(role string) VerifyOptions {
			if role == "seller" {
				return VerifyOptions{Revocation: rev}
			}
			return VerifyOptions{}
		},
	})
	if r.Valid {
		t.Fatal("expected receipt invalid: seller cert revoked")
	}
	if !strings.Contains(r.ErrorReason, "party-seller") || !strings.Contains(r.ErrorReason, "revoked") {
		t.Errorf("ErrorReason should call out seller + revoked; got %q", r.ErrorReason)
	}
	if len(r.PartyResults) < 2 || r.PartyResults[0].IdentityStatus != "authorized_agent" {
		t.Errorf("buyer should have verified before seller failed; got party_results=%+v", r.PartyResults)
	}
}

func TestReceiptProviders_PolicyDenyPerRole(t *testing.T) {
	receipt, now := twoPartyReceipt(t)
	denyBuyer := &fakePolicy{allow: false}

	r := VerifyTransactionReceipt(receipt, VerifyReceiptOptions{
		Now: now,
		PartyVerifyOptions: func(role string) VerifyOptions {
			if role == "buyer" {
				return VerifyOptions{Policy: denyBuyer}
			}
			return VerifyOptions{}
		},
	})
	if r.Valid {
		t.Fatal("expected receipt invalid: buyer policy denied")
	}
	if !strings.Contains(r.ErrorReason, "party-buyer") || !strings.Contains(r.ErrorReason, "scope_denied") {
		t.Errorf("ErrorReason should call out buyer + scope_denied; got %q", r.ErrorReason)
	}
}

func TestReceiptProviders_AuditCapturesEveryParty(t *testing.T) {
	receipt, now := twoPartyReceipt(t)
	audit := &fakeAudit{}

	r := VerifyTransactionReceipt(receipt, VerifyReceiptOptions{
		Now: now,
		PartyVerifyOptions: func(_ string) VerifyOptions {
			return VerifyOptions{Audit: audit}
		},
	})
	if !r.Valid {
		t.Fatalf("expected valid receipt: %s", r.ErrorReason)
	}
	if len(audit.results) != 2 {
		t.Errorf("audit should be invoked once per party; got %d results", len(audit.results))
	}
	for i, ar := range audit.results {
		if !ar.Valid {
			t.Errorf("party %d audit entry should be Valid; got %s", i, ar.ErrorReason)
		}
	}
}

func TestReceiptProviders_AuditCapturesFailingParty(t *testing.T) {
	receipt, now := twoPartyReceipt(t)
	audit := &fakeAudit{}
	rev := &fakeRevocation{revoked: map[string]bool{"cert-" + receipt.Parties[1].AgentID: true}}

	r := VerifyTransactionReceipt(receipt, VerifyReceiptOptions{
		Now: now,
		PartyVerifyOptions: func(role string) VerifyOptions {
			opts := VerifyOptions{Audit: audit}
			if role == "seller" {
				opts.Revocation = rev
			}
			return opts
		},
	})
	if r.Valid {
		t.Fatal("expected receipt invalid: seller revoked")
	}
	// Both parties should have audit entries even though the receipt failed
	// atomically — auditing observes per-party state regardless of overall
	// atomicity.
	if len(audit.results) != 2 {
		t.Errorf("audit should have 2 entries (buyer pass + seller revoked); got %d", len(audit.results))
	}
	// Order matches Parties order: buyer first (valid), seller second (revoked).
	if audit.results[0].IdentityStatus != "authorized_agent" {
		t.Errorf("buyer audit should be authorized_agent; got %s", audit.results[0].IdentityStatus)
	}
	if audit.results[1].IdentityStatus != "revoked" {
		t.Errorf("seller audit should be revoked; got %s", audit.results[1].IdentityStatus)
	}
}
