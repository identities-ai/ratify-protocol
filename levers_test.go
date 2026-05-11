package ratify_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	. "github.com/identities-ai/ratify-protocol"
)

// ---------------------------------------------------------------------------
// Lever 1: VerificationReceipt — SPEC §17.5
// ---------------------------------------------------------------------------
//
// A signed attestation that "this verifier, with this key, saw this exact
// bundle, and reached this decision, at this time." The cryptographic
// complement of AuditProvider: an audit provider can throw entries away,
// but a chain of VerificationReceipts is unforgeable.

func TestVerificationReceipt_RoundTrip(t *testing.T) {
	bundle, _ := providerBundle(t)
	verifier, verifierPriv, _ := GenerateAgentKeypair("verifier-1", "verifier")
	result := Verify(bundle, VerifyOptions{})
	if !result.Valid {
		t.Fatalf("setup: bundle should verify; got %s", result.ErrorReason)
	}

	r, err := IssueVerificationReceipt(
		bundle, result,
		verifier.ID, verifier.PublicKey, verifierPriv,
		nil, // genesis
		time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("IssueVerificationReceipt: %v", err)
	}
	if err := VerifyVerificationReceipt(r); err != nil {
		t.Fatalf("VerifyVerificationReceipt: %v", err)
	}
	if r.Decision != "authorized_agent" {
		t.Errorf("Decision = %q, want authorized_agent", r.Decision)
	}
	if len(r.BundleHash) != sha256.Size {
		t.Errorf("BundleHash should be 32 bytes; got %d", len(r.BundleHash))
	}
	zeros := make([]byte, sha256.Size)
	if !bytes.Equal(r.PrevHash, zeros) {
		t.Errorf("genesis prev_hash should be all zeros")
	}
}

func TestVerificationReceipt_DetectsTampering(t *testing.T) {
	bundle, _ := providerBundle(t)
	verifier, verifierPriv, _ := GenerateAgentKeypair("verifier-1", "verifier")
	result := Verify(bundle, VerifyOptions{})

	r, _ := IssueVerificationReceipt(
		bundle, result, verifier.ID, verifier.PublicKey, verifierPriv,
		nil, time.Now().Unix(),
	)
	// Flip the decision after signing.
	r.Decision = "revoked"
	if err := VerifyVerificationReceipt(r); err == nil {
		t.Fatal("tampered receipt MUST not verify")
	}
}

func TestVerificationReceipt_DetectsBundleSubstitution(t *testing.T) {
	bundle1, _ := providerBundle(t)
	bundle2, _ := providerBundle(t)
	verifier, verifierPriv, _ := GenerateAgentKeypair("v", "verifier")
	result := Verify(bundle1, VerifyOptions{})

	r, _ := IssueVerificationReceipt(
		bundle1, result, verifier.ID, verifier.PublicKey, verifierPriv,
		nil, time.Now().Unix(),
	)
	// Replace BundleHash with that of a different bundle — sig must fail.
	r.BundleHash, _ = BundleHash(bundle2)
	if err := VerifyVerificationReceipt(r); err == nil {
		t.Fatal("substituted bundle_hash MUST invalidate receipt")
	}
}

func TestVerificationReceipt_ChainLinkage(t *testing.T) {
	bundle, _ := providerBundle(t)
	verifier, verifierPriv, _ := GenerateAgentKeypair("v", "verifier")
	result := Verify(bundle, VerifyOptions{})

	r1, _ := IssueVerificationReceipt(
		bundle, result, verifier.ID, verifier.PublicKey, verifierPriv,
		nil, time.Now().Unix(),
	)
	prev, err := ReceiptHash(r1)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	r2, _ := IssueVerificationReceipt(
		bundle, result, verifier.ID, verifier.PublicKey, verifierPriv,
		prev, time.Now().Unix(),
	)
	// r2.PrevHash must match the digest of r1's signable bytes.
	if !bytes.Equal(r2.PrevHash, prev) {
		t.Errorf("r2.PrevHash should chain off r1")
	}
	// Forge a chain break: tamper r1 retroactively, recompute its hash → r2's
	// chain pointer is now wrong.
	r1.Decision = "tampered"
	prevAfterTamper, _ := ReceiptHash(r1)
	if bytes.Equal(prev, prevAfterTamper) {
		t.Fatal("ReceiptHash must change when receipt is tampered")
	}
}

func TestBundleHash_Deterministic(t *testing.T) {
	bundle, _ := providerBundle(t)
	a, _ := BundleHash(bundle)
	b, _ := BundleHash(bundle)
	if !bytes.Equal(a, b) {
		t.Error("BundleHash must be deterministic")
	}
	if len(a) != sha256.Size {
		t.Errorf("BundleHash must be 32 bytes; got %d", len(a))
	}
}

// ---------------------------------------------------------------------------
// Lever 2: PolicyVerdict — SPEC §17.6
// ---------------------------------------------------------------------------

func TestPolicyVerdict_RoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	v, err := IssuePolicyVerdict(
		"verdict-1", "agent-A", "meeting:attend", true, ctxHash,
		now.Unix(), now.Add(time.Hour).Unix(), secret,
	)
	if err != nil {
		t.Fatalf("IssuePolicyVerdict: %v", err)
	}
	if err := VerifyPolicyVerdict(v, secret, "agent-A", "meeting:attend", ctxHash, now); err != nil {
		t.Fatalf("VerifyPolicyVerdict: %v", err)
	}
}

func TestPolicyVerdict_DenyVerdict(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	v, _ := IssuePolicyVerdict(
		"v", "agent-A", "payments:send", false, ctxHash,
		now.Unix(), now.Add(time.Hour).Unix(), secret,
	)
	err := VerifyPolicyVerdict(v, secret, "agent-A", "payments:send", ctxHash, now)
	if err == nil || !strings.Contains(err.Error(), "policy_verdict_denied") {
		t.Errorf("explicit deny should return policy_verdict_denied; got %v", err)
	}
}

func TestPolicyVerdict_WrongSecretRejected(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	wrongSecret := bytes.Repeat([]byte{0x44}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	v, _ := IssuePolicyVerdict("v", "a", "s", true, ctxHash, now.Unix(), now.Add(time.Hour).Unix(), secret)
	if err := VerifyPolicyVerdict(v, wrongSecret, "a", "s", ctxHash, now); err == nil {
		t.Fatal("verdict signed by another secret must not verify")
	}
}

func TestPolicyVerdict_ContextHashMismatch(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxA, _ := VerifierContextHash(VerifierContext{HasLocation: true, CurrentLat: 37.0, CurrentLon: -122.0})
	ctxB, _ := VerifierContextHash(VerifierContext{HasLocation: true, CurrentLat: 51.5, CurrentLon: -0.1})

	v, _ := IssuePolicyVerdict("v", "a", "s", true, ctxA, now.Unix(), now.Add(time.Hour).Unix(), secret)
	// Caller is in a different context (London vs SF) — verdict must reject.
	if err := VerifyPolicyVerdict(v, secret, "a", "s", ctxB, now); err == nil {
		t.Fatal("verdict for one context must not apply to another")
	}
}

func TestPolicyVerdict_Expired(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	v, _ := IssuePolicyVerdict("v", "a", "s", true, ctxHash, now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix(), secret)
	if err := VerifyPolicyVerdict(v, secret, "a", "s", ctxHash, now); err == nil {
		t.Fatal("expired verdict must not verify")
	}
}

func TestPolicyVerdict_FastPathSkipsLivePolicy(t *testing.T) {
	bundle, _ := providerBundle(t)
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	v, _ := IssuePolicyVerdict(
		"vid", bundle.AgentID, "meeting:attend", true, ctxHash,
		now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(),
		secret,
	)
	livePolicy := &fakePolicy{allow: false} // would fail if consulted

	res := Verify(bundle, VerifyOptions{
		RequiredScope: "meeting:attend",
		Policy:        livePolicy,
		PolicyVerdict: v,
		PolicySecret:  secret,
	})
	if !res.Valid {
		t.Fatalf("verdict fast-path should accept: %s", res.ErrorReason)
	}
	if livePolicy.calls != 0 {
		t.Errorf("live policy MUST NOT be called when valid verdict is present; calls=%d", livePolicy.calls)
	}
}

func TestPolicyVerdict_FallsBackOnStaleVerdict(t *testing.T) {
	bundle, _ := providerBundle(t)
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	// Expired verdict — verdict-verify fails; should fall back to live policy.
	v, _ := IssuePolicyVerdict(
		"vid", bundle.AgentID, "meeting:attend", true, ctxHash,
		now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix(),
		secret,
	)
	livePolicy := &fakePolicy{allow: true}

	res := Verify(bundle, VerifyOptions{
		RequiredScope: "meeting:attend",
		Policy:        livePolicy,
		PolicyVerdict: v,
		PolicySecret:  secret,
	})
	if !res.Valid {
		t.Fatalf("expected valid (live policy allows): %s", res.ErrorReason)
	}
	if livePolicy.calls != 1 {
		t.Errorf("live policy should be consulted when verdict stale; calls=%d", livePolicy.calls)
	}
}

func TestPolicyVerdict_CachedDenyFastPath(t *testing.T) {
	bundle, _ := providerBundle(t)
	secret := bytes.Repeat([]byte{0x33}, 32)
	now := time.Now()
	ctxHash, _ := VerifierContextHash(VerifierContext{})

	v, _ := IssuePolicyVerdict(
		"vid", bundle.AgentID, "meeting:attend", false, ctxHash,
		now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(),
		secret,
	)
	livePolicy := &fakePolicy{allow: true}

	res := Verify(bundle, VerifyOptions{
		RequiredScope: "meeting:attend",
		Policy:        livePolicy,
		PolicyVerdict: v,
		PolicySecret:  secret,
	})
	if res.Valid {
		t.Fatal("cached deny must reject")
	}
	if res.IdentityStatus != "scope_denied" {
		t.Errorf("IdentityStatus = %q, want scope_denied", res.IdentityStatus)
	}
	if livePolicy.calls != 0 {
		t.Errorf("live policy MUST NOT be called when valid cached deny exists; calls=%d", livePolicy.calls)
	}
}

// ---------------------------------------------------------------------------
// Lever 3: ConstraintEvaluator registry — SPEC §17.7
// ---------------------------------------------------------------------------

type fakeConcurrentSessionsEvaluator struct {
	max   int
	count int
}

func (f *fakeConcurrentSessionsEvaluator) Evaluate(
	c Constraint, _ string, _ VerifierContext, _ time.Time,
) error {
	if f.count > f.max {
		return errors.New("too many concurrent sessions")
	}
	return nil
}

func providerBundleWithCustomConstraint(t *testing.T, constraintType string) (*ProofBundle, string) {
	t.Helper()
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	agent, agentPriv, _ := GenerateAgentKeypair("Custom Bot", "custom")
	now := time.Now()
	cert := &DelegationCert{
		CertID:        "custom-constraint-cert",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(time.Hour).Unix(),
		Constraints: []Constraint{
			{Type: ConstraintType(constraintType)},
		},
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}
	challenge, _ := GenerateChallenge()
	sig, _ := SignChallenge(challenge, now.Unix(), agentPriv)
	return &ProofBundle{
		AgentID: agent.ID, AgentPubKey: agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  now.Unix(),
		ChallengeSig: sig,
	}, cert.CertID
}

func TestConstraintEvaluator_UnknownTypeFailsClosed(t *testing.T) {
	bundle, _ := providerBundleWithCustomConstraint(t, "verify.max_concurrent_sessions")
	res := Verify(bundle, VerifyOptions{})
	if res.Valid {
		t.Fatal("unknown constraint type MUST fail closed")
	}
	if res.IdentityStatus != "constraint_unknown" {
		t.Errorf("IdentityStatus = %q, want constraint_unknown", res.IdentityStatus)
	}
}

func TestConstraintEvaluator_RegistryAllow(t *testing.T) {
	bundle, _ := providerBundleWithCustomConstraint(t, "verify.max_concurrent_sessions")
	ev := &fakeConcurrentSessionsEvaluator{max: 10, count: 3}

	res := Verify(bundle, VerifyOptions{
		ConstraintEvaluators: map[string]ConstraintEvaluator{
			"verify.max_concurrent_sessions": ev,
		},
	})
	if !res.Valid {
		t.Fatalf("registered evaluator should allow; got %s: %s", res.IdentityStatus, res.ErrorReason)
	}
}

func TestConstraintEvaluator_RegistryDeny(t *testing.T) {
	bundle, _ := providerBundleWithCustomConstraint(t, "verify.max_concurrent_sessions")
	ev := &fakeConcurrentSessionsEvaluator{max: 10, count: 999}

	res := Verify(bundle, VerifyOptions{
		ConstraintEvaluators: map[string]ConstraintEvaluator{
			"verify.max_concurrent_sessions": ev,
		},
	})
	if res.Valid {
		t.Fatal("registered evaluator returned error; should deny")
	}
	if res.IdentityStatus != "constraint_denied" {
		t.Errorf("IdentityStatus = %q, want constraint_denied", res.IdentityStatus)
	}
}

type fakeUnverifiableEvaluator struct{}

func (fakeUnverifiableEvaluator) Evaluate(
	_ Constraint, _ string, _ VerifierContext, _ time.Time,
) error {
	return ErrConstraintUnverifiable
}

func TestConstraintEvaluator_UnverifiableRoutes(t *testing.T) {
	bundle, _ := providerBundleWithCustomConstraint(t, "verify.needs_context")
	res := Verify(bundle, VerifyOptions{
		ConstraintEvaluators: map[string]ConstraintEvaluator{
			"verify.needs_context": fakeUnverifiableEvaluator{},
		},
	})
	if res.Valid {
		t.Fatal("unverifiable extension constraint must fail")
	}
	if res.IdentityStatus != "constraint_unverifiable" {
		t.Errorf("IdentityStatus = %q, want constraint_unverifiable", res.IdentityStatus)
	}
}

// ---------------------------------------------------------------------------
// Lever 4: AnchorResolver / anchor-bound audit — SPEC §17.8
// ---------------------------------------------------------------------------

type fakeAnchorResolver struct {
	anchors map[string]*Anchor
	err     error
}

func (f *fakeAnchorResolver) ResolveAnchor(humanID string) (*Anchor, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.anchors[humanID], nil
}

func TestAnchorResolver_PopulatesResult(t *testing.T) {
	bundle, _ := providerBundle(t)
	// Bundle has no anchor pre-attached; we resolve from human_id.
	humanID := bundle.Delegations[len(bundle.Delegations)-1].IssuerID
	anchor := &Anchor{Type: "enterprise_sso", Provider: "okta", Reference: "opaque-ref", VerifiedAt: 1000}

	res := Verify(bundle, VerifyOptions{
		AnchorResolver: &fakeAnchorResolver{anchors: map[string]*Anchor{humanID: anchor}},
	})
	if !res.Valid {
		t.Fatalf("expected valid: %s", res.ErrorReason)
	}
	if res.Anchor == nil {
		t.Fatal("Anchor should be populated")
	}
	if res.Anchor.Provider != "okta" {
		t.Errorf("Anchor.Provider = %q, want okta", res.Anchor.Provider)
	}
}

func TestAnchorResolver_ResolverErrorIsNonFatal(t *testing.T) {
	bundle, _ := providerBundle(t)
	res := Verify(bundle, VerifyOptions{
		AnchorResolver: &fakeAnchorResolver{err: errors.New("identity directory down")},
	})
	if !res.Valid {
		t.Fatalf("anchor resolver error MUST NOT fail the bundle; got %s", res.ErrorReason)
	}
	if res.Anchor != nil {
		t.Error("Anchor should be nil when resolver errors")
	}
}

func TestAnchorResolver_NoResolverLeavesAnchorNil(t *testing.T) {
	bundle, _ := providerBundle(t)
	res := Verify(bundle, VerifyOptions{})
	if !res.Valid {
		t.Fatalf("expected valid: %s", res.ErrorReason)
	}
	if res.Anchor != nil {
		t.Error("Anchor should be nil when no resolver is configured")
	}
}

func TestAnchorResolver_AuditObservesAnchor(t *testing.T) {
	bundle, _ := providerBundle(t)
	humanID := bundle.Delegations[len(bundle.Delegations)-1].IssuerID
	anchor := &Anchor{Type: "email", Provider: "google", Reference: "h:abc", VerifiedAt: 100}
	audit := &fakeAudit{}

	res := Verify(bundle, VerifyOptions{
		AnchorResolver: &fakeAnchorResolver{anchors: map[string]*Anchor{humanID: anchor}},
		Audit:          audit,
	})
	if !res.Valid {
		t.Fatalf("expected valid: %s", res.ErrorReason)
	}
	if len(audit.results) != 1 {
		t.Fatalf("expected 1 audit entry; got %d", len(audit.results))
	}
	if audit.results[0].Anchor == nil || audit.results[0].Anchor.Provider != "google" {
		t.Errorf("audit entry should observe anchor; got %+v", audit.results[0].Anchor)
	}
}

// ---------------------------------------------------------------------------
// Lever 5: IsRevoked closure remains functional (deprecation is doc-only)
// ---------------------------------------------------------------------------

func TestLegacyIsRevoked_StillWorks(t *testing.T) {
	bundle, certID := providerBundle(t)
	res := Verify(bundle, VerifyOptions{
		IsRevoked: func(c string) bool { return c == certID },
	})
	if res.Valid {
		t.Fatal("legacy closure should still revoke")
	}
	if res.IdentityStatus != "revoked" {
		t.Errorf("IdentityStatus = %q, want revoked", res.IdentityStatus)
	}
}
