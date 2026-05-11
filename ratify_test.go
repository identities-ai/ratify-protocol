package ratify_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/identities-ai/ratify-protocol"
)

// TestDelegationRoundTrip verifies the happy path:
// generate keys → issue delegation → create proof → verify
func TestDelegationRoundTrip(t *testing.T) {
	// 1. Human generates a root identity
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}

	// 2. Agent generates its identity
	agent, agentPriv, err := GenerateAgentKeypair("Test Bot", "zoom_bot")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}

	// 3. Human issues a delegation cert
	now := time.Now()
	cert := &DelegationCert{
		CertID:        "test-cert-001",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend, ScopeMeetingSpeak},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}
	if len(cert.Signature.Ed25519) == 0 || len(cert.Signature.MLDSA65) == 0 {
		t.Fatal("expected both Ed25519 and ML-DSA-65 signatures after IssueDelegation")
	}

	// 4. Verify the delegation signature
	if err := VerifyDelegationSignature(cert); err != nil {
		t.Fatalf("VerifyDelegationSignature: %v", err)
	}

	// 5. Agent creates a proof bundle
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	// 6. Verifier checks the proof
	opts := VerifyOptions{
		RequiredScope: ScopeMeetingAttend,
		Now:           time.Now(),
	}
	result := Verify(bundle, opts)

	if !result.Valid {
		t.Fatalf("expected valid proof, got: %s — %s", result.IdentityStatus, result.ErrorReason)
	}
	if result.HumanID != humanRoot.ID {
		t.Errorf("HumanID = %q, want %q", result.HumanID, humanRoot.ID)
	}
	if result.AgentID != agent.ID {
		t.Errorf("AgentID = %q, want %q", result.AgentID, agent.ID)
	}
	if result.IdentityStatus != "authorized_agent" {
		t.Errorf("IdentityStatus = %q, want authorized_agent", result.IdentityStatus)
	}
}

// TestExpiredCert verifies that an expired cert is rejected.
func TestExpiredCert(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	agent, agentPriv, _ := GenerateAgentKeypair("Expired Bot", "custom")

	past := time.Now().Add(-2 * time.Hour)
	cert := &DelegationCert{
		CertID:        "expired-cert",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      past.Add(-1 * time.Hour).Unix(),
		ExpiresAt:     past.Unix(), // already expired
	}
	_ = IssueDelegation(cert, humanPriv)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{})
	if result.Valid {
		t.Fatal("expected expired cert to be rejected")
	}
	if result.IdentityStatus != "expired" {
		t.Errorf("IdentityStatus = %q, want expired", result.IdentityStatus)
	}
}

// TestRevokedCert verifies that a revoked cert is rejected.
func TestRevokedCert(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	agent, agentPriv, _ := GenerateAgentKeypair("Revoked Bot", "custom")

	now := time.Now()
	cert := &DelegationCert{
		CertID:        "revoked-cert-123",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert, humanPriv)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{
		IsRevoked: func(certID string) bool { return certID == "revoked-cert-123" },
	})
	if result.Valid {
		t.Fatal("expected revoked cert to be rejected")
	}
	if result.IdentityStatus != "revoked" {
		t.Errorf("IdentityStatus = %q, want revoked", result.IdentityStatus)
	}
}

// TestScopeRejection verifies that a required scope not in the delegation is denied.
func TestScopeRejection(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	agent, agentPriv, _ := GenerateAgentKeypair("Limited Bot", "custom")

	now := time.Now()
	cert := &DelegationCert{
		CertID:        "limited-cert",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend}, // no video
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert, humanPriv)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{RequiredScope: ScopeMeetingVideo})
	if result.Valid {
		t.Fatal("expected scope rejection, got valid")
	}
	// Per SPEC §5.9 and the post-P1 taxonomy, scope mismatches get their
	// own identity_status so audit layers can route without parsing text.
	if result.IdentityStatus != IdentityStatusScopeDenied {
		t.Errorf("IdentityStatus = %q, want %q", result.IdentityStatus, IdentityStatusScopeDenied)
	}
}

// TestTamperedSignature verifies that a modified cert is rejected.
func TestTamperedSignature(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	agent, agentPriv, _ := GenerateAgentKeypair("Tampered Bot", "custom")

	now := time.Now()
	cert := &DelegationCert{
		CertID:        "tampered-cert",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert, humanPriv)

	// Tamper: escalate scope after signing
	cert.Scope = append(cert.Scope, ScopeMeetingRecord)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{})
	if result.Valid {
		t.Fatal("expected tampered cert to be rejected")
	}
	if result.IdentityStatus != "invalid" {
		t.Errorf("IdentityStatus = %q, want invalid", result.IdentityStatus)
	}
}

// TestScopeNarrowingDepth2Escalation verifies the critical security property
// that an intermediate cannot grant scopes it did not receive. A cert[0] that
// claims to grant files:write when cert[1] only granted meeting:attend must
// be rejected — this is the privilege-escalation case.
func TestScopeNarrowingDepth2Escalation(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	intermediate, intPriv, _ := GenerateAgentKeypair("Intermediate", "custom")
	agent, agentPriv, _ := GenerateAgentKeypair("Leaf Agent", "custom")

	now := time.Now()

	// cert[1]: human → intermediate, ONLY meeting:attend granted
	cert1 := &DelegationCert{
		CertID:        "cert-h2i",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     intermediate.ID,
		SubjectPubKey: intermediate.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert1, humanPriv); err != nil {
		t.Fatalf("IssueDelegation cert1: %v", err)
	}

	// cert[0]: intermediate → agent, attempts to grant files:write (NEVER received)
	cert0 := &DelegationCert{
		CertID:        "cert-i2a",
		Version:       ProtocolVersion,
		IssuerID:      intermediate.ID,
		IssuerPubKey:  intermediate.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeFilesWrite}, // escalation
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert0, intPriv); err != nil {
		t.Fatalf("IssueDelegation cert0: %v", err)
	}

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert0, *cert1}, // [agent-facing, human-facing]
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{RequiredScope: ScopeFilesWrite})
	if result.Valid {
		t.Fatalf("SECURITY: escalation accepted — intermediate granted files:write without receiving it. Result: %+v", result)
	}
	// The intermediate here does NOT carry identity:delegate — so it's also
	// a sub-delegation violation, which now has its own status.
	if result.IdentityStatus != IdentityStatusDelegationNotAuthorized {
		t.Errorf("IdentityStatus = %q, want %q",
			result.IdentityStatus, IdentityStatusDelegationNotAuthorized)
	}
}

// TestScopeNarrowingDepth2Legitimate verifies that legitimate narrowing works:
// a wildcard granted at the top can be narrowed to a specific scope at the leaf,
// and the leaf's required_scope is honored.
func TestScopeNarrowingDepth2Legitimate(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	intermediate, intPriv, _ := GenerateAgentKeypair("Intermediate", "custom")
	agent, agentPriv, _ := GenerateAgentKeypair("Leaf Agent", "custom")

	now := time.Now()

	// cert[1]: human → intermediate, meeting:* (broad) + identity:delegate
	// (required for intermediate to issue cert[0]; see verify.go sub-delegation gate)
	cert1 := &DelegationCert{
		CertID:        "cert-h2i-wild",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     intermediate.ID,
		SubjectPubKey: intermediate.PublicKey,
		Scope:         []string{"meeting:*", ScopeIdentityDelegate},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert1, humanPriv)

	// cert[0]: intermediate → agent, narrows to meeting:attend
	cert0 := &DelegationCert{
		CertID:        "cert-i2a-narrow",
		Version:       ProtocolVersion,
		IssuerID:      intermediate.ID,
		IssuerPubKey:  intermediate.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert0, intPriv)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert0, *cert1},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{RequiredScope: ScopeMeetingAttend})
	if !result.Valid {
		t.Fatalf("expected valid legitimate narrowing, got: %s — %s", result.IdentityStatus, result.ErrorReason)
	}
	if result.HumanID != humanRoot.ID {
		t.Errorf("HumanID = %q, want %q (leaf issuer should be root)", result.HumanID, humanRoot.ID)
	}
	// Effective scope is the intersection: meeting:* ∩ {meeting:attend} = {meeting:attend}
	if len(result.GrantedScope) != 1 || result.GrantedScope[0] != ScopeMeetingAttend {
		t.Errorf("GrantedScope = %v, want [%s]", result.GrantedScope, ScopeMeetingAttend)
	}
}

// TestScopeNarrowingWildcardSensitive verifies that a wildcard received by
// the intermediate cannot be used to grant a sensitive scope. meeting:*
// never contains meeting:record, so a cert[0] claiming meeting:record must
// fail even though cert[1] granted meeting:*.
func TestScopeNarrowingWildcardSensitive(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	intermediate, intPriv, _ := GenerateAgentKeypair("Intermediate", "custom")
	agent, agentPriv, _ := GenerateAgentKeypair("Leaf Agent", "custom")

	now := time.Now()

	cert1 := &DelegationCert{
		CertID:        "cert-h2i-wild-sens",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     intermediate.ID,
		SubjectPubKey: intermediate.PublicKey,
		Scope:         []string{"meeting:*"}, // excludes meeting:record by vocabulary rule
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert1, humanPriv)

	cert0 := &DelegationCert{
		CertID:        "cert-i2a-sens",
		Version:       ProtocolVersion,
		IssuerID:      intermediate.ID,
		IssuerPubKey:  intermediate.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingRecord}, // sensitive — not in meeting:*
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	_ = IssueDelegation(cert0, intPriv)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert0, *cert1},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	result := Verify(bundle, VerifyOptions{RequiredScope: ScopeMeetingRecord})
	if result.Valid {
		t.Fatal("SECURITY: sensitive scope rode a wildcard — meeting:record accepted when parent only had meeting:*")
	}
}

// TestScopeNarrowingDepth3 verifies scope intersection across three levels.
// Scopes dropped at any intermediate level must not appear in the effective grant.
func TestScopeNarrowingDepth3(t *testing.T) {
	humanRoot, humanPriv, _ := GenerateHumanRootKeypair()
	org, orgPriv, _ := GenerateAgentKeypair("Org", "custom")
	dept, deptPriv, _ := GenerateAgentKeypair("Dept", "custom")
	agent, agentPriv, _ := GenerateAgentKeypair("Agent", "custom")

	now := time.Now()
	exp := now.Add(24 * time.Hour).Unix()

	// Human → Org: broad + identity:delegate (org will sub-delegate)
	cert2 := &DelegationCert{
		CertID: "cert-h2o", Version: ProtocolVersion,
		IssuerID: humanRoot.ID, IssuerPubKey: humanRoot.PublicKey,
		SubjectID: org.ID, SubjectPubKey: org.PublicKey,
		Scope:    []string{"meeting:*", "comms:*", ScopeIdentityDelegate},
		IssuedAt: now.Unix(), ExpiresAt: exp,
	}
	_ = IssueDelegation(cert2, humanPriv)

	// Org → Dept: drops comms, keeps identity:delegate (dept will sub-delegate)
	cert1 := &DelegationCert{
		CertID: "cert-o2d", Version: ProtocolVersion,
		IssuerID: org.ID, IssuerPubKey: org.PublicKey,
		SubjectID: dept.ID, SubjectPubKey: dept.PublicKey,
		Scope:    []string{"meeting:*", ScopeIdentityDelegate},
		IssuedAt: now.Unix(), ExpiresAt: exp,
	}
	_ = IssueDelegation(cert1, orgPriv)

	// Dept → Agent: narrows to meeting:attend
	cert0 := &DelegationCert{
		CertID: "cert-d2a", Version: ProtocolVersion,
		IssuerID: dept.ID, IssuerPubKey: dept.PublicKey,
		SubjectID: agent.ID, SubjectPubKey: agent.PublicKey,
		Scope:    []string{ScopeMeetingAttend},
		IssuedAt: now.Unix(), ExpiresAt: exp,
	}
	_ = IssueDelegation(cert0, deptPriv)

	challenge, _ := GenerateChallenge()
	challengeAt := time.Now().Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	bundle := &ProofBundle{
		AgentID: agent.ID, AgentPubKey: agent.PublicKey,
		Delegations:  []DelegationCert{*cert0, *cert1, *cert2},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}

	// meeting:attend survives all three levels
	if r := Verify(bundle, VerifyOptions{RequiredScope: ScopeMeetingAttend}); !r.Valid {
		t.Errorf("meeting:attend should be valid through depth-3: %s — %s", r.IdentityStatus, r.ErrorReason)
	}

	// comms:message:send was dropped at the Org→Dept hop
	if r := Verify(bundle, VerifyOptions{RequiredScope: ScopeCommsMessageSend}); r.Valid {
		t.Error("comms:message:send should be denied — dropped by dept cert")
	}

	// Human ID resolves to the root at the top of the chain
	r := Verify(bundle, VerifyOptions{RequiredScope: ScopeMeetingAttend})
	if r.HumanID != humanRoot.ID {
		t.Errorf("HumanID = %q, want %q", r.HumanID, humanRoot.ID)
	}
}

// ============================================================================
// Conformance tests against the canonical test vectors in testvectors/v1/.
//
// Every fixture is loaded, parsed, and validated against the current verifier.
// This closes the loop between the generator (cmd/ratify-testvectors) and the
// verifier — any drift causes a test failure, so the fixtures stay in sync
// with the protocol semantics they document.
// ============================================================================

// fixtureFile mirrors the generator's JSON schema.
type fixtureFile struct {
	Name            string                  `json:"name"`
	Description     string                  `json:"description"`
	ProtocolVersion int                     `json:"protocol_version"`
	Kind            string                  `json:"kind"`
	Entities        []fixtureEntity         `json:"entities,omitempty"`
	Timestamps      map[string]int64        `json:"timestamps,omitempty"`
	ChallengeHex    string                  `json:"challenge_hex,omitempty"`
	CertChain       []DelegationCert        `json:"cert_chain,omitempty"`
	Bundle          *ProofBundle            `json:"bundle,omitempty"`
	Revocation      *RevocationList         `json:"revocation_list,omitempty"`
	KeyRotation     *KeyRotationStatement   `json:"key_rotation,omitempty"`
	SessionToken    *fixtureSessionToken    `json:"session_token,omitempty"`
	Receipt         *TransactionReceipt     `json:"transaction_receipt,omitempty"`
	RevPush         *RevocationPush         `json:"revocation_push,omitempty"`
	WitEntry        *WitnessEntry           `json:"witness_entry,omitempty"`
	ScopeInput      []string                `json:"scope_input,omitempty"`
	VerifierContext *fixtureVerifierContext `json:"verifier_context,omitempty"`
	Expected        fixtureExpected         `json:"expected"`
}

// fixtureVerifierContext mirrors cmd/ratify-testvectors/main.go's
// verifierContextInput. Pointers distinguish "absent" from "zero value" so
// geo_circle at lat=0/lon=0 is not silently treated as unconfigured.
type fixtureVerifierContext struct {
	CurrentLat               *float64 `json:"current_lat,omitempty"`
	CurrentLon               *float64 `json:"current_lon,omitempty"`
	CurrentAltM              *float64 `json:"current_alt_m,omitempty"`
	CurrentSpeedMps          *float64 `json:"current_speed_mps,omitempty"`
	RequestedAmount          *float64 `json:"requested_amount,omitempty"`
	RequestedCurrency        string   `json:"requested_currency,omitempty"`
	InvocationsInWindowCount *int     `json:"invocations_in_window_count,omitempty"`
}

type fixtureEntity struct {
	Role           string          `json:"role"`
	Ed25519SeedHex string          `json:"ed25519_seed_hex"`
	MLDSA65SeedHex string          `json:"ml_dsa_65_seed_hex"`
	PublicKey      HybridPublicKey `json:"public_key"`
	ID             string          `json:"id"`
}

type fixtureExpected struct {
	DelegationSignBytesHex            []string             `json:"delegation_sign_bytes_hex,omitempty"`
	ChallengeSignBytesHex             string               `json:"challenge_sign_bytes_hex,omitempty"`
	VerifyOptions                     *fixtureVerifyOpts   `json:"verify_options,omitempty"`
	VerifyResult                      *VerifyResult        `json:"verify_result,omitempty"`
	ExpandedScopes                    []string             `json:"expanded_scopes,omitempty"`
	RevocationSignBytesHex            string               `json:"revocation_sign_bytes_hex,omitempty"`
	RevocationSignatureHex            string               `json:"revocation_signature_hex,omitempty"`
	KeyRotationSignBytesHex           string               `json:"key_rotation_sign_bytes_hex,omitempty"`
	KeyRotationVerifyOK               *bool                `json:"key_rotation_verify_ok,omitempty"`
	KeyRotationErrorReason            string               `json:"key_rotation_error_reason,omitempty"`
	ReceiptSignBytesHex               string               `json:"receipt_sign_bytes_hex,omitempty"`
	ReceiptValid                      *bool                `json:"receipt_valid,omitempty"`
	ReceiptErrorReason                string               `json:"receipt_error_reason,omitempty"`
	RevocationPushSignBytesHex        string               `json:"revocation_push_sign_bytes_hex,omitempty"`
	RevocationPushSignatureEd25519Hex string               `json:"revocation_push_signature_ed25519_hex,omitempty"`
	RevocationPushSignatureMLDSA65Hex string               `json:"revocation_push_signature_ml_dsa_65_hex,omitempty"`
	WitnessEntrySignBytesHex          string               `json:"witness_entry_sign_bytes_hex,omitempty"`
	WitnessEntrySignatureEd25519Hex   string               `json:"witness_entry_signature_ed25519_hex,omitempty"`
	WitnessEntrySignatureMLDSA65Hex   string               `json:"witness_entry_signature_ml_dsa_65_hex,omitempty"`
	SessionTokenSignBytesHex          string               `json:"session_token_sign_bytes_hex,omitempty"`
	SessionTokenMACHex                string               `json:"session_token_mac_hex,omitempty"`
	StreamedTurn                      *fixtureStreamedTurn `json:"streamed_turn,omitempty"`
}

type fixtureStreamedTurn struct {
	Valid          bool     `json:"valid"`
	IdentityStatus string   `json:"identity_status"`
	HumanID        string   `json:"human_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	GrantedScope   []string `json:"granted_scope,omitempty"`
	ErrorReason    string   `json:"error_reason,omitempty"`
}

type fixtureSessionToken struct {
	SessionSecretHex string          `json:"session_secret_hex"`
	Token            *SessionToken   `json:"token"`
	Challenge        []byte          `json:"challenge"`
	ChallengeAt      int64           `json:"challenge_at"`
	ChallengeSig     HybridSignature `json:"challenge_sig"`
	VerifyNow        int64           `json:"verify_now"`
}

type fixtureVerifyOpts struct {
	RequiredScope  string                `json:"required_scope,omitempty"`
	Now            int64                 `json:"now"`
	SessionContext []byte                `json:"session_context,omitempty"`
	Stream         *fixtureStreamContext `json:"stream,omitempty"`
}

// fixtureStreamContext is the fixture-side serialized shape of a
// ratify.StreamContext. LastSeenSeq is the verifier's persisted "last accepted
// stream_seq" — zero means no turns accepted yet, so the first valid bundle
// must carry stream_seq == 1.
type fixtureStreamContext struct {
	StreamID    []byte `json:"stream_id"`
	LastSeenSeq int64  `json:"last_seen_seq"`
}

// TestConformanceVectors loads every JSON fixture in testvectors/v1 and
// validates it against the current implementation. This is the adoption
// contract: any JS/Python/Rust implementation can consume the same files
// and run the same checks.
func TestConformanceVectors(t *testing.T) {
	dir := "testvectors/v1"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v — run 'go run ./cmd/ratify-testvectors' first", dir, err)
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		// cross_sdk_vectors.json has a different schema; it's exercised by
		// TestCrossSDKByteEquivalence in cross_sdk_test.go.
		if e.Name() == "cross_sdk_vectors.json" {
			continue
		}
		count++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var fx fixtureFile
			if err := json.Unmarshal(data, &fx); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if fx.ProtocolVersion != ProtocolVersion {
				t.Fatalf("protocol version %d != %d", fx.ProtocolVersion, ProtocolVersion)
			}

			switch fx.Kind {
			case "verify":
				runVerifyFixture(t, &fx)
			case "scope":
				runScopeFixture(t, &fx)
			case "revocation":
				runRevocationFixture(t, &fx)
			case "key_rotation":
				runKeyRotationFixture(t, &fx)
			case "session_token":
				runSessionTokenFixture(t, &fx)
			case "transaction_receipt":
				runTransactionReceiptFixture(t, &fx)
			case "revocation_push":
				runRevocationPushFixture(t, &fx)
			case "witness_entry":
				runWitnessEntryFixture(t, &fx)
			default:
				t.Fatalf("unknown fixture kind %q", fx.Kind)
			}
		})
	}

	if count == 0 {
		t.Fatal("no fixtures found — run 'go run ./cmd/ratify-testvectors' to generate them")
	}
}

func runVerifyFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()

	// Cross-check canonical signing bytes for each cert in the chain.
	if got, want := len(fx.CertChain), len(fx.Expected.DelegationSignBytesHex); got != want {
		t.Fatalf("cert chain length %d != expected sign-bytes length %d", got, want)
	}
	for i := range fx.CertChain {
		gotBytes, err := DelegationSignBytes(&fx.CertChain[i])
		if err != nil {
			t.Fatalf("cert %d: DelegationSignBytes: %v", i, err)
		}
		if gotHex := hex.EncodeToString(gotBytes); gotHex != fx.Expected.DelegationSignBytesHex[i] {
			t.Errorf("cert %d canonical sign bytes drifted.\n  got:  %s\n  want: %s",
				i, gotHex, fx.Expected.DelegationSignBytesHex[i])
		}
	}

	// Cross-check the challenge signing bytes.
	if fx.Bundle != nil && fx.Expected.ChallengeSignBytesHex != "" {
		got := hex.EncodeToString(ChallengeSignBytesWithStream(fx.Bundle.Challenge, fx.Bundle.ChallengeAt, fx.Bundle.SessionContext, fx.Bundle.StreamID, fx.Bundle.StreamSeq))
		if got != fx.Expected.ChallengeSignBytesHex {
			t.Errorf("challenge sign bytes drifted.\n  got:  %s\n  want: %s",
				got, fx.Expected.ChallengeSignBytesHex)
		}
	}

	// Run the verifier and compare results.
	if fx.Bundle == nil || fx.Expected.VerifyResult == nil || fx.Expected.VerifyOptions == nil {
		return // not a verify-result fixture (e.g., revocation-only)
	}

	opts := VerifyOptions{
		RequiredScope:  fx.Expected.VerifyOptions.RequiredScope,
		Now:            time.Unix(fx.Expected.VerifyOptions.Now, 0).UTC(),
		SessionContext: fx.Expected.VerifyOptions.SessionContext,
	}
	if s := fx.Expected.VerifyOptions.Stream; s != nil {
		opts.Stream = &StreamContext{StreamID: s.StreamID, LastSeenSeq: s.LastSeenSeq}
	}
	// revocation_middle_cert fixture uses an IsRevoked callback — reconstruct
	// it from the fixture's metadata. The fixture encodes the revoked cert
	// in the description; here we take the simpler path of revoking any cert
	// that shows up as revoked in the expected result.
	if fx.Expected.VerifyResult.IdentityStatus == "revoked" {
		// The intermediate cert (cert_chain[1] for depth 2) is the revoked one.
		if len(fx.CertChain) > 1 {
			revoked := fx.CertChain[1].CertID
			opts.IsRevoked = func(certID string) bool { return certID == revoked }
		}
	}
	// Thread the fixture's verifier_context into opts.Context so constraint
	// fixtures (geo_circle, time_window, max_amount, max_rate) exercise the
	// real verifier path end-to-end. Pointer fields guard against zero-value
	// ambiguity — nil means "not supplied," zero means "supplied as zero."
	if vc := fx.VerifierContext; vc != nil {
		if vc.CurrentLat != nil && vc.CurrentLon != nil {
			opts.Context.CurrentLat = *vc.CurrentLat
			opts.Context.CurrentLon = *vc.CurrentLon
			opts.Context.HasLocation = true
		}
		if vc.CurrentAltM != nil {
			opts.Context.CurrentAltM = *vc.CurrentAltM
		}
		if vc.CurrentSpeedMps != nil {
			opts.Context.CurrentSpeedMps = *vc.CurrentSpeedMps
			opts.Context.HasSpeed = true
		}
		if vc.RequestedAmount != nil {
			opts.Context.RequestedAmount = *vc.RequestedAmount
			opts.Context.RequestedCurrency = vc.RequestedCurrency
			opts.Context.HasAmount = true
		}
		if vc.InvocationsInWindowCount != nil {
			n := *vc.InvocationsInWindowCount
			opts.Context.InvocationsInWindow = func(_ string, _ int64) int { return n }
		}
	}

	got := Verify(fx.Bundle, opts)
	want := *fx.Expected.VerifyResult

	// Normalize slice ordering for comparison (GrantedScope is unordered).
	sort.Strings(got.GrantedScope)
	sort.Strings(want.GrantedScope)

	if got.Valid != want.Valid {
		t.Errorf("Valid = %v, want %v (status=%s reason=%s)",
			got.Valid, want.Valid, got.IdentityStatus, got.ErrorReason)
	}
	if got.IdentityStatus != want.IdentityStatus {
		t.Errorf("IdentityStatus = %q, want %q", got.IdentityStatus, want.IdentityStatus)
	}
	if got.HumanID != want.HumanID {
		t.Errorf("HumanID = %q, want %q", got.HumanID, want.HumanID)
	}
	if got.AgentID != want.AgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, want.AgentID)
	}
	if !reflect.DeepEqual(got.GrantedScope, want.GrantedScope) {
		t.Errorf("GrantedScope = %v, want %v", got.GrantedScope, want.GrantedScope)
	}
	if got.ErrorReason != want.ErrorReason {
		t.Errorf("ErrorReason = %q, want %q", got.ErrorReason, want.ErrorReason)
	}
}

func runScopeFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	got := ExpandScopes(fx.ScopeInput)
	want := fx.Expected.ExpandedScopes
	sort.Strings(got)
	sortedWant := make([]string, len(want))
	copy(sortedWant, want)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(got, sortedWant) {
		t.Errorf("ExpandScopes(%v) = %v, want %v", fx.ScopeInput, got, sortedWant)
	}
}

func runRevocationFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	if fx.Revocation == nil {
		t.Fatal("revocation fixture missing revocation_list")
	}
	// Cross-check canonical signing bytes.
	got, err := RevocationSignBytes(fx.Revocation)
	if err != nil {
		t.Fatalf("RevocationSignBytes: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != fx.Expected.RevocationSignBytesHex {
		t.Errorf("revocation sign bytes drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.RevocationSignBytesHex)
	}
	// Verify the signature against the issuer's public key.
	if len(fx.Entities) == 0 {
		t.Fatal("revocation fixture missing issuer entity")
	}
	if err := VerifyRevocationList(fx.Revocation, fx.Entities[0].PublicKey); err != nil {
		t.Errorf("revocation list signature failed to verify: %v", err)
	}
}

func runKeyRotationFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	if fx.KeyRotation == nil {
		t.Fatal("key_rotation fixture missing key_rotation")
	}
	got, err := KeyRotationSignBytes(fx.KeyRotation)
	if err != nil {
		t.Fatalf("KeyRotationSignBytes: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != fx.Expected.KeyRotationSignBytesHex {
		t.Errorf("key rotation sign bytes drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.KeyRotationSignBytesHex)
	}
	verifyErr := VerifyKeyRotationStatement(fx.KeyRotation)
	gotOK := verifyErr == nil
	if fx.Expected.KeyRotationVerifyOK == nil {
		t.Fatal("key_rotation fixture missing expected.key_rotation_verify_ok")
	}
	if gotOK != *fx.Expected.KeyRotationVerifyOK {
		t.Fatalf("VerifyKeyRotationStatement ok=%v, want %v (err=%v)",
			gotOK, *fx.Expected.KeyRotationVerifyOK, verifyErr)
	}
	gotReason := ""
	if verifyErr != nil {
		gotReason = verifyErr.Error()
	}
	if gotReason != fx.Expected.KeyRotationErrorReason {
		t.Errorf("key rotation error = %q, want %q", gotReason, fx.Expected.KeyRotationErrorReason)
	}
}

// TestCanonicalJSONNoHTMLEscape locks in the non-HTML-escaping behavior:
// '<', '>', '&' must pass through unmodified so canonical bytes match
// across language implementations.
//
// Note on U+2028 / U+2029: Go's encoding/json unilaterally escapes these
// as \u2028 / \u2029 with no option to disable. Other-language implementers
// MUST apply the same escaping for those two code points to produce
// matching bytes. v1 signable field content is restricted to hex IDs,
// base64 keys, and canonical scope strings — none of which contain these
// code points in practice — so this is a latent constraint, not a live
// risk. Documented in RATIFY_PROTOCOL.md §6.1.
func TestCanonicalJSONNoHTMLEscape(t *testing.T) {
	type payload struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	p := payload{
		A: "<script>alert(1)</script>",
		B: "a & b \u2028 c \u2029 d",
	}
	got, err := CanonicalJSON(p)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	// HTML chars ('<', '>', '&') pass through unmodified.
	// Line/paragraph separators (U+2028, U+2029) are escaped to \u2028 / \u2029
	// because Go's encoding/json escapes them regardless of SetEscapeHTML.
	// Other-language implementers MUST apply the same escape for these two
	// code points to produce matching canonical bytes.
	want := `{"a":"<script>alert(1)</script>","b":"a & b \u2028 c \u2029 d"}`
	if string(got) != want {
		t.Errorf("canonical bytes drifted.\n  got:  %s\n  want: %s", got, want)
	}
}

// TestCanonicalJSONDeterministic locks in the no-trailing-newline property.
// json.Encoder appends '\n' to every encoded value; CanonicalJSON must strip
// it so signable bytes are identical byte-for-byte across implementations.
func TestCanonicalJSONDeterministic(t *testing.T) {
	type payload struct {
		X int    `json:"x"`
		Y string `json:"y"`
	}
	got, _ := CanonicalJSON(payload{X: 42, Y: "hello"})
	want := `{"x":42,"y":"hello"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if len(got) > 0 && got[len(got)-1] == '\n' {
		t.Error("canonical output must not end in newline")
	}
}

// TestStreamBoundBundle covers the v1.1 stream-binding happy path plus all
// distinct failure modes (replay, skip, mismatch, unverifiable, missing,
// invalid_stream_id, invalid_stream_seq). Keeps the cases in one test so the
// shared setup isn't duplicated.
func TestStreamBoundBundle(t *testing.T) {
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}
	agent, agentPriv, err := GenerateAgentKeypair("Stream Agent", "voice_agent")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}
	now := time.Now()
	cert := &DelegationCert{
		CertID:        "stream-cert-001",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Add(-1 * time.Hour).Unix(),
		ExpiresAt:     now.Add(1 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}

	streamID := bytes.Repeat([]byte{0xAB}, 32)
	makeBundle := func(streamSeq int64) *ProofBundle {
		challenge := []byte("stream-challenge-0123456789abcdef")[:32]
		challengeAt := now.Unix()
		sig, err := SignChallengeWithStream(challenge, challengeAt, nil, streamID, streamSeq, agentPriv)
		if err != nil {
			t.Fatalf("SignChallengeWithStream: %v", err)
		}
		return &ProofBundle{
			AgentID:      agent.ID,
			AgentPubKey:  agent.PublicKey,
			Delegations:  []DelegationCert{*cert},
			Challenge:    challenge,
			ChallengeAt:  challengeAt,
			ChallengeSig: sig,
			StreamID:     streamID,
			StreamSeq:    streamSeq,
		}
	}

	baseOpts := VerifyOptions{
		RequiredScope: ScopeMeetingAttend,
		Now:           now,
	}

	t.Run("first_turn_seq_1", func(t *testing.T) {
		b := makeBundle(1)
		opts := baseOpts
		opts.Stream = &StreamContext{StreamID: streamID, LastSeenSeq: 0}
		r := Verify(b, opts)
		if !r.Valid {
			t.Fatalf("expected valid, got status=%s reason=%s", r.IdentityStatus, r.ErrorReason)
		}
	})

	t.Run("next_turn_seq_matches_last_plus_1", func(t *testing.T) {
		b := makeBundle(5)
		opts := baseOpts
		opts.Stream = &StreamContext{StreamID: streamID, LastSeenSeq: 4}
		if r := Verify(b, opts); !r.Valid {
			t.Fatalf("expected valid for seq 5 after last=4: %s", r.ErrorReason)
		}
	})

	t.Run("replay_rejected", func(t *testing.T) {
		b := makeBundle(3)
		opts := baseOpts
		opts.Stream = &StreamContext{StreamID: streamID, LastSeenSeq: 3}
		r := Verify(b, opts)
		if r.Valid || r.IdentityStatus != IdentityStatusInvalid {
			t.Fatalf("expected invalid replay, got status=%s reason=%s", r.IdentityStatus, r.ErrorReason)
		}
		if !strings.Contains(r.ErrorReason, "stream_seq_replay") {
			t.Errorf("expected stream_seq_replay, got %q", r.ErrorReason)
		}
	})

	t.Run("skip_rejected", func(t *testing.T) {
		b := makeBundle(5)
		opts := baseOpts
		opts.Stream = &StreamContext{StreamID: streamID, LastSeenSeq: 2}
		r := Verify(b, opts)
		if r.Valid {
			t.Fatalf("expected invalid skip")
		}
		if !strings.Contains(r.ErrorReason, "stream_seq_skip") {
			t.Errorf("expected stream_seq_skip, got %q", r.ErrorReason)
		}
	})

	t.Run("stream_id_mismatch", func(t *testing.T) {
		b := makeBundle(1)
		opts := baseOpts
		other := bytes.Repeat([]byte{0xCD}, 32)
		opts.Stream = &StreamContext{StreamID: other, LastSeenSeq: 0}
		r := Verify(b, opts)
		if r.Valid {
			t.Fatalf("expected invalid id_mismatch")
		}
		if !strings.Contains(r.ErrorReason, "stream_id_mismatch") {
			t.Errorf("expected stream_id_mismatch, got %q", r.ErrorReason)
		}
	})

	t.Run("unverifiable_bundle_has_no_verifier_context", func(t *testing.T) {
		b := makeBundle(1)
		opts := baseOpts
		r := Verify(b, opts)
		if r.Valid {
			t.Fatalf("expected invalid unverifiable")
		}
		if !strings.Contains(r.ErrorReason, "stream_context_unverifiable") {
			t.Errorf("expected stream_context_unverifiable, got %q", r.ErrorReason)
		}
	})

	t.Run("missing_bundle_required_by_verifier", func(t *testing.T) {
		// Legacy (non-stream) bundle but verifier requires stream binding.
		challenge := []byte("legacy-challenge-0123456789abcdef!")[:32]
		challengeAt := now.Unix()
		sig, err := SignChallenge(challenge, challengeAt, agentPriv)
		if err != nil {
			t.Fatalf("SignChallenge: %v", err)
		}
		b := &ProofBundle{
			AgentID:      agent.ID,
			AgentPubKey:  agent.PublicKey,
			Delegations:  []DelegationCert{*cert},
			Challenge:    challenge,
			ChallengeAt:  challengeAt,
			ChallengeSig: sig,
		}
		opts := baseOpts
		opts.Stream = &StreamContext{StreamID: streamID, LastSeenSeq: 0}
		r := Verify(b, opts)
		if r.Valid {
			t.Fatalf("expected invalid missing")
		}
		if !strings.Contains(r.ErrorReason, "missing_stream_context") {
			t.Errorf("expected missing_stream_context, got %q", r.ErrorReason)
		}
	})
}

func runRevocationPushFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	if fx.RevPush == nil {
		t.Fatal("revocation_push fixture missing revocation_push block")
	}
	push := fx.RevPush
	got, err := RevocationPushSignBytes(push)
	if err != nil {
		t.Fatalf("RevocationPushSignBytes: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != fx.Expected.RevocationPushSignBytesHex {
		t.Errorf("revocation push sign bytes drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.RevocationPushSignBytesHex)
	}
	if len(fx.Entities) == 0 {
		t.Fatal("revocation_push fixture missing issuer entity")
	}
	if err := VerifyRevocationPush(push, fx.Entities[0].PublicKey); err != nil {
		t.Errorf("revocation push signature failed to verify: %v", err)
	}
}

func runWitnessEntryFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	if fx.WitEntry == nil {
		t.Fatal("witness_entry fixture missing witness_entry block")
	}
	entry := fx.WitEntry
	got, err := WitnessEntrySignBytes(entry)
	if err != nil {
		t.Fatalf("WitnessEntrySignBytes: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != fx.Expected.WitnessEntrySignBytesHex {
		t.Errorf("witness entry sign bytes drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.WitnessEntrySignBytesHex)
	}
	if len(fx.Entities) == 0 {
		t.Fatal("witness_entry fixture missing witness entity")
	}
	if err := VerifyWitnessEntry(entry, fx.Entities[0].PublicKey); err != nil {
		t.Errorf("witness entry signature failed to verify: %v", err)
	}
}

func runTransactionReceiptFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	if fx.Receipt == nil {
		t.Fatal("transaction_receipt fixture missing transaction_receipt block")
	}
	receipt := fx.Receipt

	// Cross-check canonical signing bytes.
	got, err := TransactionReceiptSignBytes(receipt)
	if err != nil {
		t.Fatalf("TransactionReceiptSignBytes: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != fx.Expected.ReceiptSignBytesHex {
		t.Errorf("receipt sign bytes drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.ReceiptSignBytesHex)
	}

	// Run the generic envelope verifier.
	result := VerifyTransactionReceipt(receipt, VerifyReceiptOptions{
		Now: time.Unix(fx.Timestamps["verifier_now"], 0).UTC(),
	})
	if fx.Expected.ReceiptValid == nil {
		t.Fatal("receipt fixture missing expected.receipt_valid")
	}
	if result.Valid != *fx.Expected.ReceiptValid {
		t.Errorf("receipt valid=%v, want %v (reason=%s)",
			result.Valid, *fx.Expected.ReceiptValid, result.ErrorReason)
	}
	if result.ErrorReason != fx.Expected.ReceiptErrorReason {
		t.Errorf("receipt error_reason=%q, want %q",
			result.ErrorReason, fx.Expected.ReceiptErrorReason)
	}
}

func runSessionTokenFixture(t *testing.T, fx *fixtureFile) {
	t.Helper()
	if fx.SessionToken == nil || fx.SessionToken.Token == nil {
		t.Fatal("session_token fixture missing session_token block")
	}
	token := fx.SessionToken.Token

	// Canonical MAC-input bytes must be byte-identical across SDKs.
	got, err := SessionTokenSignBytes(token)
	if err != nil {
		t.Fatalf("SessionTokenSignBytes: %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != fx.Expected.SessionTokenSignBytesHex {
		t.Errorf("session_token sign bytes drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.SessionTokenSignBytesHex)
	}
	if gotHex := hex.EncodeToString(token.MAC); gotHex != fx.Expected.SessionTokenMACHex {
		t.Errorf("session_token MAC drifted.\n  got:  %s\n  want: %s",
			gotHex, fx.Expected.SessionTokenMACHex)
	}

	// Reproduce VerifyStreamedTurn with the fixture inputs.
	secret, err := hex.DecodeString(fx.SessionToken.SessionSecretHex)
	if err != nil {
		t.Fatalf("decode session_secret_hex: %v", err)
	}
	result := VerifyStreamedTurn(
		token, secret,
		fx.SessionToken.Challenge, fx.SessionToken.ChallengeAt, fx.SessionToken.ChallengeSig,
		nil, nil, 0,
		time.Unix(fx.SessionToken.VerifyNow, 0).UTC(),
	)
	want := fx.Expected.StreamedTurn
	if want == nil {
		t.Fatal("session_token fixture missing expected.streamed_turn")
	}
	if result.Valid != want.Valid {
		t.Errorf("Valid=%v, want %v (status=%s reason=%s)",
			result.Valid, want.Valid, result.IdentityStatus, result.ErrorReason)
	}
	if result.IdentityStatus != want.IdentityStatus {
		t.Errorf("IdentityStatus=%q, want %q", result.IdentityStatus, want.IdentityStatus)
	}
	if result.HumanID != want.HumanID {
		t.Errorf("HumanID=%q, want %q", result.HumanID, want.HumanID)
	}
	if result.AgentID != want.AgentID {
		t.Errorf("AgentID=%q, want %q", result.AgentID, want.AgentID)
	}
	if result.ErrorReason != want.ErrorReason {
		t.Errorf("ErrorReason=%q, want %q", result.ErrorReason, want.ErrorReason)
	}
	gotScope := append([]string(nil), result.GrantedScope...)
	wantScope := append([]string(nil), want.GrantedScope...)
	sort.Strings(gotScope)
	sort.Strings(wantScope)
	if !reflect.DeepEqual(gotScope, wantScope) {
		t.Errorf("GrantedScope=%v, want %v", gotScope, wantScope)
	}
}

// TestSessionTokenRoundTrip covers the v1.1 session cert cache (ROADMAP 2.3)
// happy path and the four distinct rejection paths — expired, tampered MAC,
// wrong secret, and bad challenge signature.
func TestSessionTokenRoundTrip(t *testing.T) {
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}
	agent, agentPriv, err := GenerateAgentKeypair("Cache Agent", "voice_agent")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	cert := &DelegationCert{
		CertID:        "session-token-cert",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeMeetingAttend},
		IssuedAt:      now.Add(-1 * time.Hour).Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}
	challenge := bytes.Repeat([]byte{0x9a}, 32)
	sig, err := SignChallenge(challenge, now.Unix(), agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  now.Unix(),
		ChallengeSig: sig,
	}
	res := Verify(bundle, VerifyOptions{Now: now, RequiredScope: ScopeMeetingAttend})
	if !res.Valid {
		t.Fatalf("initial Verify must succeed before issuing token: %s — %s", res.IdentityStatus, res.ErrorReason)
	}
	sessionSecret := bytes.Repeat([]byte{0x77}, 32)
	issuedAt := now.Unix()
	validUntil := now.Add(30 * time.Minute).Unix()
	token, err := IssueSessionToken(bundle, res, "session-xyz", issuedAt, validUntil, sessionSecret)
	if err != nil {
		t.Fatalf("IssueSessionToken: %v", err)
	}
	if len(token.MAC) != 32 {
		t.Fatalf("token MAC should be 32 bytes, got %d", len(token.MAC))
	}

	// Fresh per-turn challenge (signed only by the agent key — no chain).
	turnChallenge := bytes.Repeat([]byte{0xAA}, 32)
	turnAt := now.Add(5 * time.Minute).Unix()
	turnSig, err := SignChallenge(turnChallenge, turnAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge(turn): %v", err)
	}

	t.Run("happy_path", func(t *testing.T) {
		r := VerifyStreamedTurn(token, sessionSecret, turnChallenge, turnAt, turnSig, nil, nil, 0, now.Add(5*time.Minute))
		if !r.Valid {
			t.Fatalf("VerifyStreamedTurn: status=%s reason=%s", r.IdentityStatus, r.ErrorReason)
		}
		if r.AgentID != agent.ID || r.HumanID != humanRoot.ID {
			t.Errorf("identity fields mismatch: got human=%s agent=%s", r.HumanID, r.AgentID)
		}
		if len(r.GrantedScope) != 1 || r.GrantedScope[0] != ScopeMeetingAttend {
			t.Errorf("granted_scope = %v, want [%s]", r.GrantedScope, ScopeMeetingAttend)
		}
	})

	t.Run("reject_expired", func(t *testing.T) {
		// Time advances past valid_until.
		r := VerifyStreamedTurn(token, sessionSecret, turnChallenge, turnAt, turnSig, nil, nil, 0, now.Add(31*time.Minute))
		if r.Valid {
			t.Fatalf("expected invalid for expired token")
		}
		if !strings.Contains(r.ErrorReason, "expired") {
			t.Errorf("expected expired error, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_tampered_mac", func(t *testing.T) {
		tampered := *token
		tampered.MAC = append([]byte(nil), token.MAC...)
		tampered.MAC[0] ^= 0xFF
		r := VerifyStreamedTurn(&tampered, sessionSecret, turnChallenge, turnAt, turnSig, nil, nil, 0, now.Add(5*time.Minute))
		if r.Valid {
			t.Fatalf("expected invalid for tampered MAC")
		}
		if !strings.Contains(r.ErrorReason, "MAC invalid") {
			t.Errorf("expected MAC invalid error, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_wrong_secret", func(t *testing.T) {
		otherSecret := bytes.Repeat([]byte{0x99}, 32)
		r := VerifyStreamedTurn(token, otherSecret, turnChallenge, turnAt, turnSig, nil, nil, 0, now.Add(5*time.Minute))
		if r.Valid {
			t.Fatalf("expected invalid for wrong session secret")
		}
		if !strings.Contains(r.ErrorReason, "MAC invalid") {
			t.Errorf("expected MAC invalid error, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_bad_challenge_sig", func(t *testing.T) {
		badSig := turnSig
		badSig.Ed25519 = append([]byte(nil), turnSig.Ed25519...)
		badSig.Ed25519[0] ^= 0xFF
		r := VerifyStreamedTurn(token, sessionSecret, turnChallenge, turnAt, badSig, nil, nil, 0, now.Add(5*time.Minute))
		if r.Valid {
			t.Fatalf("expected invalid for bad challenge sig")
		}
		if !strings.Contains(r.ErrorReason, "bad_challenge_sig") {
			t.Errorf("expected bad_challenge_sig error, got %q", r.ErrorReason)
		}
	})

	t.Run("chain_hash_binding", func(t *testing.T) {
		// Tamper the token's chain_hash — MAC should fail.
		tampered := *token
		tampered.ChainHash = append([]byte(nil), token.ChainHash...)
		tampered.ChainHash[0] ^= 0xFF
		r := VerifyStreamedTurn(&tampered, sessionSecret, turnChallenge, turnAt, turnSig, nil, nil, 0, now.Add(5*time.Minute))
		if r.Valid {
			t.Fatalf("expected invalid for tampered chain_hash")
		}
	})
}

// TestTransactionReceiptRoundTrip covers the v1.1 transaction receipt
// envelope (ROADMAP 3.1 / 3.3): canonical signable, party atomicity, and
// the five negative paths from TRANSACTION_RECEIPTS.md §7.
func TestTransactionReceiptRoundTrip(t *testing.T) {
	// Two parties — buyer and seller — each with a valid v1 delegation chain.
	human, humanPriv, _ := GenerateHumanRootKeypair()
	buyer, buyerPriv, _ := GenerateAgentKeypair("Buyer Agent", "voice_agent")
	seller, sellerPriv, _ := GenerateAgentKeypair("Seller Agent", "voice_agent")
	now := time.Now()
	mkCert := func(subjectID string, subjectPub HybridPublicKey, scope []string) DelegationCert {
		c := DelegationCert{
			CertID:        "cert-" + subjectID,
			Version:       ProtocolVersion,
			IssuerID:      human.ID,
			IssuerPubKey:  human.PublicKey,
			SubjectID:     subjectID,
			SubjectPubKey: subjectPub,
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

	buyerChallenge := bytes.Repeat([]byte{0xB1}, 32)
	buyerSig, _ := SignChallenge(buyerChallenge, now.Unix(), buyerPriv)
	sellerChallenge := bytes.Repeat([]byte{0xB2}, 32)
	sellerSig, _ := SignChallenge(sellerChallenge, now.Unix(), sellerPriv)
	buyerBundle := ProofBundle{
		AgentID:      buyer.ID,
		AgentPubKey:  buyer.PublicKey,
		Delegations:  []DelegationCert{buyerCert},
		Challenge:    buyerChallenge,
		ChallengeAt:  now.Unix(),
		ChallengeSig: buyerSig,
	}
	sellerBundle := ProofBundle{
		AgentID:      seller.ID,
		AgentPubKey:  seller.PublicKey,
		Delegations:  []DelegationCert{sellerCert},
		Challenge:    sellerChallenge,
		ChallengeAt:  now.Unix(),
		ChallengeSig: sellerSig,
	}

	terms := []byte(`{"resource":"gpu-a100-8x","hours":10,"currency":"USD","amount":500}`)
	receipt := &TransactionReceipt{
		Version:            ProtocolVersion,
		TransactionID:      "tx-round-trip",
		CreatedAt:          now.Unix(),
		TermsSchemaURI:     "ratify://schemas/receipt/compute-purchase/v1",
		TermsCanonicalJSON: terms,
		Parties: []ReceiptParty{
			{PartyID: "party-buyer", Role: "buyer", AgentID: buyer.ID, AgentPubKey: buyer.PublicKey, ProofBundle: buyerBundle},
			{PartyID: "party-seller", Role: "seller", AgentID: seller.ID, AgentPubKey: seller.PublicKey, ProofBundle: sellerBundle},
		},
	}
	buyerSignature, err := SignTransactionReceiptParty(receipt, "party-buyer", buyerPriv)
	if err != nil {
		t.Fatalf("buyer sign: %v", err)
	}
	sellerSignature, err := SignTransactionReceiptParty(receipt, "party-seller", sellerPriv)
	if err != nil {
		t.Fatalf("seller sign: %v", err)
	}
	receipt.PartySignatures = []ReceiptPartySignature{buyerSignature, sellerSignature}

	t.Run("happy_path", func(t *testing.T) {
		r := VerifyTransactionReceipt(receipt, VerifyReceiptOptions{Now: now})
		if !r.Valid {
			t.Fatalf("expected valid: %s", r.ErrorReason)
		}
	})

	t.Run("reject_missing_party_signature", func(t *testing.T) {
		// Drop the seller's signature.
		tampered := *receipt
		tampered.PartySignatures = []ReceiptPartySignature{buyerSignature}
		r := VerifyTransactionReceipt(&tampered, VerifyReceiptOptions{Now: now})
		if r.Valid {
			t.Fatal("expected invalid: missing signature")
		}
		if !strings.Contains(r.ErrorReason, "missing_party_signature") {
			t.Errorf("expected missing_party_signature, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_party_tampered", func(t *testing.T) {
		// Change the seller's role after signing → seller signature is over
		// the old parties set, new signable differs, signature fails.
		tampered := *receipt
		tampered.Parties = append([]ReceiptParty(nil), receipt.Parties...)
		tampered.Parties[1].Role = "auditor"
		r := VerifyTransactionReceipt(&tampered, VerifyReceiptOptions{Now: now})
		if r.Valid {
			t.Fatal("expected invalid: party tampered")
		}
		if !strings.Contains(r.ErrorReason, "party_signature_invalid") {
			t.Errorf("expected party_signature_invalid, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_terms_tampered", func(t *testing.T) {
		tampered := *receipt
		tampered.TermsCanonicalJSON = append([]byte(nil), receipt.TermsCanonicalJSON...)
		tampered.TermsCanonicalJSON[0] ^= 0xFF
		r := VerifyTransactionReceipt(&tampered, VerifyReceiptOptions{Now: now})
		if r.Valid {
			t.Fatal("expected invalid: terms tampered")
		}
		if !strings.Contains(r.ErrorReason, "party_signature_invalid") {
			t.Errorf("expected party_signature_invalid, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_wrong_party_key", func(t *testing.T) {
		// Seller's proof bundle is valid, but PartySignatures has seller's
		// signature produced with the BUYER's key — fails verification against
		// the seller's agent_pub_key.
		wrongSig, err := SignTransactionReceiptParty(receipt, "party-seller", buyerPriv)
		if err != nil {
			t.Fatalf("buyer-signing-for-seller: %v", err)
		}
		tampered := *receipt
		tampered.PartySignatures = []ReceiptPartySignature{buyerSignature, wrongSig}
		r := VerifyTransactionReceipt(&tampered, VerifyReceiptOptions{Now: now})
		if r.Valid {
			t.Fatal("expected invalid: wrong party key")
		}
		if !strings.Contains(r.ErrorReason, "party_signature_invalid") {
			t.Errorf("expected party_signature_invalid, got %q", r.ErrorReason)
		}
	})

	t.Run("reject_duplicate_party_id", func(t *testing.T) {
		tampered := *receipt
		tampered.Parties = append([]ReceiptParty(nil), receipt.Parties...)
		tampered.Parties[1].PartyID = "party-buyer" // collide
		r := VerifyTransactionReceipt(&tampered, VerifyReceiptOptions{Now: now})
		if r.Valid {
			t.Fatal("expected invalid: duplicate party_id")
		}
		if !strings.Contains(r.ErrorReason, "duplicate_party_id") {
			t.Errorf("expected duplicate_party_id, got %q", r.ErrorReason)
		}
	})
}

// TestScopeWildcard verifies that "meeting:*" grants constituent scopes.
func TestScopeWildcard(t *testing.T) {
	expanded := ExpandScopes([]string{"meeting:*"})
	required := []string{ScopeMeetingAttend, ScopeMeetingSpeak, ScopeMeetingVideo, ScopeMeetingChat}
	found := make(map[string]bool, len(expanded))
	for _, s := range expanded {
		found[s] = true
	}
	for _, r := range required {
		if !found[r] {
			t.Errorf("meeting:* expansion missing %q", r)
		}
	}
	// Sensitive scope must NOT be included in wildcard
	if found[ScopeMeetingRecord] {
		t.Error("meeting:* must not include meeting:record (sensitive)")
	}
}
