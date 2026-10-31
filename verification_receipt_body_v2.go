package ratify

import (
	"bytes"
	"context"
	"fmt"
)

// verificationReceiptBodyV2 is the immutable receipt content prepared before
// the receipt log assigns its position and the verifier signs it.
type verificationReceiptBodyV2 struct {
	AgentID              string                      `json:"agent_id,omitempty"`
	BundleHash           string                      `json:"bundle_hash"`
	ChallengeAssessment  string                      `json:"challenge_assessment"`
	ConstraintEvaluators []ConstraintEvaluatorRefV2  `json:"constraint_evaluators,omitempty"`
	ContextAssessment    string                      `json:"context_assessment"`
	ContextPolicyDigest  *string                     `json:"context_policy_digest"`
	Decision             string                      `json:"decision"`
	DecisionReason       string                      `json:"decision_reason"`
	GrantedScope         []string                    `json:"granted_scope"`
	HumanID              string                      `json:"human_id,omitempty"`
	IdentityStatus       string                      `json:"identity_status"`
	IssuerIDs            []string                    `json:"issuer_ids"`
	RequiredScope        string                      `json:"required_scope"`
	StatusAssessment     string                      `json:"status_assessment"`
	StatusEvidence       []statusEvidenceCanonicalV2 `json:"status_evidence_digests"`
	TrustAssessment      string                      `json:"trust_assessment"`
	VerifiedAt           int64                       `json:"verified_at"`
	VerifierID           string                      `json:"verifier_id"`
	Version              int                         `json:"version"`
}

func receiptBodyFieldsV2(r *VerificationReceiptV2) verificationReceiptBodyV2 {
	return verificationReceiptBodyV2{
		AgentID: r.AgentID, BundleHash: r.BundleHash,
		ChallengeAssessment: r.ChallengeAssessment, ContextAssessment: r.ContextAssessment,
		ConstraintEvaluators: cloneConstraintEvaluatorRefsV2(r.ConstraintEvaluators),
		ContextPolicyDigest:  r.ContextPolicyDigest, Decision: r.Decision,
		DecisionReason: r.DecisionReason, GrantedScope: r.GrantedScope,
		HumanID: r.HumanID, IdentityStatus: r.IdentityStatus, IssuerIDs: r.IssuerIDs,
		RequiredScope: r.RequiredScope, StatusAssessment: r.StatusAssessment,
		StatusEvidence:  canonicalStatusEvidenceV2(r.StatusEvidence),
		TrustAssessment: r.TrustAssessment, VerifiedAt: r.VerifiedAt,
		VerifierID: r.VerifierID, Version: r.Version,
	}
}

// VerificationReceiptV2Body returns the canonical content that must be
// prepared before terminal commit. It excludes log position, previous hash,
// and signature; the caller must bind the body to its authenticated claim.
func VerificationReceiptV2Body(receipt *VerificationReceiptV2) (_ []byte, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	if receipt == nil {
		return nil, fmt.Errorf("wire v2: receipt body is nil")
	}
	candidate := *receipt
	candidate.LogID = "0123456789abcdef0123456789abcdef"
	candidate.Sequence = 1
	candidate.PreviousReceiptHash = make([]byte, 48)
	candidate.Signature = HybridSignature{}
	if err := validateVerificationReceiptV2(&candidate, false); err != nil {
		return nil, err
	}
	// Reserve the largest log envelope before commit, so signing cannot turn
	// an otherwise valid outbox body into an unpublishable oversized receipt.
	candidate.Sequence = maxSafeInteger
	candidate.PreviousReceiptHash[0] = 1
	candidate.Signature = HybridSignature{Ed25519: make([]byte, 64), MLDSA65: make([]byte, 3309)}
	if _, err := EncodeVerificationReceiptV2(&candidate); err != nil {
		return nil, err
	}
	return CanonicalJSON(receiptBodyFieldsV2(receipt))
}

// DecodeVerificationReceiptBodyV2 rejects a malformed or noncanonical
// pre-signing body before it can become an immutable terminal outbox entry.
func DecodeVerificationReceiptBodyV2(data []byte) (_ *VerificationReceiptV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "verification receipt body", "MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2", MaxVerificationReceiptBodyBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2WithTextTopLevel(data, nil, map[string]bool{"bundle_hash": true}); err != nil {
		return nil, err
	}
	required := []string{"version", "verifier_id", "bundle_hash", "issuer_ids", "decision",
		"decision_reason", "identity_status", "trust_assessment", "status_assessment",
		"challenge_assessment", "context_assessment", "context_policy_digest", "verified_at",
		"required_scope", "granted_scope", "status_evidence_digests"}
	if err := requireV2Fields(data, required, "context_policy_digest"); err != nil {
		return nil, err
	}
	var body verificationReceiptBodyV2
	if err := strictUnmarshalV2(data, &body); err != nil {
		return nil, err
	}
	receipt := &VerificationReceiptV2{
		Version: body.Version, VerifierID: body.VerifierID, AgentID: body.AgentID,
		HumanID: body.HumanID, BundleHash: body.BundleHash, IssuerIDs: body.IssuerIDs,
		Decision: body.Decision, DecisionReason: body.DecisionReason,
		IdentityStatus: body.IdentityStatus, TrustAssessment: body.TrustAssessment,
		StatusAssessment: body.StatusAssessment, ChallengeAssessment: body.ChallengeAssessment,
		ContextAssessment: body.ContextAssessment, ContextPolicyDigest: body.ContextPolicyDigest,
		ConstraintEvaluators: body.ConstraintEvaluators,
		VerifiedAt:           body.VerifiedAt, RequiredScope: body.RequiredScope,
		GrantedScope: body.GrantedScope, StatusEvidence: statusEvidenceFromCanonicalV2(body.StatusEvidence),
	}
	canonical, err := VerificationReceiptV2Body(receipt)
	if err != nil {
		return nil, fmt.Errorf("wire v2: verification receipt body is invalid or noncanonical: %v", err)
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("wire v2: verification receipt body is noncanonical")
	}
	return receipt, nil
}

// BindVerificationReceiptBodyV2 assigns the next position in a
// caller-authenticated receipt log to an immutable prepared body. It does not
// sign or append the receipt; the caller must use the same authenticated head
// when atomically publishing the signed result.
func BindVerificationReceiptBodyV2(data []byte, head ReceiptV2Head) (_ *VerificationReceiptV2, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	if err := validateReceiptV2Head(head); err != nil {
		return nil, err
	}
	if head.Frozen || head.Sequence == maxSafeInteger {
		return nil, fmt.Errorf("wire v2: receipt log cannot accept another entry")
	}
	receipt, err := DecodeVerificationReceiptBodyV2(data)
	if err != nil {
		return nil, err
	}
	if receipt.VerifierID != head.VerifierID {
		return nil, fmt.Errorf("wire v2: prepared receipt verifier differs from authenticated log")
	}
	receipt.LogID = head.LogID
	receipt.Sequence = head.Sequence + 1
	receipt.PreviousReceiptHash = bytes.Clone(head.HeadHash)
	if err := validateVerificationReceiptV2(receipt, false); err != nil {
		return nil, err
	}
	return receipt, nil
}

// SignPreparedVerificationReceiptV2 binds and signs an exact prepared body
// with a local verifier key. Publication still requires an atomic append
// against the same caller-authenticated log head.
func SignPreparedVerificationReceiptV2(data []byte, head ReceiptV2Head, private HybridPrivateKey) (*VerificationReceiptV2, error) {
	return SignPreparedVerificationReceiptV2WithSigner(context.Background(), data, head, localSignerV2{private})
}

// SignPreparedVerificationReceiptV2WithSigner is
// SignPreparedVerificationReceiptV2 with an external verifier signer.
func SignPreparedVerificationReceiptV2WithSigner(ctx context.Context, data []byte, head ReceiptV2Head, signer SignerV2) (_ *VerificationReceiptV2, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	bound, err := BindVerificationReceiptBodyV2(data, head)
	if err != nil {
		return nil, err
	}
	signed, err := SignVerificationReceiptV2WithSigner(ctx, bound, signer)
	if err != nil {
		return nil, err
	}
	signedBody, err := VerificationReceiptV2Body(signed)
	if err != nil || !bytes.Equal(signedBody, data) {
		return nil, fmt.Errorf("wire v2: signed receipt differs from prepared body")
	}
	return signed, nil
}
