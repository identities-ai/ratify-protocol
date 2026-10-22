package ratify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// VerificationReceiptV2 is a caller-verifier-signed terminal assertion. Its
// signature does not independently establish trust or status for the bundle.
type VerificationReceiptV2 struct {
	Version             int                     `json:"version"`
	LogID               string                  `json:"log_id"`
	Sequence            int64                   `json:"sequence"`
	VerifierID          string                  `json:"verifier_id"`
	AgentID             string                  `json:"agent_id,omitempty"`
	HumanID             string                  `json:"human_id,omitempty"`
	BundleHash          string                  `json:"bundle_hash"`
	IssuerIDs           []string                `json:"issuer_ids"`
	Decision            string                  `json:"decision"`
	DecisionReason      string                  `json:"decision_reason"`
	IdentityStatus      string                  `json:"identity_status"`
	TrustAssessment     string                  `json:"trust_assessment"`
	StatusAssessment    string                  `json:"status_assessment"`
	ChallengeAssessment string                  `json:"challenge_assessment"`
	ContextAssessment   string                  `json:"context_assessment"`
	ContextPolicyDigest *string                 `json:"context_policy_digest"`
	VerifiedAt          int64                   `json:"verified_at"`
	RequiredScope       string                  `json:"required_scope"`
	GrantedScope        []string                `json:"granted_scope"`
	StatusEvidence      []StatusEvidenceEntryV2 `json:"status_evidence_digests"`
	PreviousReceiptHash []byte                  `json:"previous_receipt_hash"`
	Signature           HybridSignature         `json:"signature"`
}

type verificationReceiptSignableV2 struct {
	AgentID             string                      `json:"agent_id,omitempty"`
	BundleHash          string                      `json:"bundle_hash"`
	ChallengeAssessment string                      `json:"challenge_assessment"`
	ContextAssessment   string                      `json:"context_assessment"`
	ContextPolicyDigest *string                     `json:"context_policy_digest"`
	Decision            string                      `json:"decision"`
	DecisionReason      string                      `json:"decision_reason"`
	GrantedScope        []string                    `json:"granted_scope"`
	HumanID             string                      `json:"human_id,omitempty"`
	IdentityStatus      string                      `json:"identity_status"`
	IssuerIDs           []string                    `json:"issuer_ids"`
	LogID               string                      `json:"log_id"`
	PreviousReceiptHash []byte                      `json:"previous_receipt_hash"`
	RequiredScope       string                      `json:"required_scope"`
	Sequence            int64                       `json:"sequence"`
	StatusAssessment    string                      `json:"status_assessment"`
	StatusEvidence      []statusEvidenceCanonicalV2 `json:"status_evidence_digests"`
	TrustAssessment     string                      `json:"trust_assessment"`
	VerifiedAt          int64                       `json:"verified_at"`
	VerifierID          string                      `json:"verifier_id"`
	Version             int                         `json:"version"`
}

type verificationReceiptWireV2 struct {
	AgentID             string                      `json:"agent_id,omitempty"`
	BundleHash          string                      `json:"bundle_hash"`
	ChallengeAssessment string                      `json:"challenge_assessment"`
	ContextAssessment   string                      `json:"context_assessment"`
	ContextPolicyDigest *string                     `json:"context_policy_digest"`
	Decision            string                      `json:"decision"`
	DecisionReason      string                      `json:"decision_reason"`
	GrantedScope        []string                    `json:"granted_scope"`
	HumanID             string                      `json:"human_id,omitempty"`
	IdentityStatus      string                      `json:"identity_status"`
	IssuerIDs           []string                    `json:"issuer_ids"`
	LogID               string                      `json:"log_id"`
	PreviousReceiptHash []byte                      `json:"previous_receipt_hash"`
	RequiredScope       string                      `json:"required_scope"`
	Sequence            int64                       `json:"sequence"`
	Signature           HybridSignature             `json:"signature"`
	StatusAssessment    string                      `json:"status_assessment"`
	StatusEvidence      []statusEvidenceCanonicalV2 `json:"status_evidence_digests"`
	TrustAssessment     string                      `json:"trust_assessment"`
	VerifiedAt          int64                       `json:"verified_at"`
	VerifierID          string                      `json:"verifier_id"`
	Version             int                         `json:"version"`
}

type statusEvidenceCanonicalV2 struct {
	Digest      string `json:"digest"`
	IssuerID    string `json:"issuer_id"`
	ObjectType  uint16 `json:"object_type_code"`
	Sequence    int64  `json:"sequence"`
	StatusKeyID string `json:"status_key_id"`
}

// ReceiptV2Head is caller-authenticated state before a candidate receipt.
// VerifierID is pinned for the log lifetime. AcceptedDigests must contain the
// complete body-digest history for the log.
type ReceiptV2Head struct {
	LogID           string
	VerifierID      string
	Sequence        int64
	HeadHash        []byte
	AcceptedDigests map[int64][]byte
	Frozen          bool
}

var verificationReceiptV2Fields = []string{
	"version", "log_id", "sequence", "verifier_id", "bundle_hash", "issuer_ids",
	"decision", "decision_reason", "identity_status", "trust_assessment",
	"status_assessment", "challenge_assessment", "context_assessment",
	"context_policy_digest", "verified_at", "required_scope", "granted_scope",
	"status_evidence_digests", "previous_receipt_hash", "signature",
}

func receiptV2Signable(r *VerificationReceiptV2) verificationReceiptSignableV2 {
	return verificationReceiptSignableV2{
		AgentID: r.AgentID, BundleHash: r.BundleHash,
		ChallengeAssessment: r.ChallengeAssessment, ContextAssessment: r.ContextAssessment,
		ContextPolicyDigest: r.ContextPolicyDigest, Decision: r.Decision,
		DecisionReason: r.DecisionReason, GrantedScope: r.GrantedScope,
		HumanID: r.HumanID, IdentityStatus: r.IdentityStatus, IssuerIDs: r.IssuerIDs,
		LogID: r.LogID, PreviousReceiptHash: r.PreviousReceiptHash,
		RequiredScope: r.RequiredScope, Sequence: r.Sequence,
		StatusAssessment: r.StatusAssessment, StatusEvidence: canonicalStatusEvidenceV2(r.StatusEvidence),
		TrustAssessment: r.TrustAssessment, VerifiedAt: r.VerifiedAt,
		VerifierID: r.VerifierID, Version: r.Version,
	}
}

func canonicalStatusEvidenceV2(values []StatusEvidenceEntryV2) []statusEvidenceCanonicalV2 {
	out := make([]statusEvidenceCanonicalV2, len(values))
	for i, value := range values {
		out[i] = statusEvidenceCanonicalV2{Digest: value.Digest, IssuerID: value.IssuerID,
			ObjectType: value.ObjectType, Sequence: value.Sequence, StatusKeyID: value.StatusKeyID}
	}
	return out
}

func statusEvidenceFromCanonicalV2(values []statusEvidenceCanonicalV2) []StatusEvidenceEntryV2 {
	out := make([]StatusEvidenceEntryV2, len(values))
	for i, value := range values {
		out[i] = StatusEvidenceEntryV2{IssuerID: value.IssuerID, StatusKeyID: value.StatusKeyID,
			Sequence: value.Sequence, ObjectType: value.ObjectType, Digest: value.Digest}
	}
	return out
}

func validateVerificationReceiptV2(r *VerificationReceiptV2, signature bool) error {
	if r == nil || r.Version != 2 || len(r.LogID) != 32 || !lowerHexString(r.LogID) || r.Sequence <= 0 || r.Sequence > maxSafeInteger || !validV2Timestamp(r.VerifiedAt) {
		return fmt.Errorf("wire v2: receipt version, log ID, sequence, or verified_at is invalid")
	}
	if !validV2ID(r.VerifierID) || r.AgentID != "" && !validV2ID(r.AgentID) {
		return fmt.Errorf("wire v2: receipt verifier_id and optional agent_id must be v2 key IDs")
	}
	if r.HumanID != "" && !utf8.ValidString(r.HumanID) {
		return fmt.Errorf("wire v2: human_id must be a valid UTF-8 string")
	}
	if !validPrefixedDigestV2(r.BundleHash) || len(r.PreviousReceiptHash) != 48 {
		return fmt.Errorf("wire v2: receipt bundle hash or previous receipt hash is invalid")
	}
	if r.IssuerIDs == nil || !sortedUniqueV2IDs(r.IssuerIDs) || r.GrantedScope == nil || r.StatusEvidence == nil {
		return fmt.Errorf("wire v2: receipt arrays must be present and canonical")
	}
	if r.DecisionReason != "not_delegated" && r.DecisionReason != "evaluation_interrupted" && len(r.IssuerIDs) == 0 {
		return fmt.Errorf("wire v2: a receipt for a delegated decision must identify its certificate issuers")
	}
	if r.DecisionReason == "evaluation_interrupted" && len(r.IssuerIDs) == 0 && (r.TrustAssessment != "not_evaluated" || r.StatusAssessment != "not_evaluated" || r.ContextAssessment != "not_evaluated" || len(r.StatusEvidence) != 0) {
		return fmt.Errorf("wire v2: interrupted empty-chain receipt cannot claim completed trust, status, or context checks")
	}
	if err := ValidateRequiredScopeV2(r.RequiredScope); err != nil {
		return fmt.Errorf("wire v2: %w", err)
	}
	if r.Sequence == 1 && !bytes.Equal(r.PreviousReceiptHash, make([]byte, 48)) || r.Sequence > 1 && bytes.Equal(r.PreviousReceiptHash, make([]byte, 48)) {
		return fmt.Errorf("wire v2: previous_receipt_hash is inconsistent with receipt sequence")
	}
	if !sortedGrantedScopesV2(r.GrantedScope) {
		return fmt.Errorf("wire v2: granted_scope must be sorted, unique canonical scopes")
	}
	for _, issuerID := range r.IssuerIDs {
		if !validV2ID(issuerID) {
			return fmt.Errorf("wire v2: issuer_ids contains an invalid v2 key ID")
		}
	}
	if !sortedEvidenceV2(r.StatusEvidence, r.IssuerIDs, r.VerifierID, r.AgentID) {
		return fmt.Errorf("wire v2: status evidence is invalid, duplicated, or not canonically sorted")
	}
	if (r.StatusAssessment == "current" || r.StatusAssessment == "revoked" || r.StatusAssessment == "stale") && len(r.StatusEvidence) == 0 {
		return fmt.Errorf("wire v2: evaluated status requires authenticated evidence")
	}
	if r.ContextPolicyDigest != nil && !validPrefixedDigestV2(*r.ContextPolicyDigest) {
		return fmt.Errorf("wire v2: context_policy_digest is invalid")
	}
	if (r.ContextAssessment == "not_evaluated" || r.ContextAssessment == "unbound") && r.ContextPolicyDigest != nil || (r.ContextAssessment == "bound" || r.ContextAssessment == "not_required" || r.ContextAssessment == "mismatch") && r.ContextPolicyDigest == nil {
		return fmt.Errorf("wire v2: context_policy_digest does not match context_assessment")
	}
	if r.StatusAssessment == "not_evaluated" && len(r.StatusEvidence) != 0 {
		return fmt.Errorf("wire v2: status evidence cannot be present when status was not evaluated")
	}
	if (r.StatusAssessment == "current" || r.StatusAssessment == "stale") && !hasAcceptedStatusHistoryPerIssuerV2(r.StatusEvidence, r.IssuerIDs) {
		return fmt.Errorf("wire v2: current or stale status requires one accepted full-list base and contiguous pushes for every issuer")
	}
	if r.ChallengeAssessment != "current" {
		return fmt.Errorf("wire v2: terminal receipt challenge_assessment must be current")
	}
	if err := validateReceiptDecisionV2(r); err != nil {
		return err
	}
	if signature {
		return validateHybridSignatureV2(r.Signature)
	}
	return nil
}

func validateReceiptDecisionV2(r *VerificationReceiptV2) error {
	decisionReasons := map[string]bool{
		"authorized": true, "not_delegated": true, "delegation_not_authorized": true, "delegation_expired": true,
		"delegation_revoked": true, "scope_denied": true, "constraint_denied": true,
		"constraint_unverifiable": true, "constraint_unknown": true, "invalid_scope": true,
		"proof_invalid": true, "unauthorized": true, "status_stale": true,
		"status_unavailable": true, "action_context_unverified": true,
		"trust_unavailable": true, "evaluation_interrupted": true,
	}
	if !decisionReasons[r.DecisionReason] {
		return fmt.Errorf("wire v2: receipt decision_reason is invalid")
	}
	switch r.TrustAssessment {
	case "trusted", "untrusted", "unavailable", "not_evaluated":
	default:
		return fmt.Errorf("wire v2: receipt trust_assessment is invalid")
	}
	switch r.StatusAssessment {
	case "current", "revoked", "stale", "unavailable", "not_evaluated":
	default:
		return fmt.Errorf("wire v2: receipt status_assessment is invalid")
	}
	switch r.ContextAssessment {
	case "bound", "not_required", "unbound", "unverified", "mismatch", "not_evaluated":
	default:
		return fmt.Errorf("wire v2: receipt context_assessment is invalid")
	}
	if r.Decision == "allow" {
		if r.DecisionReason != "authorized" || r.IdentityStatus != "authorized_agent" || r.TrustAssessment != "trusted" || r.StatusAssessment != "current" || len(r.StatusEvidence) == 0 || len(r.GrantedScope) == 0 || !containsAllStringSetV2(r.GrantedScope, []string{r.RequiredScope}) || r.ContextAssessment != "bound" && r.ContextAssessment != "not_required" || r.ContextPolicyDigest == nil {
			return fmt.Errorf("wire v2: allow receipt violates authorization, status, context, or scope requirements")
		}
		return nil
	}
	if r.Decision == "deny" {
		if len(r.GrantedScope) != 0 || !validDenyReceiptPairV2(r.DecisionReason, r.IdentityStatus) {
			return fmt.Errorf("wire v2: deny receipt has an invalid reason/status pair or granted scope")
		}
		if r.DecisionReason == "not_delegated" && len(r.IssuerIDs) != 0 {
			return fmt.Errorf("wire v2: not_delegated receipt cannot contain certificate issuers")
		}
		if (r.DecisionReason == "scope_denied" || r.DecisionReason == "constraint_denied" || r.DecisionReason == "constraint_unverifiable" || r.DecisionReason == "constraint_unknown") && r.StatusAssessment != "current" {
			return fmt.Errorf("wire v2: post-status local policy denial requires current status")
		}
		if r.DecisionReason == "unauthorized" && r.TrustAssessment != "untrusted" || r.DecisionReason == "not_delegated" && r.TrustAssessment != "not_evaluated" || r.DecisionReason != "unauthorized" && r.DecisionReason != "not_delegated" && r.TrustAssessment != "trusted" {
			return fmt.Errorf("wire v2: deny receipt trust assessment is inconsistent")
		}
		if r.DecisionReason == "delegation_revoked" && r.StatusAssessment != "revoked" || r.DecisionReason == "not_delegated" && r.StatusAssessment != "not_evaluated" || r.DecisionReason != "delegation_revoked" && r.DecisionReason != "not_delegated" && r.StatusAssessment != "not_evaluated" && !(r.StatusAssessment == "current" && (r.DecisionReason == "scope_denied" || r.DecisionReason == "constraint_denied" || r.DecisionReason == "constraint_unverifiable" || r.DecisionReason == "constraint_unknown")) {
			return fmt.Errorf("wire v2: deny receipt status assessment is inconsistent")
		}
		if r.DecisionReason == "not_delegated" && r.ContextAssessment != "not_evaluated" || r.DecisionReason == "unauthorized" && r.ContextAssessment != "not_evaluated" {
			return fmt.Errorf("wire v2: deny receipt context assessment is inconsistent")
		}
		if r.DecisionReason == "delegation_revoked" && r.ContextAssessment == "not_evaluated" {
			return fmt.Errorf("wire v2: delegation_revoked receipt must retain its completed context assessment")
		}
		if r.DecisionReason != "delegation_revoked" && r.DecisionReason != "scope_denied" && r.DecisionReason != "constraint_denied" && r.DecisionReason != "constraint_unverifiable" && r.DecisionReason != "constraint_unknown" && r.DecisionReason != "not_delegated" && r.DecisionReason != "unauthorized" && r.ContextAssessment != "not_evaluated" {
			return fmt.Errorf("wire v2: context assessment must be not_evaluated for this deny result")
		}
		if r.DecisionReason == "scope_denied" && r.ContextAssessment == "not_evaluated" || (r.DecisionReason == "constraint_denied" || r.DecisionReason == "constraint_unverifiable" || r.DecisionReason == "constraint_unknown") && r.ContextAssessment != "bound" && r.ContextAssessment != "not_required" && !(r.DecisionReason == "constraint_denied" && r.ContextAssessment == "mismatch") {
			return fmt.Errorf("wire v2: constraint denial must retain its completed context assessment")
		}
		if (r.DecisionReason == "not_delegated" || r.DecisionReason == "unauthorized") && len(r.StatusEvidence) != 0 {
			return fmt.Errorf("wire v2: status evidence is not evaluated for this deny result")
		}
		if r.DecisionReason == "constraint_denied" && r.ContextAssessment == "mismatch" && r.IdentityStatus != "constraint_denied" {
			return fmt.Errorf("wire v2: context mismatch must be a constraint denial")
		}
		return nil
	}
	if r.Decision != "indeterminate" || len(r.GrantedScope) != 0 || r.IdentityStatus != "authorization_unverified" {
		return fmt.Errorf("wire v2: receipt decision or indeterminate identity/scope is invalid")
	}
	switch r.DecisionReason {
	case "status_stale":
		if r.TrustAssessment != "trusted" || r.StatusAssessment != "stale" || r.ContextAssessment == "not_evaluated" {
			return fmt.Errorf("wire v2: status_stale assessment tuple is invalid")
		}
	case "status_unavailable":
		if r.TrustAssessment != "trusted" || r.StatusAssessment != "unavailable" || r.ContextAssessment == "not_evaluated" {
			return fmt.Errorf("wire v2: status_unavailable assessment tuple is invalid")
		}
	case "trust_unavailable":
		if r.TrustAssessment != "unavailable" || r.StatusAssessment != "not_evaluated" || r.ContextAssessment != "not_evaluated" || len(r.StatusEvidence) != 0 {
			return fmt.Errorf("wire v2: trust_unavailable assessment tuple is invalid")
		}
	case "action_context_unverified":
		if r.TrustAssessment != "trusted" || r.StatusAssessment != "current" || r.ContextAssessment != "unbound" && r.ContextAssessment != "unverified" {
			return fmt.Errorf("wire v2: action_context_unverified assessment tuple is invalid")
		}
	case "evaluation_interrupted":
		if r.TrustAssessment == "untrusted" || r.StatusAssessment == "revoked" || r.StatusAssessment == "stale" || r.ContextAssessment == "unbound" || r.ContextAssessment == "unverified" || r.ContextAssessment == "mismatch" || r.TrustAssessment == "not_evaluated" && (r.StatusAssessment != "not_evaluated" || r.ContextAssessment != "not_evaluated") || r.TrustAssessment == "unavailable" && (r.StatusAssessment != "not_evaluated" || r.ContextAssessment != "not_evaluated") || r.TrustAssessment == "trusted" && r.StatusAssessment != "not_evaluated" && r.StatusAssessment != "unavailable" && r.StatusAssessment != "current" || r.ContextAssessment == "not_evaluated" && r.StatusAssessment != "not_evaluated" || (r.StatusAssessment == "unavailable" || r.StatusAssessment == "current") && (r.TrustAssessment != "trusted" || r.ContextAssessment != "bound" && r.ContextAssessment != "not_required") {
			return fmt.Errorf("wire v2: evaluation_interrupted assessment tuple is invalid")
		}
	default:
		return fmt.Errorf("wire v2: indeterminate reason is invalid")
	}
	return nil
}

func validDenyReceiptPairV2(reason, status string) bool {
	pairs := map[string]string{
		"not_delegated": "delegation_not_authorized", "delegation_not_authorized": "delegation_not_authorized", "delegation_expired": "expired",
		"delegation_revoked": "revoked", "scope_denied": "scope_denied",
		"invalid_scope": "invalid_scope", "constraint_denied": "constraint_denied",
		"constraint_unverifiable": "constraint_unverifiable", "constraint_unknown": "constraint_unknown",
		"proof_invalid": "invalid", "unauthorized": "unauthorized",
	}
	expected, ok := pairs[reason]
	return ok && expected == status
}

func validPrefixedDigestV2(value string) bool {
	if !strings.HasPrefix(value, "sha384:") || len(value) != len("sha384:")+96 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha384:"))
	return err == nil && len(decoded) == 48 && strings.ToLower(value) == value
}

func sortedUniqueV2IDs(values []string) bool {
	for i, value := range values {
		if !validV2ID(value) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func sortedGrantedScopesV2(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if ValidateScopesV2(values) != nil {
		return false
	}
	for i, value := range values {
		if scopeWildcards[value] != nil || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func hasAcceptedStatusHistoryPerIssuerV2(evidence []StatusEvidenceEntryV2, issuerIDs []string) bool {
	for _, issuerID := range issuerIDs {
		var baseSequence int64
		statusKeyID := ""
		pushes := make(map[int64]bool)
		for _, entry := range evidence {
			if entry.IssuerID != issuerID {
				continue
			}
			if statusKeyID == "" {
				statusKeyID = entry.StatusKeyID
			} else if statusKeyID != entry.StatusKeyID {
				return false
			}
			if entry.ObjectType == 3 {
				if baseSequence != 0 {
					return false
				}
				baseSequence = entry.Sequence
			} else {
				if pushes[entry.Sequence] {
					return false
				}
				pushes[entry.Sequence] = true
			}
		}
		if baseSequence == 0 {
			return false
		}
		for sequence := range pushes {
			if sequence <= baseSequence {
				return false
			}
		}
		for sequence, expected := baseSequence+1, baseSequence+int64(len(pushes)); sequence <= expected; sequence++ {
			if !pushes[sequence] {
				return false
			}
		}
	}
	return len(issuerIDs) > 0
}

func sortedEvidenceV2(values []StatusEvidenceEntryV2, issuerIDs []string, verifierID, agentID string) bool {
	issuerSet := make(map[string]bool, len(issuerIDs))
	for _, id := range issuerIDs {
		issuerSet[id] = true
	}
	statusKeyIssuers := make(map[string]string)
	for i, value := range values {
		if priorIssuer, ok := statusKeyIssuers[value.StatusKeyID]; ok && priorIssuer != value.IssuerID {
			return false
		}
		statusKeyIssuers[value.StatusKeyID] = value.IssuerID
		if !issuerSet[value.IssuerID] || !validV2ID(value.StatusKeyID) || issuerSet[value.StatusKeyID] || value.StatusKeyID == verifierID || agentID != "" && value.StatusKeyID == agentID || value.Sequence <= 0 || value.Sequence > maxSafeInteger || value.ObjectType != 3 && value.ObjectType != 5 || !validPrefixedDigestV2(value.Digest) {
			return false
		}
		if i > 0 && compareStatusEvidenceV2(values[i-1], value) >= 0 {
			return false
		}
	}
	return true
}

func compareStatusEvidenceV2(a, b StatusEvidenceEntryV2) int {
	left := []string{a.IssuerID, a.StatusKeyID}
	right := []string{b.IssuerID, b.StatusKeyID}
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	if a.Sequence < b.Sequence {
		return -1
	}
	if a.Sequence > b.Sequence {
		return 1
	}
	if a.ObjectType < b.ObjectType {
		return -1
	}
	if a.ObjectType > b.ObjectType {
		return 1
	}
	if a.Digest < b.Digest {
		return -1
	}
	if a.Digest > b.Digest {
		return 1
	}
	return 0
}

func VerificationReceiptV2Digest(receipt *VerificationReceiptV2) ([]byte, error) {
	if err := validateVerificationReceiptV2(receipt, false); err != nil {
		return nil, err
	}
	body, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		return nil, err
	}
	return StatementBodyDigestV2(uint16(v2VerificationReceipt), body)
}

func SignVerificationReceiptV2(receipt *VerificationReceiptV2, verifierPrivate HybridPrivateKey) (*VerificationReceiptV2, error) {
	return SignVerificationReceiptV2WithSigner(context.Background(), receipt, localSignerV2{verifierPrivate})
}

// SignVerificationReceiptV2WithSigner is SignVerificationReceiptV2 with an
// external signer whose key ID must equal verifier_id.
func SignVerificationReceiptV2WithSigner(ctx context.Context, receipt *VerificationReceiptV2, signer SignerV2) (*VerificationReceiptV2, error) {
	if err := validateVerificationReceiptV2(receipt, false); err != nil {
		return nil, err
	}
	verifierPublic, err := signerPublicKeyV2(signer)
	if err != nil {
		return nil, err
	}
	verifierID, err := keyIDV2(verifierPublic)
	if err != nil || verifierID != receipt.VerifierID {
		return nil, fmt.Errorf("receipt verifier_id does not match signing key")
	}
	body, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		return nil, err
	}
	sig, err := signV2StatementWithSigner(ctx, v2VerificationReceipt, body, signer, verifierPublic)
	if err != nil {
		return nil, err
	}
	result := *receipt
	result.Signature = sig
	if _, err := EncodeVerificationReceiptV2(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func EncodeVerificationReceiptV2(receipt *VerificationReceiptV2) ([]byte, error) {
	if err := validateVerificationReceiptV2(receipt, true); err != nil {
		return nil, err
	}
	signable := receiptV2Signable(receipt)
	wire := verificationReceiptWireV2{
		AgentID: signable.AgentID, BundleHash: signable.BundleHash,
		ChallengeAssessment: signable.ChallengeAssessment, ContextAssessment: signable.ContextAssessment,
		ContextPolicyDigest: signable.ContextPolicyDigest, Decision: signable.Decision,
		DecisionReason: signable.DecisionReason, GrantedScope: signable.GrantedScope,
		HumanID: signable.HumanID, IdentityStatus: signable.IdentityStatus, IssuerIDs: signable.IssuerIDs,
		LogID: signable.LogID, PreviousReceiptHash: signable.PreviousReceiptHash,
		RequiredScope: signable.RequiredScope, Sequence: signable.Sequence, Signature: receipt.Signature, StatusAssessment: signable.StatusAssessment,
		StatusEvidence: signable.StatusEvidence, TrustAssessment: signable.TrustAssessment,
		VerifiedAt: signable.VerifiedAt, VerifierID: signable.VerifierID, Version: signable.Version,
	}
	data, err := CanonicalJSON(wire)
	if err != nil {
		return nil, err
	}
	if err := checkV2WireSize(data, "verification receipt", "MAX_VERIFICATION_RECEIPT_BYTES_V2", MaxVerificationReceiptBytesV2); err != nil {
		return nil, err
	}
	return data, nil
}

func DecodeVerificationReceiptV2(data []byte) (_ *VerificationReceiptV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "verification receipt", "MAX_VERIFICATION_RECEIPT_BYTES_V2", MaxVerificationReceiptBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2WithTextTopLevel(data, map[string]bool{"previous_receipt_hash": true}, map[string]bool{"bundle_hash": true}); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, verificationReceiptV2Fields, "context_policy_digest"); err != nil {
		return nil, err
	}
	var wire verificationReceiptWireV2
	if err := strictUnmarshal(data, &wire); err != nil {
		return nil, err
	}
	receipt := &VerificationReceiptV2{
		Version: wire.Version, LogID: wire.LogID, Sequence: wire.Sequence, VerifierID: wire.VerifierID,
		AgentID: wire.AgentID, HumanID: wire.HumanID, BundleHash: wire.BundleHash, IssuerIDs: wire.IssuerIDs,
		Decision: wire.Decision, DecisionReason: wire.DecisionReason, IdentityStatus: wire.IdentityStatus,
		TrustAssessment: wire.TrustAssessment, StatusAssessment: wire.StatusAssessment,
		ChallengeAssessment: wire.ChallengeAssessment, ContextAssessment: wire.ContextAssessment,
		ContextPolicyDigest: wire.ContextPolicyDigest, VerifiedAt: wire.VerifiedAt,
		RequiredScope: wire.RequiredScope, GrantedScope: wire.GrantedScope, StatusEvidence: statusEvidenceFromCanonicalV2(wire.StatusEvidence),
		PreviousReceiptHash: wire.PreviousReceiptHash, Signature: wire.Signature,
	}
	if err := validateVerificationReceiptV2(receipt, true); err != nil {
		return nil, err
	}
	canonical, err := EncodeVerificationReceiptV2(receipt)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("wire v2: verification receipt is not canonical Ratify JSON")
	}
	return receipt, nil
}

func validateVerificationReceiptSignableV2(data []byte) error {
	if err := checkWireJSONV2WithTextTopLevel(data, map[string]bool{"previous_receipt_hash": true}, map[string]bool{"bundle_hash": true}); err != nil {
		return err
	}
	if err := requireV2Fields(data, verificationReceiptV2Fields[:len(verificationReceiptV2Fields)-1], "context_policy_digest"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, exists := fields["signature"]; exists {
		return fmt.Errorf("signable body must exclude signature")
	}
	var wire verificationReceiptWireV2
	if err := strictUnmarshal(data, &wire); err != nil {
		return err
	}
	receipt := &VerificationReceiptV2{
		Version: wire.Version, LogID: wire.LogID, Sequence: wire.Sequence, VerifierID: wire.VerifierID,
		AgentID: wire.AgentID, HumanID: wire.HumanID, BundleHash: wire.BundleHash, IssuerIDs: wire.IssuerIDs,
		Decision: wire.Decision, DecisionReason: wire.DecisionReason, IdentityStatus: wire.IdentityStatus,
		TrustAssessment: wire.TrustAssessment, StatusAssessment: wire.StatusAssessment,
		ChallengeAssessment: wire.ChallengeAssessment, ContextAssessment: wire.ContextAssessment,
		ContextPolicyDigest: wire.ContextPolicyDigest, VerifiedAt: wire.VerifiedAt,
		RequiredScope: wire.RequiredScope, GrantedScope: wire.GrantedScope, StatusEvidence: statusEvidenceFromCanonicalV2(wire.StatusEvidence),
		PreviousReceiptHash: wire.PreviousReceiptHash,
	}
	if err := validateVerificationReceiptV2(receipt, false); err != nil {
		return err
	}
	canonical, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("signable body must use RatifyCanonicalJSON")
	}
	return nil
}

// VerifyVerificationReceiptV2 verifies a receipt with a verifier key supplied
// by the caller and authenticated log state. The receipt never supplies trust
// in its own key. The result distinguishes an append candidate from replay.
func VerifyVerificationReceiptV2(receipt *VerificationReceiptV2, verifierPublic HybridPublicKey, head ReceiptV2Head) (WitnessEntryV2Result, error) {
	if err := validateVerificationReceiptV2(receipt, true); err != nil {
		return 0, v2Classify(V2ErrMalformed, err)
	}
	if _, err := EncodeVerificationReceiptV2(receipt); err != nil {
		return 0, v2Classify(V2ErrMalformed, err)
	}
	if err := validateReceiptV2Head(head); err != nil {
		return 0, err
	}
	if receipt.LogID != head.LogID || receipt.VerifierID != head.VerifierID {
		return 0, v2Errorf(V2ErrLogStateMismatch, "receipt log ID or verifier identity does not match caller-authenticated state")
	}
	verifierID, err := keyIDV2(verifierPublic)
	if err != nil {
		return 0, err
	}
	if receipt.VerifierID != verifierID {
		return 0, v2Errorf(V2ErrLogStateMismatch, "receipt verifier_id does not match caller-authenticated key")
	}
	body, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		return 0, err
	}
	if err := verifyV2Statement(v2VerificationReceipt, body, receipt.Signature, verifierPublic); err != nil {
		return 0, err
	}
	digest, err := VerificationReceiptV2Digest(receipt)
	if err != nil {
		return 0, err
	}
	if receipt.Sequence <= head.Sequence {
		accepted := head.AcceptedDigests[receipt.Sequence]
		if bytes.Equal(accepted, digest) {
			return WitnessEntryV2Replay, nil
		}
		return 0, fmt.Errorf("%w at receipt sequence %d; caller must freeze log %s", ErrWitnessLogFork, receipt.Sequence, head.LogID)
	}
	if head.Frozen {
		return 0, fmt.Errorf("%w", ErrWitnessLogFrozen)
	}
	if receipt.Sequence > head.Sequence+1 {
		return 0, fmt.Errorf("%w: receipt sequence gap", ErrWitnessLogGap)
	}
	if receipt.Sequence != head.Sequence+1 || !bytes.Equal(receipt.PreviousReceiptHash, head.HeadHash) {
		return 0, fmt.Errorf("%w: receipt does not link to current head", ErrWitnessLogOrphan)
	}
	return WitnessEntryV2Appended, nil
}

func validateReceiptV2Head(head ReceiptV2Head) error {
	if len(head.LogID) != 32 || !lowerHexString(head.LogID) || !validV2ID(head.VerifierID) || head.Sequence < 0 || head.Sequence > maxSafeInteger || len(head.HeadHash) != 48 {
		return v2Errorf(V2ErrConfigurationInvalid, "caller receipt head is invalid")
	}
	if head.Sequence == 0 && (!bytes.Equal(head.HeadHash, make([]byte, 48)) || len(head.AcceptedDigests) != 0) || head.Sequence > 0 && bytes.Equal(head.HeadHash, make([]byte, 48)) {
		return v2Errorf(V2ErrConfigurationInvalid, "caller receipt head has inconsistent genesis state")
	}
	if head.Sequence > 0 && int64(len(head.AcceptedDigests)) != head.Sequence {
		return v2Errorf(V2ErrConfigurationInvalid, "caller receipt head is missing accepted sequence digests")
	}
	if head.Sequence > 0 && !bytes.Equal(head.AcceptedDigests[head.Sequence], head.HeadHash) {
		return v2Errorf(V2ErrConfigurationInvalid, "caller receipt head hash does not match accepted digest history")
	}
	for sequence, digest := range head.AcceptedDigests {
		if sequence <= 0 || sequence > head.Sequence || len(digest) != 48 {
			return v2Errorf(V2ErrConfigurationInvalid, "caller receipt head contains invalid digest history")
		}
	}
	return nil
}

// CheckVerificationReceiptV2BundleBinding checks the fields that can be
// compared when a receipt and its proof bundle are both available. It does not
// establish root trust or current revocation status for the bundle.
func CheckVerificationReceiptV2BundleBinding(receipt *VerificationReceiptV2, bundle *ProofBundleV2) error {
	if err := validateVerificationReceiptV2(receipt, false); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if _, err := EncodeProofBundleV2(bundle); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if receipt.VerifierID != bundle.VerifierID || receipt.AgentID != "" && receipt.AgentID != bundle.AgentID {
		return v2Errorf(V2ErrReceiptBundleMismatch, "receipt verifier or agent ID does not match the proof bundle")
	}
	roleKeyIDs := map[string]bool{bundle.VerifierID: true, bundle.AgentID: true}
	for _, cert := range bundle.Delegations {
		roleKeyIDs[cert.IssuerID] = true
		roleKeyIDs[cert.SubjectID] = true
	}
	for _, evidence := range receipt.StatusEvidence {
		if roleKeyIDs[evidence.StatusKeyID] {
			return v2Errorf(V2ErrReceiptBundleMismatch, "receipt status key ID overlaps a proof or verifier key role")
		}
	}
	bundleHash, err := BundleHashV2(bundle)
	if err != nil {
		return err
	}
	if receipt.BundleHash != bundleHash {
		return v2Errorf(V2ErrReceiptBundleMismatch, "receipt bundle_hash does not match the proof bundle")
	}
	issuerSet := make(map[string]bool, len(bundle.Delegations))
	for _, cert := range bundle.Delegations {
		issuerSet[cert.IssuerID] = true
	}
	issuerIDs := make([]string, 0, len(issuerSet))
	for id := range issuerSet {
		issuerIDs = append(issuerIDs, id)
	}
	sort.Strings(issuerIDs)
	if len(issuerIDs) != len(receipt.IssuerIDs) {
		return v2Errorf(V2ErrReceiptBundleMismatch, "receipt issuer_ids do not match the proof bundle chain")
	}
	for i := range issuerIDs {
		if issuerIDs[i] != receipt.IssuerIDs[i] {
			return v2Errorf(V2ErrReceiptBundleMismatch, "receipt issuer_ids do not match the proof bundle chain")
		}
	}
	return nil
}
