package ratify

import (
	"bytes"
	"context"
	"fmt"
	"slices"
)

// V2EvaluationProgress is the per-dimension progress of one claimed
// evaluation (SPEC-v2 §6.7, §7.5). The evaluator persists it in the claim
// store under its evaluator capability before every external lookup starts
// and after it completes, so lease-expiry recovery commits an
// evaluation_interrupted receipt that keeps completed assessments, marks an
// interrupted lookup unavailable, and retains collected status evidence.
//
//   - TrustAssessment: not_evaluated (resolution not started), unavailable
//     (resolution started and not completed), trusted, or untrusted.
//   - StatusAssessment: not_evaluated (no status request started),
//     unavailable (started and not completed, or completed unavailable),
//     current, revoked, or stale.
//   - ContextAssessment: not_evaluated, bound, or not_required. A pending
//     unbound, unverified, or mismatch outcome is never recorded.
//   - ContextPolicyDigest is non-nil exactly when ContextAssessment is bound
//     or not_required.
//   - StatusEvidence is the canonical evidence already selected; it is empty
//     while StatusAssessment is not_evaluated.
//
// Its canonical JSON form (RatifyCanonicalJSON) is
// {"context_assessment","context_policy_digest","status_assessment","status_evidence_digests","trust_assessment"}.
type V2EvaluationProgress struct {
	TrustAssessment     string                  `json:"trust_assessment"`
	StatusAssessment    string                  `json:"status_assessment"`
	ContextAssessment   string                  `json:"context_assessment"`
	ContextPolicyDigest *string                 `json:"context_policy_digest"`
	StatusEvidence      []StatusEvidenceEntryV2 `json:"status_evidence_digests"`
}

// V2InterruptedClaim is what a claim store returns to lease-expiry recovery:
// the sealed claim, its authoritative claim time T_claim, and the last
// persisted evaluation progress.
type V2InterruptedClaim struct {
	Claim     V2ChallengeClaim
	ClaimedAt int64
	Progress  V2EvaluationProgress
}

// InitialV2EvaluationProgress is the progress of a claim on which no
// post-claim check has started.
func InitialV2EvaluationProgress() V2EvaluationProgress {
	return V2EvaluationProgress{TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ContextAssessment: "not_evaluated", StatusEvidence: []StatusEvidenceEntryV2{}}
}

func cloneV2EvaluationProgress(p V2EvaluationProgress) V2EvaluationProgress {
	out := p
	if p.ContextPolicyDigest != nil {
		digest := *p.ContextPolicyDigest
		out.ContextPolicyDigest = &digest
	}
	out.StatusEvidence = append([]StatusEvidenceEntryV2{}, p.StatusEvidence...)
	return out
}

// ValidateV2EvaluationProgress checks the per-dimension rules above. A claim
// store rejects an invalid record, and recovery refuses to build a receipt
// from one.
func ValidateV2EvaluationProgress(p V2EvaluationProgress) (resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	switch p.TrustAssessment {
	case "not_evaluated", "unavailable", "trusted", "untrusted":
	default:
		return fmt.Errorf("v2 evaluation progress trust_assessment is invalid")
	}
	switch p.StatusAssessment {
	case "not_evaluated", "unavailable", "current", "revoked", "stale":
	default:
		return fmt.Errorf("v2 evaluation progress status_assessment is invalid")
	}
	switch p.ContextAssessment {
	case "not_evaluated", "bound", "not_required":
	default:
		return fmt.Errorf("v2 evaluation progress context_assessment is invalid")
	}
	if (p.ContextAssessment == "not_evaluated") != (p.ContextPolicyDigest == nil) || p.ContextPolicyDigest != nil && !validPrefixedDigestV2(*p.ContextPolicyDigest) {
		return fmt.Errorf("v2 evaluation progress context_policy_digest does not match context_assessment")
	}
	if p.TrustAssessment != "trusted" && (p.StatusAssessment != "not_evaluated" || p.ContextAssessment != "not_evaluated") {
		return fmt.Errorf("v2 evaluation progress records status or context without a trusted root")
	}
	if p.StatusEvidence == nil || p.StatusAssessment == "not_evaluated" && len(p.StatusEvidence) != 0 {
		return fmt.Errorf("v2 evaluation progress status evidence is inconsistent with status_assessment")
	}
	return nil
}

// V2EvaluationInterruptedResult builds the canonical terminal result object
// and receipt outbox body for indeterminate/evaluation_interrupted from the
// claim's sealed values and its evaluation progress (SPEC-v2 §6.7). The body
// is bound to the claim's sealed bundle hash, issuers, verifier, agent and
// required scope; verifiedAt is the claim's authoritative claim time T_claim.
func V2EvaluationInterruptedResult(claim V2ChallengeClaim, verifiedAt int64, progress V2EvaluationProgress) (terminalResult, receiptBody []byte, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if !validV2Timestamp(verifiedAt) {
		return nil, nil, v2Errorf(V2ErrConfigurationInvalid, "v2 recovery time is outside the timestamp domain")
	}
	if err := ValidateV2EvaluationProgress(progress); err != nil {
		return nil, nil, v2Classify(V2ErrMalformed, err)
	}
	issuers := append([]string{}, claim.IssuerIDs...)
	slices.Sort(issuers)
	progress = cloneV2EvaluationProgress(progress)
	receipt := &VerificationReceiptV2{
		Version: 2, VerifierID: claim.VerifierID, AgentID: claim.AgentID, BundleHash: claim.BundleHash, IssuerIDs: slices.Compact(issuers),
		Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified",
		TrustAssessment: progress.TrustAssessment, StatusAssessment: progress.StatusAssessment, ChallengeAssessment: "current",
		ContextAssessment: progress.ContextAssessment, ContextPolicyDigest: progress.ContextPolicyDigest,
		VerifiedAt: verifiedAt, RequiredScope: claim.RequiredScope,
		GrantedScope: []string{}, StatusEvidence: progress.StatusEvidence,
		ConstraintEvaluators: cloneConstraintEvaluatorRefsV2(claim.ConstraintEvaluators),
	}
	receiptBody, err = VerificationReceiptV2Body(receipt)
	if err != nil {
		return nil, nil, v2Classify(V2ErrMalformed, err)
	}
	terminalResult, err = CanonicalJSON(map[string]string{"decision": "indeterminate", "decision_reason": "evaluation_interrupted", "identity_status": "authorization_unverified"})
	if err != nil {
		return nil, nil, err
	}
	return terminalResult, receiptBody, nil
}

// RecoverInterruptedClaimV2 is lease-expiry recovery (SPEC-v2 §7.5): it loads
// the claim's sealed values, T_claim and persisted progress from the store
// (which refuses while the evaluator lease is live), commits the
// evaluation_interrupted result built from them, and returns the committed
// (non-actionable) outcome for publication and release. An identical repeat
// returns the same outcome.
func RecoverInterruptedClaimV2(ctx context.Context, store ClaimStoreV2, claimID string) (_ *CommittedV2Outcome, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrClaimStoreUnavailable, resultErr) }()
	if ctx == nil || store == nil || claimID == "" {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 recovery requires a context, claim store and claim ID")
	}
	classify := func(err error) error {
		if V2ErrorClassOf(err) == V2ErrUnclassified {
			return v2Classify(V2ErrClaimStoreUnavailable, err)
		}
		return err
	}
	interrupted, err := loadV2InterruptedSafely(ctx, store, claimID)
	if err != nil {
		return nil, classify(err)
	}
	if interrupted.Claim.ClaimID != claimID {
		return nil, v2Errorf(V2ErrClaimStoreUnavailable, "v2 claim store returned a different claim for recovery")
	}
	terminal, body, err := V2EvaluationInterruptedResult(interrupted.Claim, interrupted.ClaimedAt, interrupted.Progress)
	if err != nil {
		return nil, err
	}
	if _, err := recoverV2Safely(ctx, store, claimID, terminal, body); err != nil {
		return nil, classify(err)
	}
	return newCommittedV2Outcome(interrupted.Claim, body, 0), nil
}

func loadV2InterruptedSafely(ctx context.Context, store ClaimStoreV2, claimID string) (interrupted V2InterruptedClaim, err error) {
	defer func() {
		if r := recover(); r != nil {
			interrupted, err = V2InterruptedClaim{}, fmt.Errorf("claim store recovery load panicked: %v", r)
		}
	}()
	return store.LoadV2InterruptedClaim(ctx, claimID)
}

func recoverV2Safely(ctx context.Context, store ClaimStoreV2, claimID string, terminal, body []byte) (recovered bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			recovered, err = false, fmt.Errorf("claim store recovery panicked: %v", r)
		}
	}()
	return store.RecoverInterruptedV2Claim(ctx, claimID, terminal, body)
}

// recordV2ProgressSafely persists progress under the evaluator capability.
// Any failure stops the evaluation before the next provider call.
func recordV2ProgressSafely(ctx context.Context, store ClaimStoreV2, token *V2EvaluationToken, progress V2EvaluationProgress) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = v2Errorf(V2ErrClaimStoreUnavailable, "claim store progress write panicked: %v", r)
		}
	}()
	if err := ValidateV2EvaluationProgress(progress); err != nil {
		return err
	}
	err = store.RecordV2EvaluationProgress(ctx, token.state.claimID, bytes.Clone(token.state.ownerToken), cloneV2EvaluationProgress(progress))
	if err != nil && V2ErrorClassOf(err) == V2ErrUnclassified {
		err = v2Classify(V2ErrClaimStoreUnavailable, err)
	}
	return err
}
