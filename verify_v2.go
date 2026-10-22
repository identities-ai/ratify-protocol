package ratify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// CertificateRefV2 is the issuer-scoped certificate reference passed to status
// providers. A bare certificate ID is never used as a status key.
type CertificateRefV2 struct {
	IssuerID string `json:"issuer_id"`
	CertID   string `json:"cert_id"`
}

// V2TrustResolution is the caller-authenticated trust configuration for one
// verified chain. Available=false means no trust configuration or the
// configured trust source is unavailable (indeterminate/trust_unavailable).
type V2TrustResolution struct {
	Available bool
	RootID    string
	RootKey   HybridPublicKey
}

// V2VerifyCallbacks are the verifier-owned dependencies of the live v2
// decision path. ClaimStore is required. Trust is required for a non-empty
// chain; a nil Trust is treated as unavailable trust configuration. Status is
// required for a trusted chain; a nil Status yields unavailable results.
//
// ReceiverBinding is the application's pure pre-consumption hook. It runs
// after the built-in expected-agent, session-context and exact-audience checks
// and before the claim. It must not perform I/O or have side effects.
type V2VerifyCallbacks struct {
	ReceiverBinding func(bundle *ProofBundleV2, expected ExpectedChallengeV2) error
	ClaimStore      ClaimStoreV2
	Trust           func(ctx context.Context, chain []DelegationCertV2) (V2TrustResolution, error)
	Status          func(ctx context.Context, ref CertificateRefV2) RevocationStatusResultV2
	Audience        func(ctx context.Context, deferred []V2DeferredConstraint, receiverID string) ([]V2AudienceMembership, error)
	Rate            V2RateReservationStore
}

// V2VerifyRequest is one live verification. ContextPolicy nil means the
// verifier explicitly configured no context policy; the terminal result can
// then never be allow (SPEC-v2 §6 table). StatusRoles must come from
// caller-authenticated trust configuration.
type V2VerifyRequest struct {
	Bundle                 []byte
	Expected               *ExpectedChallengeV2
	ContextPolicy          *V2ContextPolicy
	RequiredScope          string
	VerifierNamespace      string
	ReplayEpoch            int64
	Now                    int64
	MaxChallengeAgeSeconds int64
	FutureSkewSeconds      int64
	Context                ConstraintContextV2
	StatusRoles            V2StatusRoleBindings
}

// V2VerifyStage names where a verification stopped.
type V2VerifyStage string

const (
	// V2StagePreflight: a pre-claim failure. No challenge was consumed, no
	// trust/status/policy callback ran, and no Protocol receipt exists.
	V2StagePreflight V2VerifyStage = "preflight"
	// V2StageReplay: preflight passed but the claim already existed. The
	// result is not disclosed and no evaluation callback ran.
	V2StageReplay V2VerifyStage = "replay"
	// V2StageEvaluating: the claim was created but evaluation could not reach a
	// terminal commit. The claim stays in progress for lease-expiry recovery.
	V2StageEvaluating V2VerifyStage = "evaluating"
	// V2StageTerminal: a terminal Protocol result was committed.
	V2StageTerminal V2VerifyStage = "terminal"
)

// V2VerifyOutcome is the result of VerifyProofBundleV2. For a terminal
// outcome, Receipt holds the receipt body fields (log position, previous
// hash, and signature are assigned at ordered append) and ReceiptBody is the
// exact sealed outbox body that was finalized with the claim.
type V2VerifyOutcome struct {
	Stage           V2VerifyStage
	Error           error
	ErrorClass      V2ErrorClass
	Disposition     V2ClaimDisposition
	Claim           V2ChallengeClaim
	Decision        string
	Reason          string
	IdentityStatus  string
	Receipt         *VerificationReceiptV2
	ReceiptBody     []byte
	AllowValidUntil int64
}

// VerifyProofBundleV2 runs the complete live Protocol v2 decision path in the
// SPEC-v2 §6 order: bounded strict decode and structure, required-scope
// validation, key-ID/digest/linkage/duplicate checks, every certificate and
// challenge signature, authenticated ExpectedChallenge validation and
// freshness, the pure receiver-binding hook, the atomic challenge claim, and
// only then trust, local authorization, status for every CertificateRef,
// receiver audience, and max_rate reservation, followed by terminal
// finalization through the claim store.
//
// A pre-claim failure returns Stage=preflight with a classified Error and
// invokes no claim, trust, status, audience, or rate callback. The returned
// error is non-nil only when a claimed evaluation could not reach a terminal
// commit; the claim then remains in progress for lease-expiry recovery.
func VerifyProofBundleV2(ctx context.Context, req V2VerifyRequest, cb V2VerifyCallbacks) (V2VerifyOutcome, error) {
	preflightFailure := func(err error) (V2VerifyOutcome, error) {
		return V2VerifyOutcome{Stage: V2StagePreflight, Error: err, ErrorClass: V2ErrorClassOf(err)}, nil
	}
	if ctx == nil || cb.ClaimStore == nil {
		return preflightFailure(v2Errorf(V2ErrConfigurationInvalid, "v2 verification requires a context and claim store"))
	}
	bundle, err := DecodeProofBundleV2(req.Bundle)
	if err != nil {
		return preflightFailure(err)
	}
	preflight, err := preflightProofBundleV2(bundle, req.Expected, req.ContextPolicy, true, cb.ReceiverBinding,
		req.RequiredScope, req.VerifierNamespace, req.ReplayEpoch, req.Now, req.MaxChallengeAgeSeconds, req.FutureSkewSeconds)
	if err != nil {
		return preflightFailure(err)
	}
	claim, disposition, token, err := ClaimProofBundleV2(ctx, cb.ClaimStore, bundle, preflight, req.VerifierNamespace, req.ReplayEpoch, req.Now)
	if err != nil {
		if V2ErrorClassOf(err) == V2ErrUnclassified {
			err = v2Classify(V2ErrClaimStoreUnavailable, err)
		}
		return preflightFailure(err)
	}
	if disposition != V2ClaimCreated {
		return V2VerifyOutcome{Stage: V2StageReplay, Disposition: disposition, Claim: claim}, nil
	}

	trust := "not_evaluated"
	opts := V2LocalAuthorizationOptions{
		Now: time.Unix(req.Now, 0), FutureSkew: time.Duration(req.FutureSkewSeconds) * time.Second,
		RequiredScope: req.RequiredScope, Context: req.Context, ContextPolicy: req.ContextPolicy,
		ExpectedChallenge: req.Expected, ClaimToken: token,
	}
	if len(bundle.Delegations) > 0 {
		resolution := V2TrustResolution{}
		if cb.Trust != nil {
			chain := make([]DelegationCertV2, len(bundle.Delegations))
			copy(chain, bundle.Delegations)
			resolved, trustErr := cb.Trust(ctx, chain)
			if trustErr == nil {
				resolution = resolved
			}
		}
		opts.TrustConfigured = resolution.Available
		opts.TrustedRootID = resolution.RootID
		opts.TrustedRootKey = resolution.RootKey
		switch {
		case !resolution.Available:
			trust = "unavailable"
		case resolution.RootID != bundle.Delegations[len(bundle.Delegations)-1].IssuerID || !equalHybridPublicKeys(resolution.RootKey, bundle.Delegations[len(bundle.Delegations)-1].IssuerPubKey):
			trust = "untrusted"
		default:
			trust = "trusted"
		}
	}
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, opts)

	if assessment.Status == "pending_external_checks" {
		results := make([]RevocationStatusResultV2, len(assessment.StatusChecks))
		for i, check := range assessment.StatusChecks {
			ref := CertificateRefV2{IssuerID: check.IssuerID, CertID: check.CertID}
			if cb.Status == nil {
				results[i] = RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}
				continue
			}
			results[i] = cb.Status(ctx, ref)
		}
		assessment, err = ResolveClaimProofBundleV2AfterStatus(token, results, req.StatusRoles)
		if err != nil {
			return V2VerifyOutcome{Stage: V2StageEvaluating, Claim: claim, Disposition: disposition}, v2Classify(V2ErrConfigurationInvalid, err)
		}
	}
	if assessment.Status == "pending_external_checks" && slices.ContainsFunc(assessment.Deferred, func(d V2DeferredConstraint) bool { return d.Type == ConstraintReceiverAudience }) {
		var memberships []V2AudienceMembership
		if cb.Audience != nil {
			audienceDeferred := make([]V2DeferredConstraint, 0, len(assessment.Deferred))
			for _, d := range assessment.Deferred {
				if d.Type == ConstraintReceiverAudience {
					audienceDeferred = append(audienceDeferred, d)
				}
			}
			if result, audienceErr := cb.Audience(ctx, audienceDeferred, req.Expected.ExpectedReceiverID); audienceErr == nil {
				memberships = result
			}
		}
		assessment, err = ResolveClaimProofBundleV2AfterAudience(token, memberships, req.Now)
		if err != nil {
			return V2VerifyOutcome{Stage: V2StageEvaluating, Claim: claim, Disposition: disposition}, v2Classify(V2ErrConfigurationInvalid, err)
		}
	}
	if assessment.Status == "pending_external_checks" {
		assessment, err = ResolveClaimProofBundleV2AfterRate(ctx, cb.Rate, token)
		if err != nil {
			return V2VerifyOutcome{Stage: V2StageEvaluating, Claim: claim, Disposition: disposition}, v2Classify(V2ErrConfigurationInvalid, err)
		}
	}

	for attempt := 0; attempt < 2; attempt++ {
		outcome, buildErr := terminalV2Outcome(bundle, assessment, trust, req, claim)
		if buildErr != nil {
			return V2VerifyOutcome{Stage: V2StageEvaluating, Claim: claim, Disposition: disposition}, buildErr
		}
		terminal, encodeErr := CanonicalJSON(map[string]string{"decision": outcome.Decision, "decision_reason": outcome.Reason, "identity_status": outcome.IdentityStatus})
		if encodeErr != nil {
			return outcome, encodeErr
		}
		_, finalizeErr := FinalizeClaimProofBundleV2(ctx, cb.ClaimStore, token, terminal, outcome.ReceiptBody)
		if finalizeErr == nil {
			outcome.Disposition = disposition
			outcome.AllowValidUntil = token.state.allowValidUntil
			return outcome, nil
		}
		if !errors.Is(finalizeErr, ErrV2RateLimitExceeded) || attempt > 0 {
			return V2VerifyOutcome{Stage: V2StageEvaluating, Claim: claim, Disposition: disposition}, finalizeErr
		}
		// A barrier store proved definitive capacity exhaustion and rolled back;
		// the same claim finalizes once as constraint_denied (SPEC-v2 §6.2).
		assessment.Status, assessment.Reason = "constraint_denied", "constraint_denied"
		assessment.Detail = "signed rate limit has no remaining capacity"
	}
	return V2VerifyOutcome{}, fmt.Errorf("v2 terminal finalization did not complete")
}

// terminalV2Outcome maps a terminal assessment to the receipt tuple required
// by SPEC-v2 §5.6 and the §6 table, and validates it by preparing the exact
// receipt outbox body.
func terminalV2Outcome(bundle *ProofBundleV2, assessment V2LocalAuthorizationAssessment, trust string, req V2VerifyRequest, claim V2ChallengeClaim) (V2VerifyOutcome, error) {
	decision, ok := terminalDecisionForV2Evaluation(assessment.Status, assessment.Reason)
	if !ok {
		return V2VerifyOutcome{}, fmt.Errorf("v2 evaluation did not reach a terminal result: %s/%s", assessment.Status, assessment.Reason)
	}
	statusAssessment := assessment.StatusAssessment
	if statusAssessment == "" {
		statusAssessment = "not_evaluated"
	}
	contextAssessment := assessment.ContextAssessment
	if contextAssessment == "" {
		contextAssessment = "not_evaluated"
	}
	switch assessment.Reason {
	case "not_delegated":
		trust = "not_evaluated"
	case "evaluation_interrupted":
		if trust != "trusted" {
			trust, statusAssessment = "not_evaluated", "not_evaluated"
		}
		if contextAssessment != "bound" && contextAssessment != "not_required" {
			contextAssessment = "not_evaluated"
		}
		if contextAssessment == "not_evaluated" {
			statusAssessment = "not_evaluated"
		}
	}
	var policyDigest *string
	if contextAssessment != "not_evaluated" && contextAssessment != "unbound" && assessment.ContextPolicyDigest != nil {
		digest := *assessment.ContextPolicyDigest
		policyDigest = &digest
	}
	evidence := append([]StatusEvidenceEntryV2{}, assessment.StatusEvidence...)
	if statusAssessment == "not_evaluated" {
		evidence = []StatusEvidenceEntryV2{}
	}
	granted := []string{}
	if decision == "allow" {
		granted = append(granted, assessment.EffectiveScope...)
		slices.Sort(granted)
		granted = slices.Compact(granted)
	}
	issuerIDs := append([]string{}, claim.IssuerIDs...)
	receipt := &VerificationReceiptV2{
		Version: 2, VerifierID: bundle.VerifierID, AgentID: bundle.AgentID,
		BundleHash: claim.BundleHash, IssuerIDs: issuerIDs,
		Decision: decision, DecisionReason: assessment.Reason, IdentityStatus: assessment.Status,
		TrustAssessment: trust, StatusAssessment: statusAssessment, ChallengeAssessment: "current",
		ContextAssessment: contextAssessment, ContextPolicyDigest: policyDigest,
		VerifiedAt: req.Now, RequiredScope: claim.RequiredScope, GrantedScope: granted,
		StatusEvidence: evidence,
	}
	body, err := VerificationReceiptV2Body(receipt)
	if err != nil {
		return V2VerifyOutcome{}, fmt.Errorf("v2 terminal receipt body is inconsistent with the evaluated result: %w", err)
	}
	return V2VerifyOutcome{
		Stage: V2StageTerminal, Claim: claim, Decision: decision, Reason: assessment.Reason,
		IdentityStatus: assessment.Status, Receipt: receipt, ReceiptBody: body,
	}, nil
}
