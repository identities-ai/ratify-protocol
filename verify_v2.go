package ratify

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// CertificateRefV2 is the issuer-scoped certificate reference used for
// status. A bare certificate ID is never used as a status key.
type CertificateRefV2 struct {
	IssuerID string `json:"issuer_id"`
	CertID   string `json:"cert_id"`
}

// V2TrustOutcome is a trust provider's answer for one verified chain (SPEC-v2 §6.1).
type V2TrustOutcome string

const (
	// V2TrustTrusted: the chain terminates at the returned configured root.
	V2TrustTrusted V2TrustOutcome = "trusted"
	// V2TrustUntrusted: trust configuration is available and the chain does
	// not terminate at any configured root.
	V2TrustUntrusted V2TrustOutcome = "untrusted"
	// V2TrustUnavailable: no trust configuration, or the source is unavailable.
	V2TrustUnavailable V2TrustOutcome = "unavailable"
	// V2TrustAmbiguous: more than one configured candidate matches, or the
	// resolver cannot decide uniquely. Never becomes trusted.
	V2TrustAmbiguous V2TrustOutcome = "ambiguous"
)

// V2TrustResolution is the caller-authenticated trust provider result. The
// provider is selected by authenticated configuration and never follows a
// location or identifier taken from the proof. RootKey is the complete root
// public key for V2TrustTrusted; the verifier recomputes its key ID and
// requires it and the key to equal the chain's terminal issuer, treating a
// mismatch as ambiguous. Unavailable, ambiguous, an unknown outcome, an
// error, or a panic yields indeterminate/trust_unavailable.
type V2TrustResolution struct {
	Outcome V2TrustOutcome
	RootKey HybridPublicKey
}

// V2VerifyCallbacks are the verifier-owned dependencies of the live v2
// decision path. ClaimStore is required. Every callback is selected by
// authenticated configuration. A callback that returns an error or panics is
// handled fail-closed: trust -> trust_unavailable, status -> unavailable for
// that issuer, audience -> constraint_unverifiable, rate ->
// constraint_unverifiable. If the caller's context has ended when a callback
// fails, nothing is committed (evaluation_cancelled) and the claim remains in
// progress for lease-expiry recovery.
//
// ReceiverBinding is the application's pure pre-consumption hook. It runs
// after the built-in expected-agent, session-context and exact-audience checks
// and before the claim. It must not perform I/O or have side effects.
type V2VerifyCallbacks struct {
	ReceiverBinding func(bundle *ProofBundleV2, expected ExpectedChallengeV2) error
	ClaimStore      ClaimStoreV2
	Trust           func(ctx context.Context, chain []DelegationCertV2) (V2TrustResolution, error)
	// StatusEvidence returns a bounded batch of signed status objects for one
	// issuer (status_provenance_v2.go). It never returns a status result.
	StatusEvidence func(ctx context.Context, req V2StatusEvidenceRequest) (V2StatusEvidenceBatch, error)
	// StatusJournal is the rollback-protected, anchored security journal the
	// evidence is applied to. Without it every status is unavailable.
	StatusJournal SecurityJournalStoreV2
	Audience      func(ctx context.Context, deferred []V2DeferredConstraint, receiverID string) ([]V2AudienceMembership, error)
	Rate          V2RateReservationStore
}

// V2VerifyRequest is one live verification. ContextPolicy nil means the
// verifier explicitly configured no context policy; the terminal result can
// then never be allow (SPEC-v2 §6 table). StatusKeys and StatusPolicy come
// from caller-authenticated configuration.
//
// Now is the caller's clock and is used only for the pre-claim freshness
// check. Every post-claim time-sensitive check uses the claim store's
// authoritative time: the time returned with the claim for evaluation, a
// fresh reading at finalization, and a fresh reading at release.
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
	// TZDBVersion is the configured IANA tzdata release for time_window
	// (SPEC-v2 §5.2, §6.1); it must equal TZDBVersionV2.
	TZDBVersion  string
	StatusKeys   map[string]V2StatusKeyConfig
	StatusPolicy RevocationStatusPolicyV2
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
	// V2StageEvaluating: the claim was created but nothing was committed (the
	// context ended, the authoritative clock failed or regressed, or the store
	// rejected finalization). The claim stays in progress for lease-expiry
	// recovery, which commits indeterminate/evaluation_interrupted.
	V2StageEvaluating V2VerifyStage = "evaluating"
	// V2StageCommitted: a terminal Protocol result and its receipt outbox body
	// were committed. A committed outcome is NOT actionable; only
	// ReleaseV2Decision produces an actionable decision.
	V2StageCommitted V2VerifyStage = "committed"
)

// V2VerifyOutcome is the result of VerifyProofBundleV2. It deliberately has
// no decision field: for V2StageCommitted, Committed is the opaque handoff to
// ReleaseV2Decision.
type V2VerifyOutcome struct {
	Stage       V2VerifyStage
	Error       error
	ErrorClass  V2ErrorClass
	Disposition V2ClaimDisposition
	Claim       V2ChallengeClaim
	Committed   *CommittedV2Outcome
}

// v2EvaluationProgress is the evaluator's progress. persisted is exactly
// what was last recorded in the claim store and what an interrupted result
// reports (SPEC-v2 §6.7); trustCompleted notes that trust resolution ran.
type v2EvaluationProgress struct {
	persisted      V2EvaluationProgress
	trustCompleted bool
}

// VerifyProofBundleV2 runs the live Protocol v2 decision path in the SPEC-v2
// §6 order: configuration bounds; bounded strict decode and structure;
// required-scope validation; key-ID/digest/linkage/duplicate checks; every
// certificate and challenge signature; authenticated ExpectedChallenge
// validation and freshness; the pure receiver-binding hook; the atomic
// challenge claim (with stream sequence); and only then trust, local
// authorization, authenticated status for every CertificateRef, receiver
// audience, and max_rate reservation, followed by terminal finalization at a
// fresh authoritative time.
//
// A pre-claim failure returns Stage=preflight with a classified Error and
// invokes no claim, trust, status, audience, or rate callback. A committed
// outcome is never an authorization: callers must pass it to
// ReleaseV2Decision. The returned error is non-nil only for
// Stage=evaluating.
func VerifyProofBundleV2(ctx context.Context, req V2VerifyRequest, cb V2VerifyCallbacks) (V2VerifyOutcome, error) {
	preflightFailure := func(err error) (V2VerifyOutcome, error) {
		return V2VerifyOutcome{Stage: V2StagePreflight, Error: err, ErrorClass: V2ErrorClassOf(err)}, nil
	}
	if ctx == nil || cb.ClaimStore == nil {
		return preflightFailure(v2Errorf(V2ErrConfigurationInvalid, "v2 verification requires a context and claim store"))
	}
	if err := validateV2VerifyConfiguration(req); err != nil {
		return preflightFailure(err)
	}
	bundle, err := DecodeProofBundleV2(req.Bundle)
	if err != nil {
		return preflightFailure(err)
	}
	preflight, err := preflightProofBundleV2(bundle, req.Expected, req.ContextPolicy, true, safeV2ReceiverBinding(cb.ReceiverBinding),
		req.RequiredScope, req.VerifierNamespace, req.ReplayEpoch, req.Now, req.MaxChallengeAgeSeconds, req.FutureSkewSeconds)
	if err != nil {
		return preflightFailure(err)
	}
	claim, disposition, token, err := claimV2Safely(ctx, cb.ClaimStore, bundle, preflight, req)
	if err != nil {
		if V2ErrorClassOf(err) == V2ErrUnclassified {
			err = v2Classify(V2ErrClaimStoreUnavailable, err)
		}
		return preflightFailure(err)
	}
	if disposition != V2ClaimCreated {
		return V2VerifyOutcome{Stage: V2StageReplay, Disposition: disposition, Claim: claim}, nil
	}
	evaluating := func(err error) (V2VerifyOutcome, error) {
		return V2VerifyOutcome{Stage: V2StageEvaluating, Claim: claim, Disposition: disposition, Error: err, ErrorClass: V2ErrorClassOf(err)}, err
	}
	cancelled := func(err error) (V2VerifyOutcome, error) {
		return evaluating(v2Classify(V2ErrEvaluationCancelled, fmt.Errorf("v2 evaluation cancelled before commit: %w", err)))
	}

	progress := v2EvaluationProgress{persisted: InitialV2EvaluationProgress()}
	// record persists progress before an external lookup starts and after it
	// completes (SPEC-v2 §7.5). A failed write stops evaluation before the
	// next provider call; recovery then uses the last recorded progress.
	record := func() error {
		err := recordV2ProgressSafely(ctx, cb.ClaimStore, token, progress.persisted)
		if err != nil && ctx.Err() != nil {
			return v2Classify(V2ErrEvaluationCancelled, fmt.Errorf("v2 evaluation cancelled before commit: %w", ctx.Err()))
		}
		return err
	}
	opts := V2LocalAuthorizationOptions{
		FutureSkewSeconds: req.FutureSkewSeconds, RequiredScope: req.RequiredScope, Context: req.Context, TZDBVersion: req.TZDBVersion,
		ContextPolicy: req.ContextPolicy, ExpectedChallenge: req.Expected, ClaimToken: token,
	}
	// The claim's own consistency (authoritative claim time inside the sealed
	// challenge bounds) is checked before trust; an inconsistent claim is
	// interrupted with every assessment not_evaluated.
	if token.state.claimTimeValid && len(bundle.Delegations) > 0 {
		progress.persisted.TrustAssessment = "unavailable" // resolution started
		if err := record(); err != nil {
			return evaluating(err)
		}
		chain := make([]DelegationCertV2, len(bundle.Delegations))
		copy(chain, bundle.Delegations)
		resolution, trustErr := callV2TrustSafely(ctx, cb.Trust, chain)
		if trustErr != nil && ctx.Err() != nil {
			return cancelled(ctx.Err())
		}
		root := bundle.Delegations[len(bundle.Delegations)-1]
		trust := "unavailable"
		if trustErr == nil {
			switch resolution.Outcome {
			case V2TrustTrusted:
				rootID, idErr := keyIDV2(resolution.RootKey)
				if idErr == nil && rootID == root.IssuerID && equalHybridPublicKeys(resolution.RootKey, root.IssuerPubKey) {
					trust = "trusted"
					opts.TrustedRootID, opts.TrustedRootKey = rootID, resolution.RootKey
				}
			case V2TrustUntrusted:
				// Configured trust that excludes this chain: the local
				// evaluation compares against an empty root and denies.
				trust = "untrusted"
			}
		}
		opts.TrustConfigured = trust != "unavailable"
		progress.trustCompleted = true
		progress.persisted.TrustAssessment = trust
	}
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, opts)
	claimedAt := token.state.claimedAt
	if progress.trustCompleted {
		if progress.persisted.TrustAssessment == "trusted" && (assessment.ContextAssessment == "bound" || assessment.ContextAssessment == "not_required") && assessment.ContextPolicyDigest != nil {
			digest := *assessment.ContextPolicyDigest
			progress.persisted.ContextAssessment, progress.persisted.ContextPolicyDigest = assessment.ContextAssessment, &digest
		}
		if assessment.Status == "pending_external_checks" {
			progress.persisted.StatusAssessment = "unavailable" // status started
		}
		if err := record(); err != nil {
			return evaluating(err)
		}
	}

	if assessment.Status == "pending_external_checks" {
		stage := runV2StatusStage(ctx, bundle, assessment.StatusChecks, req, cb, claimedAt)
		if stage.cancelled != nil {
			return cancelled(stage.cancelled)
		}
		progress.persisted.StatusAssessment = stage.assessment.Assessment
		progress.persisted.StatusEvidence = append([]StatusEvidenceEntryV2{}, stage.assessment.Evidence...)
		if err := record(); err != nil {
			return evaluating(err)
		}
		resolved, resolveErr := resolveClaimProofBundleV2AfterStatus(token, func([]V2CertificateStatusCheck) (V2StatusAssessment, error) {
			return stage.assessment, nil
		})
		if resolveErr != nil {
			interruptV2Evaluation(token)
			assessment = v2InterruptedAssessment(bundle, "evaluation interrupted after status")
		} else {
			assessment = resolved
		}
	}
	if assessment.Status == "pending_external_checks" && slices.ContainsFunc(assessment.Deferred, func(d V2DeferredConstraint) bool { return d.Type == ConstraintReceiverAudience }) {
		audienceDeferred := make([]V2DeferredConstraint, 0, len(assessment.Deferred))
		for _, d := range assessment.Deferred {
			if d.Type == ConstraintReceiverAudience {
				audienceDeferred = append(audienceDeferred, d)
			}
		}
		memberships, audienceErr := callV2AudienceSafely(ctx, cb.Audience, audienceDeferred, req.Expected.ExpectedReceiverID)
		if audienceErr != nil {
			if ctx.Err() != nil {
				return cancelled(ctx.Err())
			}
			memberships = nil
		}
		resolved, resolveErr := ResolveClaimProofBundleV2AfterAudience(token, memberships)
		if resolveErr != nil {
			interruptV2Evaluation(token)
			assessment = v2InterruptedAssessment(bundle, "evaluation interrupted after audience")
		} else {
			assessment = resolved
		}
	}
	if assessment.Status == "pending_external_checks" {
		if err := ctx.Err(); err != nil {
			return cancelled(err)
		}
		resolved, resolveErr := ResolveClaimProofBundleV2AfterRate(ctx, safeV2RateStore(cb.Rate), token)
		if resolveErr != nil {
			if ctx.Err() != nil {
				return cancelled(ctx.Err())
			}
			interruptV2Evaluation(token)
			assessment = v2InterruptedAssessment(bundle, "evaluation interrupted after rate")
		} else {
			assessment = resolved
		}
	}

	// The claim store reads T_final inside the finalization compare-and-set
	// and rejects a regressed clock or an allow at or beyond its horizon or
	// the challenge expiry; nothing is then committed and lease-expiry
	// recovery later commits evaluation_interrupted (SPEC-v2 §7.2, §7.5).
	for attempt := 0; attempt < 2; attempt++ {
		decision, terminal, body, buildErr := buildV2TerminalResult(bundle, assessment, progress, claim, claimedAt)
		if buildErr != nil {
			return evaluating(buildErr)
		}
		_, finalizeErr := finalizeV2Safely(ctx, cb.ClaimStore, token, terminal, body)
		if V2ErrorClassOf(finalizeErr) == V2ErrUnclassified {
			finalizeErr = v2Classify(V2ErrClaimStoreUnavailable, finalizeErr)
		}
		if finalizeErr == nil {
			horizon := int64(0)
			if decision == "allow" {
				horizon = token.state.allowHorizon()
			}
			return V2VerifyOutcome{Stage: V2StageCommitted, Claim: claim, Disposition: disposition, Committed: newCommittedV2Outcome(claim, body, horizon)}, nil
		}
		if ctx.Err() != nil {
			return cancelled(ctx.Err())
		}
		if !errors.Is(finalizeErr, ErrV2RateLimitExceeded) || attempt > 0 {
			return evaluating(finalizeErr)
		}
		// A barrier store proved definitive capacity exhaustion and rolled back;
		// the same claim finalizes once as constraint_denied (SPEC-v2 §6.2).
		assessment.Status, assessment.Reason = "constraint_denied", "constraint_denied"
		assessment.Detail = "signed rate limit has no remaining capacity"
	}
	return evaluating(fmt.Errorf("v2 terminal finalization did not complete"))
}

// validateV2VerifyConfiguration rejects out-of-bounds configuration before
// the presented bytes are decoded (SPEC-v2 A5).
func validateV2VerifyConfiguration(req V2VerifyRequest) error {
	if err := validateV2FreshnessConfiguration(req.Now, req.MaxChallengeAgeSeconds, req.FutureSkewSeconds); err != nil {
		return err
	}
	return validateV2StatusConfiguration(req.StatusKeys, req.StatusPolicy)
}

// validateV2StatusConfiguration checks the caller-authenticated status policy
// bounds and status-key configuration (SPEC-v2 §2.5, §6.5).
func validateV2StatusConfiguration(keys map[string]V2StatusKeyConfig, policy RevocationStatusPolicyV2) error {
	if policy.MaxListLifetimeSeconds < 1 || policy.MaxListLifetimeSeconds > V2MaxStatusLifetimeSeconds ||
		policy.MaxStatusAgeSeconds < 1 || policy.MaxStatusAgeSeconds > V2MaxStatusLifetimeSeconds ||
		policy.ClockSkewSeconds < 0 || policy.ClockSkewSeconds > V2MaxFutureSkewSeconds {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 status policy must bound list lifetime and status age to 1..%d seconds and skew to 0..%d", V2MaxStatusLifetimeSeconds, V2MaxFutureSkewSeconds)
	}
	for issuerID, config := range keys {
		if !validV2ID(issuerID) || config.Epoch == 0 || config.Epoch > uint64(maxSafeInteger) {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 status-key configuration has an invalid issuer or epoch")
		}
		if _, err := keyIDV2(config.Key); err != nil {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 status-key configuration has an invalid key: %v", err)
		}
	}
	return nil
}

// buildV2TerminalResult maps a terminal assessment to the receipt tuple of
// SPEC-v2 §5.8 and the §6.7 table and validates it by preparing the exact
// receipt outbox body. verifiedAt is the authoritative claim time T_claim.
func buildV2TerminalResult(bundle *ProofBundleV2, assessment V2LocalAuthorizationAssessment, progress v2EvaluationProgress, claim V2ChallengeClaim, verifiedAt int64) (decision string, terminal, body []byte, err error) {
	decision, ok := terminalDecisionForV2Evaluation(assessment.Status, assessment.Reason)
	if !ok {
		return "", nil, nil, fmt.Errorf("v2 evaluation did not reach a terminal result: %s/%s", assessment.Status, assessment.Reason)
	}
	trust := progress.persisted.TrustAssessment
	statusAssessment := assessment.StatusAssessment
	if statusAssessment == "" {
		statusAssessment = "not_evaluated"
	}
	contextAssessment := assessment.ContextAssessment
	if contextAssessment == "" {
		contextAssessment = "not_evaluated"
	}
	evidence := append([]StatusEvidenceEntryV2{}, assessment.StatusEvidence...)
	switch assessment.Reason {
	case "not_delegated":
		trust = "not_evaluated"
	}
	if statusAssessment == "not_evaluated" {
		evidence = []StatusEvidenceEntryV2{}
	}
	var policyDigest *string
	if contextAssessment != "not_evaluated" && contextAssessment != "unbound" && assessment.ContextPolicyDigest != nil {
		digest := *assessment.ContextPolicyDigest
		policyDigest = &digest
	}
	if assessment.Reason == "evaluation_interrupted" {
		// Per-dimension progress, exactly as lease-expiry recovery reports it.
		p := cloneV2EvaluationProgress(progress.persisted)
		trust, statusAssessment, contextAssessment, policyDigest, evidence = p.TrustAssessment, p.StatusAssessment, p.ContextAssessment, p.ContextPolicyDigest, p.StatusEvidence
	}
	granted := []string{}
	if decision == "allow" {
		granted = append(granted, assessment.EffectiveScope...)
		slices.Sort(granted)
		granted = slices.Compact(granted)
	}
	receipt := &VerificationReceiptV2{
		Version: 2, VerifierID: bundle.VerifierID, AgentID: bundle.AgentID,
		BundleHash: claim.BundleHash, IssuerIDs: append([]string{}, claim.IssuerIDs...),
		Decision: decision, DecisionReason: assessment.Reason, IdentityStatus: assessment.Status,
		TrustAssessment: trust, StatusAssessment: statusAssessment, ChallengeAssessment: "current",
		ContextAssessment: contextAssessment, ContextPolicyDigest: policyDigest,
		VerifiedAt: verifiedAt, RequiredScope: claim.RequiredScope, GrantedScope: granted,
		StatusEvidence: evidence,
	}
	body, err = VerificationReceiptV2Body(receipt)
	if err != nil {
		return "", nil, nil, fmt.Errorf("v2 terminal receipt body is inconsistent with the evaluated result: %w", err)
	}
	terminal, err = CanonicalJSON(map[string]string{"decision": decision, "decision_reason": assessment.Reason, "identity_status": assessment.Status})
	if err != nil {
		return "", nil, nil, err
	}
	return decision, terminal, body, nil
}

// ---------------------------------------------------------------------------
// Fail-closed callback adapters. A panic is treated exactly like an error.

func safeV2ReceiverBinding(hook func(*ProofBundleV2, ExpectedChallengeV2) error) func(*ProofBundleV2, ExpectedChallengeV2) error {
	if hook == nil {
		return nil
	}
	return func(bundle *ProofBundleV2, expected ExpectedChallengeV2) (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("receiver-binding hook panicked: %v", recovered)
			}
		}()
		return hook(bundle, expected)
	}
}

func claimV2Safely(ctx context.Context, store ClaimStoreV2, bundle *ProofBundleV2, preflight *V2PreflightResult, req V2VerifyRequest) (claim V2ChallengeClaim, disposition V2ClaimDisposition, token *V2EvaluationToken, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			claim, disposition, token = V2ChallengeClaim{}, "", nil
			err = v2Errorf(V2ErrClaimStoreUnavailable, "claim store panicked: %v", recovered)
		}
	}()
	return ClaimProofBundleV2(ctx, store, bundle, preflight, req.VerifierNamespace, req.ReplayEpoch, req.Now)
}

func callV2TrustSafely(ctx context.Context, trust func(context.Context, []DelegationCertV2) (V2TrustResolution, error), chain []DelegationCertV2) (resolution V2TrustResolution, err error) {
	if trust == nil {
		return V2TrustResolution{}, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			resolution, err = V2TrustResolution{}, fmt.Errorf("trust resolver panicked: %v", recovered)
		}
	}()
	return trust(ctx, chain)
}

func callV2AudienceSafely(ctx context.Context, audience func(context.Context, []V2DeferredConstraint, string) ([]V2AudienceMembership, error), deferred []V2DeferredConstraint, receiverID string) (memberships []V2AudienceMembership, err error) {
	if audience == nil {
		return nil, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			memberships, err = nil, fmt.Errorf("audience provider panicked: %v", recovered)
		}
	}()
	return audience(ctx, deferred, receiverID)
}

type v2SafeRateStore struct{ inner V2RateReservationStore }

func (s v2SafeRateStore) ReserveV2RateBatch(ctx context.Context, claimID string, owner []byte, bundleHash string, batch []V2RateReservation) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("rate store panicked: %v", recovered)
		}
	}()
	return s.inner.ReserveV2RateBatch(ctx, claimID, owner, bundleHash, batch)
}

// safeV2RateStore wraps a provisional rate store with panic containment. A
// rate-at-finalization store is passed through unchanged because its
// admission happens inside FinalizeV2Claim, which is itself contained.
func safeV2RateStore(store V2RateReservationStore) V2RateReservationStore {
	if store == nil {
		return nil
	}
	if _, atFinalization := store.(V2RateAtFinalizationStore); atFinalization {
		return store
	}
	return v2SafeRateStore{inner: store}
}

func finalizeV2Safely(ctx context.Context, store ClaimStoreV2, token *V2EvaluationToken, terminal, body []byte) (finalized bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			finalized, err = false, fmt.Errorf("claim store finalization panicked: %v", recovered)
		}
	}()
	return FinalizeClaimProofBundleV2(ctx, store, token, terminal, body)
}

func readV2AuthoritativeTime(ctx context.Context, clock V2AuthoritativeClock) (now int64, err error) {
	if clock == nil {
		return 0, v2Errorf(V2ErrClockUnavailable, "v2 authoritative clock is not configured")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			now, err = 0, v2Errorf(V2ErrClockUnavailable, "v2 authoritative clock panicked: %v", recovered)
		}
	}()
	now, err = clock.AuthoritativeTimeV2(ctx)
	if err != nil {
		return 0, v2Classify(V2ErrClockUnavailable, err)
	}
	if !validV2Timestamp(now) {
		return 0, v2Errorf(V2ErrClockUnavailable, "v2 authoritative clock returned %d outside 0..%d", now, V2MaxTimestampSeconds)
	}
	return now, nil
}
