package ratify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// V2LocalAuthorizationOptions contains verifier-owned inputs for the
// deterministic authorization checks that follow a successful challenge
// claim. Status retrieval and max_rate reservation are deliberately separate
// stages because they have ordering and durability requirements.
//
// There is no caller-supplied evaluation time: every time-sensitive check
// uses the claim store's authoritative claim time sealed in ClaimToken
// (SPEC-v2 §2.5, §6.2). FutureSkewSeconds must equal the value sealed at claim.
type V2LocalAuthorizationOptions struct {
	FutureSkewSeconds int64
	RequiredScope     string
	TrustedRootID     string
	TrustedRootKey    HybridPublicKey
	TrustConfigured   bool
	Context           ConstraintContextV2
	// TZDBVersion is the caller-configured IANA tzdata release required for
	// time_window evaluation; it must equal TZDBVersionV2 (SPEC-v2 §5.2).
	TZDBVersion       string
	ContextPolicy     *V2ContextPolicy
	ExpectedChallenge *ExpectedChallengeV2
	ClaimToken        *V2EvaluationToken
}

// V2LocalAuthorizationAssessment is an intermediate result, not a terminal
// authorization decision. Callers must still evaluate issuer status and any
// max_rate reservations before they can allow an action.
type V2LocalAuthorizationAssessment struct {
	// BundleHash and IssuerIDs are copied from the sealed preflight state so a
	// terminal receipt remains bound to the claimed proof after a mismatch.
	BundleHash              string
	IssuerIDs               []string
	AgentID                 string
	RootID                  string
	RequiredScope           string
	DelegationDigest        []byte
	EffectiveScope          []string
	ContextAssessment       string
	ContextPolicyDigest     *string
	StatusAssessment        string
	DelegationValidUntil    int64
	LocalTimeValidUntil     int64
	ExtensionValidUntil     int64
	StatusFreshUntil        int64
	AudienceFreshUntil      int64
	StatusEvidence          []StatusEvidenceEntryV2
	AudienceEvidenceDigests []string
	RateStoreUnavailable    bool
	RateAdmissionDeferred   bool
	StatusChecks            []V2CertificateStatusCheck
	Deferred                []V2DeferredConstraint
	LocalPolicyFailure      *V2LocalPolicyFailure
	Status                  string
	Reason                  string
	Detail                  string
}

// V2LocalPolicyFailure is a pure local verdict that must not become terminal
// until every authenticated chain CertificateRef has completed status
// evaluation. A pending external assessment cannot be finalized as allow.
type V2LocalPolicyFailure struct {
	Status string
	Reason string
	Detail string
}

// V2CertificateStatusCheck identifies every issuer-scoped certificate whose
// current status must be resolved before a terminal decision can be made.
type V2CertificateStatusCheck struct {
	DelegationIndex int
	IssuerID        string
	SubjectID       string
	CertID          string
}

// V2DeferredConstraint identifies a constraint requiring the ordered status,
// membership, or rate-reservation stage.
type V2DeferredConstraint struct {
	DelegationIndex int
	ConstraintIndex int
	IssuerID        string
	CertID          string
	Type            ConstraintType
	CanonicalJSON   []byte
}

// EvaluateProofBundleV2LocalAuthorization evaluates trust-root binding,
// delegation times, effective scope, and deterministic constraints. The
// caller must invoke it only after preflight and atomic challenge claim. It
// performs no status lookup, rate reservation, or other external call.
func EvaluateProofBundleV2LocalAuthorization(bundle *ProofBundleV2, opts V2LocalAuthorizationOptions) (assessment V2LocalAuthorizationAssessment) {
	evaluationStarted := false
	defer func() {
		if opts.ClaimToken != nil && opts.ClaimToken.state != nil && opts.ClaimToken.state.expected != nil {
			assessment.BundleHash = opts.ClaimToken.state.expected.BundleHash
			assessment.IssuerIDs = append([]string(nil), opts.ClaimToken.state.expected.IssuerIDs...)
		}
		if evaluationStarted && assessment.Status != "" {
			opts.ClaimToken.state.finalizationMu.Lock()
			opts.ClaimToken.state.evaluationStatus = assessment.Status
			opts.ClaimToken.state.evaluationReason = assessment.Reason
			if assessment.Status == "pending_external_checks" {
				opts.ClaimToken.state.pendingAssessment = cloneV2LocalAuthorizationAssessment(assessment)
			}
			opts.ClaimToken.state.evaluationComplete.Store(true)
			opts.ClaimToken.state.finalizationMu.Unlock()
		}
	}()
	if opts.ClaimToken == nil || opts.ClaimToken.state == nil || opts.ClaimToken.state.expected == nil {
		return v2LocalAssessment(bundle, "preflight_binding_mismatch", "claim_required", nil, "local authorization requires a successful atomic challenge claim")
	}
	tokenState := opts.ClaimToken.state
	claimID, claimErr := ProtocolClaimIDV2(tokenState.expected.VerifierNamespace, tokenState.expected.ReplayEpoch, tokenState.expected.Value)
	if claimErr != nil || tokenState.claimID != claimID || tokenState.proofDigest != tokenState.expected.BundleHash || len(tokenState.ownerToken) != 32 {
		return v2InterruptedAssessment(bundle, "local authorization state differs from successful preflight or atomic claim")
	}
	if !tokenState.used.CompareAndSwap(false, true) {
		return v2LocalAssessment(bundle, "evaluation_in_progress", "claim_in_progress", nil, "the claim's single evaluation token has already been used")
	}
	evaluationStarted = true
	if !tokenState.claimTimeValid {
		return v2InterruptedAssessment(bundle, "claim store returned an authoritative claim time outside the authenticated freshness bounds")
	}
	if opts.ExpectedChallenge != nil && !matchesExpectedChallengeV2(opts.ExpectedChallenge, tokenState.expected) {
		return v2InterruptedAssessment(bundle, "local authorization challenge state differs from successful preflight or atomic claim")
	}
	nowUnix := tokenState.claimedAt
	now := time.Unix(nowUnix, 0)
	tokenState.finalizationMu.Lock()
	tokenState.evaluatedAt = nowUnix
	tokenState.finalizationMu.Unlock()
	if opts.RequiredScope != tokenState.requiredScope || opts.FutureSkewSeconds != tokenState.futureSkew {
		return v2InterruptedAssessment(bundle, "local authorization state differs from successful preflight or atomic claim")
	}
	if opts.RequiredScope != tokenState.expected.RequiredScope {
		return v2InterruptedAssessment(bundle, "required scope differs from the scope validated during preflight")
	}
	bundleHash, err := BundleHashV2(bundle)
	if err != nil || bundleHash != tokenState.proofDigest {
		return v2InterruptedAssessment(bundle, "proof bundle differs from the bundle validated during preflight")
	}
	if bundle == nil || !bytes.Equal(bundle.Challenge, tokenState.expected.Value) ||
		bundle.ChallengeAt != tokenState.expected.IssuedAt ||
		bundle.VerifierID != tokenState.expected.VerifierID {
		return v2InterruptedAssessment(bundle, "proof challenge differs from the challenge validated during preflight")
	}
	if err := ValidateRequiredScopeV2(opts.RequiredScope); err != nil {
		return v2InterruptedAssessment(bundle, "required scope changed after successful preflight: "+err.Error())
	}
	if bundle == nil || VerifyProofBundleV2Signatures(bundle) != nil {
		return v2InterruptedAssessment(bundle, "proof signature changed after successful preflight")
	}
	if len(bundle.Delegations) == 0 {
		return v2LocalAssessment(bundle, "delegation_not_authorized", "not_delegated", nil, "proof has no delegation certificates")
	}
	if !opts.TrustConfigured {
		return v2LocalAssessment(bundle, "authorization_unverified", "trust_unavailable", nil, "caller-authenticated trust configuration is unavailable")
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	if opts.TrustedRootID != root.IssuerID || !equalHybridPublicKeys(opts.TrustedRootKey, root.IssuerPubKey) {
		return v2LocalAssessment(bundle, "unauthorized", "unauthorized", nil, "delegation chain does not terminate at the configured trust root")
	}
	for i := range bundle.Delegations {
		cert := &bundle.Delegations[i]
		// Checked integer seconds: both timestamps inside the v2 domain, a
		// bounded lifetime, and issued_at no later than now + skew.
		latestIssue, ok := checkedAddV2(nowUnix, tokenState.futureSkew)
		if !validV2Timestamp(cert.IssuedAt) || !validV2Timestamp(cert.ExpiresAt) || cert.IssuedAt >= cert.ExpiresAt ||
			cert.ExpiresAt-cert.IssuedAt > V2MaxDelegationLifetimeSeconds || !ok || cert.IssuedAt > latestIssue {
			return v2LocalAssessment(bundle, "invalid", "proof_invalid", nil, fmt.Sprintf("delegation %d has invalid time bounds", i))
		}
	}
	for i := range bundle.Delegations {
		cert := &bundle.Delegations[i]
		if nowUnix >= cert.ExpiresAt {
			return v2LocalAssessment(bundle, "expired", "delegation_expired", nil, fmt.Sprintf("delegation %d has expired", i))
		}
	}
	for i := range bundle.Delegations {
		cert := &bundle.Delegations[i]
		if err := ValidateScopesV2(cert.Scope); err != nil {
			return v2LocalAssessment(bundle, "invalid_scope", "invalid_scope", nil, fmt.Sprintf("delegation %d: %v", i, err))
		}
	}
	for i := range bundle.Delegations {
		if i+1 < len(bundle.Delegations) && !slices.Contains(bundle.Delegations[i+1].Scope, ScopeIdentityDelegate) {
			return v2LocalAssessment(bundle, "delegation_not_authorized", "delegation_not_authorized", nil, fmt.Sprintf("parent delegation %d does not grant %q", i+1, ScopeIdentityDelegate))
		}
	}
	scopeLists := make([][]string, len(bundle.Delegations))
	for i := range bundle.Delegations {
		scopeLists[i] = bundle.Delegations[i].Scope
	}
	effective := IntersectScopes(scopeLists...)
	var localPolicyFailure *V2LocalPolicyFailure
	if !slices.Contains(effective, opts.RequiredScope) {
		localPolicyFailure = &V2LocalPolicyFailure{Status: "scope_denied", Reason: "scope_denied", Detail: fmt.Sprintf("required scope %q is not in the effective delegation scope", opts.RequiredScope)}
	}
	if opts.ContextPolicy != nil && !sameV2ContextPolicy(opts.ContextPolicy, tokenState.expected.ContextPolicy) {
		return v2InterruptedAssessment(bundle, "context policy differs from the policy sealed during successful preflight")
	}
	contextAssessment := EvaluateProofBundleV2ContextPolicy(bundle, tokenState.expected.ContextPolicy)
	if contextAssessment.Status != "passed" {
		if localPolicyFailure == nil {
			localPolicyFailure = &V2LocalPolicyFailure{Status: contextAssessment.Status, Reason: contextAssessment.Reason, Detail: contextAssessment.Detail}
		}
	}
	deferred, constraintStatus, constraintFailures, extensionValidUntil := evaluateV2LocalConstraints(bundle, opts, tokenState.expected, nowUnix, now)
	if constraintStatus != "" {
		slices.Sort(constraintFailures)
		candidate := &V2LocalPolicyFailure{Status: constraintStatus, Reason: constraintStatus, Detail: strings.Join(constraintFailures, "; ")}
		if localPolicyFailure == nil {
			localPolicyFailure = candidate
		}
	}
	assessment = pendingV2LocalAssessment(bundle, opts, effective, deferred, localPolicyFailure)
	assessment.ExtensionValidUntil = extensionValidUntil
	assessment.DelegationValidUntil = bundle.Delegations[0].ExpiresAt
	for _, cert := range bundle.Delegations[1:] {
		if cert.ExpiresAt < assessment.DelegationValidUntil {
			assessment.DelegationValidUntil = cert.ExpiresAt
		}
	}
	if localPolicyFailure == nil {
		var err error
		assessment.LocalTimeValidUntil, err = localTimeWindowValidUntilV2(bundle, opts.TZDBVersion, now)
		if err != nil {
			assessment.LocalPolicyFailure = &V2LocalPolicyFailure{Status: "constraint_unverifiable", Reason: "constraint_unverifiable", Detail: err.Error()}
		}
	}
	assessment.ContextAssessment = contextAssessment.Assessment
	assessment.ContextPolicyDigest = contextAssessment.PolicyDigest
	return assessment
}

// resolveClaimProofBundleV2AfterStatusResults completes the ordered post-claim
// status stage for the assessment sealed by the single-use claim evaluator
// from one reducer result per certificate reference. It is internal: status
// results reach a claim only through the authenticated evidence path of
// SPEC-v2 §6.5 (runV2StatusStage), never from a caller.
// Local denials are applied only when every status is current. Deferred
// audience and rate constraints remain pending for their dedicated evaluators.
func resolveClaimProofBundleV2AfterStatusResults(token *V2EvaluationToken, results []RevocationStatusResultV2, roles V2StatusRoleBindings) (V2LocalAuthorizationAssessment, error) {
	return resolveClaimProofBundleV2AfterStatus(token, func(checks []V2CertificateStatusCheck) (V2StatusAssessment, error) {
		return aggregateCertificateStatusResultsV2(checks, results, roles)
	})
}

func resolveClaimProofBundleV2AfterStatus(token *V2EvaluationToken, aggregate func([]V2CertificateStatusCheck) (V2StatusAssessment, error)) (V2LocalAuthorizationAssessment, error) {
	if token == nil || token.state == nil {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 claim evaluator capability is required")
	}
	state := token.state
	state.finalizationMu.Lock()
	defer state.finalizationMu.Unlock()
	if state.expected == nil || !state.evaluationComplete.Load() || state.evaluationStatus != "pending_external_checks" || state.pendingAssessment == nil {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 claim does not have a pending status assessment")
	}
	assessment := *cloneV2LocalAuthorizationAssessment(*state.pendingAssessment)
	if assessment.BundleHash != state.expected.BundleHash || assessment.RequiredScope != state.expected.RequiredScope {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("pending status assessment differs from its claimed proof")
	}
	aggregated, err := aggregate(assessment.StatusChecks)
	if err != nil {
		return V2LocalAuthorizationAssessment{}, err
	}
	assessment.StatusAssessment = aggregated.Assessment
	assessment.StatusFreshUntil = aggregated.FreshUntil
	assessment.StatusEvidence = append([]StatusEvidenceEntryV2(nil), aggregated.Evidence...)
	switch aggregated.Assessment {
	case "revoked":
		assessment.Status, assessment.Reason = "revoked", "delegation_revoked"
		assessment.Detail = "at least one delegation certificate is revoked"
	case "unavailable":
		assessment.Status, assessment.Reason = "authorization_unverified", "status_unavailable"
		assessment.Detail = "one or more delegation certificate statuses are unavailable"
	case "stale":
		assessment.Status, assessment.Reason = "authorization_unverified", "status_stale"
		assessment.Detail = "one or more delegation certificate statuses are stale"
	case "current":
		if assessment.LocalPolicyFailure != nil && combinableWithAudienceV2(assessment.LocalPolicyFailure, assessment.Deferred) {
			// SPEC-v2 §5.2, §6.4: a proven audience violation on another link
			// outranks a local unknown or unverifiable constraint, so the
			// audience stage still runs. Rate reservation never follows.
			audienceOnly := assessment.Deferred[:0]
			for _, deferred := range assessment.Deferred {
				if deferred.Type == ConstraintReceiverAudience {
					audienceOnly = append(audienceOnly, deferred)
				}
			}
			assessment.Deferred = audienceOnly
			assessment.Status, assessment.Reason = "pending_external_checks", "deferred_policy_checks_required"
			assessment.Detail = "status is current; audience must be aggregated with a pending local constraint result"
			state.pendingAssessment = cloneV2LocalAuthorizationAssessment(assessment)
			state.evaluationStatus, state.evaluationReason = assessment.Status, assessment.Reason
			return assessment, nil
		} else if assessment.LocalPolicyFailure != nil {
			assessment.Status = assessment.LocalPolicyFailure.Status
			assessment.Reason = assessment.LocalPolicyFailure.Reason
			assessment.Detail = assessment.LocalPolicyFailure.Detail
		} else if len(assessment.Deferred) != 0 {
			assessment.Status, assessment.Reason = "pending_external_checks", "deferred_policy_checks_required"
			assessment.Detail = "status is current; deferred audience or rate checks remain"
			state.pendingAssessment = cloneV2LocalAuthorizationAssessment(assessment)
			state.evaluationStatus, state.evaluationReason = assessment.Status, assessment.Reason
			return assessment, nil
		} else {
			assessment.Status, assessment.Reason = "authorized_agent", "authorized"
			assessment.Detail = "proof, status, and local authorization checks passed"
			state.allowValidUntil = allowHorizonV2(assessment)
		}
	default:
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 status aggregator returned an unknown assessment")
	}
	state.evaluationStatus, state.evaluationReason = assessment.Status, assessment.Reason
	state.pendingAssessment = nil
	return assessment, nil
}

// ResolveClaimProofBundleV2AfterAudience consumes caller-authenticated,
// complete membership results only after every certificate status is current.
// The application adapter, not Protocol, authenticates these results.
// Membership freshness is evaluated at the authoritative claim time sealed in
// the token, never at a caller-supplied time (SPEC-v2 §7.2).
func ResolveClaimProofBundleV2AfterAudience(token *V2EvaluationToken, memberships []V2AudienceMembership) (V2LocalAuthorizationAssessment, error) {
	if token == nil || token.state == nil {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 claim evaluator capability is required")
	}
	state := token.state
	state.finalizationMu.Lock()
	defer state.finalizationMu.Unlock()
	if state.expected == nil || !state.evaluationComplete.Load() || state.evaluationStatus != "pending_external_checks" || state.pendingAssessment == nil || state.pendingAssessment.StatusAssessment != "current" || state.pendingAssessment.LocalPolicyFailure != nil && !combinableWithAudienceV2(state.pendingAssessment.LocalPolicyFailure, state.pendingAssessment.Deferred) {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 claim does not have current status and pending audience checks")
	}
	assessment := *cloneV2LocalAuthorizationAssessment(*state.pendingAssessment)
	if assessment.BundleHash != state.expected.BundleHash || assessment.RequiredScope != state.expected.RequiredScope {
		state.evaluationStatus, state.evaluationReason = "authorization_unverified", "evaluation_interrupted"
		state.pendingAssessment = nil
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("pending audience assessment differs from its claimed proof")
	}
	result, err := EvaluateReceiverAudienceV2(assessment.Deferred, state.expected.ExpectedReceiverID, memberships, state.evaluatedAt, state.futureSkew)
	if err != nil {
		state.evaluationStatus, state.evaluationReason = "authorization_unverified", "evaluation_interrupted"
		state.pendingAssessment = nil
		return V2LocalAuthorizationAssessment{}, err
	}
	assessment.AudienceEvidenceDigests = append([]string(nil), result.EvidenceDigests...)
	assessment.AudienceFreshUntil = result.FreshUntil
	if local := assessment.LocalPolicyFailure; local != nil {
		// Aggregate independently of link order: denied, then unknown, then
		// unverifiable (SPEC-v2 §5.2).
		if result.Status == "passed" || constraintPrecedenceV2(local.Status) > constraintPrecedenceV2(result.Status) {
			assessment.Status, assessment.Reason, assessment.Detail = local.Status, local.Reason, local.Detail
		} else {
			assessment.Status, assessment.Reason = result.Status, result.Status
			assessment.Detail = "receiver audience did not authorize this receiver"
		}
		assessment.Deferred = nil
		state.pendingAssessment = nil
	} else if result.Status != "passed" {
		assessment.Status, assessment.Reason = result.Status, result.Status
		assessment.Detail = "receiver audience did not authorize this receiver"
		state.pendingAssessment = nil
	} else {
		remaining := assessment.Deferred[:0]
		for _, deferred := range assessment.Deferred {
			if deferred.Type != ConstraintReceiverAudience {
				remaining = append(remaining, deferred)
			}
		}
		assessment.Deferred = remaining
		if len(assessment.Deferred) == 0 {
			assessment.Status, assessment.Reason = "authorized_agent", "authorized"
			assessment.Detail = "proof, status, audience, and local authorization checks passed"
			state.allowValidUntil = allowHorizonV2(assessment)
			state.pendingAssessment = nil
		} else {
			assessment.Status, assessment.Reason = "pending_external_checks", "rate_reservation_required"
			assessment.Detail = "audience passed; rate reservation remains"
			state.pendingAssessment = cloneV2LocalAuthorizationAssessment(assessment)
		}
	}
	state.evaluationStatus, state.evaluationReason = assessment.Status, assessment.Reason
	return assessment, nil
}

// V2RateReservationStore atomically reserves the complete claim-sealed rate
// batch. An exact live retry is idempotent. Implementations must not call back
// into the token, and nil means every counter remains provisionally held.
type V2RateReservationStore interface {
	ReserveV2RateBatch(context.Context, string, []byte, string, []V2RateReservation) error
}

// ResolveClaimProofBundleV2AfterRate performs the final external Protocol
// constraint stage. The caller must pass a bounded context and finalize the
// returned terminal result through the same claim store; an ambiguous store
// error never authorizes, and claim recovery releases any provisional rows.
func ResolveClaimProofBundleV2AfterRate(ctx context.Context, store V2RateReservationStore, token *V2EvaluationToken) (V2LocalAuthorizationAssessment, error) {
	if ctx == nil || token == nil || token.state == nil {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 rate evaluation requires context and claim capability")
	}
	if err := ctx.Err(); err != nil {
		return V2LocalAuthorizationAssessment{}, err
	}
	state := token.state
	state.finalizationMu.Lock()
	defer state.finalizationMu.Unlock()
	if state.expected == nil || !state.evaluationComplete.Load() || state.evaluationStatus != "pending_external_checks" || state.pendingAssessment == nil || state.pendingAssessment.StatusAssessment != "current" || state.pendingAssessment.LocalPolicyFailure != nil {
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("v2 claim does not have current status and pending rate checks")
	}
	assessment := *cloneV2LocalAuthorizationAssessment(*state.pendingAssessment)
	if assessment.BundleHash != state.expected.BundleHash || assessment.RequiredScope != state.expected.RequiredScope || len(state.rateBatch) == 0 {
		state.evaluationStatus, state.evaluationReason = "authorization_unverified", "evaluation_interrupted"
		state.pendingAssessment = nil
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("pending rate assessment differs from its claimed proof")
	}
	for _, item := range assessment.Deferred {
		if item.Type != ConstraintMaxRate {
			return V2LocalAuthorizationAssessment{}, fmt.Errorf("audience or unknown checks remain before rate reservation")
		}
	}
	batch, err := BuildV2RateReservationBatch(assessment.Deferred)
	if err != nil || !slices.Equal(batch, state.rateBatch) {
		state.evaluationStatus, state.evaluationReason = "authorization_unverified", "evaluation_interrupted"
		state.pendingAssessment = nil
		return V2LocalAuthorizationAssessment{}, fmt.Errorf("pending rate checks differ from sealed signed batch")
	}
	if store == nil {
		err = fmt.Errorf("v2 rate reservation store is unavailable")
	} else if _, ok := store.(V2RateAtFinalizationStore); ok {
		state.rateAtFinalization = true
		assessment.RateAdmissionDeferred = true
	} else {
		err = store.ReserveV2RateBatch(ctx, state.claimID, bytes.Clone(state.ownerToken), assessment.BundleHash, append([]V2RateReservation{}, batch...))
	}
	switch {
	case err == nil:
		assessment.Status, assessment.Reason = "authorized_agent", "authorized"
		if state.rateAtFinalization {
			assessment.Detail = "proof, status, and audience passed; rate admission is deferred to durable finalization"
		} else {
			assessment.Detail = "proof, status, audience, and rate checks passed"
		}
		state.allowValidUntil = allowHorizonV2(assessment)
	case errors.Is(err, ErrV2RateLimitExceeded):
		assessment.Status, assessment.Reason = "constraint_denied", "constraint_denied"
		assessment.Detail = "signed rate limit has no remaining capacity"
	default:
		assessment.Status, assessment.Reason = "constraint_unverifiable", "constraint_unverifiable"
		assessment.Detail = "rate reservation could not be verified"
		assessment.RateStoreUnavailable = true
	}
	assessment.Deferred = nil
	state.pendingAssessment = nil
	state.evaluationStatus, state.evaluationReason = assessment.Status, assessment.Reason
	return assessment, nil
}

func cloneV2LocalAuthorizationAssessment(src V2LocalAuthorizationAssessment) *V2LocalAuthorizationAssessment {
	dst := src
	dst.IssuerIDs = append([]string(nil), src.IssuerIDs...)
	dst.DelegationDigest = bytes.Clone(src.DelegationDigest)
	dst.EffectiveScope = append([]string(nil), src.EffectiveScope...)
	dst.StatusChecks = append([]V2CertificateStatusCheck(nil), src.StatusChecks...)
	dst.StatusEvidence = append([]StatusEvidenceEntryV2(nil), src.StatusEvidence...)
	dst.AudienceEvidenceDigests = append([]string(nil), src.AudienceEvidenceDigests...)
	dst.Deferred = make([]V2DeferredConstraint, len(src.Deferred))
	for i, constraint := range src.Deferred {
		dst.Deferred[i] = constraint
		dst.Deferred[i].CanonicalJSON = bytes.Clone(constraint.CanonicalJSON)
	}
	if src.LocalPolicyFailure != nil {
		failure := *src.LocalPolicyFailure
		dst.LocalPolicyFailure = &failure
	}
	if src.ContextPolicyDigest != nil {
		digest := *src.ContextPolicyDigest
		dst.ContextPolicyDigest = &digest
	}
	return &dst
}

func pendingV2LocalAssessment(bundle *ProofBundleV2, opts V2LocalAuthorizationOptions, effective []string, deferred []V2DeferredConstraint, failure *V2LocalPolicyFailure) V2LocalAuthorizationAssessment {
	assessment := v2LocalAssessment(bundle, "pending_external_checks", "external_checks_required", effective, "local checks recorded; status and deferred authorization checks remain")
	assessment.AgentID = bundle.AgentID
	assessment.RootID = opts.TrustedRootID
	assessment.RequiredScope = opts.RequiredScope
	assessment.DelegationDigest = bytes.Clone(bundle.DelegationDigest)
	assessment.LocalPolicyFailure = failure
	assessment.StatusChecks = make([]V2CertificateStatusCheck, len(bundle.Delegations))
	for i, cert := range bundle.Delegations {
		assessment.StatusChecks[i] = V2CertificateStatusCheck{DelegationIndex: i, IssuerID: cert.IssuerID, SubjectID: cert.SubjectID, CertID: cert.CertID}
	}
	assessment.Deferred = deferred
	return assessment
}

// evaluateV2LocalConstraints evaluates every locally decidable constraint in
// chain order. A registered v2 type uses its built-in rule; an extension type
// uses the evaluator sealed for it at preflight (SPEC-v2 §5.2), and any other
// type is constraint_unknown. It also returns the earliest pass horizon an
// extension evaluator reported (0 = none).
func evaluateV2LocalConstraints(bundle *ProofBundleV2, opts V2LocalAuthorizationOptions, sealed *expectedChallengeStateV2, nowUnix int64, now time.Time) ([]V2DeferredConstraint, string, []string, int64) {
	deferred := make([]V2DeferredConstraint, 0)
	constraintStatus := ""
	constraintFailures := make([]string, 0)
	var extensionHorizon int64
	for i := range bundle.Delegations {
		cert := &bundle.Delegations[i]
		for j, constraint := range cert.Constraints {
			if constraint.Type == ConstraintMaxRate || constraint.Type == ConstraintReceiverAudience {
				encoded, err := CanonicalJSON(constraint)
				if err != nil {
					if constraintPrecedenceV2("constraint_unverifiable") > constraintPrecedenceV2(constraintStatus) {
						constraintStatus = "constraint_unverifiable"
					}
					constraintFailures = append(constraintFailures, fmt.Sprintf("delegation %d constraint %d cannot be encoded: %v", i, j, err))
					continue
				}
				deferred = append(deferred, V2DeferredConstraint{DelegationIndex: i, ConstraintIndex: j, IssuerID: cert.IssuerID, CertID: cert.CertID, Type: constraint.Type, CanonicalJSON: encoded})
				continue
			}
			var err error
			if entry, ok := sealed.evaluators[constraint.Type]; ok && !IsRegisteredConstraintTypeV2(constraint.Type) {
				var horizon int64
				params, encodeErr := extensionParamsJSONV2(constraint)
				if encodeErr != nil {
					err = errConstraintUnverifiable(fmt.Sprintf("%s params cannot be encoded: %v", constraint.Type, encodeErr))
				} else {
					horizon, err = runConstraintEvaluatorV2(entry, sealed.evaluatorTimeout, ConstraintEvaluationInputV2{
						Type: constraint.Type, ParamsJSON: params, DelegationIndex: i, ConstraintIndex: j,
						IssuerID: cert.IssuerID, CertID: cert.CertID, Context: cloneConstraintContextV2(opts.Context), EvaluationTime: nowUnix,
					})
				}
				if err == nil && horizon != 0 && (extensionHorizon == 0 || horizon < extensionHorizon) {
					extensionHorizon = horizon
				}
			} else {
				err = evaluateConstraintV2(constraint, opts.Context, opts.TZDBVersion, now)
			}
			if err != nil {
				status := "constraint_denied"
				switch {
				case errors.Is(err, ErrConstraintUnverifiable):
					status = "constraint_unverifiable"
				case isUnknownV2Constraint(err):
					status = "constraint_unknown"
				}
				if constraintStatus == "" || constraintPrecedenceV2(status) > constraintPrecedenceV2(constraintStatus) {
					constraintStatus = status
				}
				constraintFailures = append(constraintFailures, fmt.Sprintf("delegation %d constraint %d: %v", i, j, err))
			}
		}
	}
	return deferred, constraintStatus, constraintFailures, extensionHorizon
}

func allowHorizonV2(assessment V2LocalAuthorizationAssessment) int64 {
	horizon := min(assessment.DelegationValidUntil, assessment.StatusFreshUntil)
	if assessment.AudienceFreshUntil > 0 {
		horizon = min(horizon, assessment.AudienceFreshUntil)
	}
	if assessment.LocalTimeValidUntil > 0 {
		horizon = min(horizon, assessment.LocalTimeValidUntil)
	}
	if assessment.ExtensionValidUntil > 0 {
		horizon = min(horizon, assessment.ExtensionValidUntil)
	}
	return min(horizon, V2MaxTimestampSeconds)
}

// localTimeWindowValidUntilV2 bounds an allow at the end of each currently
// accepted local minute or the next timezone offset transition, whichever is
// first. At a transition the verifier must evaluate the window again.
func localTimeWindowValidUntilV2(bundle *ProofBundleV2, tzdbVersion string, now time.Time) (int64, error) {
	var horizon int64
	for _, cert := range bundle.Delegations {
		for _, constraint := range cert.Constraints {
			if constraint.Type != ConstraintTimeWindow {
				continue
			}
			loc, err := loadV2TimeZone(tzdbVersion, constraint.TZ)
			if err != nil {
				return 0, err
			}
			start, err := parseHHMMV2(constraint.Start)
			if err != nil {
				return 0, err
			}
			end, err := parseHHMMV2(constraint.End)
			if err != nil {
				return 0, err
			}
			local := now.In(loc)
			minute := local.Hour()*60 + local.Minute()
			if (start <= end && (minute < start || minute > end)) ||
				(start > end && minute < start && minute > end) {
				return 0, fmt.Errorf("time window is no longer current")
			}
			_, offset := local.Zone()
			dayOffset := 0
			if start > end && minute >= start {
				dayOffset = 1
			}
			year, month, day := local.Date()
			until := time.Date(year, month, day+dayOffset, 0, end+1, 0, 0, time.UTC).Add(-time.Duration(offset) * time.Second)
			_, zoneEnd := local.ZoneBounds()
			if !zoneEnd.IsZero() && zoneEnd.Before(until) {
				until = zoneEnd
			}
			if !until.After(now) {
				return 0, fmt.Errorf("time window has no valid terminal horizon")
			}
			// A horizon past the timestamp domain (minute end+1 in year
			// 10000) is clamped to its upper bound (SPEC-v2 §2.5, §5.2).
			contribution := min(until.Unix(), V2MaxTimestampSeconds)
			if horizon == 0 || contribution < horizon {
				horizon = contribution
			}
		}
	}
	return horizon, nil
}

// v2InterruptedAssessment maps failures discovered after challenge claim to
// the Protocol's terminal receipt tuple. Callers reject preflight failures
// before claim; this guard handles a lost or inconsistent post-claim binding.
func v2InterruptedAssessment(bundle *ProofBundleV2, detail string) V2LocalAuthorizationAssessment {
	return v2LocalAssessment(bundle, "authorization_unverified", "evaluation_interrupted", nil, detail)
}

func v2LocalAssessment(bundle *ProofBundleV2, status, reason string, scope []string, detail string) V2LocalAuthorizationAssessment {
	assessment := V2LocalAuthorizationAssessment{EffectiveScope: scope, ContextAssessment: "not_evaluated", Status: status, Reason: reason, Detail: detail}
	return assessment
}

func isUnknownV2Constraint(err error) bool {
	var unknown unknownConstraintError
	return errors.As(err, &unknown)
}

// combinableWithAudienceV2 reports whether a pending local constraint result
// must still be aggregated with deferred receiver-audience results.
func combinableWithAudienceV2(failure *V2LocalPolicyFailure, deferred []V2DeferredConstraint) bool {
	if failure == nil || failure.Status != "constraint_unknown" && failure.Status != "constraint_unverifiable" {
		return false
	}
	for _, item := range deferred {
		if item.Type == ConstraintReceiverAudience {
			return true
		}
	}
	return false
}

func constraintPrecedenceV2(status string) int {
	switch status {
	case "constraint_denied":
		return 3
	case "constraint_unknown":
		return 2
	case "constraint_unverifiable":
		return 1
	default:
		return 0
	}
}

// allowHorizon returns the exclusive allow deadline sealed for this claim (0
// unless the evaluation reached allow).
func (state *v2EvaluationTokenState) allowHorizon() int64 {
	state.finalizationMu.Lock()
	defer state.finalizationMu.Unlock()
	return state.allowValidUntil
}

// interruptV2Evaluation turns the claim's evaluation into the terminal
// indeterminate/evaluation_interrupted result. It is used when a post-claim
// stage cannot complete deterministically (sealed-state mismatch, an
// inconsistent pending stage, or an allow whose horizon passed before
// finalization). Any provisional rate admission is abandoned because the
// result is not allow.
func interruptV2Evaluation(token *V2EvaluationToken) {
	if token == nil || token.state == nil {
		return
	}
	state := token.state
	state.finalizationMu.Lock()
	defer state.finalizationMu.Unlock()
	state.evaluationStatus, state.evaluationReason = "authorization_unverified", "evaluation_interrupted"
	state.allowValidUntil = 0
	state.rateAtFinalization = false
	state.pendingAssessment = nil
	state.evaluationComplete.Store(true)
}
