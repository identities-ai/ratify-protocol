package ratify

import (
	"context"
	"slices"
)

// TransactionVerifySourcesV2 are the caller-authenticated trust and status
// sources for composed transaction-receipt verification (SPEC-v2 §5.7). They
// have the same shapes as the live verifier's V2VerifyCallbacks.Trust,
// .StatusEvidence and .StatusJournal and V2VerifyRequest.StatusKeys and
// .StatusPolicy, so one deployment configuration serves both. Status is
// derived only through the authenticated evidence path of SPEC-v2 §6.5. A nil
// Trust means trust is unavailable; a nil StatusEvidence or StatusJournal, or
// an issuer without a StatusKeys entry, makes that issuer's status
// unavailable. Neither is ever treated as success.
type TransactionVerifySourcesV2 struct {
	Trust          func(ctx context.Context, chain []DelegationCertV2) (V2TrustResolution, error)
	StatusEvidence func(ctx context.Context, req V2StatusEvidenceRequest) (V2StatusEvidenceBatch, error)
	StatusJournal  SecurityJournalStoreV2
	StatusKeys     map[string]V2StatusKeyConfig
	StatusPolicy   RevocationStatusPolicyV2
}

// TransactionVerifyRequestV2 is one composed transaction-receipt check. Now
// is the caller-supplied authoritative evaluation time and FutureSkewSeconds
// the configured future skew (0..300) for delegation issuance times.
type TransactionVerifyRequestV2 struct {
	Receipt           []byte
	Now               int64
	FutureSkewSeconds int64
}

// TransactionPartyVerificationV2 is the per-party evidence of SPEC-v2 §5.7.
// A dimension after a non-trusted trust assessment is "not_evaluated".
type TransactionPartyVerificationV2 struct {
	PartyID       string `json:"party_id"`
	AgentID       string `json:"agent_id"`
	RequiredScope string `json:"required_scope"`
	// TrustAssessment: trusted | untrusted | unavailable.
	TrustAssessment string `json:"trust_assessment"`
	// DelegationAssessment: current | expired | invalid | not_evaluated.
	DelegationAssessment string `json:"delegation_assessment"`
	// DelegationExpiresAt is the earliest expires_at in the chain, or nil
	// when the delegation dimension was not evaluated.
	DelegationExpiresAt *int64 `json:"delegation_expires_at"`
	// StatusAssessment: current | revoked | stale | unavailable | not_evaluated.
	StatusAssessment string `json:"status_assessment"`
	// ScopeAssessment: covered | not_covered | invalid_scope |
	// delegation_not_authorized | not_evaluated.
	ScopeAssessment string `json:"scope_assessment"`
	// Freshness is always FreshnessUnverifiedV2: no live challenge is consumed.
	Freshness      string                  `json:"freshness"`
	StatusEvidence []StatusEvidenceEntryV2 `json:"status_evidence_digests"`
}

// TransactionReceiptVerificationV2 is evidence about signed authority. It is
// never an authorization decision: Actionable is always false and it must
// not be presented as allow. Parties are sorted by party_id.
type TransactionReceiptVerificationV2 struct {
	TransactionID string                           `json:"transaction_id"`
	Actionable    bool                             `json:"actionable"`
	Parties       []TransactionPartyVerificationV2 `json:"parties"`
}

// VerifyTransactionReceiptV2 first verifies the complete receipt: structure,
// every party signature, bundle hash, bundle signature, party binding and
// transaction-derived context. Any failure returns its error class and
// invokes no provider; a party whose proof has no delegation is rejected as
// transaction_party_mismatch. It then evaluates each party in party_id
// order: trust of the party's chain, status of every chain CertificateRef,
// and the effective delegated scope against the signed required_scope. It
// never claims a challenge and never evaluates request-context constraints.
func VerifyTransactionReceiptV2(ctx context.Context, req TransactionVerifyRequestV2, sources TransactionVerifySourcesV2) (_ TransactionReceiptVerificationV2, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if ctx == nil {
		return TransactionReceiptVerificationV2{}, v2Errorf(V2ErrConfigurationInvalid, "transaction verification requires a context")
	}
	if err := validateV2TransactionVerifyConfiguration(req, sources); err != nil {
		return TransactionReceiptVerificationV2{}, err
	}
	receipt, err := DecodeTransactionReceiptV2(req.Receipt)
	if err != nil {
		return TransactionReceiptVerificationV2{}, err
	}
	result := TransactionReceiptVerificationV2{TransactionID: receipt.TransactionID, Parties: []TransactionPartyVerificationV2{}}
	for _, party := range receipt.Parties {
		if err := ctx.Err(); err != nil {
			return TransactionReceiptVerificationV2{}, v2Classify(V2ErrEvaluationCancelled, err)
		}
		party, err := verifyTransactionPartyV2(ctx, party, req, sources)
		if err != nil {
			return TransactionReceiptVerificationV2{}, err
		}
		result.Parties = append(result.Parties, party)
	}
	return result, nil
}

// validateV2TransactionVerifyConfiguration applies the SPEC-v2 §2.5 bounds
// to the evaluation time, skew and status policy, and checks every
// configured status key, before any decoding or provider call.
func validateV2TransactionVerifyConfiguration(req TransactionVerifyRequestV2, sources TransactionVerifySourcesV2) error {
	if !validV2Timestamp(req.Now) {
		return v2Errorf(V2ErrConfigurationInvalid, "transaction verification time is outside 0..%d", V2MaxTimestampSeconds)
	}
	if req.FutureSkewSeconds < 0 || req.FutureSkewSeconds > V2MaxFutureSkewSeconds {
		return v2Errorf(V2ErrConfigurationInvalid, "transaction verification future skew must be 0..%d seconds", V2MaxFutureSkewSeconds)
	}
	return validateV2StatusConfiguration(sources.StatusKeys, sources.StatusPolicy)
}

// verifyTransactionPartyV2 evaluates one decoded party in the SPEC-v2 §5.7
// order: trust, then delegation validity times, status of every chain
// CertificateRef, and effective scope. A non-nil error is a cancellation of
// the caller's context.
func verifyTransactionPartyV2(ctx context.Context, party TransactionReceiptPartyV2, req TransactionVerifyRequestV2, sources TransactionVerifySourcesV2) (TransactionPartyVerificationV2, error) {
	out := TransactionPartyVerificationV2{
		PartyID: party.PartyID, AgentID: party.AgentID, RequiredScope: party.RequiredScope,
		TrustAssessment: "unavailable", DelegationAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ScopeAssessment: "not_evaluated",
		Freshness: FreshnessUnverifiedV2, StatusEvidence: []StatusEvidenceEntryV2{},
	}
	bundle := party.ProofBundle
	chain := bundle.Delegations
	root := chain[len(chain)-1] // decoding rejects an empty chain
	resolution, err := callV2TrustSafely(ctx, sources.Trust, slices.Clone(chain))
	if err != nil && ctx.Err() != nil {
		return out, v2Classify(V2ErrEvaluationCancelled, ctx.Err())
	}
	if err == nil && sources.Trust != nil {
		switch resolution.Outcome {
		case V2TrustTrusted:
			rootID, idErr := keyIDV2(resolution.RootKey)
			if idErr == nil && rootID == root.IssuerID && equalHybridPublicKeys(resolution.RootKey, root.IssuerPubKey) {
				out.TrustAssessment = "trusted"
			}
		case V2TrustUntrusted:
			out.TrustAssessment = "untrusted"
		}
	}
	if out.TrustAssessment != "trusted" {
		return out, nil
	}

	// Delegation validity uses the §6.7 rules at the evaluation time.
	out.DelegationAssessment = "current"
	earliest := chain[0].ExpiresAt
	for _, cert := range chain {
		earliest = min(earliest, cert.ExpiresAt)
		latestIssue, ok := checkedAddV2(req.Now, req.FutureSkewSeconds)
		if !ok || cert.IssuedAt >= cert.ExpiresAt || cert.ExpiresAt-cert.IssuedAt > V2MaxDelegationLifetimeSeconds || cert.IssuedAt > latestIssue {
			out.DelegationAssessment = "invalid"
		} else if req.Now >= cert.ExpiresAt && out.DelegationAssessment == "current" {
			out.DelegationAssessment = "expired"
		}
	}
	out.DelegationExpiresAt = &earliest

	checks := make([]V2CertificateStatusCheck, len(chain))
	for i, cert := range chain {
		checks[i] = V2CertificateStatusCheck{DelegationIndex: i, IssuerID: cert.IssuerID, SubjectID: cert.SubjectID, CertID: cert.CertID}
	}
	stage := runV2StatusStage(ctx, bundle,
		checks, V2VerifyRequest{StatusKeys: sources.StatusKeys, StatusPolicy: sources.StatusPolicy},
		V2VerifyCallbacks{StatusEvidence: sources.StatusEvidence, StatusJournal: sources.StatusJournal}, req.Now)
	if stage.cancelled != nil {
		return out, stage.cancelled
	}
	out.StatusAssessment = stage.assessment.Assessment
	out.StatusEvidence = append(out.StatusEvidence, stage.assessment.Evidence...)

	out.ScopeAssessment = "covered"
	scopes := make([][]string, len(chain))
	for i, cert := range chain {
		if ValidateScopesV2(cert.Scope) != nil {
			out.ScopeAssessment = "invalid_scope"
			return out, nil
		}
		scopes[i] = cert.Scope
	}
	for i := 0; i+1 < len(chain); i++ {
		if !slices.Contains(chain[i+1].Scope, ScopeIdentityDelegate) {
			out.ScopeAssessment = "delegation_not_authorized"
			return out, nil
		}
	}
	if !slices.Contains(IntersectScopes(scopes...), party.RequiredScope) {
		out.ScopeAssessment = "not_covered"
	}
	return out, nil
}
