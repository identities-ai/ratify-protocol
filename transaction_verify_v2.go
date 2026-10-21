package ratify

import (
	"context"
	"errors"
	"slices"
	"time"
)

// TransactionVerifySourcesV2 are the caller-authenticated trust and status
// sources for composed transaction-receipt verification. They have the same
// shapes as the live verifier's V2VerifyCallbacks.Trust and .Status and
// V2VerifyRequest.StatusRoles, so one deployment configuration serves both.
// A nil Trust or Status means that source is not configured; the affected
// parties then report authorization and freshness "unknown", never allowed.
type TransactionVerifySourcesV2 struct {
	Trust       func(ctx context.Context, chain []DelegationCertV2) (V2TrustResolution, error)
	Status      func(ctx context.Context, ref CertificateRefV2) RevocationStatusResultV2
	StatusRoles V2StatusRoleBindings
}

// TransactionVerifyRequestV2 is one composed transaction-receipt check.
// Delegation time bounds and status freshness are evaluated at Now.
// PartyContext supplies verifier-authenticated constraint inputs by party_id;
// a party without an entry evaluates against an empty context.
type TransactionVerifyRequestV2 struct {
	Receipt           []byte
	Now               int64
	FutureSkewSeconds int64
	PartyContext      map[string]ConstraintContextV2
}

// Transaction party authorization values.
const (
	TransactionPartyAuthorizedV2 = "authorized"
	TransactionPartyDeniedV2     = "denied"
	TransactionPartyUnknownV2    = "unknown"
)

// TransactionPartyVerificationV2 is the per-party outcome. Authorization is
// "authorized" only when trust is "trusted", every certificate status is
// "current", and every local check passed. A proven denial (untrusted root,
// invalid or expired delegation, revocation, scope or constraint denial) is
// "denied"; anything not established (unconfigured or unavailable trust or
// status, stale status, unverifiable constraint) is "unknown".
type TransactionPartyVerificationV2 struct {
	PartyID       string
	AgentID       string
	RequiredScope string
	// TrustAssessment: trusted | untrusted | unavailable | unknown (no source).
	TrustAssessment string
	// StatusAssessment: current | revoked | stale | unavailable |
	// unknown (no source) | not_evaluated.
	StatusAssessment string
	// Freshness: fresh | stale | unknown.
	Freshness     string
	Authorization string
	// Reason uses the v2 decision-reason vocabulary.
	Reason string
	// ValidUntil is the exclusive horizon of an authorized result: the
	// earliest delegation expiry, status freshness and time-window bound.
	ValidUntil     int64
	StatusEvidence []StatusEvidenceEntryV2
}

// TransactionReceiptVerificationV2 is the composed result. Parties appear in
// receipt order (sorted by party_id).
type TransactionReceiptVerificationV2 struct {
	TransactionID string
	Parties       []TransactionPartyVerificationV2
	// AllAuthorized is true only when every party is authorized.
	AllAuthorized bool
}

// VerifyTransactionReceiptV2 decodes a transaction receipt, verifies its
// signatures, bundle hashes, party bindings and transaction-derived contexts
// (a failure there is returned as a classified error, including
// transaction_party_mismatch for a party whose proof has no delegation), and
// then evaluates every party's proof against the caller-authenticated trust
// and status sources: trust root, delegation time bounds at Now, scope
// validity and delegation authority, the party's signed required_scope,
// locally decidable constraints, and current status of every certificate.
// max_rate and ratify.receiver_audience cannot be exercised for a completed
// transaction and are reported constraint_unverifiable.
func VerifyTransactionReceiptV2(ctx context.Context, req TransactionVerifyRequestV2, sources TransactionVerifySourcesV2) (TransactionReceiptVerificationV2, error) {
	if ctx == nil {
		return TransactionReceiptVerificationV2{}, v2Errorf(V2ErrConfigurationInvalid, "transaction verification requires a context")
	}
	if req.Now < 0 || req.Now > maxSafeInteger || req.FutureSkewSeconds < 0 || req.FutureSkewSeconds > 300 {
		return TransactionReceiptVerificationV2{}, v2Errorf(V2ErrConfigurationInvalid, "transaction verification clock inputs are outside the protocol bounds")
	}
	receipt, err := DecodeTransactionReceiptV2(req.Receipt)
	if err != nil {
		return TransactionReceiptVerificationV2{}, err
	}
	result := TransactionReceiptVerificationV2{TransactionID: receipt.TransactionID, AllAuthorized: true}
	for _, party := range receipt.Parties {
		if err := ctx.Err(); err != nil {
			return TransactionReceiptVerificationV2{}, err
		}
		outcome := verifyTransactionPartyV2(ctx, party, req, sources)
		if outcome.Authorization != TransactionPartyAuthorizedV2 {
			result.AllAuthorized = false
		}
		result.Parties = append(result.Parties, outcome)
	}
	return result, nil
}

func verifyTransactionPartyV2(ctx context.Context, party TransactionReceiptPartyV2, req TransactionVerifyRequestV2, sources TransactionVerifySourcesV2) TransactionPartyVerificationV2 {
	out := TransactionPartyVerificationV2{
		PartyID: party.PartyID, AgentID: party.AgentID, RequiredScope: party.RequiredScope,
		TrustAssessment: "unknown", StatusAssessment: "not_evaluated", Freshness: "unknown",
		Authorization: TransactionPartyUnknownV2, StatusEvidence: []StatusEvidenceEntryV2{},
	}
	finish := func(authorization, reason string) TransactionPartyVerificationV2 {
		out.Authorization, out.Reason = authorization, reason
		return out
	}
	bundle := party.ProofBundle
	chain := bundle.Delegations
	if len(chain) == 0 {
		// Unreachable: decoding rejects an empty chain as transaction_party_mismatch.
		return finish(TransactionPartyDeniedV2, "not_delegated")
	}
	root := chain[len(chain)-1]

	// Trust.
	if sources.Trust == nil {
		return finish(TransactionPartyUnknownV2, "trust_unavailable")
	}
	resolution, err := sources.Trust(ctx, slices.Clone(chain))
	switch {
	case err != nil || !resolution.Available:
		out.TrustAssessment = "unavailable"
		return finish(TransactionPartyUnknownV2, "trust_unavailable")
	case resolution.RootID != root.IssuerID || !equalHybridPublicKeys(resolution.RootKey, root.IssuerPubKey):
		out.TrustAssessment = "untrusted"
		return finish(TransactionPartyDeniedV2, "unauthorized")
	}
	out.TrustAssessment = "trusted"

	// Deterministic local checks, in the live verifier's order.
	now := time.Unix(req.Now, 0)
	for _, cert := range chain {
		if cert.IssuedAt >= cert.ExpiresAt || cert.IssuedAt > req.Now+req.FutureSkewSeconds {
			return finish(TransactionPartyDeniedV2, "proof_invalid")
		}
	}
	validUntil := chain[0].ExpiresAt
	for _, cert := range chain {
		if req.Now >= cert.ExpiresAt {
			return finish(TransactionPartyDeniedV2, "delegation_expired")
		}
		validUntil = min(validUntil, cert.ExpiresAt)
	}
	for _, cert := range chain {
		if ValidateScopesV2(cert.Scope) != nil {
			return finish(TransactionPartyDeniedV2, "invalid_scope")
		}
	}
	for i := 0; i+1 < len(chain); i++ {
		if !slices.Contains(chain[i+1].Scope, ScopeIdentityDelegate) {
			return finish(TransactionPartyDeniedV2, "delegation_not_authorized")
		}
	}
	scopes := make([][]string, len(chain))
	for i := range chain {
		scopes[i] = chain[i].Scope
	}
	localFailure := ""
	if !slices.Contains(IntersectScopes(scopes...), party.RequiredScope) {
		localFailure = "scope_denied"
	}
	if localFailure == "" {
		localFailure = transactionPartyConstraintsV2(chain, req.PartyContext[party.PartyID], now)
	}

	// Status of every certificate reference.
	statusAssessment := "unknown"
	if sources.Status != nil {
		checks := make([]V2CertificateStatusCheck, len(chain))
		results := make([]RevocationStatusResultV2, len(chain))
		for i, cert := range chain {
			checks[i] = V2CertificateStatusCheck{DelegationIndex: i, IssuerID: cert.IssuerID, SubjectID: cert.SubjectID, CertID: cert.CertID}
			results[i] = sources.Status(ctx, CertificateRefV2{IssuerID: cert.IssuerID, CertID: cert.CertID})
		}
		aggregated, err := AggregateCertificateStatusV2(checks, results, sources.StatusRoles)
		if err != nil {
			statusAssessment = "unavailable"
		} else {
			statusAssessment = aggregated.Assessment
			out.StatusEvidence = append(out.StatusEvidence, aggregated.Evidence...)
			if statusAssessment == "current" {
				validUntil = min(validUntil, aggregated.FreshUntil)
			}
		}
	}
	out.StatusAssessment = statusAssessment
	switch statusAssessment {
	case "current":
		out.Freshness = "fresh"
	case "stale":
		out.Freshness = "stale"
	}

	// A proven denial outranks anything not established.
	switch {
	case statusAssessment == "revoked":
		return finish(TransactionPartyDeniedV2, "delegation_revoked")
	case localFailure == "scope_denied" || localFailure == "constraint_denied" || localFailure == "constraint_unknown":
		return finish(TransactionPartyDeniedV2, localFailure)
	case statusAssessment == "stale":
		return finish(TransactionPartyUnknownV2, "status_stale")
	case statusAssessment != "current":
		return finish(TransactionPartyUnknownV2, "status_unavailable")
	case localFailure != "":
		return finish(TransactionPartyUnknownV2, localFailure)
	}
	if horizon, err := localTimeWindowValidUntilV2(bundle, now); err != nil {
		return finish(TransactionPartyUnknownV2, "constraint_unverifiable")
	} else if horizon > 0 {
		validUntil = min(validUntil, horizon)
	}
	if req.Now >= validUntil {
		out.Freshness = "stale"
		return finish(TransactionPartyUnknownV2, "status_stale")
	}
	out.ValidUntil = validUntil
	return finish(TransactionPartyAuthorizedV2, "authorized")
}

// transactionPartyConstraintsV2 aggregates constraint results independent of
// link order: denied, then unknown, then unverifiable. It returns "" when
// every constraint passed.
func transactionPartyConstraintsV2(chain []DelegationCertV2, context ConstraintContextV2, now time.Time) string {
	status := ""
	for _, cert := range chain {
		for _, constraint := range cert.Constraints {
			candidate := ""
			switch err := evaluateConstraintV2(constraint, context, now); {
			case err == nil:
				continue
			case errors.Is(err, ErrConstraintUnverifiable):
				candidate = "constraint_unverifiable"
			case isUnknownV2Constraint(err):
				candidate = "constraint_unknown"
			default:
				candidate = "constraint_denied"
			}
			if constraintPrecedenceV2(candidate) > constraintPrecedenceV2(status) {
				status = candidate
			}
		}
	}
	return status
}
