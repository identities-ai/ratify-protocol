package ratify

import (
	"context"
	"slices"
)

// TransactionVerifySourcesV2 are the caller-authenticated trust and status
// sources for composed transaction-receipt verification. They have the same
// shapes as the live verifier's V2VerifyCallbacks.Trust and .Status and
// V2VerifyRequest.StatusRoles, so one deployment configuration serves both.
// A nil Trust means trust is unavailable; a nil Status means status is
// unavailable. Neither is ever treated as success.
type TransactionVerifySourcesV2 struct {
	Trust       func(ctx context.Context, chain []DelegationCertV2) (V2TrustResolution, error)
	Status      func(ctx context.Context, ref CertificateRefV2) RevocationStatusResultV2
	StatusRoles V2StatusRoleBindings
}

// TransactionVerifyRequestV2 is one composed transaction-receipt check. Now
// is the caller-supplied authoritative evaluation time: a status result
// whose fresh_until is not after Now is stale.
type TransactionVerifyRequestV2 struct {
	Receipt []byte
	Now     int64
}

// TransactionPartyVerificationV2 is the per-party evidence of SPEC-v2 §5.7.
// A dimension after a non-trusted trust assessment is "not_evaluated".
type TransactionPartyVerificationV2 struct {
	PartyID       string
	AgentID       string
	RequiredScope string
	// TrustAssessment: trusted | untrusted | unavailable.
	TrustAssessment string
	// StatusAssessment: current | revoked | stale | unavailable | not_evaluated.
	StatusAssessment string
	// ScopeAssessment: covered | not_covered | invalid_scope | not_evaluated.
	ScopeAssessment string
	// Freshness is always FreshnessUnverifiedV2: no live challenge is consumed.
	Freshness      string
	StatusEvidence []StatusEvidenceEntryV2
}

// TransactionReceiptVerificationV2 is evidence about signed authority. It is
// never an authorization decision: Actionable is always false and it must
// not be presented as allow. Parties are sorted by party_id.
type TransactionReceiptVerificationV2 struct {
	TransactionID string
	Actionable    bool
	Parties       []TransactionPartyVerificationV2
}

// VerifyTransactionReceiptV2 first verifies the complete receipt: structure,
// every party signature, bundle hash, bundle signature, party binding and
// transaction-derived context. Any failure returns its error class and
// invokes no provider; a party whose proof has no delegation is rejected as
// transaction_party_mismatch. It then evaluates each party in party_id
// order: trust of the party's chain, status of every chain CertificateRef,
// and the effective delegated scope against the signed required_scope. It
// never claims a challenge and never evaluates request-context constraints.
func VerifyTransactionReceiptV2(ctx context.Context, req TransactionVerifyRequestV2, sources TransactionVerifySourcesV2) (TransactionReceiptVerificationV2, error) {
	if ctx == nil {
		return TransactionReceiptVerificationV2{}, v2Errorf(V2ErrConfigurationInvalid, "transaction verification requires a context")
	}
	if req.Now < 0 || req.Now > maxTimestampV2 {
		return TransactionReceiptVerificationV2{}, v2Errorf(V2ErrConfigurationInvalid, "transaction verification time is outside the protocol timestamp range")
	}
	receipt, err := DecodeTransactionReceiptV2(req.Receipt)
	if err != nil {
		return TransactionReceiptVerificationV2{}, err
	}
	result := TransactionReceiptVerificationV2{TransactionID: receipt.TransactionID, Parties: []TransactionPartyVerificationV2{}}
	for _, party := range receipt.Parties {
		if err := ctx.Err(); err != nil {
			return TransactionReceiptVerificationV2{}, err
		}
		result.Parties = append(result.Parties, verifyTransactionPartyV2(ctx, party, req.Now, sources))
	}
	return result, nil
}

// maxTimestampV2 is 9999-12-31T23:59:59Z (SPEC-v2 §2.5).
const maxTimestampV2 = 253402300799

func verifyTransactionPartyV2(ctx context.Context, party TransactionReceiptPartyV2, now int64, sources TransactionVerifySourcesV2) TransactionPartyVerificationV2 {
	out := TransactionPartyVerificationV2{
		PartyID: party.PartyID, AgentID: party.AgentID, RequiredScope: party.RequiredScope,
		TrustAssessment: "unavailable", StatusAssessment: "not_evaluated", ScopeAssessment: "not_evaluated",
		Freshness: FreshnessUnverifiedV2, StatusEvidence: []StatusEvidenceEntryV2{},
	}
	chain := party.ProofBundle.Delegations
	root := chain[len(chain)-1] // decoding rejects an empty chain
	if sources.Trust == nil {
		return out
	}
	resolution, err := sources.Trust(ctx, slices.Clone(chain))
	switch {
	case err != nil || !resolution.Available:
		return out
	case resolution.RootID != root.IssuerID || !equalHybridPublicKeys(resolution.RootKey, root.IssuerPubKey):
		out.TrustAssessment = "untrusted"
		return out
	}
	out.TrustAssessment = "trusted"

	out.StatusAssessment = "unavailable"
	if sources.Status != nil {
		checks := make([]V2CertificateStatusCheck, len(chain))
		results := make([]RevocationStatusResultV2, len(chain))
		for i, cert := range chain {
			checks[i] = V2CertificateStatusCheck{DelegationIndex: i, IssuerID: cert.IssuerID, SubjectID: cert.SubjectID, CertID: cert.CertID}
			results[i] = sources.Status(ctx, CertificateRefV2{IssuerID: cert.IssuerID, CertID: cert.CertID})
		}
		if aggregated, err := AggregateCertificateStatusV2(checks, results, sources.StatusRoles); err == nil {
			out.StatusAssessment = aggregated.Assessment
			out.StatusEvidence = append(out.StatusEvidence, aggregated.Evidence...)
			if aggregated.Assessment == "current" && now >= aggregated.FreshUntil {
				out.StatusAssessment = "stale"
			}
		}
	}

	out.ScopeAssessment = "covered"
	scopes := make([][]string, len(chain))
	for i, cert := range chain {
		if ValidateScopesV2(cert.Scope) != nil {
			out.ScopeAssessment = "invalid_scope"
			return out
		}
		scopes[i] = cert.Scope
	}
	for i := 0; i+1 < len(chain); i++ {
		if !slices.Contains(chain[i+1].Scope, ScopeIdentityDelegate) {
			out.ScopeAssessment = "not_covered"
			return out
		}
	}
	if !slices.Contains(IntersectScopes(scopes...), party.RequiredScope) {
		out.ScopeAssessment = "not_covered"
	}
	return out
}
