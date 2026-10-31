package ratify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// V2AudienceMembership is a caller-authenticated, complete membership result
// for one constrained certificate link.
// Protocol does not authenticate this input: a live adapter must verify the
// statement, signer, current version floor, receiver ownership, source, and
// completeness before passing it here. Absence of this result is unavailable,
// not proof of nonmembership. It must never copy these fields from a proof.
type V2AudienceMembership struct {
	DelegationIndex int
	ConstraintIndex int
	ReceiverID      string
	TrustDomainIDs  []string
	IssuedAt        int64
	ExpiresAt       int64
	EvidenceDigest  string
}

// V2AudienceAssessment is a post-claim, post-status constraint outcome.
type V2AudienceAssessment struct {
	Status          string
	EvidenceDigests []string
	FreshUntil      int64
}

type v2AudienceConstraint struct {
	Type   ConstraintType `json:"type"`
	Params struct {
		ExactReceiverIDs        []string `json:"exact_receiver_ids"`
		TrustDomainIDs          []string `json:"trust_domain_ids"`
		MaxMembershipAgeSeconds int64    `json:"max_membership_age_seconds"`
	} `json:"params"`
}

// EvaluateReceiverAudienceV2 evaluates every deferred audience link. A valid
// nonmatching membership takes precedence over unavailable membership in
// another link. Only the verifier's authenticated expected receiver is used.
func EvaluateReceiverAudienceV2(deferred []V2DeferredConstraint, receiverID string, memberships []V2AudienceMembership, now, futureSkew int64) (_ V2AudienceAssessment, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if receiverID == "" || !validV2Timestamp(now) || futureSkew < 0 || futureSkew > V2MaxFutureSkewSeconds {
		return V2AudienceAssessment{}, fmt.Errorf("v2 audience requires a sealed receiver and valid security time")
	}
	type audienceLink struct {
		constraint      v2AudienceConstraint
		delegationIndex int
		constraintIndex int
	}
	constraints := make([]audienceLink, 0)
	seenLinks := make(map[[2]int]bool)
	maxAge := int64(maxSafeInteger)
	freshUntil := int64(maxSafeInteger)
	for _, item := range deferred {
		if item.Type != ConstraintReceiverAudience {
			continue
		}
		if err := validateV2ConstraintFields(item.CanonicalJSON); err != nil {
			return V2AudienceAssessment{}, fmt.Errorf("v2 sealed audience constraint is invalid: %w", err)
		}
		linkKey := [2]int{item.DelegationIndex, item.ConstraintIndex}
		if item.DelegationIndex < 0 || item.ConstraintIndex < 0 || seenLinks[linkKey] {
			return V2AudienceAssessment{}, fmt.Errorf("v2 audience constraint has duplicate or invalid position")
		}
		seenLinks[linkKey] = true
		var original ConstraintV2
		if err := json.Unmarshal(item.CanonicalJSON, &original); err != nil {
			return V2AudienceAssessment{}, fmt.Errorf("v2 audience constraint cannot be decoded: %w", err)
		}
		canonical, err := CanonicalJSON(original)
		if err != nil || !bytes.Equal(canonical, item.CanonicalJSON) {
			return V2AudienceAssessment{}, fmt.Errorf("v2 audience constraint is not canonical")
		}
		var constraint v2AudienceConstraint
		if err := json.Unmarshal(item.CanonicalJSON, &constraint); err != nil || constraint.Type != ConstraintReceiverAudience {
			return V2AudienceAssessment{}, fmt.Errorf("v2 sealed audience constraint has wrong type")
		}
		if len(constraint.Params.TrustDomainIDs) > 0 && (constraint.Params.MaxMembershipAgeSeconds <= 0 || constraint.Params.MaxMembershipAgeSeconds > V2MaxAudienceMembershipAgeSeconds) {
			return V2AudienceAssessment{}, fmt.Errorf("v2 audience membership age must be 1..%d seconds", V2MaxAudienceMembershipAgeSeconds)
		}
		if len(constraint.Params.TrustDomainIDs) > 0 && constraint.Params.MaxMembershipAgeSeconds < maxAge {
			maxAge = constraint.Params.MaxMembershipAgeSeconds
		}
		constraints = append(constraints, audienceLink{constraint, item.DelegationIndex, item.ConstraintIndex})
	}
	if len(constraints) == 0 {
		return V2AudienceAssessment{}, fmt.Errorf("v2 audience stage has no audience constraints")
	}
	denied, unavailable := false, false
	evidence := make([]string, 0)
	for _, link := range constraints {
		constraint := link.constraint
		if slices.Contains(constraint.Params.ExactReceiverIDs, receiverID) {
			continue
		}
		if len(constraint.Params.TrustDomainIDs) == 0 {
			return V2AudienceAssessment{}, fmt.Errorf("v2 exact-only audience mismatch passed preflight")
		}
		var membership *V2AudienceMembership
		for _, candidate := range memberships {
			if candidate.DelegationIndex == link.delegationIndex && candidate.ConstraintIndex == link.constraintIndex {
				if membership != nil {
					unavailable = true
					membership = nil
					break
				}
				copy := candidate
				membership = &copy
			}
		}
		if membership == nil {
			unavailable = true
			continue
		}
		if membership.ReceiverID != receiverID || !validPrefixedDigestV2(membership.EvidenceDigest) ||
			!validV2Timestamp(membership.IssuedAt) || !validV2Timestamp(membership.ExpiresAt) ||
			membership.IssuedAt >= membership.ExpiresAt || now >= membership.ExpiresAt ||
			(membership.IssuedAt > now && membership.IssuedAt-now > futureSkew) ||
			// Exclusive age deadline: current only while now < issued_at + max_age.
			(now >= membership.IssuedAt && now-membership.IssuedAt >= maxAge) {
			unavailable = true
			continue
		}
		seen := make(map[string]bool)
		match := false
		malformed := false
		for _, domainID := range membership.TrustDomainIDs {
			if domainID == "" || seen[domainID] {
				malformed = true
				break
			}
			seen[domainID] = true
			match = match || slices.Contains(constraint.Params.TrustDomainIDs, domainID)
		}
		if malformed {
			unavailable = true
			continue
		}
		evidence = append(evidence, membership.EvidenceDigest)
		if !match {
			denied = true
		} else {
			if membership.ExpiresAt < freshUntil {
				freshUntil = membership.ExpiresAt
			}
			ageUntil := membership.IssuedAt + maxAge
			if ageUntil < freshUntil {
				freshUntil = ageUntil
			}
		}
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)
	switch {
	case denied:
		return V2AudienceAssessment{Status: "constraint_denied", EvidenceDigests: evidence}, nil
	case unavailable:
		return V2AudienceAssessment{Status: "constraint_unverifiable", EvidenceDigests: evidence}, nil
	default:
		return V2AudienceAssessment{Status: "passed", EvidenceDigests: evidence, FreshUntil: freshUntil}, nil
	}
}
