package ratify

import (
	"bytes"
	"strings"
	"testing"
)

func audienceConstraintV2Test(t *testing.T, exact, domains []string, age int64) V2DeferredConstraint {
	t.Helper()
	exactValues := make([]any, len(exact))
	for i, value := range exact {
		exactValues[i] = value
	}
	domainValues := make([]any, len(domains))
	for i, value := range domains {
		domainValues[i] = value
	}
	params := map[string]any{"exact_receiver_ids": exactValues, "trust_domain_ids": domainValues}
	if len(domains) > 0 {
		params["max_membership_age_seconds"] = age
	}
	encoded, err := CanonicalJSON(ConstraintV2{Type: ConstraintReceiverAudience, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	return V2DeferredConstraint{Type: ConstraintReceiverAudience, CanonicalJSON: encoded}
}

func TestEvaluateReceiverAudienceV2IntersectsLinksAndUsesMinimumAge(t *testing.T) {
	first := audienceConstraintV2Test(t, []string{}, []string{"domain-a"}, 300)
	second := audienceConstraintV2Test(t, []string{}, []string{"domain-b"}, 30)
	second.DelegationIndex = 1
	digestA := "sha384:" + strings.Repeat("a", 96)
	digestB := "sha384:" + strings.Repeat("b", 96)
	memberships := []V2AudienceMembership{
		// Exclusive age deadline (SPEC-v2 §2.5): issued 71 with minimum age 30 is
		// current at 100 (100 < 101); issued 70 reaches the deadline exactly.
		{ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-a"}, IssuedAt: 71, ExpiresAt: 200, EvidenceDigest: digestA},
		{DelegationIndex: 1, ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-b"}, IssuedAt: 80, ExpiresAt: 200, EvidenceDigest: digestB},
	}
	got, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{first, second}, "receiver-1", memberships, 100, 0)
	if err != nil || got.Status != "passed" || len(got.EvidenceDigests) != 2 || got.EvidenceDigests[0] != digestA || got.EvidenceDigests[1] != digestB {
		t.Fatalf("minimum-age boundary rejected valid membership: %+v, %v", got, err)
	}
	memberships[0].IssuedAt = 70
	got, err = EvaluateReceiverAudienceV2([]V2DeferredConstraint{first, second}, "receiver-1", memberships, 100, 0)
	if err != nil || got.Status != "constraint_unverifiable" {
		t.Fatalf("membership at the exact minimum-age deadline was accepted: %+v, %v", got, err)
	}
}

func TestEvaluateReceiverAudienceV2DenialBeatsUnavailableInEitherOrder(t *testing.T) {
	unavailable := audienceConstraintV2Test(t, []string{}, []string{"domain-a"}, 30)
	denied := audienceConstraintV2Test(t, []string{}, []string{"domain-b"}, 30)
	denied.DelegationIndex = 1
	membership := V2AudienceMembership{DelegationIndex: 1, ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-c"}, IssuedAt: 90, ExpiresAt: 110, EvidenceDigest: "sha384:" + strings.Repeat("a", 96)}
	for _, constraints := range [][]V2DeferredConstraint{{unavailable, denied}, {denied, unavailable}} {
		got, err := EvaluateReceiverAudienceV2(constraints, "receiver-1", []V2AudienceMembership{membership}, 100, 0)
		if err != nil || got.Status != "constraint_denied" {
			t.Fatalf("valid nonmatch did not win over unavailable: %+v, %v", got, err)
		}
	}
}

func TestEvaluateReceiverAudienceV2RejectsUnboundOrStaleEvidence(t *testing.T) {
	constraint := audienceConstraintV2Test(t, []string{"receiver-2"}, []string{"domain-a"}, 30)
	base := V2AudienceMembership{ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-a"}, IssuedAt: 90, ExpiresAt: 110, EvidenceDigest: "sha384:" + strings.Repeat("a", 96)}
	tests := []struct {
		name string
		edit func(*V2AudienceMembership)
	}{
		{"wrong receiver", func(m *V2AudienceMembership) { m.ReceiverID = "receiver-2" }},
		{"expired", func(m *V2AudienceMembership) { m.ExpiresAt = 100 }},
		{"stale", func(m *V2AudienceMembership) { m.IssuedAt = 69 }},
		{"future", func(m *V2AudienceMembership) { m.IssuedAt = 102 }},
		{"missing digest", func(m *V2AudienceMembership) { m.EvidenceDigest = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			membership := base
			test.edit(&membership)
			for _, domains := range [][]string{{"domain-a"}, {"domain-z"}} {
				membership.TrustDomainIDs = domains
				got, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{constraint}, "receiver-1", []V2AudienceMembership{membership}, 100, 0)
				if err != nil || got.Status != "constraint_unverifiable" {
					t.Fatalf("unbound or stale evidence was accepted: %+v, %v", got, err)
				}
			}
		})
	}
	got, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{constraint}, "receiver-1", []V2AudienceMembership{base}, 100, 0)
	if err != nil || got.Status != "passed" {
		t.Fatalf("valid domain evidence was rejected: %+v, %v", got, err)
	}
}

func TestEvaluateReceiverAudienceV2RejectsAmbiguousOrMutatedInputs(t *testing.T) {
	constraint := audienceConstraintV2Test(t, nil, []string{"domain-a"}, 30)
	valid := V2AudienceMembership{ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-a"}, IssuedAt: 90, ExpiresAt: 110, EvidenceDigest: "sha384:" + strings.Repeat("a", 96)}
	for _, memberships := range [][]V2AudienceMembership{
		{valid, valid},
		{{ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-a", "domain-a"}, IssuedAt: 90, ExpiresAt: 110, EvidenceDigest: valid.EvidenceDigest}},
	} {
		got, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{constraint}, "receiver-1", memberships, 100, 0)
		if err != nil || got.Status != "constraint_unverifiable" {
			t.Fatalf("ambiguous membership was accepted: %+v, %v", got, err)
		}
	}
	if _, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{constraint, constraint}, "receiver-1", []V2AudienceMembership{valid}, 100, 0); err == nil {
		t.Fatal("duplicate deferred audience link was accepted")
	}
	caseVariant := constraint
	caseVariant.CanonicalJSON = bytes.Replace(caseVariant.CanonicalJSON, []byte("max_membership_age_seconds"), []byte("MAX_MEMBERSHIP_AGE_SECONDS"), 1)
	if _, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{caseVariant}, "receiver-1", []V2AudienceMembership{valid}, 100, 0); err == nil {
		t.Fatal("case-variant audience key was accepted")
	}
	wrongPosition := valid
	wrongPosition.ConstraintIndex = 1
	got, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{constraint}, "receiver-1", []V2AudienceMembership{wrongPosition}, 100, 0)
	if err != nil || got.Status != "constraint_unverifiable" {
		t.Fatalf("wrong-position membership was accepted: %+v, %v", got, err)
	}
}

// The audience stage evaluates at the sealed authoritative evaluation time
// (15), never at an earlier caller time: membership expiring at 15 is expired.
func TestResolveClaimProofBundleV2AfterAudienceUsesEvaluationTimeFloor(t *testing.T) {
	constraint := audienceConstraintV2Test(t, nil, []string{"domain-a"}, 30)
	state := &v2EvaluationTokenState{
		expected:  &expectedChallengeStateV2{ExpectedReceiverID: "receiver-1", BundleHash: "sealed", RequiredScope: "data:read"},
		claimedAt: 10, evaluatedAt: 15, evaluationStatus: "pending_external_checks",
		pendingAssessment: &V2LocalAuthorizationAssessment{
			BundleHash: "sealed", RequiredScope: "data:read", StatusAssessment: "current",
			Deferred: []V2DeferredConstraint{constraint},
		},
	}
	state.evaluationComplete.Store(true)
	token := &V2EvaluationToken{state: state}
	membership := V2AudienceMembership{ReceiverID: "receiver-1", TrustDomainIDs: []string{"domain-a"}, IssuedAt: 10, ExpiresAt: 15, EvidenceDigest: "sha384:" + strings.Repeat("a", 96)}
	if got, err := ResolveClaimProofBundleV2AfterAudience(token, []V2AudienceMembership{membership}); err != nil || got.Status != "constraint_unverifiable" {
		t.Fatalf("audience accepted evidence expired at the local evaluation time: %+v, %v", got, err)
	}
	if decision, ok := terminalDecisionForV2Evaluation(state.evaluationStatus, state.evaluationReason); !ok || decision != "deny" || state.pendingAssessment != nil {
		t.Fatalf("audience floor did not preserve a terminal denial: status=%s reason=%s pending=%v", state.evaluationStatus, state.evaluationReason, state.pendingAssessment)
	}
}

func TestEvaluateReceiverAudienceV2ExactMatchDoesNotNeedMembership(t *testing.T) {
	constraint := audienceConstraintV2Test(t, []string{"receiver-1"}, []string{"domain-a"}, 30)
	got, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{constraint}, "receiver-1", nil, 100, 0)
	if err != nil || got.Status != "passed" {
		t.Fatalf("exact audience was made dependent on domain lookup: %+v, %v", got, err)
	}
	invalid := audienceConstraintV2Test(t, []string{"receiver-2"}, []string{}, 0)
	if _, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{invalid}, "receiver-1", nil, 100, 0); err == nil {
		t.Fatal("post-claim exact-only mismatch did not signal broken preflight binding")
	}
	invalid.CanonicalJSON = bytes.Replace(invalid.CanonicalJSON, []byte("receiver-2"), []byte("receiver-2\",\"extra\":1"), 1)
	if _, err := EvaluateReceiverAudienceV2([]V2DeferredConstraint{invalid}, "receiver-1", nil, 100, 0); err == nil {
		t.Fatal("malformed sealed audience constraint was accepted")
	}
}
