package ratify

import "testing"

// SPEC-v2 §6.7: an interrupted evaluation reports each dimension
// independently from the persisted progress: completed checks keep their
// assessment (including untrusted), an interrupted lookup is unavailable, a
// status outcome is never dropped because context was pending, and stages not
// reached are not_evaluated. Every valid progress record must produce a valid
// receipt, and an invalid one is refused.
func TestInterruptedV2ReceiptFollowsPersistedProgress(t *testing.T) {
	digest := "sha384:" + hexRepeatV2Test('d', 96)
	claim := V2ChallengeClaim{ClaimID: "c", VerifierID: validV2TestID('a'), BundleHash: "sha384:" + hexRepeatV2Test('b', 96),
		IssuerIDs: []string{validV2TestID('c')}, RequiredScope: "data:read"}
	for _, tc := range []struct {
		name                   string
		trust, status, context string
		valid                  bool
	}{
		{"before trust", "not_evaluated", "not_evaluated", "not_evaluated", true},
		{"trust resolution interrupted", "unavailable", "not_evaluated", "not_evaluated", true},
		{"untrusted is retained", "untrusted", "not_evaluated", "not_evaluated", true},
		{"trusted, local stage interrupted", "trusted", "not_evaluated", "not_evaluated", true},
		{"status lookup interrupted", "trusted", "unavailable", "bound", true},
		{"status kept while context was pending", "trusted", "unavailable", "not_evaluated", true},
		{"context kept before status started", "trusted", "not_evaluated", "not_required", true},
		{"status without a trusted root", "unavailable", "unavailable", "not_evaluated", false},
		{"context without a trusted root", "untrusted", "not_evaluated", "bound", false},
		{"pending unbound context is never recorded", "trusted", "unavailable", "unbound", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			progress := V2EvaluationProgress{TrustAssessment: tc.trust, StatusAssessment: tc.status, ContextAssessment: tc.context, StatusEvidence: []StatusEvidenceEntryV2{}}
			if tc.context != "not_evaluated" {
				progress.ContextPolicyDigest = &digest
			}
			_, body, err := V2EvaluationInterruptedResult(claim, 15, progress)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid progress produced a receipt body")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			receipt := &VerificationReceiptV2{
				Version: 2, LogID: "0123456789abcdef0123456789abcdef", Sequence: 1, PreviousReceiptHash: make([]byte, 48),
				VerifierID: claim.VerifierID, BundleHash: claim.BundleHash, IssuerIDs: claim.IssuerIDs,
				Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified",
				TrustAssessment: tc.trust, StatusAssessment: tc.status, ChallengeAssessment: "current", ContextAssessment: tc.context,
				ContextPolicyDigest: progress.ContextPolicyDigest, VerifiedAt: 15,
				RequiredScope: "data:read", GrantedScope: []string{}, StatusEvidence: []StatusEvidenceEntryV2{},
			}
			want, err := VerificationReceiptV2Body(receipt)
			if err != nil || string(want) != string(body) {
				t.Fatalf("interrupted body mismatch: %v\n%s\n%s", err, want, body)
			}
		})
	}
}

func validV2TestID(c byte) string { return hexRepeatV2Test(c, 64) }

func hexRepeatV2Test(c byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = c
	}
	return string(out)
}
