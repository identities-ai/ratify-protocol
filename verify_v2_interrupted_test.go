package ratify

import "testing"

// SPEC-v2 §6.7: an interrupted evaluation keeps completed checks, marks an
// interrupted status lookup unavailable, and marks stages not reached
// not_evaluated. Every tuple produced here must also be a valid receipt.
func TestInterruptedV2AssessmentsFollowStageProgress(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		trust, status, context       string
		wantTrust, wantStatus, wantC string
	}{
		{"before trust", "not_evaluated", "not_evaluated", "not_evaluated", "not_evaluated", "not_evaluated", "not_evaluated"},
		{"trust unavailable", "unavailable", "not_evaluated", "bound", "unavailable", "not_evaluated", "not_evaluated"},
		{"untrusted is not an interruptible state", "untrusted", "not_evaluated", "bound", "not_evaluated", "not_evaluated", "not_evaluated"},
		{"trusted, local stage interrupted", "trusted", "not_evaluated", "not_evaluated", "trusted", "not_evaluated", "not_evaluated"},
		{"status lookup interrupted", "trusted", "unavailable", "bound", "trusted", "unavailable", "bound"},
		{"audience or rate interrupted", "trusted", "current", "not_required", "trusted", "current", "not_required"},
		{"pending unbound context is not recorded", "trusted", "current", "unbound", "trusted", "not_evaluated", "not_evaluated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust, status, context := interruptedV2Assessments(v2EvaluationProgress{trust: tc.trust, status: tc.status}, tc.context, "ignored")
			if trust != tc.wantTrust || status != tc.wantStatus || context != tc.wantC {
				t.Fatalf("got %s/%s/%s, want %s/%s/%s", trust, status, context, tc.wantTrust, tc.wantStatus, tc.wantC)
			}
			receipt := &VerificationReceiptV2{
				Version: 2, LogID: "0123456789abcdef0123456789abcdef", Sequence: 1, PreviousReceiptHash: make([]byte, 48),
				VerifierID: validV2TestID('a'), BundleHash: "sha384:" + hexRepeatV2Test('b', 96), IssuerIDs: []string{validV2TestID('c')},
				Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified",
				TrustAssessment: trust, StatusAssessment: status, ChallengeAssessment: "current", ContextAssessment: context,
				RequiredScope: "data:read", GrantedScope: []string{}, StatusEvidence: []StatusEvidenceEntryV2{},
			}
			if context == "bound" || context == "not_required" {
				digest := "sha384:" + hexRepeatV2Test('d', 96)
				receipt.ContextPolicyDigest = &digest
			}
			if status == "current" {
				return // a current status additionally requires accepted evidence, covered by vectors
			}
			if err := validateVerificationReceiptV2(receipt, false); err != nil {
				t.Fatalf("interrupted tuple is not a valid receipt: %v", err)
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
