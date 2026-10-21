package ratify

import (
	"bytes"
	stdcontext "context"
	"strings"
	"testing"
	"time"
)

const testV2ContextPolicyDigest = "sha384:610c40faa472aa2a4f905988899733758cccf30f243aed35f1f42433228a28dbab1725cb2a4a6811029a8109da0b9b29"

func testUnboundContextPolicy(t testing.TB) *V2ContextPolicy {
	t.Helper()
	policy, err := NewV2ContextPolicy("ratify.test.context/v1", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testBoundContextPolicy(t testing.TB, expected []byte) *V2ContextPolicy {
	t.Helper()
	policy, err := NewV2ContextPolicy(verifySessionContextProfileV2, true, verifySessionContextFieldsV2, expected)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testExpectedContextChallenge(t testing.TB, bundle *ProofBundleV2, policy *V2ContextPolicy) *ExpectedChallengeV2 {
	t.Helper()
	expected := &ExpectedChallengeV2{
		Value: bytes.Clone(bundle.Challenge), IssuedAt: bundle.ChallengeAt, ExpiresAt: bundle.ChallengeAt + 100,
		VerifierNamespace: "test", VerifierID: bundle.VerifierID,
		ContextPolicy: cloneV2ContextPolicy(policy),
	}
	if policy != nil && policy.requireBound {
		expected.ExpectedSessionContext = bytes.Clone(policy.expectedSessionContext)
	}
	return expected
}

func TestEvaluateProofBundleV2ContextPolicyOutcomes(t *testing.T) {
	want := bytes.Repeat([]byte{0x51}, 32)
	other := bytes.Repeat([]byte{0x52}, 32)
	bound := bytes.Clone(want)
	nullContext := []byte(nil)
	unbound := testUnboundContextPolicy(t)
	boundPolicy := testBoundContextPolicy(t, want)
	mismatchPolicy, err := NewV2ContextPolicy("ratify.test.session-context/v1", true, []string{"session"}, other)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name               string
		bundle             *ProofBundleV2
		policy             *V2ContextPolicy
		status, assessment string
		wantDigest         bool
	}{
		{name: "no policy and no context", bundle: &ProofBundleV2{}, status: "authorization_unverified", assessment: "unbound"},
		{name: "no policy with context", bundle: &ProofBundleV2{SessionContext: &bound}, status: "authorization_unverified", assessment: "unverified"},
		{name: "explicitly not required", bundle: &ProofBundleV2{}, policy: unbound, status: "passed", assessment: "not_required", wantDigest: true},
		{name: "required context matches", bundle: &ProofBundleV2{SessionContext: &bound}, policy: boundPolicy, status: "passed", assessment: "bound", wantDigest: true},
		{name: "required context mismatch", bundle: &ProofBundleV2{SessionContext: &bound}, policy: mismatchPolicy, status: "constraint_denied", assessment: "mismatch", wantDigest: true},
		{name: "required context absent", bundle: &ProofBundleV2{SessionContext: &nullContext}, policy: boundPolicy, status: "authorization_unverified", assessment: "unverified", wantDigest: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateProofBundleV2ContextPolicy(test.bundle, test.policy)
			if got.Status != test.status || got.Assessment != test.assessment || (got.PolicyDigest != nil) != test.wantDigest {
				t.Fatalf("context assessment = %+v", got)
			}
			if got.Status == "constraint_denied" && (got.Reason != "constraint_denied" || got.PolicyDigest == nil) {
				t.Fatalf("context mismatch lacks its terminal reason or policy digest: %+v", got)
			}
		})
	}
}

func TestZeroValueContextPolicyCannotPass(t *testing.T) {
	validPolicy := testUnboundContextPolicy(t)
	policy := cloneV2ContextPolicy(validPolicy)
	policy.valid = false
	got := EvaluateProofBundleV2ContextPolicy(&ProofBundleV2{}, policy)
	if got.Status != "authorization_unverified" || got.Reason != "action_context_unverified" || got.Assessment != "unbound" || got.PolicyDigest != nil {
		t.Fatalf("unvalidated policy with a well-formed digest was treated as configured: %+v", got)
	}
	if sameV2ContextPolicy(policy, validPolicy) {
		t.Fatal("unvalidated policy compared equal to a constructor-validated policy")
	}
	bundle := signedV2TestBundle(t)
	root := bundle.Delegations[0]
	authorization := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: testExpectedContextChallenge(t, bundle, validPolicy),
		ClaimToken:        testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, validPolicy), validPolicy, "execute:tool"),
	})
	if authorization.Status != "authorization_unverified" || authorization.Reason != "evaluation_interrupted" || len(authorization.StatusChecks) != 0 {
		t.Fatalf("local authorization trusted an invalid-but-well-formed context policy: %+v", authorization)
	}
}

func TestZeroValueContextPolicyRejectedByBothPreflightPaths(t *testing.T) {
	bundle, _, _, _, agentPriv := signedV2DelegationChainTest(t, true)
	context := bytes.Repeat([]byte{0x21}, 32)
	bundle.SessionContext = &context
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	leaf := bundle.Delegations[0]
	validPolicy := testBoundContextPolicy(t, context)
	base := ExpectedChallengeV2{
		Value: bundle.Challenge, IssuedAt: bundle.ChallengeAt, ExpiresAt: 30,
		VerifierNamespace: "test", VerifierID: bundle.VerifierID,
		ExpectedAgentID: bundle.AgentID, ExpectedAgentPublicKey: &leaf.SubjectPubKey,
		ExpectedSessionContext: bytes.Clone(context),
	}
	verifyExpected := base
	if _, err := PreflightProofBundleV2(bundle, &verifyExpected, validPolicy, "data:read", "test", 0, 15, 10, 0); err != nil {
		t.Fatalf("valid Verify policy failed its preflight control: %v", err)
	}
	genericExpected := base
	genericExpected.ContextPolicy = cloneV2ContextPolicy(validPolicy)
	if err := ValidateProofBundleV2Preflight(bundle, genericExpected, "data:read", "test", 0, 15, 10, 0); err != nil {
		t.Fatalf("valid carried policy failed its generic preflight control: %v", err)
	}
	invalidPolicy := cloneV2ContextPolicy(validPolicy)
	invalidPolicy.valid = false
	invalidVerifyExpected := base
	if _, err := PreflightProofBundleV2(bundle, &invalidVerifyExpected, invalidPolicy, "data:read", "test", 0, 15, 10, 0); err == nil || !strings.Contains(err.Error(), "missing or invalid") {
		t.Fatal("Verify preflight accepted an otherwise valid policy with valid=false")
	}
	if invalidVerifyExpected.ContextPolicy != nil {
		t.Fatal("failed preflight mutated expected challenge")
	}
	invalidGenericExpected := base
	invalidGenericExpected.ContextPolicy = cloneV2ContextPolicy(invalidPolicy)
	if err := ValidateProofBundleV2Preflight(bundle, invalidGenericExpected, "data:read", "test", 0, 15, 10, 0); err == nil || !strings.Contains(err.Error(), "expected context policy is invalid") {
		t.Fatal("generic preflight accepted an otherwise valid carried policy with valid=false")
	}
}

func TestLocalAuthorizationEvaluatesContextBeforeConstraints(t *testing.T) {
	bundle, rootKey, _, midPriv, agentPriv := signedV2DelegationChainTest(t, true)
	policyContext := bytes.Repeat([]byte{0x61}, 32)
	bundle.SessionContext = &policyContext
	leaf := &bundle.Delegations[0]
	leaf.Constraints = []ConstraintV2{{Type: "future_constraint", Params: map[string]any{}}}
	leafBytes, err := certSignableBytesV2(leaf)
	if err != nil {
		t.Fatal(err)
	}
	leaf.Signature, err = signV2Statement(v2DelegationCertificate, leafBytes, midPriv)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DelegationDigest, err = delegationDigestV2(bundle.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	contextPolicy := testBoundContextPolicy(t, policyContext)
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: bundle.Delegations[1].IssuerID,
		TrustedRootKey: rootKey, TrustConfigured: true, RequiredScope: "data:read",
		ContextPolicy:     contextPolicy,
		ExpectedChallenge: testExpectedContextChallenge(t, bundle, contextPolicy),
		ClaimToken:        testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, contextPolicy), contextPolicy, "data:read"),
	})
	if assessment.Status != "pending_external_checks" || assessment.LocalPolicyFailure == nil || assessment.LocalPolicyFailure.Status != "constraint_unknown" || assessment.ContextAssessment != "bound" || assessment.ContextPolicyDigest == nil || *assessment.ContextPolicyDigest != testV2ContextPolicyDigest {
		t.Fatalf("local authorization did not preserve completed context before constraint failure: %+v", assessment)
	}
}

func TestLocalAuthorizationUsesSealedPreflightPolicyWhenOptionOmitted(t *testing.T) {
	bundle := signedV2TestBundle(t)
	root := bundle.Delegations[len(bundle.Delegations)-1]
	policy := testUnboundContextPolicy(t)
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken: testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "execute:tool"),
	})
	if assessment.Status != "pending_external_checks" || assessment.ContextAssessment != "not_required" || assessment.ContextPolicyDigest == nil || len(assessment.StatusChecks) != len(bundle.Delegations) {
		t.Fatalf("local authorization did not use the policy sealed by preflight: %+v", assessment)
	}
}

func TestVerifyContextPolicyDigestAndPreclaimMismatch(t *testing.T) {
	policy, err := NewV2ContextPolicy(verifySessionContextProfileV2, true, verifySessionContextFieldsV2, bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if policy.digest != testV2ContextPolicyDigest {
		t.Fatalf("Verify policy digest = %q, want canonical digest %q", policy.digest, testV2ContextPolicyDigest)
	}
	bundle, rootKey, _, _, agentPriv := signedV2DelegationChainTest(t, true)
	context := bytes.Repeat([]byte{0x11}, 32)
	bundle.SessionContext = &context
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	leaf := bundle.Delegations[0]
	expectedContext := bytes.Repeat([]byte{0x12}, 32)
	verifyPolicy := testBoundContextPolicy(t, expectedContext)
	expected := ExpectedChallengeV2{
		Value: bundle.Challenge, IssuedAt: bundle.ChallengeAt, ExpiresAt: 30,
		VerifierNamespace: "test", ReplayEpoch: 0, VerifierID: bundle.VerifierID,
		ExpectedAgentID: bundle.AgentID, ExpectedAgentPublicKey: &leaf.SubjectPubKey,
		ExpectedSessionContext: expectedContext,
	}
	positive := *bundle
	positiveContext := bytes.Clone(expectedContext)
	positive.SessionContext = &positiveContext
	positivePresentation, err := presentationSignableBytesV2(&positive)
	if err != nil {
		t.Fatal(err)
	}
	positive.ChallengeSig, err = signV2Statement(v2ChallengePresentation, positivePresentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := PreflightProofBundleV2(&positive, &expected, verifyPolicy, "data:read", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatalf("matching Verify session context failed preflight: %v", err)
	}
	if expected.ContextPolicy != nil || !sameV2ContextPolicy(pre.state.ContextPolicy, verifyPolicy) {
		t.Fatal("successful preflight did not seal the policy without mutating issuance state")
	}
	_, disposition, claimToken, claimErr := ClaimProofBundleV2(stdcontext.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, &positive, pre, "test", 0, 15)
	if claimErr != nil || disposition != V2ClaimCreated {
		t.Fatalf("successful preflight did not atomically claim before authorization: disposition=%s err=%v", disposition, claimErr)
	}
	root := positive.Delegations[len(positive.Delegations)-1]
	postClaim := EvaluateProofBundleV2LocalAuthorization(&positive, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: verifyPolicy, ExpectedChallenge: &expected,
		ClaimToken: claimToken,
	})
	if postClaim.Status != "pending_external_checks" || postClaim.ContextAssessment != "bound" || len(postClaim.StatusChecks) != len(positive.Delegations) {
		t.Fatalf("successful preflight policy did not carry safely into post-claim authorization: %+v", postClaim)
	}
	mutatedIssuance := expected
	mutatedIssuance.Value = bytes.Repeat([]byte{0x24}, 32)
	issuanceMismatch := EvaluateProofBundleV2LocalAuthorization(&positive, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: verifyPolicy, ExpectedChallenge: &mutatedIssuance,
		ClaimToken: testTokenFromPreflightV2(t, pre),
	})
	if issuanceMismatch.Status != "authorization_unverified" || issuanceMismatch.Reason != "evaluation_interrupted" || issuanceMismatch.ContextAssessment != "not_evaluated" || len(issuanceMismatch.StatusChecks) != 0 {
		t.Fatalf("mutating authenticated challenge issuance after claim did not yield a terminal-safe assessment: %+v", issuanceMismatch)
	}
	otherBundle := positive
	otherBundle.Challenge = bytes.Repeat([]byte{0x23}, 32)
	otherPresentation, err := presentationSignableBytesV2(&otherBundle)
	if err != nil {
		t.Fatal(err)
	}
	otherBundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, otherPresentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	otherAuthorization := EvaluateProofBundleV2LocalAuthorization(&otherBundle, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: verifyPolicy, ExpectedChallenge: &expected,
		ClaimToken: testTokenFromPreflightV2(t, pre),
	})
	if otherAuthorization.Status != "authorization_unverified" || otherAuthorization.Reason != "evaluation_interrupted" || otherAuthorization.ContextAssessment != "not_evaluated" || len(otherAuthorization.StatusChecks) != 0 {
		t.Fatalf("preflight state for one proof authorized a different proof bundle: %+v", otherAuthorization)
	}
	unboundPolicy := testUnboundContextPolicy(t)
	downgradedExpected := expected
	downgradedExpected.ContextPolicy = unboundPolicy
	downgrade := EvaluateProofBundleV2LocalAuthorization(&positive, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: unboundPolicy, ExpectedChallenge: &downgradedExpected,
		ClaimToken: testTokenFromPreflightV2(t, pre),
	})
	if downgrade.Status != "authorization_unverified" || downgrade.Reason != "evaluation_interrupted" || len(downgrade.StatusChecks) != 0 {
		t.Fatalf("mutating the exposed challenge policy downgraded a successfully preflighted Verify decision: %+v", downgrade)
	}
	originalVerifyPolicy := cloneV2ContextPolicy(verifyPolicy)
	*verifyPolicy = *unboundPolicy
	mutatedSource := EvaluateProofBundleV2LocalAuthorization(&positive, V2LocalAuthorizationOptions{
		Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: verifyPolicy, ExpectedChallenge: &expected,
		ClaimToken: testTokenFromPreflightV2(t, pre),
	})
	if mutatedSource.Status != "authorization_unverified" || mutatedSource.Reason != "evaluation_interrupted" || len(mutatedSource.StatusChecks) != 0 {
		t.Fatalf("mutating the caller-owned policy after preflight downgraded authorization: %+v", mutatedSource)
	}
	*verifyPolicy = *originalVerifyPolicy
	issuedWithDifferentPolicy := expected
	issuedWithDifferentPolicy.ContextPolicy = testBoundContextPolicy(t, bytes.Repeat([]byte{0x14}, 32))
	if _, err := PreflightProofBundleV2(&positive, &issuedWithDifferentPolicy, verifyPolicy, "data:read", "test", 0, 15, 10, 0); err == nil || !bytes.Contains([]byte(err.Error()), []byte("does not match the issued policy")) {
		t.Fatal("Verify preflight replaced a different policy from authenticated issuance state")
	}
	if _, err := PreflightProofBundleV2(bundle, &expected, verifyPolicy, "data:read", "test", 0, 15, 10, 0); err == nil || !bytes.Contains([]byte(err.Error()), []byte("expected session context")) {
		t.Fatal("Verify expected-session mismatch passed preflight and could be claimed")
	}
	if _, err := PreflightProofBundleV2(&positive, &expected, nil, "data:read", "test", 0, 15, 10, 0); err == nil {
		t.Fatal("preflight accepted a missing context policy")
	}
	divergent := expected
	divergent.ExpectedSessionContext = bytes.Repeat([]byte{0x13}, 32)
	divergentProof := positive
	divergentProofContext := bytes.Clone(divergent.ExpectedSessionContext)
	divergentProof.SessionContext = &divergentProofContext
	divergentPresentation, err := presentationSignableBytesV2(&divergentProof)
	if err != nil {
		t.Fatal(err)
	}
	divergentProof.ChallengeSig, err = signV2Statement(v2ChallengePresentation, divergentPresentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightProofBundleV2(&divergentProof, &divergent, verifyPolicy, "data:read", "test", 0, 15, 10, 0); err == nil || !bytes.Contains([]byte(err.Error()), []byte("challenge context does not match")) {
		t.Fatal("preflight accepted challenge context that diverged from the configured policy")
	}
	freshExpected := expected
	freshExpected.ContextPolicy = nil
	if _, err := PreflightProofBundleV2(&divergentProof, &freshExpected, verifyPolicy, "data:read", "test", 0, 15, 10, 0); err == nil || freshExpected.ContextPolicy != nil {
		t.Fatal("failed preflight mutated issuance state with an unvalidated context policy")
	}
	for _, fields := range [][]string{nil, append(append([]string(nil), verifySessionContextFieldsV2...), "unbound_override")} {
		if _, err := NewV2ContextPolicy(verifySessionContextProfileV2, false, fields, nil); err == nil {
			t.Fatalf("accepted invalid Verify context policy fields %v", fields)
		}
	}
	if _, err := NewV2ContextPolicy("", false, nil, nil); err == nil {
		t.Fatal("accepted empty context policy profile")
	}
}

func TestVerifyAuthorizationRequiresExactPreflightPolicy(t *testing.T) {
	bundle, rootKey, _, _, agentPriv := signedV2DelegationChainTest(t, true)
	root := bundle.Delegations[len(bundle.Delegations)-1]
	context := bytes.Repeat([]byte{0x61}, 32)
	bundle.SessionContext = &context
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	verifyPolicy := testBoundContextPolicy(t, context)
	unboundPolicy := testUnboundContextPolicy(t)
	leaf := bundle.Delegations[0]
	expected := &ExpectedChallengeV2{
		Value: bundle.Challenge, IssuedAt: bundle.ChallengeAt, ExpiresAt: 30,
		VerifierNamespace: "test", VerifierID: bundle.VerifierID,
		ExpectedAgentID: bundle.AgentID, ExpectedAgentPublicKey: &leaf.SubjectPubKey,
		ExpectedSessionContext: bytes.Clone(context),
	}
	pre, err := PreflightProofBundleV2(bundle, expected, verifyPolicy, "data:read", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatalf("setup Verify preflight failed: %v", err)
	}
	if _, _, _, err := ClaimProofBundleV2(stdcontext.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, bundle, pre, "test", 0, 15); err != nil {
		t.Fatalf("setup Verify claim failed: %v", err)
	}
	divergentExpected := *expected
	divergentExpected.ContextPolicy = testBoundContextPolicy(t, bytes.Repeat([]byte{0x62}, 32))
	downgradedExpected := *expected
	downgradedExpected.ContextPolicy = unboundPolicy
	cases := []struct {
		name     string
		policy   *V2ContextPolicy
		expected *ExpectedChallengeV2
	}{
		{name: "divergent policy", policy: verifyPolicy, expected: &divergentExpected},
		{name: "unbound downgrade", policy: unboundPolicy, expected: &downgradedExpected},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
				Now: time.Unix(15, 0), TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
				TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: test.policy, ExpectedChallenge: test.expected,
				ClaimToken: testTokenFromPreflightV2(t, pre),
			})
			if got.Status != "authorization_unverified" || got.Reason != "evaluation_interrupted" || got.ContextAssessment != "not_evaluated" || len(got.StatusChecks) != 0 {
				t.Fatalf("authorization did not fail closed on context policy drift: %+v", got)
			}
		})
	}
}

func TestInvalidOrMismatchedFutureSkewInterruptsPostClaimEvaluation(t *testing.T) {
	bundle, _, _, midPriv, agentPriv := signedV2DelegationChainTest(t, true)
	policy := testUnboundContextPolicy(t)
	leaf := &bundle.Delegations[0]
	leaf.IssuedAt = 16
	leafBytes, err := certSignableBytesV2(leaf)
	if err != nil {
		t.Fatal(err)
	}
	leaf.Signature, err = signV2Statement(v2DelegationCertificate, leafBytes, midPriv)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DelegationDigest, err = delegationDigestV2(bundle.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	expected := &ExpectedChallengeV2{Value: bundle.Challenge, IssuedAt: bundle.ChallengeAt, ExpiresAt: 30, VerifierNamespace: "test", VerifierID: bundle.VerifierID}
	if _, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, -1); err == nil || expected.ContextPolicy != nil {
		t.Fatal("preflight accepted invalid verifier freshness configuration or sealed it as validated")
	}
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatalf("valid zero-skew preflight failed: %v", err)
	}
	if _, _, _, err := ClaimProofBundleV2(stdcontext.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, bundle, pre, "test", 0, 15); err != nil {
		t.Fatalf("valid preflight failed to claim: %v", err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	for _, skew := range []time.Duration{-time.Second, 10 * time.Second} {
		got := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
			Now: time.Unix(15, 0), FutureSkew: skew, TrustedRootID: root.IssuerID,
			TrustedRootKey: root.IssuerPubKey, TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy,
			ExpectedChallenge: expected,
			ClaimToken:        testTokenFromPreflightV2(t, pre),
		})
		if got.Status != "authorization_unverified" || got.Reason != "evaluation_interrupted" || got.ContextAssessment != "not_evaluated" {
			t.Fatalf("unmatched verifier skew did not produce an interrupted terminal assessment: skew=%s result=%+v", skew, got)
		}
	}
	withoutPreflight := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{FutureSkew: -time.Second})
	if withoutPreflight.Status != "preflight_binding_mismatch" || withoutPreflight.Reason != "claim_required" {
		t.Fatalf("missing preflight state was not rejected before claim: %+v", withoutPreflight)
	}
}
