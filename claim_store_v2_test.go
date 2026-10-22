package ratify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
)

type recordingClaimStoreV2 struct {
	claim                 V2ChallengeClaim
	disposition           V2ClaimDisposition
	claimedAt             *int64
	ownerToken            []byte
	ownerTokenSet         bool
	retryToken            []byte
	claimErrorAfterCreate bool
	calls                 int
	finalizeCalls         int
	finalizeToken         []byte
	finalized             bool
	finalizeDigest        [32]byte
	ambiguousFinalize     bool
	mutateFinalizeBuffers bool
}

func int64PtrV2Test(value int64) *int64 { return &value }

// AuthoritativeTimeV2 returns the scripted claim time (15 by default).
func (s *recordingClaimStoreV2) AuthoritativeTimeV2(context.Context) (int64, error) {
	if s.claimedAt != nil {
		return *s.claimedAt, nil
	}
	return 15, nil
}

func TestV2PreflightDoesNotRaceOnSharedIssuance(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	start := make(chan struct{})
	const workers = 32
	results := make(chan error, workers)
	for range workers {
		go func() {
			<-start
			_, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
			results <- err
		}()
	}
	close(start)
	for range workers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func (s *recordingClaimStoreV2) ClaimV2(_ context.Context, claim V2ChallengeClaim) (V2ClaimResult, error) {
	s.calls++
	s.claim = claim
	if s.claimErrorAfterCreate {
		s.claimErrorAfterCreate = false
		s.disposition = V2ClaimInProgress
		return V2ClaimResult{}, fmt.Errorf("simulated ambiguous response after claim commit")
	}
	claimedAt := claim.IssuedAt
	if s.claimedAt != nil {
		claimedAt = *s.claimedAt
	}
	ownerToken := s.retryToken
	if s.disposition == V2ClaimCreated {
		ownerToken = s.ownerToken
		if !s.ownerTokenSet {
			token := sha256.Sum256([]byte(claim.ClaimID))
			ownerToken = token[:]
		}
	}
	return V2ClaimResult{Disposition: s.disposition, ClaimedAt: claimedAt, OwnerToken: ownerToken}, nil
}

func TestClaimProofBundleV2AmbiguousCreateErrorRecoversWithoutOwnership(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated, claimErrorAfterCreate: true}
	if _, _, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15); err == nil || token != nil {
		t.Fatal("ambiguous create response did not fail without exposing evaluator ownership")
	}
	claim, disposition, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
	if err != nil || disposition != V2ClaimInProgress || token != nil || claim.ClaimID == "" {
		t.Fatalf("exact retry after ambiguous create did not fail closed without restoring lost ownership: claim=%+v disposition=%s token=%t err=%v", claim, disposition, token != nil, err)
	}
}

func TestEvaluateProofBundleV2LocalAuthorizationAllowsOneConcurrentEvaluator(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	_, _, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	opts := V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	}
	start := make(chan struct{})
	results := make(chan V2LocalAuthorizationAssessment, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- EvaluateProofBundleV2LocalAuthorization(bundle, opts)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var pending, rejected int
	for result := range results {
		switch result.Status {
		case "pending_external_checks":
			if result.LocalPolicyFailure == nil || result.LocalPolicyFailure.Status != "scope_denied" || len(result.StatusChecks) != len(bundle.Delegations) {
				t.Fatalf("scope denial did not remain pending with complete status work: %+v", result)
			}
			pending++
		case "evaluation_in_progress":
			rejected++
		default:
			t.Fatalf("unexpected concurrent evaluation result: %+v", result)
		}
	}
	if pending != 1 || rejected != 1 {
		t.Fatalf("single-use evaluator allowed %d evaluations and rejected %d duplicates", pending, rejected)
	}
	terminal := []byte(`{"decision":"deny","decision_reason":"scope_denied"}`)
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, terminal, terminal); err == nil || finalized || store.finalizeCalls != 0 {
		t.Fatalf("pending local denial finalized before status aggregation: finalized=%t err=%v", finalized, err)
	}
}

func (s *recordingClaimStoreV2) FinalizeV2Claim(_ context.Context, _ string, ownerToken, terminalResult, receiptBody []byte, _ int64) (bool, error) {
	s.finalizeCalls++
	s.finalizeToken = append([]byte(nil), ownerToken...)
	digest := v2FinalizationPayloadDigest(terminalResult, receiptBody)
	if s.finalized {
		if s.finalizeDigest != digest {
			return false, fmt.Errorf("different terminal payload")
		}
		return false, nil
	}
	s.finalized = true
	s.finalizeDigest = digest
	if s.mutateFinalizeBuffers {
		terminalResult[0] ^= 0xff
		receiptBody[0] ^= 0xff
	}
	if s.ambiguousFinalize {
		s.ambiguousFinalize = false
		return false, fmt.Errorf("simulated response loss after durable finalization")
	}
	return true, nil
}

func (*recordingClaimStoreV2) RecoverInterruptedV2Claim(context.Context, string, []byte, []byte) (bool, error) {
	return true, nil
}

func TestClaimProofBundleV2RevalidatesAndPassesSealedClaim(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	issuedToken := bytes.Repeat([]byte{0x6d}, 32)
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated, ownerToken: issuedToken}
	store.ownerTokenSet = true
	claim, disposition, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil || disposition != V2ClaimCreated || store.calls != 1 || claim.ClaimID == "" || claim.ClaimID != store.claim.ClaimID {
		t.Fatalf("claim store did not receive one stable claim: result=%+v disposition=%s calls=%d", claim, disposition, store.calls)
	}
	if claim.BundleHash != pre.state.BundleHash || claim.ProofDigest != claim.BundleHash || claim.RequiredScope != "data:read" || len(claim.IssuerIDs) != 1 {
		t.Fatalf("claim did not preserve sealed proof identity and scope: %+v", claim)
	}
	if len(claim.ChallengeDigest) != len("sha384:")+96 || claim.Namespace != "test" || claim.ReplayEpoch != 0 || claim.VerifierID != bundle.VerifierID || claim.AgentID != bundle.AgentID {
		t.Fatalf("claim omitted challenge replay binding: %+v", claim)
	}
	if _, err := FinalizeClaimProofBundleV2(context.Background(), store, token, []byte(`{"decision":"allow"}`), []byte(`{"decision":"allow"}`)); err == nil || store.finalizeCalls != 0 {
		t.Fatal("claim finalized before evaluation completed")
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if assessment.Status != "pending_external_checks" || assessment.LocalPolicyFailure == nil || assessment.LocalPolicyFailure.Status != "scope_denied" {
		t.Fatalf("expected local scope denial to remain pending status aggregation, got %+v", assessment)
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	deniedResult := []byte(`{"decision":"deny","decision_reason":"scope_denied"}`)
	deniedReceipt := []byte(`{"decision":"deny","decision_reason":"scope_denied"}`)
	if _, err := FinalizeClaimProofBundleV2(cancelledCtx, store, token, deniedResult, deniedReceipt); err == nil || store.finalizeCalls != 0 {
		t.Fatal("cancelled context consumed the evaluator finalization attempt")
	}
	if _, err := FinalizeClaimProofBundleV2(context.Background(), store, token, []byte(`{"decision":"allow","decision_reason":"authorized"}`), []byte(`{"decision":"allow","decision_reason":"authorized"}`)); err == nil || store.finalizeCalls != 0 {
		t.Fatal("claim finalized an allow that disagreed with the local scope denial")
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, deniedResult, deniedReceipt); err == nil || finalized {
		t.Fatalf("pending local denial was incorrectly finalized: finalized=%t err=%v", finalized, err)
	}
	if store.finalizeCalls != 0 {
		t.Fatalf("pending local denial reached durable finalization %d times", store.finalizeCalls)
	}
}

func TestFinalizeClaimProofBundleV2RejectsDuplicateJSONKeys(t *testing.T) {
	for _, input := range []string{
		`{"decision":"deny","decision":"allow","decision_reason":"scope_denied"}`,
		`{"decision":"deny","decision_reason":"scope_denied","metadata":{"source":"verified","source":"unverified"}}`,
	} {
		if terminalPayloadMatchesV2([]byte(input), []byte(input), "deny", "scope_denied") {
			t.Fatalf("finalization accepted duplicate JSON keys: %s", input)
		}
	}
	trailing := []byte(`{"decision":"deny","decision_reason":"scope_denied"} {}`)
	if terminalPayloadMatchesV2(trailing, trailing, "deny", "scope_denied") {
		t.Fatal("finalization accepted trailing JSON data")
	}
	invalidUTF8 := []byte("{\"decision\":\"deny\",\"decision_reason\":\"scope_denied\",\"metadata\":\"\xff\"}")
	if terminalPayloadMatchesV2(invalidUTF8, invalidUTF8, "deny", "scope_denied") {
		t.Fatal("finalization accepted invalid UTF-8 in a JSON string")
	}
}

func TestTerminalDecisionForV2EvaluationMatchesReceiptTable(t *testing.T) {
	tests := []struct {
		status, reason, decision string
	}{
		{"authorization_unverified", "evaluation_interrupted", "indeterminate"},
		{"authorization_unverified", "trust_unavailable", "indeterminate"},
		{"authorization_unverified", "action_context_unverified", "indeterminate"},
		{"authorization_unverified", "status_unavailable", "indeterminate"},
		{"authorization_unverified", "status_stale", "indeterminate"},
		{"authorized_agent", "authorized", "allow"},
		{"delegation_not_authorized", "not_delegated", "deny"},
		{"delegation_not_authorized", "delegation_not_authorized", "deny"},
		{"unauthorized", "unauthorized", "deny"},
		{"invalid", "proof_invalid", "deny"},
		{"expired", "delegation_expired", "deny"},
		{"invalid_scope", "invalid_scope", "deny"},
		{"scope_denied", "scope_denied", "deny"},
		{"constraint_denied", "constraint_denied", "deny"},
		{"constraint_unverifiable", "constraint_unverifiable", "deny"},
		{"constraint_unknown", "constraint_unknown", "deny"},
		{"revoked", "delegation_revoked", "deny"},
	}
	for _, tt := range tests {
		decision, ok := terminalDecisionForV2Evaluation(tt.status, tt.reason)
		if !ok || decision != tt.decision {
			t.Errorf("%s/%s = %s, %t; want %s", tt.status, tt.reason, decision, ok, tt.decision)
		}
	}
	for _, tt := range []struct{ status, reason string }{
		{"unauthorized", "authorized"},
		{"revoked", "status_unavailable"},
		{"authorization_unverified", "authorized"},
		{"scope_denied", ""},
		{"pending_external_checks", "external_checks_required"},
	} {
		if decision, ok := terminalDecisionForV2Evaluation(tt.status, tt.reason); ok {
			t.Errorf("accepted mismatched terminal tuple %s/%s as %s", tt.status, tt.reason, decision)
		}
	}
}

func TestCloneV2ChallengeClaimSeparatesMutableFields(t *testing.T) {
	sequence := int64(7)
	original := V2ChallengeClaim{IssuerIDs: []string{"issuer"}, StreamID: []byte("stream"), StreamSeq: &sequence}
	cloned := cloneV2ChallengeClaim(original)
	original.IssuerIDs[0] = "original-mutated"
	original.StreamID[0] = 'X'
	*original.StreamSeq = 8
	if cloned.IssuerIDs[0] != "issuer" || string(cloned.StreamID) != "stream" || *cloned.StreamSeq != 7 {
		t.Fatalf("clone retained shared caller memory: %+v", cloned)
	}
	cloned.IssuerIDs[0] = "clone-mutated"
	cloned.StreamID[0] = 'Y'
	*cloned.StreamSeq = 9
	if original.IssuerIDs[0] != "original-mutated" || string(original.StreamID) != "Xtream" || *original.StreamSeq != 8 {
		t.Fatalf("mutating clone changed source claim: %+v", original)
	}
}

func TestClaimProofBundleV2RejectsInvalidStoreOwnerCapabilities(t *testing.T) {
	for _, test := range []struct {
		name        string
		disposition V2ClaimDisposition
		ownerToken  []byte
	}{
		{name: "created without token", disposition: V2ClaimCreated},
		{name: "created with short token", disposition: V2ClaimCreated, ownerToken: []byte{1}},
		{name: "created with long token", disposition: V2ClaimCreated, ownerToken: bytes.Repeat([]byte{1}, 33)},
		{name: "retry exposes token", disposition: V2ClaimInProgress, ownerToken: bytes.Repeat([]byte{1}, 32)},
		{name: "terminal replay exposes token", disposition: V2ClaimTerminalReplay, ownerToken: bytes.Repeat([]byte{1}, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := signedV2TestBundle(t)
			policy := testUnboundContextPolicy(t)
			expected := testExpectedContextChallenge(t, bundle, policy)
			pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			store := &recordingClaimStoreV2{disposition: test.disposition}
			if test.disposition == V2ClaimCreated {
				store.ownerToken = test.ownerToken
				store.ownerTokenSet = true
			} else {
				store.retryToken = test.ownerToken
			}
			if _, _, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15); err == nil || token != nil {
				t.Fatalf("claim store capability contract violation was accepted: token=%t err=%v", token != nil, err)
			}
		})
	}
}

func TestFinalizeClaimProofBundleV2BlocksDeferredExternalChecks(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	_, _, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if assessment.Status != "pending_external_checks" {
		t.Fatalf("expected deferred status and rate checks, got %+v", assessment)
	}
	result := []byte(`{"decision":"allow","decision_reason":"authorized"}`)
	if _, err := FinalizeClaimProofBundleV2(context.Background(), store, token, result, result); err == nil || store.finalizeCalls != 0 {
		t.Fatal("terminal allow was committed before status and rate checks")
	}
}

func TestClaimProofBundleV2RejectsBeforeStoreOnBindingOrFreshnessFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ProofBundleV2, *ExpectedChallengeV2) (scope string, now int64)
	}{
		{name: "substituted proof", mutate: func(bundle *ProofBundleV2, _ *ExpectedChallengeV2) (string, int64) {
			bundle.ChallengeSig.Ed25519 = append([]byte(nil), bundle.ChallengeSig.Ed25519...)
			bundle.ChallengeSig.Ed25519[0] ^= 1
			return "data:read", 15
		}},
		{name: "expired at claim", mutate: func(_ *ProofBundleV2, _ *ExpectedChallengeV2) (string, int64) { return "data:read", 110 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := signedV2TestBundle(t)
			policy := testUnboundContextPolicy(t)
			expected := testExpectedContextChallenge(t, bundle, policy)
			pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, now := test.mutate(bundle, expected)
			store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
			if _, _, _, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, now); err == nil {
				t.Fatal("invalid proof state reached atomic claim store")
			}
			if store.calls != 0 {
				t.Fatalf("claim store called before binding/freshness rejection: %d", store.calls)
			}
		})
	}
}

func TestClaimProofBundleV2RetriesNeverReevaluate(t *testing.T) {
	for _, disposition := range []V2ClaimDisposition{V2ClaimInProgress, V2ClaimTerminalReplay} {
		t.Run(string(disposition), func(t *testing.T) {
			bundle := signedV2TestBundle(t)
			policy := testUnboundContextPolicy(t)
			expected := testExpectedContextChallenge(t, bundle, policy)
			pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			store := &recordingClaimStoreV2{disposition: disposition}
			_, gotDisposition, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
			if err != nil || gotDisposition != disposition || token != nil {
				t.Fatalf("retry disposition incorrectly acquired evaluation ownership: disposition=%s token=%t err=%v", gotDisposition, token != nil, err)
			}
			assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{RequiredScope: "data:read", ExpectedChallenge: expected})
			if assessment.Status != "preflight_binding_mismatch" || assessment.Reason != "claim_required" || len(assessment.StatusChecks) != 0 {
				t.Fatalf("retry launched a second local evaluation: %+v", assessment)
			}
		})
	}
}

func TestV2EvaluationTokenCannotStartASecondEvaluation(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, disposition, token, err := ClaimProofBundleV2(context.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, bundle, pre, "test", 0, 15)
	if err != nil || disposition != V2ClaimCreated || token == nil {
		t.Fatalf("new claim did not return its one evaluation token: disposition=%s token=%t err=%v", disposition, token != nil, err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	opts := V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	}
	copiedToken := *token
	first := EvaluateProofBundleV2LocalAuthorization(bundle, opts)
	if first.Status != "pending_external_checks" {
		t.Fatalf("first owner evaluation did not proceed: %+v", first)
	}
	opts.ClaimToken = &copiedToken
	second := EvaluateProofBundleV2LocalAuthorization(bundle, opts)
	if second.Status != "evaluation_in_progress" || second.Reason != "claim_in_progress" || len(second.StatusChecks) != 0 {
		t.Fatalf("reused token started or terminalized a second evaluation: %+v", second)
	}
}

func TestV2EvaluationTokenSealsClaimAgainstLaterPreflight(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, token, err := ClaimProofBundleV2(context.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	_, err = PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if assessment.Status != "pending_external_checks" || len(assessment.StatusChecks) != len(bundle.Delegations) || assessment.BundleHash != token.state.expected.BundleHash || token.state.expected.MaxAge != 10 {
		t.Fatalf("later preflight changed sealed claimed inputs: %+v", assessment)
	}
	retry := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if retry.Status != "evaluation_in_progress" || retry.Reason != "claim_in_progress" {
		t.Fatalf("claimed evaluation token produced a second outcome: %+v", retry)
	}
}

func TestV2EvaluationUsesAuthoritativeClaimTimeFloor(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, token, err := ClaimProofBundleV2(context.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated, claimedAt: int64PtrV2Test(15)}, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if assessment.Status != "pending_external_checks" || len(assessment.StatusChecks) != len(bundle.Delegations) || token.state.evaluatedAt != 15 {
		t.Fatalf("evaluation did not use the authoritative claim-time floor: %+v", assessment)
	}
}

func TestV2EvaluationUsesSealedChallengeWhenCallerOmitsIssuance(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, token, err := ClaimProofBundleV2(context.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	base := V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy, ClaimToken: token,
	}
	base.ExpectedChallenge = nil
	first := EvaluateProofBundleV2LocalAuthorization(bundle, base)
	if first.Status != "pending_external_checks" || len(first.StatusChecks) != len(bundle.Delegations) {
		t.Fatalf("sealed post-claim challenge state was not sufficient for evaluation: %+v", first)
	}
	base.ExpectedChallenge = expected
	second := EvaluateProofBundleV2LocalAuthorization(bundle, base)
	if second.Status != "evaluation_in_progress" || second.Reason != "claim_in_progress" {
		t.Fatalf("omitted caller issuance left token available for a second result: %+v", second)
	}
}

func TestV2EvaluationTokenBindsContextPolicyDigest(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	claimStore := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	claim, _, token, err := ClaimProofBundleV2(context.Background(), claimStore, bundle, pre, "test", 0, 15)
	if err != nil || token == nil || claim.ContextPolicyDigest != policy.digest {
		t.Fatalf("claim did not seal its context-policy digest: claim=%+v err=%v", claim, err)
	}
	otherPolicy, err := NewV2ContextPolicy("ratify.test.other-context/v1", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherExpected := testExpectedContextChallenge(t, bundle, otherPolicy)
	_, err = PreflightProofBundleV2(bundle, otherExpected, otherPolicy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: otherPolicy,
		ExpectedChallenge: otherExpected, ClaimToken: token,
	})
	if assessment.Status != "authorization_unverified" || assessment.Reason != "evaluation_interrupted" || assessment.BundleHash != claim.BundleHash {
		t.Fatalf("replacement context policy was evaluated for a claim made under another policy: %+v", assessment)
	}
	interrupted := []byte(`{"decision":"indeterminate","decision_reason":"evaluation_interrupted"}`)
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), claimStore, token, interrupted, interrupted); err != nil || !finalized {
		t.Fatalf("context-policy interruption could not be terminalized: finalized=%t err=%v", finalized, err)
	}
}

func TestAuthorizationAssessmentDoesNotExposeContextPolicyStorage(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "execute:tool", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	_, _, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatal(err)
	}
	otherPolicy, err := NewV2ContextPolicy("ratify.test.other-context/v1", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: otherPolicy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if assessment.Status != "authorization_unverified" || assessment.Reason != "evaluation_interrupted" || assessment.ContextPolicyDigest != nil || len(assessment.StatusChecks) != 0 {
		t.Fatalf("context-policy drift did not fail closed as an interrupted evaluation: %+v", assessment)
	}
	if pre.state.ContextPolicyDigest != policy.digest || token.state.expected.ContextPolicyDigest != policy.digest {
		t.Fatal("context-policy drift changed sealed preflight state")
	}
	interrupted := []byte(fmt.Sprintf(`{"decision":"indeterminate","decision_reason":%q}`, assessment.Reason))
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, interrupted, interrupted); err != nil || !finalized {
		t.Fatalf("interrupted context-policy evaluation could not be terminalized: finalized=%t err=%v", finalized, err)
	}
}

func TestClaimProofBundleV2UsesSealedFreshnessConfiguration(t *testing.T) {
	bundle := signedV2TestBundle(t)
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	if _, _, _, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.claim.MaxAgeSeconds != 10 {
		t.Fatalf("claim did not retain preflight freshness configuration: calls=%d max_age=%d", store.calls, store.claim.MaxAgeSeconds)
	}
}

func TestClaimProofBundleV2PreservesOwnerForInvalidStoreClaimTime(t *testing.T) {
	for _, claimedAt := range []int64{0, 21, 110, maxSafeInteger + 1} {
		t.Run(fmt.Sprint(claimedAt), func(t *testing.T) {
			bundle := signedV2TestBundle(t)
			policy := testUnboundContextPolicy(t)
			expected := testExpectedContextChallenge(t, bundle, policy)
			pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			store := &recordingClaimStoreV2{disposition: V2ClaimCreated, claimedAt: int64PtrV2Test(claimedAt)}
			_, _, token, err := ClaimProofBundleV2(context.Background(), store, bundle, pre, "test", 0, 15)
			if err != nil || token == nil || token.state.claimTimeValid {
				t.Fatalf("invalid authoritative time did not preserve a recovery owner: token=%t err=%v", token != nil, err)
			}
			root := bundle.Delegations[len(bundle.Delegations)-1]
			assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
				TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
				TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy,
				ExpectedChallenge: expected, ClaimToken: token,
			})
			if assessment.Reason != "evaluation_interrupted" {
				t.Fatalf("invalid authoritative time did not fail closed as interrupted: %+v", assessment)
			}
			allow := []byte(`{"decision":"allow","decision_reason":"authorized"}`)
			if _, err := FinalizeClaimProofBundleV2(context.Background(), store, token, allow, allow); err == nil || store.finalizeCalls != 0 {
				t.Fatal("invalid claim time capability finalized an allow")
			}
			interrupted := []byte(`{"decision":"indeterminate","decision_reason":"evaluation_interrupted"}`)
			if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, interrupted, interrupted); err != nil || !finalized {
				t.Fatalf("invalid claim time could not finalize as interrupted: finalized=%t err=%v", finalized, err)
			}
		})
	}
}
