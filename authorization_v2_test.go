package ratify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLocalTimeWindowValidUntilV2(t *testing.T) {
	for _, tc := range []struct {
		name, start, end, zone, now, until string
	}{
		{"inclusive end minute", "10:00", "10:30", "UTC", "2026-10-13T10:30:45Z", "2026-10-13T10:31:00Z"},
		{"wraps midnight", "23:00", "01:00", "UTC", "2026-10-13T23:30:00Z", "2026-10-14T01:01:00Z"},
		{"DST transition closes evidence", "01:30", "03:30", "America/New_York", "2026-03-08T06:45:00Z", "2026-03-08T07:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			want, err := time.Parse(time.RFC3339, tc.until)
			if err != nil {
				t.Fatal(err)
			}
			bundle := &ProofBundleV2{Delegations: []DelegationCertV2{{Constraints: []ConstraintV2{{Type: ConstraintTimeWindow, Start: tc.start, End: tc.end, TZ: tc.zone}}}}}
			got, err := localTimeWindowValidUntilV2(bundle, TZDBVersionV2, now)
			if err != nil || got != want.Unix() {
				t.Fatalf("terminal horizon=%d want=%d err=%v", got, want.Unix(), err)
			}
		})
	}
}

func TestAllowHorizonV2UsesEarliestPassingEvidence(t *testing.T) {
	assessment := V2LocalAuthorizationAssessment{
		DelegationValidUntil: 150,
		StatusFreshUntil:     130,
		AudienceFreshUntil:   120,
		LocalTimeValidUntil:  110,
	}
	if got := allowHorizonV2(assessment); got != 110 {
		t.Fatalf("allow horizon=%d, want earliest local time window expiry", got)
	}
	assessment.LocalTimeValidUntil = 0
	if got := allowHorizonV2(assessment); got != 120 {
		t.Fatalf("allow horizon=%d, want earliest audience membership expiry", got)
	}
	assessment.AudienceFreshUntil = 0
	if got := allowHorizonV2(assessment); got != 130 {
		t.Fatalf("allow horizon=%d, want authenticated status freshness expiry", got)
	}
}

type recordingV2RateStore struct {
	calls int
	batch []V2RateReservation
	err   error
}

func (s *recordingV2RateStore) ReserveV2RateBatch(_ context.Context, _ string, _ []byte, _ string, batch []V2RateReservation) error {
	s.calls++
	s.batch = append([]V2RateReservation{}, batch...)
	return s.err
}

type recordingV2AtomicRateStore struct {
	recordingClaimStoreV2
	reserveCalls int
	nextError    error
}

func (*recordingV2AtomicRateStore) AdmitsV2RateAtFinalization() {}

func (s *recordingV2AtomicRateStore) ReserveV2RateBatch(context.Context, string, []byte, string, []V2RateReservation) error {
	s.reserveCalls++
	return fmt.Errorf("rate reservation ran before atomic finalization")
}

func (s *recordingV2AtomicRateStore) FinalizeV2Claim(ctx context.Context, claimID string, ownerToken, terminalResult, receiptBody []byte, allowValidUntil int64) (bool, error) {
	if s.nextError != nil {
		err := s.nextError
		s.nextError = nil
		return false, err
	}
	return s.recordingClaimStoreV2.FinalizeV2Claim(ctx, claimID, ownerToken, terminalResult, receiptBody, allowValidUntil)
}

func testEvaluationTokenForTest(t testing.TB, bundle *ProofBundleV2, expected *ExpectedChallengeV2, policy *V2ContextPolicy, scope string) *V2EvaluationToken {
	t.Helper()
	preflight, err := PreflightProofBundleV2(bundle, expected, policy, scope, "test", 0, 15, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	return testTokenFromPreflightV2(t, preflight)
}

func testTokenFromPreflightV2(t testing.TB, preflight *V2PreflightResult) *V2EvaluationToken {
	t.Helper()
	state := preflight.state
	claimID, err := ProtocolClaimIDV2(state.VerifierNamespace, state.ReplayEpoch, state.Value)
	if err != nil {
		t.Fatal(err)
	}
	return &V2EvaluationToken{state: &v2EvaluationTokenState{
		claimID: claimID, proofDigest: state.BundleHash,
		requiredScope:  state.RequiredScope,
		futureSkew:     state.FutureSkew,
		ownerToken:     make([]byte, 32),
		claimedAt:      15, // authoritative claim time used for evaluation
		claimTimeValid: true,
		expected:       cloneExpectedChallengeStateV2(state),
	}}
}

func TestEvaluateProofBundleV2LocalAuthorizationRequiresConfiguredTrustedRoot(t *testing.T) {
	bundle := signedV2TestBundle(t)
	root := bundle.Delegations[len(bundle.Delegations)-1]
	policy := testUnboundContextPolicy(t)
	base := V2LocalAuthorizationOptions{
		TrustedRootID:     root.IssuerID,
		TrustedRootKey:    root.IssuerPubKey,
		TrustConfigured:   true,
		RequiredScope:     "execute:tool",
		ContextPolicy:     policy,
		ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken:        testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "execute:tool"),
	}

	got := EvaluateProofBundleV2LocalAuthorization(bundle, base)
	if got.Status != "pending_external_checks" || got.AgentID != bundle.AgentID || got.RootID != root.IssuerID {
		t.Fatalf("valid local checks not reported as pending external checks: %+v", got)
	}
	if got.Reason != "external_checks_required" || len(got.StatusChecks) != len(bundle.Delegations) || !bytes.Equal(got.DelegationDigest, bundle.DelegationDigest) {
		t.Fatalf("pending result omitted stable reason or required status-check bindings: %+v", got)
	}
	if len(got.EffectiveScope) != 1 || got.EffectiveScope[0] != "execute:tool" {
		t.Fatalf("unexpected effective scope: %v", got.EffectiveScope)
	}

	base.TrustConfigured = false
	base.ClaimToken = testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "execute:tool")
	got = EvaluateProofBundleV2LocalAuthorization(bundle, base)
	if got.Status != "authorization_unverified" || got.Reason != "trust_unavailable" || got.Detail != "caller-authenticated trust configuration is unavailable" {
		t.Fatalf("missing trust configuration did not fail closed: %+v", got)
	}

	base.TrustConfigured = true
	base.TrustedRootID = strings.Repeat("0", 64)
	base.ClaimToken = testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "execute:tool")
	got = EvaluateProofBundleV2LocalAuthorization(bundle, base)
	if got.Status != "unauthorized" || got.Reason != "unauthorized" || got.Detail != "delegation chain does not terminate at the configured trust root" {
		t.Fatalf("untrusted root did not fail closed: %+v", got)
	}
}

func TestV2ConstraintErrorClassificationSurvivesWrapping(t *testing.T) {
	wrappedUnverifiable := errors.Join(errors.New("outer context"), errConstraintUnverifiable("missing action data"))
	if !errors.Is(wrappedUnverifiable, ErrConstraintUnverifiable) {
		t.Fatal("wrapped unverifiable constraint lost its stable error identity")
	}
	wrappedUnknown := errors.Join(errors.New("outer context"), unknownConstraintError{kind: "future_constraint"})
	if !isUnknownV2Constraint(wrappedUnknown) {
		t.Fatal("wrapped unknown constraint lost its stable error identity")
	}
}

func signedV2DelegationChainTest(t testing.TB, parentMayDelegate bool) (*ProofBundleV2, HybridPublicKey, HybridPrivateKey, HybridPrivateKey, HybridPrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	midPub, midPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := keyIDV2(rootPub)
	midID, _ := keyIDV2(midPub)
	agentID, _ := keyIDV2(agentPub)
	parentScope := []string{"data:read"}
	if parentMayDelegate {
		parentScope = append(parentScope, ScopeIdentityDelegate)
	}
	rootCert := DelegationCertV2{Version: 2, CertID: "root-cert", IssuerID: rootID, IssuerPubKey: rootPub, SubjectID: midID, SubjectPubKey: midPub, Scope: parentScope, Constraints: []ConstraintV2{}, IssuedAt: 10, ExpiresAt: 30}
	rootBytes, err := certSignableBytesV2(&rootCert)
	if err != nil {
		t.Fatal(err)
	}
	rootCert.Signature, err = signV2Statement(v2DelegationCertificate, rootBytes, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	leafCert := DelegationCertV2{Version: 2, CertID: "leaf-cert", IssuerID: midID, IssuerPubKey: midPub, SubjectID: agentID, SubjectPubKey: agentPub, Scope: []string{"data:read"}, Constraints: []ConstraintV2{}, IssuedAt: 10, ExpiresAt: 30}
	leafBytes, err := certSignableBytesV2(&leafCert)
	if err != nil {
		t.Fatal(err)
	}
	leafCert.Signature, err = signV2Statement(v2DelegationCertificate, leafBytes, midPriv)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &ProofBundleV2{Version: 2, VerifierID: strings.Repeat("a", 64), AgentID: agentID, AgentPubKey: agentPub, Delegations: []DelegationCertV2{leafCert, rootCert}, DelegationDigest: make([]byte, sha512.Size384), Challenge: bytes.Repeat([]byte{0x42}, 32), ChallengeAt: 10}
	digest, err := delegationDigestV2(bundle.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DelegationDigest = digest
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, rootPub, rootPriv, midPriv, agentPriv
}

func TestEvaluateProofBundleV2RequiresParentDelegationScope(t *testing.T) {
	for _, mayDelegate := range []bool{true, false} {
		bundle, rootKey, _, _, _ := signedV2DelegationChainTest(t, mayDelegate)
		root := bundle.Delegations[len(bundle.Delegations)-1]
		policy := testUnboundContextPolicy(t)
		got := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
			TrustedRootID:     root.IssuerID,
			TrustedRootKey:    rootKey,
			TrustConfigured:   true,
			RequiredScope:     "data:read",
			ContextPolicy:     policy,
			ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
			ClaimToken:        testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read"),
		})
		if mayDelegate && got.Status != "pending_external_checks" {
			t.Errorf("delegated chain should pass local checks, got %+v", got)
		}
		if !mayDelegate && got.Status != "delegation_not_authorized" {
			t.Errorf("parent without identity:delegate must fail, got %+v", got)
		}
		if !mayDelegate && (got.Reason != "delegation_not_authorized" || got.Detail == "") {
			t.Errorf("parent without identity:delegate must use its nonempty-chain receipt reason, got %+v", got)
		}
	}
}

func TestEvaluateProofBundleV2CarriesAuthenticatedSubjectIDsIntoStatusChecks(t *testing.T) {
	bundle, rootKey, _, _, _ := signedV2DelegationChainTest(t, true)
	root := bundle.Delegations[len(bundle.Delegations)-1]
	policy := testUnboundContextPolicy(t)
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy, ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken: testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read"),
	})
	if assessment.Status != "pending_external_checks" || len(assessment.StatusChecks) != len(bundle.Delegations) {
		t.Fatalf("expected status checks for each authenticated delegation: %+v", assessment)
	}
	for i, check := range assessment.StatusChecks {
		cert := bundle.Delegations[i]
		if check.DelegationIndex != i || check.IssuerID != cert.IssuerID || check.SubjectID != cert.SubjectID || check.CertID != cert.CertID {
			t.Fatalf("status check %d lost its authenticated certificate roles: %+v, cert=%+v", i, check, cert)
		}
	}
}

func TestAuthenticatedStatusChecksAggregateWithVerifiedChainRoles(t *testing.T) {
	bundle, rootKey, _, _, _ := signedV2DelegationChainTest(t, true)
	root := bundle.Delegations[len(bundle.Delegations)-1]
	policy := testUnboundContextPolicy(t)
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy, ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken: testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read"),
	})
	if assessment.Status != "pending_external_checks" {
		t.Fatalf("expected chain ready for external status checks: %+v", assessment)
	}

	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
	results := make([]RevocationStatusResultV2, len(assessment.StatusChecks))
	for i, check := range assessment.StatusChecks {
		keyID := fmt.Sprintf("%064x", i+1)
		roles.StatusKeyIssuers[keyID] = check.IssuerID
		roles.CurrentStatusKeyIDs[check.IssuerID] = keyID
		evidence := testV2StatusEvidence("issuer", string(rune('1'+i)), 1, uint16(v2RevocationList), string(rune('a'+i)))
		evidence.IssuerID = check.IssuerID
		evidence.StatusKeyID = keyID
		results[i] = RevocationStatusResultV2{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{evidence}}
	}
	assessmentResult, err := aggregateCertificateStatusResultsV2(assessment.StatusChecks, results, roles)
	if err != nil || assessmentResult.Assessment != "current" || assessmentResult.Reason != "" || len(assessmentResult.Evidence) != len(assessment.StatusChecks) {
		t.Fatalf("authenticated chain status did not aggregate as current: %+v, %v", assessmentResult, err)
	}
	wantStatusKeys := make(map[string]string, len(assessment.StatusChecks))
	for _, check := range assessment.StatusChecks {
		wantStatusKeys[check.IssuerID] = roles.CurrentStatusKeyIDs[check.IssuerID]
	}
	for _, evidence := range assessmentResult.Evidence {
		if wantStatusKeys[evidence.IssuerID] != evidence.StatusKeyID {
			t.Fatalf("aggregate evidence lost its issuer binding: %+v", evidence)
		}
		delete(wantStatusKeys, evidence.IssuerID)
	}
	if len(wantStatusKeys) != 0 || assessmentResult.Evidence[0].IssuerID >= assessmentResult.Evidence[1].IssuerID {
		t.Fatalf("aggregate evidence is incomplete or not canonically ordered: %+v", assessmentResult.Evidence)
	}
}

func TestAuthenticatedStatusAggregationRejectsCrossCertificateRoleKeys(t *testing.T) {
	bundle, rootKey, _, _, _ := signedV2DelegationChainTest(t, true)
	root := bundle.Delegations[len(bundle.Delegations)-1]
	policy := testUnboundContextPolicy(t)
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy, ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken: testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read"),
	})
	cases := []struct {
		name     string
		checkIdx int
		roleID   string
	}{
		{name: "root issuer", checkIdx: 1, roleID: bundle.Delegations[1].IssuerID},
		{name: "intermediate key on parent status", checkIdx: 1, roleID: bundle.Delegations[1].SubjectID},
		{name: "agent subject on root status", checkIdx: 1, roleID: bundle.Delegations[0].SubjectID},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
			results := make([]RevocationStatusResultV2, len(assessment.StatusChecks))
			for i, check := range assessment.StatusChecks {
				keyID := fmt.Sprintf("%064x", i+10)
				if i == tt.checkIdx {
					keyID = tt.roleID
				}
				roles.StatusKeyIssuers[keyID] = check.IssuerID
				roles.CurrentStatusKeyIDs[check.IssuerID] = keyID
				results[i] = RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}
			}
			check := assessment.StatusChecks[tt.checkIdx]
			evidence := testV2StatusEvidence("issuer", "1", 2, uint16(v2RevocationPush), "b")
			evidence.IssuerID = check.IssuerID
			evidence.StatusKeyID = tt.roleID
			results[tt.checkIdx] = RevocationStatusResultV2{Status: "revoked", Evidence: []StatusEvidenceEntryV2{evidence}}
			got, err := aggregateCertificateStatusResultsV2(assessment.StatusChecks, results, roles)
			if err != nil || got.Assessment != "unavailable" || len(got.Evidence) != 0 {
				t.Fatalf("cross-certificate role collision produced a revocation decision: %+v, %v", got, err)
			}
		})
	}
}

func TestEvaluateProofBundleV2LocalAuthorizationScopeAndExpiry(t *testing.T) {
	bundle := signedV2TestBundle(t)
	root := bundle.Delegations[0]
	policy := testUnboundContextPolicy(t)
	opts := V2LocalAuthorizationOptions{
		TrustedRootID:     root.IssuerID,
		TrustedRootKey:    root.IssuerPubKey,
		TrustConfigured:   true,
		RequiredScope:     "data:read",
		ContextPolicy:     policy,
		ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken:        testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read"),
	}
	got := EvaluateProofBundleV2LocalAuthorization(bundle, opts)
	if got.Status != "pending_external_checks" || got.LocalPolicyFailure == nil || got.LocalPolicyFailure.Status != "scope_denied" || len(got.EffectiveScope) != 1 {
		t.Fatalf("scope miss was not deferred until chain status completes: %+v", got)
	}
	if len(got.StatusChecks) != len(bundle.Delegations) {
		t.Fatalf("scope miss skipped status checks for part of the certificate chain: %+v", got.StatusChecks)
	}

	opts.RequiredScope = ""
	opts.ClaimToken = testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read")
	got = EvaluateProofBundleV2LocalAuthorization(bundle, opts)
	if got.Status != "authorization_unverified" || got.Reason != "evaluation_interrupted" || got.ContextAssessment != "not_evaluated" {
		t.Fatalf("required scope mutation after preflight did not fail closed: %+v", got)
	}

	tampered := *bundle
	tampered.ChallengeSig.Ed25519 = bytes.Clone(bundle.ChallengeSig.Ed25519)
	tampered.ChallengeSig.Ed25519[0] ^= 0xff
	opts.RequiredScope = "data:read"
	opts.ClaimToken = testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read")
	got = EvaluateProofBundleV2LocalAuthorization(&tampered, opts)
	if got.Status != "authorization_unverified" || got.Reason != "evaluation_interrupted" || got.ContextAssessment != "not_evaluated" || got.AgentID != "" || len(got.StatusChecks) != 0 || got.BundleHash != opts.ClaimToken.state.expected.BundleHash || len(got.IssuerIDs) != len(bundle.Delegations) {
		t.Fatalf("post-claim preflight binding failure did not produce a terminal-safe assessment: %+v", got)
	}

	// Evaluation uses the authoritative claim time; a claim at expires_at is expired.
	opts.ClaimToken = testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read")
	opts.ClaimToken.state.claimedAt = 20
	got = EvaluateProofBundleV2LocalAuthorization(bundle, opts)
	if got.Status != "expired" || got.Reason == "" {
		t.Fatalf("certificate at expires_at was not expired: %+v", got)
	}
}

func TestEvaluateProofBundleV2DefersLocalConstraintFailuresUntilEveryStatusCheck(t *testing.T) {
	tests := []struct {
		name       string
		constraint ConstraintV2
		context    ConstraintContextV2
		wantStatus string
	}{
		{
			name:       "known constraint denied",
			constraint: ConstraintV2{Type: ConstraintMaxAmount, MaxAmountMicros: 5_000_000, Currency: "USD"},
			context:    ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 10_000_000, RequestedCurrency: "USD"},
			wantStatus: "constraint_denied",
		},
		{
			name:       "unknown constraint",
			constraint: ConstraintV2{Type: ConstraintType("future_constraint"), Params: map[string]any{}},
			wantStatus: "constraint_unknown",
		},
		{
			name:       "unverifiable constraint",
			constraint: ConstraintV2{Type: ConstraintMaxAmount, MaxAmountMicros: 5_000_000, Currency: "USD"},
			wantStatus: "constraint_unverifiable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, rootKey, rootPriv, _, agentPriv := signedV2DelegationChainTest(t, true)
			rootIndex := len(bundle.Delegations) - 1
			bundle.Delegations[rootIndex].Constraints = []ConstraintV2{tt.constraint}
			signable, err := certSignableBytesV2(&bundle.Delegations[rootIndex])
			if err != nil {
				t.Fatal(err)
			}
			bundle.Delegations[rootIndex].Signature, err = signV2Statement(v2DelegationCertificate, signable, rootPriv)
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
			policy := testUnboundContextPolicy(t)
			expected := testExpectedContextChallenge(t, bundle, policy)
			got := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
				TrustedRootID:  bundle.Delegations[rootIndex].IssuerID,
				TrustedRootKey: rootKey, TrustConfigured: true, RequiredScope: "data:read",
				Context: tt.context, ContextPolicy: policy, ExpectedChallenge: expected,
				ClaimToken: testEvaluationTokenForTest(t, bundle, expected, policy, "data:read"),
			})
			if got.Status != "pending_external_checks" || got.LocalPolicyFailure == nil || got.LocalPolicyFailure.Status != tt.wantStatus {
				t.Fatalf("local constraint failure was finalized before status aggregation: %+v", got)
			}
			if len(got.StatusChecks) != len(bundle.Delegations) {
				t.Fatalf("constraint failure omitted chain status work: %+v", got.StatusChecks)
			}
			for i, cert := range bundle.Delegations {
				if got.StatusChecks[i].CertID != cert.CertID || got.StatusChecks[i].IssuerID != cert.IssuerID {
					t.Fatalf("status check %d lost its exact issuer/certificate binding: %+v", i, got.StatusChecks[i])
				}
			}
		})
	}
}

func TestResolveClaimProofBundleV2AppliesStatusBeforePendingLocalDenial(t *testing.T) {
	for _, statusCase := range []struct {
		name       string
		target     int
		status     string
		wantStatus string
		wantReason string
	}{
		{name: "current status applies local denial", target: -1, status: "current", wantStatus: "constraint_denied", wantReason: "constraint_denied"},
		{name: "revocation takes precedence", target: 0, status: "revoked", wantStatus: "revoked", wantReason: "delegation_revoked"},
		{name: "unavailable status takes precedence", target: 0, status: "unavailable", wantStatus: "authorization_unverified", wantReason: "status_unavailable"},
		{name: "stale status takes precedence", target: 0, status: "stale", wantStatus: "authorization_unverified", wantReason: "status_stale"},
	} {
		t.Run(statusCase.name, func(t *testing.T) {
			bundle, rootKey, rootPriv, _, agentPriv := signedV2DelegationChainTest(t, true)
			rootIndex := len(bundle.Delegations) - 1
			bundle.Delegations[rootIndex].Constraints = []ConstraintV2{{Type: ConstraintMaxAmount, MaxAmountMicros: 5_000_000, Currency: "USD"}}
			signable, err := certSignableBytesV2(&bundle.Delegations[rootIndex])
			if err != nil {
				t.Fatal(err)
			}
			bundle.Delegations[rootIndex].Signature, err = signV2Statement(v2DelegationCertificate, signable, rootPriv)
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
			policy := testUnboundContextPolicy(t)
			expected := testExpectedContextChallenge(t, bundle, policy)
			token := testEvaluationTokenForTest(t, bundle, expected, policy, "data:read")
			assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
				TrustedRootID:  bundle.Delegations[rootIndex].IssuerID,
				TrustedRootKey: rootKey, TrustConfigured: true, RequiredScope: "data:read",
				Context:       ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 10_000_000, RequestedCurrency: "USD"},
				ContextPolicy: policy, ExpectedChallenge: expected, ClaimToken: token,
			})
			if assessment.Status != "pending_external_checks" || assessment.LocalPolicyFailure == nil {
				t.Fatalf("expected pending local denial before status stage, got %+v", assessment)
			}
			checks := assessment.StatusChecks
			results := make([]RevocationStatusResultV2, len(checks))
			roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
			for i, check := range checks {
				keyID := fmt.Sprintf("%064x", i+100)
				roles.StatusKeyIssuers[keyID] = check.IssuerID
				roles.CurrentStatusKeyIDs[check.IssuerID] = keyID
				evidence := StatusEvidenceEntryV2{IssuerID: check.IssuerID, StatusKeyID: keyID, Sequence: 1, ObjectType: uint16(v2RevocationList), Digest: "sha384:" + strings.Repeat(string(rune('a'+i)), 96)}
				results[i] = RevocationStatusResultV2{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{evidence}}
			}
			if statusCase.status == "revoked" {
				check := checks[statusCase.target]
				results[statusCase.target] = RevocationStatusResultV2{Status: "revoked", Evidence: []StatusEvidenceEntryV2{{IssuerID: check.IssuerID, StatusKeyID: roles.CurrentStatusKeyIDs[check.IssuerID], Sequence: 2, ObjectType: uint16(v2RevocationPush), Digest: "sha384:" + strings.Repeat("c", 96)}}}
			} else if statusCase.status == "unavailable" {
				results[statusCase.target] = RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}
			} else if statusCase.status == "stale" {
				results[statusCase.target].Status = "indeterminate"
				results[statusCase.target].Reason = "stale"
			}
			resolved, err := resolveClaimProofBundleV2AfterStatusResults(token, results, roles)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.Status != statusCase.wantStatus || resolved.Reason != statusCase.wantReason || resolved.StatusAssessment != statusCase.status {
				t.Fatalf("status and local-policy precedence = %+v", resolved)
			}
			decision := "deny"
			if resolved.Status == "authorization_unverified" {
				decision = "indeterminate"
			}
			terminal := []byte(fmt.Sprintf(`{"decision":%q,"decision_reason":%q}`, decision, resolved.Reason))
			store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
			if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, terminal, terminal); err != nil || !finalized {
				t.Fatalf("resolved terminal result could not finalize: finalized=%t err=%v", finalized, err)
			}
		})
	}
}

func TestResolveClaimProofBundleV2AllowsOnlyAfterCurrentStatus(t *testing.T) {
	bundle := signedV2TestBundle(t)
	root := bundle.Delegations[0]
	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	token := testEvaluationTokenForTest(t, bundle, expected, policy, "execute:tool")
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: root.IssuerPubKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy,
		ExpectedChallenge: expected, ClaimToken: token,
	})
	if assessment.Status != "pending_external_checks" {
		t.Fatalf("status stage was not required before allow: %+v", assessment)
	}
	check := assessment.StatusChecks[0]
	keyID := fmt.Sprintf("%064x", 100)
	roles := V2StatusRoleBindings{
		StatusKeyIssuers:    map[string]string{keyID: check.IssuerID},
		CurrentStatusKeyIDs: map[string]string{check.IssuerID: keyID},
		ReservedKeyIDs:      map[string]struct{}{},
	}
	evidence := StatusEvidenceEntryV2{IssuerID: check.IssuerID, StatusKeyID: keyID, Sequence: 1, ObjectType: uint16(v2RevocationList), Digest: "sha384:" + strings.Repeat("a", 96)}
	resolved, err := resolveClaimProofBundleV2AfterStatusResults(token, []RevocationStatusResultV2{{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{evidence}}}, roles)
	if err != nil || resolved.Status != "authorized_agent" || resolved.Reason != "authorized" || resolved.StatusAssessment != "current" {
		t.Fatalf("current status did not resolve the pending allow: %+v, %v", resolved, err)
	}
	terminal := []byte(`{"decision":"allow","decision_reason":"authorized"}`)
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, terminal, terminal); err != nil || !finalized {
		t.Fatalf("current, fully checked allow could not finalize: finalized=%t err=%v", finalized, err)
	}
}

func TestEvaluateProofBundleV2FailureOrderChecksAllTimeBoundsBeforeExpiry(t *testing.T) {
	bundle, rootKey, rootPriv, midPriv, agentPriv := signedV2DelegationChainTest(t, true)
	bundle.Delegations[0].IssuedAt = 40
	bundle.Delegations[1].ExpiresAt = 14
	for i, issuerKey := range []HybridPrivateKey{midPriv, rootPriv} {
		signable, err := certSignableBytesV2(&bundle.Delegations[i])
		if err != nil {
			t.Fatal(err)
		}
		bundle.Delegations[i].Signature, err = signV2Statement(v2DelegationCertificate, signable, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	digest, err := delegationDigestV2(bundle.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DelegationDigest = digest
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		t.Fatalf("test proof signatures invalid: %v", err)
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	policy := testUnboundContextPolicy(t)
	got := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy, ExpectedChallenge: testExpectedContextChallenge(t, bundle, policy),
		ClaimToken: testEvaluationTokenForTest(t, bundle, testExpectedContextChallenge(t, bundle, policy), policy, "data:read"),
	})
	if got.Status != "invalid" || got.Reason != "proof_invalid" || got.Detail == "" {
		t.Fatalf("failure order must report invalid time bounds before expiry: %+v", got)
	}
}

func TestV2DeferredConstraintsPreservePositionAndSignedParameters(t *testing.T) {
	bundle, rootKey, _, midPriv, agentPriv := signedV2DelegationChainTest(t, true)
	bundle.Delegations[0].Constraints = []ConstraintV2{
		{Type: ConstraintMaxRate, Count: 2, WindowS: 60},
		{Type: ConstraintMaxRate, Count: 4, WindowS: 120},
		{Type: ConstraintReceiverAudience, Params: map[string]any{
			"exact_receiver_ids": []any{"service-1"}, "trust_domain_ids": []any{"domain-1"}, "max_membership_age_seconds": 300,
		}},
	}
	signable, err := certSignableBytesV2(&bundle.Delegations[0])
	if err != nil {
		t.Fatal(err)
	}
	bundle.Delegations[0].Signature, err = signV2Statement(v2DelegationCertificate, signable, midPriv)
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
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		t.Fatalf("test proof signatures invalid: %v", err)
	}
	encoded, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = DecodeProofBundleV2(encoded)
	if err != nil {
		t.Fatalf("signed constraints did not survive v2 wire round-trip: %v", err)
	}
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		t.Fatalf("wire-decoded proof signatures invalid: %v", err)
	}

	policy := testUnboundContextPolicy(t)
	expected := testExpectedContextChallenge(t, bundle, policy)
	expected.ExpectedReceiverID = "service-1"
	pre, err := PreflightProofBundleV2(bundle, expected, policy, "data:read", "test", 0, 15, 15, 0)
	if err != nil {
		t.Fatal(err)
	}
	claimStore := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	claim, _, token, err := ClaimProofBundleV2(context.Background(), claimStore, bundle, pre, "test", 0, 15)
	if err != nil {
		t.Fatalf("seal signed rate limits in challenge claim: %v", err)
	}
	if !claim.RequiresRate || len(claim.RateBatch) != 2 || len(claimStore.claim.RateBatch) != 2 ||
		claim.RateBatch[0].IssuerID != bundle.Delegations[0].IssuerID ||
		claim.RateBatch[0].CertID != bundle.Delegations[0].CertID ||
		claim.RateBatch[0].WindowS != 60 || claim.RateBatch[0].Limit != 2 ||
		claim.RateBatch[1].WindowS != 120 || claim.RateBatch[1].Limit != 4 {
		t.Fatalf("claim omitted or changed signed rate batch: %+v", claim.RateBatch)
	}
	claim.RateBatch[0].Limit = 99
	if claimStore.claim.RateBatch[0].Limit != 2 {
		t.Fatal("claim store rate batch aliases caller-owned output")
	}
	assessment := EvaluateProofBundleV2LocalAuthorization(bundle, V2LocalAuthorizationOptions{
		TrustedRootID:  bundle.Delegations[1].IssuerID,
		TrustedRootKey: rootKey, TrustConfigured: true, RequiredScope: "data:read", ContextPolicy: policy, ExpectedChallenge: expected,
		ClaimToken: token,
	})
	if assessment.Status != "pending_external_checks" || len(assessment.Deferred) != 3 {
		t.Fatalf("expected three deferred constraints: %+v", assessment)
	}
	wantRates := [][]byte{
		[]byte(`{"count":2,"type":"max_rate","window_s":60}`),
		[]byte(`{"count":4,"type":"max_rate","window_s":120}`),
	}
	for i := range wantRates {
		got := assessment.Deferred[i]
		if got.DelegationIndex != 0 || got.ConstraintIndex != i || got.IssuerID != bundle.Delegations[0].IssuerID || got.CertID != bundle.Delegations[0].CertID || got.Type != ConstraintMaxRate {
			t.Errorf("deferred constraint %d lost its certificate/constraint identity: %+v", i, got)
		}
		if !bytes.Equal(got.CanonicalJSON, wantRates[i]) {
			t.Errorf("deferred constraint %d lost its signed parameters: %s", i, got.CanonicalJSON)
		}
	}
	wantAudience, err := CanonicalJSON(bundle.Delegations[0].Constraints[2])
	if err != nil {
		t.Fatal(err)
	}
	audience := assessment.Deferred[2]
	if audience.ConstraintIndex != 2 || audience.Type != ConstraintReceiverAudience || !bytes.Equal(audience.CanonicalJSON, wantAudience) || !bytes.Contains(audience.CanonicalJSON, []byte("service-1")) || !bytes.Contains(audience.CanonicalJSON, []byte("domain-1")) || !bytes.Contains(audience.CanonicalJSON, []byte(`"max_membership_age_seconds":300`)) {
		t.Fatalf("deferred receiver audience lost its signed parameters: %+v %s", audience, audience.CanonicalJSON)
	}
	if len(assessment.StatusChecks) != len(bundle.Delegations) || assessment.StatusChecks[0].CertID != bundle.Delegations[0].CertID || assessment.StatusChecks[1].CertID != bundle.Delegations[1].CertID {
		t.Fatalf("status work list does not cover every issuer-scoped chain certificate: %+v", assessment.StatusChecks)
	}
	results := make([]RevocationStatusResultV2, len(assessment.StatusChecks))
	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
	for i, check := range assessment.StatusChecks {
		keyID := fmt.Sprintf("%064x", i+100)
		roles.StatusKeyIssuers[keyID] = check.IssuerID
		roles.CurrentStatusKeyIDs[check.IssuerID] = keyID
		results[i] = RevocationStatusResultV2{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{{
			IssuerID: check.IssuerID, StatusKeyID: keyID, Sequence: 1, ObjectType: uint16(v2RevocationList),
			Digest: "sha384:" + strings.Repeat(string(rune('a'+i)), 96),
		}}}
	}
	resolved, err := resolveClaimProofBundleV2AfterStatusResults(token, results, roles)
	if err != nil || resolved.Status != "pending_external_checks" || resolved.StatusAssessment != "current" || resolved.Reason != "deferred_policy_checks_required" {
		t.Fatalf("current status incorrectly finalized unresolved audience/rate checks: %+v, %v", resolved, err)
	}
	store := &recordingClaimStoreV2{disposition: V2ClaimCreated}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, []byte(`{"decision":"allow","decision_reason":"authorized"}`), []byte(`{"decision":"allow","decision_reason":"authorized"}`)); err == nil || finalized || store.finalizeCalls != 0 {
		t.Fatalf("allow finalized before deferred audience/rate evaluation: finalized=%t err=%v", finalized, err)
	}
	audienceResolved, err := ResolveClaimProofBundleV2AfterAudience(token, nil)
	if err != nil || audienceResolved.Status != "pending_external_checks" || audienceResolved.Reason != "rate_reservation_required" || len(audienceResolved.Deferred) != 2 {
		t.Fatalf("exact audience did not preserve pending rate checks: %+v, %v", audienceResolved, err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, []byte(`{"decision":"allow","decision_reason":"authorized"}`), []byte(`{"decision":"allow","decision_reason":"authorized"}`)); err == nil || finalized || store.finalizeCalls != 0 {
		t.Fatalf("allow finalized before rate reservation: finalized=%t err=%v", finalized, err)
	}
	newRateToken := func(pending V2LocalAuthorizationAssessment) *V2EvaluationToken {
		state := &v2EvaluationTokenState{
			claimID: claim.ClaimID, proofDigest: claim.ProofDigest,
			requiredScope: claim.RequiredScope, expected: cloneExpectedChallengeStateV2(pre.state),
			ownerToken: bytes.Repeat([]byte{0x7a}, 32), rateBatch: append([]V2RateReservation{}, claimStore.claim.RateBatch...),
			evaluationStatus: "pending_external_checks", pendingAssessment: cloneV2LocalAuthorizationAssessment(pending),
		}
		state.evaluationComplete.Store(true)
		return &V2EvaluationToken{state: state}
	}
	atomicStore := &recordingV2AtomicRateStore{nextError: ErrV2RateLimitExceeded}
	atomicToken := newRateToken(audienceResolved)
	atomicOutcome, err := ResolveClaimProofBundleV2AfterRate(context.Background(), atomicStore, atomicToken)
	if err != nil || atomicOutcome.Status != "authorized_agent" || !atomicOutcome.RateAdmissionDeferred ||
		atomicStore.reserveCalls != 0 || !atomicToken.state.rateAtFinalization {
		t.Fatalf("atomic rate admission ran before finalization: outcome=%+v calls=%d err=%v", atomicOutcome, atomicStore.reserveCalls, err)
	}
	allowPayload := []byte(`{"decision":"allow","decision_reason":"authorized"}`)
	otherStore := &recordingClaimStoreV2{}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), otherStore, atomicToken, allowPayload, allowPayload); err == nil || finalized || otherStore.finalizeCalls != 0 {
		t.Fatalf("rate-at-finalization token reached a non-atomic store: finalized=%t err=%v", finalized, err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), atomicStore, atomicToken, allowPayload, allowPayload); !errors.Is(err, ErrV2RateLimitExceeded) || finalized || atomicStore.finalizeCalls != 0 {
		t.Fatalf("rolled-back rate exhaustion did not release the allow payload: finalized=%t err=%v", finalized, err)
	}
	if _, err := FinalizeClaimProofBundleV2(context.Background(), atomicStore, atomicToken, allowPayload, allowPayload); err == nil {
		t.Fatal("exhausted rate attempt still permitted an allow")
	}
	deniedPayload := []byte(`{"decision":"deny","decision_reason":"constraint_denied"}`)
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), atomicStore, atomicToken, deniedPayload, deniedPayload); err != nil || !finalized || atomicToken.state.allowValidUntil != 0 {
		t.Fatalf("rolled-back capacity denial did not terminalize exactly once: finalized=%t err=%v", finalized, err)
	}
	ambiguousAtomic := &recordingV2AtomicRateStore{nextError: errors.New("ambiguous external commit")}
	ambiguousToken := newRateToken(audienceResolved)
	if _, err := ResolveClaimProofBundleV2AfterRate(context.Background(), ambiguousAtomic, ambiguousToken); err != nil {
		t.Fatal(err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), ambiguousAtomic, ambiguousToken, allowPayload, allowPayload); err == nil || finalized {
		t.Fatalf("ambiguous atomic allow unexpectedly committed: finalized=%t err=%v", finalized, err)
	}
	if _, err := FinalizeClaimProofBundleV2(context.Background(), ambiguousAtomic, ambiguousToken, deniedPayload, deniedPayload); err == nil {
		t.Fatal("ambiguous atomic allow changed its terminal payload")
	}
	wrappedAtomic := &recordingV2AtomicRateStore{nextError: fmt.Errorf("ambiguous: %w", ErrV2RateLimitExceeded)}
	wrappedToken := newRateToken(audienceResolved)
	if _, err := ResolveClaimProofBundleV2AfterRate(context.Background(), wrappedAtomic, wrappedToken); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeClaimProofBundleV2(context.Background(), wrappedAtomic, wrappedToken, allowPayload, allowPayload); !errors.Is(err, ErrV2RateLimitExceeded) {
		t.Fatalf("wrapped ambiguous rate error was lost: %v", err)
	}
	if _, err := FinalizeClaimProofBundleV2(context.Background(), wrappedAtomic, wrappedToken, deniedPayload, deniedPayload); err == nil {
		t.Fatal("wrapped ambiguous rate error changed its terminal payload")
	}
	successAtomic := &recordingV2AtomicRateStore{}
	successToken := newRateToken(audienceResolved)
	if _, err := ResolveClaimProofBundleV2AfterRate(context.Background(), successAtomic, successToken); err != nil {
		t.Fatal(err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), successAtomic, successToken, allowPayload, allowPayload); err != nil || !finalized || successAtomic.reserveCalls != 0 {
		t.Fatalf("atomic rate allow did not finalize once: finalized=%t err=%v", finalized, err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), successAtomic, successToken, allowPayload, allowPayload); err != nil || finalized {
		t.Fatalf("atomic allow exact retry was not idempotent: finalized=%t err=%v", finalized, err)
	}
	lostResponseAtomic := &recordingV2AtomicRateStore{}
	lostResponseAtomic.ambiguousFinalize = true
	lostResponseToken := newRateToken(audienceResolved)
	if _, err := ResolveClaimProofBundleV2AfterRate(context.Background(), lostResponseAtomic, lostResponseToken); err != nil {
		t.Fatal(err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), lostResponseAtomic, lostResponseToken, allowPayload, allowPayload); err == nil || finalized {
		t.Fatalf("lost atomic finalization response unexpectedly succeeded: finalized=%t err=%v", finalized, err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), lostResponseAtomic, lostResponseToken, allowPayload, allowPayload); err != nil || finalized {
		t.Fatalf("atomic finalization response loss did not preserve exact retry: finalized=%t err=%v", finalized, err)
	}
	for _, test := range []struct {
		name, status, reason, decision string
		rateError                      error
		unavailable                    bool
	}{
		{"capacity exhausted", "constraint_denied", "constraint_denied", "deny", ErrV2RateLimitExceeded, false},
		{"ambiguous store error", "constraint_unverifiable", "constraint_unverifiable", "deny", fmt.Errorf("simulated lost reserve response"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := newRateToken(audienceResolved)
			rate := &recordingV2RateStore{err: test.rateError}
			outcome, err := ResolveClaimProofBundleV2AfterRate(context.Background(), rate, candidate)
			if err != nil || outcome.Status != test.status || outcome.Reason != test.reason || outcome.RateStoreUnavailable != test.unavailable || rate.calls != 1 {
				t.Fatalf("rate outcome did not fail closed: %+v calls=%d err=%v", outcome, rate.calls, err)
			}
			terminal := []byte(fmt.Sprintf(`{"decision":%q,"decision_reason":%q}`, test.decision, test.reason))
			if finalized, err := FinalizeClaimProofBundleV2(context.Background(), &recordingClaimStoreV2{}, candidate, terminal, terminal); err != nil || !finalized {
				t.Fatalf("rate denial did not reach its exact terminal tuple: finalized=%t err=%v", finalized, err)
			}
		})
	}
	if _, err := ResolveClaimProofBundleV2AfterRate(context.Background(), &recordingV2RateStore{}, newRateToken(resolved)); err == nil {
		t.Fatal("rate reservation ran while audience checks remained")
	}
	tamperedPending := *cloneV2LocalAuthorizationAssessment(audienceResolved)
	tamperedPending.Deferred[0].CanonicalJSON = []byte(`{"count":1,"type":"max_rate","window_s":60}`)
	tamperedRate := &recordingV2RateStore{}
	if _, err := ResolveClaimProofBundleV2AfterRate(context.Background(), tamperedRate, newRateToken(tamperedPending)); err == nil || tamperedRate.calls != 0 {
		t.Fatalf("changed signed rate batch reached store: calls=%d err=%v", tamperedRate.calls, err)
	}
	rateStore := &recordingV2RateStore{}
	rateResolved, err := ResolveClaimProofBundleV2AfterRate(context.Background(), rateStore, token)
	if err != nil || rateResolved.Status != "authorized_agent" || rateResolved.Reason != "authorized" ||
		rateResolved.RateAdmissionDeferred || rateStore.calls != 1 || !slices.Equal(rateStore.batch, claimStore.claim.RateBatch) {
		t.Fatalf("signed rate batch did not complete authorization: %+v calls=%d batch=%+v err=%v", rateResolved, rateStore.calls, rateStore.batch, err)
	}
	allow := []byte(`{"decision":"allow","decision_reason":"authorized"}`)
	store.ambiguousFinalize = true
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, allow, allow); err == nil || finalized || rateStore.calls != 1 {
		t.Fatalf("lost terminal response was released or rate was reserved again: finalized=%t calls=%d err=%v", finalized, rateStore.calls, err)
	}
	if finalized, err := FinalizeClaimProofBundleV2(context.Background(), store, token, allow, allow); err != nil || finalized || rateStore.calls != 1 {
		t.Fatalf("identical terminal retry did not reuse committed result: finalized=%t calls=%d err=%v", finalized, rateStore.calls, err)
	}

	tampered := *bundle
	tampered.Delegations = append([]DelegationCertV2(nil), bundle.Delegations...)
	tampered.Delegations[0].Constraints = append([]ConstraintV2(nil), bundle.Delegations[0].Constraints...)
	tamperedParams := make(map[string]any, len(tampered.Delegations[0].Constraints[2].Params))
	for key, value := range tampered.Delegations[0].Constraints[2].Params {
		tamperedParams[key] = value
	}
	tamperedParams["trust_domain_ids"] = []any{"other-domain"}
	tampered.Delegations[0].Constraints[2].Params = tamperedParams
	tampered.DelegationDigest, err = delegationDigestV2(tampered.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProofBundleV2Signatures(&tampered); err == nil || !strings.Contains(err.Error(), "delegation 0 signature") {
		t.Fatalf("mutating a signed audience parameter must invalidate its certificate signature, got %v", err)
	}
}
