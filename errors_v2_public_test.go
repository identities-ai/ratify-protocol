package ratify

import (
	"context"
	"errors"
	"os"
	"regexp"
	"testing"
	"time"
)

// failingJournalStoreV2 fails every load and commit.
type failingJournalStoreV2 struct{}

func (failingJournalStoreV2) Load(context.Context) (SecurityJournalV2, SecurityJournalHeadV2, error) {
	return SecurityJournalV2{}, SecurityJournalHeadV2{}, errors.New("journal backend down")
}
func (failingJournalStoreV2) CompareAndSwap(context.Context, SecurityJournalHeadV2, SecurityJournalV2) error {
	return errors.New("journal backend down")
}

// failingSignerV2 reports a key and then fails every signing request.
type failingSignerV2 struct{ pub HybridPublicKey }

func (s failingSignerV2) PublicKeyV2() HybridPublicKey { return s.pub }
func (failingSignerV2) ModeV2() SignerModeV2           { return SignerModeDirectV2 }
func (failingSignerV2) SignV2(context.Context, SignRequestV2) (HybridSignature, error) {
	return HybridSignature{}, errors.New("hardware signer unavailable")
}

// v2ListedErrorClasses reads the closed class list declared in errors_v2.go,
// which TestV2ErrorClassesMatchSpecTable holds equal to SPEC-v2 §2.7.
func v2ListedErrorClasses(t *testing.T) map[V2ErrorClass]bool {
	t.Helper()
	source, err := os.ReadFile("errors_v2.go")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[V2ErrorClass]bool{}
	for _, m := range regexp.MustCompile(`V2ErrorClass = "([a-z_0-9]+)"`).FindAllStringSubmatch(string(source), -1) {
		if m[1] != string(V2ErrUnclassified) {
			listed[V2ErrorClass(m[1])] = true
		}
	}
	if len(listed) != 49 {
		t.Fatalf("errors_v2.go declares %d classes, want the 49 of SPEC-v2 §2.7", len(listed))
	}
	return listed
}

// SPEC-v2 §2.7: every v2 failure that is not a terminal result or a release
// result has exactly one class from the closed list. Each public v2 API is
// called with inputs it must reject; the error must carry a listed class,
// never "unclassified", so an SDK port can match the reference class for
// the same input. Where the class is fixed by the specification it is
// asserted exactly.
func TestV2PublicAPIErrorsAreClassified(t *testing.T) {
	listed := v2ListedErrorClasses(t)
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := KeyIDV2(pub)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	garbage := []byte(`{"version":2}`)
	badKey := HybridPublicKey{Ed25519: make([]byte, 3)}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 3600, ClockSkewSeconds: 5}
	list := &RevocationListV2{Version: 2, IssuerID: keyID, UpdatedAt: 100, NextUpdate: 200, Sequence: 1, Revoked: []RevokedCertV2{}}
	push := &RevocationPushV2{Version: 2, IssuerID: keyID, Sequence: 1, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "c1"}}}
	state := RevocationStatusStateV2{IssuerID: keyID, StatusKeyEpoch: 1, StatusKeyID: keyID}

	type call struct {
		name string
		want V2ErrorClass // empty: any listed class
		run  func() error
	}
	first := func(_ any, err error) error { return err }
	calls := []call{
		// Decoders and archival verification.
		{"DecodeDelegationCertV2", V2ErrMalformed, func() error { return first(DecodeDelegationCertV2(garbage)) }},
		{"DecodeProofBundleV2", V2ErrMalformed, func() error { return first(DecodeProofBundleV2(garbage)) }},
		{"DecodeRevocationListV2", V2ErrMalformed, func() error { return first(DecodeRevocationListV2(garbage)) }},
		{"DecodeRevocationPushV2", V2ErrMalformed, func() error { return first(DecodeRevocationPushV2(garbage)) }},
		{"DecodeKeyRotationStatementV2", V2ErrMalformed, func() error { return first(DecodeKeyRotationStatementV2(garbage)) }},
		{"DecodeWitnessEntryV2", V2ErrMalformed, func() error { return first(DecodeWitnessEntryV2(garbage)) }},
		{"DecodeTransactionReceiptV2", V2ErrMalformed, func() error { return first(DecodeTransactionReceiptV2(garbage)) }},
		{"DecodeVerificationReceiptV2", V2ErrMalformed, func() error { return first(DecodeVerificationReceiptV2(garbage)) }},
		{"DecodeVerificationReceiptBodyV2", V2ErrMalformed, func() error { return first(DecodeVerificationReceiptBodyV2(garbage)) }},
		{"DecodeV2CheckpointAcknowledgement", V2ErrMalformed, func() error { return first(DecodeV2CheckpointAcknowledgement(garbage)) }},
		{"DecodeV2StatusEvidenceBatch", V2ErrMalformed, func() error { return first(DecodeV2StatusEvidenceBatch(garbage)) }},
		{"ImportSecurityJournalSnapshotV2", V2ErrMalformed, func() error { return first(ImportSecurityJournalSnapshotV2(garbage, SecurityJournalHeadV2{})) }},
		{"ConstraintV2.UnmarshalJSON", V2ErrMalformed, func() error { var c ConstraintV2; return c.UnmarshalJSON([]byte(`{"type":"time_window"}`)) }},
		{"ConstraintV2.MarshalJSON", V2ErrMalformed, func() error { return first(ConstraintV2{Type: ConstraintTimeWindow}.MarshalJSON()) }},
		{"VerifyArchivalDelegationCertV2", V2ErrMalformed, func() error { return first(VerifyArchivalDelegationCertV2(garbage)) }},
		{"VerifyArchivalRevocationListV2", V2ErrMalformed, func() error { return first(VerifyArchivalRevocationListV2(garbage, keyID, pub)) }},
		{"VerifyArchivalRevocationPushV2", V2ErrMalformed, func() error { return first(VerifyArchivalRevocationPushV2(garbage, keyID, pub)) }},
		{"VerifyArchivalKeyRotationStatementV2", V2ErrMalformed, func() error { return first(VerifyArchivalKeyRotationStatementV2(garbage)) }},
		{"VerifyArchivalWitnessEntryV2", V2ErrMalformed, func() error { return first(VerifyArchivalWitnessEntryV2(garbage, pub)) }},
		{"VerifyArchivalVerificationReceiptV2", V2ErrMalformed, func() error { return first(VerifyArchivalVerificationReceiptV2(garbage, pub)) }},
		{"VerifyArchivalTransactionReceiptV2", V2ErrMalformed, func() error { return first(VerifyArchivalTransactionReceiptV2(garbage)) }},

		// Encoders, digests and identifiers.
		{"KeyIDV2", V2ErrMalformed, func() error { return first(KeyIDV2(badKey)) }},
		{"BundleHashV2", V2ErrMalformed, func() error { return first(BundleHashV2(&ProofBundleV2{})) }},
		{"EncodeDelegationCertV2", V2ErrMalformed, func() error { return first(EncodeDelegationCertV2(&DelegationCertV2{})) }},
		{"EncodeProofBundleV2", V2ErrMalformed, func() error { return first(EncodeProofBundleV2(&ProofBundleV2{})) }},
		{"EncodeRevocationListV2", V2ErrMalformed, func() error { return first(EncodeRevocationListV2(&RevocationListV2{})) }},
		{"EncodeRevocationPushV2", V2ErrMalformed, func() error { return first(EncodeRevocationPushV2(&RevocationPushV2{})) }},
		{"EncodeKeyRotationStatementV2", V2ErrMalformed, func() error { return first(EncodeKeyRotationStatementV2(&KeyRotationStatementV2{})) }},
		{"EncodeWitnessEntryV2", V2ErrMalformed, func() error { return first(EncodeWitnessEntryV2(&WitnessEntryV2{})) }},
		{"EncodeTransactionReceiptV2", "", func() error { return first(EncodeTransactionReceiptV2(&TransactionReceiptV2{})) }},
		{"EncodeVerificationReceiptV2", V2ErrMalformed, func() error { return first(EncodeVerificationReceiptV2(&VerificationReceiptV2{})) }},
		{"EncodeV2CheckpointAcknowledgement", V2ErrMalformed, func() error { return first(EncodeV2CheckpointAcknowledgement(V2CheckpointAcknowledgement{})) }},
		{"EncodeV2StatusEvidenceBatch", V2ErrMalformed, func() error {
			return first(EncodeV2StatusEvidenceBatch(V2StatusEvidenceBatch{Objects: []V2StatusEvidenceObject{{ObjectType: 9}}}))
		}},
		{"VerificationReceiptV2Body", V2ErrMalformed, func() error { return first(VerificationReceiptV2Body(&VerificationReceiptV2{})) }},
		{"VerificationReceiptV2Digest", V2ErrMalformed, func() error { return first(VerificationReceiptV2Digest(&VerificationReceiptV2{})) }},
		{"WitnessEntryV2Digest", V2ErrMalformed, func() error { return first(WitnessEntryV2Digest(&WitnessEntryV2{})) }},
		{"KeyRotationStatementV2Digest", V2ErrMalformed, func() error { return first(KeyRotationStatementV2Digest(&KeyRotationStatementV2{})) }},
		{"TransactionReceiptV2SignBytes", V2ErrMalformed, func() error { return first(TransactionReceiptV2SignBytes(&TransactionReceiptV2{})) }},
		{"StatementBodyDigestV2 unregistered code", V2ErrUnsupportedObjectType, func() error { return first(StatementBodyDigestV2(0x0001, []byte(`{}`))) }},
		{"StatementBodyDigestV2 bad body", V2ErrMalformed, func() error { return first(StatementBodyDigestV2(0x0006, []byte(`{}`))) }},
		{"StatusEvidenceDigest unregistered code", V2ErrUnsupportedObjectType, func() error { return first(StatusEvidenceDigest(0x0001, list)) }},
		{"StatusEvidenceDigest wrong value", V2ErrMalformed, func() error { return first(StatusEvidenceDigest(0x0003, push)) }},
		{"ChallengeClaimDigestV2", V2ErrMalformed, func() error { return first(ChallengeClaimDigestV2([]byte("short"))) }},
		{"ProtocolClaimIDV2 namespace", V2ErrConfigurationInvalid, func() error { return first(ProtocolClaimIDV2("", 0, make([]byte, 32))) }},
		{"ProtocolClaimIDV2 challenge", V2ErrMalformed, func() error { return first(ProtocolClaimIDV2("ns", 0, []byte("short"))) }},
		{"ProtocolClaimIDFromDigestV2", V2ErrMalformed, func() error { return first(ProtocolClaimIDFromDigestV2("ns", 0, []byte("short"))) }},
		{"DecodePayloadDigest", V2ErrMalformed, func() error { s := "!"; return first(DecodePayloadDigest(&s)) }},
		{"BuildOperationContextV2", "", func() error { return first(BuildOperationContextV2(OperationContextV2Inputs{})) }},
		{"BuildSessionContextV2", V2ErrConfigurationInvalid, func() error { return first(BuildSessionContextV2(SessionContextV2Inputs{})) }},
		{"BuildV2RateReservationBatch", V2ErrMalformed, func() error {
			return first(BuildV2RateReservationBatch([]V2DeferredConstraint{{Type: ConstraintMaxRate, CanonicalJSON: garbage}}))
		}},

		// Signing.
		{"NewLocalSignerV2", V2ErrConfigurationInvalid, func() error { return first(NewLocalSignerV2(HybridPrivateKey{})) }},
		{"SignDelegationCertV2", V2ErrMalformed, func() error { return first(SignDelegationCertV2(&DelegationCertV2{}, priv)) }},
		{"SignDelegationCertV2WithSigner failing signer", "", func() error {
			return first(SignDelegationCertV2WithSigner(ctx, &DelegationCertV2{}, failingSignerV2{pub}))
		}},
		{"SignProofBundleV2 agent key binding", V2ErrKeyIDMismatch, func() error { return first(SignProofBundleV2(&ProofBundleV2{}, priv)) }},
		{"SignProofBundleV2", V2ErrMalformed, func() error {
			return first(SignProofBundleV2(&ProofBundleV2{AgentID: keyID, AgentPubKey: pub}, priv))
		}},
		{"SignRevocationListV2 issuer binding", V2ErrStatusKeyBindingMismatch, func() error { return first(SignRevocationListV2(list, "other", pub, priv)) }},
		{"SignRevocationListV2 status key binding", V2ErrStatusKeyBindingMismatch, func() error { return first(SignRevocationListV2(list, keyID, other, priv)) }},
		{"SignRevocationListV2WithSigner failing signer", V2ErrConfigurationInvalid, func() error {
			return first(SignRevocationListV2WithSigner(ctx, list, keyID, pub, failingSignerV2{pub}))
		}},
		{"SignRevocationListV2WithSigner cancelled", V2ErrEvaluationCancelled, func() error {
			return first(SignRevocationListV2WithSigner(cancelled, list, keyID, pub, failingSignerV2{pub}))
		}},
		{"SignRevocationPushV2 issuer binding", V2ErrStatusKeyBindingMismatch, func() error { return first(SignRevocationPushV2(push, "other", pub, priv)) }},
		{"SignKeyRotationStatementV2", V2ErrMalformed, func() error { return first(SignKeyRotationStatementV2(&KeyRotationStatementV2{}, priv, priv)) }},
		{"SignWitnessEntryV2", V2ErrMalformed, func() error { return first(SignWitnessEntryV2(&WitnessEntryV2{}, priv)) }},
		{"SignVerificationReceiptV2", V2ErrMalformed, func() error { return first(SignVerificationReceiptV2(&VerificationReceiptV2{}, priv)) }},
		{"SignPreparedVerificationReceiptV2", V2ErrConfigurationInvalid, func() error { return first(SignPreparedVerificationReceiptV2(garbage, ReceiptV2Head{}, priv)) }},
		{"BindVerificationReceiptBodyV2", V2ErrConfigurationInvalid, func() error { return first(BindVerificationReceiptBodyV2(garbage, ReceiptV2Head{})) }},
		{"SignTransactionReceiptPartyV2", "", func() error { return first(SignTransactionReceiptPartyV2(&TransactionReceiptV2{}, "p", priv)) }},

		// Signature and object verification.
		{"VerifyDelegationCertV2Signature", V2ErrMalformed, func() error { return VerifyDelegationCertV2Signature(&DelegationCertV2{}) }},
		{"VerifyProofBundleV2Signatures", V2ErrMalformed, func() error { return VerifyProofBundleV2Signatures(&ProofBundleV2{}) }},
		{"VerifyRevocationListV2Signature", V2ErrMalformed, func() error { return VerifyRevocationListV2Signature(&RevocationListV2{}, keyID, pub) }},
		{"VerifyRevocationPushV2Signature", V2ErrStatusKeyBindingMismatch, func() error { return VerifyRevocationPushV2Signature(push, "other", pub) }},
		{"VerifyKeyRotationStatementV2", "", func() error {
			return VerifyKeyRotationStatementV2(&KeyRotationStatementV2{}, KeyRotationV2State{}, 0, 0)
		}},
		{"VerifyWitnessEntryV2", V2ErrMalformed, func() error { return first(VerifyWitnessEntryV2(&WitnessEntryV2{}, WitnessV2Head{}, pub)) }},
		{"VerifyVerificationReceiptV2", V2ErrMalformed, func() error {
			return first(VerifyVerificationReceiptV2(&VerificationReceiptV2{}, pub, ReceiptV2Head{}))
		}},
		{"VerifyTransactionReceiptV2Signatures", "", func() error { return VerifyTransactionReceiptV2Signatures(&TransactionReceiptV2{}) }},
		{"CheckVerificationReceiptV2BundleBinding", "", func() error {
			return CheckVerificationReceiptV2BundleBinding(&VerificationReceiptV2{}, &ProofBundleV2{})
		}},

		// Key rotation journal.
		{"NewKeyRotationV2Journal", "", func() error { return first(NewKeyRotationV2Journal("", -1, "", badKey)) }},
		{"AcceptKeyRotationStatementV2", "", func() error {
			_, _, err := AcceptKeyRotationStatementV2(&KeyRotationStatementV2{}, KeyRotationV2Journal{}, 0, 0)
			return err
		}},
		{"RecoverKeyRotationV2", "", func() error { return first(RecoverKeyRotationV2(KeyRotationV2Journal{}, 0, badKey)) }},

		// Status reducer and SecurityJournalV2 operations (§5.4, §6.6).
		{"TransitionRevocationStatusEpochV2", V2ErrStatusObjectRejected, func() error { return first(TransitionRevocationStatusEpochV2(state, keyID, 3, other)) }},
		{"TransitionRevocationStatusEpochV2 reused key", V2ErrStatusObjectRejected, func() error { return first(TransitionRevocationStatusEpochV2(state, keyID, 2, pub)) }},
		{"ApplyRevocationListV2 unsigned", V2ErrInvalidSignature, func() error { return first(ApplyRevocationListV2(state, list, keyID, 1, pub, policy, 150)) }},
		{"ApplyRevocationPushV2 unsigned", V2ErrInvalidSignature, func() error { return first(ApplyRevocationPushV2(state, push, keyID, 1, pub, policy, 150)) }},
		{"RevocationStatusForCertV2", "", func() error { return first(RevocationStatusForCertV2(state, keyID, "", 1, pub, policy, 150)) }},
		{"RecordSecurityKeyRoleV2", V2ErrStatusObjectRejected, func() error { return first(RecordSecurityKeyRoleV2(ctx, failingJournalStoreV2{}, "verifier", pub)) }},
		{"RecordSecurityKeyRoleV2 status role", V2ErrStatusObjectRejected, func() error { return first(RecordSecurityKeyRoleV2(ctx, nil, "status", pub)) }},
		{"ConfigureStatusKeyEpochV2", V2ErrStatusObjectRejected, func() error { return first(ConfigureStatusKeyEpochV2(ctx, failingJournalStoreV2{}, keyID, 1, pub)) }},
		{"ApplyRevocationListToJournalV2", V2ErrStatusObjectRejected, func() error {
			return first(ApplyRevocationListToJournalV2(ctx, failingJournalStoreV2{}, list, keyID, 1, pub, policy, 150))
		}},
		{"ApplyRevocationPushToJournalV2", V2ErrStatusObjectRejected, func() error {
			return first(ApplyRevocationPushToJournalV2(ctx, nil, push, keyID, 1, pub, policy, 150))
		}},
		{"RevocationStatusFromJournalV2", V2ErrStatusObjectRejected, func() error {
			return first(RevocationStatusFromJournalV2(ctx, failingJournalStoreV2{}, keyID, "c1", 1, pub, policy, 150))
		}},
		{"RegisterKeyRoleV2", V2ErrStatusObjectRejected, func() error { j := EmptySecurityJournalV2(); return RegisterKeyRoleV2(&j, "nonsense", pub) }},
		{"RegisterStatusKeyEpochV2", V2ErrStatusObjectRejected, func() error { j := EmptySecurityJournalV2(); return RegisterStatusKeyEpochV2(&j, keyID, 0, pub) }},
		{"ValidateSecurityJournalV2", V2ErrMalformed, func() error { return ValidateSecurityJournalV2(SecurityJournalV2{}) }},
		{"ValidateSecurityJournalTransitionV2", "", func() error {
			return ValidateSecurityJournalTransitionV2(EmptySecurityJournalV2(), SecurityJournalV2{})
		}},
		{"ExportSecurityJournalSnapshotV2", V2ErrConfigurationInvalid, func() error { return first(ExportSecurityJournalSnapshotV2(SecurityJournalV2{})) }},
		{"MigrateSecurityJournalV2", V2ErrConfigurationInvalid, func() error { return first(MigrateSecurityJournalV2(SecurityJournalV2{})) }},
		{"NewV2StatusPublisher", V2ErrConfigurationInvalid, func() error { return first(NewV2StatusPublisher(ctx, nil, pub, nil, 0)) }},
		{"V2StatusPublisher.Heartbeat", V2ErrConfigurationInvalid, func() error { return first((&V2StatusPublisher{}).Heartbeat(ctx, V2StatusPublisherState{}, 1)) }},
		{"V2StatusPublisher.Revoke", V2ErrConfigurationInvalid, func() error { return first((&V2StatusPublisher{}).Revoke(ctx, V2StatusPublisherState{}, nil, 1)) }},
		{"V2StatusPublisher.Genesis", V2ErrConfigurationInvalid, func() error { return first((&V2StatusPublisher{}).Genesis(ctx, -1)) }},

		// Verifier configuration, preflight, claim and evaluation (§6, §7).
		{"NewV2ContextPolicy", V2ErrConfigurationInvalid, func() error { return first(NewV2ContextPolicy("", true, nil, nil)) }},
		{"NewConstraintEvaluatorRegistryV2", V2ErrConfigurationInvalid, func() error { return first(NewConstraintEvaluatorRegistryV2(-time.Second)) }},
		{"ConstraintProfileDigestV2", V2ErrConfigurationInvalid, func() error { return first(ConstraintProfileDigestV2(ConstraintProfileDescriptorV2{})) }},
		{"EvaluateReceiverAudienceV2", V2ErrConfigurationInvalid, func() error { return first(EvaluateReceiverAudienceV2(nil, "", nil, -1, 0)) }},
		{"PreflightProofBundleV2", "", func() error {
			return first(PreflightProofBundleV2(&ProofBundleV2{}, nil, nil, "data:read", "ns", 0, 0, 0, 0))
		}},
		{"ValidateProofBundleV2Preflight", "", func() error {
			return ValidateProofBundleV2Preflight(&ProofBundleV2{}, ExpectedChallengeV2{}, "data:read", "ns", 0, 0, 0, 0)
		}},
		{"ClaimProofBundleV2", V2ErrConfigurationInvalid, func() error {
			_, _, _, err := ClaimProofBundleV2(ctx, nil, &ProofBundleV2{}, nil, "ns", 0, 0)
			return err
		}},
		{"FinalizeClaimProofBundleV2", V2ErrConfigurationInvalid, func() error { return first(FinalizeClaimProofBundleV2(ctx, nil, nil, nil, nil)) }},
		{"ResolveClaimProofBundleV2AfterAudience", V2ErrConfigurationInvalid, func() error { return first(ResolveClaimProofBundleV2AfterAudience(nil, nil)) }},
		{"ResolveClaimProofBundleV2AfterRate", V2ErrConfigurationInvalid, func() error { return first(ResolveClaimProofBundleV2AfterRate(ctx, nil, nil)) }},
		{"ValidateV2EvaluationProgress", V2ErrMalformed, func() error { return ValidateV2EvaluationProgress(V2EvaluationProgress{}) }},
		{"V2EvaluationInterruptedResult", V2ErrConfigurationInvalid, func() error {
			_, _, err := V2EvaluationInterruptedResult(V2ChallengeClaim{}, -1, V2EvaluationProgress{})
			return err
		}},
		{"RecoverInterruptedClaimV2", V2ErrConfigurationInvalid, func() error { return first(RecoverInterruptedClaimV2(ctx, nil, "")) }},
		{"IssueChallengeV2", V2ErrConfigurationInvalid, func() error { return first(V2ChallengeIssuer{}.IssueChallengeV2(ctx, V2ChallengeIssueRequest{})) }},
		{"LoadExpectedChallengeV2", V2ErrConfigurationInvalid, func() error { return first(LoadExpectedChallengeV2(ctx, nil, "ns", 0, nil)) }},
		{"CheckV2StreamSequence", V2ErrStreamSequenceMismatch, func() error { return CheckV2StreamSequence(true, 5, 5) }},
		{"V2ReleasedDecision.Receipt", V2ErrConfigurationInvalid, func() error { return first((&V2ReleasedDecision{}).Receipt()) }},
		{"VerifyTransactionReceiptV2", V2ErrConfigurationInvalid, func() error {
			return first(VerifyTransactionReceiptV2(ctx, TransactionVerifyRequestV2{Now: -1}, TransactionVerifySourcesV2{}))
		}},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if err == nil {
				t.Fatal("bad input was accepted")
			}
			class := V2ErrorClassOf(err)
			if !listed[class] {
				t.Fatalf("class %q is not in the SPEC-v2 §2.7 list: %v", class, err)
			}
			if c.want != "" && class != c.want {
				t.Fatalf("class %q, want %q: %v", class, c.want, err)
			}
		})
	}

	// The live verifier reports a listed class in its outcome as well.
	outcome, _ := VerifyProofBundleV2(ctx, V2VerifyRequest{Bundle: garbage}, V2VerifyCallbacks{})
	if outcome.Stage != V2StagePreflight || outcome.ErrorClass != V2ErrConfigurationInvalid {
		t.Fatalf("VerifyProofBundleV2 without a claim store: stage %q class %q", outcome.Stage, outcome.ErrorClass)
	}
}
