package ratify

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type txVerifyFixtureV2 struct {
	wire    []byte
	rootID  string
	rootPub HybridPublicKey
	chain   []DelegationCertV2
}

// buildTxVerifyFixtureV2 builds a one-party receipt whose proof chain is
// root (execute:tool, identity:delegate) -> intermediate -> agent. With
// emptyChain the party proof carries no delegation at all.
func buildTxVerifyFixtureV2(t *testing.T, leafScope []string, rootConstraints []ConstraintV2, emptyChain bool) txVerifyFixtureV2 {
	t.Helper()
	return buildTxVerifyFixtureWithRootScopeV2(t, []string{"execute:tool", ScopeIdentityDelegate}, leafScope, rootConstraints, emptyChain)
}

func buildTxVerifyFixtureWithRootScopeV2(t *testing.T, rootScope, leafScope []string, rootConstraints []ConstraintV2, emptyChain bool) txVerifyFixtureV2 {
	t.Helper()
	rootPub, rootKey, _ := GenerateHybridKeypair()
	interPub, interKey, _ := GenerateHybridKeypair()
	agentPub, agentKey, _ := GenerateHybridKeypair()
	rootID, _ := KeyIDV2(rootPub)
	interID, _ := KeyIDV2(interPub)
	agentID, _ := KeyIDV2(agentPub)
	receipt := &TransactionReceiptV2{
		Version: 2, TransactionID: "tx-verify-1", CreatedAt: 10,
		TermsSchemaURI: "https://example.test/schemas/payment/v1", TermsCanonicalJSON: []byte(`{"amount":7}`),
		Parties: []TransactionReceiptPartyV2{{
			PartyID: "buyer", Role: "buyer", AgentID: agentID, AgentPubKey: agentPub,
			VerifierID: strings.Repeat("a", 64), WorkspaceID: "7c66c74c-6a2e-4363-9c05-22651535803c",
			SessionID: "session-1", InvocationID: "invoke-1", RequiredScope: "execute:tool",
		}},
	}
	party := &receipt.Parties[0]
	session, err := BuildSessionContextV2(SessionContextV2Inputs{
		VerifierID: party.VerifierID, WorkspaceID: party.WorkspaceID, AgentID: agentID,
		SessionID: party.SessionID, InvocationID: party.InvocationID,
		RequestHash: transactionPartyRequestHashV2(transactionContextHashV2(receipt), party.RequiredScope),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rootConstraints == nil {
		rootConstraints = []ConstraintV2{}
	}
	var chain []DelegationCertV2
	if !emptyChain {
		root, err := SignDelegationCertV2(&DelegationCertV2{Version: 2, CertID: "root", IssuerID: rootID, IssuerPubKey: rootPub,
			SubjectID: interID, SubjectPubKey: interPub, Scope: rootScope,
			Constraints: rootConstraints, IssuedAt: 1, ExpiresAt: 100}, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := SignDelegationCertV2(&DelegationCertV2{Version: 2, CertID: "leaf", IssuerID: interID, IssuerPubKey: interPub,
			SubjectID: agentID, SubjectPubKey: agentPub, Scope: leafScope, Constraints: []ConstraintV2{}, IssuedAt: 1, ExpiresAt: 90}, interKey)
		if err != nil {
			t.Fatal(err)
		}
		chain = []DelegationCertV2{*leaf, *root}
	}
	bundle := &ProofBundleV2{Version: 2, VerifierID: party.VerifierID, AgentID: agentID, AgentPubKey: agentPub,
		Delegations: chain, Challenge: bytes.Repeat([]byte{0x42}, 32), ChallengeAt: 10, SessionContext: &session}
	if chain == nil {
		bundle.Delegations = []DelegationCertV2{}
	}
	if party.ProofBundle, err = SignProofBundleV2(bundle, agentKey); err != nil {
		t.Fatal(err)
	}
	if party.ProofBundleHash, err = BundleHashV2(party.ProofBundle); err != nil {
		t.Fatal(err)
	}
	signable, err := transactionReceiptV2SignableBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signV2Statement(v2TransactionPartyStatement, signable, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt.PartySignatures = []TransactionReceiptSignatureV2{{PartyID: "buyer", Signature: signature}}
	wire, err := encodeTransactionReceiptV2Canonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return txVerifyFixtureV2{wire: wire, rootID: rootID, rootPub: rootPub, chain: chain}
}

func (f txVerifyFixtureV2) trust(rootPub HybridPublicKey, outcome V2TrustOutcome, err error) func(context.Context, []DelegationCertV2) (V2TrustResolution, error) {
	return func(context.Context, []DelegationCertV2) (V2TrustResolution, error) {
		return V2TrustResolution{Outcome: outcome, RootKey: rootPub}, err
	}
}

var txStatusPolicyV2 = RevocationStatusPolicyV2{MaxListLifetimeSeconds: 86400, MaxStatusAgeSeconds: 86400}

// statusSources configures one status key per chain issuer in an anchored
// journal and serves one signed full list per issuer (sequence 1, valid
// until 80) that revokes the named certificates of that issuer.
func (f txVerifyFixtureV2) statusSources(t *testing.T, revoked map[string]bool) TransactionVerifySourcesV2 {
	t.Helper()
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	keys := map[string]V2StatusKeyConfig{}
	lists := map[string][]byte{}
	for _, cert := range f.chain {
		if _, done := keys[cert.IssuerID]; done {
			continue
		}
		pub, priv, err := GenerateHybridKeypair()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ConfigureStatusKeyEpochV2(ctx, store, cert.IssuerID, 1, pub); err != nil {
			t.Fatal(err)
		}
		keys[cert.IssuerID] = V2StatusKeyConfig{Epoch: 1, Key: pub}
		entries := []RevokedCertV2{}
		for _, c := range f.chain {
			if c.IssuerID == cert.IssuerID && revoked[c.CertID] {
				entries = append(entries, RevokedCertV2{CertID: c.CertID})
			}
		}
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: cert.IssuerID, UpdatedAt: 5, NextUpdate: 80, Sequence: 1, Revoked: entries}, cert.IssuerID, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		if lists[cert.IssuerID], err = EncodeRevocationListV2(list); err != nil {
			t.Fatal(err)
		}
	}
	provider := func(_ context.Context, req V2StatusEvidenceRequest) (V2StatusEvidenceBatch, error) {
		return V2StatusEvidenceBatch{Objects: []V2StatusEvidenceObject{{ObjectType: uint16(v2RevocationList), Wire: lists[req.IssuerID]}}}, nil
	}
	return TransactionVerifySourcesV2{Trust: f.trust(f.rootPub, V2TrustTrusted, nil), StatusEvidence: provider, StatusJournal: store, StatusKeys: keys, StatusPolicy: txStatusPolicyV2}
}

func TestVerifyTransactionReceiptV2PerPartyTrustStatusScope(t *testing.T) {
	base := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, nil, false)
	leafPub := base.chain[0].IssuerPubKey
	tests := []struct {
		name                             string
		fixture                          txVerifyFixtureV2
		now                              int64
		sources                          func(f txVerifyFixtureV2) TransactionVerifySourcesV2
		trust, delegation, status, scope string
		evidence                         int
	}{
		{"no sources configured", base, 20, func(txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{StatusPolicy: txStatusPolicyV2}
		}, "unavailable", "not_evaluated", "not_evaluated", "not_evaluated", 0},
		{"trust error", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			s := f.statusSources(t, nil)
			s.Trust = f.trust(f.rootPub, V2TrustTrusted, errors.New("trust store down"))
			return s
		}, "unavailable", "not_evaluated", "not_evaluated", "not_evaluated", 0},
		{"ambiguous trust", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			s := f.statusSources(t, nil)
			s.Trust = f.trust(f.rootPub, V2TrustAmbiguous, nil)
			return s
		}, "unavailable", "not_evaluated", "not_evaluated", "not_evaluated", 0},
		{"trusted outcome naming another root is not trusted", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			s := f.statusSources(t, nil)
			s.Trust = f.trust(leafPub, V2TrustTrusted, nil)
			return s
		}, "unavailable", "not_evaluated", "not_evaluated", "not_evaluated", 0},
		{"untrusted", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			s := f.statusSources(t, nil)
			s.Trust = f.trust(f.rootPub, V2TrustUntrusted, nil)
			return s
		}, "untrusted", "not_evaluated", "not_evaluated", "not_evaluated", 0},
		{"trust only", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{Trust: f.trust(f.rootPub, V2TrustTrusted, nil), StatusPolicy: txStatusPolicyV2}
		}, "trusted", "current", "unavailable", "covered", 0},
		{"current", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 { return f.statusSources(t, nil) },
			"trusted", "current", "current", "covered", 2},
		{"a list first seen after its next_update is unavailable, and the leaf delegation expired", base, 90, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 { return f.statusSources(t, nil) },
			"trusted", "expired", "unavailable", "covered", 2},
		{"revoked leaf", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return f.statusSources(t, map[string]bool{"leaf": true})
		},
			"trusted", "current", "revoked", "covered", 2},
		{"future-dated delegation is invalid", base, 0, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 { return f.statusSources(t, nil) },
			"trusted", "invalid", "unavailable", "covered", 2},
		{"scope not covered", buildTxVerifyFixtureV2(t, []string{"data:read"}, nil, false), 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 { return f.statusSources(t, nil) },
			"trusted", "current", "current", "not_covered", 2},
		{"parent without identity:delegate", buildTxVerifyFixtureWithRootScopeV2(t, []string{"execute:tool"}, []string{"execute:tool"}, nil, false), 20,
			func(f txVerifyFixtureV2) TransactionVerifySourcesV2 { return f.statusSources(t, nil) },
			"trusted", "current", "current", "delegation_not_authorized", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: tt.fixture.wire, Now: tt.now}, tt.sources(tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if got.Actionable || len(got.Parties) != 1 {
				t.Fatalf("result = %+v", got)
			}
			p := got.Parties[0]
			if p.TrustAssessment != tt.trust || p.DelegationAssessment != tt.delegation || p.StatusAssessment != tt.status || p.ScopeAssessment != tt.scope ||
				p.Freshness != FreshnessUnverifiedV2 || len(p.StatusEvidence) != tt.evidence {
				t.Fatalf("party = %+v", p)
			}
			if (p.DelegationExpiresAt == nil) != (tt.delegation == "not_evaluated") || (p.DelegationExpiresAt != nil && *p.DelegationExpiresAt != 90) {
				t.Fatalf("delegation_expires_at = %v", p.DelegationExpiresAt)
			}
		})
	}
}

func TestVerifyTransactionReceiptV2DoesNotEvaluateRequestConstraints(t *testing.T) {
	amount := []ConstraintV2{{Type: ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 1}}
	f := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, amount, false)
	got, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20}, f.statusSources(t, nil))
	if err != nil || got.Parties[0].ScopeAssessment != "covered" || got.Actionable {
		t.Fatalf("constraints must not be evaluated here: %+v %v", got, err)
	}
}

func TestVerifyTransactionReceiptV2RejectsEmptyDelegationParty(t *testing.T) {
	f := buildTxVerifyFixtureV2(t, nil, nil, true)
	called := false
	trust := func(context.Context, []DelegationCertV2) (V2TrustResolution, error) {
		called = true
		return V2TrustResolution{}, nil
	}
	_, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20}, TransactionVerifySourcesV2{Trust: trust, StatusPolicy: txStatusPolicyV2})
	if V2ErrorClassOf(err) != V2ErrTransactionPartyMismatch || !strings.Contains(err.Error(), "no delegation certificates") || called {
		t.Fatalf("empty-delegation party: class=%q err=%v providerCalled=%t", V2ErrorClassOf(err), err, called)
	}
}

func TestVerifyTransactionReceiptV2RejectsBadInputs(t *testing.T) {
	f := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, nil, false)
	if _, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: -1}, TransactionVerifySourcesV2{StatusPolicy: txStatusPolicyV2}); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Fatalf("negative time: %v", err)
	}
	tampered := bytes.Replace(f.wire, []byte(`"tx-verify-1"`), []byte(`"tx-verify-2"`), 1)
	if _, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: tampered, Now: 20}, TransactionVerifySourcesV2{StatusPolicy: txStatusPolicyV2}); err == nil {
		t.Fatal("tampered transaction receipt verified")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyTransactionReceiptV2(ctx, TransactionVerifyRequestV2{Receipt: f.wire, Now: 20}, TransactionVerifySourcesV2{StatusPolicy: txStatusPolicyV2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}
