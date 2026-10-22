package ratify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
			SubjectID: interID, SubjectPubKey: interPub, Scope: []string{"execute:tool", ScopeIdentityDelegate},
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

func (f txVerifyFixtureV2) trust(rootID string, rootPub HybridPublicKey, err error) func(context.Context, []DelegationCertV2) (V2TrustResolution, error) {
	return func(context.Context, []DelegationCertV2) (V2TrustResolution, error) {
		return V2TrustResolution{Available: err == nil, RootID: rootID, RootKey: rootPub}, err
	}
}

// statusSource returns per-certificate results with authenticated-looking
// evidence bound to each issuer, overriding one certificate when asked.
func (f txVerifyFixtureV2) statusSource(override map[string]RevocationStatusResultV2) (func(context.Context, CertificateRefV2) RevocationStatusResultV2, V2StatusRoleBindings) {
	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
	for i, cert := range f.chain {
		keyID := fmt.Sprintf("%064x", i+100)
		roles.StatusKeyIssuers[keyID] = cert.IssuerID
		roles.CurrentStatusKeyIDs[cert.IssuerID] = keyID
	}
	return func(_ context.Context, ref CertificateRefV2) RevocationStatusResultV2 {
		if result, ok := override[ref.CertID]; ok {
			return result
		}
		evidence := StatusEvidenceEntryV2{IssuerID: ref.IssuerID, StatusKeyID: roles.CurrentStatusKeyIDs[ref.IssuerID], Sequence: 1, ObjectType: uint16(v2RevocationList), Digest: "sha384:" + strings.Repeat(ref.IssuerID[:2], 48)}
		return RevocationStatusResultV2{Status: "not_revoked", FreshUntil: 80, Evidence: []StatusEvidenceEntryV2{evidence}}
	}, roles
}

func TestVerifyTransactionReceiptV2PerPartyTrustStatusScope(t *testing.T) {
	base := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, nil, false)
	status, roles := base.statusSource(nil)
	leafIssuer := base.chain[0].IssuerID
	trusted := func(f txVerifyFixtureV2) func(context.Context, []DelegationCertV2) (V2TrustResolution, error) {
		return f.trust(f.rootID, f.rootPub, nil)
	}
	tests := []struct {
		name                 string
		fixture              txVerifyFixtureV2
		now                  int64
		sources              func(f txVerifyFixtureV2) TransactionVerifySourcesV2
		trust, status, scope string
	}{
		{"no sources configured", base, 20, func(txVerifyFixtureV2) TransactionVerifySourcesV2 { return TransactionVerifySourcesV2{} },
			"unavailable", "not_evaluated", "not_evaluated"},
		{"trust error", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, errors.New("trust store down")), Status: status, StatusRoles: roles}
		}, "unavailable", "not_evaluated", "not_evaluated"},
		{"other root", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{Trust: f.trust(leafIssuer, f.chain[0].IssuerPubKey, nil), Status: status, StatusRoles: roles}
		}, "untrusted", "not_evaluated", "not_evaluated"},
		{"trust only", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{Trust: trusted(f)}
		}, "trusted", "unavailable", "covered"},
		{"current", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{Trust: trusted(f), Status: status, StatusRoles: roles}
		}, "trusted", "current", "covered"},
		{"current result past its fresh_until is stale", base, 80, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			return TransactionVerifySourcesV2{Trust: trusted(f), Status: status, StatusRoles: roles}
		}, "trusted", "stale", "covered"},
		{"revoked leaf", base, 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			src, r := f.statusSource(map[string]RevocationStatusResultV2{"leaf": {Status: "revoked", Evidence: []StatusEvidenceEntryV2{{IssuerID: leafIssuer, StatusKeyID: fmt.Sprintf("%064x", 100), Sequence: 2, ObjectType: uint16(v2RevocationPush), Digest: "sha384:" + strings.Repeat("c", 96)}}}})
			return TransactionVerifySourcesV2{Trust: trusted(f), Status: src, StatusRoles: r}
		}, "trusted", "revoked", "covered"},
		{"scope not covered", buildTxVerifyFixtureV2(t, []string{"data:read"}, nil, false), 20, func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
			src, r := f.statusSource(nil)
			return TransactionVerifySourcesV2{Trust: trusted(f), Status: src, StatusRoles: r}
		}, "trusted", "current", "not_covered"},
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
			if p.TrustAssessment != tt.trust || p.StatusAssessment != tt.status || p.ScopeAssessment != tt.scope || p.Freshness != FreshnessUnverifiedV2 {
				t.Fatalf("party = %+v", p)
			}
		})
	}
}

func TestVerifyTransactionReceiptV2DoesNotEvaluateRequestConstraints(t *testing.T) {
	amount := []ConstraintV2{{Type: ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 1}}
	f := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, amount, false)
	src, roles := f.statusSource(nil)
	got, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20},
		TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil), Status: src, StatusRoles: roles})
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
	_, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20}, TransactionVerifySourcesV2{Trust: trust})
	if V2ErrorClassOf(err) != V2ErrTransactionPartyMismatch || !strings.Contains(err.Error(), "no delegation certificates") || called {
		t.Fatalf("empty-delegation party: class=%q err=%v providerCalled=%t", V2ErrorClassOf(err), err, called)
	}
}

func TestVerifyTransactionReceiptV2RejectsBadInputs(t *testing.T) {
	f := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, nil, false)
	if _, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: -1}, TransactionVerifySourcesV2{}); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Fatalf("negative time: %v", err)
	}
	tampered := bytes.Replace(f.wire, []byte(`"tx-verify-1"`), []byte(`"tx-verify-2"`), 1)
	if _, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: tampered, Now: 20}, TransactionVerifySourcesV2{}); err == nil {
		t.Fatal("tampered transaction receipt verified")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyTransactionReceiptV2(ctx, TransactionVerifyRequestV2{Receipt: f.wire, Now: 20}, TransactionVerifySourcesV2{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}
