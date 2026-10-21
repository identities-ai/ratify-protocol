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

func TestVerifyTransactionReceiptV2PerPartyTrustAndStatus(t *testing.T) {
	base := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, nil, false)
	status, roles := base.statusSource(nil)
	leafIssuer := base.chain[0].IssuerID
	tests := []struct {
		name          string
		fixture       txVerifyFixtureV2
		now           int64
		sources       func(f txVerifyFixtureV2) TransactionVerifySourcesV2
		context       map[string]ConstraintContextV2
		trust, status string
		freshness     string
		authorization string
		reason        string
		validUntil    int64
	}{
		{name: "no sources configured", fixture: base, now: 20,
			sources: func(txVerifyFixtureV2) TransactionVerifySourcesV2 { return TransactionVerifySourcesV2{} },
			trust:   "unknown", status: "not_evaluated", freshness: "unknown", authorization: "unknown", reason: "trust_unavailable"},
		{name: "trust only", fixture: base, now: 20,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil)}
			},
			trust: "trusted", status: "unknown", freshness: "unknown", authorization: "unknown", reason: "status_unavailable"},
		{name: "trust error", fixture: base, now: 20,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, errors.New("trust store down")), Status: status, StatusRoles: roles}
			},
			trust: "unavailable", status: "not_evaluated", freshness: "unknown", authorization: "unknown", reason: "trust_unavailable"},
		{name: "other root", fixture: base, now: 20,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				return TransactionVerifySourcesV2{Trust: f.trust(leafIssuer, f.chain[0].IssuerPubKey, nil), Status: status, StatusRoles: roles}
			},
			trust: "untrusted", status: "not_evaluated", freshness: "unknown", authorization: "denied", reason: "unauthorized"},
		{name: "authorized", fixture: base, now: 20,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil), Status: status, StatusRoles: roles}
			},
			trust: "trusted", status: "current", freshness: "fresh", authorization: "authorized", reason: "authorized", validUntil: 80},
		{name: "revoked leaf", fixture: base, now: 20,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				src, r := f.statusSource(map[string]RevocationStatusResultV2{"leaf": {Status: "revoked", Evidence: []StatusEvidenceEntryV2{{IssuerID: leafIssuer, StatusKeyID: fmt.Sprintf("%064x", 100), Sequence: 2, ObjectType: uint16(v2RevocationPush), Digest: "sha384:" + strings.Repeat("c", 96)}}}})
				return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil), Status: src, StatusRoles: r}
			},
			trust: "trusted", status: "revoked", freshness: "unknown", authorization: "denied", reason: "delegation_revoked"},
		{name: "stale status", fixture: base, now: 20,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				src, r := f.statusSource(nil)
				stale := src(context.Background(), CertificateRefV2{IssuerID: f.chain[1].IssuerID, CertID: "root"})
				stale.Status, stale.Reason = "indeterminate", "stale"
				src2, _ := f.statusSource(map[string]RevocationStatusResultV2{"root": stale})
				return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil), Status: src2, StatusRoles: r}
			},
			trust: "trusted", status: "stale", freshness: "stale", authorization: "unknown", reason: "status_stale"},
		{name: "expired delegation", fixture: base, now: 95,
			sources: func(f txVerifyFixtureV2) TransactionVerifySourcesV2 {
				return TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil), Status: status, StatusRoles: roles}
			},
			trust: "trusted", status: "not_evaluated", freshness: "unknown", authorization: "denied", reason: "delegation_expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: tt.fixture.wire, Now: tt.now, PartyContext: tt.context}, tt.sources(tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Parties) != 1 {
				t.Fatalf("parties = %+v", got.Parties)
			}
			p := got.Parties[0]
			if p.TrustAssessment != tt.trust || p.StatusAssessment != tt.status || p.Freshness != tt.freshness || p.Authorization != tt.authorization || p.Reason != tt.reason || p.ValidUntil != tt.validUntil {
				t.Fatalf("party = %+v", p)
			}
			if got.AllAuthorized != (tt.authorization == "authorized") {
				t.Fatalf("AllAuthorized = %t for %s", got.AllAuthorized, tt.authorization)
			}
		})
	}
}

func TestVerifyTransactionReceiptV2ScopeAndConstraints(t *testing.T) {
	run := func(t *testing.T, f txVerifyFixtureV2, ctx map[string]ConstraintContextV2) TransactionPartyVerificationV2 {
		t.Helper()
		status, roles := f.statusSource(nil)
		got, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20, PartyContext: ctx},
			TransactionVerifySourcesV2{Trust: f.trust(f.rootID, f.rootPub, nil), Status: status, StatusRoles: roles})
		if err != nil {
			t.Fatal(err)
		}
		return got.Parties[0]
	}
	if p := run(t, buildTxVerifyFixtureV2(t, []string{"data:read"}, nil, false), nil); p.Authorization != "denied" || p.Reason != "scope_denied" {
		t.Fatalf("leaf scope without the signed required_scope = %+v", p)
	}
	amount := []ConstraintV2{{Type: ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 7_000_000}}
	f := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, amount, false)
	if p := run(t, f, nil); p.Authorization != "unknown" || p.Reason != "constraint_unverifiable" {
		t.Fatalf("absent authenticated amount = %+v", p)
	}
	if p := run(t, f, map[string]ConstraintContextV2{"buyer": {HasAmount: true, RequestedAmountMicros: 7_000_001, RequestedCurrency: "USD"}}); p.Authorization != "denied" || p.Reason != "constraint_denied" {
		t.Fatalf("amount over the limit = %+v", p)
	}
	if p := run(t, f, map[string]ConstraintContextV2{"buyer": {HasAmount: true, RequestedAmountMicros: 7_000_000, RequestedCurrency: "USD"}}); p.Authorization != "authorized" {
		t.Fatalf("amount at the limit = %+v", p)
	}
	rate := []ConstraintV2{{Type: ConstraintMaxRate, Count: 1, WindowS: 60}}
	if p := run(t, buildTxVerifyFixtureV2(t, []string{"execute:tool"}, rate, false), nil); p.Authorization != "unknown" || p.Reason != "constraint_unverifiable" {
		t.Fatalf("max_rate cannot be exercised for a completed transaction: %+v", p)
	}
	geo := []ConstraintV2{{Type: ConstraintGeoCircle, Params: map[string]any{"radius_mm": 1}}}
	if p := run(t, buildTxVerifyFixtureV2(t, []string{"execute:tool"}, geo, false), nil); p.Authorization != "denied" || p.Reason != "constraint_unknown" {
		t.Fatalf("unregistered geo_circle must fail closed: %+v", p)
	}
}

func TestVerifyTransactionReceiptV2RejectsEmptyDelegationParty(t *testing.T) {
	f := buildTxVerifyFixtureV2(t, nil, nil, true)
	_, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20}, TransactionVerifySourcesV2{})
	if V2ErrorClassOf(err) != V2ErrTransactionPartyMismatch || !strings.Contains(err.Error(), "no delegation certificates") {
		t.Fatalf("empty-delegation party: class=%q err=%v", V2ErrorClassOf(err), err)
	}
}

func TestVerifyTransactionReceiptV2RejectsBadInputs(t *testing.T) {
	f := buildTxVerifyFixtureV2(t, []string{"execute:tool"}, nil, false)
	if _, err := VerifyTransactionReceiptV2(context.Background(), TransactionVerifyRequestV2{Receipt: f.wire, Now: 20, FutureSkewSeconds: 301}, TransactionVerifySourcesV2{}); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Fatalf("future skew above 300 seconds: %v", err)
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
