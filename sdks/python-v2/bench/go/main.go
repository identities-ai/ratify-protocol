// Go counterpart of sdks/python-v2/bench/bench_v2.py: its cert_signature_verify,
// decision and dual_root_decision measurements over the same flow, for
// comparing the SDKs on one host.
//
// Run from the repository root: go run ./sdks/python-v2/bench/go [-json out.json] [-scale 1]
//
// DEVELOPMENT ONLY: the claim store, receipt log, checkpoint, journal and
// challenge issuance store are the in-memory v2reference stores.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

const (
	start = int64(1800000000)
	epoch = int64(1)
	logID = "00000000000000000000000000000001"
	scope = "payments:send"
)

var iterations = map[string]int{"cert_signature_verify": 200, "decision": 50, "dual_root_decision": 25}

// key is deterministic hybrid keypair number n (the Python bench's _key).
func key(n int) (ratify.HybridPublicKey, ratify.HybridPrivateKey) {
	var ed, ml [32]byte
	copy(ed[:], bytes.Repeat([]byte{byte(n)}, 32))
	copy(ml[:], bytes.Repeat([]byte{byte(n + 100)}, 32))
	pub, priv, err := ratify.HybridKeypairFromSeeds(ed, ml)
	must(err)
	return pub, priv
}

func keyID(pub ratify.HybridPublicKey) string {
	id, err := ratify.KeyIDV2(pub)
	must(err)
	return id
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type presentation struct {
	challenge []byte
	wire      []byte
}

// flow is one root's quickstart verifier flow against a shared reference store.
type flow struct {
	ctx         context.Context
	store       *v2reference.Store
	journal     *v2reference.JournalStore
	namespace   string
	agentPub    ratify.HybridPublicKey
	agentPriv   ratify.HybridPrivateKey
	agentID     string
	verifierPub ratify.HybridPublicKey
	verifierID  string
	rootPub     ratify.HybridPublicKey
	rootID      string
	certs       []ratify.DelegationCertV2 // leaf first
	statusKeys  map[string]ratify.V2StatusKeyConfig
	statusWires map[string][]byte
	issuance    *v2reference.TestOnlyChallengeIssuanceStore
	policy      *ratify.V2ContextPolicy
}

type holder struct {
	pub  ratify.HybridPublicKey
	priv ratify.HybridPrivateKey
}

func newFlow(ctx context.Context, store *v2reference.Store, journal *v2reference.JournalStore,
	verifierPub ratify.HybridPublicKey, agent holder, rootN, depth int, namespace string) *flow {
	f := &flow{
		ctx: ctx, store: store, journal: journal, namespace: namespace,
		agentPub: agent.pub, agentPriv: agent.priv, agentID: keyID(agent.pub),
		verifierPub: verifierPub, verifierID: keyID(verifierPub),
		statusKeys: map[string]ratify.V2StatusKeyConfig{}, statusWires: map[string][]byte{},
		issuance: v2reference.NewTestOnlyChallengeIssuanceStore(),
	}
	rootPub, rootPriv := key(rootN)
	statusPub, statusPriv := key(rootN + 1)
	f.rootPub, f.rootID = rootPub, keyID(rootPub)
	// Chain from the root down to the agent; depth 2 adds one intermediate.
	holders := []holder{{rootPub, rootPriv}}
	for i := 0; i < depth-1; i++ {
		p, k := key(rootN + 2 + i)
		holders = append(holders, holder{p, k})
	}
	holders = append(holders, agent)
	certs := make([]ratify.DelegationCertV2, 0, depth)
	for i := 0; i < depth; i++ {
		issuer, subject := holders[i], holders[i+1]
		// Every certificate above the leaf must also grant identity:delegate.
		sc := []string{scope}
		if i != depth-1 {
			sc = []string{scope, "identity:delegate"}
		}
		cert, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{
			Version: 2, CertID: fmt.Sprintf("%s-cert-%d", namespace, i),
			IssuerID: keyID(issuer.pub), IssuerPubKey: issuer.pub,
			SubjectID: keyID(subject.pub), SubjectPubKey: subject.pub,
			Scope:       sc,
			Constraints: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 50_000_000}},
			IssuedAt:    start, ExpiresAt: start + 86400,
		}, issuer.priv)
		must(err)
		certs = append(certs, *cert)
	}
	for i := len(certs) - 1; i >= 0; i-- {
		f.certs = append(f.certs, certs[i])
	}
	type roleKey struct {
		role string
		pub  ratify.HybridPublicKey
	}
	roles := []roleKey{{"issuer", rootPub}, {"delegation", agent.pub}}
	for _, h := range holders[1 : len(holders)-1] {
		roles = append(roles, roleKey{"delegation", h.pub})
	}
	for _, r := range roles {
		_, err := ratify.RecordSecurityKeyRoleV2(ctx, journal, r.role, r.pub)
		must(err)
	}
	// Every issuer in the chain publishes signed status under its own key.
	for j, h := range holders[:len(holders)-1] {
		sPub, sPriv := statusPub, statusPriv
		if j != 0 {
			sPub, sPriv = key(rootN + 50 + j)
		}
		issuerID := keyID(h.pub)
		_, err := ratify.ConfigureStatusKeyEpochV2(ctx, journal, issuerID, 1, sPub)
		must(err)
		publisher, err := ratify.NewV2StatusPublisherWithKey(ctx, journal, h.pub, sPriv, 3600)
		must(err)
		genesis, err := publisher.Genesis(ctx, start)
		must(err)
		wire, err := ratify.EncodeRevocationListV2(genesis.List)
		must(err)
		f.statusWires[issuerID] = wire
		f.statusKeys[issuerID] = ratify.V2StatusKeyConfig{Epoch: 1, Key: sPub}
	}
	policy, err := ratify.NewV2ContextPolicy("example.quickstart/v1", false, nil, nil)
	must(err)
	f.policy = policy
	return f
}

// present issues a challenge and signs a presentation (agent side, untimed).
func (f *flow) present() presentation {
	issuer := ratify.V2ChallengeIssuer{Clock: f.store, Store: f.issuance}
	agentPub := f.agentPub
	challenge, err := issuer.IssueChallengeV2(f.ctx, ratify.V2ChallengeIssueRequest{
		VerifierNamespace: f.namespace, ReplayEpoch: epoch, VerifierID: f.verifierID,
		LifetimeSeconds: 120, ExpectedAgentID: f.agentID, ExpectedAgentPublicKey: &agentPub,
	})
	must(err)
	bundle, err := ratify.SignProofBundleV2(&ratify.ProofBundleV2{
		Version: 2, VerifierID: f.verifierID, AgentID: f.agentID, AgentPubKey: f.agentPub,
		Delegations: f.certs, Challenge: challenge.Value, ChallengeAt: challenge.IssuedAt,
	}, f.agentPriv)
	must(err)
	wire, err := ratify.EncodeProofBundleV2(bundle)
	must(err)
	return presentation{bundle.Challenge, wire}
}

// decide verifies, commits, publishes, acknowledges and releases one decision.
func (f *flow) decide(p presentation) {
	ctx, store := f.ctx, f.store
	expected, err := ratify.LoadExpectedChallengeV2(ctx, f.issuance, f.namespace, epoch, p.challenge)
	must(err)
	req := ratify.V2VerifyRequest{
		Bundle: p.wire, Expected: expected, ContextPolicy: f.policy,
		RequiredScope: scope, VerifierNamespace: f.namespace, ReplayEpoch: epoch,
		Now: store.Now(), MaxChallengeAgeSeconds: 300, FutureSkewSeconds: 5,
		Context:      ratify.ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 12_500_000, RequestedCurrency: "USD"},
		TZDBVersion:  ratify.TZDBVersionV2,
		StatusKeys:   f.statusKeys,
		StatusPolicy: ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 3600, ClockSkewSeconds: 5},
	}
	cb := ratify.V2VerifyCallbacks{
		ClaimStore: store,
		Trust: func(_ context.Context, chain []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
			if chain[len(chain)-1].IssuerID == f.rootID {
				return ratify.V2TrustResolution{Outcome: ratify.V2TrustTrusted, RootKey: f.rootPub}, nil
			}
			return ratify.V2TrustResolution{Outcome: ratify.V2TrustUntrusted}, nil
		},
		StatusEvidence: func(_ context.Context, sr ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
			return ratify.V2StatusEvidenceBatch{Objects: []ratify.V2StatusEvidenceObject{{ObjectType: 3, Wire: f.statusWires[sr.IssuerID]}}}, nil
		},
		StatusJournal: f.journal,
	}
	outcome, err := ratify.VerifyProofBundleV2(ctx, req, cb)
	must(err)
	if outcome.Stage != ratify.V2StageCommitted {
		panic(fmt.Sprintf("verify stopped at %s: %v", outcome.Stage, outcome.Error))
	}
	receiptWire, err := store.PublishV2Receipt(ctx, outcome.Committed.ClaimID(), outcome.Committed.ReceiptBody())
	must(err)
	_, err = ratify.DecodeVerificationReceiptV2(receiptWire)
	must(err)
	result := ratify.ReleaseV2Decision(ctx, outcome.Committed, receiptWire, ratify.V2ReleaseConfig{
		VerifierPublicKey: f.verifierPub, LogID: logID, ClaimStore: store, Checkpoint: store,
	})
	if result.Status != ratify.V2ReleaseReleased || !result.Decision.Allowed(ctx, store) {
		panic(fmt.Sprintf("release %s: %s", result.Status, result.Reason))
	}
}

type bench struct {
	store                        *v2reference.Store
	clock                        int64
	single, authority, admission *flow
}

func newBench() *bench {
	ctx := context.Background()
	verifierPub, verifierPriv := key(1)
	agentPub, agentPriv := key(2)
	agent := holder{agentPub, agentPriv}
	store, err := v2reference.NewStore(start, 30, logID, verifierPriv)
	must(err)
	journal, err := v2reference.NewJournalStore()
	must(err)
	_, err = ratify.RecordSecurityKeyRoleV2(ctx, journal, "verifier", verifierPub)
	must(err)
	return &bench{
		store: store, clock: start,
		single:    newFlow(ctx, store, journal, verifierPub, agent, 10, 1, "bench-single"),
		authority: newFlow(ctx, store, journal, verifierPub, agent, 20, 2, "bench-authority"),
		admission: newFlow(ctx, store, journal, verifierPub, agent, 30, 1, "bench-admission"),
	}
}

// tick advances the reference clock, which never moves backward.
func (b *bench) tick() {
	b.clock += 2
	b.store.SetTime(b.clock)
}

// run returns per-operation latencies for n operations.
func (b *bench) run(name string, n int) []time.Duration {
	var ops []func()
	switch name {
	case "cert_signature_verify":
		// VerifyDelegationCertV2Signature: the certificate's structure and
		// key-ID checks plus one strict hybrid verification (Go keeps the raw
		// statement verifier unexported).
		cert := b.single.certs[0]
		for i := 0; i < n; i++ {
			ops = append(ops, func() { must(ratify.VerifyDelegationCertV2Signature(&cert)) })
		}
	case "decision":
		b.tick()
		ps := make([]presentation, n)
		for i := range ps {
			ps[i] = b.single.present()
		}
		b.tick()
		for _, p := range ps {
			ops = append(ops, func() { b.single.decide(p) })
		}
	case "dual_root_decision":
		b.tick()
		type pair struct{ a, b presentation }
		ps := make([]pair, n)
		for i := range ps {
			ps[i] = pair{b.authority.present(), b.admission.present()}
		}
		b.tick()
		for _, p := range ps {
			ops = append(ops, func() { b.authority.decide(p.a); b.admission.decide(p.b) })
		}
	default:
		panic(name)
	}
	out := make([]time.Duration, 0, n)
	for _, op := range ops {
		t0 := time.Now()
		op()
		out = append(out, time.Since(t0))
	}
	return out
}

type summary struct {
	N       int     `json:"n"`
	OpsPerS float64 `json:"ops_per_s"`
	MeanMs  float64 `json:"mean_ms"`
	P50Ms   float64 `json:"p50_ms"`
	P95Ms   float64 `json:"p95_ms"`
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func summarize(lat []time.Duration) summary {
	var total time.Duration
	for _, d := range lat {
		total += d
	}
	ordered := append([]time.Duration(nil), lat...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	p95 := int(float64(len(ordered)) * 0.95)
	if p95 > len(ordered)-1 {
		p95 = len(ordered) - 1
	}
	return summary{
		N:       len(lat),
		OpsPerS: round(float64(len(lat))/total.Seconds(), 2),
		MeanMs:  round(ms(total)/float64(len(lat)), 3),
		P50Ms:   round(ms(ordered[len(ordered)/2]), 3),
		P95Ms:   round(ms(ordered[p95]), 3),
	}
}

func main() {
	jsonPath := flag.String("json", "", "write results as JSON to this path")
	scale := flag.Float64("scale", 1.0, "multiply iteration counts")
	flag.Parse()

	b := newBench()
	names := []string{"cert_signature_verify", "decision", "dual_root_decision"}
	results := map[string]summary{}
	for _, name := range names {
		n := int(float64(iterations[name]) * *scale)
		if n < 1 {
			n = 1
		}
		b.run(name, min(n, 3)) // warm-up
		results[name] = summarize(b.run(name, n))
	}
	fmt.Printf("go %s on %s %s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("%-22s %5s %10s %10s %10s %10s\n", "measurement", "n", "ops/s", "mean ms", "p50 ms", "p95 ms")
	for _, name := range names {
		r := results[name]
		fmt.Printf("%-22s %5d %10v %10v %10v %10v\n", name, r.N, r.OpsPerS, r.MeanMs, r.P50Ms, r.P95Ms)
	}
	if *jsonPath != "" {
		report := map[string]any{
			"sdk": "go", "go": runtime.Version(), "machine": runtime.GOOS + " " + runtime.GOARCH, "results": results,
		}
		data, err := json.MarshalIndent(report, "", "  ")
		must(err)
		must(os.WriteFile(*jsonPath, append(data, '\n'), 0o644))
	}
}
