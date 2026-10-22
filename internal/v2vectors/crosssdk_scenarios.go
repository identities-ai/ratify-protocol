package v2vectors

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// Cross-SDK verifier and release scenarios (SPEC-v2 §8.1). The producing SDK
// signs every input with its own fresh keys, runs each scenario through its
// own verifier, reference store and release gate, and records the outcome;
// every other SDK replays the same inputs and must reach the same committed
// outcome and release result, releasing with the producer's signed receipt.

// crossScenarioLogID is the receipt log of every cross-SDK scenario.
const crossScenarioLogID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01"

// CrossScenarioNames are the scenarios every cross-SDK fixture contains.
var CrossScenarioNames = []string{"allow_released", "deny_revoked_released", "indeterminate_status_unavailable_released", "allow_withheld_past_horizon"}

type crossScenarioConfigJSON struct {
	VerifierNamespace      string           `json:"verifier_namespace"`
	ReplayEpoch            int64            `json:"replay_epoch"`
	VerifierKey            string           `json:"verifier_key"`
	ReceiptLogID           string           `json:"receipt_log_id"`
	LeaseSeconds           int64            `json:"lease_seconds"`
	MaxChallengeAgeSeconds int64            `json:"max_challenge_age_seconds"`
	FutureSkewSeconds      int64            `json:"future_skew_seconds"`
	StatusPolicy           statusPolicyJSON `json:"status_policy"`
	TZDBVersion            string           `json:"tzdb_version"`
}

type crossStatusKeyJSON struct {
	Epoch uint64 `json:"epoch"`
	Key   string `json:"key"`
}

type crossReleaseJSON struct {
	Status      string  `json:"status"`
	Reason      *string `json:"reason"`
	Decision    *string `json:"decision"`
	ReleaseTime *int64  `json:"release_time"`
}

type crossScenarioExpectJSON struct {
	ReceiptBodyB64   string           `json:"receipt_body_b64"`
	AllowHorizon     *int64           `json:"allow_horizon"`
	SignedReceiptB64 string           `json:"signed_receipt_b64"`
	Release          crossReleaseJSON `json:"release"`
}

type crossScenarioJSON struct {
	Name              string                          `json:"name"`
	Description       string                          `json:"description"`
	BundleB64         string                          `json:"bundle_b64"`
	RequiredScope     string                          `json:"required_scope"`
	ExpectedChallenge *expectedChallengeJSON          `json:"expected_challenge"`
	ContextPolicy     *contextPolicyJSON              `json:"context_policy"`
	TrustRootKey      string                          `json:"trust_root_key"`
	StatusKeys        map[string]crossStatusKeyJSON   `json:"status_keys"`
	StatusEvidence    map[string][]evidenceObjectJSON `json:"status_evidence"`
	VerifyTime        int64                           `json:"verify_time"`
	PublishTime       int64                           `json:"publish_time"`
	ReleaseTime       int64                           `json:"release_time"`
	Expected          crossScenarioExpectJSON         `json:"expected"`
}

func crossScenarioConfig() crossScenarioConfigJSON {
	return crossScenarioConfigJSON{
		VerifierNamespace: fixtureNamespace, ReplayEpoch: fixtureReplayEpoch, VerifierKey: "verifier", ReceiptLogID: crossScenarioLogID,
		LeaseSeconds: lifecycleLeaseSeconds, MaxChallengeAgeSeconds: 300, FutureSkewSeconds: 5,
		StatusPolicy: orderingStatusPolicy, TZDBVersion: ratify.TZDBVersionV2,
	}
}

// crossScenarios builds the scenario inputs; expectations are filled by
// running each through the producing SDK (the Go reference here).
func (g *gen) crossScenarios() []crossScenarioJSON {
	agent, root, inter := g.k("agent"), g.k("root"), g.k("intermediate")
	statusRoot, statusInter := g.k("status_root"), g.k("status_intermediate")
	session := g.fixtureSessionContext(agent)
	certs := g.chain(chainSpec{})
	ev := func(wire []byte) evidenceObjectJSON {
		return evidenceObjectJSON{ObjectTypeCode: int(codeList), WireB64: b64(wire)}
	}
	_, rootList, _ := g.list(statusRoot, root.ID, 1, Now-60, Now+3600)
	_, rootShort, _ := g.list(statusRoot, root.ID, 1, Now-60, Now+60)
	_, interList, _ := g.list(statusInter, inter.ID, 1, Now-60, Now+3600)
	_, interRevoked, _ := g.list(statusInter, inter.ID, 1, Now-60, Now+3600, "cert-leaf")
	mk := func(name, desc string, challengeByte byte, evidence map[string][]evidenceObjectJSON, publish, release int64) crossScenarioJSON {
		challenge := defaultChallenge()
		challenge[0] = challengeByte
		_, bundle, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: session, challenge: challenge})
		expected := g.defaultExpected(agent, session)
		expected.ValueB64 = b64(challenge)
		return crossScenarioJSON{
			Name: name, Description: desc, BundleB64: b64(bundle), RequiredScope: "data:read", ExpectedChallenge: expected,
			ContextPolicy: g.verifyPolicyJSON(session), TrustRootKey: "root",
			StatusKeys:     map[string]crossStatusKeyJSON{root.ID: {Epoch: 1, Key: "status_root"}, inter.ID: {Epoch: 1, Key: "status_intermediate"}},
			StatusEvidence: evidence, VerifyTime: Now, PublishTime: publish, ReleaseTime: release,
		}
	}
	return []crossScenarioJSON{
		mk("allow_released", "every check passes; the published, acknowledged allow is released at the acknowledgement time", 0xa1,
			map[string][]evidenceObjectJSON{root.ID: {ev(rootList)}, inter.ID: {ev(interList)}}, Now, Now),
		mk("deny_revoked_released", "the intermediate's signed list revokes the leaf: a committed deny / delegation_revoked, released as a non-actionable deny", 0xa2,
			map[string][]evidenceObjectJSON{root.ID: {ev(rootList)}, inter.ID: {ev(interRevoked)}}, Now, Now),
		mk("indeterminate_status_unavailable_released", "the status provider returns no evidence for the intermediate: indeterminate / status_unavailable, released as a non-actionable indeterminate", 0xa3,
			map[string][]evidenceObjectJSON{root.ID: {ev(rootList)}}, Now, Now),
		mk("allow_withheld_past_horizon", "the root list's next_update makes the allow horizon verify_time + 60; the receipt is acknowledged at that horizon, so release is withheld as allow_horizon_passed and never becomes released", 0xa4,
			map[string][]evidenceObjectJSON{root.ID: {ev(rootShort)}, inter.ID: {ev(interList)}}, Now+60, Now+60),
	}
}

// crossScenarioResult is what one SDK observed for a scenario.
type crossScenarioResult struct {
	expect    crossScenarioExpectJSON
	published []byte
}

// replayCrossScenario runs a scenario through the Go reference: a fresh
// reference store at verify_time, the live verifier, publication at
// publish_time, and ReleaseV2Decision at release_time with releaseReceipt
// (the scenario's own published receipt when nil).
func replayCrossScenario(cfg crossScenarioConfigJSON, sc crossScenarioJSON, pub map[string]ratify.HybridPublicKey, verifierPriv ratify.HybridPrivateKey, releaseReceipt []byte) (crossScenarioResult, error) {
	ctx := context.Background()
	var out crossScenarioResult
	store, err := v2reference.NewStore(sc.VerifyTime, cfg.LeaseSeconds, cfg.ReceiptLogID, verifierPriv)
	if err != nil {
		return out, err
	}
	journal, err := v2reference.NewJournalStore()
	if err != nil {
		return out, err
	}
	issuers := make([]string, 0, len(sc.StatusKeys))
	for issuer := range sc.StatusKeys {
		issuers = append(issuers, issuer)
	}
	sort.Strings(issuers)
	req := ratify.V2VerifyRequest{
		Bundle: must(b64d(sc.BundleB64)), RequiredScope: sc.RequiredScope, VerifierNamespace: cfg.VerifierNamespace, ReplayEpoch: cfg.ReplayEpoch,
		Now: sc.VerifyTime, MaxChallengeAgeSeconds: cfg.MaxChallengeAgeSeconds, FutureSkewSeconds: cfg.FutureSkewSeconds, TZDBVersion: cfg.TZDBVersion,
		StatusKeys: map[string]ratify.V2StatusKeyConfig{},
		StatusPolicy: ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: cfg.StatusPolicy.MaxListLifetimeSeconds, MaxStatusAgeSeconds: cfg.StatusPolicy.MaxStatusAgeSeconds,
			ClockSkewSeconds: cfg.StatusPolicy.ClockSkewSeconds},
	}
	for _, issuer := range issuers {
		k := sc.StatusKeys[issuer]
		key, ok := pub[k.Key]
		if !ok {
			return out, fmt.Errorf("status key %q is not in the fixture", k.Key)
		}
		req.StatusKeys[issuer] = ratify.V2StatusKeyConfig{Epoch: k.Epoch, Key: key}
		if _, err := ratify.ConfigureStatusKeyEpochV2(ctx, journal, issuer, k.Epoch, key); err != nil {
			return out, err
		}
	}
	e := sc.ExpectedChallenge
	exp := &ratify.ExpectedChallengeV2{Value: must(b64d(e.ValueB64)), IssuedAt: e.IssuedAt, ExpiresAt: e.ExpiresAt, VerifierNamespace: e.VerifierNamespace, ReplayEpoch: e.ReplayEpoch, VerifierID: e.VerifierID}
	if e.ExpectedAgentID != nil {
		key, err := jsonPublicKey(e.ExpectedAgentPublicKey)
		if err != nil {
			return out, err
		}
		exp.ExpectedAgentID, exp.ExpectedAgentPublicKey = *e.ExpectedAgentID, &key
	}
	if e.ExpectedReceiverID != nil {
		exp.ExpectedReceiverID = *e.ExpectedReceiverID
	}
	if e.ExpectedSessionContextB64 != nil {
		exp.ExpectedSessionContext = must(b64d(*e.ExpectedSessionContextB64))
	}
	req.Expected = exp
	if p := sc.ContextPolicy; p != nil {
		var expected []byte
		if p.ExpectedSessionContextB64 != nil {
			expected = must(b64d(*p.ExpectedSessionContextB64))
		}
		if req.ContextPolicy, err = ratify.NewV2ContextPolicy(p.Profile, p.RequireBound, p.RequiredFields, expected); err != nil {
			return out, err
		}
	}
	rootKey, ok := pub[sc.TrustRootKey]
	if !ok {
		return out, fmt.Errorf("trust root key %q is not in the fixture", sc.TrustRootKey)
	}
	cb := ratify.V2VerifyCallbacks{
		ClaimStore: store, StatusJournal: journal,
		Trust: func(context.Context, []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
			return ratify.V2TrustResolution{Outcome: ratify.V2TrustTrusted, RootKey: rootKey}, nil
		},
		StatusEvidence: func(_ context.Context, r ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
			batch := ratify.V2StatusEvidenceBatch{}
			for _, o := range sc.StatusEvidence[r.IssuerID] {
				batch.Objects = append(batch.Objects, ratify.V2StatusEvidenceObject{ObjectType: uint16(o.ObjectTypeCode), Wire: must(b64d(o.WireB64))})
			}
			return batch, nil
		},
	}
	outcome, _ := ratify.VerifyProofBundleV2(ctx, req, cb)
	if outcome.Stage != ratify.V2StageCommitted {
		return out, fmt.Errorf("stage %s (%s): %v", outcome.Stage, outcome.ErrorClass, outcome.Error)
	}
	committed := outcome.Committed
	out.expect.ReceiptBodyB64 = b64(committed.ReceiptBody())
	if h, ok := committed.AllowHorizon(); ok {
		out.expect.AllowHorizon = &h
	}
	store.SetTime(sc.PublishTime)
	if out.published, err = store.PublishV2Receipt(ctx, committed.ClaimID(), committed.ReceiptBody()); err != nil {
		return out, fmt.Errorf("publish: %w", err)
	}
	out.expect.SignedReceiptB64 = b64(out.published)
	if releaseReceipt == nil {
		releaseReceipt = out.published
	}
	store.SetTime(sc.ReleaseTime)
	result := ratify.ReleaseV2Decision(ctx, committed, releaseReceipt, ratify.V2ReleaseConfig{
		VerifierPublicKey: verifierPriv.Public(), LogID: cfg.ReceiptLogID, ClaimStore: store, Checkpoint: store})
	out.expect.Release = crossReleaseJSON{Status: string(result.Status)}
	if result.Reason != "" {
		out.expect.Release.Reason = strp(result.Reason)
	}
	if d := result.Decision; d != nil {
		decision, t := d.Decision(), d.ReleaseTime()
		out.expect.Release.Decision, out.expect.Release.ReleaseTime = &decision, &t
	}
	return out, nil
}

func jsonPublicKey(v map[string]any) (ratify.HybridPublicKey, error) {
	var key ratify.HybridPublicKey
	raw, err := json.Marshal(v)
	if err != nil {
		return key, err
	}
	return key, json.Unmarshal(raw, &key)
}

// checkCrossScenarios replays every scenario of a fixture and compares the
// committed outcome and release result, releasing with the fixture's own
// signed receipt.
func checkCrossScenarios(cfg crossScenarioConfigJSON, scenarios []crossScenarioJSON, pub map[string]ratify.HybridPublicKey, verifierPriv ratify.HybridPrivateKey) error {
	if cfg != crossScenarioConfig() {
		return fmt.Errorf("scenario_configuration differs from the fixed values")
	}
	seen := map[string]bool{}
	for _, sc := range scenarios {
		seen[sc.Name] = true
		got, err := replayCrossScenario(cfg, sc, pub, verifierPriv, must(b64d(sc.Expected.SignedReceiptB64)))
		if err != nil {
			return fmt.Errorf("scenario %s: %w", sc.Name, err)
		}
		want := sc.Expected
		if got.expect.ReceiptBodyB64 != want.ReceiptBodyB64 || !equalInt64Ptr(got.expect.AllowHorizon, want.AllowHorizon) {
			return fmt.Errorf("scenario %s: committed outcome differs", sc.Name)
		}
		gr, wr := got.expect.Release, want.Release
		if gr.Status != wr.Status || !equalStringPtr(gr.Reason, wr.Reason) || !equalStringPtr(gr.Decision, wr.Decision) || !equalInt64Ptr(gr.ReleaseTime, wr.ReleaseTime) {
			return fmt.Errorf("scenario %s: release %+v, want %+v", sc.Name, gr, wr)
		}
	}
	for _, name := range CrossScenarioNames {
		if !seen[name] {
			return fmt.Errorf("missing scenario %s", name)
		}
	}
	return nil
}

func equalInt64Ptr(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func equalStringPtr(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// fillCrossScenarios runs each scenario through the Go reference and records
// the observed outcome as its expectation.
func (g *gen) fillCrossScenarios(scenarios []crossScenarioJSON) []crossScenarioJSON {
	pub := map[string]ratify.HybridPublicKey{}
	for name, k := range g.keys {
		pub[name] = k.Pub
	}
	for i := range scenarios {
		got := must(replayCrossScenario(crossScenarioConfig(), scenarios[i], pub, g.k("verifier").Priv, nil))
		scenarios[i].Expected = got.expect
	}
	return scenarios
}
