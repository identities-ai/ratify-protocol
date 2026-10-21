package v2vectors

import (
	"encoding/hex"
	"sort"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type expectedChallengeJSON struct {
	ValueB64                  string         `json:"value_b64"`
	IssuedAt                  int64          `json:"issued_at"`
	ExpiresAt                 int64          `json:"expires_at"`
	VerifierNamespace         string         `json:"verifier_namespace"`
	ReplayEpoch               int64          `json:"replay_epoch"`
	VerifierID                string         `json:"verifier_id"`
	ExpectedAgentID           *string        `json:"expected_agent_id"`
	ExpectedAgentPublicKey    map[string]any `json:"expected_agent_public_key"`
	ExpectedReceiverID        *string        `json:"expected_receiver_id"`
	ExpectedSessionContextB64 *string        `json:"expected_session_context_b64"`
}

type contextPolicyJSON struct {
	Profile                   string   `json:"profile"`
	RequireBound              bool     `json:"require_bound"`
	RequiredFields            []string `json:"required_fields"`
	ExpectedSessionContextB64 *string  `json:"expected_session_context_b64"`
	Digest                    string   `json:"digest"`
}

type trustJSON struct {
	Available     bool           `json:"available"`
	RootKeyID     string         `json:"root_key_id,omitempty"`
	RootPublicKey map[string]any `json:"root_public_key,omitempty"`
}

type statusResultJSON struct {
	Status     string         `json:"status"`
	Reason     string         `json:"reason,omitempty"`
	FreshUntil int64          `json:"fresh_until,omitempty"`
	Evidence   []EvidenceJSON `json:"evidence"`
}

type statusRolesJSON struct {
	StatusKeyIssuers    map[string]string `json:"status_key_issuers"`
	CurrentStatusKeyIDs map[string]string `json:"current_status_key_ids"`
	ReservedKeyIDs      []string          `json:"reserved_key_ids"`
}

type membershipJSON struct {
	DelegationIndex int      `json:"delegation_index"`
	ConstraintIndex int      `json:"constraint_index"`
	ReceiverID      string   `json:"receiver_id"`
	TrustDomainIDs  []string `json:"trust_domain_ids"`
	IssuedAt        int64    `json:"issued_at"`
	ExpiresAt       int64    `json:"expires_at"`
	EvidenceDigest  string   `json:"evidence_digest"`
}

type requestContextJSON struct {
	HasResource           bool   `json:"has_resource"`
	RequestedResourceID   string `json:"requested_resource_id,omitempty"`
	RequestedPath         string `json:"requested_path,omitempty"`
	HasAmount             bool   `json:"has_amount,omitempty"`
	RequestedAmountMicros int64  `json:"requested_amount_micros,omitempty"`
	RequestedCurrency     string `json:"requested_currency,omitempty"`
}

type rateJSON struct {
	IssuerID string `json:"issuer_id"`
	CertID   string `json:"cert_id"`
	WindowS  int64  `json:"window_s"`
	Limit    int64  `json:"limit"`
}

type countsJSON struct {
	ReceiverBinding int `json:"receiver_binding"`
	Claim           int `json:"claim"`
	Trust           int `json:"trust"`
	Status          int `json:"status"`
	Audience        int `json:"audience"`
	Rate            int `json:"rate"`
	Finalize        int `json:"finalize"`
}

type outcomeJSON struct {
	Stage               string         `json:"stage"`
	ErrorClass          string         `json:"error_class,omitempty"`
	Disposition         string         `json:"disposition,omitempty"`
	Decision            string         `json:"decision,omitempty"`
	DecisionReason      string         `json:"decision_reason,omitempty"`
	IdentityStatus      string         `json:"identity_status,omitempty"`
	TrustAssessment     string         `json:"trust_assessment,omitempty"`
	StatusAssessment    string         `json:"status_assessment,omitempty"`
	ContextAssessment   string         `json:"context_assessment,omitempty"`
	ContextPolicyDigest *string        `json:"context_policy_digest,omitempty"`
	GrantedScope        []string       `json:"granted_scope,omitempty"`
	StatusEvidence      []EvidenceJSON `json:"status_evidence,omitempty"`
	ReceiptBodyB64      string         `json:"receipt_body_b64,omitempty"`
	AllowValidUntil     int64          `json:"allow_valid_until,omitempty"`
	RateBatch           []rateJSON     `json:"rate_batch,omitempty"`
	CallbackCounts      countsJSON     `json:"callback_counts"`
}

type orderingVector struct {
	Name                   string                      `json:"name"`
	Description            string                      `json:"description"`
	Bundle                 string                      `json:"bundle"`
	RequiredScope          string                      `json:"required_scope"`
	ExpectedChallenge      *expectedChallengeJSON      `json:"expected_challenge"`
	ContextPolicy          *contextPolicyJSON          `json:"context_policy"`
	ConfiguredNamespace    string                      `json:"configured_namespace"`
	ConfiguredReplayEpoch  int64                       `json:"configured_replay_epoch"`
	Now                    int64                       `json:"now"`
	MaxChallengeAgeSeconds int64                       `json:"max_challenge_age_seconds"`
	FutureSkewSeconds      int64                       `json:"future_skew_seconds"`
	RequestContext         *requestContextJSON         `json:"request_context"`
	ReceiverBindingHook    string                      `json:"receiver_binding_hook"`
	ClaimStore             string                      `json:"claim_store"`
	Trust                  *trustJSON                  `json:"trust"`
	Status                 map[string]statusResultJSON `json:"status"`
	StatusRoles            statusRolesJSON             `json:"status_roles"`
	AudienceMemberships    []membershipJSON            `json:"audience_memberships"`
	Rate                   string                      `json:"rate"`
	Expected               outcomeJSON                 `json:"expected"`
}

type orderingFile struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Semantics   map[string]string `json:"semantics"`
	Bundles     map[string]string `json:"bundles_b64"`
	Vectors     []orderingVector  `json:"vectors"`
}

// scenario is the generator-side description of one ordering case.
type scenario struct {
	name, desc  string
	bundle      []byte
	certs       []ratify.DelegationCertV2
	agent       *Key
	scope       string
	expected    *expectedChallengeJSON
	policy      *contextPolicyJSON
	namespace   string
	epoch       int64
	now         int64
	maxAge      int64
	reqCtx      *requestContextJSON
	hook        string
	claim       string
	trust       *trustJSON
	status      map[string]statusResultJSON
	memberships []membershipJSON
	rate        string
	out         outcomeJSON
}

func strp(s string) *string { return &s }

func (g *gen) verifyPolicyJSON(session []byte) *contextPolicyJSON {
	return &contextPolicyJSON{Profile: verifyPolicy, RequireBound: true, RequiredFields: verifyPolicyFields, ExpectedSessionContextB64: strp(b64(session)), Digest: policyDigest(verifyPolicy, true, verifyPolicyFields)}
}

func (g *gen) notRequiredPolicyJSON() *contextPolicyJSON {
	return &contextPolicyJSON{Profile: notRequiredPolicy, RequireBound: false, RequiredFields: []string{}, Digest: policyDigest(notRequiredPolicy, false, nil)}
}

func (g *gen) defaultExpected(agent *Key, session []byte) *expectedChallengeJSON {
	e := &expectedChallengeJSON{
		ValueB64: b64(defaultChallenge()), IssuedAt: Now - 10, ExpiresAt: Now + 290, VerifierNamespace: fixtureNamespace,
		ReplayEpoch: fixtureReplayEpoch, VerifierID: g.k("verifier").ID, ExpectedAgentID: strp(agent.ID), ExpectedAgentPublicKey: pubJSON(agent.Pub),
	}
	if session != nil {
		e.ExpectedSessionContextB64 = strp(b64(session))
	}
	return e
}

func (g *gen) statusRoles() statusRolesJSON {
	return statusRolesJSON{
		StatusKeyIssuers: map[string]string{
			g.k("status_root").ID: g.k("root").ID, g.k("status_intermediate").ID: g.k("intermediate").ID,
			g.k("status_party_b").ID: g.k("untrusted_root").ID,
		},
		CurrentStatusKeyIDs: map[string]string{
			g.k("root").ID: g.k("status_root").ID, g.k("intermediate").ID: g.k("status_intermediate").ID,
			g.k("untrusted_root").ID: g.k("status_party_b").ID,
		},
		ReservedKeyIDs: []string{g.k("verifier").ID},
	}
}

const statusFreshUntil = Now + 3600

func notRevoked(e EvidenceJSON) statusResultJSON {
	return statusResultJSON{Status: "not_revoked", FreshUntil: statusFreshUntil, Evidence: []EvidenceJSON{e}}
}

func (g *gen) currentStatus(certs []ratify.DelegationCertV2) map[string]statusResultJSON {
	st := g.statusFixtures()
	out := map[string]statusResultJSON{}
	for _, c := range certs {
		switch c.IssuerID {
		case g.k("root").ID:
			out[c.IssuerID+"/"+c.CertID] = notRevoked(g.evidence(st["root_current"]))
		case g.k("intermediate").ID:
			out[c.IssuerID+"/"+c.CertID] = notRevoked(g.evidence(st["intermediate_current"]))
		}
	}
	return out
}

func (g *gen) trustRoot(name string) *trustJSON {
	return &trustJSON{Available: true, RootKeyID: g.k(name).ID, RootPublicKey: pubJSON(g.k(name).Pub)}
}

// finish fills defaults and computes the expected receipt body for terminal
// outcomes from the hand-specified tuple.
func (g *gen) finish(s scenario) orderingVector {
	if s.agent == nil {
		s.agent = g.k("agent")
	}
	if s.namespace == "" {
		s.namespace = fixtureNamespace
	}
	if s.epoch == 0 {
		s.epoch = fixtureReplayEpoch
	}
	if s.now == 0 {
		s.now = Now
	}
	if s.maxAge == 0 {
		s.maxAge = 300
	}
	if s.hook == "" {
		s.hook = "absent"
	}
	if s.claim == "" {
		s.claim = "create"
	}
	if s.rate == "" {
		s.rate = "absent"
	}
	if s.status == nil {
		s.status = map[string]statusResultJSON{}
	}
	if s.memberships == nil {
		s.memberships = []membershipJSON{}
	}
	if s.out.Stage == "terminal" {
		b := must(ratify.DecodeProofBundleV2(s.bundle))
		issuers := []string{}
		seen := map[string]bool{}
		for _, c := range b.Delegations {
			if !seen[c.IssuerID] {
				seen[c.IssuerID] = true
				issuers = append(issuers, c.IssuerID)
			}
		}
		sort.Strings(issuers)
		if s.out.StatusEvidence == nil {
			s.out.StatusEvidence = []EvidenceJSON{}
		}
		s.out.StatusEvidence = sortEvidence(s.out.StatusEvidence)
		granted := s.out.GrantedScope
		if granted == nil {
			granted = []string{}
		}
		r := &ratify.VerificationReceiptV2{
			Version: 2, VerifierID: b.VerifierID, AgentID: b.AgentID, BundleHash: bundleHash(s.bundle), IssuerIDs: issuers,
			Decision: s.out.Decision, DecisionReason: s.out.DecisionReason, IdentityStatus: s.out.IdentityStatus,
			TrustAssessment: s.out.TrustAssessment, StatusAssessment: s.out.StatusAssessment, ChallengeAssessment: "current",
			ContextAssessment: s.out.ContextAssessment, ContextPolicyDigest: s.out.ContextPolicyDigest, VerifiedAt: s.now,
			RequiredScope: s.scope, GrantedScope: granted, StatusEvidence: toLibEvidence(s.out.StatusEvidence),
		}
		s.out.ReceiptBodyB64 = b64(must(ratify.VerificationReceiptV2Body(r)))
		s.out.CallbackCounts.Finalize = 1
	}
	return orderingVector{
		Name: s.name, Description: s.desc, Bundle: bundleName(s.bundle), RequiredScope: s.scope, ExpectedChallenge: s.expected,
		ContextPolicy: s.policy, ConfiguredNamespace: s.namespace, ConfiguredReplayEpoch: s.epoch, Now: s.now,
		MaxChallengeAgeSeconds: s.maxAge, FutureSkewSeconds: 5, RequestContext: s.reqCtx, ReceiverBindingHook: s.hook,
		ClaimStore: s.claim, Trust: s.trust, Status: s.status, StatusRoles: g.statusRoles(), AudienceMemberships: s.memberships,
		Rate: s.rate, Expected: s.out,
	}
}

func preflight(class string, hook int) outcomeJSON {
	return outcomeJSON{Stage: "preflight", ErrorClass: class, CallbackCounts: countsJSON{ReceiverBinding: hook}}
}

func (g *gen) orderingFile() any {
	f := orderingFile{
		Version:     2,
		Description: "End-to-end live verifier ordering vectors (SPEC-v2 §6, §6.2, §8). Run the complete decision path with the given inputs and scripted callbacks; compare the stage, error class or terminal tuple, the exact receipt outbox body, and the number of times each callback ran.",
		Semantics: map[string]string{
			"bundle":                           "key into bundles_b64; the exact presented proof bundle bytes",
			"stage":                            "preflight = rejected before claim (no receipt, nothing consumed); replay = claim already existed (no result disclosed, no evaluation); terminal = a terminal Protocol result was committed with receipt_body_b64",
			"receiver_binding_hook":            "absent = no application hook; accept/reject = the pure application hook, invoked only after every built-in pre-claim check passed",
			"claim_store":                      "create = atomic claim succeeds; proof_conflict = challenge already claimed by a different proof digest; in_progress = exact retry while evaluating; terminal_replay = exact retry after commit; unavailable = store error",
			"trust":                            "null = no caller-authenticated trust configuration is available; otherwise the configured root for this chain",
			"status":                           "result returned for CertificateRef issuer_id/cert_id; a reference absent from the map returns indeterminate/unavailable with no evidence",
			"status_roles":                     "caller-authenticated status-key role bindings used to authenticate returned evidence",
			"audience_memberships":             "caller-authenticated membership results returned by the audience provider",
			"rate":                             "absent = no rate store; reserve = batch reserved; exceeded = definitive capacity exhaustion; unavailable = store error",
			"callback_counts.status":           "number of CertificateRef status queries",
			"callback_counts.claim":            "number of atomic claim attempts",
			"callback_counts.finalize":         "number of terminal finalize calls",
			"callback_counts.trust":            "number of trust-resolver invocations",
			"callback_counts.audience":         "number of audience-provider invocations",
			"callback_counts.rate":             "number of rate-batch reservations",
			"callback_counts.receiver_binding": "number of application hook invocations",
			"receipt_body_b64":                 "exact canonical receipt outbox body: every required receipt field except log_id, sequence, previous_receipt_hash and signature, plus agent_id",
		},
	}
	f.Bundles = map[string]string{}
	for _, s := range append(g.preflightScenarios(), g.terminalScenarios()...) {
		f.Bundles[bundleName(s.bundle)] = b64(s.bundle)
		f.Vectors = append(f.Vectors, g.finish(s))
	}
	return f
}

// base returns the default allow-path bundle and its inputs.
func (g *gen) base() (bundle []byte, certs []ratify.DelegationCertV2, session []byte) {
	agent := g.k("agent")
	certs = g.chain(chainSpec{})
	session = g.fixtureSessionContext(agent)
	_, bundle, _ = g.bundle(bundleSpec{agent: agent, certs: certs, session: session})
	return bundle, certs, session
}

func (g *gen) preflightScenarios() []scenario {
	agent, attacker, root := g.k("agent"), g.k("attacker"), g.k("root")
	bundle, certs, session := g.base()
	std := func(name, desc string, b []byte, class string, edit func(*scenario)) scenario {
		s := scenario{name: name, desc: desc, bundle: b, certs: certs, scope: "data:read", expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session),
			trust: g.trustRoot("root"), status: g.currentStatus(certs), out: preflight(class, 0)}
		if edit != nil {
			edit(&s)
		}
		return s
	}
	var out []scenario
	add := func(s scenario) { out = append(out, s) }

	add(std("malformed_json", "truncated JSON never reaches signatures, claim, or callbacks", bundle[:len(bundle)/3], "malformed", nil))
	add(std("unknown_field", "unknown bundle field is a strict decode failure", mutate(bundle, func(o map[string]any) { o["extra"] = true }), "malformed", nil))
	add(std("v1_bundle", "v1 objects are never accepted by a v2 verifier", canon(map[string]any{"agent_id": ratify.DeriveID(agent.Pub), "agent_pub_key": pubJSON(agent.Pub), "delegations": []any{}, "challenge": b64(defaultChallenge()), "challenge_at": num(Now - 10), "challenge_sig": sigJSON(placeholderSig())}), "malformed", nil))
	for _, bad := range []struct{ name, scope string }{{"wildcard", "data:*"}, {"custom", "custom:read"}, {"empty", ""}, {"unregistered", "data:read:all"}} {
		add(std("required_scope_"+bad.name, "invalid request scope is rejected before claim", bundle, "invalid_required_scope", func(s *scenario) { s.scope = bad.scope }))
	}
	add(std("delegation_digest_mismatch", "digest mismatch is a structural preflight failure", mutate(bundle, func(o map[string]any) { o["delegation_digest"] = flipB64(o["delegation_digest"]) }), "delegation_digest_mismatch", nil))
	swapped := parse(bundle).(map[string]any)
	d := arr(swapped["delegations"])
	d[0], d[1] = d[1], d[0]
	add(std("swapped_chain", "root-first chain fails linkage before any callback", g.resign(swapped, agent), "chain_linkage_mismatch", nil))
	dupLeaf, _, _ := g.cert(certSpec{issuer: g.k("intermediate"), subject: agent, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	dupSelf, _, _ := g.cert(certSpec{issuer: g.k("intermediate"), subject: g.k("intermediate"), certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	dupRoot, _, _ := g.cert(certSpec{issuer: root, subject: g.k("intermediate"), certID: "cert-root", scope: []string{"data:read", "identity:delegate"}})
	_, dupWire, _ := g.bundle(bundleSpec{agent: agent, certs: []ratify.DelegationCertV2{dupLeaf, dupSelf, dupRoot}, session: session})
	add(std("duplicate_certificate_ref", "a repeated exact (issuer_id, cert_id) is a pre-claim structural failure with no claim or receipt", dupWire, "duplicate_certificate_ref", nil))
	add(std("agent_id_mismatch", "agent_id does not match agent_pub_key", mutate(bundle, func(o map[string]any) { o["agent_id"] = attacker.ID }), "key_id_mismatch", nil))
	badCert := parse(bundle).(map[string]any)
	s0 := obj(obj(arr(badCert["delegations"])[0])["signature"])
	s0["ml_dsa_65"] = flipB64(s0["ml_dsa_65"])
	add(std("bad_certificate_signature", "invalid certificate signature produces no claim and no trust/status callback", g.resign(badCert, agent), "invalid_signature", nil))
	add(std("bad_challenge_signature", "invalid challenge signature produces no claim", mutate(bundle, func(o map[string]any) { s := obj(o["challenge_sig"]); s["ed25519"] = flipB64(s["ed25519"]) }), "invalid_signature", nil))
	_, emptyBad, _ := g.bundle(bundleSpec{agent: agent, signer: attacker})
	add(std("empty_chain_invalid_signature", "empty delegation chain with an invalid challenge signature fails before claim", emptyBad, "invalid_signature", func(s *scenario) { s.expected = g.defaultExpected(agent, nil); s.policy = g.notRequiredPolicyJSON() }))
	add(std("expected_challenge_missing", "no authenticated expected challenge", bundle, "expected_challenge_unavailable", func(s *scenario) { s.expected = nil }))
	add(std("wrong_namespace", "expected challenge from another verifier namespace", bundle, "namespace_mismatch", func(s *scenario) { s.expected.VerifierNamespace = "verify-other" }))
	add(std("stale_replay_epoch", "challenge issued under an earlier replay epoch is rejected before claim and callbacks", bundle, "stale_replay_epoch", func(s *scenario) { s.expected.ReplayEpoch = 2 }))
	add(std("verifier_id_mismatch", "bundle verifier_id differs from the authenticated expected verifier", bundle, "verifier_id_mismatch", func(s *scenario) { s.expected.VerifierID = attacker.ID }))
	other := defaultChallenge()
	other[0] ^= 1
	add(std("challenge_bytes_mismatch", "proof challenge differs from the issued challenge", bundle, "challenge_mismatch", func(s *scenario) { s.expected.ValueB64 = b64(other) }))
	add(std("challenge_at_mismatch", "challenge_at differs from authenticated issuance time", bundle, "challenge_mismatch", func(s *scenario) { s.expected.IssuedAt = Now - 11 }))
	add(std("challenge_expired_at_boundary", "now == expires_at is expired (exclusive boundary)", bundle, "challenge_not_fresh", func(s *scenario) { s.expected.ExpiresAt = Now }))
	add(std("delayed_claim_after_expiry", "request received after expiry fails preflight and cannot reach a stored claim", bundle, "challenge_not_fresh", func(s *scenario) { s.now = Now + 400 }))
	add(std("challenge_exceeds_max_age", "challenge older than the configured maximum age", bundle, "challenge_not_fresh", func(s *scenario) { s.maxAge = 5 }))
	futureChallenge := func() []byte {
		_, w, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: session, challengeAt: Now + 60})
		return w
	}()
	add(std("challenge_issued_in_future", "issued_at beyond now + skew", futureChallenge, "challenge_not_fresh", func(s *scenario) { s.expected.IssuedAt = Now + 60; s.expected.ExpiresAt = Now + 300 }))
	add(std("expected_agent_mismatch", "a validly signed proof from a key other than the challenge-bound agent cannot consume the challenge", bundle, "expected_agent_mismatch", func(s *scenario) {
		s.expected.ExpectedAgentID = strp(attacker.ID)
		s.expected.ExpectedAgentPublicKey = pubJSON(attacker.Pub)
	}))
	otherSession := append([]byte(nil), session...)
	otherSession[0] ^= 1
	add(std("session_context_mismatch", "proof session_context differs from the authenticated expected context", bundle, "session_context_mismatch", func(s *scenario) {
		s.expected.ExpectedSessionContextB64 = strp(b64(otherSession))
		s.policy = g.verifyPolicyJSON(otherSession)
	}))
	_, noSession, _ := g.bundle(bundleSpec{agent: agent, certs: certs})
	add(std("policy_required_context_absent", "a bound context policy with a null proof session_context is a pre-claim mismatch in the Verify profile", noSession, "session_context_mismatch", nil))

	audience := []ratify.ConstraintV2{{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-1"}, "trust_domain_ids": []any{}}}}
	exactCerts := g.chain(chainSpec{leafCons: audience})
	_, exactWire, _ := g.bundle(bundleSpec{agent: agent, certs: exactCerts, session: session})
	add(std("audience_requires_expected_receiver", "an audience-constrained chain without expected_receiver_id fails before claim", exactWire, "receiver_audience_required", nil))
	add(std("exact_audience_mismatch", "exact-only audience excluding the receiver is rejected by the pure hook with no claim", exactWire, "receiver_audience_mismatch", func(s *scenario) { s.expected.ExpectedReceiverID = strp("receiver-2") }))
	add(std("receiver_binding_hook_rejects", "application hook rejection after built-in checks consumes nothing", bundle, "receiver_binding_rejected", func(s *scenario) { s.hook = "reject"; s.out.CallbackCounts.ReceiverBinding = 1 }))
	add(std("claim_proof_conflict", "a different proof digest for an already claimed challenge is rejected as replay without retrieving the first result", bundle, "claim_replay", func(s *scenario) {
		s.hook = "accept"
		s.claim = "proof_conflict"
		s.out.CallbackCounts = countsJSON{ReceiverBinding: 1, Claim: 1}
	}))
	add(std("claim_store_unavailable", "claim-store failure is pre-claim and cannot authorize", bundle, "claim_store_unavailable", func(s *scenario) {
		s.claim = "unavailable"
		s.out.CallbackCounts = countsJSON{Claim: 1}
	}))
	add(std("exact_retry_in_progress", "exact retry while the first evaluation is pending launches no callbacks", bundle, "", func(s *scenario) {
		s.claim = "in_progress"
		s.out = outcomeJSON{Stage: "replay", Disposition: "in_progress", CallbackCounts: countsJSON{Claim: 1}}
	}))
	add(std("exact_retry_after_commit", "exact retry after terminal commit is a replay and runs no evaluation callbacks", bundle, "", func(s *scenario) {
		s.claim = "terminal_replay"
		s.out = outcomeJSON{Stage: "replay", Disposition: "terminal_replay", CallbackCounts: countsJSON{Claim: 1}}
	}))
	return out
}

// terminal builds a terminal scenario with the default inputs.
func (g *gen) terminal(name, desc string, certs []ratify.DelegationCertV2, out outcomeJSON, edit func(*scenario)) scenario {
	agent := g.k("agent")
	session := g.fixtureSessionContext(agent)
	_, bundle, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: session})
	out.Stage = "terminal"
	s := scenario{name: name, desc: desc, bundle: bundle, certs: certs, scope: "data:read", expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session),
		trust: g.trustRoot("root"), status: g.currentStatus(certs), out: out}
	if edit != nil {
		edit(&s)
	}
	return s
}

func (g *gen) currentEvidence() []EvidenceJSON {
	st := g.statusFixtures()
	return []EvidenceJSON{g.evidence(st["root_current"]), g.evidence(st["intermediate_current"])}
}

func (g *gen) terminalScenarios() []scenario {
	agent := g.k("agent")
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	np := policyDigest(notRequiredPolicy, false, nil)
	st := g.statusFixtures()
	leafKey := func(certs []ratify.DelegationCertV2) string { return certs[0].IssuerID + "/" + certs[0].CertID }
	rootKey := func(certs []ratify.DelegationCertV2) string { return certs[1].IssuerID + "/" + certs[1].CertID }
	allowCounts := countsJSON{Claim: 1, Trust: 1, Status: 2}
	allow := func() outcomeJSON {
		return outcomeJSON{Decision: "allow", DecisionReason: "authorized", IdentityStatus: "authorized_agent", TrustAssessment: "trusted", StatusAssessment: "current",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), GrantedScope: []string{"data:read", "files:read"}, StatusEvidence: g.currentEvidence(),
			AllowValidUntil: statusFreshUntil, CallbackCounts: allowCounts}
	}
	deny := func(reason, identity, trust, status, context string, digest *string, evidence []EvidenceJSON, counts countsJSON) outcomeJSON {
		return outcomeJSON{Decision: "deny", DecisionReason: reason, IdentityStatus: identity, TrustAssessment: trust, StatusAssessment: status,
			ContextAssessment: context, ContextPolicyDigest: digest, StatusEvidence: evidence, CallbackCounts: counts}
	}
	indeterminate := func(reason, trust, status, context string, digest *string, evidence []EvidenceJSON, counts countsJSON) outcomeJSON {
		return outcomeJSON{Decision: "indeterminate", DecisionReason: reason, IdentityStatus: "authorization_unverified", TrustAssessment: trust,
			StatusAssessment: status, ContextAssessment: context, ContextPolicyDigest: digest, StatusEvidence: evidence, CallbackCounts: counts}
	}
	noStatus := countsJSON{Claim: 1, Trust: 1}
	unavailable := statusResultJSON{Status: "indeterminate", Reason: "unavailable", Evidence: []EvidenceJSON{}}
	stale := func(e EvidenceJSON) statusResultJSON {
		return statusResultJSON{Status: "indeterminate", Reason: "stale", Evidence: []EvidenceJSON{e}}
	}
	revoked := statusResultJSON{Status: "revoked", Evidence: []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"])}}
	def := g.chain(chainSpec{})

	var out []scenario
	add := func(s scenario) { out = append(out, s) }

	add(g.terminal("allow_bound_context", "all checks pass with the Verify session-context policy", def, allow(), func(s *scenario) { s.hook = "accept"; s.out.CallbackCounts.ReceiverBinding = 1 }))
	add(g.terminal("allow_context_not_required", "explicit not_required context policy with an unbound proof", def, allow(), func(s *scenario) {
		_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, certs: def})
		s.expected = g.defaultExpected(agent, nil)
		s.policy = g.notRequiredPolicyJSON()
		s.out.ContextAssessment, s.out.ContextPolicyDigest = "not_required", strp(np)
	}))
	add(g.terminal("empty_delegations_not_delegated", "validly signed empty chain is claimed, then denied without trust or status lookup", nil,
		deny("not_delegated", "delegation_not_authorized", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil, countsJSON{Claim: 1}), func(s *scenario) {
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent})
			s.expected = g.defaultExpected(agent, nil)
			s.policy = g.notRequiredPolicyJSON()
		}))
	add(g.terminal("untrusted_root_consumes_challenge", "validly signed proof for the challenge-bound agent with an untrusted root commits a sticky deny and makes no status callback", def,
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = g.trustRoot("untrusted_root") }))
	add(g.terminal("trust_anchor_key_substitution", "configured root ID matches the chain root but the configured key differs: the root is untrusted (IDs are lookup indexes, the complete key must match)", def,
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.trust = &trustJSON{Available: true, RootKeyID: g.k("root").ID, RootPublicKey: pubJSON(g.k("attacker").Pub)}
		}))
	add(g.terminal("trust_unavailable", "no caller-authenticated trust configuration", def,
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = nil }))
	add(g.terminal("parent_lacks_identity_delegate", "non-root issuer without identity:delegate in its parent certificate", g.chain(chainSpec{rootScope: []string{"data:read", "files:read"}}),
		deny("delegation_not_authorized", "delegation_not_authorized", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("delegation_expired", "now >= expires_at for the leaf", g.chain(chainSpec{leafIssued: Now - 7200, leafExpires: Now}),
		deny("delegation_expired", "expired", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("delegation_issued_in_future", "leaf issued_at beyond now + skew", g.chain(chainSpec{leafIssued: Now + 600, leafExpires: Now + 7200}),
		deny("proof_invalid", "invalid", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("invalid_certificate_scope", "unregistered scope in a structurally valid signed certificate is post-claim invalid_scope", g.chain(chainSpec{leafScope: []string{"data:read", "data:read:all"}}),
		deny("invalid_scope", "invalid_scope", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("custom_wildcard_scope", "custom:* in a certificate is invalid_scope", g.chain(chainSpec{leafScope: []string{"data:read", "custom:*"}}),
		deny("invalid_scope", "invalid_scope", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("duplicate_scope_in_certificate", "duplicate scope entries are invalid_scope after claim", g.chain(chainSpec{leafScope: []string{"data:read", "data:read"}}),
		deny("invalid_scope", "invalid_scope", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("scope_denied_after_complete_status", "valid but insufficient scope is deferred until every CertificateRef status is current", def,
		deny("scope_denied", "scope_denied", "trusted", "current", "bound", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) { s.scope = "meeting:attend" }))
	add(g.terminal("sensitive_scope_not_granted_by_wildcard", "data:* never grants the sensitive data:write", g.chain(chainSpec{leafScope: []string{"data:*"}, rootScope: []string{"data:*", "identity:delegate"}}),
		deny("scope_denied", "scope_denied", "trusted", "current", "bound", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) { s.scope = "data:write" }))
	add(g.terminal("wildcard_grants_non_sensitive", "data:* expands to the registered non-sensitive data scopes", g.chain(chainSpec{leafScope: []string{"data:*"}, rootScope: []string{"data:*", "identity:delegate"}}),
		allow(), func(s *scenario) { s.out.GrantedScope = []string{"data:read", "data:share"} }))
	add(g.terminal("custom_scope_passes_through", "exact custom: scopes are carried into granted_scope but cannot be requested", g.chain(chainSpec{leafScope: []string{"custom:billing", "data:read"}, rootScope: []string{"custom:billing", "data:read", "identity:delegate"}}),
		allow(), func(s *scenario) { s.out.GrantedScope = []string{"custom:billing", "data:read"} }))
	add(g.terminal("revoked_outranks_unavailable", "one reference revoked and the other unavailable: revoked wins and both references are queried", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"])}, allowCounts), func(s *scenario) {
			s.status[leafKey(def)] = revoked
			s.status[rootKey(def)] = unavailable
		}))
	add(g.terminal("revoked_outranks_scope_denied", "status aggregation precedes a pending local scope denial", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"]), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.scope = "meeting:attend"
			s.status[leafKey(def)] = revoked
		}))
	add(g.terminal("unavailable_outranks_stale", "unavailable on one reference and stale on another yields status_unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.status[leafKey(def)] = unavailable
			s.status[rootKey(def)] = stale(g.evidence(st["root_current"]))
		}))
	add(g.terminal("status_stale", "accepted status beyond its freshness bounds yields status_stale", def,
		indeterminate("status_stale", "trusted", "stale", "bound", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) {
			s.status[rootKey(def)] = stale(g.evidence(st["root_current"]))
		}))
	add(g.terminal("unavailable_outranks_scope_denied", "a pending scope denial is not finalized while status is unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.scope = "meeting:attend"
			s.status[leafKey(def)] = unavailable
		}))
	add(g.terminal("unauthenticated_status_evidence", "evidence signed by a key not bound to the issuer is excluded and the result is unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			e := g.evidence(st["intermediate_current"])
			e.StatusKeyID = g.k("status_party_b").ID
			s.status[leafKey(def)] = notRevoked(e)
		}))

	// Context policy cases.
	add(g.terminal("no_policy_unbound_context", "no context policy and a null session_context: never allow", def,
		indeterminate("action_context_unverified", "trusted", "current", "unbound", nil, g.currentEvidence(), allowCounts), func(s *scenario) {
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, certs: def})
			s.expected = g.defaultExpected(agent, nil)
			s.policy = nil
		}))
	add(g.terminal("no_policy_bound_context", "no context policy and a present session_context: unverified, never allow", def,
		indeterminate("action_context_unverified", "trusted", "current", "unverified", nil, g.currentEvidence(), allowCounts), func(s *scenario) {
			s.expected = g.defaultExpected(agent, nil)
			s.policy = nil
		}))

	// Constraint aggregation, audience, and rate.
	resourcePath := ratify.ConstraintV2{Type: ratify.ConstraintResourcePath, ResourceID: "customer/123"}
	unknown := ratify.ConstraintV2{Type: "ratify.conformance_unknown", Params: map[string]any{"x": 1}}
	domainA := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}}
	domainB := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{"domain-b"}, "max_membership_age_seconds": 3600}}
	exactOrDomain := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-9"}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}}
	rate := ratify.ConstraintV2{Type: ratify.ConstraintMaxRate, Count: 5, WindowS: 60}
	membership := func(link int, domains ...string) membershipJSON {
		return membershipJSON{DelegationIndex: link, ReceiverID: "receiver-1", TrustDomainIDs: domains, IssuedAt: Now - 60, ExpiresAt: Now + 600, EvidenceDigest: "sha384:" + hexRepeat(byte('a'+link), 96)}
	}
	withReceiver := func(s *scenario) { s.expected.ExpectedReceiverID = strp("receiver-1") }
	constraintOut := func(reason string, audience int) outcomeJSON {
		return deny(reason, reason, "trusted", "current", "bound", strp(vp), g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Audience: audience})
	}
	resourceCtx := &requestContextJSON{HasResource: true, RequestedResourceID: "customer/999"}

	add(g.terminal("constraint_denied_resource_mismatch", "a known constraint that evaluates false is denied after complete status", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}}),
		constraintOut("constraint_denied", 0), func(s *scenario) { s.reqCtx = resourceCtx }))
	add(g.terminal("constraint_unverifiable_missing_context", "a constraint whose action context is absent is unverifiable, never passed by omission", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}}),
		constraintOut("constraint_unverifiable", 0), nil))
	add(g.terminal("constraint_unknown_type", "an unrecognized constraint type fails closed after status aggregation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknown}}),
		constraintOut("constraint_unknown", 0), nil))
	add(g.terminal("constraint_denied_outranks_unknown", "denied outranks unknown independent of link order", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknown}, rootCons: []ratify.ConstraintV2{resourcePath}}),
		constraintOut("constraint_denied", 0), func(s *scenario) { s.reqCtx = resourceCtx }))
	add(g.terminal("constraint_unknown_outranks_unverifiable", "unknown outranks unverifiable independent of link order", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}, rootCons: []ratify.ConstraintV2{unknown}}),
		constraintOut("constraint_unknown", 0), nil))
	add(g.terminal("scope_denied_outranks_constraint", "scope_denied precedes constraint results", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}}),
		constraintOut("scope_denied", 0), func(s *scenario) { s.scope = "meeting:attend" }))
	add(g.terminal("audience_domain_match", "trust-domain membership authorizes the receiver after claim", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		allow(), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{membership(0, "domain-a")}
			s.out.CallbackCounts.Audience = 1
			s.out.AllowValidUntil = Now + 600
		}))
	add(g.terminal("audience_exact_mismatch_domain_match", "an exact-ID mismatch alone does not reject when a domain is named; the domain match authorizes", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{exactOrDomain}}),
		allow(), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{membership(0, "domain-a")}
			s.out.CallbackCounts.Audience = 1
			s.out.AllowValidUntil = Now + 600
		}))
	add(g.terminal("audience_membership_missing", "missing required membership is constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), withReceiver))
	add(g.terminal("audience_domain_nonmatch", "authoritative membership ruling out the named domain is constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_denied", 1), func(s *scenario) { withReceiver(s); s.memberships = []membershipJSON{membership(0, "domain-x")} }))
	add(g.terminal("audience_nonmatch_and_missing_leaf_first", "two domain links: valid non-match on the leaf, missing membership on the root: constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_denied", 1), func(s *scenario) { withReceiver(s); s.memberships = []membershipJSON{membership(0, "domain-x")} }))
	add(g.terminal("audience_nonmatch_and_missing_root_first", "two domain links: missing membership on the leaf, valid non-match on the root: constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_denied", 1), func(s *scenario) { withReceiver(s); s.memberships = []membershipJSON{membership(1, "domain-x")} }))
	add(g.terminal("mixed_unverifiable_constraint_and_audience_denied_leaf_first", "leaf resource_path unverifiable, root audience non-match: constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_denied", 1), func(s *scenario) { withReceiver(s); s.memberships = []membershipJSON{membership(1, "domain-x")} }))
	add(g.terminal("mixed_unverifiable_constraint_and_audience_denied_root_first", "leaf audience non-match, root resource_path unverifiable: constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}, rootCons: []ratify.ConstraintV2{resourcePath}}),
		constraintOut("constraint_denied", 1), func(s *scenario) { withReceiver(s); s.memberships = []membershipJSON{membership(0, "domain-x")} }))
	add(g.terminal("mixed_unknown_constraint_and_audience_missing", "unknown constraint and missing audience membership: constraint_unknown", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknown}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_unknown", 1), withReceiver))
	add(g.terminal("mixed_unverifiable_constraint_and_audience_match", "audience passes, resource_path unverifiable: constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) { withReceiver(s); s.memberships = []membershipJSON{membership(1, "domain-b")} }))

	// Closed v2 registry: integer micro-unit amounts, IANA zones the verifier
	// cannot load, and v1 geo types that v2 does not register.
	amount := ratify.ConstraintV2{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 5000000}
	amountCerts := g.chain(chainSpec{rootCons: []ratify.ConstraintV2{amount}})
	amountCtx := func(micros int64, currency string) func(*scenario) {
		return func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: micros, RequestedCurrency: currency}
		}
	}
	add(g.terminal("max_amount_at_limit", "a request of exactly max_amount_micros in the same currency passes", amountCerts, allow(), amountCtx(5000000, "USD")))
	add(g.terminal("max_amount_exceeded", "one micro-unit above max_amount_micros is constraint_denied", amountCerts, constraintOut("constraint_denied", 0), amountCtx(5000001, "USD")))
	add(g.terminal("max_amount_currency_mismatch", "a request in another currency is constraint_denied", amountCerts, constraintOut("constraint_denied", 0), amountCtx(1, "EUR")))
	add(g.terminal("max_amount_missing_context", "an absent authenticated amount is constraint_unverifiable", amountCerts, constraintOut("constraint_unverifiable", 0), nil))
	unknownZone := ratify.ConstraintV2{Type: ratify.ConstraintTimeWindow, Start: "00:00", End: "23:59", TZ: "Ratify/Conformance_Unknown_Zone"}
	add(g.terminal("time_window_unknown_zone", "a tz the verifier time-zone database cannot load is constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknownZone}}),
		constraintOut("constraint_unverifiable", 0), nil))
	geo := ratify.ConstraintV2{Type: ratify.ConstraintGeoCircle, Params: map[string]any{"lat_microdegrees": 0, "lon_microdegrees": 0, "radius_mm": 1000}}
	add(g.terminal("geo_circle_unregistered_in_v2", "geo_circle is not in the v2 registry and fails closed as constraint_unknown", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{geo}}),
		constraintOut("constraint_unknown", 0), nil))

	rateCerts := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}})
	batch := []rateJSON{{IssuerID: g.k("intermediate").ID, CertID: "cert-leaf", WindowS: 60, Limit: 5}}
	add(g.terminal("rate_reserved", "max_rate reserved only after every status is current", rateCerts, allow(), func(s *scenario) {
		s.rate = "reserve"
		s.out.CallbackCounts.Rate = 1
		s.out.RateBatch = batch
	}))
	add(g.terminal("rate_exceeded", "definitive capacity exhaustion is constraint_denied", rateCerts,
		constraintOut("constraint_denied", 0), func(s *scenario) { s.rate = "exceeded"; s.out.CallbackCounts.Rate = 1; s.out.RateBatch = batch }))
	add(g.terminal("rate_store_unavailable", "reservation storage failure is constraint_unverifiable and never assumes capacity", rateCerts,
		constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.rate = "unavailable"; s.out.CallbackCounts.Rate = 1; s.out.RateBatch = batch }))
	add(g.terminal("rate_not_reserved_when_status_unavailable", "no reservation occurs after non-current status", rateCerts,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.rate = "reserve"
			s.status[leafKey(rateCerts)] = unavailable
		}))
	add(g.terminal("rate_not_reserved_after_local_denial", "no reservation occurs after a local policy denial", rateCerts,
		constraintOut("scope_denied", 0), func(s *scenario) { s.rate = "reserve"; s.scope = "meeting:attend" }))

	// Issuer collision: the same cert_id and rate window under two issuers.
	shared := g.chain(chainSpec{leafID: "shared-id", rootID: "shared-id", leafCons: []ratify.ConstraintV2{rate}, rootCons: []ratify.ConstraintV2{rate}})
	add(g.terminal("issuer_scoped_cert_id_collision", "the same cert_id under two issuers is valid; status and rate counters stay issuer-scoped", shared, allow(), func(s *scenario) {
		s.rate = "reserve"
		s.out.CallbackCounts.Rate = 1
		s.out.RateBatch = []rateJSON{{IssuerID: g.k("intermediate").ID, CertID: "shared-id", WindowS: 60, Limit: 5}, {IssuerID: g.k("root").ID, CertID: "shared-id", WindowS: 60, Limit: 5}}
		sort.Slice(s.out.RateBatch, func(i, j int) bool { return s.out.RateBatch[i].IssuerID < s.out.RateBatch[j].IssuerID })
	}))
	add(g.terminal("issuer_collision_status_isolation", "revoking (intermediate, shared-id) does not revoke (root, shared-id) and vice versa", shared,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_shared"]), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.status[leafKey(shared)] = statusResultJSON{Status: "revoked", Evidence: []EvidenceJSON{g.evidence(st["intermediate_revoked_shared"])}}
		}))
	return out
}

// bundleName is a content-derived key so identical bundle bytes are stored once.
func bundleName(wire []byte) string {
	return "bundle-" + hex.EncodeToString(sha256Sum(wire))[:16]
}

func hexRepeat(c byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = "0123456789abcdef"[int(c)%16]
	}
	return string(out)
}
