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

// trustJSON scripts the trust provider: mode ok returns outcome (with
// root_public_key for trusted); mode error returns an error; mode panic panics.
type trustJSON struct {
	Mode          string         `json:"mode"`
	Outcome       string         `json:"outcome,omitempty"`
	RootPublicKey map[string]any `json:"root_public_key,omitempty"`
}

type evidenceObjectJSON struct {
	ObjectTypeCode int    `json:"object_type_code"`
	WireB64        string `json:"wire_b64"`
}

type statusProviderJSON struct {
	Mode    string               `json:"mode"`
	Objects []evidenceObjectJSON `json:"objects"`
}

type statusKeyJSON struct {
	Epoch       uint64         `json:"epoch"`
	StatusKeyID string         `json:"status_key_id"`
	PublicKey   map[string]any `json:"public_key"`
}

type journalPreloadJSON struct {
	IssuerID       string `json:"issuer_id"`
	ObjectTypeCode int    `json:"object_type_code"`
	WireB64        string `json:"wire_b64"`
	Now            int64  `json:"now"`
}

type journalJSON struct {
	Mode    string               `json:"mode"`
	Preload []journalPreloadJSON `json:"preload"`
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
	Progress        int `json:"progress"`
}

type outcomeJSON struct {
	Stage               string         `json:"stage"`
	VerifiedAt          int64          `json:"verified_at,omitempty"`
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
	Name                   string                        `json:"name"`
	Description            string                        `json:"description"`
	Bundle                 string                        `json:"bundle"`
	RequiredScope          string                        `json:"required_scope"`
	ExpectedChallenge      *expectedChallengeJSON        `json:"expected_challenge"`
	ContextPolicy          *contextPolicyJSON            `json:"context_policy"`
	ConfiguredNamespace    string                        `json:"configured_namespace"`
	ConfiguredReplayEpoch  int64                         `json:"configured_replay_epoch"`
	Now                    int64                         `json:"now"`
	MaxChallengeAgeSeconds int64                         `json:"max_challenge_age_seconds"`
	FutureSkewSeconds      int64                         `json:"future_skew_seconds"`
	RequestContext         *requestContextJSON           `json:"request_context"`
	TZDBVersion            string                        `json:"tzdb_version"`
	ReceiverBindingHook    string                        `json:"receiver_binding_hook"`
	ClaimStore             string                        `json:"claim_store"`
	ClaimTimeOffset        int64                         `json:"claim_time_offset"`
	FinalizeTimeOffset     int64                         `json:"finalize_time_offset"`
	Trust                  *trustJSON                    `json:"trust"`
	StatusKeys             map[string]statusKeyJSON      `json:"status_keys"`
	StatusPolicy           statusPolicyJSON              `json:"status_policy"`
	Journal                journalJSON                   `json:"journal"`
	StatusEvidence         map[string]statusProviderJSON `json:"status_evidence"`
	AudienceMode           string                        `json:"audience_mode"`
	AudienceMemberships    []membershipJSON              `json:"audience_memberships"`
	Rate                   string                        `json:"rate"`
	Expected               outcomeJSON                   `json:"expected"`
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
	skew        int64
	reqCtx      *requestContextJSON
	tzdb        *string // nil = the embedded release ratify.TZDBVersionV2
	hook        string
	claim       string
	claimOffset int64
	finOffset   int64
	trust       *trustJSON
	statusKeys  map[string]statusKeyJSON
	policy2     *statusPolicyJSON
	journal     journalJSON
	evidence    map[string]statusProviderJSON
	audience    string
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

// statusKeyConfig is the caller-authenticated status-key configuration of
// every ordering vector: one epoch-1 status key per issuer.
func (g *gen) statusKeyConfig() map[string]statusKeyJSON {
	key := func(name string) statusKeyJSON {
		return statusKeyJSON{Epoch: 1, StatusKeyID: g.k(name).ID, PublicKey: pubJSON(g.k(name).Pub)}
	}
	return map[string]statusKeyJSON{
		g.k("root").ID: key("status_root"), g.k("intermediate").ID: key("status_intermediate"),
		g.k("untrusted_root").ID: key("status_party_b"),
	}
}

// orderingStatusPolicy: a 3660-second list (updated Now-60, next Now+3600)
// is fresh until Now+3600 under both bounds.
var orderingStatusPolicy = statusPolicyJSON{MaxListLifetimeSeconds: 7200, MaxStatusAgeSeconds: 3660, ClockSkewSeconds: 5}

const statusFreshUntil = Now + 3600

func (g *gen) object(f statusFixture) evidenceObjectJSON {
	return evidenceObjectJSON{ObjectTypeCode: int(f.code), WireB64: b64(f.wire)}
}

func evidenceBatch(objects ...evidenceObjectJSON) statusProviderJSON {
	if objects == nil {
		objects = []evidenceObjectJSON{}
	}
	return statusProviderJSON{Mode: "ok", Objects: objects}
}

func providerFailure(mode string) statusProviderJSON {
	return statusProviderJSON{Mode: mode, Objects: []evidenceObjectJSON{}}
}

// currentEvidenceBatches returns, for each issuer of certs, a provider batch
// holding that issuer's fresh signed revocation list.
func (g *gen) currentEvidenceBatches(certs []ratify.DelegationCertV2) map[string]statusProviderJSON {
	st := g.statusFixtures()
	out := map[string]statusProviderJSON{}
	for _, c := range certs {
		switch c.IssuerID {
		case g.k("root").ID:
			out[c.IssuerID] = evidenceBatch(g.object(st["root_current"]))
		case g.k("intermediate").ID:
			out[c.IssuerID] = evidenceBatch(g.object(st["intermediate_current"]))
		}
	}
	return out
}

func (g *gen) preload(f statusFixture, now int64) journalPreloadJSON {
	return journalPreloadJSON{IssuerID: f.issuerID, ObjectTypeCode: int(f.code), WireB64: b64(f.wire), Now: now}
}

func (g *gen) trustRoot(name string) *trustJSON {
	return &trustJSON{Mode: "ok", Outcome: "trusted", RootPublicKey: pubJSON(g.k(name).Pub)}
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
	if s.evidence == nil {
		s.evidence = map[string]statusProviderJSON{}
	}
	if s.statusKeys == nil {
		s.statusKeys = g.statusKeyConfig()
	}
	if s.journal.Mode == "" {
		s.journal.Mode = "anchored"
	}
	if s.journal.Preload == nil {
		s.journal.Preload = []journalPreloadJSON{}
	}
	if s.audience == "" {
		s.audience = "ok"
	}
	if s.skew == 0 {
		s.skew = 5
	}
	if s.skew < 0 {
		s.skew = 0
	}
	tzdb := ratify.TZDBVersionV2
	if s.tzdb != nil {
		tzdb = *s.tzdb
	}
	policy := orderingStatusPolicy
	if s.policy2 != nil {
		policy = *s.policy2
	}
	if s.memberships == nil {
		s.memberships = []membershipJSON{}
	}
	if s.out.Stage == "committed" {
		s.out.VerifiedAt = s.now + s.claimOffset // T_claim (SPEC-v2 §7.2)
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
			ContextAssessment: s.out.ContextAssessment, ContextPolicyDigest: s.out.ContextPolicyDigest, VerifiedAt: s.out.VerifiedAt,
			RequiredScope: s.scope, GrantedScope: granted, StatusEvidence: toLibEvidence(s.out.StatusEvidence),
		}
		s.out.ReceiptBodyB64 = b64(must(ratify.VerificationReceiptV2Body(r)))
		s.out.CallbackCounts.Finalize = 1
	}
	// Evaluation-progress writes (SPEC-v2 §7.5): one before trust resolution
	// starts, one after it completes (also marking a status stage as
	// started), and one after the status stage completes.
	switch {
	case s.out.Stage == "evaluating":
		s.out.CallbackCounts.Progress = 2
		if s.out.CallbackCounts.Status > 0 {
			s.out.CallbackCounts.Progress = 3
		}
	case s.out.Stage != "committed", s.out.DecisionReason == "not_delegated", s.out.TrustAssessment == "not_evaluated":
	case s.out.StatusAssessment == "not_evaluated":
		s.out.CallbackCounts.Progress = 2
	default:
		s.out.CallbackCounts.Progress = 3
	}
	return orderingVector{
		Name: s.name, Description: s.desc, Bundle: bundleName(s.bundle), RequiredScope: s.scope, ExpectedChallenge: s.expected,
		ContextPolicy: s.policy, ConfiguredNamespace: s.namespace, ConfiguredReplayEpoch: s.epoch, Now: s.now,
		MaxChallengeAgeSeconds: s.maxAge, FutureSkewSeconds: s.skew, RequestContext: s.reqCtx, TZDBVersion: tzdb, ReceiverBindingHook: s.hook,
		ClaimStore: s.claim, ClaimTimeOffset: s.claimOffset, FinalizeTimeOffset: s.finOffset, Trust: s.trust, StatusKeys: s.statusKeys,
		StatusPolicy: policy, Journal: s.journal, StatusEvidence: s.evidence, AudienceMode: s.audience, AudienceMemberships: s.memberships,
		Rate: s.rate, Expected: s.out,
	}
}

func preflight(class string, hook int) outcomeJSON {
	return outcomeJSON{Stage: "preflight", ErrorClass: class, CallbackCounts: countsJSON{ReceiverBinding: hook}}
}

func (g *gen) orderingFile() any {
	f := orderingFile{
		Version:     2,
		Description: "End-to-end live verifier ordering vectors (SPEC-v2 §2.5, §6, §7.2). Run the complete decision path with the given inputs and scripted Part B dependencies; compare the stage, error class or committed tuple, the exact receipt outbox body, and the number of times each callback ran. A committed outcome is not a released decision.",
		Semantics: map[string]string{
			"bundle":                           "key into bundles_b64; the exact presented proof bundle bytes",
			"stage":                            "preflight = rejected before claim (no receipt, nothing consumed); replay = claim already existed (no result disclosed, no evaluation); evaluating = claim created but nothing committed (error_class says why; lease-expiry recovery commits evaluation_interrupted later); committed = a terminal Protocol result was committed with receipt_body_b64 (not actionable until released)",
			"configuration":                    "now, max_challenge_age_seconds, future_skew_seconds, status_policy and status_keys are validated against SPEC-v2 §2.5 bounds before the bundle is decoded",
			"tzdb_version":                     "the configured IANA tzdata release required for time_window (SPEC-v2 §5.2); empty = not configured. The corpus assumes the pinned release named in SPEC-v2 §5.2; any other value makes every time_window constraint_unverifiable",
			"receiver_binding_hook":            "absent = no application hook; accept/reject = the pure application hook, invoked only after every built-in pre-claim check passed",
			"claim_store":                      "create = atomic claim succeeds with ClaimedAt = now + claim_time_offset; proof_conflict = challenge already claimed by a different proof digest; in_progress = exact retry while evaluating; terminal_replay = exact retry after commit; unavailable = store error. The claim store's finalization compare-and-set reads T_final = now + claim_time_offset + finalize_time_offset inside the compare-and-set: T_final < T_claim fails with clock_regressed, and an allow commits only while T_final < its allow horizon and T_final < the challenge expiry, else allow_horizon_passed; either failure commits nothing",
			"trust":                            "null = provider returns unavailable; mode ok returns outcome (trusted with root_public_key, untrusted, unavailable, ambiguous); mode error returns an error; mode panic panics",
			"status_keys":                      "caller-authenticated status key per issuer_id (epoch and complete public key)",
			"status_policy":                    "configured status freshness bounds",
			"journal":                          "anchored = reference anchored store; absent = no store configured; unanchored = Load returns a head that does not match the record; load_error = Load fails; cas_conflict = every CompareAndSwap reports a conflict; cas_conflict_once = the 1st, 3rd, 5th, ... CompareAndSwap calls report a conflict and the others proceed. Setup: genesis, then ConfigureStatusKeyEpoch for every status_keys entry in ascending issuer_id order, then each preload object applied at its now under status_policy",
			"status_evidence":                  "per issuer_id provider response: mode ok returns objects (each object_type_code and exact wire bytes); error returns an error; panic panics. An issuer absent from the map returns an empty batch",
			"audience_mode":                    "ok returns audience_memberships; error returns an error; panic panics",
			"audience_memberships":             "caller-authenticated membership results returned by the audience provider",
			"rate":                             "absent = no rate store; reserve = batch reserved; exceeded = definitive capacity exhaustion; unavailable = store error; panic = the store panics",
			"callback_counts.status":           "number of status-provider invocations (one per issuer whose binding, anchoring and role checks passed)",
			"callback_counts.claim":            "number of atomic claim attempts",
			"callback_counts.finalize":         "number of terminal finalize calls",
			"callback_counts.progress":         "number of evaluation-progress writes to the claim store (SPEC-v2 §7.5): before trust resolution starts, after it completes, and after the status stage completes",
			"callback_counts.trust":            "number of trust-provider invocations",
			"callback_counts.audience":         "number of audience-provider invocations",
			"callback_counts.rate":             "number of rate-batch reservations",
			"callback_counts.receiver_binding": "number of application hook invocations",
			"verified_at":                      "the authoritative claim time (T_claim) recorded in the receipt",
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
			trust: g.trustRoot("root"), evidence: g.currentEvidenceBatches(certs), out: preflight(class, 0)}
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
	add(std("challenge_max_age_exact_deadline", "now == issued_at + max_age is not fresh (exclusive deadline)", bundle, "challenge_not_fresh", func(s *scenario) { s.maxAge = 10 }))
	add(std("config_future_skew_above_bound", "configured future skew 301 is outside 0..300 and is rejected before decode and claim", bundle, "configuration_invalid", func(s *scenario) { s.skew = 301 }))
	add(std("config_max_age_above_bound", "configured challenge maximum age 301 is outside 1..300", bundle, "configuration_invalid", func(s *scenario) { s.maxAge = 301 }))
	add(std("config_max_age_below_bound", "configured challenge maximum age below 1 is rejected", bundle, "configuration_invalid", func(s *scenario) { s.maxAge = -1 }))
	add(std("config_status_lifetime_above_bound", "configured status list lifetime 86401 is outside 1..86400", bundle, "configuration_invalid", func(s *scenario) {
		p := orderingStatusPolicy
		p.MaxListLifetimeSeconds = 86401
		s.policy2 = &p
	}))
	reqAmount := func(micros int64, currency string) func(*scenario) {
		return func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: micros, RequestedCurrency: currency}
		}
	}
	add(std("request_amount_negative", "a supplied requested_amount_micros below 0 is configuration_invalid before claim", bundle, "configuration_invalid", reqAmount(-1, "USD")))
	add(std("request_amount_above_safe_integer", "a supplied requested_amount_micros of 2^53 is configuration_invalid before claim", bundle, "configuration_invalid", reqAmount(1<<53, "USD")))
	add(std("request_currency_lowercase", "a lowercase requested_currency is configuration_invalid before claim", bundle, "configuration_invalid", reqAmount(1, "usd")))
	add(std("request_currency_two_letters", "a two-letter requested_currency is configuration_invalid before claim", bundle, "configuration_invalid", reqAmount(1, "US")))
	add(std("request_amount_without_has_amount", "an amount supplied without has_amount is configuration_invalid: amount and currency are supplied together", bundle, "configuration_invalid", func(s *scenario) {
		s.reqCtx = &requestContextJSON{RequestedAmountMicros: 5, RequestedCurrency: "USD"}
	}))
	add(std("config_now_outside_timestamp_domain", "a verifier time below 0 is configuration_invalid", bundle, "configuration_invalid", func(s *scenario) { s.now = -1 }))
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
	out.Stage = "committed"
	s := scenario{name: name, desc: desc, bundle: bundle, certs: certs, scope: "data:read", expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session),
		trust: g.trustRoot("root"), evidence: g.currentEvidenceBatches(certs), out: out}
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
	rootID, intermediateID := g.k("root").ID, g.k("intermediate").ID
	providerError := providerFailure("error")
	revoked := evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
	// staleRoot preloads a root list that was fresh when applied (Now-3990)
	// and whose age reaches the 3660-second bound before Now.
	staleRoot := func(s *scenario) {
		s.journal.Preload = []journalPreloadJSON{g.preload(st["root_stale"], Now-3990)}
		s.evidence[rootID] = evidenceBatch()
	}
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
	add(g.terminal("untrusted_root_consumes_challenge", "the trust provider reports the chain untrusted: a sticky deny is committed and no status callback runs", def,
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = &trustJSON{Mode: "ok", Outcome: "untrusted"} }))
	add(g.terminal("trust_anchor_key_substitution", "the provider returns trusted with a complete key that differs from the chain root: the verifier treats the mismatch as ambiguous (SPEC-v2 §6.1), never trusted", def,
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.trust = &trustJSON{Mode: "ok", Outcome: "trusted", RootPublicKey: pubJSON(g.k("attacker").Pub)}
		}))
	add(g.terminal("trust_unavailable", "no caller-authenticated trust configuration", def,
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = nil }))
	for _, c := range []struct {
		name, desc string
		trust      *trustJSON
	}{
		{"trust_ambiguous", "the trust provider reports more than one matching candidate: never trusted", &trustJSON{Mode: "ok", Outcome: "ambiguous"}},
		{"trust_provider_error", "a trust provider error fails closed", &trustJSON{Mode: "error"}},
		{"trust_provider_panic", "a trust provider panic fails closed", &trustJSON{Mode: "panic"}},
	} {
		trust := c.trust
		add(g.terminal(c.name, c.desc, def, indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = trust }))
	}
	add(g.terminal("delegation_lifetime_exceeds_bound", "expires_at - issued_at above 315360000 seconds is proof_invalid", g.chain(chainSpec{leafIssued: Now - 3600, leafExpires: Now - 3600 + 315360001}),
		deny("proof_invalid", "invalid", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	add(g.terminal("delegation_lifetime_at_bound", "expires_at - issued_at exactly 315360000 seconds passes the lifetime check", g.chain(chainSpec{leafIssued: Now - 3600, leafExpires: Now - 3600 + 315360000}),
		allow(), nil))
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
			s.evidence[intermediateID] = revoked
			s.evidence[rootID] = providerError
		}))
	add(g.terminal("revoked_outranks_scope_denied", "status aggregation precedes a pending local scope denial", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"]), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.scope = "meeting:attend"
			s.evidence[intermediateID] = revoked
		}))
	add(g.terminal("unavailable_outranks_stale", "unavailable on one reference and stale on another yields status_unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_stale"])}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = providerError
			staleRoot(s)
		}))
	add(g.terminal("status_stale", "accepted status beyond its freshness bounds yields status_stale", def,
		indeterminate("status_stale", "trusted", "stale", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(st["root_stale"])}, allowCounts), staleRoot))
	add(g.terminal("unavailable_outranks_scope_denied", "a pending scope denial is not finalized while status is unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.scope = "meeting:attend"
			s.evidence[intermediateID] = providerError
		}))
	add(g.terminal("unauthenticated_status_evidence", "a list signed by a key other than the configured issuer status key fails verification; that issuer's batch is discarded and its status is unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_signed_by_party_b"]))
		}))
	g.statusProvenanceScenarios(add, def, allow, indeterminate, allowCounts, vp)

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
	for _, mode := range []string{"error", "panic"} {
		mode := mode
		add(g.terminal("audience_provider_"+mode, "an audience provider "+mode+" leaves the required membership unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
			constraintOut("constraint_unverifiable", 1), func(s *scenario) { withReceiver(s); s.audience = mode }))
	}
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
	// time_window against the pinned IANA release. Now (2027-01-15T08:00:00Z)
	// is 03:00 EST in America/New_York and 22:30 the previous day in
	// Pacific/Marquesas (UTC-09:30).
	unknownZone := ratify.ConstraintV2{Type: ratify.ConstraintTimeWindow, Start: "00:00", End: "23:59", TZ: "Ratify/Conformance_Unknown_Zone"}
	add(g.terminal("time_window_unknown_zone", "a tz that is not a zone in the configured tzdata release is constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknownZone}}),
		constraintOut("constraint_unverifiable", 0), nil))
	nyWindow := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "02:00", End: "03:30", TZ: "America/New_York"}}})
	add(g.terminal("time_window_tzdb_not_configured", "a time_window with no configured tzdb_version is constraint_unverifiable even inside the window", nyWindow,
		constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.tzdb = strp("") }))
	add(g.terminal("time_window_tzdb_version_mismatch", "a configured tzdb_version other than the loaded release is constraint_unverifiable", nyWindow,
		constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.tzdb = strp("2024a") }))
	add(g.terminal("time_window_inside_sets_horizon", "local 03:00 is inside 02:00-03:30 America/New_York; the allow horizon is the start of local minute 03:31 (08:31:00Z)", nyWindow,
		allow(), func(s *scenario) { s.out.AllowValidUntil = Now + 1860 }))
	add(g.terminal("time_window_outside_denied", "local 03:00 is outside 09:00-17:00 America/New_York: constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "09:00", End: "17:00", TZ: "America/New_York"}}}),
		constraintOut("constraint_denied", 0), nil))
	add(g.terminal("time_window_wraps_midnight", "local 22:30 is inside the wrapping window 22:00-00:10 Pacific/Marquesas; its horizon (next local day 00:11, 09:41:00Z) is later than status freshness", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "22:00", End: "00:10", TZ: "Pacific/Marquesas"}}}),
		allow(), nil))
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
	add(g.terminal("rate_store_panic", "a rate store panic is handled like a storage failure: constraint_unverifiable", rateCerts,
		constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.rate = "panic"; s.out.CallbackCounts.Rate = 1; s.out.RateBatch = batch }))
	add(g.terminal("rate_store_unavailable", "reservation storage failure is constraint_unverifiable and never assumes capacity", rateCerts,
		constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.rate = "unavailable"; s.out.CallbackCounts.Rate = 1; s.out.RateBatch = batch }))
	add(g.terminal("rate_not_reserved_when_status_unavailable", "no reservation occurs after non-current status", rateCerts,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.rate = "reserve"
			s.evidence[intermediateID] = providerError
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
			s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_revoked_shared"]))
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

// statusProvenanceScenarios covers SPEC-v2 §6.5 status provenance, the
// §6.11 provider failure classes, §2.5 exclusive status deadlines, and
// §7.2/§7.5 finalization clock rules.
func (g *gen) statusProvenanceScenarios(add func(scenario), def []ratify.DelegationCertV2, allow func() outcomeJSON,
	indeterminate func(reason, trust, status, context string, digest *string, evidence []EvidenceJSON, counts countsJSON) outcomeJSON, allowCounts countsJSON, vp string) {
	st := g.statusFixtures()
	rootID, intermediateID := g.k("root").ID, g.k("intermediate").ID
	rootOnly := []EvidenceJSON{g.evidence(st["root_current"])}
	unavailableIntermediate := func(name, desc string, counts countsJSON, edit func(*scenario)) {
		add(g.terminal(name, desc, def, indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), rootOnly, counts), edit))
	}
	unavailableIntermediate("status_provider_error", "a status provider error makes that issuer's references unavailable", allowCounts,
		func(s *scenario) { s.evidence[intermediateID] = providerFailure("error") })
	unavailableIntermediate("status_provider_panic", "a status provider panic is handled exactly like an error", allowCounts,
		func(s *scenario) { s.evidence[intermediateID] = providerFailure("panic") })
	unavailableIntermediate("status_batch_malformed_object", "an object that fails strict decoding rejects the whole batch", allowCounts, func(s *scenario) {
		s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_current"]), evidenceObjectJSON{ObjectTypeCode: int(codeList), WireB64: b64([]byte("{"))})
	})
	unavailableIntermediate("status_batch_unknown_object_type", "an object code other than 3 or 5 rejects the whole batch", allowCounts, func(s *scenario) {
		s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_current"]), evidenceObjectJSON{ObjectTypeCode: 7, WireB64: g.object(st["intermediate_current"]).WireB64})
	})
	unavailableIntermediate("status_batch_oversized", "a batch of 65 objects exceeds the 64-object bound", allowCounts, func(s *scenario) {
		objects := make([]evidenceObjectJSON, 65)
		for i := range objects {
			objects[i] = g.object(st["intermediate_current"])
		}
		s.evidence[intermediateID] = evidenceBatch(objects...)
	})
	unavailableIntermediate("status_batch_wrong_issuer", "an object naming another issuer fails authentication and rejects the batch", allowCounts, func(s *scenario) {
		s.evidence[intermediateID] = evidenceBatch(g.object(st["root_current"]))
	})
	unavailableIntermediate("status_issuer_unconfigured", "an issuer without a caller-authenticated status key is unavailable and its provider is not called", countsJSON{Claim: 1, Trust: 1, Status: 1}, func(s *scenario) {
		s.statusKeys = g.statusKeyConfig()
		delete(s.statusKeys, intermediateID)
	})
	mixed := g.mixedKey()
	add(g.terminal("status_key_component_reuse", "a status key that reuses the intermediate issuer's Ed25519 component under a different ML-DSA component (different key ID) is a chain key sharing a component with a status binding (SPEC-v2 §6.5 step 2); the check is chain-wide, so every issuer is unavailable and no provider is called", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), nil, countsJSON{Claim: 1, Trust: 1}), func(s *scenario) {
			s.statusKeys = g.statusKeyConfig()
			s.statusKeys[intermediateID] = statusKeyJSON{Epoch: 1, StatusKeyID: mixed.ID, PublicKey: pubJSON(mixed.Pub)}
		}))
	unavailableIntermediate("status_key_is_verifier_key", "a status key equal to the verifier key named by the proof's verifier_id violates role separation (SPEC-v2 §6.5 step 2): that issuer is unavailable and its provider is not called", countsJSON{Claim: 1, Trust: 1, Status: 1}, func(s *scenario) {
		s.statusKeys = g.statusKeyConfig()
		s.statusKeys[intermediateID] = statusKeyJSON{Epoch: 1, StatusKeyID: g.k("verifier").ID, PublicKey: pubJSON(g.k("verifier").Pub)}
	})
	for _, c := range []struct {
		mode, desc string
		queries    int
	}{
		{"absent", "no status journal is configured: every reference is unavailable and no provider is called", 0},
		{"unanchored", "the journal record does not match the store's anchored head: never not_revoked, no provider call", 0},
		{"load_error", "the journal store fails to load: unavailable, no provider call", 0},
		{"cas_conflict", "the compare-and-swap of each issuer's transition conflicts on both the attempt and its single reload-and-reapply retry: unavailable", 2},
	} {
		mode := c.mode
		add(g.terminal("status_journal_"+c.mode, c.desc, def, indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), nil, countsJSON{Claim: 1, Trust: 1, Status: c.queries}),
			func(s *scenario) { s.journal.Mode = mode }))
	}
	add(g.terminal("status_journal_cas_conflict_once", "each issuer's first compare-and-swap conflicts; the verifier reloads the anchored journal, rechecks the binding and role separation, and reapplies the same batch once without calling the provider again: allow", def, allow(),
		func(s *scenario) { s.journal.Mode = "cas_conflict_once" }))
	add(g.terminal("status_next_update_exact_deadline", "a list whose next_update equals the evaluation time is not fresh (exclusive deadline): stale", def,
		indeterminate("status_stale", "trusted", "stale", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(st["root_next_at_now"])}, allowCounts), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(st["root_next_at_now"], Now-30)}
			s.evidence[rootID] = evidenceBatch()
		}))
	add(g.terminal("status_one_second_before_next_update", "a list whose next_update is one second after the evaluation time is fresh and bounds the allow horizon", def, allow(), func(s *scenario) {
		s.evidence[rootID] = evidenceBatch(g.object(st["root_next_plus_one"]))
		s.out.StatusEvidence = []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(st["root_next_plus_one"])}
		s.out.AllowValidUntil = Now + 1
	}))
	add(g.terminal("status_age_exact_deadline", "accepted status whose updated_at plus the configured age equals the evaluation time is stale (exclusive deadline)", def,
		indeterminate("status_stale", "trusted", "stale", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(st["root_age_at_now"])}, allowCounts), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(st["root_age_at_now"], Now-3600)}
			s.evidence[rootID] = evidenceBatch()
		}))
	// Authoritative clock and finalization (SPEC-v2 §7.2, §7.5).
	add(g.terminal("claim_time_outside_challenge_interrupts", "the store's authoritative claim time equals the challenge expiry: evaluation is interrupted before trust, with every assessment not_evaluated", def,
		indeterminate("evaluation_interrupted", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil, countsJSON{Claim: 1}), func(s *scenario) { s.claimOffset = 290 }))
	evaluating := func(class string) outcomeJSON {
		counts := allowCounts
		counts.Finalize = 1 // the store rejects the compare-and-set itself
		return outcomeJSON{Stage: "evaluating", ErrorClass: class, CallbackCounts: counts}
	}
	add(g.terminal("finalization_clock_regressed", "the finalization reading is earlier than the claim reading: nothing is committed and the claim stays evaluating", def, outcomeJSON{}, func(s *scenario) {
		s.finOffset = -1
		s.out = evaluating("clock_regressed")
	}))
	add(g.terminal("allow_at_challenge_expiry_at_finalization", "an allow whose finalization time equals the challenge expiry is not committed (exclusive deadline)", def, outcomeJSON{}, func(s *scenario) {
		s.finOffset = 290
		s.out = evaluating("allow_horizon_passed")
	}))
	add(g.terminal("allow_one_second_before_challenge_expiry_at_finalization", "an allow finalized one second before the challenge expiry commits with verified_at equal to the claim time", def, allow(), func(s *scenario) {
		s.finOffset = 289
	}))
}

// mixedKey is a status key that reuses the intermediate issuer's Ed25519
// component with a different ML-DSA-65 component, so its key ID differs.
func (g *gen) mixedKey() *Key {
	var ml [32]byte
	for i := range ml {
		ml[i] = 0x53
	}
	ed := g.k("intermediate").EdSeed
	pub, priv := must2(ratify.HybridKeypairFromSeeds(ed, ml))
	return &Key{Name: "status_component_reuse", Pub: pub, Priv: priv, ID: keyIDV2(pub), EdSeed: ed, MLSeed: ml}
}
