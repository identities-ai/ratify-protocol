package v2vectors

// Additional end-to-end ordering cases (SPEC-v2 §2.5, §5.2, §5.4, §6).
// Each expectation is derived from the specification text: two-fault cases
// pin the first failing check of §6.2, and post-claim cases pin the §6.4
// order, the §5.4 status reducer, the §5.2 constraint models and the
// verifier's configured identity (§6.1).

import (
	"bytes"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func (g *gen) orderingProbeScenarios() []scenario {
	agent, root := g.k("agent"), g.k("root")
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	st := g.statusFixtures()
	intermediateID := g.k("intermediate").ID
	allowCounts := countsJSON{Claim: 1, Trust: 1, Status: 2}
	noStatus := countsJSON{Claim: 1, Trust: 1}
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
	constraintOut := func(reason string, audience int) outcomeJSON {
		return deny(reason, reason, "trusted", "current", "bound", strp(vp), g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Audience: audience})
	}
	var out []scenario
	add := func(s scenario) { out = append(out, s) }

	bundle, certs, session := g.base()
	std := func(name, desc string, b []byte, class string, edit func(*scenario)) scenario {
		s := scenario{name: name, desc: desc, bundle: b, certs: certs, scope: "data:read", expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session),
			trust: g.trustRoot("root"), evidence: g.currentEvidenceBatches(certs), out: preflight(class, 0)}
		if edit != nil {
			edit(&s)
		}
		return s
	}
	def := g.chain(chainSpec{})

	// ---------------- Pre-claim.
	add(std("pre_future_replay_epoch", "spec §6.1: replay_epoch MUST equal the configured epoch; a later epoch is rejected", bundle, "stale_replay_epoch", func(s *scenario) { s.expected.ReplayEpoch = 4 }))
	add(std("pre_namespace_case_variant", "namespace is byte equality", bundle, "namespace_mismatch", func(s *scenario) { s.expected.VerifierNamespace = "Verify-test" }))
	futureAt := func(at int64) []byte {
		_, w, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: session, challengeAt: at})
		return w
	}
	add(std("pre_expires_before_issued_within_skew", "an ExpectedChallenge with issued_at = now+3 (inside the skew) and expires_at = now+2 breaks issued_at < expires_at: configuration_invalid even though each freshness inequality alone holds", futureAt(Now+3), "configuration_invalid", func(s *scenario) {
		s.expected.IssuedAt, s.expected.ExpiresAt = Now+3, Now+2
	}))
	add(std("pre_skew0_issued_now_plus_1", "future_skew 0: issued_at = now+1 is not fresh", futureAt(Now+1), "challenge_not_fresh", func(s *scenario) {
		s.expected.IssuedAt, s.expected.ExpiresAt = Now+1, Now+200
		s.skew = -1 // finish() maps negative to 0
		p := orderingStatusPolicy
		p.ClockSkewSeconds = 0
		s.policy2 = &p
	}))
	exactAud := []ratify.ConstraintV2{{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-1"}, "trust_domain_ids": []any{}}}}
	exactCerts := g.chain(chainSpec{leafCons: exactAud})
	_, exactWire, _ := g.bundle(bundleSpec{agent: agent, certs: exactCerts, session: session})
	add(std("pre_receiver_empty_string_exact_only", "an empty expected_receiver_id is not a receiver ID (1 to 512 bytes), so no receiver is supplied for an exact-only audience", exactWire, "receiver_audience_required", func(s *scenario) { s.expected.ExpectedReceiverID = strp("") }))
	add(std("pre_receiver_case_variant", "exact receiver IDs compare by bytes", exactWire, "receiver_audience_mismatch", func(s *scenario) { s.expected.ExpectedReceiverID = strp("Receiver-1") }))
	add(std("pre_expected_agent_id_empty_with_key", "an expected agent key with an empty expected agent ID: the two are not supplied together (step 7)", bundle, "configuration_invalid", func(s *scenario) { s.expected.ExpectedAgentID = strp("") }))
	add(std("pre_expected_session_empty", "expected_session_context present with 0 bytes is not exactly 32 bytes: configuration_invalid (step 2)", bundle, "configuration_invalid", func(s *scenario) { s.expected.ExpectedSessionContextB64 = strp("") }))
	add(std("pre_custom_scope_257_bytes", "a custom: required scope over 256 bytes is invalid_required_scope", bundle, "invalid_required_scope", func(s *scenario) { s.scope = "custom:" + strings.Repeat("a", 250) }))
	add(std("pre_scope_case_variant", "Data:read is not a registered scope", bundle, "invalid_required_scope", func(s *scenario) { s.scope = "Data:read" }))
	add(std("pre_not_required_policy_with_expected_session", "a not-required policy with an expected session context is inconsistent: configuration_invalid", bundle, "configuration_invalid", func(s *scenario) { s.policy = g.notRequiredPolicyJSON() }))
	add(std("pre_hook_reject_and_claim_absent", "claim store absent (step 2) precedes the hook (step 9)", bundle, "configuration_invalid", func(s *scenario) { s.hook = "reject"; s.claim = "absent" }))
	add(std("pre_audience_required_and_receiver_on_wrong_link", "two audience links (exact-only leaf with receiver-1, exact-only root without it): mismatch", func() []byte {
		c := g.chain(chainSpec{leafCons: exactAud, rootCons: []ratify.ConstraintV2{{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-2"}, "trust_domain_ids": []any{}}}}})
		_, w, _ := g.bundle(bundleSpec{agent: agent, certs: c, session: session})
		return w
	}(), "receiver_audience_mismatch", func(s *scenario) { s.expected.ExpectedReceiverID = strp("receiver-1") }))

	// tz spelling checks at decode (§5.2 tz grammar): malformed before claim.
	for _, tz := range []struct{ name, tz string }{{"dot_char", "tzdata.zi"}, {"empty_segment", "UTC/"}, {"dotdot_segment", "Etc/../UTC"}, {"len65", strings.Repeat("A", 65)}, {"space", "America/New York"}} {
		c := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "00:00", End: "23:59", TZ: "AAAA"}}})
		_, w, _ := g.bundle(bundleSpec{agent: agent, certs: c, session: session})
		bo := parse(w).(map[string]any)
		leaf := obj(arr(bo["delegations"])[0])
		obj(arr(leaf["constraints"])[0])["tz"] = tz.tz
		delete(leaf, "signature")
		leafSig := signDetUnchecked(g.k("intermediate"), codeDelegation, canon(leaf))
		leaf["signature"] = sigJSON(leafSig)
		add(std("pre_tz_"+tz.name, "tz outside the §5.2 grammar is malformed before claim", g.resign(bo, agent), "malformed", nil))
	}

	// ---------------- Post-claim: generic cases.
	add(g.terminal("post_empty_chain_no_policy", "empty chain with no context policy: not_delegated, context not_evaluated", nil,
		deny("not_delegated", "delegation_not_authorized", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil, countsJSON{Claim: 1}), func(s *scenario) {
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent})
			s.expected = g.defaultExpected(agent, nil)
			s.policy = nil
		}))
	add(g.terminal("post_receiver_empty_no_audience", "an empty expected_receiver_id is not consulted when no link carries an audience constraint", def, allow(), func(s *scenario) { s.expected.ExpectedReceiverID = strp("") }))
	add(g.terminal("post_receiver_set_no_audience", "an expected receiver without any audience constraint is harmless", def, allow(), func(s *scenario) { s.expected.ExpectedReceiverID = strp("receiver-1") }))
	add(g.terminal("post_tzdb_garbage_no_time_window", "tzdb_version is consulted only when a time_window is evaluated; a chain without one is unaffected by its value", def, allow(), func(s *scenario) { s.tzdb = strp("not-a-release") }))
	add(g.terminal("post_no_expected_agent_generic", "generic profile with no expected agent fields", def, allow(), func(s *scenario) {
		s.expected.ExpectedAgentID = nil
		s.expected.ExpectedAgentPublicKey = nil
	}))
	add(g.terminal("post_trusted_without_root_key", "trust provider says trusted but returns no root key: never trusted (§6.1)", def,
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = &trustJSON{Mode: "ok", Outcome: "trusted"} }))
	add(g.terminal("post_issued_equals_expires", "issued_at == expires_at in a signed certificate is proof_invalid after claim", g.chain(chainSpec{leafIssued: Now + 1, leafExpires: Now + 1}),
		deny("proof_invalid", "invalid", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), nil))
	single, _, _ := g.cert(certSpec{issuer: root, subject: agent, certID: "cert-single", scope: []string{"data:read"}})
	add(g.terminal("post_single_link_chain", "a one-link chain root->agent allows", []ratify.DelegationCertV2{single}, allow(), func(s *scenario) {
		s.out.GrantedScope = []string{"data:read"}
		s.out.StatusEvidence = []EvidenceJSON{g.evidence(st["root_current"])}
		s.out.CallbackCounts.Status = 1
	}))
	add(g.terminal("post_claim_time_before_issue_skew", "authoritative claim time earlier than issued_at - skew: the claim is outside the sealed challenge bounds", def,
		outcomeJSON{Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified", TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ContextAssessment: "not_evaluated", CallbackCounts: countsJSON{Claim: 1}}, func(s *scenario) {
			s.claimOffset = -20
		}))

	// ---------------- Context policy digests for generic policies.
	customFields := []string{"session_id", "agent_id"}
	add(g.terminal("ctx_custom_policy_field_order", "a generic bound policy's digest is the canonical JSON of its object, with required_fields in configured order (arrays are not sorted)", def, allow(), func(s *scenario) {
		s.policy = &contextPolicyJSON{Profile: "example.custom-context/v1", RequireBound: true, RequiredFields: customFields, ExpectedSessionContextB64: strp(b64(session)), Digest: policyDigest("example.custom-context/v1", true, customFields)}
		s.out.ContextPolicyDigest = strp(policyDigest("example.custom-context/v1", true, customFields))
	}))
	add(g.terminal("ctx_not_required_policy_with_fields", "an unbound generic policy that lists fields records not_required and its digest", def, allow(), func(s *scenario) {
		_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, certs: def})
		s.expected = g.defaultExpected(agent, nil)
		s.policy = &contextPolicyJSON{Profile: "example.unbound/v1", RequireBound: false, RequiredFields: []string{"z", "a"}, Digest: policyDigest("example.unbound/v1", false, []string{"z", "a"})}
		s.out.ContextAssessment, s.out.ContextPolicyDigest = "not_required", strp(policyDigest("example.unbound/v1", false, []string{"z", "a"}))
	}))

	// ---------------- Rate never reserved after a non-rate local result.
	rate := ratify.ConstraintV2{Type: ratify.ConstraintMaxRate, Count: 5, WindowS: 60}
	add(g.terminal("rate_and_no_policy", "no context policy: action_context_unverified, no reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}}),
		indeterminate("action_context_unverified", "trusted", "current", "unverified", nil, g.currentEvidence(), allowCounts), func(s *scenario) {
			s.rate = "reserve"
			s.expected = g.defaultExpected(agent, nil)
			s.policy = nil
		}))
	add(g.terminal("rate_and_context_mismatch", "post-claim context mismatch: constraint_denied, no reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}}),
		deny("constraint_denied", "constraint_denied", "trusted", "current", "mismatch", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) {
			s.rate = "reserve"
			s.expected.ExpectedSessionContextB64 = nil
			s.policy.ExpectedSessionContextB64 = strp(b64(bytes.Repeat([]byte{0x33}, 32)))
		}))
	maxNodes := ratify.ConstraintV2{Type: maxCountType, Params: map[string]any{"counter": "nodes", "max": 10}}
	stdCount := evaluatorJSON{Type: maxCountType, Profile: maxCountProfile, Implementation: maxCountProfile}
	add(g.terminal("rate_and_evaluator_denied", "extension profile denies: constraint_denied, no reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate, maxNodes}}),
		constraintOut("constraint_denied", 0), func(s *scenario) {
			s.rate = "reserve"
			s.evaluators = []evaluatorJSON{stdCount}
			s.reqCtx = &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 11}}
			s.out.CallbackCounts.Evaluator = 1
		}))
	add(g.terminal("rate_and_time_window_outside", "time_window outside: constraint_denied, no reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate, {Type: ratify.ConstraintTimeWindow, Start: "09:00", End: "17:00", TZ: "America/New_York"}}}),
		constraintOut("constraint_denied", 0), func(s *scenario) { s.rate = "reserve" }))
	add(g.terminal("rate_absent_store", "max_rate with no rate store configured: constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}}),
		constraintOut("constraint_unverifiable", 0), nil))

	// ---------------- Status evidence: rollback, forks, pushes, future, batch size.
	mk := func(seq, updated int64, revoked ...string) statusFixture {
		_, wire, _ := g.list(g.k("status_intermediate"), intermediateID, seq, updated, updated+3660, revoked...)
		return statusFixture{wire, codeList, intermediateID, "status_intermediate", seq, statusEvidenceDigest(codeList, wire)}
	}
	mkAt := func(seq, updated, next int64, revoked ...string) statusFixture {
		_, wire, _ := g.list(g.k("status_intermediate"), intermediateID, seq, updated, next, revoked...)
		return statusFixture{wire, codeList, intermediateID, "status_intermediate", seq, statusEvidenceDigest(codeList, wire)}
	}
	mkPush := func(seq, at int64, revoked ...string) statusFixture {
		_, wire, _ := g.push(g.k("status_intermediate"), intermediateID, seq, at, revoked...)
		return statusFixture{wire, codePush, intermediateID, "status_intermediate", seq, statusEvidenceDigest(codePush, wire)}
	}
	l1, l2 := mk(1, Now-120), mk(2, Now-60)
	l1rev := mk(1, Now-100, "cert-leaf")
	l1other := mk(1, Now-100, "other-cert")
	rootEv := g.evidence(st["root_current"])
	add(g.terminal("status_rollback_lower_snapshot_ignored", "journal at seq 2; provider returns a fresh consistent seq-1 list: below the floor, a no-op, allow from seq 2", def, allow(), func(s *scenario) {
		s.journal.Preload = []journalPreloadJSON{g.preload(l2, Now-30)}
		s.evidence[intermediateID] = evidenceBatch(g.object(l1))
		s.out.StatusEvidence = []EvidenceJSON{g.evidence(l2), rootEv}
		s.out.AllowValidUntil = Now - 60 + 3660
	}))
	add(g.terminal("status_rollback_lower_snapshot_new_revocation", "journal at seq 2; a seq-1 list revoking cert-leaf contradicts accepted later state: fork, deny_union gains cert-leaf, revoked", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(l2), g.evidence(l1rev), rootEv}, allowCounts), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(l2, Now-30)}
			s.evidence[intermediateID] = evidenceBatch(g.object(l1rev))
		}))
	add(g.terminal("status_fork_against_preloaded", "journal accepted seq 1; a different seq-1 list arrives: fork, unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(l1), g.evidence(l1other), rootEv}, allowCounts), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(l1, Now-30)}
			s.evidence[intermediateID] = evidenceBatch(g.object(l1other))
		}))
	p2other, p2leaf := mkPush(2, Now-50, "other-cert"), mkPush(2, Now-50, "cert-leaf")
	add(g.terminal("status_contiguous_push_allow", "accepted list seq 1 then contiguous push seq 2 revoking another cert: not_revoked with list+push evidence", def, allow(), func(s *scenario) {
		s.journal.Preload = []journalPreloadJSON{g.preload(l1, Now-30)}
		s.evidence[intermediateID] = evidenceBatch(g.object(p2other))
		s.out.StatusEvidence = []EvidenceJSON{g.evidence(l1), g.evidence(p2other), rootEv}
		s.out.AllowValidUntil = Now - 120 + 3660
	}))
	add(g.terminal("status_contiguous_push_revokes_leaf", "contiguous push revoking cert-leaf: revoked", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(l1), g.evidence(p2leaf), rootEv}, allowCounts), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(l1, Now-30)}
			s.evidence[intermediateID] = evidenceBatch(g.object(p2leaf))
		}))
	p1 := mkPush(1, Now-50, "other-cert")
	add(g.terminal("status_push_before_bootstrap", "only a push at seq 1 and no full list: unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(p1), rootEv}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(p1))
		}))
	lf := mkAt(1, Now+60, Now+3000)
	add(g.terminal("status_future_dated_list", "a list with updated_at beyond now+skew: unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(lf), rootEv}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(lf))
		}))
	lskew := mkAt(1, Now+5, Now+3000)
	add(g.terminal("status_list_at_now_plus_skew", "updated_at == now + skew is fresh (inclusive lower bound)", def, allow(), func(s *scenario) {
		s.evidence[intermediateID] = evidenceBatch(g.object(lskew))
		s.out.StatusEvidence = []EvidenceJSON{g.evidence(lskew), rootEv}
		s.out.AllowValidUntil = Now + 3000
	}))
	lstale2 := mkAt(2, Now-5000, Now-1400)
	add(g.terminal("status_stale_snapshot_above_floor", "accepted seq 1; a non-fresh seq-2 list above the floor requires reconciliation: unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(l1), g.evidence(lstale2), rootEv}, allowCounts), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(l1, Now-30)}
			s.evidence[intermediateID] = evidenceBatch(g.object(lstale2))
		}))
	many := func(n int) statusProviderJSON {
		objs := make([]evidenceObjectJSON, n)
		for i := range objs {
			objs[i] = g.object(st["intermediate_current"])
		}
		return evidenceBatch(objs...)
	}
	add(g.terminal("status_batch_64_objects", "a batch of exactly 64 objects is within bounds", def, allow(), func(s *scenario) { s.evidence[intermediateID] = many(64) }))
	add(g.terminal("status_reconcile_fork_with_higher_snapshot", "a preloaded fork at seq 1 is reconciled by a fresh seq-2 list containing the deny union", def, allow(), func(s *scenario) {
		l1a, l1b := mk(1, Now-300), mk(1, Now-300, "other-cert")
		l2u := mk(2, Now-60, "other-cert")
		s.journal.Preload = []journalPreloadJSON{g.preload(l1a, Now-200), g.preload(l1b, Now-200)}
		s.evidence[intermediateID] = evidenceBatch(g.object(l2u))
		s.out.StatusEvidence = []EvidenceJSON{g.evidence(l2u), rootEv}
		s.out.AllowValidUntil = Now - 60 + 3660
	}))

	// ---------------- Audience membership shapes.
	domainA := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}}
	membership := func(link int, domains ...string) membershipJSON {
		if domains == nil {
			domains = []string{}
		}
		return membershipJSON{DelegationIndex: link, ReceiverID: "receiver-1", TrustDomainIDs: domains, IssuedAt: Now - 60, ExpiresAt: Now + 600, EvidenceDigest: "sha384:" + hexRepeat(byte('a'+link), 96)}
	}
	withReceiver := func(s *scenario) { s.expected.ExpectedReceiverID = strp("receiver-1") }
	audCerts := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}})
	add(g.terminal("aud_membership_duplicate_domains", "a membership listing a domain twice is not well-formed evidence: unverifiable", audCerts,
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{membership(0, "domain-a", "domain-a")}
		}))
	add(g.terminal("aud_membership_bad_digest", "a membership evidence digest that is not sha384: followed by 96 lowercase hex characters is unverifiable", audCerts,
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.EvidenceDigest = "sha384:XYZ"
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_membership_expires_before_issued", "membership evidence with issued_at = now+3 (inside the skew) and expires_at = now+2 breaks issued_at < expires_at: unverifiable", audCerts,
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.IssuedAt, m.ExpiresAt = Now+3, Now+2
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_membership_expires_equals_issued", "membership evidence with issued_at == expires_at breaks issued_at < expires_at: unverifiable", audCerts,
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.ExpiresAt = m.IssuedAt
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_membership_wrong_constraint_index", "a membership for constraint index 1 does not cover the constraint at index 0", audCerts,
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.ConstraintIndex = 1
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_membership_extra_link_ignored", "a membership for an unconstrained link alongside a valid one", audCerts, allow(), func(s *scenario) {
		withReceiver(s)
		s.memberships = []membershipJSON{membership(0, "domain-a"), membership(1, "domain-x")}
		s.out.CallbackCounts.Audience = 1
		s.out.AllowValidUntil = Now + 600
	}))
	add(g.terminal("aud_membership_negative_issued", "a membership time outside the timestamp domain is unverifiable", audCerts,
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.IssuedAt = -1
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_untrusted_no_audience_call", "untrusted root: no audience call", audCerts,
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			withReceiver(s)
			s.trust = &trustJSON{Mode: "ok", Outcome: "untrusted"}
		}))
	add(g.terminal("aud_revoked_audience_count", "revoked status decides before the deferred domain audience, which is not resolved", audCerts,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"]), rootEv}, allowCounts), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{membership(0, "domain-a")}
			s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
		}))
	// ---------------- time_window zone-name membership in tzdata 2025c.
	// The window 00:00-23:59 passes whenever the zone loads, so a name that
	// is a Zone or Link line in 2025c allows and any other name is
	// constraint_unverifiable.
	zones := []struct {
		tz    string
		known bool
	}{
		{"posixrules", false}, {"Factory", true}, {"localtime", false}, {"right/UTC", false}, {"posix/UTC", false},
		{"EST5EDT", true}, {"Etc/GMT+5", true}, {"Etc/GMT+13", false}, {"Etc/GMT-14", true}, {"GMT0", true}, {"Zulu", true}, {"UCT", true},
		{"US/Pacific-New", false}, {"America/Ciudad_Juarez", true}, {"+VERSION", false}, {"SystemV/EST5", false}, {"WET", true}, {"America/Nuuk", true},
		{"Asia/Rangoon", true}, {"Europe/Kyiv", true}, {"Europe/Kiev", true}, {"Canada/East-Saskatchewan", false}, {"ROC", true}, {"Etc/Unknown", false},
	}
	for _, z := range zones {
		c := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "00:00", End: "23:59", TZ: z.tz}}})
		name := "tz_" + strings.NewReplacer("/", "_", "+", "plus", "-", "minus").Replace(z.tz)
		if z.known {
			add(g.terminal(name, "zone "+z.tz+" is in tzdata 2025c: the full-day window passes", c, allow(), nil))
		} else {
			add(g.terminal(name, "name "+z.tz+" is not a Zone or Link in tzdata 2025c: constraint_unverifiable", c, constraintOut("constraint_unverifiable", 0), nil))
		}
	}
	nyWindow := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "02:00", End: "03:30", TZ: "America/New_York"}}})
	add(g.terminal("tz_tzdb_uppercase", "tzdb_version 2025C differs from 2025c: unverifiable", nyWindow, constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.tzdb = strp("2025C") }))
	add(g.terminal("tz_tzdb_trailing_space", "tzdb_version \"2025c \" differs: unverifiable", nyWindow, constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.tzdb = strp("2025c ") }))

	// ---------------- Step 4 internal order, scopes, resource_path.
	attacker, inter := g.k("attacker"), g.k("intermediate")
	c0, _, _ := g.cert(certSpec{issuer: inter, subject: agent, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	c1, _, _ := g.cert(certSpec{issuer: root, subject: attacker, certID: "c1", scope: []string{"data:read", "identity:delegate"}})
	c2, _, _ := g.cert(certSpec{issuer: inter, subject: root, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	_, linkDup, _ := g.bundle(bundleSpec{agent: agent, certs: []ratify.DelegationCertV2{c0, c1, c2}, session: session})
	add(std("pre_link_before_later_duplicate", "step 4: link 0->1 is checked before the duplicate at index 2", linkDup, "chain_linkage_mismatch", nil))
	d0, _, _ := g.cert(certSpec{issuer: inter, subject: attacker, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	d1, _, _ := g.cert(certSpec{issuer: inter, subject: inter, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	d2, _, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "identity:delegate"}})
	_, dupLeaf, _ := g.bundle(bundleSpec{agent: agent, certs: []ratify.DelegationCertV2{d0, d1, d2}, session: session})
	add(std("pre_duplicate_before_leaf_subject", "step 4: the duplicate at index 1 precedes the leaf-subject check", dupLeaf, "duplicate_certificate_ref", nil))
	add(std("pre_keyid_before_linkage", "step 4: a certificate key-ID mismatch precedes chain linkage", mutate(linkDup, func(o map[string]any) {
		obj(arr(o["delegations"])[1])["subject_id"] = agent.ID
	}), "key_id_mismatch", nil))
	add(std("pre_digest_before_linkage", "step 4: delegation_digest precedes chain linkage", mutate(linkDup, func(o map[string]any) {
		o["delegation_digest"] = flipB64(o["delegation_digest"])
	}), "delegation_digest_mismatch", nil))
	early := func(reason, identity string) outcomeJSON {
		return deny(reason, identity, "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus)
	}
	add(g.terminal("scope_empty_string_entry", "an empty scope string in a signed certificate is invalid_scope after claim", g.chain(chainSpec{leafScope: []string{"data:read", ""}}), early("invalid_scope", "invalid_scope"), nil))
	add(g.terminal("scope_identity_wildcard", "identity:* is not a registered wildcard: invalid_scope (before delegation_not_authorized)", g.chain(chainSpec{rootScope: []string{"data:read", "files:read", "identity:*"}}), early("invalid_scope", "invalid_scope"), nil))
	add(g.terminal("scope_files_wildcard", "files:* is not a registered wildcard: invalid_scope", g.chain(chainSpec{leafScope: []string{"data:read", "files:*"}}), early("invalid_scope", "invalid_scope"), nil))
	add(g.terminal("scope_actuate_wildcard", "actuate:* is not a registered wildcard: invalid_scope", g.chain(chainSpec{leafScope: []string{"data:read", "actuate:*"}}), early("invalid_scope", "invalid_scope"), nil))
	add(g.terminal("scope_comms_wildcard_calendar_write", "comms:* expands to the 6 non-sensitive comms scopes including comms:calendar:write", g.chain(chainSpec{leafScope: []string{"comms:*"}, rootScope: []string{"comms:*", "identity:delegate"}}), allow(), func(s *scenario) {
		s.scope = "comms:calendar:write"
		s.out.GrantedScope = []string{"comms:calendar:read", "comms:calendar:write", "comms:email:read", "comms:email:send", "comms:message:read", "comms:message:send"}
	}))
	add(g.terminal("scope_required_identity_delegate", "identity:delegate granted explicitly on every link may be required", g.chain(chainSpec{leafScope: []string{"data:read", "identity:delegate"}}), allow(), func(s *scenario) {
		s.scope = "identity:delegate"
		s.out.GrantedScope = []string{"data:read", "identity:delegate"}
	}))
	add(g.terminal("scope_wildcard_and_sensitive_root_only", "the root grants data:write explicitly, the leaf only data:*: data:write is not effective", g.chain(chainSpec{leafScope: []string{"data:*"}, rootScope: []string{"data:*", "data:write", "identity:delegate"}}),
		deny("scope_denied", "scope_denied", "trusted", "current", "bound", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) { s.scope = "data:write" }))

	type rp struct{ name, prefix, path, want string }
	for _, c := range []rp{
		{"prefix_trailing_slash", "/v1/customers/", "/v1/customers/123", ""},
		{"prefix_trailing_slash_exact", "/v1/customers/", "/v1/customers", ""},
		{"root_prefix_any", "/", "/x/y", ""},
		{"root_prefix_root", "/", "/", ""},
		{"exact_equal", "/v1/customers", "/v1/customers", ""},
		{"string_prefix_only", "/v1/customers", "/v1/customersX", "constraint_denied"},
		{"request_trailing_slash", "/v1/customers", "/v1/customers/123/", ""},
		{"request_double_trailing_slash", "/v1/customers", "/v1/customers/123//", "constraint_denied"},
		{"request_dot_segment", "/v1/customers", "/v1/customers/./123", "constraint_denied"},
		{"request_percent_literal", "/v1/customers", "/v1/customers/%2e%2e", ""},
		{"request_backslash", "/v1/customers", "/v1/customers/a\\b", "constraint_denied"},
		{"request_nul", "/v1/customers", "/v1/customers/a\x00", "constraint_denied"},
		{"request_relative", "/v1/customers", "v1/customers/1", "constraint_denied"},
		{"prefix_case", "/V1/customers", "/v1/customers/1", "constraint_denied"},
		{"request_above_prefix", "/v1", "/", "constraint_denied"},
		{"unicode_not_normalized", "/v1/c\u00fcstomers", "/v1/cu\u0308stomers/1", "constraint_denied"},
		{"request_leading_double_slash", "/v1", "//v1/x", "constraint_denied"},
		{"request_dotdot_tail", "/v1/customers", "/v1/customers/123/..", "constraint_denied"},
	} {
		c := c
		certs := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintResourcePath, ResourceID: "customer/123", PathPrefix: c.prefix}}})
		o := allow()
		if c.want != "" {
			o = constraintOut(c.want, 0)
		}
		add(g.terminal("path_"+c.name, "resource_path "+c.prefix+" vs "+c.path, certs, o, func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasResource: true, RequestedResourceID: "customer/123", RequestedPath: c.path}
		}))
	}
	add(g.terminal("path_resource_id_case", "resource_id compares by bytes", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintResourcePath, ResourceID: "Customer/123"}}}),
		constraintOut("constraint_denied", 0), func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasResource: true, RequestedResourceID: "customer/123"}
		}))
	add(g.terminal("amount_zero_zero", "max 0, request 0 passes", g.chain(chainSpec{rootCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 0}}}),
		allow(), func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: 0, RequestedCurrency: "USD"}
		}))
	add(g.terminal("amount_max_safe", "max and request 2^53-1 pass", g.chain(chainSpec{rootCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 1<<53 - 1}}}),
		allow(), func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: 1<<53 - 1, RequestedCurrency: "USD"}
		}))
	add(g.terminal("amount_two_constraints_both_links", "max_amount on both links: the smaller bound decides", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 10}}, rootCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 5}}}),
		constraintOut("constraint_denied", 0), func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: 6, RequestedCurrency: "USD"}
		}))

	// ---------------- Configured verifier identity (SPEC-v2 §2.4, §6.1, §6.2).
	otherVerifier := attacker.ID
	_, otherVerifierBundle, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: session, verifierID: otherVerifier})
	add(std("pre_verifier_id_challenge_and_proof_name_other_verifier", "the proof and the ExpectedChallenge both name a verifier key ID other than the configured one: verifier_id_mismatch before claim", otherVerifierBundle, "verifier_id_mismatch", func(s *scenario) {
		s.expected.VerifierID = otherVerifier
	}))
	add(std("pre_verifier_id_proof_names_other_verifier", "the ExpectedChallenge names the configured verifier but the proof names another: verifier_id_mismatch", otherVerifierBundle, "verifier_id_mismatch", nil))
	add(std("pre_verifier_id_other_verifier_before_challenge_mismatch", "two faults: the proof names another verifier and the challenge bytes differ; the verifier ID check runs first in step 6", otherVerifierBundle, "verifier_id_mismatch", func(s *scenario) {
		other := defaultChallenge()
		other[0] ^= 1
		s.expected.ValueB64 = b64(other)
	}))
	add(std("pre_namespace_before_verifier_id", "two faults: the ExpectedChallenge namespace and the proof verifier ID both differ from the configuration; the namespace check runs first in step 6", otherVerifierBundle, "namespace_mismatch", func(s *scenario) {
		s.expected.VerifierNamespace = "verify-other"
	}))
	add(std("config_verifier_id_absent", "no configured verifier key ID: configuration_invalid at step 2", bundle, "configuration_invalid", func(s *scenario) { s.verifierID = strp("") }))
	add(std("config_verifier_id_uppercase", "a configured verifier key ID with uppercase hex is not a canonical v2 key ID: configuration_invalid", bundle, "configuration_invalid", func(s *scenario) {
		s.verifierID = strp(strings.ToUpper(g.k("verifier").ID))
	}))
	add(std("config_verifier_id_short", "a configured verifier key ID of 63 hex characters: configuration_invalid", bundle, "configuration_invalid", func(s *scenario) {
		s.verifierID = strp(g.k("verifier").ID[:63])
	}))
	add(std("config_verifier_id_absent_before_expected_challenge", "two faults: no configured verifier key ID and no ExpectedChallenge; configuration precedes the challenge record in step 2", bundle, "configuration_invalid", func(s *scenario) {
		s.verifierID = strp("")
		s.expected = nil
	}))
	add(std("config_namespace_empty", "an empty configured verifier namespace is configuration_invalid at step 2, even when the ExpectedChallenge namespace is also empty", bundle, "configuration_invalid", func(s *scenario) {
		s.emptyNamespace = true
		s.expected.VerifierNamespace = ""
	}))
	add(std("config_namespace_empty_before_expected_challenge", "two faults: an empty configured namespace and no ExpectedChallenge; configuration precedes the challenge record in step 2", bundle, "configuration_invalid", func(s *scenario) {
		s.emptyNamespace = true
		s.expected = nil
	}))

	// ---------------- Push and snapshot consistency, and heartbeats.
	{
		bl1 := mk(1, Now-120)
		bl2leaf := mk(2, Now-60, "cert-leaf")
		bp2other := mkPush(2, Now-60, "other-cert")
		add(g.terminal("status_push_conflicts_snapshot_leaf_revoked", "list2 revokes cert-leaf, push2 revokes other-cert: fork, but cert-leaf is in deny_union: revoked", def,
			deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(bl2leaf), rootEv}, allowCounts), func(s *scenario) {
				s.evidence[intermediateID] = evidenceBatch(g.object(bl1), g.object(bl2leaf), g.object(bp2other))
			}))
		bl2x := mk(2, Now-60, "x1")
		bp2y := mkPush(2, Now-60, "x2")
		add(g.terminal("status_push_conflicts_snapshot_unavailable", "list2 revokes x1, push2 revokes x2: fork, cert-leaf unavailable", def,
			indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(bl2x), g.evidence(bp2y), rootEv}, allowCounts), func(s *scenario) {
				s.evidence[intermediateID] = evidenceBatch(g.object(bl1), g.object(bl2x), g.object(bp2y))
			}))
		staleHB := mkAt(1, Now-4000, Now+3000)
		freshHB := mkAt(1, Now-60, Now+3000)
		add(g.terminal("status_heartbeat_refreshes", "a stale accepted list refreshed by a same-sequence identical-set heartbeat: allow from the heartbeat", def, allow(), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(staleHB, Now-3990)}
			s.evidence[intermediateID] = evidenceBatch(g.object(freshHB))
			s.out.StatusEvidence = []EvidenceJSON{g.evidence(freshHB), rootEv}
			s.out.AllowValidUntil = Now + 3000
		}))
		olderHB := mkAt(1, Now-120, Now+3000)
		add(g.terminal("status_older_heartbeat_ignored", "an older same-set heartbeat does not replace the accepted snapshot", def, allow(), func(s *scenario) {
			s.journal.Preload = []journalPreloadJSON{g.preload(freshHB, Now-30)}
			s.evidence[intermediateID] = evidenceBatch(g.object(olderHB))
			s.out.StatusEvidence = []EvidenceJSON{g.evidence(freshHB), rootEv}
			s.out.AllowValidUntil = Now + 3000
		}))
		add(g.terminal("status_both_heartbeats_one_batch", "two same-set heartbeats in one batch: the greater updated_at is the accepted base", def, allow(), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(olderHB), g.object(freshHB))
			s.out.StatusEvidence = []EvidenceJSON{g.evidence(freshHB), rootEv}
			s.out.AllowValidUntil = Now + 3000
		}))
	}

	// ---------------- A repeated issuer in one chain.
	{
		r0, _, _ := g.cert(certSpec{issuer: inter, subject: agent, certID: "cert-leaf", scope: []string{"data:read", "files:read"}})
		r1, _, _ := g.cert(certSpec{issuer: inter, subject: inter, certID: "cert-self", scope: []string{"data:read", "files:read", "identity:delegate"}})
		r2, _, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
		add(g.terminal("chain_repeated_issuer", "an issuer appearing twice is queried once with both references", []ratify.DelegationCertV2{r0, r1, r2}, allow(), nil))
	}

	// ---------------- Paired failures: the earlier check decides.
	revokedLeaf := evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
	add(std("pre_claim_store_absent_before_bad_signature", "two faults: no claim store (step 2) and an invalid certificate signature (step 5): configuration_invalid", func() []byte {
		bad := parse(bundle).(map[string]any)
		sig := obj(obj(arr(bad["delegations"])[0])["signature"])
		sig["ml_dsa_65"] = flipB64(sig["ml_dsa_65"])
		return g.resign(bad, agent)
	}(), "configuration_invalid", func(s *scenario) { s.claim = "absent" }))
	add(std("pre_bad_signature_before_hook", "two faults: an invalid certificate signature (step 5) and a rejecting receiver-binding hook (step 9): invalid_signature and the hook never runs", func() []byte {
		bad := parse(bundle).(map[string]any)
		sig := obj(obj(arr(bad["delegations"])[0])["signature"])
		sig["ml_dsa_65"] = flipB64(sig["ml_dsa_65"])
		return g.resign(bad, agent)
	}(), "invalid_signature", func(s *scenario) { s.hook = "reject" }))
	add(std("pre_namespace_before_hook", "two faults: a namespace mismatch (step 6) and a rejecting hook (step 9): namespace_mismatch and the hook never runs", bundle, "namespace_mismatch", func(s *scenario) {
		s.hook = "reject"
		s.expected.VerifierNamespace = "verify-other"
	}))
	add(std("pre_expected_agent_before_hook", "two faults: an expected agent mismatch (step 7) and a rejecting hook (step 9): expected_agent_mismatch and the hook never runs", bundle, "expected_agent_mismatch", func(s *scenario) {
		s.hook = "reject"
		s.expected.ExpectedAgentID = strp(attacker.ID)
		s.expected.ExpectedAgentPublicKey = pubJSON(attacker.Pub)
	}))
	add(g.terminal("post_invalid_scope_before_revoked_status", "an unregistered certificate scope is invalid_scope before status lookup, so revoking evidence is never fetched (§6.4)", g.chain(chainSpec{leafScope: []string{"data:read", "data:read:all"}}),
		deny("invalid_scope", "invalid_scope", "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.evidence[intermediateID] = revokedLeaf
		}))
	add(g.terminal("post_trust_before_delegation_expiry", "an ambiguous trust resolution (§6.4 check 2) precedes the leaf's expiry (check 4): trust_unavailable", g.chain(chainSpec{leafIssued: Now - 7200, leafExpires: Now}),
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.trust = &trustJSON{Mode: "ok", Outcome: "ambiguous"}
		}))
	add(g.terminal("post_status_unavailable_before_scope_and_rate", "unavailable status outranks a pending scope denial, and no max_rate capacity is reserved", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}}),
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{rootEv}, allowCounts), func(s *scenario) {
			s.rate = "reserve"
			s.scope = "meeting:attend"
			s.evidence[intermediateID] = providerFailure("error")
		}))
	return out
}

// statusKeyEpochScenarios run status-key epoch transitions (SPEC-v2 §5.4,
// §6.6) through the live verifier: the journal is configured at epoch 1,
// accepts a root list, then rotates the root issuer to epoch 2 before the
// request, and the caller configuration names the new key.
func (g *gen) statusKeyEpochScenarios() []scenario {
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	st := g.statusFixtures()
	rootID, interID := g.k("root").ID, g.k("intermediate").ID
	allowCounts := countsJSON{Claim: 1, Trust: 1, Status: 2}
	def := g.chain(chainSpec{})
	mkRoot := func(key string, seq, updated int64, revoked ...string) statusFixture {
		_, wire, _ := g.list(g.k(key), rootID, seq, updated, updated+3660, revoked...)
		return statusFixture{wire, codeList, rootID, key, seq, statusEvidenceDigest(codeList, wire)}
	}
	configure := func(issuer string, epoch uint64, key string) journalSetupJSON {
		return journalSetupJSON{Op: "configure_status_key", IssuerID: issuer, Epoch: epoch, PublicKey: pubJSON(g.k(key).Pub)}
	}
	apply := func(f statusFixture, epoch uint64, now int64) journalSetupJSON {
		return journalSetupJSON{Op: "apply", IssuerID: f.issuerID, Epoch: epoch, PublicKey: pubJSON(g.k(f.keyName).Pub), ObjectTypeCode: int(f.code), WireB64: b64(f.wire), Now: now}
	}
	rotated := func(old statusFixture) []journalSetupJSON {
		return []journalSetupJSON{configure(interID, 1, "status_intermediate"), configure(rootID, 1, "status_root"), apply(old, 1, Now-400), configure(rootID, 2, "status_root_epoch_2")}
	}
	epoch2 := statusKeyJSON{Epoch: 2, StatusKeyID: g.k("status_root_epoch_2").ID, PublicKey: pubJSON(g.k("status_root_epoch_2").Pub)}
	epoch1 := statusKeyJSON{Epoch: 1, StatusKeyID: g.k("status_root").ID, PublicKey: pubJSON(g.k("status_root").Pub)}
	interEv := g.evidence(st["intermediate_current"])
	var out []scenario
	add := func(name, desc string, o outcomeJSON, setup []journalSetupJSON, rootKey statusKeyJSON, rootBatch statusProviderJSON) {
		out = append(out, g.terminal(name, desc, def, o, func(s *scenario) {
			s.statusKeys = map[string]statusKeyJSON{interID: {Epoch: 1, StatusKeyID: g.k("status_intermediate").ID, PublicKey: pubJSON(g.k("status_intermediate").Pub)}, rootID: rootKey}
			s.evidence[rootID] = rootBatch
			s.journal.Setup = setup
		}))
	}
	allow := func(evidence ...EvidenceJSON) outcomeJSON {
		return outcomeJSON{Decision: "allow", DecisionReason: "authorized", IdentityStatus: "authorized_agent", TrustAssessment: "trusted", StatusAssessment: "current",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), GrantedScope: []string{"data:read", "files:read"}, StatusEvidence: evidence,
			AllowValidUntil: Now - 60 + 3660, CallbackCounts: allowCounts}
	}
	unavailable := func(counts countsJSON, evidence ...EvidenceJSON) outcomeJSON {
		return outcomeJSON{Decision: "indeterminate", DecisionReason: "status_unavailable", IdentityStatus: "authorization_unverified", TrustAssessment: "trusted", StatusAssessment: "unavailable",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), StatusEvidence: evidence, CallbackCounts: counts}
	}
	oldRevoked, oldEmpty, oldOther := mkRoot("status_root", 1, Now-500, "cert-root"), mkRoot("status_root", 1, Now-500), mkRoot("status_root", 1, Now-500, "x-old")
	newEmpty, newOther := mkRoot("status_root_epoch_2", 1, Now-60), mkRoot("status_root_epoch_2", 1, Now-60, "x-old")
	add("status_epoch_retired_key_revocation_retained", "a revocation accepted under the retired epoch-1 key stays in the deny union after rotation to epoch 2: revoked",
		outcomeJSON{Decision: "deny", DecisionReason: "delegation_revoked", IdentityStatus: "revoked", TrustAssessment: "trusted", StatusAssessment: "revoked",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), StatusEvidence: []EvidenceJSON{g.evidence(oldRevoked), interEv}, CallbackCounts: allowCounts},
		rotated(oldRevoked), epoch2, evidenceBatch(g.object(newEmpty)))
	add("status_epoch_new_list_bootstraps", "after rotation a fresh list signed by the epoch-2 key bootstraps the new epoch: allow",
		allow(g.evidence(newEmpty), interEv), rotated(oldEmpty), epoch2, evidenceBatch(g.object(newEmpty)))
	add("status_epoch_retired_key_list_rejected", "after rotation a list signed by the retired epoch-1 key is not authenticated for the root issuer: unavailable",
		unavailable(allowCounts, interEv), rotated(oldEmpty), epoch2, evidenceBatch(g.object(mkRoot("status_root", 2, Now-60))))
	add("status_epoch_stale_caller_configuration", "the caller configuration still names epoch 1 after the journal moved to epoch 2: the binding fails, the root's provider is not called, and its status is unavailable",
		unavailable(countsJSON{Claim: 1, Trust: 1, Status: 1}, interEv), rotated(oldEmpty), epoch1, evidenceBatch(g.object(oldEmpty)))
	add("status_epoch_new_list_carries_deny_union", "the first epoch-2 list contains the retained deny union: allow",
		allow(g.evidence(newOther), interEv), rotated(oldOther), epoch2, evidenceBatch(g.object(newOther)))
	add("status_epoch_new_list_omits_deny_union", "the first epoch-2 list omits a revocation retained from epoch 1: the new epoch is not bootstrapped and the root's status is unavailable",
		unavailable(allowCounts, g.evidence(newEmpty), interEv), rotated(oldOther), epoch2, evidenceBatch(g.object(newEmpty)))
	return out
}
