package v2vectors

import (
	"bytes"
	"sort"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// orderingCoverageScenarios adds two-fault ordering cases and boundary cases
// for audience, rate, extension evaluators, status batches, scope, time
// zones and the allow horizon. Each expectation is written from SPEC-v2.
func (g *gen) orderingCoverageScenarios() []scenario {
	agent, attacker := g.k("agent"), g.k("attacker")
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	np := policyDigest(notRequiredPolicy, false, nil)
	st := g.statusFixtures()
	rootID, intermediateID := g.k("root").ID, g.k("intermediate").ID
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
	early := func(reason, identity string) outcomeJSON {
		return deny(reason, identity, "trusted", "not_evaluated", "not_evaluated", nil, nil, noStatus)
	}
	constraintOut := func(reason string, audience int) outcomeJSON {
		return deny(reason, reason, "trusted", "current", "bound", strp(vp), g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Audience: audience})
	}
	providerError := providerFailure("error")

	var out []scenario
	add := func(s scenario) { out = append(out, s) }

	// ---------------- Pre-claim: two faults, first in §6.2 order wins.
	bundle, certs, session := g.base()
	std := func(name, desc string, b []byte, class string, edit func(*scenario)) scenario {
		s := scenario{name: name, desc: desc, bundle: b, certs: certs, scope: "data:read", expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session),
			trust: g.trustRoot("root"), evidence: g.currentEvidenceBatches(certs), out: preflight(class, 0)}
		if edit != nil {
			edit(&s)
		}
		return s
	}
	badCert := parse(bundle).(map[string]any)
	s0 := obj(obj(arr(badCert["delegations"])[0])["signature"])
	s0["ml_dsa_65"] = flipB64(s0["ml_dsa_65"])
	badCertWire := g.resign(badCert, agent)
	add(std("pre_scope_invalid_and_bad_cert_sig", "step 3 (scope) precedes step 5 (signatures)", badCertWire, "invalid_required_scope", func(s *scenario) { s.scope = "data:*" }))
	add(std("pre_expected_missing_and_scope_invalid", "step 2 (expected challenge) precedes step 3", bundle, "expected_challenge_unavailable", func(s *scenario) { s.expected = nil; s.scope = "data:*" }))
	add(std("pre_config_invalid_and_expected_missing", "configured bounds precede expected-challenge presence (step 2 order)", bundle, "configuration_invalid", func(s *scenario) { s.expected = nil; s.skew = 301 }))
	add(std("pre_reqctx_invalid_and_expected_missing", "request context validation precedes expected-challenge presence (step 2 order)", bundle, "configuration_invalid", func(s *scenario) {
		s.expected = nil
		s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: -1, RequestedCurrency: "USD"}
	}))
	add(std("pre_malformed_and_reqctx_invalid", "step 1 decode precedes step 2 configuration", bundle[:len(bundle)/2], "malformed", func(s *scenario) {
		s.reqCtx = &requestContextJSON{HasAmount: true, RequestedAmountMicros: -1, RequestedCurrency: "USD"}
	}))
	add(std("pre_malformed_and_now_invalid", "step 1 decode precedes the now bound", bundle[:len(bundle)/2], "malformed", func(s *scenario) { s.now = -1 }))
	otherSession := append([]byte(nil), session...)
	otherSession[0] ^= 1
	add(std("pre_policy_inconsistent_and_scope_invalid", "step 2 policy/challenge consistency precedes step 3", bundle, "configuration_invalid", func(s *scenario) {
		s.policy = g.verifyPolicyJSON(otherSession)
		s.scope = "data:*"
	}))
	add(std("pre_agent_keyid_and_digest", "agent key ID check precedes delegation_digest within step 4", mutate(bundle, func(o map[string]any) {
		o["agent_id"] = attacker.ID
		o["delegation_digest"] = flipB64(o["delegation_digest"])
	}), "key_id_mismatch", nil))
	add(std("pre_bad_sig_and_namespace", "step 5 precedes step 6", badCertWire, "invalid_signature", func(s *scenario) { s.expected.VerifierNamespace = "verify-other" }))
	add(std("pre_namespace_and_epoch", "namespace precedes replay epoch", bundle, "namespace_mismatch", func(s *scenario) { s.expected.VerifierNamespace = "verify-other"; s.expected.ReplayEpoch = 2 }))
	add(std("pre_epoch_and_verifier_id", "replay epoch precedes verifier ID", bundle, "stale_replay_epoch", func(s *scenario) { s.expected.ReplayEpoch = 2; s.expected.VerifierID = attacker.ID }))
	other := defaultChallenge()
	other[0] ^= 1
	add(std("pre_verifier_id_and_challenge", "verifier ID precedes challenge bytes", bundle, "verifier_id_mismatch", func(s *scenario) { s.expected.VerifierID = attacker.ID; s.expected.ValueB64 = b64(other) }))
	add(std("pre_challenge_and_bad_times", "challenge bytes precede the ExpectedChallenge time bounds", bundle, "challenge_mismatch", func(s *scenario) { s.expected.ValueB64 = b64(other); s.expected.ExpiresAt = s.expected.IssuedAt }))
	add(std("pre_bad_times_and_not_fresh", "ExpectedChallenge expires_at == issued_at is configuration_invalid before freshness", bundle, "configuration_invalid", func(s *scenario) { s.expected.ExpiresAt = s.expected.IssuedAt }))
	add(std("pre_not_fresh_and_agent_mismatch", "step 6 freshness precedes step 7 agent binding", bundle, "challenge_not_fresh", func(s *scenario) {
		s.maxAge = 5
		s.expected.ExpectedAgentID = strp(attacker.ID)
		s.expected.ExpectedAgentPublicKey = pubJSON(attacker.Pub)
	}))
	add(std("pre_agent_id_without_key", "expected agent ID without its public key is configuration_invalid (step 7)", bundle, "configuration_invalid", func(s *scenario) { s.expected.ExpectedAgentPublicKey = nil }))
	add(std("pre_agent_key_without_id", "expected agent public key without its ID is configuration_invalid (step 7)", bundle, "configuration_invalid", func(s *scenario) { s.expected.ExpectedAgentID = nil }))
	add(std("pre_agent_id_key_mismatch", "expected agent ID that is not the ID of the expected key (step 7)", bundle, "expected_agent_mismatch", func(s *scenario) { s.expected.ExpectedAgentID = strp(attacker.ID) }))
	add(std("pre_agent_mismatch_and_session_mismatch", "expected agent precedes session context", bundle, "expected_agent_mismatch", func(s *scenario) {
		s.expected.ExpectedAgentID = strp(attacker.ID)
		s.expected.ExpectedAgentPublicKey = pubJSON(attacker.Pub)
		s.expected.ExpectedSessionContextB64 = strp(b64(otherSession))
		s.policy = g.verifyPolicyJSON(otherSession)
	}))
	audience := []ratify.ConstraintV2{{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-1"}, "trust_domain_ids": []any{}}}}
	exactCerts := g.chain(chainSpec{leafCons: audience})
	_, exactWire, _ := g.bundle(bundleSpec{agent: agent, certs: exactCerts, session: session})
	add(std("pre_session_mismatch_and_audience_required", "step 7 session context precedes step 8 audience", exactWire, "session_context_mismatch", func(s *scenario) {
		s.expected.ExpectedSessionContextB64 = strp(b64(otherSession))
		s.policy = g.verifyPolicyJSON(otherSession)
	}))
	add(std("pre_audience_required_and_hook_reject", "step 8 precedes the hook; the hook never runs", exactWire, "receiver_audience_required", func(s *scenario) { s.hook = "reject" }))
	domainOnly := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}}
	exactRoot := []ratify.ConstraintV2{{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-7"}, "trust_domain_ids": []any{}}}}
	mixCerts := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainOnly}, rootCons: exactRoot})
	_, mixWire, _ := g.bundle(bundleSpec{agent: agent, certs: mixCerts, session: session})
	add(std("pre_exact_only_root_excludes_with_domain_leaf", "an exact-only audience on the root link excludes the receiver: pre-claim mismatch even though the leaf names a domain", mixWire, "receiver_audience_mismatch", func(s *scenario) {
		s.expected.ExpectedReceiverID = strp("receiver-1")
		s.hook = "accept"
	}))
	add(std("pre_replay_epoch_above_safe_integer", "a configured (and expected) replay epoch of 2^53 is outside the unsigned safe-integer bound: configuration_invalid at step 2 (SPEC-v2 §2.5, §6.1)", bundle, "configuration_invalid", func(s *scenario) {
		s.epoch = 1 << 53
		s.expected.ReplayEpoch = 1 << 53
	}))
	add(std("pre_expected_session_31_bytes_no_policy", "no context policy and a 31-byte expected session context: the challenge record is malformed configuration (SPEC-v2 §6.1), configuration_invalid at step 2", bundle, "configuration_invalid", func(s *scenario) {
		s.policy = nil
		s.expected.ExpectedSessionContextB64 = strp(b64(session[:31]))
	}))
	add(std("pre_expected_challenge_31_bytes", "a 31-byte expected challenge value never matches", bundle, "challenge_mismatch", func(s *scenario) { s.expected.ValueB64 = b64(defaultChallenge()[:31]) }))

	// ---------------- Post-claim ordering of verification failures.
	add(g.terminal("post_untrusted_and_expired", "trust resolution precedes delegation expiry", g.chain(chainSpec{leafIssued: Now - 3600, leafExpires: Now - 1}),
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) { s.trust = &trustJSON{Mode: "ok", Outcome: "untrusted"} }))
	add(g.terminal("post_expired_leaf_and_lifetime_root", "proof_invalid on any link precedes delegation_expired on an earlier link (table order)", g.chain(chainSpec{leafIssued: Now - 3600, leafExpires: Now - 1, rootIssued: Now - 3600, rootExpires: Now - 3600 + 315360001}),
		early("proof_invalid", "invalid"), nil))
	add(g.terminal("post_expired_and_parent_lacks_delegate", "expired leaf and a parent without identity:delegate", g.chain(chainSpec{leafIssued: Now - 3600, leafExpires: Now - 1, rootScope: []string{"data:read", "files:read"}}),
		early("delegation_expired", "expired"), nil))
	add(g.terminal("post_invalid_scope_and_parent_lacks_delegate", "invalid certificate scope and a parent without identity:delegate", g.chain(chainSpec{leafScope: []string{"data:read", "custom:*"}, rootScope: []string{"data:read", "files:read"}}),
		early("invalid_scope", "invalid_scope"), nil))
	add(g.terminal("post_invalid_scope_and_expired_root", "invalid scope on the leaf and an expired root", g.chain(chainSpec{leafScope: []string{"data:read", "custom:*"}, rootIssued: Now - 3600, rootExpires: Now - 1}),
		early("delegation_expired", "expired"), nil))
	add(g.terminal("post_future_issued_leaf_and_expired_root", "issued_at beyond now+skew on the leaf and an expired root", g.chain(chainSpec{leafIssued: Now + 100, leafExpires: Now + 200, rootIssued: Now - 3600, rootExpires: Now - 1}),
		early("proof_invalid", "invalid"), nil))
	add(g.terminal("post_delegation_expiry_uses_claim_time", "a delegation valid at request now but expired at T_claim is delegation_expired", g.chain(chainSpec{leafIssued: Now - 3600, leafExpires: Now + 50}),
		early("delegation_expired", "expired"), func(s *scenario) { s.claimOffset = 100 }))
	add(g.terminal("post_trust_untrusted_with_key", "untrusted with a root key is still untrusted", g.chain(chainSpec{}),
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.trust = &trustJSON{Mode: "ok", Outcome: "untrusted", RootPublicKey: pubJSON(g.k("root").Pub)}
		}))
	add(g.terminal("post_trust_trusted_intermediate_key", "trusted with a non-terminal chain key is treated as ambiguous", g.chain(chainSpec{}),
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.trust = &trustJSON{Mode: "ok", Outcome: "trusted", RootPublicKey: pubJSON(g.k("intermediate").Pub)}
		}))
	add(g.terminal("post_empty_chain_bound_policy", "empty chain under a bound Verify policy: not_delegated, context not evaluated", nil,
		deny("not_delegated", "delegation_not_authorized", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil, countsJSON{Claim: 1}), func(s *scenario) {
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, session: session})
		}))

	// ---------------- Local-policy precedence after complete status.
	def := g.chain(chainSpec{})
	resourcePath := ratify.ConstraintV2{Type: ratify.ConstraintResourcePath, ResourceID: "customer/123"}
	unknown := ratify.ConstraintV2{Type: "ratify.conformance_unknown", Params: map[string]any{"x": 1}}
	domainA := domainOnly
	domainB := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{"domain-b"}, "max_membership_age_seconds": 3600}}
	rate := ratify.ConstraintV2{Type: ratify.ConstraintMaxRate, Count: 5, WindowS: 60}
	membership := func(link int, domains ...string) membershipJSON {
		return membershipJSON{DelegationIndex: link, ReceiverID: "receiver-1", TrustDomainIDs: domains, IssuedAt: Now - 60, ExpiresAt: Now + 600, EvidenceDigest: "sha384:" + hexRepeat(byte('a'+link), 96)}
	}
	withReceiver := func(s *scenario) { s.expected.ExpectedReceiverID = strp("receiver-1") }
	resourceCtx := &requestContextJSON{HasResource: true, RequestedResourceID: "customer/999"}
	postMismatch := func(s *scenario) {
		s.expected.ExpectedSessionContextB64 = nil
		s.policy.ExpectedSessionContextB64 = strp(b64(bytes.Repeat([]byte{0x33}, 32)))
	}
	noPolicy := func(s *scenario) { s.expected.ExpectedSessionContextB64 = nil; s.policy = nil }

	add(g.terminal("local_scope_denied_and_context_mismatch", "scope_denied outranks a post-claim context mismatch; context retains mismatch", def,
		deny("scope_denied", "scope_denied", "trusted", "current", "mismatch", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) { postMismatch(s); s.scope = "meeting:attend" }))
	add(g.terminal("local_context_mismatch_and_constraint_unknown", "context mismatch (constraint_denied) outranks an unknown constraint", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknown}}),
		deny("constraint_denied", "constraint_denied", "trusted", "current", "mismatch", strp(vp), g.currentEvidence(), allowCounts), postMismatch))
	add(g.terminal("local_bound_policy_session_absent_after_claim", "bound policy, no expected session in the challenge, null proof session: action_context_unverified after claim", def,
		indeterminate("action_context_unverified", "trusted", "current", "unverified", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) {
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, certs: def})
			s.expected.ExpectedSessionContextB64 = nil
		}))
	add(g.terminal("local_context_unverified_and_constraint_denied", "action_context_unverified outranks constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}}),
		indeterminate("action_context_unverified", "trusted", "current", "unverified", strp(vp), g.currentEvidence(), allowCounts), func(s *scenario) {
			certs := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}})
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, certs: certs})
			s.expected.ExpectedSessionContextB64 = nil
			s.reqCtx = resourceCtx
		}))
	add(g.terminal("local_no_policy_and_constraint_denied", "no policy: action_context_unverified outranks constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}}),
		indeterminate("action_context_unverified", "trusted", "current", "unverified", nil, g.currentEvidence(), allowCounts), func(s *scenario) { noPolicy(s); s.reqCtx = resourceCtx }))
	add(g.terminal("local_no_policy_and_audience_domain", "no policy with a domain audience: action_context_unverified", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		indeterminate("action_context_unverified", "trusted", "current", "unverified", nil, g.currentEvidence(), allowCounts), func(s *scenario) {
			noPolicy(s)
			withReceiver(s)
			s.memberships = []membershipJSON{membership(0, "domain-a")}
		}))
	add(g.terminal("local_scope_denied_and_audience_domain", "scope_denied with a domain audience", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("scope_denied", 0), func(s *scenario) {
			withReceiver(s)
			s.scope = "meeting:attend"
			s.memberships = []membershipJSON{membership(0, "domain-a")}
		}))
	add(g.terminal("local_constraint_denied_and_audience_missing", "a local proven violation with missing audience membership is constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{resourcePath}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_denied", 0), func(s *scenario) { withReceiver(s); s.reqCtx = resourceCtx }))
	add(g.terminal("local_not_required_policy_with_proof_session", "not_required policy with a non-null proof session context allows as not_required", def, allow(), func(s *scenario) {
		s.expected.ExpectedSessionContextB64 = nil
		s.policy = g.notRequiredPolicyJSON()
		s.out.ContextAssessment, s.out.ContextPolicyDigest = "not_required", strp(np)
	}))

	// ---------------- Audience details.
	add(g.terminal("aud_rate_and_audience_denied", "audience non-match: constraint_denied and no rate reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_denied", 1), func(s *scenario) {
			withReceiver(s)
			s.rate = "reserve"
			s.memberships = []membershipJSON{membership(1, "domain-x")}
		}))
	add(g.terminal("aud_rate_and_audience_missing", "audience missing: constraint_unverifiable and no rate reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}, rootCons: []ratify.ConstraintV2{domainB}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) { withReceiver(s); s.rate = "reserve" }))
	add(g.terminal("aud_rate_and_audience_pass", "audience passes then rate reserves; membership expiry bounds the horizon", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}, rootCons: []ratify.ConstraintV2{domainB}}),
		allow(), func(s *scenario) {
			withReceiver(s)
			s.rate = "reserve"
			s.memberships = []membershipJSON{membership(1, "domain-b")}
			s.out.CallbackCounts.Audience, s.out.CallbackCounts.Rate = 1, 1
			s.out.AllowValidUntil = Now + 600
			s.out.RateBatch = []rateJSON{{IssuerID: intermediateID, CertID: "cert-leaf", WindowS: 60, Limit: 5}}
		}))
	agedDomain := func(domain string, age int64) ratify.ConstraintV2 {
		return ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{domain}, "max_membership_age_seconds": age}}
	}
	at := func(m membershipJSON, issued int64) membershipJSON { m.IssuedAt = issued; return m }
	add(g.terminal("aud_smallest_age_from_root_applies_to_leaf", "the smallest max_membership_age (root, 50) applies to every domain link: memberships 60s old are stale", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{agedDomain("domain-a", 3600)}, rootCons: []ratify.ConstraintV2{agedDomain("domain-b", 50)}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{membership(0, "domain-a"), membership(1, "domain-b")}
		}))
	add(g.terminal("aud_smallest_age_from_leaf_applies_to_root", "leaf age 50 is the smallest; the root membership is 60s old (fresh under its own 3600) and so stale: constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{agedDomain("domain-a", 50)}, rootCons: []ratify.ConstraintV2{agedDomain("domain-b", 3600)}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{at(membership(0, "domain-a"), Now-40), membership(1, "domain-b")}
		}))
	add(g.terminal("aud_smallest_age_pass_sets_horizon", "both memberships 40s old under the smallest age 50: allow with horizon issued_at + 50", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{agedDomain("domain-a", 3600)}, rootCons: []ratify.ConstraintV2{agedDomain("domain-b", 50)}}),
		allow(), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{at(membership(0, "domain-a"), Now-40), at(membership(1, "domain-b"), Now-40)}
			s.out.CallbackCounts.Audience = 1
			s.out.AllowValidUntil = Now + 10
		}))
	add(g.terminal("aud_membership_expires_at_now", "membership expiry equal to T_claim is not current", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.ExpiresAt = Now
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_membership_age_exact_deadline", "membership issued exactly max_membership_age before T_claim is not current", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{at(membership(0, "domain-a"), Now-3600)}
		}))
	add(g.terminal("aud_membership_wrong_receiver", "membership for another receiver is not evidence for this one", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.ReceiverID = "receiver-2"
			s.memberships = []membershipJSON{m}
		}))
	add(g.terminal("aud_duplicate_membership_same_link", "two membership results for one link are not a unique answer", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m2 := membership(0, "domain-a")
			m2.EvidenceDigest = "sha384:" + hexRepeat('c', 96)
			s.memberships = []membershipJSON{membership(0, "domain-a"), m2}
		}))
	exactOrDomain := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-9"}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}}
	add(g.terminal("aud_exact_match_with_domain_no_membership", "an exact receiver match on a link that also names a domain needs no membership", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{exactOrDomain}}),
		allow(), func(s *scenario) {
			s.expected.ExpectedReceiverID = strp("receiver-9")
			s.out.CallbackCounts.Audience = 1
		}))
	add(g.terminal("aud_membership_future_beyond_skew", "a membership issued after T_claim + skew is not current", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{at(membership(0, "domain-a"), Now+6)}
		}))

	// ---------------- Rate.
	add(g.terminal("rate_multi_batch", "two windows on the leaf (same-window limits take the smallest count) and one on the root; batch sorted by issuer, cert, window", g.chain(chainSpec{
		leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxRate, Count: 5, WindowS: 60}, {Type: ratify.ConstraintMaxRate, Count: 10, WindowS: 3600}, {Type: ratify.ConstraintMaxRate, Count: 3, WindowS: 60}},
		rootCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxRate, Count: 2, WindowS: 60}}}),
		allow(), func(s *scenario) {
			s.rate = "reserve"
			s.out.CallbackCounts.Rate = 1
			b := []rateJSON{{IssuerID: intermediateID, CertID: "cert-leaf", WindowS: 60, Limit: 3}, {IssuerID: intermediateID, CertID: "cert-leaf", WindowS: 3600, Limit: 10}, {IssuerID: rootID, CertID: "cert-root", WindowS: 60, Limit: 2}}
			sort.SliceStable(b, func(i, j int) bool {
				if b[i].IssuerID != b[j].IssuerID {
					return b[i].IssuerID < b[j].IssuerID
				}
				if b[i].CertID != b[j].CertID {
					return b[i].CertID < b[j].CertID
				}
				return b[i].WindowS < b[j].WindowS
			})
			s.out.RateBatch = b
		}))
	staleRoot := func(s *scenario) {
		s.journal.Preload = []journalPreloadJSON{g.preload(st["root_stale"], Now-3990)}
		s.evidence[rootID] = evidenceBatch()
	}
	add(g.terminal("rate_and_status_stale", "no reservation after stale status", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}}),
		indeterminate("status_stale", "trusted", "stale", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(st["root_stale"])}, allowCounts), func(s *scenario) { s.rate = "reserve"; staleRoot(s) }))
	add(g.terminal("rate_and_unknown_constraint", "no reservation after constraint_unknown", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}, rootCons: []ratify.ConstraintV2{unknown}}),
		constraintOut("constraint_unknown", 0), func(s *scenario) { s.rate = "reserve" }))
	add(g.terminal("rate_and_unverifiable_constraint", "no reservation after constraint_unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate, resourcePath}}),
		constraintOut("constraint_unverifiable", 0), func(s *scenario) { s.rate = "reserve" }))
	nyWindow := ratify.ConstraintV2{Type: ratify.ConstraintTimeWindow, Start: "02:00", End: "03:30", TZ: "America/New_York"}
	add(g.terminal("rate_and_time_window", "time window horizon with a rate reservation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{nyWindow, rate}}),
		allow(), func(s *scenario) {
			s.rate = "reserve"
			s.out.CallbackCounts.Rate = 1
			s.out.AllowValidUntil = Now + 1860
			s.out.RateBatch = []rateJSON{{IssuerID: intermediateID, CertID: "cert-leaf", WindowS: 60, Limit: 5}}
		}))
	add(g.terminal("rate_and_revoked", "no reservation after revocation", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{rate}}),
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"]), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.rate = "reserve"
			s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
		}))

	// ---------------- Extension evaluators and early failures.
	maxNodes := ratify.ConstraintV2{Type: maxCountType, Params: map[string]any{"counter": "nodes", "max": 10}}
	stdCount := evaluatorJSON{Type: maxCountType, Profile: maxCountProfile, Implementation: maxCountProfile}
	ctx3 := &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 3}}
	add(g.terminal("ext_and_expired", "an expired delegation terminates before any extension evaluator runs", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}, leafIssued: Now - 3600, leafExpires: Now - 1}),
		early("delegation_expired", "expired"), func(s *scenario) { s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3 }))
	add(g.terminal("ext_and_untrusted", "an untrusted root terminates before any extension evaluator runs", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}}),
		deny("unauthorized", "unauthorized", "untrusted", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3
			s.trust = &trustJSON{Mode: "ok", Outcome: "untrusted"}
		}))
	add(g.terminal("ext_and_scope_denied", "scope_denied with a passing extension constraint", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}}),
		deny("scope_denied", "scope_denied", "trusted", "current", "bound", strp(vp), g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: 1}), func(s *scenario) {
			s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3
			s.scope = "meeting:attend"
		}))
	add(g.terminal("ext_and_status_unavailable", "status unavailable with an extension constraint", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}}),
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: 1}), func(s *scenario) {
			s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3
			s.evidence[intermediateID] = providerError
		}))
	faultC := ratify.ConstraintV2{Type: faultType, Params: map[string]any{"case": "fault"}}
	passUntil := func(t int64) []evaluatorJSON {
		return []evaluatorJSON{{Type: faultType, Profile: faultProfile, Implementation: "fault:pass_until", ValidUntil: t}}
	}
	add(g.terminal("ext_pass_horizon_beyond_domain_is_clamped", "a pass horizon past the timestamp domain is clamped, not rejected", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{faultC}}),
		func() outcomeJSON { o := allow(); o.CallbackCounts.Evaluator = 1; return o }(), func(s *scenario) { s.evaluators = passUntil(ratify.V2MaxTimestampSeconds + 1) }))
	add(g.terminal("ext_pass_horizon_one_after_claim", "a pass horizon of T_claim+1 is valid and bounds the allow", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{faultC}}),
		func() outcomeJSON {
			o := allow()
			o.CallbackCounts.Evaluator = 1
			o.AllowValidUntil = Now + 1
			return o
		}(), func(s *scenario) { s.evaluators = passUntil(Now + 1) }))
	add(g.terminal("ext_horizon_and_time_window", "the earliest of an evaluator horizon and a time_window horizon bounds the allow", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{faultC}, rootCons: []ratify.ConstraintV2{nyWindow}}),
		func() outcomeJSON {
			o := allow()
			o.CallbackCounts.Evaluator = 1
			o.AllowValidUntil = Now + 1000
			return o
		}(), func(s *scenario) { s.evaluators = passUntil(Now + 1000) }))

	// ---------------- Status.
	add(g.terminal("status_preloaded_empty_batch", "an empty provider batch over a journal already holding current lists allows from committed state", def, allow(), func(s *scenario) {
		s.journal.Preload = []journalPreloadJSON{g.preload(st["root_current"], Now-30), g.preload(st["intermediate_current"], Now-30)}
		s.evidence = map[string]statusProviderJSON{rootID: evidenceBatch(), intermediateID: evidenceBatch()}
	}))
	add(g.terminal("status_key_is_agent_key", "a status key equal to the bundle agent key is a chain-wide role violation: every issuer unavailable, no provider call", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), nil, countsJSON{Claim: 1, Trust: 1}), func(s *scenario) {
			s.statusKeys = g.statusKeyConfig()
			s.statusKeys[rootID] = statusKeyJSON{Epoch: 1, StatusKeyID: agent.ID, PublicKey: pubJSON(agent.Pub)}
		}))
	add(g.terminal("status_revoked_and_stale", "revoked outranks stale", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_revoked_leaf"]), g.evidence(st["root_stale"])}, allowCounts), func(s *scenario) {
			staleRoot(s)
			s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
		}))
	add(g.terminal("status_stale_and_scope_denied", "stale outranks scope_denied", def,
		indeterminate("status_stale", "trusted", "stale", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(st["root_stale"])}, allowCounts), func(s *scenario) {
			staleRoot(s)
			s.scope = "meeting:attend"
		}))
	add(g.terminal("status_unavailable_and_context_mismatch", "unavailable status outranks a post-claim context mismatch", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "mismatch", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			postMismatch(s)
			s.evidence[intermediateID] = providerError
		}))

	// ---------------- One future skew (SPEC-v2 §2.5, §6.1): status freshness
	// uses future_skew_seconds, and a status policy skew that differs from it
	// is configuration_invalid before claim.
	futureList := func(keyName, issuerID string) statusFixture {
		_, wire, _ := g.list(g.k(keyName), issuerID, 1, Now+100, Now+3700)
		return statusFixture{wire, codeList, issuerID, keyName, 1, statusEvidenceDigest(codeList, wire)}
	}
	fr, fi := futureList("status_root", rootID), futureList("status_intermediate", intermediateID)
	futureEvidence := func(s *scenario) {
		s.evidence = map[string]statusProviderJSON{rootID: evidenceBatch(g.object(fr)), intermediateID: evidenceBatch(g.object(fi))}
	}
	skews := func(future, status int64) func(*scenario) {
		return func(s *scenario) {
			s.skew = future
			if future == 0 {
				s.skew = -1 // finish(): negative means 0
			}
			p := orderingStatusPolicy
			p.ClockSkewSeconds = status
			s.policy2 = &p
			futureEvidence(s)
		}
	}
	add(std("status_skew_verifier0_status300", "future_skew_seconds 0 with a status policy skew of 300: two different skews are configuration_invalid before claim", bundle, "configuration_invalid", skews(0, 300)))
	add(std("status_skew_verifier300_status0", "future_skew_seconds 300 with a status policy skew of 0: two different skews are configuration_invalid before claim", bundle, "configuration_invalid", skews(300, 0)))
	add(g.terminal("status_skew_shared_0_future_dated", "future skew 0 (status policy the same): lists updated 100s after now are future-dated, so status is unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(fr), g.evidence(fi)}, allowCounts), skews(0, 0)))
	add(g.terminal("status_skew_shared_300_fresh", "future skew 300 (status policy the same): lists updated 100s after now are within the skew and fresh, so allow until next_update", def,
		func() outcomeJSON {
			o := allow()
			o.StatusEvidence = []EvidenceJSON{g.evidence(fr), g.evidence(fi)}
			o.AllowValidUntil = Now + 3700
			return o
		}(), skews(300, 300)))

	// ---------------- Inclusive skew lower bounds.
	skewBundle := func(at int64) []byte {
		_, w, _ := g.bundle(bundleSpec{agent: agent, certs: def, session: session, challengeAt: at})
		return w
	}
	add(g.terminal("skew_challenge_issued_at_now_plus_skew", "issued_at == now + skew is fresh (inclusive)", def, allow(), func(s *scenario) {
		s.bundle = skewBundle(Now + 5)
		s.expected.IssuedAt, s.expected.ExpiresAt = Now+5, Now+300
	}))
	add(std("skew_challenge_issued_at_now_plus_skew_plus_one", "issued_at == now + skew + 1 is not fresh", skewBundle(Now+6), "challenge_not_fresh", func(s *scenario) {
		s.expected.IssuedAt, s.expected.ExpiresAt = Now+6, Now+300
	}))
	add(g.terminal("skew_delegation_issued_at_now_plus_skew", "delegation issued_at == T_claim + skew is current", g.chain(chainSpec{leafIssued: Now + 5, leafExpires: Now + 86400}), allow(), nil))
	add(g.terminal("skew_delegation_issued_at_now_plus_skew_plus_one", "delegation issued_at == T_claim + skew + 1 is proof_invalid", g.chain(chainSpec{leafIssued: Now + 6, leafExpires: Now + 86400}), early("proof_invalid", "invalid"), nil))
	add(g.terminal("skew_membership_issued_at_now_plus_skew", "membership issued_at == T_claim + skew is current", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		allow(), func(s *scenario) {
			withReceiver(s)
			s.memberships = []membershipJSON{at(membership(0, "domain-a"), Now+5)}
			s.out.CallbackCounts.Audience = 1
			s.out.AllowValidUntil = Now + 600
		}))

	// ---------------- Scope intersection and wildcards (Annex A §A.4).
	scopeCase := func(name, desc, required string, leaf, root []string, out outcomeJSON) {
		add(g.terminal(name, desc, g.chain(chainSpec{leafScope: leaf, rootScope: root}), out, func(s *scenario) { s.scope = required }))
	}
	scopeAllow := func(granted ...string) outcomeJSON { o := allow(); o.GrantedScope = granted; return o }
	scopeCase("scope_root_wildcard_never_grants_sensitive", "comms:* on the root does not grant the sensitive comms:email:delete held by the leaf", "comms:email:delete",
		[]string{"comms:email:delete"}, []string{"comms:*", "identity:delegate"}, constraintOut("scope_denied", 0))
	scopeCase("scope_both_wildcards_intersect", "comms:email:* on the leaf and comms:* on the root intersect to the two email scopes", "comms:email:send",
		[]string{"comms:email:*"}, []string{"comms:*", "identity:delegate"}, scopeAllow("comms:email:read", "comms:email:send"))
	scopeCase("scope_identity_prove_is_literal", "identity:prove is not implied: a root that omits it does not pass it through", "identity:prove",
		[]string{"identity:prove", "data:read"}, []string{"data:read", "identity:delegate"}, constraintOut("scope_denied", 0))
	scopeCase("scope_wildcard_and_member_in_one_cert", "data:* and data:read in one certificate are distinct valid strings", "data:read",
		[]string{"data:*", "data:read"}, []string{"data:*", "identity:delegate"}, scopeAllow("data:read", "data:share"))
	scopeCase("scope_sensitive_explicit_both_links", "identity:delegate held explicitly by both links can be required", "identity:delegate",
		[]string{"identity:delegate"}, []string{"identity:delegate"}, scopeAllow("identity:delegate"))
	scopeCase("scope_custom_and_canonical_mix", "custom scope passes through only where both links list it; canonical scopes intersect normally", "custom:ops.restart",
		[]string{"custom:ops.restart", "data:*"}, []string{"custom:ops.restart", "data:read", "identity:delegate"}, scopeAllow("custom:ops.restart", "data:read"))

	// ---------------- Zone names must match the pinned database exactly.
	for _, c := range []struct{ name, tz string }{{"lower", "america/new_york"}, {"upper", "AMERICA/NEW_YORK"}, {"mixed", "America/New_york"}} {
		tz := c.tz
		add(g.terminal("tz_case_variant_"+c.name, "a tz spelled with different case is not a zone in the pinned database: constraint_unverifiable (SPEC-v2 §5.2), even inside the window",
			g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "02:00", End: "03:30", TZ: tz}}}),
			constraintOut("constraint_unverifiable", 0), nil))
	}
	add(g.terminal("tz_backward_link_us_eastern", "US/Eastern is a backward link present in the pinned database and evaluates like America/New_York",
		g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "02:00", End: "03:30", TZ: "US/Eastern"}}}),
		func() outcomeJSON { o := allow(); o.AllowValidUntil = Now + 1860; return o }(), nil))

	// ---------------- Allow horizon contributions and T_claim use.
	agedList := func() statusFixture {
		_, wire, _ := g.list(g.k("status_root"), rootID, 1, Now-3000, Now+3000)
		return statusFixture{wire, codeList, rootID, "status_root", 1, statusEvidenceDigest(codeList, wire)}
	}()
	add(g.terminal("horizon_status_age_bound", "status freshness ends at updated_at + max_status_age when that is before next_update", def,
		func() outcomeJSON {
			o := allow()
			o.StatusEvidence = []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(agedList)}
			o.AllowValidUntil = Now + 660
			return o
		}(), func(s *scenario) {
			s.evidence[rootID] = evidenceBatch(g.object(agedList))
		}))
	add(g.terminal("horizon_delegation_expiry", "the earliest delegation expiry bounds the allow", g.chain(chainSpec{rootIssued: Now - 3600, rootExpires: Now + 100}),
		func() outcomeJSON { o := allow(); o.AllowValidUntil = Now + 100; return o }(), nil))
	add(g.terminal("tclaim_evaluator_horizon_equals_claim_time", "an evaluator horizon after request now but equal to T_claim is invalid output", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{faultC}}),
		deny("constraint_unverifiable", "constraint_unverifiable", "trusted", "current", "bound", strp(vp), g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: 1}), func(s *scenario) {
			s.claimOffset = 50
			s.evaluators = passUntil(Now + 50)
		}))
	add(g.terminal("tclaim_membership_expired_at_claim_time", "a membership current at request now but expired at T_claim is unverifiable", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{domainA}}),
		constraintOut("constraint_unverifiable", 1), func(s *scenario) {
			withReceiver(s)
			m := membership(0, "domain-a")
			m.ExpiresAt = Now + 30
			s.memberships = []membershipJSON{m}
			s.claimOffset = 50
		}))
	shortList := func() statusFixture {
		_, wire, _ := g.list(g.k("status_root"), rootID, 1, Now-60, Now+30)
		return statusFixture{wire, codeList, rootID, "status_root", 1, statusEvidenceDigest(codeList, wire)}
	}()
	add(g.terminal("tclaim_status_expired_at_claim_time", "a status list fresh at request now but past next_update at T_claim is not current", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["intermediate_current"]), g.evidence(shortList)}, allowCounts), func(s *scenario) {
			s.evidence[rootID] = evidenceBatch(g.object(shortList))
			s.claimOffset = 50
		}))
	add(std("pre_config_replay_epoch_out_of_range_and_bad_sig", "a configured replay epoch above 2^53-1 is a configured bound (step 2, configuration_invalid) and precedes signatures (step 5)", badCertWire, "configuration_invalid", func(s *scenario) {
		s.epoch = 1 << 53
		s.expected.ReplayEpoch = 1 << 53
	}))

	// ---------------- Preflight before any claim disclosure.
	add(std("pre_bad_sig_with_terminal_replay", "a stored terminal claim is never consulted when preflight fails", badCertWire, "invalid_signature", func(s *scenario) { s.claim = "terminal_replay" }))
	add(std("pre_hook_reject_with_in_progress", "the hook rejects before an in-progress claim is consulted", bundle, "receiver_binding_rejected", func(s *scenario) {
		s.claim = "in_progress"
		s.hook = "reject"
		s.out.CallbackCounts.ReceiverBinding = 1
	}))
	add(std("pre_not_fresh_with_proof_conflict", "a stale challenge fails before a conflicting claim is consulted", bundle, "challenge_not_fresh", func(s *scenario) { s.claim = "proof_conflict"; s.maxAge = 5 }))
	// ---------------- Evaluators never run on early post-claim failures.
	add(g.terminal("ext_and_trust_unavailable", "trust unavailable: no extension evaluator runs", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}}),
		indeterminate("trust_unavailable", "unavailable", "not_evaluated", "not_evaluated", nil, nil, noStatus), func(s *scenario) {
			s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3
			s.trust = nil
		}))
	add(g.terminal("ext_and_invalid_scope", "invalid certificate scope: no extension evaluator runs", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}, leafScope: []string{"data:read", "custom:"}}),
		early("invalid_scope", "invalid_scope"), func(s *scenario) { s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3 }))
	add(g.terminal("ext_and_parent_lacks_delegate", "parent lacks identity:delegate: no extension evaluator runs", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes}, rootScope: []string{"data:read", "files:read"}}),
		early("delegation_not_authorized", "delegation_not_authorized"), func(s *scenario) { s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctx3 }))
	add(g.terminal("scope_empty_list", "an empty certificate scope list is invalid_scope after claim", g.chain(chainSpec{leafScope: []string{}}),
		early("invalid_scope", "invalid_scope"), nil))

	// ---------------- Status batch order independence at the verifier boundary.
	mk := func(seq, updated int64, revoked ...string) statusFixture {
		_, wire, _ := g.list(g.k("status_intermediate"), intermediateID, seq, updated, updated+3660, revoked...)
		return statusFixture{wire, codeList, intermediateID, "status_intermediate", seq, statusEvidenceDigest(codeList, wire)}
	}
	mkPush := func(seq, at int64, revoked ...string) statusFixture {
		_, wire, _ := g.push(g.k("status_intermediate"), intermediateID, seq, at, revoked...)
		return statusFixture{wire, codePush, intermediateID, "status_intermediate", seq, statusEvidenceDigest(codePush, wire)}
	}
	l1, l2, p2 := mk(1, Now-120), mk(2, Now-60, "cert-leaf"), mkPush(2, Now-60, "cert-leaf")
	revokedEvidence := []EvidenceJSON{g.evidence(l2), g.evidence(st["root_current"])} // push2 at the accepted sequence is represented by list2 (earliest-sequence witness)
	add(g.terminal("batch_revocation_forward_order", "list1, list2, push2 in sequence order: revoked", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), revokedEvidence, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(l1), g.object(l2), g.object(p2))
		}))
	add(g.terminal("batch_revocation_reverse_order", "the same batch reversed (push2, list2, list1) gives the same result", def,
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), revokedEvidence, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(p2), g.object(l2), g.object(l1))
		}))
	fa, fb := mk(1, Now-60), mk(1, Now-60, "other-cert")
	add(g.terminal("batch_same_sequence_fork_forward", "two different lists at one sequence in one batch are a fork: unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(fa), g.evidence(fb), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(fa), g.object(fb))
		}))
	add(g.terminal("batch_same_sequence_fork_reverse", "the fork batch reversed gives the same result", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(fa), g.evidence(fb), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(fb), g.object(fa))
		}))
	add(g.terminal("batch_duplicate_object", "the same list twice in one batch is idempotent", def, allow(), func(s *scenario) {
		s.evidence[intermediateID] = evidenceBatch(g.object(st["intermediate_current"]), g.object(st["intermediate_current"]))
	}))

	// ---------------- Opaque batch objects (SPEC-v2 §6.5 steps 3 and 4): an
	// object the batch decoder accepts but that does not decode under its
	// code fails authentication, which rejects the whole batch, so that
	// issuer is unavailable and no transition occurs.
	opaque := func(name, desc string, objects ...evidenceObjectJSON) {
		add(g.terminal(name, desc, def,
			indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
				s.evidence[intermediateID] = evidenceBatch(objects...)
			}))
	}
	raw := func(code int, object string) evidenceObjectJSON {
		return evidenceObjectJSON{ObjectTypeCode: code, WireB64: b64([]byte(object))}
	}
	opaque("batch_object_empty", "a batch entry whose object is {} fails authentication: the issuer is unavailable", raw(3, `{}`))
	opaque("batch_object_nested_null", "a batch entry whose object is {\"a\":null} fails authentication: the issuer is unavailable", raw(3, `{"a":null}`))
	opaque("batch_valid_list_and_empty_object", "one unauthenticated entry rejects the whole batch, including a valid current list", g.object(st["intermediate_current"]), raw(3, `{}`))
	opaque("batch_list_labelled_push", "a valid signed list labelled code 5 does not decode as a push: the issuer is unavailable", evidenceObjectJSON{ObjectTypeCode: 5, WireB64: g.object(st["intermediate_current"]).WireB64})

	// ---------------- Gap and status-policy lifetime bound.
	p3 := mkPush(3, Now-30, "other-cert")
	add(g.terminal("batch_push_gap", "a push two sequences past the accepted list is a gap: unavailable", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(l1), g.evidence(p3), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(l1), g.object(p3))
		}))
	longList := func() statusFixture {
		_, wire, _ := g.list(g.k("status_intermediate"), intermediateID, 1, Now-60, Now-60+7201)
		return statusFixture{wire, codeList, intermediateID, "status_intermediate", 1, statusEvidenceDigest(codeList, wire)}
	}()
	add(g.terminal("status_list_lifetime_above_policy", "a list whose next_update - updated_at exceeds max_list_lifetime_seconds is never current", def,
		indeterminate("status_unavailable", "trusted", "unavailable", "bound", strp(vp), []EvidenceJSON{g.evidence(longList), g.evidence(st["root_current"])}, allowCounts), func(s *scenario) {
			s.evidence[intermediateID] = evidenceBatch(g.object(longList))
		}))
	add(std("pre_empty_configured_namespace", "an empty configured namespace never matches", bundle, "namespace_mismatch", func(s *scenario) {
		s.namespace = "x"
		s.expected.VerifierNamespace = ""
	}))

	// ---------------- Empty request context strings (absent and "" are the same value).
	prefixCerts := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintResourcePath, ResourceID: "customer/123", PathPrefix: "/v1/customers"}}})
	add(g.terminal("ctx_empty_requested_resource_id", "has_resource with requested_resource_id \"\" (supplied, differs from resource_id)", prefixCerts,
		constraintOut("constraint_unverifiable", 0), func(s *scenario) {
			s.reqCtx = &requestContextJSON{HasResource: true, RequestedPath: "/v1/customers/123"}
		}))

	// ---------------- time_window at T_claim and tzdb edge cases.
	nyEdge := ratify.ConstraintV2{Type: ratify.ConstraintTimeWindow, Start: "02:00", End: "03:00", TZ: "America/New_York"}
	add(g.terminal("tw_uses_claim_time", "inside the window at request now (03:00) but outside at T_claim (03:01:40): constraint_denied", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{nyEdge}}),
		constraintOut("constraint_denied", 0), func(s *scenario) { s.claimOffset = 100 }))
	add(g.terminal("tw_single_minute", "start == end allows exactly that minute; horizon is the next minute", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "08:00", End: "08:00", TZ: "UTC"}}}),
		func() outcomeJSON { o := allow(); o.AllowValidUntil = Now + 60; return o }(), nil))
	add(g.terminal("tw_wrap_early_part", "wrapping window 22:00-08:30 evaluated at 08:00 (m <= end): horizon 08:31 the same day", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: "22:00", End: "08:30", TZ: "UTC"}}}),
		func() outcomeJSON { o := allow(); o.AllowValidUntil = Now + 1860; return o }(), nil))
	zoneCase := func(name, desc, zone, start, end string, now, horizon int64) {
		certs := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintTimeWindow, Start: start, End: end, TZ: zone}},
			leafIssued: now - 3600, leafExpires: now + 86400, rootIssued: now - 3600, rootExpires: now + 86400})
		rootList := g.zoneStatusFixture("status_root", rootID, now)
		intermediateList := g.zoneStatusFixture("status_intermediate", intermediateID, now)
		add(g.terminal(name, desc, certs, allow(), func(s *scenario) {
			_, s.bundle, _ = g.bundle(bundleSpec{agent: agent, certs: certs, session: session, challengeAt: now - 10})
			s.expected.IssuedAt, s.expected.ExpiresAt = now-10, now+290
			s.now = now
			s.evidence = map[string]statusProviderJSON{rootID: evidenceBatch(g.object(rootList)), intermediateID: evidenceBatch(g.object(intermediateList))}
			s.out.StatusEvidence = []EvidenceJSON{g.evidence(rootList), g.evidence(intermediateList)}
			s.out.AllowValidUntil = horizon
		}))
	}
	zoneCase("tw_lord_howe_half_hour_dst", "Australia/Lord_Howe +10:30 -> +11:00 at 2027-10-02T15:30Z; at 01:30 local the window 00:00-02:59 is capped at the 30-minute offset change",
		"Australia/Lord_Howe", "00:00", "02:59", 1822491000-1800, 1822491000)
	zoneCase("tw_casablanca_2045_explicit_transition_out", "Africa/Casablanca +01 -> +00 at 2045-07-09T02:00Z (explicit tzdata transition past 2037); window 00:00-03:59 at 02:30 local is capped there",
		"Africa/Casablanca", "00:00", "03:59", 2383178400-1800, 2383178400)
	zoneCase("tw_casablanca_2045_explicit_transition_in", "Africa/Casablanca +00 -> +01 at 2045-08-20T02:00Z; window 00:00-02:59 at 01:30 local is capped there",
		"Africa/Casablanca", "00:00", "02:59", 2386807200-1800, 2386807200)
	zoneCase("tw_dublin_negative_dst_fall_back", "Europe/Dublin +01 -> +00 at 2030-10-27T01:00Z (negative-DST zone); window 00:00-02:29 at 01:30 local is capped at the offset change",
		"Europe/Dublin", "00:00", "02:29", 1919293200-1800, 1919293200)
	zoneCase("tw_new_york_fold_second_occurrence", "America/New_York at 2040-11-04T06:30Z is 01:30 EST (second occurrence); window 01:00-01:44 ends at 01:45 under the current offset (06:45Z), not at 01:45 EDT",
		"America/New_York", "01:00", "01:44", 2235621600+1800, 2235621600+2700)
	return out
}
