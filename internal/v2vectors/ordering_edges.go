package v2vectors

// Ordering edges (SPEC-v2 §2.5, §5.2, §6.1, §6.2, §6.4, §6.5): chains whose
// ascending issuer order differs from chain order, a repeated issuer whose
// references are not in sorted order, trust answers from a working provider,
// extension constraints on different links, an exact audience match with a
// failing audience provider, and the configured verifier ID and §2.5 bounds
// one step outside their ranges.

import (
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func (g *gen) orderingEdgeScenarios() []scenario {
	agent, root, inter, inter2 := g.k("agent"), g.k("root"), g.k("intermediate"), g.k("intermediate_2")
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	st := g.statusFixtures()
	rootEv, interEv := g.evidence(st["root_current"]), g.evidence(st["intermediate_current"])
	var out []scenario
	add := func(s scenario) { out = append(out, s) }
	deny := func(reason, identity, status string, evidence []EvidenceJSON, counts countsJSON) outcomeJSON {
		return outcomeJSON{Decision: "deny", DecisionReason: reason, IdentityStatus: identity, TrustAssessment: "trusted", StatusAssessment: status,
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), StatusEvidence: evidence, CallbackCounts: counts}
	}
	statusUnavailable := func(evidence []EvidenceJSON, counts countsJSON) outcomeJSON {
		return outcomeJSON{Decision: "indeterminate", DecisionReason: "status_unavailable", IdentityStatus: "authorization_unverified", TrustAssessment: "trusted",
			StatusAssessment: "unavailable", ContextAssessment: "bound", ContextPolicyDigest: strp(vp), StatusEvidence: evidence, CallbackCounts: counts}
	}
	allow := func(evidence []EvidenceJSON, counts countsJSON) outcomeJSON {
		return outcomeJSON{Decision: "allow", DecisionReason: "authorized", IdentityStatus: "authorized_agent", TrustAssessment: "trusted", StatusAssessment: "current",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), GrantedScope: []string{"data:read", "files:read"}, StatusEvidence: evidence,
			AllowValidUntil: statusFreshUntil, CallbackCounts: counts}
	}
	full := []string{"data:read", "files:read", "identity:delegate"}
	leafScope := []string{"data:read", "files:read"}

	// ---------------- Status requests: ascending issuer order, not chain order.
	// Chain order is intermediate (89b5...), intermediate_2 (4717...), root
	// (f1f0...); ascending byte order is intermediate_2, intermediate, root.
	list := func(key, issuerID string, seq int64, revoked ...string) statusFixture {
		_, wire, _ := g.list(g.k(key), issuerID, seq, Now-60, Now+3600, revoked...)
		return statusFixture{wire, codeList, issuerID, key, seq, statusEvidenceDigest(codeList, wire)}
	}
	leaf3, _, _ := g.cert(certSpec{issuer: inter, subject: agent, certID: "z-leaf", scope: leafScope})
	mid3, _, _ := g.cert(certSpec{issuer: inter2, subject: inter, certID: "m-mid", scope: full})
	root3, _, _ := g.cert(certSpec{issuer: root, subject: inter2, certID: "a-root", scope: full})
	three := []ratify.DelegationCertV2{leaf3, mid3, root3}
	threeKeys := func() map[string]statusKeyJSON {
		k := g.statusKeyConfig()
		k[inter2.ID] = statusKeyJSON{Epoch: 1, StatusKeyID: g.k("rotation_third").ID, PublicKey: pubJSON(g.k("rotation_third").Pub)}
		return k
	}
	inter2Current := list("rotation_third", inter2.ID, 1)
	threeCounts := countsJSON{Claim: 1, Trust: 1, Status: 3}
	add(g.terminal("status_order_ascending_issuer_not_chain_order", "three distinct issuers whose ascending byte order (intermediate_2, intermediate, root) differs from chain order (intermediate, intermediate_2, root): one request per issuer, in ascending order, each with that issuer's reference", three,
		allow([]EvidenceJSON{rootEv, interEv, g.evidence(inter2Current)}, threeCounts), func(s *scenario) {
			s.statusKeys = threeKeys()
			s.evidence[inter2.ID] = evidenceBatch(g.object(inter2Current))
		}))
	rootRevoked := list("status_root", root.ID, 2, "a-root")
	add(g.terminal("status_first_issuer_error_later_issuer_revokes", "the first issuer in ascending order (intermediate_2) errors and the root revokes its certificate: every issuer is still requested and revoked outranks unavailable", three,
		deny("delegation_revoked", "revoked", "revoked", []EvidenceJSON{g.evidence(rootRevoked), interEv}, threeCounts), func(s *scenario) {
			s.statusKeys = threeKeys()
			s.evidence[inter2.ID] = providerFailure("error")
			s.evidence[root.ID] = evidenceBatch(g.object(rootRevoked))
		}))
	add(g.terminal("status_middle_issuer_unconfigured", "intermediate_2 has no configured status key: its reference is unavailable without a provider request, and the other two issuers are requested in ascending order", three,
		statusUnavailable([]EvidenceJSON{rootEv, interEv}, countsJSON{Claim: 1, Trust: 1, Status: 2}), nil))

	// ---------------- A repeated issuer whose chain order is not sorted order.
	repLeaf, _, _ := g.cert(certSpec{issuer: inter, subject: agent, certID: "z-leaf", scope: leafScope})
	repSelf, _, _ := g.cert(certSpec{issuer: inter, subject: inter, certID: "a-self", scope: full})
	repRoot, _, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: full})
	repeated := []ratify.DelegationCertV2{repLeaf, repSelf, repRoot}
	twoCounts := countsJSON{Claim: 1, Trust: 1, Status: 2}
	add(g.terminal("status_repeated_issuer_refs_in_chain_order", "intermediate issues chain links 0 (z-leaf) and 1 (a-self): one request for it with both references in chain order, not sorted order", repeated,
		allow([]EvidenceJSON{rootEv, interEv}, twoCounts), nil))
	selfRevoked := list("status_intermediate", inter.ID, 2, "a-self")
	add(g.terminal("status_repeated_issuer_second_ref_revoked", "the repeated issuer's second reference (a-self, chain link 1) is revoked: delegation_revoked", repeated,
		deny("delegation_revoked", "revoked", "revoked", []EvidenceJSON{rootEv, g.evidence(selfRevoked)}, twoCounts), func(s *scenario) {
			s.evidence[inter.ID] = evidenceBatch(g.object(selfRevoked))
		}))
	add(g.terminal("status_repeated_issuer_provider_error", "the repeated issuer's provider errors: one request, and both of its references are unavailable", repeated,
		statusUnavailable([]EvidenceJSON{rootEv}, twoCounts), func(s *scenario) {
			s.evidence[inter.ID] = providerFailure("error")
		}))

	// ---------------- Trust answers from a working provider (§6.1, §6.4).
	def := g.chain(chainSpec{})
	trustUnavailable := outcomeJSON{Decision: "indeterminate", DecisionReason: "trust_unavailable", IdentityStatus: "authorization_unverified", TrustAssessment: "unavailable",
		StatusAssessment: "not_evaluated", ContextAssessment: "not_evaluated", CallbackCounts: countsJSON{Claim: 1, Trust: 1}}
	add(g.terminal("trust_unavailable_with_root_key", "the provider answers unavailable while returning the correct root key: trust_unavailable and no status request", def, trustUnavailable, func(s *scenario) {
		s.trust = &trustJSON{Mode: "ok", Outcome: "unavailable", RootPublicKey: pubJSON(root.Pub)}
	}))
	add(g.terminal("trust_trusted_mixed_component_key", "trusted with the root's Ed25519 component and another key's ML-DSA-65 component: the returned key is not the terminal issuer key, so trust_unavailable", def, trustUnavailable, func(s *scenario) {
		s.trust = &trustJSON{Mode: "ok", Outcome: "trusted", RootPublicKey: map[string]any{"ed25519": b64(root.Pub.Ed25519), "ml_dsa_65": b64(g.k("attacker").Pub.MLDSA65)}}
	}))
	add(g.terminal("trust_untrusted_before_revoked_leaf", "an untrusted root with a revoked leaf: unauthorized, and status is never requested", def,
		outcomeJSON{Decision: "deny", DecisionReason: "unauthorized", IdentityStatus: "unauthorized", TrustAssessment: "untrusted", StatusAssessment: "not_evaluated",
			ContextAssessment: "not_evaluated", CallbackCounts: countsJSON{Claim: 1, Trust: 1}}, func(s *scenario) {
			s.trust = &trustJSON{Mode: "ok", Outcome: "untrusted"}
			s.evidence[inter.ID] = evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
		}))
	add(g.terminal("trust_unavailable_three_issuers", "trust unavailable on a chain of three issuers with every status key configured: no status request", three, trustUnavailable, func(s *scenario) {
		s.trust = &trustJSON{Mode: "ok", Outcome: "unavailable"}
		s.statusKeys = threeKeys()
	}))

	// ---------------- Extension constraints on different links (§5.2, §6.4).
	maxNodes := ratify.ConstraintV2{Type: maxCountType, Params: map[string]any{"counter": "nodes", "max": 10}}
	category := ratify.ConstraintV2{Type: allowedType, Params: map[string]any{"field": "work_order_category", "allowed": []any{"inspection"}}}
	stdCount := evaluatorJSON{Type: maxCountType, Profile: maxCountProfile, Implementation: maxCountProfile}
	stdAllowed := evaluatorJSON{Type: allowedType, Profile: allowedProfile, Implementation: allowedProfile}
	absent := evaluatorJSON{Type: "com.example.absent", Profile: "com.example.absent/v1", Implementation: "fault:error"}
	twoLinks := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{category}, rootCons: []ratify.ConstraintV2{maxNodes}})
	extDeny := func(reason string, evaluators int) outcomeJSON {
		return deny(reason, reason, "current", g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: evaluators})
	}
	add(g.terminal("extension_two_links_unused_registry_entry", "allowed_values on the leaf and max_count on the root, with a registry entry for a type absent from the chain: both evaluated, and only the two present types are sealed, sorted by type", twoLinks,
		allow(g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: 2}), func(s *scenario) {
			s.evaluators = []evaluatorJSON{absent, stdCount, stdAllowed}
			s.reqCtx = &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 10}, ExtensionValues: map[string]string{"work_order_category": "inspection"}}
		}))
	add(g.terminal("extension_root_denied_leaf_unverifiable", "the leaf's allowed_values has no authenticated value (unverifiable) and the root's max_count is exceeded (denied): constraint_denied", twoLinks, extDeny("constraint_denied", 2), func(s *scenario) {
		s.evaluators = []evaluatorJSON{stdCount, stdAllowed}
		s.reqCtx = &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 11}}
	}))
	add(g.terminal("extension_registered_root_unknown_leaf", "only max_count is registered and the root passes: the leaf's allowed_values type is constraint_unknown", twoLinks, extDeny("constraint_unknown", 1), func(s *scenario) {
		s.evaluators = []evaluatorJSON{stdCount}
		s.reqCtx = &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 3}}
	}))
	add(g.terminal("extension_registry_only_absent_type_two_links", "a registry holding only a type absent from the chain: nothing is sealed, and both links' extension types are constraint_unknown with no evaluator call", twoLinks, extDeny("constraint_unknown", 0), func(s *scenario) {
		s.evaluators = []evaluatorJSON{absent}
	}))
	add(g.terminal("extension_revoked_outranks_denied", "the leaf is revoked and the root's max_count is exceeded: delegation_revoked, and the sealed profiles are still recorded", twoLinks,
		deny("delegation_revoked", "revoked", "revoked", []EvidenceJSON{rootEv, g.evidence(st["intermediate_revoked_leaf"])}, countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: 2}), func(s *scenario) {
			s.evaluators = []evaluatorJSON{stdCount, stdAllowed}
			s.reqCtx = &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 11}}
			s.evidence[inter.ID] = evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
		}))

	// ---------------- An exact audience match needs no membership (§5.2).
	exactOrDomain := ratify.ConstraintV2{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-9"}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}}
	add(g.terminal("audience_exact_match_provider_error", "an exact receiver match on a link that also names a domain is eligible, so a failing audience provider does not affect the allow", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{exactOrDomain}}),
		allow(g.currentEvidence(), countsJSON{Claim: 1, Trust: 1, Status: 2, Audience: 1}), func(s *scenario) {
			s.expected.ExpectedReceiverID = strp("receiver-9")
			s.audience = "error"
		}))

	// ---------------- Configured verifier ID and §2.5 bounds (§6.2 steps 2 and 6).
	bundle, certs, session := g.base()
	std := func(name, desc, class string, edit func(*scenario)) {
		s := scenario{name: name, desc: desc, bundle: bundle, certs: certs, scope: "data:read", expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session),
			trust: g.trustRoot("root"), evidence: g.currentEvidenceBatches(certs), out: preflight(class, 0)}
		edit(&s)
		add(s)
	}
	verifierID := g.k("verifier").ID
	configuredID := func(id string) func(*scenario) { return func(s *scenario) { s.verifierID = strp(id) } }
	std("config_verifier_id_long", "a configured verifier key ID of 65 hex characters is not a canonical v2 key ID: configuration_invalid", "configuration_invalid", configuredID(verifierID+"0"))
	std("config_verifier_id_non_hex", "a configured verifier key ID with a non-hex character: configuration_invalid", "configuration_invalid", configuredID(verifierID[:63]+"g"))
	std("config_verifier_id_leading_space", "a configured verifier key ID with a leading space in place of its first character: configuration_invalid", "configuration_invalid", configuredID(" "+verifierID[1:]))
	std("config_verifier_id_prefixed", "a configured verifier key ID with a sha256: prefix: configuration_invalid", "configuration_invalid", configuredID("sha256:"+verifierID))
	std("pre_verifier_id_other_canonical", "a canonical configured verifier key ID that the challenge and proof do not name: verifier_id_mismatch at step 6", "verifier_id_mismatch", configuredID(strings.Repeat("0", 64)))
	std("pre_expected_verifier_id_uppercase", "the ExpectedChallenge verifier_id in uppercase hex is not byte-equal to the configured verifier key ID: verifier_id_mismatch", "verifier_id_mismatch", func(s *scenario) {
		s.expected.VerifierID = strings.ToUpper(verifierID)
	})
	std("pre_expected_replay_epoch_negative", "an ExpectedChallenge replay_epoch of -1 is outside 0..2^53-1 and can never equal the configured epoch: stale_replay_epoch", "stale_replay_epoch", func(s *scenario) {
		s.expected.ReplayEpoch = -1
	})
	std("pre_expected_replay_epoch_above_safe_integer", "an ExpectedChallenge replay_epoch of 2^53 is outside 0..2^53-1 and can never equal the configured epoch: stale_replay_epoch", "stale_replay_epoch", func(s *scenario) {
		s.expected.ReplayEpoch = 1 << 53
	})
	std("config_replay_epoch_negative", "a configured replay epoch of -1 is outside 0..2^53-1: configuration_invalid", "configuration_invalid", func(s *scenario) {
		s.epoch, s.expected.ReplayEpoch = -1, -1
	})
	std("config_future_skew_negative", "a configured future skew of -1 (the status policy's skew the same) is outside 0..300: configuration_invalid", "configuration_invalid", func(s *scenario) {
		s.post = func(v *orderingVector) { v.FutureSkewSeconds, v.StatusPolicy.ClockSkewSeconds = -1, -1 }
	})
	std("config_max_age_zero", "a configured challenge maximum age of 0 is outside 1..300: configuration_invalid", "configuration_invalid", func(s *scenario) {
		s.post = func(v *orderingVector) { v.MaxChallengeAgeSeconds = 0 }
	})
	std("config_now_after_timestamp_domain", "a verifier time of 253402300800, one past the timestamp domain: configuration_invalid", "configuration_invalid", func(s *scenario) {
		s.now = ratify.V2MaxTimestampSeconds + 1
	})
	std("config_expected_session_33_bytes", "an ExpectedChallenge session context of 33 bytes is not exactly 32 bytes: configuration_invalid at step 2", "configuration_invalid", func(s *scenario) {
		s.expected.ExpectedSessionContextB64 = strp(b64(append(append([]byte{}, session...), 0)))
	})
	std("config_status_skew_one_above_future_skew", "a status policy skew of 6 with a future skew of 5: the live verifier's single skew differs, configuration_invalid", "configuration_invalid", func(s *scenario) {
		p := orderingStatusPolicy
		p.ClockSkewSeconds = 6
		s.policy2 = &p
	})
	return out
}
