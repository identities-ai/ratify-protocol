package v2vectors

import (
	"encoding/hex"
	"sort"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Extension evaluator profiles (SPEC-v2 §5.2). The profile digest is
// computed here from the specification formula, independently of the
// library's ConstraintProfileDigestV2.
const (
	maxCountType      = "com.ratifyprotocol.max_count"
	maxCountProfile   = "com.ratifyprotocol.max_count/v1"
	allowedType       = "com.ratifyprotocol.allowed_values"
	allowedProfile    = "com.ratifyprotocol.allowed_values/v1"
	faultType         = "com.example.fault"
	faultProfile      = "com.example.fault/v1"
	referenceTypeADK  = "com.ratifyprotocol.adk.max_nodes"
	profileDigestName = "ratify-protocol-constraint-profile-v2"
)

func profileDigest(profile, kind string) string {
	return "sha384:" + hex.EncodeToString(sha384Prefixed(profileDigestName, canon(map[string]any{"profile": profile, "type": kind})))
}

// sealedEvaluatorRefs is the receipt's constraint_evaluators: the configured
// entries whose type appears in the chain, sorted by type; nil when none.
func sealedEvaluatorRefs(b *ratify.ProofBundleV2, evaluators []evaluatorJSON) []ratify.ConstraintEvaluatorRefV2 {
	present := map[string]bool{}
	for _, c := range b.Delegations {
		for _, k := range c.Constraints {
			present[string(k.Type)] = true
		}
	}
	var refs []ratify.ConstraintEvaluatorRefV2
	for _, e := range evaluators {
		if present[e.Type] {
			refs = append(refs, ratify.ConstraintEvaluatorRefV2{Type: ratify.ConstraintType(e.Type), ProfileDigest: profileDigest(e.Profile, e.Type)})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Type < refs[j].Type })
	return refs
}

func (g *gen) extensionScenarios(add func(scenario), allow func() outcomeJSON,
	deny func(reason, identity, trust, status, context string, digest *string, evidence []EvidenceJSON, counts countsJSON) outcomeJSON, vp string) {
	maxNodes := func(max int64) ratify.ConstraintV2 {
		return ratify.ConstraintV2{Type: maxCountType, Params: map[string]any{"counter": "nodes", "max": max}}
	}
	category := ratify.ConstraintV2{Type: allowedType, Params: map[string]any{"field": "work_order_category", "allowed": []any{"inspection", "maintenance"}}}
	unknown := ratify.ConstraintV2{Type: "ratify.conformance_unknown", Params: map[string]any{"x": 1}}
	fault := ratify.ConstraintV2{Type: faultType, Params: map[string]any{"case": "fault"}}
	stdCount := evaluatorJSON{Type: maxCountType, Profile: maxCountProfile, Implementation: maxCountProfile}
	stdAllowed := evaluatorJSON{Type: allowedType, Profile: allowedProfile, Implementation: allowedProfile}
	faultEval := func(implementation string, validUntil int64) evaluatorJSON {
		return evaluatorJSON{Type: faultType, Profile: faultProfile, Implementation: implementation, ValidUntil: validUntil}
	}
	counts := func(evaluator int) countsJSON {
		return countsJSON{Claim: 1, Trust: 1, Status: 2, Evaluator: evaluator}
	}
	outFor := func(reason string, evaluator int) outcomeJSON {
		return deny(reason, reason, "trusted", "current", "bound", strp(vp), g.currentEvidence(), counts(evaluator))
	}
	allowWith := func(evaluator int, horizon int64) outcomeJSON {
		out := allow()
		out.CallbackCounts.Evaluator = evaluator
		if horizon != 0 {
			out.AllowValidUntil = horizon
		}
		return out
	}
	ctxCounts := func(n int64) *requestContextJSON {
		return &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": n}}
	}
	ctxValue := func(v string) *requestContextJSON {
		return &requestContextJSON{ExtensionValues: map[string]string{"work_order_category": v}}
	}
	with := func(evals []evaluatorJSON, ctx *requestContextJSON) func(*scenario) {
		return func(s *scenario) { s.evaluators, s.reqCtx = evals, ctx }
	}
	leaf := func(cons ...ratify.ConstraintV2) []ratify.DelegationCertV2 {
		return g.chain(chainSpec{leafCons: cons})
	}

	// Standard count profile (references' max_nodes).
	add(g.terminal("extension_max_count_pass", "standard count profile: authenticated count 3 under max 10 passes; the receipt records the sealed profile digest", leaf(maxNodes(10)),
		allowWith(1, 0), with([]evaluatorJSON{stdCount}, ctxCounts(3))))
	add(g.terminal("extension_max_count_at_bound", "standard count profile: a count equal to max passes", leaf(maxNodes(10)),
		allowWith(1, 0), with([]evaluatorJSON{stdCount}, ctxCounts(10))))
	add(g.terminal("extension_max_count_exceeded", "standard count profile: a count above max is constraint_denied after complete status", leaf(maxNodes(10)),
		outFor("constraint_denied", 1), with([]evaluatorJSON{stdCount}, ctxCounts(11))))
	add(g.terminal("extension_max_count_missing_context", "standard count profile: no authenticated count is constraint_unverifiable, never a pass", leaf(maxNodes(10)),
		outFor("constraint_unverifiable", 1), with([]evaluatorJSON{stdCount}, nil)))
	add(g.terminal("extension_max_count_params_invalid", "standard count profile: params outside {counter,max} can never pass and are constraint_denied", leaf(ratify.ConstraintV2{Type: maxCountType, Params: map[string]any{"counter": "nodes", "max": 10, "unit": "vm"}}),
		outFor("constraint_denied", 1), with([]evaluatorJSON{stdCount}, ctxCounts(1))))
	add(g.terminal("extension_max_count_negative_max", "standard count profile: a negative max is outside the profile and constraint_denied", leaf(maxNodes(-1)),
		outFor("constraint_denied", 1), with([]evaluatorJSON{stdCount}, ctxCounts(0))))
	add(g.terminal("extension_reference_type_bound_to_standard_profile", "a verifier binds the standard count semantics to a reference's own type; the descriptor, and so the digest, names that type", leaf(ratify.ConstraintV2{Type: referenceTypeADK, Params: map[string]any{"counter": "nodes", "max": 4}}),
		allowWith(1, 0), with([]evaluatorJSON{{Type: referenceTypeADK, Profile: maxCountProfile, Implementation: maxCountProfile}}, ctxCounts(4))))
	add(g.terminal("extension_profile_version_changes_digest", "the same semantics registered under a new profile version allow with a different signed profile digest", leaf(maxNodes(10)),
		allowWith(1, 0), with([]evaluatorJSON{{Type: maxCountType, Profile: "com.ratifyprotocol.max_count/v2", Implementation: maxCountProfile}}, ctxCounts(3))))

	// Standard exact-value profile (work-order category).
	add(g.terminal("extension_allowed_value_pass", "standard exact-value profile: an allowed work-order category passes", leaf(category),
		allowWith(1, 0), with([]evaluatorJSON{stdAllowed}, ctxValue("maintenance"))))
	add(g.terminal("extension_allowed_value_denied", "standard exact-value profile: comparison is byte equality, so a different case is constraint_denied", leaf(category),
		outFor("constraint_denied", 1), with([]evaluatorJSON{stdAllowed}, ctxValue("Maintenance"))))
	add(g.terminal("extension_allowed_value_missing_context", "standard exact-value profile: no authenticated value is constraint_unverifiable", leaf(category),
		outFor("constraint_unverifiable", 1), with([]evaluatorJSON{stdAllowed}, ctxCounts(1))))
	add(g.terminal("extension_both_profiles_pass", "both standard profiles on one certificate pass; the receipt lists both, sorted by type", leaf(maxNodes(10), category),
		allowWith(2, 0), with([]evaluatorJSON{stdCount, stdAllowed}, &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": 2}, ExtensionValues: map[string]string{"work_order_category": "inspection"}})))

	// Registration and aggregation.
	add(g.terminal("extension_unregistered_is_unknown", "an extension type with no registered profile is constraint_unknown and the receipt names no evaluator", leaf(maxNodes(10)),
		outFor("constraint_unknown", 0), with(nil, ctxCounts(3))))
	add(g.terminal("extension_registry_without_chain_type", "a registry entry for a type absent from the chain is not sealed or recorded; the chain's type stays unknown", leaf(maxNodes(10)),
		outFor("constraint_unknown", 0), with([]evaluatorJSON{stdAllowed}, ctxCounts(3))))
	add(g.terminal("extension_denied_outranks_unknown", "an evaluator denial outranks an unregistered type independent of link order", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{unknown}, rootCons: []ratify.ConstraintV2{maxNodes(10)}}),
		outFor("constraint_denied", 1), with([]evaluatorJSON{stdCount}, ctxCounts(11))))
	add(g.terminal("extension_unknown_outranks_unverifiable", "an unregistered type outranks an evaluator's unverifiable result", g.chain(chainSpec{leafCons: []ratify.ConstraintV2{maxNodes(10)}, rootCons: []ratify.ConstraintV2{unknown}}),
		outFor("constraint_unknown", 1), with([]evaluatorJSON{stdCount}, nil)))
	add(g.terminal("extension_status_revoked_still_records_profiles", "status precedence is unchanged: a revoked leaf denies with delegation_revoked, and the receipt still records the sealed profile", leaf(maxNodes(10)),
		deny("delegation_revoked", "revoked", "trusted", "revoked", "bound", strp(vp), []EvidenceJSON{g.evidence(g.statusFixtures()["intermediate_revoked_leaf"]), g.evidence(g.statusFixtures()["root_current"])}, counts(1)),
		func(s *scenario) {
			s.evaluators, s.reqCtx = []evaluatorJSON{stdCount}, ctxCounts(3)
			s.evidence[g.k("intermediate").ID] = evidenceBatch(g.object(g.statusFixtures()["intermediate_revoked_leaf"]))
		}))

	// Evaluator failures are constraint_unverifiable and still record the profile.
	for _, c := range []struct{ name, implementation, desc string }{
		{"extension_evaluator_error", "fault:error", "an evaluator error"},
		{"extension_evaluator_panic", "fault:panic", "an evaluator panic"},
		{"extension_evaluator_timeout", "fault:timeout", "an evaluator that does not answer within the registry timeout"},
		{"extension_evaluator_invalid_outcome", "fault:invalid_outcome", "an evaluator outcome outside pass/denied/unverifiable"},
	} {
		add(g.terminal(c.name, c.desc+" is constraint_unverifiable; the receipt still records the sealed profile", leaf(fault),
			outFor("constraint_unverifiable", 1), with([]evaluatorJSON{faultEval(c.implementation, 0)}, nil)))
	}
	add(g.terminal("extension_pass_horizon_bounds_allow", "a passing evaluator horizon earlier than status freshness becomes the allow horizon", leaf(fault),
		allowWith(1, Now+120), with([]evaluatorJSON{faultEval("fault:pass_until", Now+120)}, nil)))
	add(g.terminal("extension_pass_horizon_not_after_claim", "a pass horizon at or before T_claim is invalid evaluator output: constraint_unverifiable", leaf(fault),
		outFor("constraint_unverifiable", 1), with([]evaluatorJSON{faultEval("fault:pass_until", Now)}, nil)))

	// Extension request context is validated before claim.
	agent := g.k("agent")
	bundleCerts := leaf(maxNodes(10))
	session := g.fixtureSessionContext(agent)
	_, bundle, _ := g.bundle(bundleSpec{agent: agent, certs: bundleCerts, session: session})
	for _, c := range []struct {
		name, desc string
		ctx        *requestContextJSON
	}{
		{"extension_context_negative_count", "a negative extension count", &requestContextJSON{ExtensionCounts: map[string]int64{"nodes": -1}}},
		{"extension_context_bad_name", "an extension count name outside [a-z0-9_.:-]", &requestContextJSON{ExtensionCounts: map[string]int64{"Nodes": 1}}},
		{"extension_context_value_too_long", "an extension value longer than 512 bytes", &requestContextJSON{ExtensionValues: map[string]string{"work_order_category": strings.Repeat("a", 513)}}},
	} {
		add(scenario{name: c.name, desc: c.desc + " is configuration_invalid before claim", bundle: bundle, certs: bundleCerts, scope: "data:read",
			expected: g.defaultExpected(agent, session), policy: g.verifyPolicyJSON(session), trust: g.trustRoot("root"),
			evidence: g.currentEvidenceBatches(bundleCerts), evaluators: []evaluatorJSON{stdCount}, reqCtx: c.ctx, out: preflight("configuration_invalid", 0)})
	}
}
