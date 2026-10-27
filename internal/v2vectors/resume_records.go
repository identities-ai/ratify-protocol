package v2vectors

// Resumption record checks (SPEC-v2 §7.11). Each scenario has the claim
// store answer resumption with a committed record taken from the vector, so
// every SDK feeds the same damaged record through its resume function. The
// records reuse request A's and B's signed material: their sealed claims,
// the genuine committed allow body, and the canonical interrupted body.

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// sealedClaimRecord is the canonical sealed claim object of SPEC-v2 §7.13
// claim records for a lifecycle request: the claim the verifier seals for
// it (SPEC-v2 §7.3), written from the request's inputs.
func sealedClaimRecord(v orderingVector, wire []byte) map[string]any {
	b := must(ratify.DecodeProofBundleV2(wire))
	e := v.ExpectedChallenge
	value := must(b64d(e.ValueB64))
	issuers := []any{}
	ids := []string{}
	for _, c := range b.Delegations {
		if !slices.Contains(ids, c.IssuerID) {
			ids = append(ids, c.IssuerID)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		issuers = append(issuers, id)
	}
	var policy any
	if v.ContextPolicy != nil {
		policy = v.ContextPolicy.Digest
	}
	if b.StreamID != nil || len(v.ConstraintEvaluators) != 0 {
		panic("sealedClaimRecord covers requests without a stream or constraint evaluators")
	}
	return map[string]any{
		"agent_id": b.AgentID, "bundle_hash": bundleHash(wire), "challenge_digest": "sha384:" + hex.EncodeToString(must(ratify.ChallengeClaimDigestV2(value))),
		"claim_id": must(ratify.ProtocolClaimIDV2(e.VerifierNamespace, e.ReplayEpoch, value)), "clock_skew_seconds": v.FutureSkewSeconds,
		"constraint_evaluators": []any{}, "context_policy_digest": policy, "expires_at": e.ExpiresAt, "issued_at": e.IssuedAt, "issuer_ids": issuers,
		"max_age_seconds": v.MaxChallengeAgeSeconds, "namespace": e.VerifierNamespace, "proof_digest": bundleHash(wire), "rate_batch": []any{},
		"replay_epoch": e.ReplayEpoch, "required_scope": v.RequiredScope, "requires_rate": false, "stream_id": nil, "stream_seq": nil,
		"verifier_id": e.VerifierID,
	}
}

func (g *gen) resumeRecordScenarios(sc func(string, string, ...lifecycleStepJSON), requests map[string]orderingVector, bundles map[string][]byte) {
	b := must(ratify.DecodeProofBundleV2(bundles["A"]))
	issuers := []string{}
	for _, c := range b.Delegations {
		if !slices.Contains(issuers, c.IssuerID) {
			issuers = append(issuers, c.IssuerID)
		}
	}
	slices.Sort(issuers)
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	st := g.statusFixtures()
	// The committed allow of request A at Now (statusFreshUntil horizon).
	allowBody := func(edit func(*ratify.VerificationReceiptV2)) string {
		r := &ratify.VerificationReceiptV2{
			Version: 2, VerifierID: b.VerifierID, AgentID: b.AgentID, BundleHash: bundleHash(bundles["A"]), IssuerIDs: slices.Clone(issuers),
			Decision: "allow", DecisionReason: "authorized", IdentityStatus: "authorized_agent",
			TrustAssessment: "trusted", StatusAssessment: "current", ChallengeAssessment: "current",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), VerifiedAt: Now, RequiredScope: "data:read",
			GrantedScope:   []string{"data:read", "files:read"},
			StatusEvidence: toLibEvidence(sortEvidence([]EvidenceJSON{g.evidence(st["root_current"]), g.evidence(st["intermediate_current"])})),
		}
		if edit != nil {
			edit(r)
		}
		return b64(must(ratify.VerificationReceiptV2Body(r)))
	}
	// The canonical interrupted result of request A claimed at Now with no
	// recorded progress (SPEC-v2 §6.7).
	interruptedBody := b64(must(ratify.VerificationReceiptV2Body(&ratify.VerificationReceiptV2{
		Version: 2, VerifierID: b.VerifierID, AgentID: b.AgentID, BundleHash: bundleHash(bundles["A"]), IssuerIDs: slices.Clone(issuers),
		Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified",
		TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ChallengeAssessment: "current",
		ContextAssessment: "not_evaluated", VerifiedAt: Now, RequiredScope: "data:read",
		GrantedScope: []string{}, StatusEvidence: []ratify.StatusEvidenceEntryV2{},
	})))
	terminal := func(decision, reason, identity string) string {
		return b64(must(ratify.CanonicalJSON(map[string]string{"decision": decision, "decision_reason": reason, "identity_status": identity})))
	}
	allowTerminal := terminal("allow", "authorized", "authorized_agent")
	interruptedTerminal := terminal("indeterminate", "evaluation_interrupted", "authorization_unverified")
	claimA, claimB := sealedClaimRecord(requests["A"], bundles["A"]), sealedClaimRecord(requests["B"], bundles["B"])
	encode := func(claim map[string]any, edit func(map[string]any)) string {
		c := map[string]any{}
		for k, v := range claim {
			c[k] = v
		}
		if edit != nil {
			edit(c)
		}
		return b64(must(ratify.CanonicalJSON(c)))
	}
	idB := claimB["claim_id"].(string)
	digestA := claimA["challenge_digest"].(string)

	committedAllow := lifecycleExpectJSON{Stage: "committed", Decision: "allow", DecisionReason: "authorized", AllowHorizon: statusFreshUntil}
	unavailable := lifecycleExpectJSON{ErrorClass: "claim_store_unavailable"}
	released := lifecycleExpectJSON{ReleaseStatus: "released", Decision: "allow", ReleaseTime: Now, ReceiptSeq: 1}
	record := func(claim, terminalB64, body string, horizon int64, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "resume", Request: "A", ClaimRecordB64: claim, TerminalB64: terminalB64, BodyB64: body, AllowValidUntil: horizon, Expect: expect}
	}
	verifyA := lifecycleStepJSON{Op: "verify", Request: "A", Expect: committedAllow}
	// Each refused record leaves the store's own record intact: the genuine
	// resumption then publishes and releases at sequence 1.
	thenGenuine := []lifecycleStepJSON{
		{Op: "resume", Request: "A", Expect: committedAllow},
		{Op: "publish", Request: "A", Mode: "ok", Expect: lifecycleExpectJSON{ReceiptSeq: 1}},
		{Op: "release", Request: "A", Checkpoint: "reference", Expect: released},
	}
	refused := func(name, desc string, step lifecycleStepJSON) {
		steps := append([]lifecycleStepJSON{verifyA, step}, thenGenuine...)
		sc("resume_rejects_record_"+name, "request A committed an allow; the claim store answers resumption with a committed record whose "+desc+": it fails the terminal compare-and-set's checks, so resumption returns no handoff (claim_store_unavailable, SPEC-v2 §7.11); the store's own record then resumes, publishes and releases", steps...)
	}
	honest := encode(claimA, nil)
	refused("for_another_claim", "sealed claim is request A's relabelled with request B's claim ID, so it is not the requested claim",
		record(encode(claimA, func(c map[string]any) { c["claim_id"] = idB }), allowTerminal, allowBody(nil), statusFreshUntil, unavailable))
	refused("of_another_well_formed_claim", "sealed claim, terminal result, body and allow horizon are request B's genuine committed allow: every check but the requested claim ID passes",
		record(encode(claimB, nil), allowTerminal, allowBody(func(r *ratify.VerificationReceiptV2) { r.BundleHash = bundleHash(bundles["B"]) }), statusFreshUntil, unavailable))
	step := record(encode(claimA, func(c map[string]any) { c["claim_id"] = idB }), allowTerminal, allowBody(nil), statusFreshUntil, unavailable)
	step.ClaimID = idB
	refused("claim_id_not_derived_from_replay_key", "claim ID is request B's while its namespace, replay epoch and challenge digest are request A's, and resumption requests that claim ID: the ID does not derive from the record's replay key (SPEC-v2 §7.3)", step)
	refused("uppercase_challenge_digest", "challenge digest is request A's in uppercase hex, which decodes to the digest the claim ID derives from but is not the lowercase sha384: form",
		record(encode(claimA, func(c map[string]any) {
			c["challenge_digest"] = "sha384:" + strings.ToUpper(strings.TrimPrefix(digestA, "sha384:"))
		}), allowTerminal, allowBody(nil), statusFreshUntil, unavailable))
	refused("non_sha384_challenge_digest", "challenge digest carries request A's hex digest under the sha512: prefix",
		record(encode(claimA, func(c map[string]any) { c["challenge_digest"] = "sha512:" + strings.TrimPrefix(digestA, "sha384:") }), allowTerminal, allowBody(nil), statusFreshUntil, unavailable))
	refused("body_for_another_agent", "receipt body is request A's committed allow with agent_id naming another agent, so it does not bind the sealed claim (SPEC-v2 §7.5)",
		record(honest, allowTerminal, allowBody(func(r *ratify.VerificationReceiptV2) { r.AgentID = g.k("intermediate").ID }), statusFreshUntil, unavailable))
	refused("terminal_result_other_than_body", "terminal result is deny/delegation_revoked while the receipt body is the committed allow (SPEC-v2 §7.5)",
		record(honest, terminal("deny", "delegation_revoked", "revoked"), allowBody(nil), statusFreshUntil, unavailable))
	refused("allow_without_allow_horizon", "result is the committed allow with allow horizon 0 (SPEC-v2 §6.8)",
		record(honest, allowTerminal, allowBody(nil), 0, unavailable))
	refused("allow_horizon_beyond_timestamp_domain", "result is the committed allow with allow horizon 253402300800, beyond the timestamp domain (SPEC-v2 §2.5, §6.8)",
		record(honest, allowTerminal, allowBody(nil), ratify.V2MaxTimestampSeconds+1, unavailable))
	refused("allow_horizon_on_non_allow", "result is the canonical evaluation_interrupted indeterminate with a positive allow horizon (SPEC-v2 §6.8)",
		record(honest, interruptedTerminal, interruptedBody, Now+60, unavailable))
	// The C ABI's store returns the sealed claim as record bytes, which must
	// be the canonical encoding (SPEC-v2 §7.13).
	nonCanonical := must(b64d(honest))
	if nonCanonical[0] != '{' {
		panic("claim record is not a JSON object")
	}
	nonCanonical = append([]byte("{ "), nonCanonical[1:]...)
	if bytes.Equal(nonCanonical, must(b64d(honest))) {
		panic("non-canonical record equals the canonical one")
	}
	bytesStep := record(b64(nonCanonical), allowTerminal, allowBody(nil), statusFreshUntil, unavailable)
	bytesStep.Mode = "record_bytes"
	refused("non_canonical_claim_record", "sealed claim record bytes are request A's canonical record with a space after the opening brace: they decode to the genuine claim but are not its canonical encoding (SPEC-v2 §7.13)", bytesStep)

	sc("resume_accepts_interrupted_record", "the claim store answers resumption with request A's sealed claim and the canonical evaluation_interrupted result and body with allow horizon 0: every check passes and resumption returns that committed result (SPEC-v2 §7.11)",
		record(honest, interruptedTerminal, interruptedBody, 0, lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted"}))
	sc("resume_substituted_record_rejected_at_release", "request A committed an allow and published its receipt; the claim store then answers resumption with request A's sealed claim and the canonical evaluation_interrupted result and body with allow horizon 0: the record passes every resumption check, so resumption returns that handoff, but it differs from the committed record and release rejects it at step 1 (rejected / release_state_mismatch, SPEC-v2 §6.9, §7.11); the store's own record then resumes and releases at sequence 1",
		verifyA, thenGenuine[1],
		record(honest, interruptedTerminal, interruptedBody, 0, lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted"}),
		lifecycleStepJSON{Op: "release", Request: "A", Checkpoint: "reference", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "release_state_mismatch"}},
		thenGenuine[0], thenGenuine[2])
	sc("resume_accepts_honest_record", "request A committed an allow; the claim store answers resumption with exactly that committed record (sealed claim, terminal result, body and allow horizon): the returned handoff publishes at sequence 1 and releases exactly as the handoff the verifier returned, and a second release is the same (SPEC-v2 §7.11)",
		verifyA, record(honest, allowTerminal, allowBody(nil), statusFreshUntil, committedAllow),
		thenGenuine[1], thenGenuine[2], thenGenuine[2])
}
