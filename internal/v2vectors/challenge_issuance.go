package v2vectors

import (
	"bytes"
)

// Challenge issuance lifecycle vectors (SPEC-v2 Part B, §7.3 challenge
// issuance helper). Expected results follow from the helper's contract:
// persist before exposure, insert-only records keyed by ChallengeClaimDigest,
// retrieval by that digest, and the unchanged pre-claim and claim rules.

type issueRequestJSON struct {
	VerifierNamespace         string  `json:"verifier_namespace"`
	ReplayEpoch               int64   `json:"replay_epoch"`
	VerifierID                string  `json:"verifier_id"`
	LifetimeSeconds           int64   `json:"lifetime_seconds"`
	ExpectedAgent             *string `json:"expected_agent"`
	ExpectedReceiverID        *string `json:"expected_receiver_id"`
	ExpectedSessionContextB64 *string `json:"expected_session_context_b64"`
}

type issuanceExpectJSON struct {
	Result       string   `json:"result"`
	ErrorClass   string   `json:"error_class,omitempty"`
	ChallengeB64 string   `json:"challenge_b64,omitempty"`
	IssuedAt     int64    `json:"issued_at,omitempty"`
	ExpiresAt    int64    `json:"expires_at,omitempty"`
	RecordsAfter *int     `json:"records_after,omitempty"`
	Dispositions []string `json:"dispositions,omitempty"`
}

type issuanceStepJSON struct {
	Op           string             `json:"op"`
	At           int64              `json:"at"`
	Request      *issueRequestJSON  `json:"request,omitempty"`
	PersistFault string             `json:"persist_fault,omitempty"`
	ChallengeB64 string             `json:"challenge_b64,omitempty"`
	Bundles      []string           `json:"bundles_b64,omitempty"`
	Expect       issuanceExpectJSON `json:"expect"`
}

type issuanceScenarioJSON struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	RandomB64   []string           `json:"random_b64"`
	Steps       []issuanceStepJSON `json:"steps"`
}

type challengeIssuanceFile struct {
	Version     int                    `json:"version"`
	Description string                 `json:"description"`
	Operations  map[string]string      `json:"operations"`
	Scenarios   []issuanceScenarioJSON `json:"scenarios"`
}

func intp(n int) *int { return &n }

func (g *gen) challengeIssuanceFile() any {
	agent, attacker, verifier := g.k("agent"), g.k("attacker"), g.k("verifier")
	session := g.fixtureSessionContext(agent)
	rnd := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	r1, r2, r3 := rnd(0x11), rnd(0x22), rnd(0x33)
	request := func(lifetime int64, bindAgent bool, sess []byte) *issueRequestJSON {
		req := &issueRequestJSON{VerifierNamespace: fixtureNamespace, ReplayEpoch: fixtureReplayEpoch, VerifierID: verifier.ID, LifetimeSeconds: lifetime}
		if bindAgent {
			req.ExpectedAgent = strp("agent")
		}
		if sess != nil {
			req.ExpectedSessionContextB64 = strp(b64(sess))
		}
		return req
	}
	present := func(k *Key, challenge []byte, issuedAt int64, sess []byte, verifierID string) string {
		spec := bundleSpec{agent: k, challenge: challenge, challengeAt: issuedAt, session: sess, verifierID: verifierID}
		if k == agent {
			spec.certs = g.chain(chainSpec{})
		}
		_, wire, _ := g.bundle(spec)
		return b64(wire)
	}
	issued := func(c []byte, at, lifetime int64, records int) issuanceExpectJSON {
		return issuanceExpectJSON{Result: "issued", ChallengeB64: b64(c), IssuedAt: at, ExpiresAt: at + lifetime, RecordsAfter: intp(records)}
	}
	preflight := func(class string) issuanceExpectJSON {
		return issuanceExpectJSON{Result: "preflight", ErrorClass: class}
	}
	claimed := func(d ...string) issuanceExpectJSON { return issuanceExpectJSON{Result: "claimed", Dispositions: d} }

	f := challengeIssuanceFile{
		Version:     1,
		Description: "Challenge issuance helper lifecycle (SPEC-v2 Part B, §7.3). Each scenario replays steps in order against one issuance store and one Part B claim store that share the authoritative clock; the issuer's random source yields random_b64 in order. The helper validates the request, reads the authoritative clock as issued_at, draws 32 bytes, durably persists the complete ExpectedChallengeV2 keyed by (verifier_namespace, replay_epoch, ChallengeClaimDigest), and only then returns it. A key conflict draws fresh bytes (at most three attempts) and never overwrites a record.",
		Operations: map[string]string{
			"issue":              "set the clock to at; arm persist_fault for this call only (ok; fail_before_commit = nothing stored and an error; fail_after_commit = the record is stored, then an error, modelling a crash before the response); issue request. expected_agent names a keys.json fixture whose ID and complete key are bound. expect.result issued gives the exact challenge, issued_at and expires_at; error means no challenge was returned. records_after is the number of stored records after the step",
			"load":               "retrieve the record for challenge_b64 by ChallengeClaimDigest under the fixture namespace and epoch. expect.result found returns a record naming exactly these bytes; expected_challenge_unavailable otherwise",
			"present":            "set the clock to at; load the record for the bundle's challenge (expected_challenge_unavailable when absent), then run pre-claim checks (§6.2) at now = at with max_challenge_age_seconds 300, future_skew_seconds 5, required_scope data:read, the fixture namespace and epoch, and a context policy derived from the record (the Verify session-context policy with the record's expected session context when it has one, otherwise an explicit not-required policy), then the atomic claim. expect.result preflight gives the class; claimed gives the claim disposition",
			"present_concurrent": "set the clock to at; present every bundle in bundles_b64 concurrently. expect.dispositions is the sorted multiset of outcomes: created, in_progress (an exact retry while evaluating), or proof_conflict (a different proof for the claimed challenge). Exactly one presentation creates the claim",
		},
	}
	add := func(name, desc string, random [][]byte, steps ...issuanceStepJSON) {
		var r []string
		for _, b := range random {
			r = append(r, b64(b))
		}
		f.Scenarios = append(f.Scenarios, issuanceScenarioJSON{Name: name, Description: desc, RandomB64: r, Steps: steps})
	}
	at := Now - 10

	add("issue_then_present", "a persisted challenge is retrievable by its claim digest, claims once, and an exact retry is a replay", [][]byte{r1},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issued(r1, at, 120, 1)},
		issuanceStepJSON{Op: "load", ChallengeB64: b64(r1), Expect: issuanceExpectJSON{Result: "found", IssuedAt: at, ExpiresAt: at + 120}},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r1, at, session, "")}, Expect: claimed("created")},
		issuanceStepJSON{Op: "present", At: at + 6, Bundles: []string{present(agent, r1, at, session, "")}, Expect: claimed("in_progress")},
	)
	add("crash_after_commit_before_exposure", "the store committed but the issuer failed before returning: no challenge is exposed; the orphan record is harmless and the next issuance draws fresh bytes", [][]byte{r1, r2},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), PersistFault: "fail_after_commit", Expect: issuanceExpectJSON{Result: "error", RecordsAfter: intp(1)}},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issued(r2, at, 120, 2)},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r2, at, session, "")}, Expect: claimed("created")},
	)
	add("crash_before_commit", "persistence failed before commit: no challenge is exposed and nothing is retrievable", [][]byte{r1},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), PersistFault: "fail_before_commit", Expect: issuanceExpectJSON{Result: "error", RecordsAfter: intp(0)}},
		issuanceStepJSON{Op: "load", ChallengeB64: b64(r1), Expect: issuanceExpectJSON{Result: "expected_challenge_unavailable"}},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r1, at, session, "")}, Expect: preflight("expected_challenge_unavailable")},
	)
	add("duplicate_issuance_never_overwrites", "a repeated random value conflicts with the stored record; the issuer draws again and the first record keeps its original times", [][]byte{r1, r1, r2},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issued(r1, at, 120, 1)},
		issuanceStepJSON{Op: "issue", At: at + 3, Request: request(60, true, session), Expect: issued(r2, at+3, 60, 2)},
		issuanceStepJSON{Op: "load", ChallengeB64: b64(r1), Expect: issuanceExpectJSON{Result: "found", IssuedAt: at, ExpiresAt: at + 120}},
	)
	add("random_source_repeats", "three consecutive key conflicts fail issuance instead of looping or overwriting", [][]byte{r1, r1, r1, r1},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issued(r1, at, 120, 1)},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issuanceExpectJSON{Result: "error", RecordsAfter: intp(1)}},
	)
	add("invalid_request", "an issuance request outside its bounds is configuration_invalid and draws no randomness", [][]byte{r1},
		issuanceStepJSON{Op: "issue", At: at, Request: request(301, true, session), Expect: issuanceExpectJSON{Result: "error", ErrorClass: "configuration_invalid", RecordsAfter: intp(0)}},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session[:31]), Expect: issuanceExpectJSON{Result: "error", ErrorClass: "configuration_invalid", RecordsAfter: intp(0)}},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issued(r1, at, 120, 1)},
	)
	add("wrong_binding", "the record's authenticated bindings are enforced before claim; no rejected presentation consumes the challenge", [][]byte{r1},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, session), Expect: issued(r1, at, 120, 1)},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(attacker, r1, at, session, "")}, Expect: preflight("expected_agent_mismatch")},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r1, at, bytes.Repeat([]byte{0x44}, 32), "")}, Expect: preflight("session_context_mismatch")},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r1, at, session, attacker.ID)}, Expect: preflight("verifier_id_mismatch")},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r1, at+1, session, "")}, Expect: preflight("challenge_mismatch")},
		issuanceStepJSON{Op: "present", At: at + 5, Bundles: []string{present(agent, r3, at, session, "")}, Expect: preflight("expected_challenge_unavailable")},
		issuanceStepJSON{Op: "present", At: at + 6, Bundles: []string{present(agent, r1, at, session, "")}, Expect: claimed("created")},
	)
	add("expiry", "a challenge is fresh only while now < expires_at", [][]byte{r1, r2},
		issuanceStepJSON{Op: "issue", At: at, Request: request(30, true, session), Expect: issued(r1, at, 30, 1)},
		issuanceStepJSON{Op: "present", At: at + 30, Bundles: []string{present(agent, r1, at, session, "")}, Expect: preflight("challenge_not_fresh")},
		issuanceStepJSON{Op: "issue", At: at + 31, Request: request(30, true, session), Expect: issued(r2, at+31, 30, 2)},
		issuanceStepJSON{Op: "present", At: at + 60, Bundles: []string{present(agent, r2, at+31, session, "")}, Expect: claimed("created")},
	)
	end := maxTimestampV2 - 300
	add("expiry_at_timestamp_domain_end", "issued_at + lifetime is computed with checked arithmetic (SPEC-v2 §2.5): a 300-second challenge issued at 253402300499 expires exactly at 253402300799 and still claims; one issued a second later would expire outside the timestamp domain and is configuration_invalid before any randomness is drawn", [][]byte{r1, r2},
		issuanceStepJSON{Op: "issue", At: end, Request: request(300, true, session), Expect: issued(r1, end, 300, 1)},
		issuanceStepJSON{Op: "issue", At: end + 1, Request: request(300, true, session), Expect: issuanceExpectJSON{Result: "error", ErrorClass: "configuration_invalid", RecordsAfter: intp(1)}},
		issuanceStepJSON{Op: "present", At: maxTimestampV2 - 1, Bundles: []string{present(agent, r1, end, session, "")}, Expect: claimed("created")},
	)
	add("concurrent_claims", "concurrent presentations of one issued challenge: exactly one creates the claim; an identical proof is an in-progress retry and a different proof is a conflict", [][]byte{r1, r2},
		issuanceStepJSON{Op: "issue", At: at, Request: request(120, true, nil), Expect: issued(r1, at, 120, 1)},
		issuanceStepJSON{Op: "present_concurrent", At: at + 5, Bundles: []string{present(agent, r1, at, nil, ""), present(agent, r1, at, nil, ""), present(agent, r1, at, nil, "")},
			Expect: issuanceExpectJSON{Result: "claimed", Dispositions: []string{"created", "in_progress", "in_progress"}}},
		issuanceStepJSON{Op: "issue", At: at + 6, Request: request(120, true, nil), Expect: issued(r2, at+6, 120, 2)},
		issuanceStepJSON{Op: "present_concurrent", At: at + 7, Bundles: []string{present(agent, r2, at+6, nil, ""), present(agent, r2, at+6, session, "")},
			Expect: issuanceExpectJSON{Result: "claimed", Dispositions: []string{"created", "proof_conflict"}}},
	)
	return f
}
