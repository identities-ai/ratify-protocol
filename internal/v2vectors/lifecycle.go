package v2vectors

// Part B lifecycle scenarios (SPEC-v2 §6.9, §7.2-§7.11). Each scenario is a
// script replayed against an SDK's own in-memory reference store (claim
// store with stream sequence, authoritative clock, receipt publisher and
// independent checkpoint). Expected outcomes are written from the spec rules
// here, not read back from the Go reference.

const (
	lifecycleLogID        = "dddddddddddddddddddddddddddddd01"
	lifecycleLeaseSeconds = 30
)

type lifecycleExpectJSON struct {
	Stage          string `json:"stage,omitempty"`
	ErrorClass     string `json:"error_class,omitempty"`
	Disposition    string `json:"disposition,omitempty"`
	Decision       string `json:"decision,omitempty"`
	DecisionReason string `json:"decision_reason,omitempty"`
	ReleaseStatus  string `json:"release_status,omitempty"`
	ReleaseReason  string `json:"release_reason,omitempty"`
	ReleaseTime    int64  `json:"release_time,omitempty"`
	AllowHorizon   int64  `json:"allow_horizon,omitempty"`
	ReceiptSeq     int64  `json:"receipt_sequence,omitempty"`
	Failed         bool   `json:"failed,omitempty"`
}

type lifecycleStepJSON struct {
	Op         string              `json:"op"`
	Request    string              `json:"request,omitempty"`
	Time       int64               `json:"time,omitempty"`
	Withheld   *bool               `json:"withheld,omitempty"`
	Mode       string              `json:"mode,omitempty"`
	ReceiptOf  string              `json:"receipt_of,omitempty"`
	Checkpoint string              `json:"checkpoint,omitempty"`
	Expect     lifecycleExpectJSON `json:"expect"`
}

type lifecycleScenarioJSON struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	StartTime   int64               `json:"start_time"`
	Steps       []lifecycleStepJSON `json:"steps"`
}

type lifecycleFile struct {
	Version      int                       `json:"version"`
	Description  string                    `json:"description"`
	Semantics    map[string]string         `json:"semantics"`
	VerifierKey  string                    `json:"verifier_key"`
	LogID        string                    `json:"log_id"`
	LeaseSeconds int64                     `json:"lease_seconds"`
	Bundles      map[string]string         `json:"bundles_b64"`
	Requests     map[string]orderingVector `json:"requests"`
	Scenarios    []lifecycleScenarioJSON   `json:"scenarios"`
}

func (g *gen) lifecycleRequest(challengeByte byte, streamSeq int64, edit func(*scenario)) (orderingVector, []byte) {
	agent := g.k("agent")
	certs := g.chain(chainSpec{})
	session := g.fixtureSessionContext(agent)
	challenge := defaultChallenge()
	challenge[0] = challengeByte
	spec := bundleSpec{agent: agent, certs: certs, session: session, challenge: challenge}
	if streamSeq > 0 {
		spec.streamID = make([]byte, 32)
		for i := range spec.streamID {
			spec.streamID[i] = 0x5a
		}
		spec.streamSeq = streamSeq
	}
	_, bundle, _ := g.bundle(spec)
	expected := g.defaultExpected(agent, session)
	expected.ValueB64 = b64(challenge)
	s := scenario{bundle: bundle, certs: certs, scope: "data:read", expected: expected, policy: g.verifyPolicyJSON(session),
		trust: g.trustRoot("root"), evidence: g.currentEvidenceBatches(certs), claim: "reference", out: outcomeJSON{Stage: "lifecycle"}}
	if edit != nil {
		edit(&s)
	}
	v := g.finish(s)
	v.Expected = outcomeJSON{}
	return v, s.bundle
}

func ls(op string, expect lifecycleExpectJSON) lifecycleStepJSON {
	return lifecycleStepJSON{Op: op, Expect: expect}
}

func (g *gen) lifecycleFile() any {
	st := g.statusFixtures()
	f := lifecycleFile{
		Version:     2,
		Description: "Part B lifecycle scenarios (SPEC-v2 §6.9, §7). Replay each scenario against a fresh in-memory reference store whose authoritative clock starts at start_time, whose evaluator lease is lease_seconds, and whose receipt log log_id is signed by verifier_key. Requests use the verifier-ordering input schema; the request's now is always the store clock at the step.",
		Semantics: map[string]string{
			"set_time":               "set the authoritative clock (it may move backward to exercise clock regression)",
			"set_ack_withheld":       "withheld=true stops the reference outbox from submitting appended entries to the checkpoint; withheld=false submits every pending entry in log order at the current clock",
			"verify":                 "VerifyProofBundleV2 against the store; expect stage, error_class, disposition; for committed, decision/decision_reason are read from the committed receipt body for the test only, and allow_horizon is the handoff value",
			"claim_only":             "preflight and claim without evaluating (an evaluator that crashed after claiming); expect disposition or error_class",
			"recover":                "RecoverInterruptedClaim with the claim's authoritative claim time; expect stage committed (idempotent for the same body) or error_class",
			"publish":                "drain the outbox for the request's committed outcome. mode ok = reference publisher; signer_failure = the publisher fails and appends nothing (failed=true); corrupt_signature = the published receipt with one Ed25519 signature byte flipped. Expect receipt_sequence",
			"release":                "ReleaseV2Decision with the request's committed outcome and its last published receipt (none when not published, or receipt_of another request). checkpoint reference = the store checkpoint; wrong_entry = acknowledgements report a different entry hash. Expect release_status, release_reason, decision, release_time",
			"release_forged":         "ReleaseV2Decision with a committed outcome that was never produced by the verifier (zero value); always rejected",
			"verifier_configuration": "status keys, status policy, trust, journal setup and evidence come from each request exactly as in verifier-ordering.json",
		},
		VerifierKey: "verifier", LogID: lifecycleLogID, LeaseSeconds: lifecycleLeaseSeconds,
		Bundles: map[string]string{}, Requests: map[string]orderingVector{},
	}
	add := func(name string, v orderingVector, bundle []byte) {
		f.Requests[name] = v
		f.Bundles[v.Bundle] = b64(bundle)
	}
	for _, r := range []struct {
		name      string
		challenge byte
		edit      func(*scenario)
	}{
		{"A", 0xa0, nil}, {"B", 0xb0, nil},
		{"H", 0xc0, func(s *scenario) { s.evidence[g.k("root").ID] = evidenceBatch(g.object(st["root_next_plus_one"])) }},
	} {
		v, bundle := g.lifecycleRequest(r.challenge, 0, r.edit)
		add(r.name, v, bundle)
	}
	// Stream requests share stream_id 0x5a..; S1x reuses S1's challenge with a
	// different proof (stream_seq 2), so it collides with S1's claim.
	for _, r := range []struct {
		name      string
		challenge byte
		seq       int64
	}{{"S1", 0x11, 1}, {"S1b", 0x12, 1}, {"S1x", 0x11, 2}, {"S2", 0x21, 2}, {"S2b", 0x22, 2}, {"S4", 0x41, 4}} {
		v, bundle := g.lifecycleRequest(r.challenge, r.seq, nil)
		add(r.name, v, bundle)
	}

	committedAllow := lifecycleExpectJSON{Stage: "committed", Decision: "allow", DecisionReason: "authorized", AllowHorizon: statusFreshUntil}
	released := func(t, seq int64) lifecycleExpectJSON {
		return lifecycleExpectJSON{ReleaseStatus: "released", Decision: "allow", ReleaseTime: t, ReceiptSeq: seq}
	}
	step := func(op, request string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: op, Request: request, Expect: expect}
	}
	setTime := func(t int64) lifecycleStepJSON { return lifecycleStepJSON{Op: "set_time", Time: t} }
	withhold := func(w bool) lifecycleStepJSON { return lifecycleStepJSON{Op: "set_ack_withheld", Withheld: &w} }
	publish := func(request, mode string, seq int64) lifecycleStepJSON {
		e := lifecycleExpectJSON{ReceiptSeq: seq}
		if mode == "signer_failure" {
			e = lifecycleExpectJSON{Failed: true}
		}
		return lifecycleStepJSON{Op: "publish", Request: request, Mode: mode, Expect: e}
	}
	release := func(request string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "release", Request: request, Checkpoint: "reference", Expect: expect}
	}
	sc := func(name, desc string, steps ...lifecycleStepJSON) {
		f.Scenarios = append(f.Scenarios, lifecycleScenarioJSON{Name: name, Description: desc, StartTime: Now, Steps: steps})
	}

	sc("allow_published_acknowledged_released", "verify commits a non-actionable allow; publication and acknowledgement release it; a second release is idempotent and appends nothing",
		step("verify", "A", committedAllow), publish("A", "ok", 1), release("A", released(Now, 1)), publish("A", "ok", 1), release("A", released(Now, 1)),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}))
	sc("release_without_receipt_is_pending", "a committed allow without a published receipt is pending, never released (Part A to Part B downgrade attempt)",
		step("verify", "A", committedAllow), release("A", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "receipt_not_appended"}))
	sc("release_without_acknowledgement_is_pending_then_late_ack_releases", "an appended but unacknowledged receipt is pending; a late acknowledgement before every deadline releases it at the acknowledgement time",
		withhold(true), step("verify", "A", committedAllow), publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "acknowledgement_unavailable"}),
		setTime(Now+100), withhold(false), release("A", released(Now+100, 1)))
	sc("late_ack_at_challenge_expiry_is_withheld", "an acknowledgement timestamped at the challenge expiry can never release (exclusive deadline)",
		withhold(true), step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+290), withhold(false),
		release("A", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "challenge_expired"}))
	sc("release_one_second_before_challenge_expiry", "release at expires_at - 1 succeeds",
		step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+289), release("A", released(Now, 1)))
	sc("release_at_challenge_expiry_is_withheld", "release at exactly expires_at is withheld even with an earlier acknowledgement",
		step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+290), release("A", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "challenge_expired"}))
	sc("release_at_allow_horizon_is_withheld", "an allow whose status horizon is Now+1 is withheld when released at exactly Now+1",
		step("verify", "H", lifecycleExpectJSON{Stage: "committed", Decision: "allow", DecisionReason: "authorized", AllowHorizon: Now + 1}),
		publish("H", "ok", 1), setTime(Now+1), release("H", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "allow_horizon_passed"}))
	sc("release_before_allow_horizon", "the same allow released at Now, before its Now+1 horizon, is released",
		step("verify", "H", lifecycleExpectJSON{Stage: "committed", Decision: "allow", DecisionReason: "authorized", AllowHorizon: Now + 1}),
		publish("H", "ok", 1), release("H", released(Now, 1)))
	sc("signer_failure_then_retry", "a publisher (signer) failure appends nothing and release stays pending; a retry publishes and releases",
		step("verify", "A", committedAllow), publish("A", "signer_failure", 0), release("A", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "receipt_not_appended"}),
		publish("A", "ok", 1), release("A", released(Now, 1)))
	sc("corrupt_receipt_signature_is_rejected", "a published receipt whose signature does not verify under the configured verifier key is rejected",
		step("verify", "A", committedAllow), lifecycleStepJSON{Op: "publish", Request: "A", Mode: "corrupt_signature", Expect: lifecycleExpectJSON{ReceiptSeq: 1}},
		release("A", lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "receipt_invalid"}))
	sc("receipt_of_another_claim_is_rejected", "a valid receipt for a different committed claim does not bind this claim's body",
		step("verify", "A", committedAllow), step("verify", "B", committedAllow), publish("A", "ok", 1), publish("B", "ok", 2),
		lifecycleStepJSON{Op: "release", Request: "A", ReceiptOf: "B", Checkpoint: "reference", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "receipt_body_mismatch"}},
		release("B", released(Now, 2)))
	sc("acknowledgement_for_another_entry_is_rejected", "an acknowledgement whose entry hash differs from the verified receipt is a fork signal and is rejected",
		step("verify", "A", committedAllow), publish("A", "ok", 1),
		lifecycleStepJSON{Op: "release", Request: "A", Checkpoint: "wrong_entry", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "acknowledgement_mismatch"}})
	sc("forged_committed_outcome_is_rejected", "an application cannot release a committed outcome the verifier did not produce",
		ls("release_forged", lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "release_state_mismatch"}))
	sc("clock_regression_at_release_is_withheld", "a release reading earlier than the acknowledgement time is a clock regression",
		step("verify", "A", committedAllow), setTime(Now+5), publish("A", "ok", 1), setTime(Now+3),
		release("A", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "clock_regressed"}))
	sc("crash_after_claim_lease_recovery", "an evaluator that crashes after claiming leaves the claim in progress; recovery is refused while the lease is live, then commits evaluation_interrupted, which publishes and releases as a non-actionable indeterminate; recovery is idempotent",
		step("claim_only", "A", lifecycleExpectJSON{Disposition: "created"}),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "in_progress"}),
		step("recover", "A", lifecycleExpectJSON{ErrorClass: "claim_lease_live"}),
		setTime(Now+lifecycleLeaseSeconds),
		step("recover", "A", lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted"}),
		step("recover", "A", lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted"}),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}),
		publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now + lifecycleLeaseSeconds, ReceiptSeq: 1}))
	sc("different_proof_for_claimed_challenge_is_replay", "a second, different proof for an already claimed challenge is rejected before claim without disclosure and does not advance the stream",
		step("verify", "S1", committedAllow), step("verify", "S1x", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "claim_replay"}),
		step("verify", "S2", committedAllow))
	sc("stream_sequence_rules", "first sequence must be 1; exact retries replay without advancing; duplicates, gaps and reorders fail before claim with stream_sequence_mismatch; of two claims with the same sequence exactly one commits",
		step("verify", "S2", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stream_sequence_mismatch"}),
		step("verify", "S1", committedAllow),
		step("verify", "S1", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}),
		step("verify", "S4", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stream_sequence_mismatch"}),
		step("verify", "S2", committedAllow),
		step("verify", "S2b", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stream_sequence_mismatch"}),
		step("verify", "S1b", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stream_sequence_mismatch"}))
	return f
}
