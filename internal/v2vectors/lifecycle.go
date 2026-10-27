package v2vectors

// Part B lifecycle scenarios (SPEC-v2 §6.9, §7.2-§7.11). Each scenario is a
// script replayed against an SDK's own in-memory reference store (claim
// store with stream sequence, authoritative clock, receipt publisher and
// independent checkpoint). Expected outcomes are written from the spec rules
// here, not read back from the Go reference.

import (
	"bytes"
	"slices"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

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
	PublishError   string `json:"publish_error,omitempty"`
	// Committed receipt assessments, checked when present.
	TrustAssessment   string `json:"trust_assessment,omitempty"`
	StatusAssessment  string `json:"status_assessment,omitempty"`
	ContextAssessment string `json:"context_assessment,omitempty"`
	// Abandoned lists the requests whose claims an abandon step marks.
	Abandoned []string `json:"abandoned,omitempty"`
	// Recovered is the expected recovery run by a recover_during_status step.
	Recovered *lifecycleExpectJSON `json:"recovered,omitempty"`
	// Outcomes is the sorted multiset of verify_concurrent results.
	Outcomes []string `json:"outcomes,omitempty"`
	// FinalizeResult is the outcome of a successful finalize step:
	// "committed" (the store committed the result) or "identical" (the same
	// result was already committed).
	FinalizeResult string `json:"finalize_result,omitempty"`
	// AckTimestamp is the timestamp of the acknowledgement an acknowledge
	// step returns.
	AckTimestamp int64 `json:"ack_timestamp,omitempty"`
}

type lifecycleStepJSON struct {
	Op          string   `json:"op"`
	Request     string   `json:"request,omitempty"`
	Requests    []string `json:"requests,omitempty"`
	Time        int64    `json:"time,omitempty"`
	Withheld    *bool    `json:"withheld,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	ReceiptOf   string   `json:"receipt_of,omitempty"`
	Checkpoint  string   `json:"checkpoint,omitempty"`
	ReplayEpoch int64    `json:"replay_epoch,omitempty"`
	LogID       string   `json:"log_id,omitempty"`
	// TerminalB64, BodyB64 and AllowValidUntil are the exact arguments of a
	// finalize step.
	// TerminalB64 and BodyB64 are also the exact arguments of a
	// recover_direct step.
	TerminalB64     string `json:"terminal_b64,omitempty"`
	BodyB64         string `json:"body_b64,omitempty"`
	AllowValidUntil int64  `json:"allow_valid_until,omitempty"`
	// ClaimRecordB64, with TerminalB64, BodyB64 and AllowValidUntil, is the
	// committed record a resume step's claim store answers with, and ClaimID
	// the claim ID that step requests.
	ClaimRecordB64 string              `json:"claim_record_b64,omitempty"`
	ClaimID        string              `json:"claim_id,omitempty"`
	Expect         lifecycleExpectJSON `json:"expect"`
}

type lifecycleScenarioJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	StartTime   int64  `json:"start_time"`
	// RateAtFinalization selects the reference store's max_rate admission
	// inside the finalization compare-and-set as both claim and rate store.
	RateAtFinalization bool                `json:"rate_at_finalization,omitempty"`
	Steps              []lifecycleStepJSON `json:"steps"`
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
	// ProfileScenarios are the Part B profile scripts (profiles.go).
	ProfileScenarios []profileScenarioJSON `json:"profile_scenarios"`
}

func (g *gen) lifecycleRequest(challengeByte byte, streamSeq int64, edit func(*scenario)) (orderingVector, []byte) {
	return g.lifecycleRequestWithChain(challengeByte, streamSeq, g.chain(chainSpec{}), edit)
}

func (g *gen) lifecycleRequestWithChain(challengeByte byte, streamSeq int64, certs []ratify.DelegationCertV2, edit func(*scenario)) (orderingVector, []byte) {
	agent := g.k("agent")
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
			"set_time":               "set the authoritative clock (it may move backward to exercise clock regression). The store keeps a high-water mark of every authoritative reading, including the checkpoint's acknowledgement timestamps, and a reading below it is a reported clock regression",
			"set_ack_withheld":       "withheld=true stops the reference outbox from submitting appended entries to the checkpoint; withheld=false submits every pending entry in log order at the current clock",
			"verify":                 "VerifyProofBundleV2 against the store; expect stage, error_class, disposition; for committed, decision/decision_reason are read from the committed receipt body for the test only, and allow_horizon is the handoff value",
			"claim_only":             "preflight and claim without evaluating (an evaluator that crashed after claiming); expect disposition or error_class. The harness keeps the evaluator owner token the claim store returned for a later finalize step",
			"acknowledge":            "submit the request's last published receipt to the reference checkpoint directly as Acknowledge(log_id, sequence, previous_receipt_hash, entry_hash). mode exact = the receipt's own entry hash; fork = the same tuple with the first entry-hash byte flipped. Expect ack_timestamp, or failed=true when the checkpoint refuses. A different entry hash at an acknowledged sequence is a fork: the checkpoint freezes the log and acknowledges nothing further for it, including the publisher's own submissions (SPEC-v2 §7.8)",
			"finalize":               "call the claim store's finalize operation directly for the request's claim with the owner token from its claim_only step, terminal_b64 as the terminal result, body_b64 as the receipt outbox body and allow_valid_until (0 unless an allow); expect finalize_result committed (true) or identical (false, the same result already committed), or error_class. The store binds the body to the sealed claim (SPEC-v2 §7.5): a refused finalize commits nothing",
			"recover_direct":         "call the claim store's recovery operation directly for the request's claim (from its claim_only step) with terminal_b64 as the terminal result and body_b64 as the receipt outbox body, after the evaluator lease expired; expect finalize_result committed (true) or identical (false, the same result already committed), or error_class. The store validates the result and body exactly as finalize does (SPEC-v2 §7.5: malformed for a body that is not a canonical receipt body, configuration_invalid for a body that does not bind the sealed claim or a result that differs from it) and accepts only indeterminate/evaluation_interrupted (configuration_invalid otherwise): a refused recovery commits nothing",
			"resume":                 "ResumeCommittedClaim for the request's claim ID (computed as for recover), or for claim_id when present: the store returns the claim's persisted terminal record and the implementation returns its committed handoff, which replaces any handoff the harness holds for the request, so later publish and release steps use it (SPEC-v2 §7.11). Expect stage committed with decision, decision_reason and allow_horizon (0 when absent), or error_class: claim_not_found for a claim the store does not hold, claim_lease_live for a claim still evaluating under a live lease, claim_lease_lost for one still evaluating after its lease expired, claim_store_unavailable for a record that fails the terminal compare-and-set's checks. With claim_record_b64 the claim store's committed-claim load answers, for any claim ID, with the record whose sealed claim is claim_record_b64 (the canonical sealed claim object of SPEC-v2 §7.13 claim records, which a store whose interface carries the sealed claim decodes into it), whose terminal result is terminal_b64, receipt outbox body body_b64 and allow horizon allow_valid_until (0 when absent); every other store operation is the reference store's. With mode record_bytes the record bytes are not the canonical encoding of the sealed claim they decode to: only an implementation whose store returns the record bytes (the C ABI) runs the step, and other implementations skip it",
			"recover":                "RecoverInterruptedClaim for the request's claim ID (ProtocolClaimID of the request's verifier namespace, replay epoch and challenge, whether or not it was ever claimed): the store returns the sealed claim, T_claim and the last recorded evaluation progress (refusing while the lease is live), and the evaluation_interrupted receipt reports that progress per dimension; expect stage committed (idempotent for the same body) with its assessments, or error_class",
			"verify modes":           "verify with mode expire_lease_during_status sets the store clock to time when the status provider is first called (the evaluator lease expires mid-lookup); recover_during_status additionally runs recover for the same claim there and checks expect.recovered (the late evaluator is then fenced); regress_clock_during_status sets the clock to time (below T_claim) there; cancel_before_claim calls verify with the caller's cancellation already signalled, so the verifier stops before the claim and nothing is consumed; cancel_during_status signals the caller's cancellation when the status provider is first called and the provider then reports that cancellation as its result (SPEC-v2 §6.11)",
			"verify_concurrent":      "run verify for every request in requests concurrently against the store at the current clock, each with its own callbacks; expect.outcomes is the sorted multiset of results, each the stage alone for committed and replay, or stage/error_class for preflight and evaluating",
			"publish":                "drain the outbox for the request's committed outcome; the reference store assigns each receipt-log position at terminal commit, in commit order. mode ok = reference publisher; signer_failure = the signer fails for this call and appends nothing; corrupt_signature = the published receipt with one Ed25519 signature byte flipped. Expect receipt_sequence, or failed=true with publish_error head_of_line_blocked (an earlier entry is unpublished), signer_unavailable, or log_frozen",
			"abandon":                "the receipt-abandonment procedure: freeze the receipt log and mark every claim whose outbox entry was not appended receipt_abandoned; expect abandoned (request names in log order)",
			"restore":                "mode exact = continue on an exact copy of the complete store state (restore equal to the anchored head, no epoch change); mode lost_state_epoch_bump = continue on an empty store with receipt log log_id, and the verifier's configured replay epoch becomes replay_epoch for every later verify",
			"rate_at_finalization":   "scenario flag: the reference store admits the sealed max_rate batch inside the finalization compare-and-set and is used as both claim store and rate store. This is the single-store max_rate implementation of SPEC-v2 §7.6: an allow is counted at T_final in the same transaction that commits it, all counters of the sealed batch or none, and every other terminal result, including recovery's evaluation_interrupted, counts nothing",
			"release":                "ReleaseV2Decision with the request's committed outcome and its last published receipt (none when not published or when mode is no_receipt, or receipt_of another request). mode record_release_unavailable = the claim store's record-release operation fails with store unavailability for this call only and records nothing; record_release_state_mismatch = it answers release_state_mismatch (a different record exists) for this call only and records nothing. checkpoint reference = the store checkpoint; wrong_entry = acknowledgements report a different entry hash. Expect release_status, release_reason, decision, release_time. A withheld result at release steps 7 or 8 is recorded in the claim store when no release is recorded yet, and every later release of that claim returns the recorded withheld result right after step 1; rejected describes only that call (SPEC-v2 §6.9)",
			"release_forged":         "ReleaseV2Decision with a committed outcome that was never produced by the verifier (zero value); always rejected",
			"plant_release":          "write a release record for the request's claim directly into the claim store, bypassing ReleaseV2Decision: it names the claim's appended receipt entry hash and the acknowledgement timestamp time (a primary-storage write). A recorded release never replaces the acknowledgement (SPEC-v2 §6.9 steps 4 to 6)",
			"verifier_configuration": "status keys, status policy, trust, journal setup and evidence come from each request exactly as in verifier-ordering.json",
		},
		VerifierKey: "verifier", LogID: lifecycleLogID, LeaseSeconds: lifecycleLeaseSeconds,
		Bundles: map[string]string{}, Requests: map[string]orderingVector{},
	}
	add := func(name string, v orderingVector, bundle []byte) {
		f.Requests[name] = v
		f.Bundles[v.Bundle] = b64(bundle)
	}
	nextEpoch := func(s *scenario) {
		s.epoch = fixtureReplayEpoch + 1
		s.expected.ReplayEpoch = fixtureReplayEpoch + 1
	}
	bundles := map[string][]byte{}
	for _, r := range []struct {
		name      string
		challenge byte
		edit      func(*scenario)
	}{
		{"A", 0xa0, nil}, {"B", 0xb0, nil}, {"E2", 0xe2, nextEpoch},
		{"H", 0xc0, func(s *scenario) { s.evidence[g.k("root").ID] = evidenceBatch(g.object(st["root_next_plus_one"])) }},
	} {
		v, bundle := g.lifecycleRequest(r.challenge, 0, r.edit)
		add(r.name, v, bundle)
		bundles[r.name] = bundle
	}
	// Rate requests: a leaf max_rate of 2 per 60 seconds.
	rateChain := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxRate, Count: 2, WindowS: 60}}})
	for i, name := range []string{"R1", "R2", "R3", "R4"} {
		v, bundle := g.lifecycleRequestWithChain(byte(0x71+i), 0, rateChain, nil)
		add(name, v, bundle)
	}
	// R1x reuses R1's challenge with a chain whose signed rate batch differs
	// (3 per 60 seconds), so its claim collides with R1's sealed batch. RI has
	// R1's chain and no trust configuration (indeterminate/trust_unavailable).
	{
		otherRateChain := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{{Type: ratify.ConstraintMaxRate, Count: 3, WindowS: 60}}})
		v, bundle := g.lifecycleRequestWithChain(0x71, 0, otherRateChain, nil)
		add("R1x", v, bundle)
		v, bundle = g.lifecycleRequestWithChain(0x79, 0, rateChain, func(s *scenario) { s.trust = nil })
		add("RI", v, bundle)
	}
	// Two-counter requests: one leaf certificate signs 2 per 120 seconds and
	// 1 per 60 seconds, so its sealed batch has two counters.
	twoCounterChain := g.chain(chainSpec{leafCons: []ratify.ConstraintV2{
		{Type: ratify.ConstraintMaxRate, Count: 2, WindowS: 120}, {Type: ratify.ConstraintMaxRate, Count: 1, WindowS: 60}}})
	for i, name := range []string{"T1", "T2", "T3"} {
		v, bundle := g.lifecycleRequestWithChain(byte(0x81+i), 0, twoCounterChain, nil)
		add(name, v, bundle)
	}
	// Stream requests share stream_id 0x5a..; S1x reuses S1's challenge with a
	// different proof (stream_seq 2), so it collides with S1's claim.
	for _, r := range []struct {
		name      string
		challenge byte
		seq       int64
	}{{"S1", 0x11, 1}, {"S1b", 0x12, 1}, {"S1x", 0x11, 2}, {"S2", 0x21, 2}, {"S2b", 0x22, 2}, {"S3", 0x31, 3}, {"S4", 0x41, 4}} {
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
			e = lifecycleExpectJSON{Failed: true, PublishError: "signer_unavailable"}
		}
		return lifecycleStepJSON{Op: "publish", Request: request, Mode: mode, Expect: e}
	}
	publishFails := func(request, reason string) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "publish", Request: request, Mode: "ok", Expect: lifecycleExpectJSON{Failed: true, PublishError: reason}}
	}
	interrupted := func(trust, status, context string) lifecycleExpectJSON {
		return lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted", TrustAssessment: trust, StatusAssessment: status, ContextAssessment: context}
	}
	verifyMode := func(request, mode string, t int64, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "verify", Request: request, Mode: mode, Time: t, Expect: expect}
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
	sc("corrupt_receipt_signature_is_rejected", "a published receipt whose signature does not verify under the configured verifier key is rejected; rejected describes only that call's inputs, so the genuine receipt then releases (SPEC-v2 §6.9)",
		step("verify", "A", committedAllow), lifecycleStepJSON{Op: "publish", Request: "A", Mode: "corrupt_signature", Expect: lifecycleExpectJSON{ReceiptSeq: 1}},
		release("A", lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "receipt_invalid"}),
		publish("A", "ok", 1), release("A", released(Now, 1)))
	sc("receipt_of_another_claim_is_rejected", "a valid receipt for a different committed claim does not bind this claim's body; the rejection is per call, so this claim's own receipt then releases",
		step("verify", "A", committedAllow), step("verify", "B", committedAllow), publish("A", "ok", 1), publish("B", "ok", 2),
		lifecycleStepJSON{Op: "release", Request: "A", ReceiptOf: "B", Checkpoint: "reference", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "receipt_body_mismatch"}},
		release("B", released(Now, 2)), release("A", released(Now, 1)))
	sc("acknowledgement_for_another_entry_is_rejected", "an acknowledgement whose entry hash differs from the verified receipt is a fork signal and is rejected; the rejection records nothing for the claim, so a call through the genuine checkpoint releases",
		step("verify", "A", committedAllow), publish("A", "ok", 1),
		lifecycleStepJSON{Op: "release", Request: "A", Checkpoint: "wrong_entry", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "acknowledgement_mismatch"}},
		release("A", released(Now, 1)))
	sc("planted_release_record_does_not_replace_acknowledgement", "a release record written into the claim store with the appended receipt's entry hash and a plausible acknowledgement time is not evidence of acknowledgement: release stays pending while the entry is unacknowledged, and once acknowledged at a different time the planted record is a release_state_mismatch",
		withhold(true), step("verify", "A", committedAllow), publish("A", "ok", 1),
		lifecycleStepJSON{Op: "plant_release", Request: "A", Time: Now},
		release("A", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "acknowledgement_unavailable"}),
		setTime(Now+100), withhold(false), release("A", lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "release_state_mismatch"}))
	sc("repeated_release_reverifies_acknowledgement", "a repeated release of an already released claim obtains the acknowledgement again: an acknowledgement for a different entry is rejected rather than answered from the release record",
		step("verify", "A", committedAllow), publish("A", "ok", 1), release("A", released(Now, 1)),
		lifecycleStepJSON{Op: "release", Request: "A", Checkpoint: "wrong_entry", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "acknowledgement_mismatch"}},
		release("A", released(Now, 1)))
	sc("forged_committed_outcome_is_rejected", "an application cannot release a committed outcome the verifier did not produce",
		ls("release_forged", lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "release_state_mismatch"}))
	withheldRegressed := lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "clock_regressed"}
	sc("clock_regression_at_release_is_withheld", "a release reading earlier than the acknowledgement time is a clock regression; the withheld result is recorded and is permanent, so a later release after the clock passes the acknowledgement time is still withheld (SPEC-v2 §6.9)",
		step("verify", "A", committedAllow), setTime(Now+5), publish("A", "ok", 1), setTime(Now+3),
		release("A", withheldRegressed), setTime(Now+6), release("A", withheldRegressed))
	expired := lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "challenge_expired"}
	sc("recorded_withheld_answers_before_receipt_checks", "once a withheld result is recorded, every later release of the claim returns it right after the committed-state step: without a receipt it is withheld rather than pending, and with a mismatched acknowledgement it is withheld rather than rejected",
		step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+290),
		release("A", expired),
		lifecycleStepJSON{Op: "release", Request: "A", Mode: "no_receipt", Checkpoint: "reference", Expect: expired},
		lifecycleStepJSON{Op: "release", Request: "A", Checkpoint: "wrong_entry", Expect: expired},
		release("A", expired))
	noReceipt := func(expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "release", Request: "A", Mode: "no_receipt", Checkpoint: "reference", Expect: expect}
	}
	notAppended := lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "receipt_not_appended"}
	sc("withheld_when_recording_fails", "a withheld result whose recording fails with store unavailability is still withheld for that call, and nothing is recorded: a release without a receipt is then pending; the next release records the withheld result, which every later release returns",
		step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+290),
		lifecycleStepJSON{Op: "release", Request: "A", Mode: "record_release_unavailable", Checkpoint: "reference", Expect: expired},
		noReceipt(notAppended),
		release("A", expired),
		noReceipt(expired))
	sc("withheld_record_conflict_is_rejected", "a claim store that answers the withheld record with a state mismatch (a different record already exists) makes that call rejected / release_state_mismatch, which describes only that call and records nothing; the next release records the withheld result",
		step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+290),
		lifecycleStepJSON{Op: "release", Request: "A", Mode: "record_release_state_mismatch", Checkpoint: "reference", Expect: lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "release_state_mismatch"}},
		noReceipt(notAppended),
		release("A", expired),
		noReceipt(expired))
	sc("withheld_after_recorded_release_records_nothing", "a release record already present is the first record and wins: a later call whose clock reading regressed is withheld for that call only, and a call with a current clock returns the recorded release again",
		step("verify", "A", committedAllow), publish("A", "ok", 1), setTime(Now+10), release("A", released(Now, 1)),
		setTime(Now+8), release("A", withheldRegressed),
		setTime(Now+11), release("A", released(Now, 1)))
	sc("crash_after_claim_lease_recovery", "an evaluator that crashes after claiming leaves the claim in progress; recovery is refused while the lease is live, then commits evaluation_interrupted, which publishes and releases as a non-actionable indeterminate; recovery is idempotent",
		step("claim_only", "A", lifecycleExpectJSON{Disposition: "created"}),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "in_progress"}),
		step("recover", "A", lifecycleExpectJSON{ErrorClass: "claim_lease_live"}),
		setTime(Now+lifecycleLeaseSeconds),
		step("recover", "A", interrupted("not_evaluated", "not_evaluated", "not_evaluated")),
		step("recover", "A", interrupted("not_evaluated", "not_evaluated", "not_evaluated")),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}),
		publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now + lifecycleLeaseSeconds, ReceiptSeq: 1}))
	sc("head_of_line_blocking", "receipt-log positions are assigned at terminal commit; a later entry cannot publish while an earlier one is pending, and its release stays pending until it publishes in order",
		step("verify", "A", committedAllow), step("verify", "B", committedAllow),
		publishFails("B", "head_of_line_blocked"), release("B", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "receipt_not_appended"}),
		publish("A", "ok", 1), publish("B", "ok", 2), release("B", released(Now, 2)), release("A", released(Now, 1)))
	sc("receipt_abandoned", "abandoning the log marks every committed claim whose receipt was not appended receipt_abandoned: its release is withheld, an exact retry fails before claim with receipt_abandoned, and the frozen log publishes nothing; a receipt appended before abandonment still releases",
		step("verify", "A", committedAllow), step("verify", "B", committedAllow), publish("A", "ok", 1),
		lifecycleStepJSON{Op: "abandon", Expect: lifecycleExpectJSON{Abandoned: []string{"B"}}},
		release("B", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "receipt_abandoned"}),
		step("verify", "B", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "receipt_abandoned"}),
		publishFails("B", "log_frozen"), release("A", released(Now, 1)))
	sc("lease_expires_during_status_then_recovery", "the evaluator lease expires while the status lookup runs: the next progress write is fenced (claim_lease_lost) and nothing is committed; an exact retry sees the claim in progress; recovery commits evaluation_interrupted with trust trusted and context bound retained and the interrupted status lookup unavailable",
		verifyMode("A", "expire_lease_during_status", Now+lifecycleLeaseSeconds, lifecycleExpectJSON{Stage: "evaluating", ErrorClass: "claim_lease_lost"}),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "in_progress"}),
		step("recover", "A", interrupted("trusted", "unavailable", "bound")),
		publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now + lifecycleLeaseSeconds, ReceiptSeq: 1}))
	recovered := interrupted("trusted", "unavailable", "bound")
	sc("late_worker_fenced_after_recovery", "recovery commits evaluation_interrupted while the original evaluator is still in its status lookup; the late evaluator's next write fails with claim_already_terminal and cannot replace the recovered result",
		verifyMode("A", "recover_during_status", Now+lifecycleLeaseSeconds, lifecycleExpectJSON{Stage: "evaluating", ErrorClass: "claim_already_terminal", Recovered: &recovered}),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}),
		publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now + lifecycleLeaseSeconds, ReceiptSeq: 1}))
	sc("clock_regression_at_claim", "a store clock below the greatest reading already returned creates no claim and consumes nothing (claim_store_unavailable); once the clock recovers the same request claims and commits",
		step("verify", "A", committedAllow), setTime(Now-1),
		step("verify", "B", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "claim_store_unavailable"}),
		setTime(Now), step("verify", "B", committedAllow))
	sc("clock_regression_during_evaluation", "a store clock that moves below T_claim during evaluation fails the next store write with clock_regressed and commits nothing; recovery after the lease commits evaluation_interrupted",
		verifyMode("A", "regress_clock_during_status", Now-1, lifecycleExpectJSON{Stage: "evaluating", ErrorClass: "clock_regressed"}),
		setTime(Now+lifecycleLeaseSeconds), step("recover", "A", interrupted("trusted", "unavailable", "bound")))
	sc("restore_exact_state", "continuing on an exact copy of the complete store state keeps every claim: an exact retry is a terminal replay and the published receipt still releases",
		step("verify", "A", committedAllow), publish("A", "ok", 1),
		lifecycleStepJSON{Op: "restore", Mode: "exact"},
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}), release("A", released(Now, 1)))
	sc("restore_lost_state_with_epoch_bump", "after a restore that lost claim state, the recovery authority advances the replay epoch: a challenge issued in the earlier epoch fails before claim with stale_replay_epoch, and a challenge of the new epoch claims, commits and releases on the new receipt log",
		step("verify", "A", committedAllow),
		lifecycleStepJSON{Op: "restore", Mode: "lost_state_epoch_bump", ReplayEpoch: fixtureReplayEpoch + 1, LogID: "dddddddddddddddddddddddddddddd02"},
		step("verify", "A", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stale_replay_epoch"}),
		step("verify", "E2", committedAllow), publish("E2", "ok", 1), release("E2", released(Now, 1)))
	sc("release_of_claim_the_store_does_not_hold", "after a restore that lost claim state, the configured claim store answers that it holds no claim for the earlier handoff (claim_not_found): release rejects it as release_state_mismatch rather than reporting a retryable pending (SPEC-v2 §6.9 step 1)",
		step("verify", "A", committedAllow), publish("A", "ok", 1),
		lifecycleStepJSON{Op: "restore", Mode: "lost_state_epoch_bump", ReplayEpoch: fixtureReplayEpoch + 1, LogID: "dddddddddddddddddddddddddddddd02"},
		release("A", lifecycleExpectJSON{ReleaseStatus: "rejected", ReleaseReason: "release_state_mismatch"}))
	sc("rate_admission_at_finalization", "with max_rate admitted inside the finalization compare-and-set, two allows fill a 2-per-60-second counter; the third finalizes once as constraint_denied; a request 60 seconds later is admitted again",
		step("verify", "R1", committedAllow), step("verify", "R2", committedAllow),
		step("verify", "R3", lifecycleExpectJSON{Stage: "committed", Decision: "deny", DecisionReason: "constraint_denied"}),
		setTime(Now+60), step("verify", "R4", committedAllow))
	f.Scenarios[len(f.Scenarios)-1].RateAtFinalization = true
	rateDenied := lifecycleExpectJSON{Stage: "committed", Decision: "deny", DecisionReason: "constraint_denied"}
	rateScenario := func(name, desc string, steps ...lifecycleStepJSON) {
		sc(name, desc, steps...)
		f.Scenarios[len(f.Scenarios)-1].RateAtFinalization = true
	}
	rateScenario("rate_admission_is_all_or_none", "the sealed batch has two counters of one certificate (2 per 120 seconds and 1 per 60 seconds). T2, 30 seconds after T1, is denied by the 60-second counter alone and must not count against the 120-second counter, so T3 at 60 seconds is admitted (with a partial admission it would be denied)",
		step("verify", "T1", committedAllow), setTime(Now+30),
		step("verify", "T2", rateDenied), setTime(Now+60),
		step("verify", "T3", committedAllow))
	rateScenario("rate_retry_and_changed_batch_count_once", "an exact retry of an admitted claim is a terminal replay and is not counted again; a different proof whose signed rate batch differs is a replay of the claimed challenge and admits nothing; so one more allow fills the 2-per-60-second counter and the next is denied",
		step("verify", "R1", committedAllow),
		step("verify", "R1", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}),
		step("verify", "R1x", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "claim_replay"}),
		step("verify", "R2", committedAllow), step("verify", "R3", rateDenied))
	rateScenario("rate_clock_rollback_keeps_admissions_blocking", "two allows admitted at Now+30 fill the counter; with the clock rolled back to Now nothing is claimed or admitted (claim_store_unavailable); back at Now+30 the admissions still count, and only a reading strictly later than their window (Now+90) admits again",
		setTime(Now+30), step("verify", "R1", committedAllow), step("verify", "R2", committedAllow),
		setTime(Now), step("verify", "R3", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "claim_store_unavailable"}),
		setTime(Now+30), step("verify", "R3", rateDenied),
		setTime(Now+90), step("verify", "R4", committedAllow))
	rateScenario("rate_counts_only_allow", "terminal results other than allow count nothing: an indeterminate (trust_unavailable) and a claim recovered as evaluation_interrupted after its evaluator crashed leave the 2-per-60-second counter empty, so two allows are admitted and only the third is denied",
		step("verify", "RI", lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "trust_unavailable"}),
		step("claim_only", "R1", lifecycleExpectJSON{Disposition: "created"}),
		setTime(Now+lifecycleLeaseSeconds),
		step("recover", "R1", interrupted("not_evaluated", "not_evaluated", "not_evaluated")),
		step("verify", "R2", committedAllow), step("verify", "R3", committedAllow), step("verify", "R4", rateDenied))
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
	sc("cancel_before_claim_consumes_nothing", "a caller that cancels before the claim consumes nothing: verify fails before claim with evaluation_cancelled, no claim exists to recover (claim_not_found), and the same proof then claims, commits and releases",
		verifyMode("A", "cancel_before_claim", Now, lifecycleExpectJSON{Stage: "preflight", ErrorClass: "evaluation_cancelled"}),
		step("recover", "A", lifecycleExpectJSON{ErrorClass: "claim_not_found"}),
		step("verify", "A", committedAllow), publish("A", "ok", 1), release("A", released(Now, 1)))
	sc("cancel_after_claim_keeps_claim_recoverable", "a caller that cancels during the status lookup stops evaluation with nothing committed (evaluation_cancelled); the claim stays in progress for exact retries, recovery is refused while the lease is live, and lease-expiry recovery commits evaluation_interrupted with the cancelled lookup unavailable, which publishes and releases as a non-actionable indeterminate",
		verifyMode("A", "cancel_during_status", Now, lifecycleExpectJSON{Stage: "evaluating", ErrorClass: "evaluation_cancelled"}),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "in_progress"}),
		step("recover", "A", lifecycleExpectJSON{ErrorClass: "claim_lease_live"}),
		setTime(Now+lifecycleLeaseSeconds),
		step("recover", "A", interrupted("trusted", "unavailable", "bound")),
		publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now + lifecycleLeaseSeconds, ReceiptSeq: 1}))
	sc("concurrent_stream_advances", "two different proofs carrying stream_seq 2 for one stream key are verified concurrently after sequence 1: claims are serialized per stream key, so exactly one commits and the other fails before claim with stream_sequence_mismatch; the stream then accepts only sequence 3",
		step("verify", "S1", committedAllow),
		lifecycleStepJSON{Op: "verify_concurrent", Requests: []string{"S2", "S2b"}, Expect: lifecycleExpectJSON{Outcomes: []string{"committed", "preflight/stream_sequence_mismatch"}}},
		step("verify", "S4", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stream_sequence_mismatch"}),
		step("verify", "S3", committedAllow))
	sc("outbox_retained_past_challenge_expiry", "a committed allow whose signer fails stays in the receipt outbox past challenge expiry: publication at the expiry still appends the identical sealed body at sequence 1, release is withheld as challenge_expired, and an exact retry after expiry fails before claim",
		step("verify", "A", committedAllow), publish("A", "signer_failure", 0), setTime(Now+290),
		publish("A", "ok", 1),
		release("A", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "challenge_expired"}),
		step("verify", "A", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "challenge_not_fresh"}))
	acknowledge := func(request, mode string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "acknowledge", Request: request, Mode: mode, Expect: expect}
	}
	sc("checkpoint_fork_freezes_log", "an identical acknowledgement retry returns the original timestamp; a different entry hash at an acknowledged sequence is refused as a fork and freezes the log, so the next correctly linked entry is never acknowledged (neither by the publisher's submission nor directly) and its release stays pending",
		step("verify", "A", committedAllow), publish("A", "ok", 1),
		setTime(Now+7),
		acknowledge("A", "exact", lifecycleExpectJSON{AckTimestamp: Now}),
		acknowledge("A", "fork", lifecycleExpectJSON{Failed: true}),
		acknowledge("A", "exact", lifecycleExpectJSON{AckTimestamp: Now}),
		step("verify", "B", committedAllow), publish("B", "ok", 2),
		release("B", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "acknowledgement_unavailable"}),
		acknowledge("B", "exact", lifecycleExpectJSON{Failed: true}),
		release("B", lifecycleExpectJSON{ReleaseStatus: "pending", ReleaseReason: "acknowledgement_unavailable"}))
	sc("checkpoint_refusal_without_fork_does_not_freeze", "an out-of-order acknowledgement is refused without freezing the log: the entries are then acknowledged in order and release",
		withhold(true),
		step("verify", "A", committedAllow), publish("A", "ok", 1),
		step("verify", "B", committedAllow), publish("B", "ok", 2),
		acknowledge("B", "exact", lifecycleExpectJSON{Failed: true}),
		setTime(Now+4),
		acknowledge("A", "exact", lifecycleExpectJSON{AckTimestamp: Now + 4}),
		acknowledge("B", "exact", lifecycleExpectJSON{AckTimestamp: Now + 4}),
		release("B", released(Now+4, 2)), release("A", released(Now+4, 1)))
	genuineTerminal, genuineBody := g.finalizeBindingScenarios(sc, bundles)
	finalize := func(terminalB64, bodyB64 string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "finalize", Request: "A", TerminalB64: terminalB64, BodyB64: bodyB64, Expect: expect}
	}
	// SPEC-v2 §7.11: a committed result whose handoff was lost is resumed
	// from the claim store's persisted record, then published and released.
	resume := func(request string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "resume", Request: request, Expect: expect}
	}
	committedIndeterminate := lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "status_unavailable"}
	sc("resume_finalized_claim_without_handoff", "a result committed by a direct finalize has no handoff; resumption returns it from the store, and it is published and released like a returned handoff (SPEC-v2 §7.11)",
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
		resume("A", committedIndeterminate), publish("A", "ok", 1),
		release("A", func() lifecycleExpectJSON { e := released(Now, 1); e.Decision = "indeterminate"; return e }()),
		resume("A", committedIndeterminate))
	sc("resume_replaces_lost_allow_handoff", "resuming a committed allow returns the same handoff: the same allow horizon, published at the same position and released once",
		step("verify", "A", committedAllow), resume("A", committedAllow), publish("A", "ok", 1), release("A", released(Now, 1)),
		step("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}))
	sc("resume_refuses_claims_without_a_committed_record", "resumption never commits: an unknown claim is claim_not_found, a claim evaluating under a live lease is claim_lease_live and after it claim_lease_lost; after lease-expiry recovery it resumes the interrupted result",
		resume("A", lifecycleExpectJSON{ErrorClass: "claim_not_found"}),
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		resume("A", lifecycleExpectJSON{ErrorClass: "claim_lease_live"}),
		setTime(Now+lifecycleLeaseSeconds), resume("A", lifecycleExpectJSON{ErrorClass: "claim_lease_lost"}),
		step("recover", "A", interrupted("not_evaluated", "not_evaluated", "not_evaluated")),
		resume("A", lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted"}))
	sc("resume_abandoned_claim", "resuming a committed allow whose receipt was abandoned returns its handoff; publication fails because the log is frozen, and release is withheld as receipt_abandoned (SPEC-v2 §7.7, §7.11, §6.9)",
		step("verify", "A", committedAllow),
		lifecycleStepJSON{Op: "abandon", Expect: lifecycleExpectJSON{Abandoned: []string{"A"}}},
		resume("A", committedAllow), publishFails("A", "log_frozen"),
		release("A", lifecycleExpectJSON{ReleaseStatus: "withheld", ReleaseReason: "receipt_abandoned"}),
		resume("A", committedAllow))
	g.resumeRecordScenarios(sc, f.Requests, bundles)
	g.recoveryBindingScenarios(sc, bundles)
	g.addProfileScenarios(&f, add)
	return f
}

// finalizeBindingScenarios pins SPEC-v2 §7.5: the claim store's finalize
// binds the receipt outbox body to the sealed claim. Each scenario claims
// request A, offers a body that differs from the sealed claim in exactly one
// bound member (refused as configuration_invalid, committing nothing), and
// then finalizes and retries the genuine body.
func (g *gen) finalizeBindingScenarios(sc func(string, string, ...lifecycleStepJSON), bundles map[string][]byte) (genuineTerminal, genuineBody string) {
	b := must(ratify.DecodeProofBundleV2(bundles["A"]))
	issuers := []string{}
	for _, c := range b.Delegations {
		if !slices.Contains(issuers, c.IssuerID) {
			issuers = append(issuers, c.IssuerID)
		}
	}
	slices.Sort(issuers)
	vp := policyDigest(verifyPolicy, true, verifyPolicyFields)
	genuine := func() *ratify.VerificationReceiptV2 {
		return &ratify.VerificationReceiptV2{
			Version: 2, VerifierID: b.VerifierID, AgentID: b.AgentID, BundleHash: bundleHash(bundles["A"]), IssuerIDs: slices.Clone(issuers),
			Decision: "indeterminate", DecisionReason: "status_unavailable", IdentityStatus: "authorization_unverified",
			TrustAssessment: "trusted", StatusAssessment: "unavailable", ChallengeAssessment: "current",
			ContextAssessment: "bound", ContextPolicyDigest: strp(vp), VerifiedAt: Now, RequiredScope: "data:read",
			GrantedScope: []string{}, StatusEvidence: []ratify.StatusEvidenceEntryV2{},
		}
	}
	terminal := func(decision, reason, identity string) string {
		return b64(must(ratify.CanonicalJSON(map[string]string{"decision": decision, "decision_reason": reason, "identity_status": identity})))
	}
	genuineTerminal = terminal("indeterminate", "status_unavailable", "authorization_unverified")
	genuineBody = b64(must(ratify.VerificationReceiptV2Body(genuine())))
	finalize := func(terminalB64, bodyB64 string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "finalize", Request: "A", TerminalB64: terminalB64, BodyB64: bodyB64, Expect: expect}
	}
	for _, m := range []struct {
		name, member string
		terminal     string
		edit         func(*ratify.VerificationReceiptV2)
	}{
		{"verifier_id", "verifier_id names another verifier key", "", func(r *ratify.VerificationReceiptV2) { r.VerifierID = g.k("root").ID }},
		{"agent_id", "agent_id names another agent", "", func(r *ratify.VerificationReceiptV2) { r.AgentID = g.k("intermediate").ID }},
		{"bundle_hash", "bundle_hash names request B's proof bundle", "", func(r *ratify.VerificationReceiptV2) { r.BundleHash = bundleHash(bundles["B"]) }},
		{"issuer_ids", "issuer_ids omits one sealed issuer", "", func(r *ratify.VerificationReceiptV2) { r.IssuerIDs = r.IssuerIDs[:len(r.IssuerIDs)-1] }},
		{"required_scope", "required_scope is data:write while the claim sealed data:read", "", func(r *ratify.VerificationReceiptV2) { r.RequiredScope = "data:write" }},
		{"context_policy_digest", "context_policy_digest is another policy's digest", "", func(r *ratify.VerificationReceiptV2) {
			r.ContextPolicyDigest = strp(policyDigest(notRequiredPolicy, false, nil))
		}},
		{"constraint_evaluators", "constraint_evaluators lists an evaluator the sealed snapshot does not contain", "", func(r *ratify.VerificationReceiptV2) {
			r.ConstraintEvaluators = []ratify.ConstraintEvaluatorRefV2{{Type: maxCountType, ProfileDigest: profileDigest(maxCountProfile, maxCountType)}}
		}},
		{"terminal_decision", "the terminal result is deny/delegation_revoked while the body is indeterminate/status_unavailable", terminal("deny", "delegation_revoked", "revoked"), nil},
	} {
		body := genuine()
		if m.edit != nil {
			m.edit(body)
		}
		mutatedTerminal := genuineTerminal
		if m.terminal != "" {
			mutatedTerminal = m.terminal
		}
		sc("finalize_rejects_body_with_other_"+m.name, "the claim store refuses to finalize a canonical receipt body whose "+m.member+" (configuration_invalid, SPEC-v2 §7.5) and commits nothing; the genuine body then finalizes once, an identical retry is a no-op, and an exact retry of the proof is a terminal replay",
			lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
			finalize(mutatedTerminal, b64(must(ratify.VerificationReceiptV2Body(body))), lifecycleExpectJSON{ErrorClass: "configuration_invalid"}),
			finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
			finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "identical"}),
			lifecycleStepJSON{Op: "verify", Request: "A", Expect: lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}})
	}
	// A null context_policy_digest is bound too (SPEC-v2 §5.8, §7.5): once
	// context was evaluated, the body's digest equals the sealed claim's,
	// so a body that drops the configured policy's digest is refused.
	for _, assessment := range []string{"unverified", "unbound"} {
		body := genuine()
		body.ContextAssessment, body.ContextPolicyDigest = assessment, nil
		sc("finalize_rejects_body_with_null_context_policy_digest_"+assessment, "the claim sealed a context policy, and the canonical receipt body records context_assessment "+assessment+" with a null context_policy_digest: the claim store refuses it (configuration_invalid, SPEC-v2 §7.5) and commits nothing; the genuine body then finalizes once",
			lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
			finalize(genuineTerminal, b64(must(ratify.VerificationReceiptV2Body(body))), lifecycleExpectJSON{ErrorClass: "configuration_invalid"}),
			finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
			lifecycleStepJSON{Op: "verify", Request: "A", Expect: lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}})
	}
	// The allow horizon matches the decision (SPEC-v2 §6.8): an allow carries
	// a positive horizon and every other decision carries none, so a store
	// never commits an allow that skipped its horizon and rate admission, or
	// counts a non-allow against a rate limit.
	allow := genuine()
	allow.Decision, allow.DecisionReason, allow.IdentityStatus = "allow", "authorized", "authorized_agent"
	st := g.statusFixtures()
	allow.StatusAssessment, allow.GrantedScope = "current", []string{"data:read"}
	allow.StatusEvidence = toLibEvidence(sortEvidence([]EvidenceJSON{g.evidence(st["root_current"]), g.evidence(st["intermediate_current"])}))
	sc("finalize_rejects_allow_without_allow_horizon", "a canonical allow receipt body finalized with allow_valid_until 0 is refused (configuration_invalid, SPEC-v2 §6.8, §7.5) and commits nothing; the genuine body then finalizes once",
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		finalize(terminal("allow", "authorized", "authorized_agent"), b64(must(ratify.VerificationReceiptV2Body(allow))), lifecycleExpectJSON{ErrorClass: "configuration_invalid"}),
		finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
		lifecycleStepJSON{Op: "verify", Request: "A", Expect: lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}})
	withHorizon := finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{ErrorClass: "configuration_invalid"})
	withHorizon.AllowValidUntil = Now + 60
	negative := finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{ErrorClass: "configuration_invalid"})
	negative.AllowValidUntil = -1
	sc("finalize_rejects_negative_allow_horizon_on_non_allow", "an indeterminate receipt body finalized with allow_valid_until -1 is refused (configuration_invalid, SPEC-v2 §6.8): a non-allow carries exactly 0; the same body with 0 then finalizes once",
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		negative,
		finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}))
	beyond := finalize(terminal("allow", "authorized", "authorized_agent"), b64(must(ratify.VerificationReceiptV2Body(allow))), lifecycleExpectJSON{ErrorClass: "configuration_invalid"})
	beyond.AllowValidUntil = ratify.V2MaxTimestampSeconds + 1
	sc("finalize_rejects_allow_horizon_beyond_timestamp_domain", "an allow receipt body finalized with allow_valid_until 253402300800 is refused (configuration_invalid, SPEC-v2 §2.5, §6.8): every horizon is clamped to 253402300799; the genuine indeterminate body then finalizes once",
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		beyond,
		finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}))
	sc("finalize_rejects_allow_horizon_on_non_allow", "an indeterminate receipt body finalized with a positive allow_valid_until is refused (configuration_invalid, SPEC-v2 §6.8, §7.5) and commits nothing; the same body with no horizon then finalizes once",
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		withHorizon,
		finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
		lifecycleStepJSON{Op: "verify", Request: "A", Expect: lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}})
	// A non-null digest with context not_evaluated is never a receipt body
	// (SPEC-v2 §5.8), so it fails the strict body decode before binding.
	interrupted := genuine()
	interrupted.DecisionReason, interrupted.ContextAssessment, interrupted.ContextPolicyDigest = "evaluation_interrupted", "not_evaluated", nil
	interruptedBody := must(ratify.VerificationReceiptV2Body(interrupted))
	withDigest := bytes.Replace(interruptedBody, []byte(`"context_policy_digest":null`), []byte(`"context_policy_digest":"`+vp+`"`), 1)
	if bytes.Equal(withDigest, interruptedBody) {
		panic("context_policy_digest member not found in the interrupted receipt body")
	}
	interruptedTerminal := terminal("indeterminate", "evaluation_interrupted", "authorization_unverified")
	sc("finalize_rejects_body_with_context_policy_digest_not_evaluated", "the claim sealed a context policy, and the receipt body records context_assessment not_evaluated with the sealed context_policy_digest: that body is not a receipt body (SPEC-v2 §5.8), so the claim store refuses it as malformed (SPEC-v2 §7.5) and commits nothing; the genuine body then finalizes once",
		lifecycleStepJSON{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		finalize(interruptedTerminal, b64(withDigest), lifecycleExpectJSON{ErrorClass: "malformed"}),
		finalize(genuineTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
		lifecycleStepJSON{Op: "verify", Request: "A", Expect: lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}})
	return genuineTerminal, genuineBody
}

// recoveryBindingScenarios pins SPEC-v2 §7.5 for lease-expiry recovery: the
// claim store's recovery operation validates its terminal result and receipt
// body exactly as finalize does and commits only the canonical
// indeterminate/evaluation_interrupted result. Each refusal commits nothing,
// so the recovery helper then commits the canonical interrupted receipt,
// which publishes at sequence 1.
func (g *gen) recoveryBindingScenarios(sc func(string, string, ...lifecycleStepJSON), bundles map[string][]byte) {
	b := must(ratify.DecodeProofBundleV2(bundles["A"]))
	issuers := []string{}
	for _, c := range b.Delegations {
		if !slices.Contains(issuers, c.IssuerID) {
			issuers = append(issuers, c.IssuerID)
		}
	}
	slices.Sort(issuers)
	// The body the recovery helper builds for request A claimed at Now with
	// no recorded progress (SPEC-v2 §6.7).
	interrupted := func() *ratify.VerificationReceiptV2 {
		return &ratify.VerificationReceiptV2{
			Version: 2, VerifierID: b.VerifierID, AgentID: b.AgentID, BundleHash: bundleHash(bundles["A"]), IssuerIDs: slices.Clone(issuers),
			Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified",
			TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ChallengeAssessment: "current",
			ContextAssessment: "not_evaluated", VerifiedAt: Now, RequiredScope: "data:read",
			GrantedScope: []string{}, StatusEvidence: []ratify.StatusEvidenceEntryV2{},
		}
	}
	terminal := func(decision, reason, identity string) string {
		return b64(must(ratify.CanonicalJSON(map[string]string{"decision": decision, "decision_reason": reason, "identity_status": identity})))
	}
	interruptedTerminal := terminal("indeterminate", "evaluation_interrupted", "authorization_unverified")
	genuineBody := must(ratify.VerificationReceiptV2Body(interrupted()))
	recoverDirect := func(terminalB64 string, body []byte, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "recover_direct", Request: "A", TerminalB64: terminalB64, BodyB64: b64(body), Expect: expect}
	}
	recovered := lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted",
		TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ContextAssessment: "not_evaluated"}
	claimAndExpire := []lifecycleStepJSON{
		{Op: "claim_only", Request: "A", Expect: lifecycleExpectJSON{Disposition: "created"}},
		{Op: "set_time", Time: Now + lifecycleLeaseSeconds},
	}
	thenRecover := []lifecycleStepJSON{
		{Op: "recover", Request: "A", Expect: recovered},
		{Op: "publish", Request: "A", Mode: "ok", Expect: lifecycleExpectJSON{ReceiptSeq: 1}},
		{Op: "verify", Request: "A", Expect: lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}},
	}
	refused := func(name, desc, terminalB64 string, body []byte, class string) {
		steps := append(slices.Clone(claimAndExpire), recoverDirect(terminalB64, body, lifecycleExpectJSON{ErrorClass: class}))
		sc("recover_rejects_"+name, desc+"; the refused recovery commits nothing, so the canonical interrupted recovery then commits, publishes at sequence 1, and an exact retry of the proof is a terminal replay", append(steps, thenRecover...)...)
	}

	refused("malformed_body", "after the evaluator lease expired, the claim store's recovery operation receives the canonical interrupted result with a receipt body that is not a canonical receipt body ({\"decision\":\"allow\",\"verifier_id\":\"forged\"}): it is malformed (SPEC-v2 §7.5, §7.7)",
		interruptedTerminal, []byte(`{"decision":"allow","verifier_id":"forged"}`), "malformed")
	other := interrupted()
	other.BundleHash = bundleHash(bundles["B"])
	refused("body_for_another_claim", "after the evaluator lease expired, the claim store's recovery operation receives a canonical interrupted receipt body whose bundle_hash names request B's proof bundle: it does not bind the sealed claim and is configuration_invalid (SPEC-v2 §7.5)",
		interruptedTerminal, must(ratify.VerificationReceiptV2Body(other)), "configuration_invalid")
	withDigest := bytes.Replace(genuineBody, []byte(`"context_policy_digest":null`), []byte(`"context_policy_digest":"`+policyDigest(verifyPolicy, true, verifyPolicyFields)+`"`), 1)
	if bytes.Equal(withDigest, genuineBody) {
		panic("context_policy_digest member not found in the interrupted receipt body")
	}
	refused("context_policy_digest_not_evaluated", "after the evaluator lease expired, the claim store's recovery operation receives an interrupted receipt body with context_assessment not_evaluated and the sealed context_policy_digest: that body is not a receipt body (SPEC-v2 §5.8), so recovery refuses it as malformed (SPEC-v2 §7.5)",
		interruptedTerminal, withDigest, "malformed")
	statusUnavailable := interrupted()
	statusUnavailable.DecisionReason, statusUnavailable.TrustAssessment, statusUnavailable.StatusAssessment = "status_unavailable", "trusted", "unavailable"
	statusUnavailable.ContextAssessment = "bound"
	statusUnavailable.ContextPolicyDigest = strp(policyDigest(verifyPolicy, true, verifyPolicyFields))
	refused("other_decision", "after the evaluator lease expired, the claim store's recovery operation receives a canonical receipt body bound to the sealed claim and a matching terminal result, both indeterminate/status_unavailable: recovery commits only indeterminate/evaluation_interrupted, so it is configuration_invalid (SPEC-v2 §7.5)",
		terminal("indeterminate", "status_unavailable", "authorization_unverified"), must(ratify.VerificationReceiptV2Body(statusUnavailable)), "configuration_invalid")
	refused("terminal_result_other_than_body", "after the evaluator lease expired, the claim store's recovery operation receives the canonical interrupted receipt body with a terminal result naming deny/delegation_revoked: the result differs from the body and is configuration_invalid (SPEC-v2 §7.5)",
		terminal("deny", "delegation_revoked", "revoked"), genuineBody, "configuration_invalid")
	sc("recover_direct_accepts_canonical_interrupted_body", "after the evaluator lease expired, the claim store's recovery operation commits the canonical interrupted result and receipt body for the sealed claim; an identical repeat is a no-op, the recovery helper builds the same bytes and returns the committed result, and the receipt publishes at sequence 1",
		append(slices.Clone(claimAndExpire),
			recoverDirect(interruptedTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "committed"}),
			recoverDirect(interruptedTerminal, genuineBody, lifecycleExpectJSON{FinalizeResult: "identical"}),
			thenRecover[0], thenRecover[1], thenRecover[2])...)
	// The sealed terminal result is exactly the RatifyCanonicalJSON of the
	// body's decision, decision_reason and identity_status (SPEC-v2 §7.13),
	// and recovery validates exactly as finalization does (§7.5), so any
	// other bytes are configuration_invalid.
	canonicalInterrupted := must(ratify.CanonicalJSON(map[string]string{"decision": "indeterminate", "decision_reason": "evaluation_interrupted", "identity_status": "authorization_unverified"}))
	refused("terminal_result_with_other_members", "after the evaluator lease expired, the claim store's recovery operation receives the canonical interrupted receipt body with a terminal result whose decision, decision_reason and identity_status match it but which has further members: the terminal result is not the canonical three-member object and is configuration_invalid (SPEC-v2 §7.13)",
		b64(must(ratify.CanonicalJSON(map[string]any{"decision": "indeterminate", "decision_reason": "evaluation_interrupted",
			"identity_status": "authorization_unverified", "x": 1, "y": map[string]any{"z": true}}))), genuineBody, "configuration_invalid")
	refused("terminal_result_not_canonical", "after the evaluator lease expired, the claim store's recovery operation receives the canonical interrupted receipt body with the matching terminal result preceded by a space: the bytes are not RatifyCanonicalJSON and are configuration_invalid (SPEC-v2 §7.13)",
		b64(append([]byte(" "), canonicalInterrupted...)), genuineBody, "configuration_invalid")
	refused("terminal_result_without_identity_status", "after the evaluator lease expired, the claim store's recovery operation receives the canonical interrupted receipt body with a terminal result that has only the matching decision and decision_reason: identity_status is required and the result is configuration_invalid (SPEC-v2 §7.13)",
		b64(must(ratify.CanonicalJSON(map[string]string{"decision": "indeterminate", "decision_reason": "evaluation_interrupted"}))), genuineBody, "configuration_invalid")
	refused("terminal_result_other_identity_status", "after the evaluator lease expired, the claim store's recovery operation receives the canonical interrupted receipt body with a canonical terminal result whose decision and decision_reason match but whose identity_status is revoked: it differs from the body and is configuration_invalid (SPEC-v2 §7.13)",
		terminal("indeterminate", "evaluation_interrupted", "revoked"), genuineBody, "configuration_invalid")
}
