package v2vectors

// Shared concurrency scenarios (SPEC-v2 §6.9, §6.11, §7.3 to §7.8). Each
// scenario names a concurrent workload against an SDK's own in-memory
// reference store and the outcome invariants that must hold after every
// participant completes, whatever the interleaving. Requests, bundles, the
// verifier key, receipt log and lease come from lifecycle-scenarios.json, so
// no new signed material is introduced; the finalize and recovery payloads
// are the request A bodies that lifecycle-scenarios.json already pins.

import (
	"slices"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

const (
	concurrencyFile              = "concurrency-scenarios.json"
	concurrencyDefaultIterations = 20
)

type concurrencyParticipantJSON struct {
	Group           string `json:"group"`
	Count           int    `json:"count"`
	Op              string `json:"op"`
	Request         string `json:"request,omitempty"`
	Time            int64  `json:"time,omitempty"`
	Target          string `json:"target,omitempty"`
	Mode            string `json:"mode,omitempty"`
	TerminalB64     string `json:"terminal_b64,omitempty"`
	BodyB64         string `json:"body_b64,omitempty"`
	AllowValidUntil int64  `json:"allow_valid_until,omitempty"`
}

type concurrencyGroupOutcomesJSON struct {
	IfWinner []string `json:"if_winner"`
	IfLoser  []string `json:"if_loser"`
}

type concurrencyInvariantJSON struct {
	Kind     string                                  `json:"kind"`
	Groups   []string                                `json:"groups,omitempty"`
	Outcomes []string                                `json:"outcomes,omitempty"`
	Equals   *int                                    `json:"equals,omitempty"`
	AtMost   *int                                    `json:"at_most,omitempty"`
	Winning  []string                                `json:"winning,omitempty"`
	ByGroup  map[string]concurrencyGroupOutcomesJSON `json:"by_group,omitempty"`
}

type concurrencyExpectByOutcomeJSON struct {
	Group string                         `json:"group"`
	Cases map[string]lifecycleExpectJSON `json:"cases"`
}

type concurrencyStepJSON struct {
	lifecycleStepJSON
	ExpectByOutcome *concurrencyExpectByOutcomeJSON `json:"expect_by_outcome,omitempty"`
}

type concurrencyScenarioJSON struct {
	Name               string                       `json:"name"`
	Description        string                       `json:"description"`
	StartTime          int64                        `json:"start_time"`
	RateAtFinalization bool                         `json:"rate_at_finalization,omitempty"`
	Setup              []lifecycleStepJSON          `json:"setup"`
	Participants       []concurrencyParticipantJSON `json:"participants"`
	Invariants         []concurrencyInvariantJSON   `json:"invariants"`
	After              []concurrencyStepJSON        `json:"after"`
}

type concurrencyFileJSON struct {
	Version           int                       `json:"version"`
	Description       string                    `json:"description"`
	Inputs            string                    `json:"inputs"`
	DefaultIterations int                       `json:"default_iterations"`
	Labels            map[string]string         `json:"labels"`
	Operations        map[string]string         `json:"operations"`
	Invariants        map[string]string         `json:"invariants"`
	Scenarios         []concurrencyScenarioJSON `json:"scenarios"`
}

// requestAPayloads returns the finalize payload (indeterminate /
// status_unavailable, the body lifecycle-scenarios.json finalizes after
// claim_only) and the canonical interrupted recovery payload for request A
// claimed at Now with no recorded progress, as base64 terminal result and
// receipt body.
func (g *gen) requestAPayloads() (finalTerminal, finalBody, interruptedTerminal, interruptedBody string) {
	_, wire := g.lifecycleRequest(0xa0, 0, nil)
	b := must(ratify.DecodeProofBundleV2(wire))
	issuers := []string{}
	for _, c := range b.Delegations {
		if !slices.Contains(issuers, c.IssuerID) {
			issuers = append(issuers, c.IssuerID)
		}
	}
	slices.Sort(issuers)
	body := func(reason, trust, status, context string, digest *string) string {
		return b64(must(ratify.VerificationReceiptV2Body(&ratify.VerificationReceiptV2{
			Version: 2, VerifierID: b.VerifierID, AgentID: b.AgentID, BundleHash: bundleHash(wire), IssuerIDs: issuers,
			Decision: "indeterminate", DecisionReason: reason, IdentityStatus: "authorization_unverified",
			TrustAssessment: trust, StatusAssessment: status, ChallengeAssessment: "current",
			ContextAssessment: context, ContextPolicyDigest: digest, VerifiedAt: Now, RequiredScope: "data:read",
			GrantedScope: []string{}, StatusEvidence: []ratify.StatusEvidenceEntryV2{},
		})))
	}
	terminal := func(reason string) string {
		return b64(must(ratify.CanonicalJSON(map[string]string{"decision": "indeterminate", "decision_reason": reason, "identity_status": "authorization_unverified"})))
	}
	return terminal("status_unavailable"), body("status_unavailable", "trusted", "unavailable", "bound", strp(policyDigest(verifyPolicy, true, verifyPolicyFields))),
		terminal("evaluation_interrupted"), body("evaluation_interrupted", "not_evaluated", "not_evaluated", "not_evaluated", nil)
}

func (g *gen) concurrencyFile() any {
	finalTerminal, finalBody, interruptedTerminal, interruptedBody := g.requestAPayloads()
	const (
		allow       = "committed/allow/authorized"
		rateDenied  = "committed/deny/constraint_denied"
		interrupted = "committed/indeterminate/evaluation_interrupted"
		terminal    = "replay/terminal_replay"
		inProgress  = "replay/in_progress"
	)
	committedAllow := lifecycleExpectJSON{Stage: "committed", Decision: "allow", DecisionReason: "authorized", AllowHorizon: statusFreshUntil}
	recoveredA := lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted",
		TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ContextAssessment: "not_evaluated"}
	replayTerminal := lifecycleExpectJSON{Stage: "replay", Disposition: "terminal_replay"}
	step := func(op, request string, expect lifecycleExpectJSON) lifecycleStepJSON {
		return lifecycleStepJSON{Op: op, Request: request, Expect: expect}
	}
	after := func(op, request string, expect lifecycleExpectJSON) concurrencyStepJSON {
		return concurrencyStepJSON{lifecycleStepJSON: step(op, request, expect)}
	}
	setTime := func(t int64) lifecycleStepJSON { return lifecycleStepJSON{Op: "set_time", Time: t} }
	publish := func(request string, seq int64) lifecycleStepJSON {
		return lifecycleStepJSON{Op: "publish", Request: request, Mode: "ok", Expect: lifecycleExpectJSON{ReceiptSeq: seq}}
	}
	release := func(request string, expect lifecycleExpectJSON) concurrencyStepJSON {
		return concurrencyStepJSON{lifecycleStepJSON: lifecycleStepJSON{Op: "release", Request: request, Checkpoint: "reference", Expect: expect}}
	}
	claimOnly := step("claim_only", "A", lifecycleExpectJSON{Disposition: "created"})
	verifiers := func(group, request string, n int) concurrencyParticipantJSON {
		return concurrencyParticipantJSON{Group: group, Count: n, Op: "verify", Request: request}
	}
	owner := func(n int) concurrencyParticipantJSON {
		return concurrencyParticipantJSON{Group: "owner", Count: n, Op: "finalize", Request: "A", TerminalB64: finalTerminal, BodyB64: finalBody}
	}
	recoverDirect := func(n int) concurrencyParticipantJSON {
		return concurrencyParticipantJSON{Group: "recoverers", Count: n, Op: "recover_direct", Request: "A", TerminalB64: interruptedTerminal, BodyB64: interruptedBody}
	}
	allowed := func(outcomes []string, groups ...string) concurrencyInvariantJSON {
		return concurrencyInvariantJSON{Kind: "allowed", Groups: groups, Outcomes: outcomes}
	}
	count := func(n int, outcomes []string, groups ...string) concurrencyInvariantJSON {
		return concurrencyInvariantJSON{Kind: "count", Groups: groups, Outcomes: outcomes, Equals: intp(n)}
	}
	contiguous := concurrencyInvariantJSON{Kind: "receipt_log_contiguous"}

	f := concurrencyFileJSON{
		Version: 1,
		Description: "Shared concurrency scenarios for the Part B reference store (SPEC-v2 §6.9, §6.11, §7.3 to §7.8). Every SDK runs every scenario default_iterations times (a runner may take another count from its environment, and a runner whose build or runtime makes that count slow may default to fewer iterations, documented in the runner), each iteration on a fresh in-memory reference store built exactly as for lifecycle-scenarios.json (inputs): its requests, bundles_b64, verifier_key, log_id and lease_seconds, the store clock starting at start_time, and rate_at_finalization with the same meaning. " +
			"An iteration runs setup sequentially, then starts every participant at once with the runtime's real concurrency and waits for all of them, then checks every invariant, then runs after sequentially. " +
			"Thread interleavings differ by runtime, so invariants constrain only outcomes: which labels occur, how many times, and what the store holds afterwards.",
		Inputs:            "lifecycle-scenarios.json",
		DefaultIterations: concurrencyDefaultIterations,
		Labels: map[string]string{
			"verify":         "committed/<decision>/<decision_reason> read from the committed receipt body; replay/<disposition>; preflight/<error_class>; evaluating/<error_class>",
			"claim_only":     "the claim disposition (created, in_progress, terminal_replay), or error/<error_class>",
			"finalize":       "committed (the store committed this result), identical (the same result was already committed), or error/<error_class>",
			"recover_direct": "as finalize",
			"recover":        "committed/<decision>/<decision_reason> of the returned outcome, or error/<error_class>",
			"resume":         "committed/<decision>/<decision_reason> of the returned handoff, or error/<error_class>; with mode release, the release label of the returned handoff, or error/<error_class> when resumption fails",
			"release":        "released/<decision>/<release_time>/<receipt_sequence>, or <status>/<reason> for pending, withheld and rejected",
			"acknowledge":    "acknowledged/<timestamp>, or refused",
			"set_time":       "done",
			"cancel":         "done",
		},
		Operations: map[string]string{
			"setup and after":   "steps in the lifecycle-scenarios.json vocabulary (set_time, set_ack_withheld, verify, claim_only, publish, release, recover, resume) with the same semantics and expectations. An after step may carry expect_by_outcome instead of expect: group names a group with exactly one participant, and cases maps that participant's label to the step's expectation",
			"participants":      "each entry is count participants of group performing op once. A participant has its own callbacks and its own copy of every input; all participants share the scenario's one store. A request's claim is always the claim ID ProtocolClaimID(verifier namespace, replay epoch, challenge) of the request's expected challenge, as for the lifecycle recover step, whichever step or participant created it",
			"verify":            "VerifyProofBundleV2 for request against the store at the store clock read when the participant starts, as a lifecycle verify step with mode \"\". A verify whose group is the target of a cancel participant runs with a cancellable caller context",
			"claim_only":        "preflight and claim request without evaluating, as the lifecycle claim_only step",
			"finalize":          "the claim store's finalize operation for request's claim, with the owner token its setup claim_only step returned, terminal_b64, body_b64 and allow_valid_until (0 when absent)",
			"recover_direct":    "the claim store's recovery operation for request's claim with terminal_b64 and body_b64",
			"recover":           "RecoverInterruptedClaim for request's claim",
			"resume":            "ResumeCommittedClaim for request's claim against the store, as the lifecycle resume step without a record (SPEC-v2 §7.11). The returned handoff is a committed result of the claim (committed results), and its receipt body must equal the body already recorded for the claim, if any: a resumed body that differs from the recorded one fails the iteration. The participant never replaces the request's committed outcome held for other participants. With mode release it then releases the returned handoff with request's last published receipt and the reference checkpoint, as the release participant does",
			"release":           "ReleaseV2Decision of request's committed outcome with its last published receipt and the reference checkpoint, as the lifecycle release step",
			"acknowledge":       "submit request's last published receipt to the reference checkpoint with its own entry hash, as the lifecycle acknowledge step with mode exact",
			"set_time":          "set the store clock to time while the other participants run",
			"cancel":            "signal the caller cancellation of every participant of group target. The runner spreads the signal over different points of the target's verification across iterations (an implementation-defined delay, for example a fraction of a measured uncancelled verification that varies with the iteration); no particular outcome is required of any one iteration",
			"committed results": "every terminal result committed during an iteration, by a setup or after step or by a participant (a committed verify, recover or resume outcome, or a finalize or recover_direct labelled committed with the claim ID of its setup claim_only step and its body_b64), is recorded per claim ID; a later identical commit of the same claim is the same record",
		},
		Invariants: map[string]string{
			"allowed":                "every participant of groups (all participants when groups is absent) has a label in outcomes",
			"count":                  "the number of participants of groups (all when absent) with a label in outcomes is exactly equals, or at most at_most",
			"all_equal":              "every participant of groups has the same label",
			"one_winner":             "at most one group of by_group has a participant whose label is in winning (a count invariant states when one is required); every participant of that group has a label in its if_winner list and every participant of every other group of by_group a label in its if_loser list",
			"receipt_log_contiguous": "publish every committed result recorded in the iteration through the reference publisher, in any order, retrying an entry that fails head_of_line_blocked after the others until a full pass publishes nothing new: every result publishes, the receipt sequences are exactly 1..k for k recorded claims, and each claim's receipt is the same on a second publication. A second terminal commit of one claim, or a commit that never reached the outbox, breaks this",
		},
	}
	sc := func(s concurrencyScenarioJSON) {
		s.StartTime = Now
		if s.Setup == nil {
			s.Setup = []lifecycleStepJSON{}
		}
		if s.After == nil {
			s.After = []concurrencyStepJSON{}
		}
		f.Scenarios = append(f.Scenarios, s)
	}

	sc(concurrencyScenarioJSON{
		Name:         "same_challenge_claim_storm",
		Description:  "8 concurrent verifications of one proof (SPEC-v2 §7.3): the claim is created once, so exactly one commits and every other sees the claim in progress or terminal; the one receipt publishes at sequence 1 and releases",
		Participants: []concurrencyParticipantJSON{verifiers("verifiers", "A", 8)},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{allow}), allowed([]string{allow, terminal, inProgress}), contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "A", replayTerminal), {lifecycleStepJSON: publish("A", 1)},
			release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "allow", ReleaseTime: Now, ReceiptSeq: 1})},
	})
	sc(concurrencyScenarioJSON{
		Name:         "same_challenge_claim_storm_store_level",
		Description:  "8 concurrent claims of one proof without evaluation (SPEC-v2 §7.3): exactly one is created and holds the evaluator lease, every other is in progress; after the lease, recovery commits evaluation_interrupted once",
		Participants: []concurrencyParticipantJSON{{Group: "claimers", Count: 8, Op: "claim_only", Request: "A"}},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{"created"}), allowed([]string{"created", "in_progress"}), contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "A", lifecycleExpectJSON{Stage: "replay", Disposition: "in_progress"}),
			{lifecycleStepJSON: setTime(Now + lifecycleLeaseSeconds)},
			after("recover", "A", recoveredA),
			{lifecycleStepJSON: publish("A", 1)}},
	})
	winners := []string{allow, terminal, inProgress}
	sc(concurrencyScenarioJSON{
		Name:               "conflicting_proofs_for_one_challenge",
		Description:        "4 verifications each of two different proofs for one challenge (R1 and R1x, whose signed rate batches differ) run concurrently (SPEC-v2 §7.3): the first claim seals one proof, which commits once; every verification of the other proof fails before claim with claim_replay and admits nothing, so R2 is still admitted afterwards",
		RateAtFinalization: true,
		Participants:       []concurrencyParticipantJSON{verifiers("r1", "R1", 4), verifiers("r1x", "R1x", 4)},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{allow}),
			{Kind: "one_winner", Winning: []string{allow}, ByGroup: map[string]concurrencyGroupOutcomesJSON{
				"r1":  {IfWinner: winners, IfLoser: []string{"preflight/claim_replay"}},
				"r1x": {IfWinner: winners, IfLoser: []string{"preflight/claim_replay"}},
			}},
			contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "R2", committedAllow)},
	})
	sc(concurrencyScenarioJSON{
		Name:        "owner_finalize_races_lease_expiry_and_recovery",
		Description: "an evaluator holds the claim of request A while the clock reaches its lease expiry and 3 recoverers commit the canonical interrupted result directly (SPEC-v2 §7.5): at most one terminal result is committed, by the owner (lease still live) or by one recoverer (lease expired), and none when every recovery ran before the expiry and the owner after it; the owner is never committed after recovery and recovery never replaces the owner's result, so a later recovery is claim_already_terminal exactly when the owner committed",
		Setup:       []lifecycleStepJSON{claimOnly},
		Participants: []concurrencyParticipantJSON{owner(1), recoverDirect(3),
			{Group: "clock", Count: 1, Op: "set_time", Time: Now + lifecycleLeaseSeconds}},
		Invariants: []concurrencyInvariantJSON{
			{Kind: "count", Groups: []string{"owner", "recoverers"}, Outcomes: []string{"committed"}, AtMost: intp(1)},
			{Kind: "one_winner", Winning: []string{"committed"}, ByGroup: map[string]concurrencyGroupOutcomesJSON{
				"owner":      {IfWinner: []string{"committed"}, IfLoser: []string{"error/claim_lease_lost", "error/claim_already_terminal"}},
				"recoverers": {IfWinner: []string{"committed", "identical", "error/claim_lease_live"}, IfLoser: []string{"error/claim_lease_live", "error/claim_already_terminal"}},
			}},
			contiguous,
		},
		After: []concurrencyStepJSON{
			{lifecycleStepJSON: lifecycleStepJSON{Op: "recover", Request: "A"}, ExpectByOutcome: &concurrencyExpectByOutcomeJSON{
				Group: "owner", Cases: map[string]lifecycleExpectJSON{
					"committed":                    {ErrorClass: "claim_already_terminal"},
					"error/claim_lease_lost":       recoveredA,
					"error/claim_already_terminal": recoveredA,
				}}},
			after("verify", "A", replayTerminal)},
	})
	sc(concurrencyScenarioJSON{
		Name:         "recovery_races_after_owner_committed",
		Description:  "the evaluator of request A committed an allow; after its lease would have expired, 4 direct recoveries and 2 recoveries through RecoverInterruptedClaim run concurrently (SPEC-v2 §7.5): every one is claim_already_terminal, so recovery never replaces a committed result and nothing reaches the receipt outbox twice",
		Setup:        []lifecycleStepJSON{step("verify", "A", committedAllow), setTime(Now + lifecycleLeaseSeconds)},
		Participants: []concurrencyParticipantJSON{recoverDirect(4), {Group: "helpers", Count: 2, Op: "recover", Request: "A"}},
		Invariants: []concurrencyInvariantJSON{
			allowed([]string{"error/claim_already_terminal"}), contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "A", replayTerminal), {lifecycleStepJSON: publish("A", 1)}},
	})
	sc(concurrencyScenarioJSON{
		Name:         "late_worker_finalize_after_recovery",
		Description:  "after the evaluator lease of request A expired, 2 late finalizations by the original evaluator race 3 recoveries through RecoverInterruptedClaim (SPEC-v2 §7.5, §7.9): every recovery returns the one evaluation_interrupted result and every late finalization fails, lease lost or already terminal; the result publishes once and releases as a non-actionable indeterminate",
		Setup:        []lifecycleStepJSON{claimOnly, setTime(Now + lifecycleLeaseSeconds)},
		Participants: []concurrencyParticipantJSON{owner(2), {Group: "recoverers", Count: 3, Op: "recover", Request: "A"}},
		Invariants: []concurrencyInvariantJSON{
			allowed([]string{"error/claim_lease_lost", "error/claim_already_terminal"}, "owner"),
			allowed([]string{interrupted}, "recoverers"),
			contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "A", replayTerminal), {lifecycleStepJSON: publish("A", 1)},
			release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now + lifecycleLeaseSeconds, ReceiptSeq: 1})},
	})
	sc(concurrencyScenarioJSON{
		Name:         "cancel_races_finalization",
		Description:  "the caller cancels a verification of request A while it runs (SPEC-v2 §6.11): before the claim nothing is consumed; after the claim nothing is committed and the claim stays in progress; a verification that committed reports committed. An exact retry agrees with the reported outcome in each case",
		Participants: []concurrencyParticipantJSON{verifiers("verifier", "A", 1), {Group: "canceller", Count: 1, Op: "cancel", Target: "verifier"}},
		Invariants: []concurrencyInvariantJSON{
			allowed([]string{allow, "preflight/evaluation_cancelled", "evaluating/evaluation_cancelled"}, "verifier"),
			contiguous,
		},
		After: []concurrencyStepJSON{{lifecycleStepJSON: lifecycleStepJSON{Op: "verify", Request: "A"}, ExpectByOutcome: &concurrencyExpectByOutcomeJSON{
			Group: "verifier", Cases: map[string]lifecycleExpectJSON{
				allow:                             replayTerminal,
				"evaluating/evaluation_cancelled": {Stage: "replay", Disposition: "in_progress"},
				"preflight/evaluation_cancelled":  committedAllow,
			}}}},
	})
	sc(concurrencyScenarioJSON{
		Name:         "concurrent_identical_retries",
		Description:  "6 identical finalizations by the owner of request A's claim race 4 exact retries of the proof (SPEC-v2 §7.3, §7.5): exactly one finalization commits, every other is identical, and every retry sees the claim in progress or terminal without evaluating",
		Setup:        []lifecycleStepJSON{claimOnly},
		Participants: []concurrencyParticipantJSON{owner(6), verifiers("retries", "A", 4)},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{"committed"}, "owner"), allowed([]string{"committed", "identical"}, "owner"),
			allowed([]string{terminal, inProgress}, "retries"), contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "A", replayTerminal)},
	})
	sc(concurrencyScenarioJSON{
		Name:         "concurrent_identical_recoveries",
		Description:  "6 identical direct recoveries of request A's claim after its lease expired (SPEC-v2 §7.5): exactly one commits and every other is identical; the recovery helper then returns the same result",
		Setup:        []lifecycleStepJSON{claimOnly, setTime(Now + lifecycleLeaseSeconds)},
		Participants: []concurrencyParticipantJSON{recoverDirect(6)},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{"committed"}), allowed([]string{"committed", "identical"}), contiguous,
		},
		After: []concurrencyStepJSON{after("recover", "A", recoveredA),
			{lifecycleStepJSON: publish("A", 1)}},
	})
	released := "released/allow/1800000000/1"
	withheld := true
	sc(concurrencyScenarioJSON{
		Name:        "release_while_acknowledgement_lands",
		Description: "6 releases of one committed allow run while its receipt's acknowledgement lands (SPEC-v2 §6.9, §7.8): each release is pending before the acknowledgement or released after it, every released result is the same (decision, release time, receipt sequence), and a release afterwards returns it again",
		Setup:       []lifecycleStepJSON{{Op: "set_ack_withheld", Withheld: &withheld}, step("verify", "A", committedAllow), publish("A", 1)},
		Participants: []concurrencyParticipantJSON{{Group: "releasers", Count: 6, Op: "release", Request: "A"},
			{Group: "acknowledger", Count: 1, Op: "acknowledge", Request: "A"}},
		Invariants: []concurrencyInvariantJSON{
			allowed([]string{"pending/acknowledgement_unavailable", released}, "releasers"),
			allowed([]string{"acknowledged/1800000000"}, "acknowledger"), contiguous,
		},
		After: []concurrencyStepJSON{release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "allow", ReleaseTime: Now, ReceiptSeq: 1})},
	})
	sc(concurrencyScenarioJSON{
		Name:         "concurrent_release_of_one_decision",
		Description:  "8 concurrent releases of one acknowledged allow (SPEC-v2 §6.9): the first release record wins and every release returns the same released result",
		Setup:        []lifecycleStepJSON{step("verify", "A", committedAllow), publish("A", 1)},
		Participants: []concurrencyParticipantJSON{{Group: "releasers", Count: 8, Op: "release", Request: "A"}},
		Invariants: []concurrencyInvariantJSON{
			{Kind: "all_equal", Groups: []string{"releasers"}}, allowed([]string{released}), contiguous,
		},
	})
	sc(concurrencyScenarioJSON{
		Name:         "concurrent_stream_advances",
		Description:  "after stream sequence 1, 3 verifications each of two different proofs carrying stream_seq 2 run concurrently (SPEC-v2 §7.4): claims are serialized per stream key, so one proof commits once and every verification of the other fails before claim with stream_sequence_mismatch; the stream then accepts only sequence 3",
		Setup:        []lifecycleStepJSON{step("verify", "S1", committedAllow)},
		Participants: []concurrencyParticipantJSON{verifiers("s2", "S2", 3), verifiers("s2b", "S2b", 3)},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{allow}),
			{Kind: "one_winner", Winning: []string{allow}, ByGroup: map[string]concurrencyGroupOutcomesJSON{
				"s2":  {IfWinner: winners, IfLoser: []string{"preflight/stream_sequence_mismatch"}},
				"s2b": {IfWinner: winners, IfLoser: []string{"preflight/stream_sequence_mismatch"}},
			}},
			contiguous,
		},
		After: []concurrencyStepJSON{after("verify", "S4", lifecycleExpectJSON{Stage: "preflight", ErrorClass: "stream_sequence_mismatch"}),
			after("verify", "S3", committedAllow)},
	})
	rateGroups := []string{"r1", "r2", "r3", "r4"}
	rateInvariants := []concurrencyInvariantJSON{
		count(2, []string{allow}), count(2, []string{rateDenied}), allowed([]string{allow, rateDenied, terminal, inProgress}),
	}
	for _, g := range rateGroups {
		rateInvariants = append(rateInvariants, count(1, []string{allow, rateDenied}, g))
	}
	sc(concurrencyScenarioJSON{
		Name:               "rate_admission_under_contention",
		Description:        "with max_rate admitted inside the finalization compare-and-set, 2 verifications each of four different proofs sharing a 2-per-60-second counter run concurrently (SPEC-v2 §7.6): each proof commits once, exactly 2 are admitted as allows and the other 2 commit constraint_denied, so the counter equals the committed allows",
		RateAtFinalization: true,
		Participants:       []concurrencyParticipantJSON{verifiers("r1", "R1", 2), verifiers("r2", "R2", 2), verifiers("r3", "R3", 2), verifiers("r4", "R4", 2)},
		Invariants:         append(rateInvariants, contiguous),
	})
	sc(concurrencyScenarioJSON{
		Name:               "rate_two_counter_admission_under_contention",
		Description:        "two proofs whose one sealed batch has two counters (2 per 120 seconds and 1 per 60 seconds) are verified concurrently, twice each (SPEC-v2 §7.6): exactly one is admitted and the other is denied by the 60-second counter alone; admission is all or none, so the denied one did not count against the 120-second counter and T3 at Now+60 is admitted",
		RateAtFinalization: true,
		Participants:       []concurrencyParticipantJSON{verifiers("t1", "T1", 2), verifiers("t2", "T2", 2)},
		Invariants: []concurrencyInvariantJSON{
			count(1, []string{allow}), count(1, []string{rateDenied}), allowed([]string{allow, rateDenied, terminal, inProgress}),
			count(1, []string{allow, rateDenied}, "t1"), count(1, []string{allow, rateDenied}, "t2"), contiguous,
		},
		After: []concurrencyStepJSON{{lifecycleStepJSON: setTime(Now + 60)}, after("verify", "T3", committedAllow)},
	})
	// SPEC-v2 §7.11: resumption reads the committed record and never builds,
	// re-evaluates or replaces a result, so a resume racing a commit either
	// sees the claim still evaluating or returns exactly the committed result.
	finalized := "committed/indeterminate/status_unavailable"
	resumers := func(n int, mode string) concurrencyParticipantJSON {
		return concurrencyParticipantJSON{Group: "resumers", Count: n, Op: "resume", Request: "A", Mode: mode}
	}
	sc(concurrencyScenarioJSON{
		Name:         "resume_races_owner_finalize",
		Description:  "the evaluator of request A finalizes indeterminate/status_unavailable while 6 resumptions of its claim run (SPEC-v2 §7.11): each resumption sees the claim evaluating under its live lease (claim_lease_live) or returns exactly the finalized result, never another; the finalized result then resumes, publishes at sequence 1 and releases",
		Setup:        []lifecycleStepJSON{claimOnly},
		Participants: []concurrencyParticipantJSON{owner(1), resumers(6, "")},
		Invariants: []concurrencyInvariantJSON{
			allowed([]string{"committed"}, "owner"),
			allowed([]string{"error/claim_lease_live", finalized}, "resumers"), contiguous,
		},
		After: []concurrencyStepJSON{after("resume", "A", lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "status_unavailable"}),
			{lifecycleStepJSON: publish("A", 1)},
			release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: Now, ReceiptSeq: 1}),
			after("verify", "A", replayTerminal)},
	})
	sc(concurrencyScenarioJSON{
		Name:        "resume_races_lease_expiry_recovery",
		Description: "the clock of request A's claimed but never evaluated claim reaches its lease expiry while 3 recoveries through RecoverInterruptedClaim and 6 resumptions run (SPEC-v2 §7.5, §7.11): a resumption sees the claim evaluating with its lease live (claim_lease_live) or lost (claim_lease_lost), or returns exactly the recovered evaluation_interrupted result; a recovery is refused while the lease is live or returns that result; afterwards the one result resumes and publishes at sequence 1",
		Setup:       []lifecycleStepJSON{claimOnly},
		Participants: []concurrencyParticipantJSON{resumers(6, ""), {Group: "recoverers", Count: 3, Op: "recover", Request: "A"},
			{Group: "clock", Count: 1, Op: "set_time", Time: Now + lifecycleLeaseSeconds}},
		Invariants: []concurrencyInvariantJSON{
			allowed([]string{"error/claim_lease_live", "error/claim_lease_lost", interrupted}, "resumers"),
			allowed([]string{"error/claim_lease_live", interrupted}, "recoverers"), contiguous,
		},
		After: []concurrencyStepJSON{after("recover", "A", recoveredA),
			after("resume", "A", lifecycleExpectJSON{Stage: "committed", Decision: "indeterminate", DecisionReason: "evaluation_interrupted"}),
			{lifecycleStepJSON: publish("A", 1)}, after("verify", "A", replayTerminal)},
	})
	sc(concurrencyScenarioJSON{
		Name:        "concurrent_resumes_and_releases_of_one_allow",
		Description: "request A committed an allow whose receipt is published and acknowledged; 6 participants each resume the claim and release the resumed handoff while 4 release the handoff the verifier returned (SPEC-v2 §6.9, §7.11): every resumption returns the committed allow, the first release record wins, every release returns the same released result, and a release afterwards returns it again",
		Setup:       []lifecycleStepJSON{step("verify", "A", committedAllow), publish("A", 1)},
		Participants: []concurrencyParticipantJSON{resumers(6, "release"),
			{Group: "releasers", Count: 4, Op: "release", Request: "A"}},
		Invariants: []concurrencyInvariantJSON{
			{Kind: "all_equal", Groups: []string{"resumers", "releasers"}}, allowed([]string{released}), contiguous,
		},
		After: []concurrencyStepJSON{after("resume", "A", committedAllow),
			release("A", lifecycleExpectJSON{ReleaseStatus: "released", Decision: "allow", ReleaseTime: Now, ReceiptSeq: 1})},
	})
	return f
}
