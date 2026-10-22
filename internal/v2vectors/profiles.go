package v2vectors

// Part B profile scenarios (SPEC-v2 §7.13 single-device offline profile and
// §7.14 dual-root composition profile), written into the profile_scenarios
// member of lifecycle-scenarios.json. They replay against the in-memory
// reference store plus a test-only component: the device scenarios use an
// independent monotonic authenticated checkpoint component on the same
// device, and the dual-root scenarios use an application approval ledger.
// Expected outcomes are written from the spec rules here.

import ratify "github.com/identities-ai/ratify-protocol/v2"

type profileExpectJSON struct {
	lifecycleExpectJSON
	DeviceStatus   string  `json:"device_status,omitempty"`
	DeviceError    string  `json:"device_error,omitempty"`
	Acknowledged   []int64 `json:"acknowledged,omitempty"`
	AckTime        int64   `json:"ack_time,omitempty"`
	Uploaded       []int64 `json:"uploaded,omitempty"`
	LedgerComplete bool    `json:"ledger_complete,omitempty"`
	LedgerError    string  `json:"ledger_error,omitempty"`
	Executed       int     `json:"executed,omitempty"`
}

type approvalSetJSON struct {
	ID             string    `json:"id"`
	VerifierID     string    `json:"verifier_id"`
	WorkspaceID    string    `json:"workspace_id"`
	SessionID      string    `json:"session_id"`
	AgentKey       string    `json:"agent_key"`
	RequiredScope  string    `json:"required_scope"`
	RequestHashB64 string    `json:"request_hash_b64"`
	RootKeys       [2]string `json:"root_keys"`
	// SessionContextB64 is the context the ledger must derive (§2.4 with
	// invocation_id = id); it is a known answer, never a ledger input.
	SessionContextB64 string `json:"session_context_b64"`
}

type profileStepJSON struct {
	Op          string            `json:"op"`
	Request     string            `json:"request,omitempty"`
	Requests    []string          `json:"requests,omitempty"`
	Time        int64             `json:"time,omitempty"`
	Withheld    *bool             `json:"withheld,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Checkpoint  string            `json:"checkpoint,omitempty"`
	Snapshot    string            `json:"snapshot,omitempty"`
	Sequence    int64             `json:"sequence,omitempty"`
	Slot        *int              `json:"slot,omitempty"`
	Set         string            `json:"set,omitempty"`
	Count       int               `json:"count,omitempty"`
	ApprovalSet *approvalSetJSON  `json:"approval_set,omitempty"`
	Expect      profileExpectJSON `json:"expect"`
}

type deviceConfigJSON struct {
	ComponentSeedB64 string `json:"component_seed_b64"`
	Capacity         int    `json:"capacity"`
	ReplayEpoch      int64  `json:"replay_epoch"`
}

type profileScenarioJSON struct {
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Profile            string            `json:"profile"`
	StartTime          int64             `json:"start_time"`
	RateAtFinalization bool              `json:"rate_at_finalization,omitempty"`
	Device             *deviceConfigJSON `json:"device,omitempty"`
	Steps              []profileStepJSON `json:"steps"`
}

// profileRequestSpec describes one profile request. Zero values select the
// lifecycle defaults: challenge issued at Now-10, the default chain rooted at
// root, and the fixture session context.
type profileRequestSpec struct {
	challenge   byte
	challengeAt int64
	certs       []ratify.DelegationCertV2
	session     []byte
	trustRoot   string
	edit        func(*scenario)
}

func (g *gen) profileRequest(p profileRequestSpec) (orderingVector, []byte) {
	agent := g.k("agent")
	if p.challengeAt == 0 {
		p.challengeAt = Now - 10
	}
	if p.certs == nil {
		p.certs = g.chain(chainSpec{})
	}
	if p.session == nil {
		p.session = g.fixtureSessionContext(agent)
	}
	if p.trustRoot == "" {
		p.trustRoot = "root"
	}
	challenge := defaultChallenge()
	challenge[0] = p.challenge
	_, bundle, _ := g.bundle(bundleSpec{agent: agent, certs: p.certs, session: p.session, challenge: challenge, challengeAt: p.challengeAt})
	expected := g.defaultExpected(agent, p.session)
	expected.ValueB64 = b64(challenge)
	expected.IssuedAt, expected.ExpiresAt = p.challengeAt, p.challengeAt+300
	evidence := g.currentEvidenceBatches(p.certs)
	if root := g.k("untrusted_root"); p.certs[len(p.certs)-1].IssuerID == root.ID {
		_, wire, _ := g.list(g.k("status_party_b"), root.ID, 1, Now-60, Now+3600)
		evidence[root.ID] = evidenceBatch(evidenceObjectJSON{ObjectTypeCode: int(codeList), WireB64: b64(wire)})
	}
	s := scenario{bundle: bundle, certs: p.certs, scope: "data:read", expected: expected, policy: g.verifyPolicyJSON(p.session),
		trust: g.trustRoot(p.trustRoot), evidence: evidence, claim: "reference", out: outcomeJSON{Stage: "lifecycle"}}
	if p.edit != nil {
		p.edit(&s)
	}
	v := g.finish(s)
	v.Expected = outcomeJSON{}
	return v, bundle
}

func (g *gen) addProfileScenarios(f *lifecycleFile, add func(string, orderingVector, []byte)) {
	f.Semantics["profile_scenarios"] = "SPEC-v2 §7.13 and §7.14 profile scripts. Each starts from a fresh reference store (as for scenarios) and adds the test-only component its profile names. Steps use the lifecycle ops (set_time, set_ack_withheld, verify, publish, release) plus the profile ops below; release checkpoint device = the device component, reference = the store checkpoint"
	f.Semantics["profile single_device_offline"] = "the primary is the reference store plus an anchored SecurityJournalV2 store, a challenge issuance store, and device.replay_epoch; its complete-state digest is SHA-384 over the versioned canonical projection of SPEC-v2 §7.13. The store never acknowledges its own entries; the checkpoint is an independent monotonic authenticated component on the same device (seed and capacity from device) that is provisioned with the primary's initial digest, anchors the primary's new complete-state digest before every durable security-state change takes effect (a change whose previous digest differs from the anchored one is refused and undone, so a verify fails before claim with claim_store_unavailable), records per receipt-log entry the entry hash and the anchored digest, signs every acknowledgement with its own key, and reads the same security clock as the store. rate_at_finalization makes the store admit max_rate inside finalization, as in scenarios"
	f.Semantics["device_submit"] = "submit, in log order, every appended entry of the primary that the component has not acknowledged with the same entry hash; expect acknowledged (the sequences acknowledged by this call) and device_error for the failure that stopped it: power_loss, storage_full, state_mismatch (the submission does not extend the head or its state is not the anchored state), frozen (a different entry at an acknowledged sequence; the component freezes), or clock_regressed"
	f.Semantics["device_resubmit"] = "retry the exact tuple for sequence; expect ack_time (the original acknowledgement time on an identical retry) or device_error"
	f.Semantics["device_power_loss"] = "arm a power loss for the next submission only: before_commit records nothing; after_commit records the acknowledgement durably but loses the response"
	f.Semantics["device_startup"] = "before serving, check in order: a frozen component (checkpoint_frozen); fewer appended receipt-log entries than the component acknowledged (primary_behind: rollback or lost state); a recomputed complete-state digest that differs from the anchored one (state_digest_mismatch, including a rollback that kept the receipt-log prefix); otherwise ready"
	f.Semantics["snapshot"] = "copy the complete primary state (store, journal, issuance records) under snapshot"
	f.Semantics["restore"] = "mode snapshot = replace the primary with the named copy (a rollback) and bind it to the same component without provisioning; the component and the clock are unchanged"
	f.Semantics["stage_status"] = "stage the request's status keys (configured in ascending issuer order) and journal preload into the primary's anchored SecurityJournalV2 store, as before disconnection; each journal transition is anchored"
	f.Semantics["corrupt_state"] = "alter one byte of the request's sealed terminal result in the primary store"
	f.Semantics["upload"] = "outbox upload after reconnection: send each signed receipt of the component-acknowledged prefix once, in log order; expect uploaded. Upload never releases or changes a release"
	f.Semantics["profile dual_root"] = "one verifier and receipt log; each request pins exactly one trusted root. An application approval ledger records released decisions per approval set"
	f.Semantics["ledger_open"] = "open approval_set: agent_key and root_keys name keys.json fixture keys whose complete public keys the set pins (roots in slot order); request_hash_b64 is the action's operation-context hash. The ledger derives the expected session context from verifier_id, workspace_id, the agent key ID, session_id, invocation_id = id, and request_hash (§2.4); session_context_b64 is that derivation as a known answer and is never a ledger input. Expect ledger_error approval_set_invalid when the set is malformed or names one root key twice"
	f.Semantics["ledger_record"] = "record the request's released decision (from its last release step; none if that release was not released) and its exact bundle in slot of set (default: the last set opened). Checks in order: not_released (not a released allow); action_mismatch (receipt bundle_hash differs from the bundle); approval_reused (the claim is already recorded in another approval set); action_mismatch (receipt or bundle verifier, receipt or bundle agent ID, bundle agent key, receipt required scope, or bundle session_context differs from the set and its derived context); root_mismatch (the chain's terminal issuer key is not the slot's pinned root key, or the receipt's issuer_ids omit it); slot_filled. Expect ledger_complete or that ledger_error"
	f.Semantics["ledger_record_concurrent"] = "record requests[i] in slot i concurrently; expect ledger_complete for the final state"
	f.Semantics["ledger_execute"] = "atomically mark set (default: the last set opened) executed at the store clock; expect ledger_error incomplete, expired (an approval is no longer Allowed), already_executed, or none"
	f.Semantics["ledger_execute_concurrent"] = "count concurrent executions of the set; expect executed, the number that succeeded"

	agent := g.k("agent")
	// Single-device offline profile requests.
	for _, r := range []struct {
		name      string
		challenge byte
	}{{"D1", 0xd1}, {"D2", 0xd2}} {
		v, bundle := g.profileRequest(profileRequestSpec{challenge: r.challenge})
		add(r.name, v, bundle)
	}
	// DS: status staged into the anchored journal before disconnection (at
	// Now); offline, the providers return nothing new, and the challenge is
	// issued when the staged lists reach next_update.
	st := g.statusFixtures()
	staged := func(s *scenario) {
		s.journal.Preload = []journalPreloadJSON{g.preload(st["root_current"], Now), g.preload(st["intermediate_current"], Now)}
		for issuer := range s.evidence {
			s.evidence[issuer] = evidenceBatch()
		}
	}
	ds, dsBundle := g.profileRequest(profileRequestSpec{challenge: 0xd5, challengeAt: statusFreshUntil - 10, edit: staged})
	add("DS", ds, dsBundle)

	// Dual-root requests. Both approvals bind one action and the approval set
	// through the session context: invocation_id is the approval set ID and
	// request_hash is the action's operation-context hash.
	const approvalSetID = "approval-set-01"
	actionPayload := make([]byte, 32)
	for i := range actionPayload {
		actionPayload[i] = 0x44
	}
	const approvalSession = "approval-session-01"
	actionHash := func(payload []byte) []byte {
		return operationContextHash("data:read", "records.export", "batch/7", "/v1/batches/7", payload)
	}
	setContext := func(payload []byte) []byte {
		return sessionContext(g.k("verifier").ID, fixtureWorkspace, agent.ID, approvalSession, approvalSetID, actionHash(payload))
	}
	action := setContext(actionPayload)
	otherPayload := make([]byte, 32)
	for i := range otherPayload {
		otherPayload[i] = 0x45
	}
	// swappedVerifier is the action's context derived for another verifier ID.
	swappedVerifier := sessionContext(g.k("attacker").ID, fixtureWorkspace, agent.ID, approvalSession, approvalSetID, actionHash(actionPayload))
	chainA, chainB := g.chain(chainSpec{}), g.chain(chainSpec{root: g.k("untrusted_root")})
	for _, r := range []struct {
		name      string
		challenge byte
		certs     []ratify.DelegationCertV2
		session   []byte
		trust     string
	}{
		{"RA", 0xa1, chainA, action, "root"},
		{"RA2", 0xa2, chainA, action, "root"},
		{"RB", 0xb1, chainB, action, "untrusted_root"},
		// RBr reuses RA's challenge with a root B proof: a replay.
		{"RBr", 0xa1, chainB, action, "untrusted_root"},
		// RBm approves a different action under its own challenge.
		{"RBm", 0xb2, chainB, setContext(otherPayload), "untrusted_root"},
		// RAv approves the action under a context derived for another verifier.
		{"RAv", 0xa3, chainA, swappedVerifier, "root"},
	} {
		v, bundle := g.profileRequest(profileRequestSpec{challenge: r.challenge, certs: r.certs, session: r.session, trustRoot: r.trust})
		add(r.name, v, bundle)
	}
	newSet := func(id, verifier string, payload []byte) *approvalSetJSON {
		request := actionHash(payload)
		return &approvalSetJSON{ID: id, VerifierID: g.k(verifier).ID, WorkspaceID: fixtureWorkspace, SessionID: approvalSession, AgentKey: "agent",
			RequiredScope: "data:read", RequestHashB64: b64(request), RootKeys: [2]string{"root", "untrusted_root"},
			SessionContextB64: b64(sessionContext(g.k(verifier).ID, fixtureWorkspace, agent.ID, approvalSession, id, request))}
	}
	set := newSet(approvalSetID, "verifier", actionPayload)
	sameRootSet := *set
	sameRootSet.RootKeys = [2]string{"root", "root"}
	// secondSet is a different approval set for the same action.
	secondSet := newSet("approval-set-02", "verifier", actionPayload)
	// otherActionSet reuses the approval set ID with a different action.
	otherActionSet := newSet(approvalSetID, "verifier", otherPayload)
	// otherVerifierSet names a different verifier for the same action.
	otherVerifierSet := newSet(approvalSetID, "attacker", actionPayload)

	type ex = profileExpectJSON
	type le = lifecycleExpectJSON
	committedAllow := ex{lifecycleExpectJSON: le{Stage: "committed", Decision: "allow", DecisionReason: "authorized", AllowHorizon: statusFreshUntil}}
	released := func(t, seq int64) ex {
		return ex{lifecycleExpectJSON: le{ReleaseStatus: "released", Decision: "allow", ReleaseTime: t, ReceiptSeq: seq}}
	}
	releaseState := func(status, reason string) ex {
		return ex{lifecycleExpectJSON: le{ReleaseStatus: status, ReleaseReason: reason}}
	}
	step := func(op, request string, expect ex) profileStepJSON {
		return profileStepJSON{Op: op, Request: request, Expect: expect}
	}
	setTime := func(t int64) profileStepJSON { return profileStepJSON{Op: "set_time", Time: t} }
	verify := func(request string, expect ex) profileStepJSON { return step("verify", request, expect) }
	publish := func(request string, seq int64) profileStepJSON {
		return profileStepJSON{Op: "publish", Request: request, Mode: "ok", Expect: ex{lifecycleExpectJSON: le{ReceiptSeq: seq}}}
	}
	release := func(request, checkpoint string, expect ex) profileStepJSON {
		return profileStepJSON{Op: "release", Request: request, Checkpoint: checkpoint, Expect: expect}
	}
	submit := func(errClass string, acknowledged ...int64) profileStepJSON {
		return profileStepJSON{Op: "device_submit", Expect: ex{DeviceError: errClass, Acknowledged: acknowledged}}
	}
	startup := func(status string) profileStepJSON {
		return profileStepJSON{Op: "device_startup", Expect: ex{DeviceStatus: status}}
	}
	powerLoss := func(mode string) profileStepJSON { return profileStepJSON{Op: "device_power_loss", Mode: mode} }
	upload := func(seqs ...int64) profileStepJSON { return profileStepJSON{Op: "upload", Expect: ex{Uploaded: seqs}} }
	device := func(name, desc string, capacity int, steps ...profileStepJSON) {
		f.ProfileScenarios = append(f.ProfileScenarios, profileScenarioJSON{Name: name, Description: desc, Profile: "single_device_offline", StartTime: Now,
			Device: &deviceConfigJSON{ComponentSeedB64: b64(g.k("witness").EdSeed[:]), Capacity: capacity, ReplayEpoch: fixtureReplayEpoch}, Steps: steps})
	}

	device("device_release_requires_component_ack", "a committed and appended allow stays pending until the on-device component acknowledges it; the acknowledgement releases it and the uplink sends the receipt", 8,
		verify("D1", committedAllow), publish("D1", 1), release("D1", "device", releaseState("pending", "acknowledgement_unavailable")),
		submit("", 1), release("D1", "device", released(Now, 1)), upload(1))
	device("device_power_loss_before_ack", "power fails before the component commits: nothing is recorded and release stays pending; after restart the primary matches the component head and the retried submission releases at its own acknowledgement time", 8,
		verify("D1", committedAllow), publish("D1", 1), powerLoss("before_commit"), submit("power_loss"),
		release("D1", "device", releaseState("pending", "acknowledgement_unavailable")),
		setTime(Now+20), startup("ready"), submit("", 1), release("D1", "device", released(Now+20, 1)))
	device("device_power_loss_after_ack", "power fails after the component commits: the acknowledgement is durable though its response was lost, so release uses the original acknowledgement time and an identical resubmission returns the same acknowledgement", 8,
		verify("D1", committedAllow), publish("D1", 1), powerLoss("after_commit"), submit("power_loss"),
		setTime(Now+20), startup("ready"), release("D1", "device", released(Now, 1)),
		profileStepJSON{Op: "device_resubmit", Sequence: 1, Expect: ex{AckTime: Now}})
	claimRefused := ex{lifecycleExpectJSON: le{Stage: "preflight", ErrorClass: "claim_store_unavailable"}}
	snapshot := func(name string) profileStepJSON { return profileStepJSON{Op: "snapshot", Snapshot: name} }
	restore := func(name string) profileStepJSON {
		return profileStepJSON{Op: "restore", Mode: "snapshot", Snapshot: name}
	}
	device("device_primary_rollback", "the primary is restored to a state before an acknowledged entry: startup reports primary_behind, and the rolled-back primary cannot claim a challenge because its state does not extend the anchored state", 8,
		snapshot("before"),
		verify("D1", committedAllow), publish("D1", 1), submit("", 1), release("D1", "device", released(Now, 1)),
		restore("before"),
		startup("primary_behind"),
		verify("D2", claimRefused), submit(""), startup("primary_behind"))
	device("device_state_digest_mismatch", "the primary's sealed state changes outside an anchored change after acknowledgement: startup reports state_digest_mismatch and the primary cannot claim another challenge", 8,
		verify("D1", committedAllow), publish("D1", 1), submit("", 1),
		step("corrupt_state", "D1", ex{}), startup("state_digest_mismatch"),
		verify("D2", claimRefused), startup("state_digest_mismatch"))
	device("device_rollback_loses_consumed_challenge", "with the receipt log unchanged, a restore loses a later consumed challenge: the claim was anchored when it was made, so startup reports state_digest_mismatch and the challenge cannot be claimed again", 8,
		verify("D1", committedAllow), publish("D1", 1), submit("", 1), release("D1", "device", released(Now, 1)),
		snapshot("acknowledged"), verify("D2", committedAllow), startup("ready"),
		restore("acknowledged"), startup("state_digest_mismatch"),
		verify("D2", claimRefused), startup("state_digest_mismatch"))
	device("device_rollback_loses_stream_advance", "with the receipt log unchanged, a restore loses a stream advance from sequence 1 to 2: startup reports state_digest_mismatch and the lost sequence cannot be claimed again", 8,
		verify("S1", committedAllow), publish("S1", 1), submit("", 1),
		snapshot("acknowledged"), verify("S2", committedAllow), startup("ready"),
		restore("acknowledged"), startup("state_digest_mismatch"),
		verify("S2", claimRefused))
	device("device_rollback_loses_journal_state", "with the receipt log and claims unchanged, a restore rolls back status evidence staged into the anchored journal: startup reports state_digest_mismatch", 8,
		verify("D1", committedAllow), publish("D1", 1), submit("", 1),
		snapshot("acknowledged"), step("stage_status", "DS", ex{}), startup("ready"),
		restore("acknowledged"), startup("state_digest_mismatch"),
		verify("D2", claimRefused))
	device("device_checkpoint_storage_full", "a component with room for one acknowledgement refuses the second entry without overwriting the first: the second release stays pending and the first still releases", 1,
		verify("D1", committedAllow), verify("D2", committedAllow), publish("D1", 1), publish("D2", 2), submit("storage_full", 1),
		release("D2", "device", releaseState("pending", "acknowledgement_unavailable")), release("D1", "device", released(Now, 1)))
	device("device_staged_status_goes_stale", "status staged before disconnection supports an allow until its next_update; offline at that deadline the same staged evidence is stale, so the next decision is a non-actionable indeterminate", 8,
		verify("D1", committedAllow), publish("D1", 1), submit("", 1), release("D1", "device", released(Now, 1)),
		setTime(statusFreshUntil),
		verify("DS", ex{lifecycleExpectJSON: le{Stage: "committed", Decision: "indeterminate", DecisionReason: "status_stale"}}),
		publish("DS", 2), submit("", 2),
		release("DS", "device", ex{lifecycleExpectJSON: le{ReleaseStatus: "released", Decision: "indeterminate", ReleaseTime: statusFreshUntil, ReceiptSeq: 2}}))
	device("device_rtc_regression", "the device clock moves backward: the component cannot acknowledge, a new claim is refused, and a release reading below the acknowledgement time is withheld; once the clock recovers the entry releases at its acknowledgement time", 8,
		setTime(Now+10), verify("D1", committedAllow), publish("D1", 1), setTime(Now+5),
		submit("clock_regressed"), release("D1", "device", releaseState("pending", "acknowledgement_unavailable")),
		verify("D2", ex{lifecycleExpectJSON: le{Stage: "preflight", ErrorClass: "claim_store_unavailable"}}),
		setTime(Now+10), submit("", 1), setTime(Now+9), release("D1", "device", releaseState("withheld", "clock_regressed")),
		setTime(Now+11), release("D1", "device", released(Now+10, 1)))
	f.ProfileScenarios = append(f.ProfileScenarios, profileScenarioJSON{Name: "device_rollback_loses_rate_state",
		Description: "with max_rate admitted at finalization and the receipt log unchanged, a restore loses an admitted rate commit and its claim: startup reports state_digest_mismatch and the lost request cannot be admitted again",
		Profile:     "single_device_offline", StartTime: Now, RateAtFinalization: true,
		Device: &deviceConfigJSON{ComponentSeedB64: b64(g.k("witness").EdSeed[:]), Capacity: 8, ReplayEpoch: fixtureReplayEpoch},
		Steps: []profileStepJSON{verify("R1", committedAllow), publish("R1", 1), submit("", 1),
			snapshot("acknowledged"), verify("R2", committedAllow), startup("ready"),
			restore("acknowledged"), startup("state_digest_mismatch"),
			verify("R2", claimRefused)}})
	device("device_offline_recovery_upload", "while the uplink is down the device releases locally; the uplink later sends only the acknowledged prefix, each receipt once; a receipt acknowledged after its challenge expired is uploaded as evidence but stays withheld, because upload is an outbox operation and not a deferred release", 8,
		verify("D1", committedAllow), publish("D1", 1), submit("", 1), release("D1", "device", released(Now, 1)),
		verify("D2", committedAllow), publish("D2", 2), upload(1),
		setTime(Now+290), submit("", 2), release("D2", "device", releaseState("withheld", "challenge_expired")),
		upload(2), release("D2", "device", releaseState("withheld", "challenge_expired")), upload())

	slot := func(i int) *int { return &i }
	open := func(s *approvalSetJSON, errClass string) profileStepJSON {
		return profileStepJSON{Op: "ledger_open", ApprovalSet: s, Expect: ex{LedgerError: errClass}}
	}
	record := func(request string, i int, complete bool, errClass string) profileStepJSON {
		return profileStepJSON{Op: "ledger_record", Request: request, Slot: slot(i), Expect: ex{LedgerComplete: complete, LedgerError: errClass}}
	}
	execute := func(errClass string) profileStepJSON {
		return profileStepJSON{Op: "ledger_execute", Expect: ex{LedgerError: errClass}}
	}
	recordIn := func(setID, request string, i int, complete bool, errClass string) profileStepJSON {
		r := record(request, i, complete, errClass)
		r.Set = setID
		return r
	}
	executeIn := func(setID, errClass string) profileStepJSON {
		e := execute(errClass)
		e.Set = setID
		return e
	}
	approve := func(request string, seq int64) []profileStepJSON {
		return []profileStepJSON{verify(request, committedAllow), publish(request, seq), release(request, "reference", released(Now, seq))}
	}
	dual := func(name, desc string, steps ...[]profileStepJSON) {
		var all []profileStepJSON
		for _, s := range steps {
			all = append(all, s...)
		}
		f.ProfileScenarios = append(f.ProfileScenarios, profileScenarioJSON{Name: name, Description: desc, Profile: "dual_root", StartTime: Now, Steps: all})
	}
	one := func(s ...profileStepJSON) []profileStepJSON { return s }

	dual("dual_root_both_released_executes_once", "root A and root B each release an allow under their own challenge for the same action and approval set; the ledger is incomplete after one, executable after both, and executes once",
		one(open(set, "")), approve("RA", 1), one(record("RA", 0, false, ""), execute("incomplete")),
		approve("RB", 2), one(record("RB", 1, true, ""), execute(""), execute("already_executed")))
	dual("dual_root_one_root_missing", "only root A has approved: root A's decision cannot fill root B's slot and the action is not executable",
		one(open(set, "")), approve("RA", 1), one(record("RA", 0, false, ""), record("RA", 1, false, "root_mismatch"), execute("incomplete")))
	dual("dual_root_other_root_missing", "only root B has approved: the action is not executable",
		one(open(set, "")), approve("RB", 1), one(record("RB", 1, false, ""), execute("incomplete")))
	dual("dual_root_duplicate_root", "a set naming one root twice is invalid; a second, separately released approval chaining to root A does not count for root B",
		one(open(&sameRootSet, "approval_set_invalid"), open(set, "")), approve("RA", 1), approve("RA2", 2),
		one(record("RA", 0, false, ""), record("RA2", 1, false, "root_mismatch"), execute("incomplete")))
	dual("dual_root_replay", "a root B proof presented on root A's already claimed challenge is a replay before claim; the set stays incomplete",
		one(open(set, "")), approve("RA", 1), one(record("RA", 0, false, ""),
			verify("RBr", ex{lifecycleExpectJSON: le{Stage: "preflight", ErrorClass: "claim_replay"}}), execute("incomplete")))
	dual("dual_root_mismatched_action", "root B releases an allow for a different action under its own challenge; the ledger refuses it for this set",
		one(open(set, "")), approve("RA", 1), one(record("RA", 0, false, "")), approve("RBm", 2),
		one(record("RBm", 1, false, "action_mismatch"), execute("incomplete")))
	withheld := true
	notWithheld := false
	dual("dual_root_committed_unreleased", "root B's allow is committed and appended but never released (its acknowledgement arrives at challenge expiry); a committed outcome cannot fill a slot",
		one(open(set, "")), approve("RA", 1), one(record("RA", 0, false, ""),
			profileStepJSON{Op: "set_ack_withheld", Withheld: &withheld}, verify("RB", committedAllow), publish("RB", 2),
			release("RB", "reference", releaseState("pending", "acknowledgement_unavailable")), record("RB", 1, false, "not_released"), execute("incomplete"),
			setTime(Now+290), profileStepJSON{Op: "set_ack_withheld", Withheld: &notWithheld},
			release("RB", "reference", releaseState("withheld", "challenge_expired")), record("RB", 1, false, "not_released"), execute("incomplete")))
	dual("dual_root_concurrent_completion", "both approvals are recorded concurrently and eight concurrent executions race; exactly one executes",
		one(open(set, "")), approve("RA", 1), approve("RB", 2),
		one(profileStepJSON{Op: "ledger_record_concurrent", Requests: []string{"RA", "RB"}, Expect: ex{LedgerComplete: true}},
			profileStepJSON{Op: "ledger_execute_concurrent", Count: 8, Expect: ex{Executed: 1}}))
	dual("dual_root_expired_before_execution", "both approvals are recorded but the action is attempted at the challenge expiry; it is not executable",
		one(open(set, "")), approve("RA", 1), approve("RB", 2),
		one(record("RA", 0, false, ""), record("RB", 1, true, ""), setTime(Now+290), execute("expired")))
	dual("dual_root_cross_set_reuse", "two approval sets for the same action: the released approvals recorded in the first set cannot be recorded in the second, whose derived context differs and which refuses any claim already counted elsewhere; only the first set executes",
		one(open(set, ""), open(secondSet, "")), approve("RA", 1), approve("RB", 2),
		one(recordIn(approvalSetID, "RA", 0, false, ""), recordIn(approvalSetID, "RB", 1, true, ""),
			recordIn("approval-set-02", "RA", 0, false, "approval_reused"), recordIn("approval-set-02", "RB", 1, false, "approval_reused"),
			executeIn("approval-set-02", "incomplete"), executeIn(approvalSetID, "")))
	dual("dual_root_same_set_different_action", "a set with the same approval_set_id, verifier, session and agent but a different action request hash derives a different context: approvals released for the first action do not fill it",
		one(open(otherActionSet, "")), approve("RA", 1), approve("RB", 2),
		one(record("RA", 0, false, "action_mismatch"), record("RB", 1, false, "action_mismatch"), execute("incomplete")))
	dual("dual_root_swapped_verifier", "a root A approval whose session context was derived for a different verifier ID is refused although the receipt's verifier is correct; the approval for the derived context fills the slot",
		one(open(set, "")), approve("RAv", 1), approve("RA", 2),
		one(record("RAv", 0, false, "action_mismatch"), record("RA", 0, false, ""), execute("incomplete")))
	dual("dual_root_set_names_other_verifier", "a set naming a different verifier derives a different context and does not match the receipts' verifier: released approvals for this verifier do not fill it",
		one(open(otherVerifierSet, "")), approve("RA", 1), approve("RB", 2),
		one(record("RA", 0, false, "action_mismatch"), record("RB", 1, false, "action_mismatch"), execute("incomplete")))
}
