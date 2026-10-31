package v2vectors

type logStepJSON struct {
	Op      string `json:"op"`
	Label   string `json:"label"`
	WireB64 string `json:"wire_b64,omitempty"`
	Key     string `json:"key,omitempty"`
	LogID   string `json:"log_id,omitempty"`
	Expect  string `json:"expect"`
}

type logScenarioJSON struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Kind        string        `json:"kind"`
	VerifierID  string        `json:"verifier_id,omitempty"`
	LogID       string        `json:"initial_log_id"`
	Steps       []logStepJSON `json:"steps"`
}

type logFile struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	HeadRules   map[string]string `json:"head_rules"`
	Scenarios   []logScenarioJSON `json:"scenarios"`
}

func (g *gen) logFile() any {
	f := logFile{
		Version:     2,
		Description: "Witness-log and verification-receipt-log sequences (SPEC-v2 §5.6, §5.8). The harness keeps caller-authenticated head state starting at the genesis head for initial_log_id (sequence 0, 48 zero bytes, no accepted digests). Each verify step checks the entry with the step key against the current head.",
		HeadRules: map[string]string{
			"appended": "advance: sequence+1, head hash = StatementBodyDigest(code, entry body), record the digest at that sequence",
			"replay":   "exact accepted body digest at an accepted sequence; head unchanged",
			"log_fork": "a different body digest at an accepted sequence; the caller durably freezes the log",
			"error":    "any other expected error class leaves the head unchanged",
			"recover":  "start a new caller-authenticated log at log_id from the genesis head; the frozen log is not continued",
		},
	}
	w, attacker := g.k("witness"), g.k("attacker")
	steps := []logStepJSON{}
	v := func(label string, wire []byte, key, expect string) {
		steps = append(steps, logStepJSON{Op: "verify", Label: label, WireB64: b64(wire), Key: key, Expect: expect})
	}
	_, e1, s1 := g.witness(w, witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	d1 := statementBodyDigest(codeWitness, s1.signable)
	_, e1alt, _ := g.witness(w, witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0x55)
	_, e2, s2 := g.witness(w, witnessLogA, 2, d1, "entry-2", Now-10, "", 0)
	d2 := statementBodyDigest(codeWitness, s2.signable)
	_, e2orphan, _ := g.witness(w, witnessLogA, 2, flipBytes(d1), "entry-2", Now-10, "", 0)
	_, e3gap, _ := g.witness(w, witnessLogA, 3, d1, "entry-3", Now-5, "", 0)
	_, e3, _ := g.witness(w, witnessLogA, 3, d2, "entry-3", Now-5, "", 0)
	_, e1fork, _ := g.witness(w, witnessLogA, 1, make([]byte, 48), "entry-1-forked", Now-20, "", 0)
	_, b1, _ := g.witness(w, witnessLogB, 1, make([]byte, 48), "entry-b1", Now-1, "", 0)
	_, impostor, _ := g.witness(attacker, witnessLogA, 2, d1, "entry-2", Now-10, "", 0)
	v("genesis", e1, "witness", "appended")
	v("exact_replay", e1, "witness", "replay")
	v("same_body_new_signature_bytes", e1alt, "witness", "replay")
	v("gap", e3gap, "witness", "log_gap")
	v("orphan_wrong_predecessor", e2orphan, "witness", "log_orphan")
	v("cross_log_replay", b1, "witness", "log_state_mismatch")
	v("other_witness_key", impostor, "witness", "log_state_mismatch")
	v("next", e2, "witness", "appended")
	v("fork_at_accepted_sequence", e1fork, "witness", "log_fork")
	v("frozen_log_rejects_next", e3, "witness", "log_frozen")
	steps = append(steps, logStepJSON{Op: "recover", Label: "recover_to_new_log", LogID: witnessLogB, Expect: "recovered"})
	v("new_log_genesis", b1, "witness", "appended")
	f.Scenarios = append(f.Scenarios, logScenarioJSON{Name: "witness_log", Description: "append, idempotent replay, gap, orphan, cross-log replay, fork freeze, and recovery to a new log ID", Kind: "witness_entry", LogID: witnessLogA, Steps: steps})

	verifier := g.k("verifier")
	steps = []logStepJSON{}
	body := g.receiptFixtureBody()
	body2 := *body
	body2.VerifiedAt = Now + 1
	forkBody := *body
	forkBody.VerifiedAt = Now + 7
	_, r1, rs1 := g.receipt(verifier, body, receiptLogA, 1, make([]byte, 48), 0)
	rd1 := statementBodyDigest(codeReceipt, rs1.signable)
	_, r1alt, _ := g.receipt(verifier, body, receiptLogA, 1, make([]byte, 48), 0x66)
	_, r2, _ := g.receipt(verifier, &body2, receiptLogA, 2, rd1, 0)
	_, r2orphan, _ := g.receipt(verifier, &body2, receiptLogA, 2, flipBytes(rd1), 0)
	_, r3gap, _ := g.receipt(verifier, &body2, receiptLogA, 3, rd1, 0)
	_, r1fork, _ := g.receipt(verifier, &forkBody, receiptLogA, 1, make([]byte, 48), 0)
	substituted := *body
	substituted.VerifierID = attacker.ID
	substituted.AgentID = g.k("agent").ID
	_, rSub, _ := g.receipt(attacker, &substituted, receiptLogA, 1, make([]byte, 48), 0)
	rv := func(label string, wire []byte, expect string) {
		steps = append(steps, logStepJSON{Op: "verify", Label: label, WireB64: b64(wire), Key: "verifier", Expect: expect})
	}
	rv("genesis", r1, "appended")
	rv("exact_retry_after_signed_append", r1, "replay")
	rv("same_body_new_signature_bytes", r1alt, "replay")
	rv("key_substitution", rSub, "log_state_mismatch")
	rv("gap", r3gap, "log_gap")
	rv("orphan_wrong_predecessor", r2orphan, "log_orphan")
	rv("next", r2, "appended")
	rv("fork_at_accepted_sequence", r1fork, "log_fork")
	steps = append(steps, logStepJSON{Op: "recover", Label: "recover_to_new_log", LogID: "cccccccccccccccccccccccccccccc02", Expect: "recovered"})
	_, rNew, _ := g.receipt(verifier, body, "cccccccccccccccccccccccccccccc02", 1, make([]byte, 48), 0)
	rv("new_log_genesis", rNew, "appended")
	rv("old_log_entry_after_recovery", r2, "log_state_mismatch")
	f.Scenarios = append(f.Scenarios, logScenarioJSON{Name: "verification_receipt_log", Description: "receipt idempotency by body digest, key substitution, gap, orphan, fork freeze, and recovery to a new log ID pinned to one verifier ID", Kind: "verification_receipt", VerifierID: verifier.ID, LogID: receiptLogA, Steps: steps})
	return f
}

func flipBytes(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 1
	return out
}
