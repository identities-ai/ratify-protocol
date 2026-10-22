package v2vectors

type rotationStepJSON struct {
	Op               string `json:"op"`
	Label            string `json:"label"`
	WireB64          string `json:"wire_b64,omitempty"`
	Now              int64  `json:"now,omitempty"`
	NewRecoveryEpoch int64  `json:"new_recovery_epoch,omitempty"`
	NewGenesisKey    string `json:"new_genesis_key,omitempty"`
	Expect           string `json:"expect"`
	ExpectSequence   int64  `json:"expect_sequence"`
	ExpectCurrentKey string `json:"expect_current_key"`
	ExpectEpoch      int64  `json:"expect_recovery_epoch"`
	ExpectFrozen     bool   `json:"expect_frozen"`
}

type rotationScenarioJSON struct {
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	AuthorityID   string             `json:"authority_id"`
	RecoveryEpoch int64              `json:"recovery_epoch"`
	Role          string             `json:"role"`
	GenesisKey    string             `json:"genesis_key"`
	FutureSkew    int64              `json:"future_skew_seconds"`
	Steps         []rotationStepJSON `json:"steps"`
}

type rotationFile struct {
	Version     int                    `json:"version"`
	Description string                 `json:"description"`
	Operations  map[string]string      `json:"operations"`
	Scenarios   []rotationScenarioJSON `json:"scenarios"`
}

func (g *gen) rotationFile() any {
	f := rotationFile{
		Version:     2,
		Description: "Key-rotation continuity sequences (SPEC-v2 §5.5 AcceptRotation). Initial state: sequence 0, 48 zero head bytes, current key = genesis_key, used key IDs = {genesis_key}, not frozen. After every step the harness asserts sequence, current key, recovery epoch, and frozen flag.",
		Operations: map[string]string{
			"accept":  "AcceptRotation(statement, state, now): appended advances the head; replay is an accepted body digest at its sequence (new signature bytes over that body are the same statement); rotation_fork freezes the authority and the frozen state is persisted; any other error leaves state unchanged",
			"recover": "root-authorized recovery from the caller's control plane: increment recovery_epoch, anchor a new genesis to an unused key, retain the full used-key history, clear frozen",
		},
	}
	gen1, second, third, recovery, attacker := g.k("rotation_genesis"), g.k("rotation_second"), g.k("rotation_third"), g.k("rotation_recovery"), g.k("attacker")
	_, s1, sg1, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: gen1, newKey: second})
	d1 := statementBodyDigest(codeRotationOld, sg1)
	_, s1alt, _, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: gen1, newKey: second, edNonceForOld: 0x77})
	_, s2, sg2, _, _ := g.rotation(rotationSpec{sequence: 2, prev: d1, oldKey: second, newKey: third})
	d2 := statementBodyDigest(codeRotationOld, sg2)
	_, s1fork, _, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: gen1, newKey: attacker})
	_, s3, _, _, _ := g.rotation(rotationSpec{sequence: 3, prev: d2, oldKey: third, newKey: g.k("intermediate_2")})
	_, r1, _, _, _ := g.rotation(rotationSpec{sequence: 1, epoch: 2, oldKey: recovery, newKey: g.k("intermediate_2")})
	_, s2skip, _, _, _ := g.rotation(rotationSpec{sequence: 3, prev: d1, oldKey: second, newKey: third})

	steps := []rotationStepJSON{}
	acc := func(label string, wire []byte, expect string, seq int64, current string, epoch int64, frozen bool) {
		steps = append(steps, rotationStepJSON{Op: "accept", Label: label, WireB64: b64(wire), Now: Now, Expect: expect, ExpectSequence: seq, ExpectCurrentKey: current, ExpectEpoch: epoch, ExpectFrozen: frozen})
	}
	rec := func(label string, epoch int64, key, expect string, seq int64, current string, wantEpoch int64, frozen bool) {
		steps = append(steps, rotationStepJSON{Op: "recover", Label: label, NewRecoveryEpoch: epoch, NewGenesisKey: key, Expect: expect, ExpectSequence: seq, ExpectCurrentKey: current, ExpectEpoch: wantEpoch, ExpectFrozen: frozen})
	}
	acc("genesis", s1, "appended", 1, "rotation_second", 1, false)
	acc("exact_repeat", s1, "replay", 1, "rotation_second", 1, false)
	acc("repeat_with_new_signature_bytes", s1alt, "replay", 1, "rotation_second", 1, false)
	acc("skips_a_sequence", s2skip, "rotation_state_mismatch", 1, "rotation_second", 1, false)
	acc("continuation", s2, "appended", 2, "rotation_third", 1, false)
	acc("fork_at_accepted_sequence", s1fork, "rotation_fork", 2, "rotation_third", 1, true)
	acc("frozen_rejects_next", s3, "rotation_frozen", 2, "rotation_third", 1, true)
	rec("recovery_without_epoch_increase", 1, "rotation_recovery", "rotation_recovery_invalid", 2, "rotation_third", 1, true)
	rec("recovery_to_used_key", 2, "rotation_second", "rotation_recovery_invalid", 2, "rotation_third", 1, true)
	rec("recovery", 2, "rotation_recovery", "recovered", 0, "rotation_recovery", 2, false)
	acc("old_epoch_statement_after_recovery", s1, "rotation_state_mismatch", 0, "rotation_recovery", 2, false)
	acc("new_epoch_genesis", r1, "appended", 1, "intermediate_2", 2, false)
	f.Scenarios = append(f.Scenarios, rotationScenarioJSON{Name: "continuity_fork_and_recovery", Description: "genesis, idempotent repeats, continuation, fork freeze, rejected recoveries, root-authorized recovery with an epoch increase", AuthorityID: rotationAuthority, RecoveryEpoch: 1, Role: "issuer", GenesisKey: "rotation_genesis", FutureSkew: 5, Steps: steps})
	return f
}
