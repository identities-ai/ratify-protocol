package v2vectors

import (
	"encoding/hex"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type statusPolicyJSON struct {
	MaxListLifetimeSeconds int64 `json:"max_list_lifetime_seconds"`
	MaxStatusAgeSeconds    int64 `json:"max_status_age_seconds"`
	ClockSkewSeconds       int64 `json:"clock_skew_seconds"`
}

// statusStateJSON lists only the asserted SPEC-v2 §5.4 state fields; an
// absent field is not asserted at that step.
type statusStateJSON struct {
	HasFloor                  *bool     `json:"has_floor,omitempty"`
	Floor                     *int64    `json:"floor,omitempty"`
	MaxObservedSequence       *int64    `json:"max_observed_sequence,omitempty"`
	ForkSequence              *int64    `json:"fork_sequence,omitempty"`
	ReconciliationRequired    *bool     `json:"reconciliation_required,omitempty"`
	FutureDatedObjectObserved *bool     `json:"future_dated_object_observed,omitempty"`
	AcceptedSet               *[]string `json:"accepted_set,omitempty"`
	DenyUnion                 *[]string `json:"deny_union,omitempty"`
}

type statusResultExpectJSON struct {
	Status   string         `json:"status"`
	Reason   string         `json:"reason,omitempty"`
	Evidence []EvidenceJSON `json:"evidence"`
}

type statusStepJSON struct {
	Op               string                  `json:"op"`
	Label            string                  `json:"label,omitempty"`
	WireB64          string                  `json:"wire_b64,omitempty"`
	StatusKey        string                  `json:"status_key"`
	StatusKeyEpoch   uint64                  `json:"status_key_epoch"`
	Now              int64                   `json:"now,omitempty"`
	CertID           string                  `json:"cert_id,omitempty"`
	Policy           *statusPolicyJSON       `json:"policy,omitempty"`
	ExpectErrorClass string                  `json:"expect_error_class,omitempty"`
	ExpectState      *statusStateJSON        `json:"expect_state,omitempty"`
	ExpectBodyDigest string                  `json:"expect_body_digest,omitempty"`
	ExpectResult     *statusResultExpectJSON `json:"expect_result,omitempty"`
}

type statusScenarioJSON struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	IssuerID    string           `json:"issuer_id"`
	Policy      statusPolicyJSON `json:"policy"`
	Steps       []statusStepJSON `json:"steps"`
}

type statusFile struct {
	Version     int                  `json:"version"`
	Description string               `json:"description"`
	Operations  map[string]string    `json:"operations"`
	Scenarios   []statusScenarioJSON `json:"scenarios"`
}

type statusObject struct {
	wire     []byte
	signable []byte
	code     uint16
	seq      int64
	key      string
}

type statusBuilder struct {
	g       *gen
	sc      statusScenarioJSON
	key     string
	epoch   uint64
	objects map[string]statusObject
}

func (g *gen) statusScenario(name, desc string) *statusBuilder {
	return &statusBuilder{g: g, key: "status_root", epoch: 1, objects: map[string]statusObject{}, sc: statusScenarioJSON{
		Name: name, Description: desc, IssuerID: g.k("root").ID,
		Policy: statusPolicyJSON{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 600, ClockSkewSeconds: 5},
	}}
}

func bp(v bool) *bool   { return &v }
func ip(v int64) *int64 { return &v }
func set(v ...string) *[]string {
	out := []string{}
	if v != nil {
		out = sortedStrings(v...)
	}
	return &out
}

// fresh list timing relative to Now: updated Now-60, next Now+1800.
func (b *statusBuilder) listAt(label string, seq, updated, next int64, revoked ...string) *statusBuilder {
	_, wire, sg := b.g.list(b.g.k(b.key), b.sc.IssuerID, seq, updated, next, revoked...)
	b.objects[label] = statusObject{wire, sg.signable, codeList, seq, b.key}
	return b
}

func (b *statusBuilder) list(label string, seq int64, revoked ...string) *statusBuilder {
	return b.listAt(label, seq, Now-60, Now+1800, revoked...)
}

func (b *statusBuilder) pushAt(label string, seq, pushedAt int64, edNonce byte, revoked ...string) *statusBuilder {
	p, wire, sg := b.g.push(b.g.k(b.key), b.sc.IssuerID, seq, pushedAt, revoked...)
	if edNonce != 0 {
		p.Signature.Ed25519 = ed25519WithNonce(b.g.k(b.key), message(codePush, sg.signable), edNonce)
		wire = must(ratify.EncodeRevocationPushV2(p))
	}
	b.objects[label] = statusObject{wire, sg.signable, codePush, seq, b.key}
	return b
}

func (b *statusBuilder) push(label string, seq int64, revoked ...string) *statusBuilder {
	return b.pushAt(label, seq, Now-30, 0, revoked...)
}

func (b *statusBuilder) apply(label string, now int64, expect *statusStateJSON) *statusBuilder {
	o := b.objects[label]
	op := "apply_list"
	if o.code == codePush {
		op = "apply_push"
	}
	b.sc.Steps = append(b.sc.Steps, statusStepJSON{Op: op, Label: label, WireB64: b64(o.wire), StatusKey: b.key, StatusKeyEpoch: b.epoch, Now: now, ExpectState: expect,
		ExpectBodyDigest: "sha384:" + hex.EncodeToString(sha384(o.signable))})
	return b
}

// applyUnrecorded applies an accepted object that adds no observation (a
// same-set heartbeat or a non-fresh snapshot), so no body digest is expected.
func (b *statusBuilder) applyUnrecorded(label string, now int64, expect *statusStateJSON) *statusBuilder {
	b.apply(label, now, expect)
	b.sc.Steps[len(b.sc.Steps)-1].ExpectBodyDigest = ""
	return b
}

func (b *statusBuilder) applyRejected(label, key string, epoch uint64, class string) *statusBuilder {
	o := b.objects[label]
	op := "apply_list"
	if o.code == codePush {
		op = "apply_push"
	}
	b.sc.Steps = append(b.sc.Steps, statusStepJSON{Op: op, Label: label, WireB64: b64(o.wire), StatusKey: key, StatusKeyEpoch: epoch, Now: Now, ExpectErrorClass: class})
	return b
}

func (b *statusBuilder) evidence(labels ...string) []EvidenceJSON {
	out := []EvidenceJSON{}
	for _, l := range labels {
		o := b.objects[l]
		out = append(out, EvidenceJSON{IssuerID: b.sc.IssuerID, StatusKeyID: b.g.k(o.key).ID, Sequence: o.seq, ObjectTypeCode: int(o.code), Digest: statusEvidenceDigest(o.code, o.wire)})
	}
	return sortEvidence(out)
}

func (b *statusBuilder) query(cert string, now int64, policy *statusPolicyJSON, status, reason string, evidence ...string) *statusBuilder {
	b.sc.Steps = append(b.sc.Steps, statusStepJSON{Op: "query", CertID: cert, StatusKey: b.key, StatusKeyEpoch: b.epoch, Now: now, Policy: policy,
		ExpectResult: &statusResultExpectJSON{Status: status, Reason: reason, Evidence: b.evidence(evidence...)}})
	return b
}

func (b *statusBuilder) transition(key string, epoch uint64, expect *statusStateJSON, class string) *statusBuilder {
	b.sc.Steps = append(b.sc.Steps, statusStepJSON{Op: "transition_epoch", StatusKey: key, StatusKeyEpoch: epoch, ExpectState: expect, ExpectErrorClass: class})
	if class == "" {
		b.key, b.epoch = key, epoch
	}
	return b
}

func st(hasFloor bool, floor, maxObs, fork int64, recon bool, accepted, deny []string) *statusStateJSON {
	return &statusStateJSON{HasFloor: bp(hasFloor), Floor: ip(floor), MaxObservedSequence: ip(maxObs), ForkSequence: ip(fork), ReconciliationRequired: bp(recon), AcceptedSet: set(accepted...), DenyUnion: set(deny...)}
}

func (g *gen) statusFile() any {
	f := statusFile{
		Version:     2,
		Description: "Issuer status reducer sequences (SPEC-v2 §5.4). Each scenario starts from empty state for issuer_id. Steps run in order against one reducer; a rejected step leaves state unchanged. expect_state asserts only the listed fields; accepted_set and deny_union are sorted certificate IDs. Query evidence uses the deterministic per-reference selection rules of SPEC-v2 §6.5.",
		Operations: map[string]string{
			"apply_list":       "verify the list under status_key bound to issuer_id at status_key_epoch, then apply it at time now",
			"apply_push":       "verify the push under status_key bound to issuer_id at status_key_epoch, then apply it at time now",
			"transition_epoch": "caller-authenticated status-key replacement to status_key at status_key_epoch",
			"query":            "StatusResult for CertificateRef(issuer_id, cert_id) at now, under the scenario policy unless policy overrides it",
		},
	}
	T := Now
	add := func(b *statusBuilder) { f.Scenarios = append(f.Scenarios, b.sc) }

	b := g.statusScenario("bootstrap_and_contiguous_push", "fresh snapshot bootstraps; a floor+1 push extends accepted state; an exact duplicate push is idempotent")
	b.list("L1", 1, "c1").apply("L1", T, st(true, 1, 1, 0, false, []string{"c1"}, []string{"c1"}))
	b.push("P2", 2, "c2").apply("P2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.pushAt("P2b", 2, Now-30, 0x33, "c2").apply("P2b", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.query("c2", T, nil, "revoked", "", "L1", "P2").query("c9", T, nil, "not_revoked", "", "L1", "P2")
	add(b)

	b = g.statusScenario("empty_revocation_accepted_base", "an empty accepted snapshot is retained as the accepted base and supports not_revoked")
	b.list("L1", 1).apply("L1", T, st(true, 1, 1, 0, false, nil, nil)).query("c9", T, nil, "not_revoked", "", "L1")
	add(b)

	b = g.statusScenario("gap_returns_indeterminate", "a push above floor+1 is a gap: indeterminate (never not_revoked) until a fresh full snapshot at or above max_observed_sequence reconciles it")
	b.list("L1", 1, "c1").apply("L1", T, st(true, 1, 1, 0, false, []string{"c1"}, []string{"c1"}))
	b.push("P3", 3, "c3").apply("P3", T, st(true, 1, 3, 0, true, []string{"c1"}, []string{"c1", "c3"}))
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1", "P3").query("c3", T, nil, "revoked", "", "L1", "P3").query("c1", T, nil, "revoked", "", "L1")
	b.list("L3", 3, "c1", "c3").apply("L3", T, st(true, 3, 3, 0, false, []string{"c1", "c3"}, []string{"c1", "c3"}))
	b.query("c9", T, nil, "not_revoked", "", "L3")
	add(b)

	b = g.statusScenario("push_before_bootstrap_and_bootstrap_below_observed", "a push before any snapshot is observed state only; a snapshot below the highest observed sequence cannot bootstrap; a later snapshot at that sequence can")
	b.push("P2", 2, "c2").apply("P2", T, &statusStateJSON{HasFloor: bp(false), MaxObservedSequence: ip(2), ReconciliationRequired: bp(true), DenyUnion: set("c2"), AcceptedSet: set()})
	b.query("c9", T, nil, "indeterminate", "unavailable", "P2")
	b.list("L1", 1).apply("L1", T, &statusStateJSON{HasFloor: bp(false), MaxObservedSequence: ip(2), ReconciliationRequired: bp(true), DenyUnion: set("c2"), AcceptedSet: set()})
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1", "P2")
	b.list("L2", 2, "c2").apply("L2", T, st(true, 2, 2, 0, false, []string{"c2"}, []string{"c2"}))
	b.query("c9", T, nil, "not_revoked", "", "L2")
	add(b)

	b = g.statusScenario("pre_bootstrap_push_then_same_sequence_snapshot", "a sequence-1 push before bootstrap never yields not_revoked; a fresh snapshot at that sequence containing it bootstraps")
	b.push("P1", 1, "c1").apply("P1", T, &statusStateJSON{HasFloor: bp(false), MaxObservedSequence: ip(1), DenyUnion: set("c1"), AcceptedSet: set()})
	b.sc.Steps = append(b.sc.Steps, statusStepJSON{Op: "query", CertID: "c9", StatusKey: b.key, StatusKeyEpoch: b.epoch, Now: T, ExpectResult: &statusResultExpectJSON{Status: "indeterminate", Reason: "unavailable", Evidence: b.evidence("P1")}})
	b.list("L1", 1, "c1").apply("L1", T, st(true, 1, 1, 0, false, []string{"c1"}, []string{"c1"}))
	b.query("c9", T, nil, "not_revoked", "", "L1")
	add(b)

	b = g.statusScenario("late_join_snapshot_bootstrap", "a verifier with no floor bootstraps from a fresh snapshot at a high sequence")
	b.list("L5", 5, "c1", "c4").apply("L5", T, st(true, 5, 5, 0, false, []string{"c1", "c4"}, []string{"c1", "c4"}))
	b.query("c4", T, nil, "revoked", "", "L5").query("c9", T, nil, "not_revoked", "", "L5")
	add(b)

	b = g.statusScenario("same_sequence_heartbeat_and_fork_after_bootstrap", "identical-set heartbeats refresh only forward in updated_at; a differing set at the floor is a fork that cannot self-reconcile; recovery requires a fresh snapshot above fork_sequence; replaying the fork marker after recovery is a no-op")
	b.listAt("L1a", 1, T-60, T+1800, "c1").apply("L1a", T, st(true, 1, 1, 0, false, []string{"c1"}, []string{"c1"}))
	b.listAt("L1b", 1, T-30, T+1800, "c1").apply("L1b", T, st(true, 1, 1, 0, false, []string{"c1"}, []string{"c1"}))
	b.query("c9", T, nil, "not_revoked", "", "L1b")
	b.listAt("L1c", 1, T-90, T+1800, "c1").applyUnrecorded("L1c", T, st(true, 1, 1, 0, false, []string{"c1"}, []string{"c1"}))
	b.query("c9", T, nil, "not_revoked", "", "L1b")
	b.listAt("L1d", 1, T-20, T+1800, "c1", "c2").apply("L1d", T, st(true, 1, 1, 1, true, []string{"c1"}, []string{"c1", "c2"}))
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1b", "L1d")
	b.apply("L1d", T, st(true, 1, 1, 1, true, []string{"c1"}, []string{"c1", "c2"}))
	b.list("L2", 2, "c1", "c2").apply("L2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.apply("L1d", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.query("c9", T, nil, "not_revoked", "", "L2")
	add(b)

	b = g.statusScenario("same_sequence_fork_before_bootstrap", "two authenticated snapshots at one sequence with different sets are a fork even before bootstrap")
	b.listAt("L1x", 1, T-7200, T-5400, "c1").apply("L1x", T, &statusStateJSON{HasFloor: bp(false), MaxObservedSequence: ip(1), ReconciliationRequired: bp(true), DenyUnion: set("c1")})
	b.list("L1y", 1, "c2").apply("L1y", T, &statusStateJSON{HasFloor: bp(false), MaxObservedSequence: ip(1), ForkSequence: ip(1), ReconciliationRequired: bp(true), DenyUnion: set("c1", "c2")})
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1x", "L1y")
	b.list("L2", 2, "c1", "c2").apply("L2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	add(b)

	b = g.statusScenario("push_then_snapshot_same_sequence", "push at S followed by a snapshot at S that equals the cumulative set is consistent")
	b.list("L1", 1, "c1").apply("L1", T, nil).push("P2", 2, "c2").apply("P2", T, nil)
	b.list("L2", 2, "c1", "c2").apply("L2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.query("c9", T, nil, "not_revoked", "", "L2")
	add(b)

	b = g.statusScenario("snapshot_then_push_same_sequence", "a push first received after the snapshot at its sequence is recorded without reconciliation when represented in the accepted set")
	b.list("L1", 1, "c1").apply("L1", T, nil).list("L2", 2, "c1", "c2").apply("L2", T, nil)
	b.push("P2", 2, "c2").apply("P2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.query("c9", T, nil, "not_revoked", "", "L2")
	add(b)

	b = g.statusScenario("snapshot_then_conflicting_push_same_sequence", "a push at an accepted sequence naming a certificate absent from the accepted set is a fork")
	b.list("L1", 1, "c1").apply("L1", T, nil).list("L2", 2, "c1", "c2").apply("L2", T, nil)
	b.push("P2x", 2, "c3").apply("P2x", T, st(true, 2, 2, 2, true, []string{"c1", "c2"}, []string{"c1", "c2", "c3"}))
	b.query("c9", T, nil, "indeterminate", "unavailable", "L2", "P2x").query("c3", T, nil, "revoked", "", "L2", "P2x")
	add(b)

	b = g.statusScenario("conflicting_push_at_floor", "a different push body at the accepted floor is a fork; an exact semantic duplicate with new signature bytes is idempotent")
	b.list("L1", 1, "c1").apply("L1", T, nil).push("P2", 2, "c2").apply("P2", T, nil)
	b.pushAt("P2dup", 2, Now-30, 0x44, "c2").apply("P2dup", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.push("P2x", 2, "c3").apply("P2x", T, st(true, 2, 2, 2, true, []string{"c1", "c2"}, []string{"c1", "c2", "c3"}))
	add(b)

	b = g.statusScenario("snapshot_between_floor_and_observed", "a fresh snapshot strictly between the floor and a higher observed push advances the floor but stays indeterminate until caught up")
	b.list("L1", 1, "c1").apply("L1", T, nil).push("P3", 3, "c3").apply("P3", T, nil)
	b.list("L2", 2, "c1").apply("L2", T, st(true, 2, 3, 0, true, []string{"c1"}, []string{"c1", "c3"}))
	b.query("c9", T, nil, "indeterminate", "unavailable", "L2", "P3")
	b.list("L3", 3, "c1", "c3").apply("L3", T, st(true, 3, 3, 0, false, []string{"c1", "c3"}, []string{"c1", "c3"}))
	add(b)

	b = g.statusScenario("lower_sequence_snapshot_omits_observed_revocation", "a snapshot at S that omits a revocation observed at or before S is equivocation and a fork")
	b.list("L1", 1, "c1").apply("L1", T, nil).push("P2", 2, "c2").apply("P2", T, nil).push("P4", 4, "c4").apply("P4", T, nil)
	b.list("L3", 3, "c1").apply("L3", T, &statusStateJSON{ForkSequence: ip(3), ReconciliationRequired: bp(true), DenyUnion: set("c1", "c2", "c4")})
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1", "P2", "P4", "L3")
	b.list("L4", 4, "c1", "c2", "c4").apply("L4", T, st(true, 4, 4, 0, false, []string{"c1", "c2", "c4"}, []string{"c1", "c2", "c4"}))
	add(b)

	b = g.statusScenario("below_floor_equivocation", "a push below the floor introducing a revocation absent from the accepted set is a fork at max(previous_fork_sequence, current_floor, conflicting_object_sequence); a same-floor snapshot cannot clear it; recovery only above fork_sequence")
	b.list("L3", 3, "c1").apply("L3", T, st(true, 3, 3, 0, false, []string{"c1"}, []string{"c1"}))
	b.push("P2", 2, "c2").apply("P2", T, st(true, 3, 3, 3, true, []string{"c1"}, []string{"c1", "c2"}))
	b.list("L3x", 3, "c1", "c2").apply("L3x", T, &statusStateJSON{Floor: ip(3), ForkSequence: ip(3), ReconciliationRequired: bp(true), DenyUnion: set("c1", "c2")})
	b.query("c9", T, nil, "indeterminate", "unavailable", "L3", "P2", "L3x")
	b.list("L4", 4, "c1", "c2").apply("L4", T, st(true, 4, 4, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	add(b)

	b = g.statusScenario("stale_and_future_dated", "accepted state beyond the age bound is stale; a future-dated push makes status unavailable until a fresh snapshot reconciles")
	b.list("L1", 1, "c1").apply("L1", T, nil)
	b.query("c9", T+700, nil, "indeterminate", "stale", "L1")
	b.pushAt("P2f", 2, T+100, 0, "c2").apply("P2f", T, &statusStateJSON{Floor: ip(1), MaxObservedSequence: ip(2), FutureDatedObjectObserved: bp(true), DenyUnion: set("c1", "c2")})
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1", "P2f").query("c2", T, nil, "revoked", "", "L1", "P2f")
	b.listAt("L2", 2, T-10, T+1800, "c1", "c2").apply("L2", T, &statusStateJSON{Floor: ip(2), ReconciliationRequired: bp(false), FutureDatedObjectObserved: bp(false)})
	b.query("c9", T, nil, "not_revoked", "", "L2")
	add(b)

	b = g.statusScenario("exclusive_age_deadline", "a snapshot is fresh only while now < updated_at + max_status_age (SPEC-v2 §2.5): one second before the deadline it is current, at the deadline it is stale")
	b.list("L1", 1, "c1").apply("L1", T, nil)
	b.query("c9", T+539, nil, "not_revoked", "", "L1").query("c9", T+540, nil, "indeterminate", "stale", "L1")
	add(b)

	b = g.statusScenario("exclusive_next_update_deadline", "a snapshot is fresh only while now < next_update (SPEC-v2 §2.5): one second before next_update it is current, at next_update it is stale")
	b.listAt("L1", 1, T-60, T+300, "c1").apply("L1", T, nil)
	b.query("c9", T+299, nil, "not_revoked", "", "L1").query("c9", T+300, nil, "indeterminate", "stale", "L1")
	add(b)

	b = g.statusScenario("unconfigured_freshness_bounds", "status is unavailable when either finite freshness bound is not configured")
	b.list("L1", 1).apply("L1", T, nil)
	b.query("c9", T, &statusPolicyJSON{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 0, ClockSkewSeconds: 5}, "indeterminate", "unavailable", "L1")
	b.query("c9", T, &statusPolicyJSON{MaxListLifetimeSeconds: 0, MaxStatusAgeSeconds: 600, ClockSkewSeconds: 5}, "indeterminate", "unavailable", "L1")
	add(b)

	b = g.statusScenario("non_fresh_snapshot_reconciliation", "a non-fresh snapshot above the floor requires reconciliation; a consistent non-fresh snapshot at or below the floor does not")
	b.list("L1", 1, "c1").apply("L1", T, nil)
	b.listAt("L2s", 2, T-7200, T-5400, "c1").apply("L2s", T, &statusStateJSON{Floor: ip(1), MaxObservedSequence: ip(2), ReconciliationRequired: bp(true)})
	b.query("c9", T, nil, "indeterminate", "unavailable", "L1", "L2s")
	b.list("L2", 2, "c1").apply("L2", T, st(true, 2, 2, 0, false, []string{"c1"}, []string{"c1"}))
	b.listAt("L1s", 1, T-7200, T-5400, "c1").applyUnrecorded("L1s", T, st(true, 2, 2, 0, false, []string{"c1"}, []string{"c1"}))
	b.query("c9", T, nil, "not_revoked", "", "L2")
	add(b)

	b = g.statusScenario("forward_snapshot_acceptance", "with no reconciliation pending a fresh forward snapshot containing every observation replaces the accepted base")
	b.list("L1", 1, "c1").apply("L1", T, nil).list("L3", 3, "c1", "c3").apply("L3", T, st(true, 3, 3, 0, false, []string{"c1", "c3"}, []string{"c1", "c3"}))
	b.query("c9", T, nil, "not_revoked", "", "L3")
	add(b)

	b = g.statusScenario("epoch_transition", "a status-key epoch transition resets accepted snapshot, set, and floor while retaining the issuer-wide deny union and prior evidence; late old-epoch objects are rejected; the new epoch bootstraps only from a snapshot that carries the retained deny union; a retired status key cannot be rebound")
	b.list("L1", 1, "c1").apply("L1", T, nil).push("P2", 2, "c2").apply("P2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.list("L3old", 3, "c1", "c2")
	b.transition("status_root_epoch_2", 2, st(false, 0, 0, 0, false, nil, []string{"c1", "c2"}), "")
	b.query("c9", T, nil, "indeterminate", "unavailable").query("c1", T, nil, "revoked", "", "L1")
	b.applyRejected("L3old", "status_root_epoch_2", 2, "invalid_signature")
	b.applyRejected("L3old", "status_root", 1, "status_object_rejected")
	b.list("N1", 1).apply("N1", T, &statusStateJSON{HasFloor: bp(false), DenyUnion: set("c1", "c2")})
	b.query("c9", T, nil, "indeterminate", "unavailable", "N1")
	b.list("N2", 2, "c1", "c2").apply("N2", T, st(true, 2, 2, 0, false, []string{"c1", "c2"}, []string{"c1", "c2"}))
	b.query("c9", T, nil, "not_revoked", "", "N2")
	b.transition("status_root", 3, nil, "status_object_rejected")
	add(b)
	return f
}
