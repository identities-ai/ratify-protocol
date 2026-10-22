package ratify

import (
	"strings"
	"testing"
)

func TestRevocationStatusReducerBootstrapPushGapAndRecovery(t *testing.T) {
	issuerID := strings.Repeat("a", 64)
	statusPub, statusKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50, ClockSkewSeconds: 2}
	state := RevocationStatusStateV2{}

	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 1, 99, 120, "cert-1")
	if !state.HasFloor || state.Floor != 1 || state.ReconciliationRequired || !containsAllStringSetV2(state.AcceptedCertIDs, []string{"cert-1"}) {
		t.Fatalf("fresh initial snapshot did not bootstrap: %+v", state)
	}

	state = applyPushForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 2, 100, "cert-2")
	if state.Floor != 2 || state.ReconciliationRequired || !containsAllStringSetV2(state.AcceptedCertIDs, []string{"cert-1", "cert-2"}) {
		t.Fatalf("contiguous push did not extend accepted state: %+v", state)
	}

	state = applyPushForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 4, 100, "cert-4")
	if state.Floor != 2 || state.MaxObservedSequence != 4 || !state.ReconciliationRequired || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-4"}) {
		t.Fatalf("gap push changed accepted state or failed to freeze status: %+v", state)
	}

	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 4, 99, 120, "cert-1", "cert-2", "cert-4")
	if state.Floor != 4 || state.MaxObservedSequence != 4 || state.ReconciliationRequired || state.FutureDatedObjectObserved {
		t.Fatalf("fresh full snapshot did not reconcile gap: %+v", state)
	}
	if !containsAllStringSetV2(state.AcceptedCertIDs, state.DenyUnionCertIDs) {
		t.Fatalf("accepted state lost a known revocation: accepted=%v deny_union=%v", state.AcceptedCertIDs, state.DenyUnionCertIDs)
	}
}

func TestRevocationStatusReducerFailsClosedOnOmissionForkAndFuture(t *testing.T) {
	issuerID := strings.Repeat("b", 64)
	statusPub, statusKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50, ClockSkewSeconds: 2}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, statusPub, statusKey, policy, 100, 2, 99, 120, "cert-1")

	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 3, 99, 120, "cert-1", "cert-2")
	if state.Floor != 3 || state.ReconciliationRequired || len(state.AcceptedCertIDs) != 2 {
		t.Fatalf("fresh forward snapshot did not advance accepted state: %+v", state)
	}

	// Sequence 4 omits a revocation present in the accepted sequence 3 snapshot.
	// Omission is equivocation, so the reducer records a fork and holds the floor.
	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 4, 99, 120, "cert-1")
	if !state.ReconciliationRequired || state.ForkSequence != 4 || state.Floor != 3 {
		t.Fatalf("snapshot omission was not classified as a fork: %+v", state)
	}
	if !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-1"}) {
		t.Fatal("fork handling dropped a known revoked certificate")
	}

	// A higher, fresh snapshot containing all known revocations recovers the fork.
	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 5, 99, 120, "cert-1", "cert-2")
	if state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 5 {
		t.Fatalf("strictly higher full snapshot did not recover fork: %+v", state)
	}

	futurePush := signedStateTestPush(t, statusKey, issuerID, 6, 110, "cert-future")
	state, err = ApplyRevocationPushV2(state, futurePush, issuerID, 1, statusPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if state.Floor != 5 || !state.ReconciliationRequired || !state.FutureDatedObjectObserved || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-future"}) {
		t.Fatalf("future push advanced freshness or failed to freeze status: %+v", state)
	}
}

func TestRevocationStatusReducerPushAtAcceptedSequenceIsFork(t *testing.T) {
	issuerID := strings.Repeat("9", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "cert-1", "cert-2")
	push := signedStateTestPush(t, key, issuerID, 2, 100, "cert-new")
	state, err = ApplyRevocationPushV2(state, push, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !state.ReconciliationRequired || state.ForkSequence != 2 || state.Floor != 2 || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-new"}) {
		t.Fatalf("push at an accepted sequence did not freeze as a fork: %+v", state)
	}
}

func TestRevocationStatusReducerIntermediateSnapshotDoesNotForkOrClearGap(t *testing.T) {
	issuerID := strings.Repeat("8", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 1, 99, 120, "cert-1")
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 3, 100, "cert-3")

	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "cert-1")
	if state.Floor != 2 || state.MaxObservedSequence != 3 || !state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("intermediate snapshot must remain unavailable without creating a fork: %+v", state)
	}
	result, err := RevocationStatusForCertV2(state, issuerID, "clear", 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "indeterminate" || result.Reason != "unavailable" {
		t.Fatalf("intermediate snapshot enabled a not-revoked result: %+v", result)
	}

	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 3, 99, 120, "cert-1", "cert-3")
	if state.Floor != 3 || state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("caught-up snapshot failed to reconcile the gap: %+v", state)
	}
}

func TestRevocationStatusReducerStaleOmissionCannotBeClearedBySameFloorHeartbeat(t *testing.T) {
	issuerID := strings.Repeat("6", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 1, 99, 120)
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 3, 100, "cert-x")
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 5, 99, 120, "cert-x", "cert-y")
	if state.ReconciliationRequired || state.Floor != 5 {
		t.Fatalf("setup did not reconcile the observed gap: %+v", state)
	}

	// This authenticated but stale sequence 4 snapshot omits the sequence 3
	// revocation. It is equivocation even though the snapshot cannot advance.
	stale := signedStateTestList(t, key, issuerID, 4, 1, 10, "cert-y")
	state, err = ApplyRevocationListV2(state, stale, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !state.ReconciliationRequired || state.ForkSequence != 5 || state.Floor != 5 {
		t.Fatalf("stale omission was not retained as a fork at the current floor: %+v", state)
	}

	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 5, 99, 120, "cert-x", "cert-y")
	if !state.ReconciliationRequired || state.ForkSequence != 5 || state.Floor != 5 {
		t.Fatalf("same-floor heartbeat cleared an unresolved fork: %+v", state)
	}
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 6, 99, 120, "cert-x", "cert-y")
	if state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 6 {
		t.Fatalf("strictly higher full snapshot failed to repair the fork: %+v", state)
	}
	replayed, err := ApplyRevocationListV2(state, stale, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ReconciliationRequired || replayed.ForkSequence != 0 || replayed.Floor != state.Floor {
		t.Fatalf("replaying a reconciled stale fork re-froze status: %+v", replayed)
	}
}

func TestRevocationStatusReducerSnapshotPushSameSequenceIsOrderIndependent(t *testing.T) {
	issuerID := strings.Repeat("5", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	base := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 1, 99, 120, "base")
	push := signedStateTestPush(t, key, issuerID, 2, 100, "added")
	state, err := ApplyRevocationPushV2(base, push, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "base", "added")
	if state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("push-first matching snapshot was rejected: %+v", state)
	}

	state = applyListForStateTest(t, base, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "base", "added")
	state, err = ApplyRevocationPushV2(state, push, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Observations are kept in canonical snapshot order (SPEC-v2 A3), so the
	// push is located by identity rather than by position.
	pushAccepted := false
	for _, observation := range state.Observations {
		if observation.ObjectType == uint16(v2RevocationPush) && observation.Sequence == 2 {
			pushAccepted = observation.Accepted
		}
	}
	if state.ReconciliationRequired || state.ForkSequence != 0 || pushAccepted {
		t.Fatalf("snapshot-first matching push was rejected or treated as accepted contiguous push: %+v", state)
	}

	state = applyListForStateTest(t, base, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "base", "added", "extra")
	state, err = ApplyRevocationPushV2(state, push, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !state.ReconciliationRequired || state.ForkSequence != 2 {
		t.Fatalf("same-sequence push did not detect snapshot delta mismatch: %+v", state)
	}

	state = applyPushForStateTest(t, base, issuerID, 1, pub, key, policy, 100, 2, 100, "added")
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "base", "added", "extra")
	if !state.ReconciliationRequired || state.ForkSequence != 2 {
		t.Fatalf("push-first sequence mismatch was not detected: %+v", state)
	}
}

func TestRevocationStatusReducerConsistentLatePushBelowFloorDoesNotFreeze(t *testing.T) {
	issuerID := strings.Repeat("4", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 1, 99, 120, "base")
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 100, "late")
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 3, 99, 120, "base", "late")
	if state.ReconciliationRequired {
		t.Fatalf("setup failed to reconcile through sequence 3: %+v", state)
	}
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 100, "late")
	if state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 3 {
		t.Fatalf("late consistent push below floor froze status: %+v", state)
	}
}

func TestRevocationStatusReducerDetectsSameSequenceForkBeforeBootstrap(t *testing.T) {
	issuerID := strings.Repeat("7", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	stale := signedStateTestList(t, key, issuerID, 4, 1, 10, "cert-a")
	state, err := ApplyRevocationListV2(RevocationStatusStateV2{}, stale, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 4, 99, 120, "cert-b")
	if state.HasFloor || !state.ReconciliationRequired || state.ForkSequence != 4 || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-a", "cert-b"}) {
		t.Fatalf("same-sequence snapshots before bootstrap were not forked: %+v", state)
	}

	state = RevocationStatusStateV2{}
	firstPush := signedStateTestPush(t, key, issuerID, 4, 100, "cert-a")
	state, err = ApplyRevocationPushV2(state, firstPush, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	secondPush := signedStateTestPush(t, key, issuerID, 4, 100, "cert-b")
	state, err = ApplyRevocationPushV2(state, secondPush, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if state.HasFloor || !state.ReconciliationRequired || state.ForkSequence != 4 || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-a", "cert-b"}) {
		t.Fatalf("same-sequence pushes before bootstrap were not forked: %+v", state)
	}
}

func TestRevocationStatusReducerStaleAndUnconfiguredBounds(t *testing.T) {
	issuerID := strings.Repeat("c", 64)
	statusPub, statusKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	list := signedStateTestList(t, statusKey, issuerID, 1, 1, 20, "cert-stale")
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 10, ClockSkewSeconds: 0}
	state, err := ApplyRevocationListV2(RevocationStatusStateV2{}, list, issuerID, 1, statusPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if state.HasFloor || !state.ReconciliationRequired || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"cert-stale"}) {
		t.Fatalf("stale snapshot advanced state or lost its revocation: %+v", state)
	}

	unconfigured := RevocationStatusPolicyV2{ClockSkewSeconds: 0}
	list = signedStateTestList(t, statusKey, issuerID, 1, 99, 120, "cert-current")
	state, err = ApplyRevocationListV2(RevocationStatusStateV2{}, list, issuerID, 1, statusPub, unconfigured, 100)
	if err != nil {
		t.Fatal(err)
	}
	if state.HasFloor || !state.ReconciliationRequired {
		t.Fatalf("snapshot accepted without finite freshness bounds: %+v", state)
	}
	if _, err := ApplyRevocationListV2(state, list, strings.Repeat("d", 64), 1, statusPub, policy, 100); err == nil {
		t.Fatal("accepted a snapshot under a different authenticated issuer binding")
	}
	if state.DenyUnionCertIDs[0] != "cert-current" {
		t.Fatal("test setup failed to preserve current snapshot revocation")
	}
}

func TestRevocationStatusReducerEpochTransitionRetainsDenialsAndRejectsRetiredEpoch(t *testing.T) {
	issuerID := strings.Repeat("e", 64)
	oldPub, oldKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50, ClockSkewSeconds: 2}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, oldPub, oldKey, policy, 100, 8, 99, 120, "revoked-prior")

	state, err = TransitionRevocationStatusEpochV2(state, issuerID, 2, newPub)
	if err != nil {
		t.Fatal(err)
	}
	if state.HasFloor || state.AcceptedSnapshot != nil || state.Floor != 0 || state.MaxObservedSequence != 0 || state.ReconciliationRequired || state.FutureDatedObjectObserved || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"revoked-prior"}) {
		t.Fatalf("epoch transition did not clear accepted state and preserve deny union: %+v", state)
	}
	if _, err := ApplyRevocationListV2(state, signedStateTestList(t, oldKey, issuerID, 9, 99, 120), issuerID, 1, oldPub, policy, 100); err == nil {
		t.Fatal("accepted a retired epoch object after transition")
	}

	result, err := RevocationStatusForCertV2(state, issuerID, "revoked-prior", 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "revoked" || len(result.Evidence) != 1 || result.Evidence[0].StatusKeyID == "" {
		t.Fatalf("prior-epoch revocation was not returned with evidence: %+v", result)
	}
	unknown, err := RevocationStatusForCertV2(state, issuerID, "unknown", 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Status != "indeterminate" || unknown.Reason != "unavailable" {
		t.Fatalf("new epoch allowed before fresh snapshot bootstrap: %+v", unknown)
	}

	state = applyListForStateTest(t, state, issuerID, 2, newPub, newKey, policy, 100, 1, 99, 120)
	if state.HasFloor || !state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("new epoch bootstrapped without carrying forward retained denials: %+v", state)
	}
	var sawGap bool
	for _, observation := range state.Observations {
		if observation.StatusKeyEpoch == 2 && observation.Gap && !observation.Fork {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("omitted prior-epoch denial was not classified as a pending bootstrap gap: %+v", state.Observations)
	}
	unknown, err = RevocationStatusForCertV2(state, issuerID, "unknown", 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Status != "indeterminate" || unknown.Reason != "unavailable" {
		t.Fatalf("omitted prior-epoch denial allowed a not-revoked result: %+v", unknown)
	}

	state = applyListForStateTest(t, state, issuerID, 2, newPub, newKey, policy, 100, 2, 99, 120, "revoked-prior")
	unknown, err = RevocationStatusForCertV2(state, issuerID, "unknown", 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Status != "not_revoked" {
		t.Fatalf("fresh epoch snapshot did not restore current status: %+v", unknown)
	}
}

func TestRevocationStatusReducerSnapshotAtPushAdvancedFloorBecomesAcceptedBase(t *testing.T) {
	issuerID := strings.Repeat("c", 64)
	statusPub, statusKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, statusPub, statusKey, policy, 100, 1, 99, 130, "x")
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 2, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "y"}}}, issuerID, statusPub, statusKey)
	if err != nil {
		t.Fatal(err)
	}
	state, err = ApplyRevocationPushV2(state, push, issuerID, 1, statusPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	futurePush, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 1, PushedAt: 200, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, statusPub, statusKey)
	if err != nil {
		t.Fatal(err)
	}
	state, err = ApplyRevocationPushV2(state, futurePush, issuerID, 1, statusPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 140, 2, 99, 130, "x", "y")
	snapshot, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 135, NextUpdate: 190, Sequence: 2, Revoked: []RevokedCertV2{{CertID: "x"}, {CertID: "y"}}}, issuerID, statusPub, statusKey)
	if err != nil {
		t.Fatal(err)
	}
	state, err = ApplyRevocationListV2(state, snapshot, issuerID, 1, statusPub, policy, 140)
	if err != nil {
		t.Fatal(err)
	}
	if state.AcceptedSnapshot == nil || state.AcceptedSnapshot.Sequence != 2 || state.ReconciliationRequired || !equalStringSetsV2(state.AcceptedCertIDs, []string{"x", "y"}) {
		t.Fatalf("snapshot at push-advanced floor did not become accepted base: %+v", state)
	}
}

func TestRevocationStatusReducerBoundsDirectHeartbeatHistory(t *testing.T) {
	issuerID := strings.Repeat("f", 64)
	statusPub, statusKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := RevocationStatusStateV2{}
	for updatedAt := int64(80); updatedAt <= 100; updatedAt++ {
		state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 100, 1, updatedAt, 120, "revoked")
	}
	if len(state.Observations) > 2 || state.AcceptedSnapshot == nil || state.AcceptedSnapshot.UpdatedAt != 100 {
		t.Fatalf("direct reducer did not apply and compact repeated heartbeats: observations=%d snapshot=%+v", len(state.Observations), state.AcceptedSnapshot)
	}
}

func TestRevocationStatusReducerFreshHeartbeatReevaluatesStaleSameSequenceSnapshot(t *testing.T) {
	issuerID := strings.Repeat("9", 64)
	statusPub, statusKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, statusPub, statusKey, policy, 100, 4, 99, 130, "x")
	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 140, 5, 99, 130, "x")
	if !state.ReconciliationRequired || state.Floor != 4 {
		t.Fatalf("stale snapshot unexpectedly advanced accepted state: %+v", state)
	}
	state = applyListForStateTest(t, state, issuerID, 1, statusPub, statusKey, policy, 140, 5, 135, 160, "x")
	if state.ReconciliationRequired || state.Floor != 5 {
		t.Fatalf("fresh same-set heartbeat did not repair the stale snapshot gap: %+v", state)
	}
	for _, observation := range state.Observations {
		if observation.Sequence == 5 && observation.Accepted && observation.Gap {
			t.Fatalf("accepted base retained a cleared gap flag: %+v", observation)
		}
	}
}

func TestRevocationStatusReducerRejectsReuseOfRetiredStatusKey(t *testing.T) {
	issuerID := strings.Repeat("4", 64)
	oldPub, oldKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	middlePub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, oldPub, oldKey, RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}, 100, 1, 99, 120)
	if _, err := TransitionRevocationStatusEpochV2(state, issuerID, 3, middlePub); err == nil {
		t.Fatal("skipped a status-key epoch")
	}
	state, err = TransitionRevocationStatusEpochV2(state, issuerID, 2, middlePub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TransitionRevocationStatusEpochV2(state, issuerID, 3, oldPub); err == nil {
		t.Fatal("reused a status key retired in an earlier epoch")
	}
}

func TestRevocationStatusReducerResultPrecedenceAndFreshness(t *testing.T) {
	issuerID := strings.Repeat("f", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 10, ClockSkewSeconds: 0}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 1, 99, 120, "revoked")
	for _, test := range []struct{ cert, want, reason string }{
		{"revoked", "revoked", ""},
		{"clear", "not_revoked", ""},
	} {
		got, err := RevocationStatusForCertV2(state, issuerID, test.cert, 1, pub, policy, 100)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != test.want || got.Reason != test.reason || len(got.Evidence) == 0 {
			t.Fatalf("unexpected current status for %q: %+v", test.cert, got)
		}
		if test.want == "not_revoked" && got.FreshUntil != 109 || test.want == "revoked" && got.FreshUntil != 0 {
			t.Fatalf("status freshness horizon does not match signed snapshot and policy: %+v", got)
		}
	}
	stale, err := RevocationStatusForCertV2(state, issuerID, "clear", 1, pub, policy, 110)
	if err != nil {
		t.Fatal(err)
	}
	if stale.Status != "indeterminate" || stale.Reason != "stale" {
		t.Fatalf("expired accepted list was not stale: %+v", stale)
	}
}

func applyListForStateTest(t *testing.T, state RevocationStatusStateV2, issuerID string, epoch uint64, pub HybridPublicKey, key HybridPrivateKey, policy RevocationStatusPolicyV2, now, sequence, updatedAt, nextUpdate int64, certIDs ...string) RevocationStatusStateV2 {
	t.Helper()
	list := signedStateTestList(t, key, issuerID, sequence, updatedAt, nextUpdate, certIDs...)
	next, err := ApplyRevocationListV2(state, list, issuerID, epoch, pub, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func applyPushForStateTest(t *testing.T, state RevocationStatusStateV2, issuerID string, epoch uint64, pub HybridPublicKey, key HybridPrivateKey, policy RevocationStatusPolicyV2, now, sequence, pushedAt int64, certID string) RevocationStatusStateV2 {
	t.Helper()
	push := signedStateTestPush(t, key, issuerID, sequence, pushedAt, certID)
	next, err := ApplyRevocationPushV2(state, push, issuerID, epoch, pub, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func signedStateTestList(t *testing.T, key HybridPrivateKey, issuerID string, sequence, updatedAt, nextUpdate int64, certIDs ...string) *RevocationListV2 {
	t.Helper()
	refs := make([]RevokedCertV2, len(certIDs))
	for i, certID := range certIDs {
		refs[i] = RevokedCertV2{CertID: certID}
	}
	list, err := SignRevocationListV2(&RevocationListV2{
		Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate,
		Sequence: sequence, Revoked: refs,
	}, issuerID, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func signedStateTestPush(t *testing.T, key HybridPrivateKey, issuerID string, sequence, pushedAt int64, certID string) *RevocationPushV2 {
	t.Helper()
	push, err := SignRevocationPushV2(&RevocationPushV2{
		Version: 2, IssuerID: issuerID, Sequence: sequence, PushedAt: pushedAt,
		Revoked: []RevokedCertV2{{CertID: certID}},
	}, issuerID, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return push
}

func TestRevocationStatusReducerConsistentStaleSnapshotDoesNotCreateReconciliation(t *testing.T) {
	issuerID := strings.Repeat("3", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "known")
	stale := signedStateTestList(t, key, issuerID, 1, 1, 10)
	state, err = ApplyRevocationListV2(state, stale, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if state.ReconciliationRequired || state.Floor != 2 {
		t.Fatalf("consistent stale snapshot at/below floor made status unavailable: %+v", state)
	}
	aboveFloor := signedStateTestList(t, key, issuerID, 3, 1, 10, "known")
	state, err = ApplyRevocationListV2(state, aboveFloor, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !state.ReconciliationRequired || state.Floor != 2 || state.ForkSequence != 0 {
		t.Fatalf("consistent stale snapshot above floor did not create a non-fork gap: %+v", state)
	}
}

func TestRevocationStatusReducerReprocessesFutureSnapshotWhenFresh(t *testing.T) {
	issuerID := strings.Repeat("2", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50, ClockSkewSeconds: 1}
	future := signedStateTestList(t, key, issuerID, 1, 110, 130, "known")
	state, err := ApplyRevocationListV2(RevocationStatusStateV2{}, future, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if state.HasFloor || !state.ReconciliationRequired || !state.FutureDatedObjectObserved {
		t.Fatalf("future snapshot was not held: %+v", state)
	}
	state, err = ApplyRevocationListV2(state, future, issuerID, 1, pub, policy, 110)
	if err != nil {
		t.Fatal(err)
	}
	if !state.HasFloor || state.Floor != 1 || state.ReconciliationRequired || state.FutureDatedObjectObserved {
		t.Fatalf("same authenticated snapshot did not become usable when fresh: %+v", state)
	}
	accepted := false
	for _, observation := range state.Observations {
		accepted = accepted || observation.Accepted
	}
	if !accepted {
		t.Fatal("journal evidence does not record the snapshot's later accepted evaluation")
	}
}

func TestRevocationStatusReducerLatePushContradictsHigherSnapshot(t *testing.T) {
	issuerID := strings.Repeat("1", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 5, 99, 120)
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 4, 100, "late-revocation")
	if !state.ReconciliationRequired || state.ForkSequence != 5 || state.Floor != 5 || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"late-revocation"}) {
		t.Fatalf("late push omitted by an already observed later snapshot was not a fork: %+v", state)
	}
}

func TestRevocationStatusReducerBootstrapCannotFallBelowObservedSequence(t *testing.T) {
	issuerID := strings.Repeat("0", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyPushForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 5, 100, "from-push")
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 4, 99, 120)
	if state.HasFloor || !state.ReconciliationRequired || state.MaxObservedSequence != 5 {
		t.Fatalf("bootstrap below observed sequence was accepted: %+v", state)
	}
}

func TestRevocationStatusReducerBootstrapSequenceOnePushSnapshotIsOrderIndependent(t *testing.T) {
	issuerID := strings.Repeat("a", 64)
	oldPub, oldKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	prior := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, oldPub, oldKey, policy, 100, 4, 99, 120, "prior")
	prior, err = TransitionRevocationStatusEpochV2(prior, issuerID, 2, newPub)
	if err != nil {
		t.Fatal(err)
	}
	push := signedStateTestPush(t, newKey, issuerID, 1, 100, "new")

	snapshotFirst, err := ApplyRevocationListV2(prior, signedStateTestList(t, newKey, issuerID, 1, 99, 120, "new", "prior"), issuerID, 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	snapshotFirst, err = ApplyRevocationPushV2(snapshotFirst, push, issuerID, 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotFirst.ReconciliationRequired || snapshotFirst.ForkSequence != 0 {
		t.Fatalf("snapshot-first sequence-one evidence forked: %+v", snapshotFirst)
	}

	pushFirst, err := ApplyRevocationPushV2(prior, push, issuerID, 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	pushFirst, err = ApplyRevocationListV2(pushFirst, signedStateTestList(t, newKey, issuerID, 1, 99, 120, "new", "prior"), issuerID, 2, newPub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if pushFirst.ReconciliationRequired || pushFirst.ForkSequence != 0 {
		t.Fatalf("push-first sequence-one evidence forked: %+v", pushFirst)
	}
}

func TestRevocationStatusReducerDetectsPendingSameSequencePushSnapshotMismatch(t *testing.T) {
	issuerID := strings.Repeat("6", 64)
	pub, key, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	state := applyListForStateTest(t, RevocationStatusStateV2{}, issuerID, 1, pub, key, policy, 100, 1, 99, 120, "base")
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 5, 100, "late")
	state = applyPushForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 100, "added")
	state = applyListForStateTest(t, state, issuerID, 1, pub, key, policy, 100, 2, 99, 120, "base", "added", "extra")
	if !state.ReconciliationRequired || state.ForkSequence != 2 {
		t.Fatalf("same-sequence push/snapshot mismatch during reconciliation was not detected: %+v", state)
	}
}
