package ratify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"strings"
	"testing"
)

type memorySecurityJournalStoreV2 struct {
	anchor SecurityJournalHeadV2
	latest SecurityJournalV2
	stale  *SecurityJournalV2
}

func newMemorySecurityJournalStoreV2() *memorySecurityJournalStoreV2 {
	genesis := EmptySecurityJournalV2()
	return &memorySecurityJournalStoreV2{anchor: SecurityJournalHeadV2{Digest: genesis.Digest}, latest: genesis}
}

func (s *memorySecurityJournalStoreV2) Load(context.Context) (SecurityJournalV2, SecurityJournalHeadV2, error) {
	if s.stale != nil {
		if s.stale.Generation != s.anchor.Generation || s.stale.Digest != s.anchor.Digest {
			return SecurityJournalV2{}, SecurityJournalHeadV2{}, errors.New("anchored security journal head is missing")
		}
		journal, err := cloneSecurityJournalV2(*s.stale)
		return journal, s.anchor, err
	}
	if s.latest.Generation != s.anchor.Generation || s.latest.Digest != s.anchor.Digest {
		return SecurityJournalV2{}, SecurityJournalHeadV2{}, errors.New("stored security journal does not match independent anchor")
	}
	journal, err := cloneSecurityJournalV2(s.latest)
	return journal, s.anchor, err
}

func (s *memorySecurityJournalStoreV2) CompareAndSwap(_ context.Context, expected SecurityJournalHeadV2, next SecurityJournalV2) error {
	if expected != s.anchor {
		return ErrSecurityJournalConflictV2
	}
	if err := ValidateSecurityJournalTransitionV2(s.latest, next); err != nil {
		return err
	}
	copyNext, err := cloneSecurityJournalV2(next)
	if err != nil {
		return err
	}
	s.latest = copyNext
	s.anchor = SecurityJournalHeadV2{Generation: next.Generation, Digest: next.Digest}
	return nil
}

func TestSecurityJournalV2AnchorsHeadAndCommitsMonotonically(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	first, err := RecordSecurityKeyRoleV2(ctx, store, "delegation", pub)
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation != 1 || len(first.KeyRoleHistory) != 1 {
		t.Fatalf("first journal update was not committed: %+v", first)
	}
	deleted, err := cloneSecurityJournalV2(first)
	if err != nil {
		t.Fatal(err)
	}
	deleted.Generation++
	deleted.PreviousDigest = first.Digest
	deleted.KeyRoleHistory = []KeyRoleBindingV2{}
	deleted.Digest, err = securityJournalDigestV2(deleted)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityJournalTransitionV2(first, deleted); err == nil {
		t.Fatal("allowed an update that deleted permanent key-role history")
	}
	loaded, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation != 1 || len(loaded.KeyRoleHistory) != 1 {
		t.Fatalf("failed transition changed durable state: %+v", loaded)
	}
}

func TestSecurityJournalV2RejectsStaleWriterAndRolledBackBackup(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	base, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, err = RecordSecurityKeyRoleV2(ctx, store, "delegation", pub)
	if err != nil {
		t.Fatal(err)
	}
	staleNext, err := cloneSecurityJournalV2(base)
	if err != nil {
		t.Fatal(err)
	}
	staleNext.Generation = 1
	staleNext.PreviousDigest = base.Digest
	staleNext.Digest, err = securityJournalDigestV2(staleNext)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwap(ctx, SecurityJournalHeadV2{Generation: 0, Digest: base.Digest}, staleNext); !errors.Is(err, ErrSecurityJournalConflictV2) {
		t.Fatalf("stale writer was not rejected as a conflict: %v", err)
	}
	store.stale = &base
	if _, _, err := store.Load(ctx); err == nil {
		t.Fatal("restored old valid journal record despite a newer independent anchor")
	}
}

func TestSecurityJournalV2RetainsStatusEpochsAndRevocations(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("a", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	first, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub)
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50, ClockSkewSeconds: 2}
	list, err := SignRevocationListV2(&RevocationListV2{
		Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: 1,
		Revoked: []RevokedCertV2{{CertID: "cert-denied"}},
	}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAllStringSetV2(second.StatusByIssuer[issuerID].DenyUnionCertIDs, []string{"cert-denied"}) {
		t.Fatal("durable transition lost an authenticated revocation")
	}
	newPub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	third, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 2, newPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(third.StatusKeyHistory) != 2 || !containsAllStringSetV2(third.StatusByIssuer[issuerID].DenyUnionCertIDs, []string{"cert-denied"}) {
		t.Fatalf("key epoch transition dropped durable history or revocation: %+v", third)
	}
	result, err := RevocationStatusForCertV2(third.StatusByIssuer[issuerID], issuerID, "cert-denied", 2, newPub, policy, 100)
	if err != nil || result.Status != "revoked" {
		t.Fatalf("retained revocation did not survive epoch transition: result=%+v err=%v", result, err)
	}
	if err := ValidateSecurityJournalV2(third); err != nil {
		t.Fatalf("committed journal failed validation: %v", err)
	}
	rolledBack, err := cloneSecurityJournalV2(third)
	if err != nil {
		t.Fatal(err)
	}
	rolledState := rolledBack.StatusByIssuer[issuerID]
	rolledState.StatusKeyEpoch = 1
	rolledState.StatusKeyID = first.StatusByIssuer[issuerID].StatusKeyID
	rolledState.RetiredStatusKeyIDs = []string{}
	rolledState.MaxObservedSequence = 1
	rolledState.HasFloor = false
	rolledState.Floor = 0
	rolledState.AcceptedSnapshot = nil
	rolledState.AcceptedCertIDs = []string{}
	rolledBack.StatusByIssuer[issuerID] = rolledState
	rolledBack.Digest, err = securityJournalDigestV2(rolledBack)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityJournalV2(rolledBack); err == nil {
		t.Fatal("accepted issuer status state rolled back behind retained key history")
	}
	if first.Generation != 1 {
		t.Fatalf("test expected first generation 1, got %d", first.Generation)
	}
}

func TestSecurityJournalV2RejectsCrossRoleKeyReuse(t *testing.T) {
	journal := EmptySecurityJournalV2()
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterKeyRoleV2(&journal, "delegation", pub); err != nil {
		t.Fatal(err)
	}
	if err := RegisterStatusKeyEpochV2(&journal, strings.Repeat("b", 64), 1, pub); err == nil {
		t.Fatal("allowed delegation key material to be reused for the status role")
	}
	if len(journal.StatusKeyHistory) != 0 || len(journal.KeyRoleHistory) != 1 {
		t.Fatalf("failed registration partially mutated journal histories: %+v", journal)
	}
}

func TestSecurityJournalV2RejectsClearingReconciliationWithoutCatchup(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("c", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: 1, Revoked: []RevokedCertV2{}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 3, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "gap"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ApplyRevocationPushToJournalV2(ctx, store, push, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	next, err := cloneSecurityJournalV2(current)
	if err != nil {
		t.Fatal(err)
	}
	state := next.StatusByIssuer[issuerID]
	state.ReconciliationRequired = false
	next.StatusByIssuer[issuerID] = state
	next.Generation++
	next.PreviousDigest = current.Digest
	next.Digest, err = securityJournalDigestV2(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityJournalTransitionV2(current, next); err == nil {
		t.Fatal("allowed reconciliation to clear without a caught-up full snapshot")
	}
}

func TestSecurityJournalV2RequiresAcceptedSnapshotEvidence(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("d", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "known"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}, 100)
	if err != nil {
		t.Fatal(err)
	}
	state := journal.StatusByIssuer[issuerID]
	state.AcceptedSnapshot.Revoked = nil
	journal.StatusByIssuer[issuerID] = state
	// The canonical snapshot cannot even encode a structurally altered accepted
	// list; if a digest can be formed, validation must still reject it.
	journal.Digest, err = securityJournalDigestV2(journal)
	if err == nil {
		if err := ValidateSecurityJournalV2(journal); err == nil {
			t.Fatal("accepted a changed snapshot not backed by its authenticated observation")
		}
	}
}

func TestSecurityJournalV2RequiresContiguousAcceptedPushHistory(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("e", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: 1, Revoked: []RevokedCertV2{}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 2, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "accepted"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := ApplyRevocationPushToJournalV2(ctx, store, push, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	state := journal.StatusByIssuer[issuerID]
	state.Observations = state.Observations[:1]
	journal.StatusByIssuer[issuerID] = state
	journal.Digest, err = securityJournalDigestV2(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityJournalV2(journal); err == nil {
		t.Fatal("accepted a status floor whose contiguous push history was missing")
	}
}

func TestSecurityJournalV2ForkedHeartbeatDoesNotCorruptAcceptedBase(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("8", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 130, Sequence: 3, Revoked: []RevokedCertV2{}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 2, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "late"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationPushToJournalV2(ctx, store, push, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 100, NextUpdate: 130, Sequence: 3, Revoked: []RevokedCertV2{}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := ApplyRevocationListToJournalV2(ctx, store, heartbeat, issuerID, 1, pub, policy, 100)
	if err != nil {
		t.Fatalf("forked same-set heartbeat corrupted the accepted base: %v", err)
	}
	state := journal.StatusByIssuer[issuerID]
	if !state.ReconciliationRequired || !state.HasFloor || state.Floor != 3 || !containsAllStringSetV2(state.DenyUnionCertIDs, []string{"late"}) {
		t.Fatalf("forked heartbeat did not retain fail-closed state: %+v", state)
	}
}

func TestSecurityJournalV2CompactedBelowFloorSnapshotDoesNotCauseFalsePushFork(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("b", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	applyList := func(now, sequence, updatedAt, nextUpdate int64, ids ...string) SecurityJournalV2 {
		t.Helper()
		revoked := make([]RevokedCertV2, 0, len(ids))
		for _, id := range ids {
			revoked = append(revoked, RevokedCertV2{CertID: id})
		}
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: revoked}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, now)
		if err != nil {
			t.Fatal(err)
		}
		return journal
	}
	applyList(100, 3, 99, 130, "x")
	applyList(140, 4, 99, 130, "x")  // stale gap above the floor
	applyList(140, 5, 135, 190, "x") // fresh snapshot recovers the gap
	applyList(140, 5, 300, 330, "x") // future heartbeat reopens reconciliation
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 4, PushedAt: 140, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationPushToJournalV2(ctx, store, push, issuerID, 1, pub, policy, 140); err != nil {
		t.Fatal(err)
	}
	journal := applyList(150, 5, 145, 190, "x")
	state := journal.StatusByIssuer[issuerID]
	if state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 5 {
		t.Fatalf("compacted below-floor snapshot created a false push fork: %+v", state)
	}
	futureFloorPush, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 5, PushedAt: 300, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	journal, err = ApplyRevocationPushToJournalV2(ctx, store, futureFloorPush, issuerID, 1, pub, policy, 150)
	if err != nil {
		t.Fatal(err)
	}
	state = journal.StatusByIssuer[issuerID]
	if !state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("future push at the accepted floor was misclassified as a fork: %+v", state)
	}
	journal = applyList(155, 5, 150, 190, "x")
	state = journal.StatusByIssuer[issuerID]
	if state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 5 {
		t.Fatalf("fresh accepted-floor heartbeat did not recover future push: %+v", state)
	}
}

func TestSecurityJournalV2RepeatingCurrentStatusEpochIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("f", 64)
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	first, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Generation != first.Generation || repeated.Digest != first.Digest {
		t.Fatalf("reloading the already configured epoch created a journal version: first=%d repeated=%d", first.Generation, repeated.Generation)
	}
}

func TestSecurityJournalV2PrunesOnlyUnneededEmptyHeartbeats(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("a", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	for sequence := int64(1); sequence <= 2; sequence++ {
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: sequence, Revoked: []RevokedCertV2{}}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100); err != nil {
			t.Fatal(err)
		}
	}
	journal, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observations := journal.StatusByIssuer[issuerID].Observations
	if len(observations) != 2 {
		t.Fatalf("journal did not compact empty snapshots to one sequence marker each: %+v", observations)
	}
	if observations[0].Sequence != 1 || !observations[0].Accepted || observations[1].Sequence != 2 || !observations[1].Accepted {
		t.Fatalf("journal sequence index or accepted snapshot evidence is incomplete: %+v", observations)
	}
}

func TestSecurityJournalV2BoundsRepeatedSnapshotHeartbeats(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("9", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	for updatedAt := int64(80); updatedAt <= 100; updatedAt++ {
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: 120, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "revoked"}}}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100); err != nil {
			t.Fatal(err)
		}
	}
	journal, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(journal.StatusByIssuer[issuerID].Observations); got > 2 {
		t.Fatalf("repeated same-sequence heartbeats caused unbounded observation growth: retained %d records", got)
	}
}

func TestSecurityJournalV2BoundsSameFloorHeartbeatsDuringGap(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("d", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	base, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 180, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, base, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	gap, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 3, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "z"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationPushToJournalV2(ctx, store, gap, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	for updatedAt := int64(100); updatedAt <= 120; updatedAt++ {
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: 180, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 120); err != nil {
			t.Fatal(err)
		}
	}
	journal, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state := journal.StatusByIssuer[issuerID]
	if !state.ReconciliationRequired || state.MaxObservedSequence != 3 || len(state.Observations) > 4 {
		t.Fatalf("same-floor heartbeat evidence grew with heartbeat count or changed the gap: %+v", state)
	}
	if state.AcceptedSnapshot == nil || state.AcceptedSnapshot.UpdatedAt != 120 {
		t.Fatalf("same-floor heartbeats were dropped instead of applied and compacted: %+v", state.AcceptedSnapshot)
	}
}

func TestSecurityJournalV2AcceptsPartialCatchupAfterCompactedGap(t *testing.T) {
	for _, gapFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "gap_digest_first", false: "accepted_digest_first"}[gapFirst], func(t *testing.T) {
			ctx := context.Background()
			store := newMemorySecurityJournalStoreV2()
			issuerID := strings.Repeat("a", 64)
			pub, private, err := GenerateHybridKeypair()
			if err != nil {
				t.Fatal(err)
			}
			policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
			if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
				t.Fatal(err)
			}
			applyList := func(now, sequence, updatedAt, nextUpdate int64, ids ...string) SecurityJournalV2 {
				t.Helper()
				revoked := make([]RevokedCertV2, 0, len(ids))
				for _, id := range ids {
					revoked = append(revoked, RevokedCertV2{CertID: id})
				}
				list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: revoked}, issuerID, pub, private)
				if err != nil {
					t.Fatal(err)
				}
				journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, now)
				if err != nil {
					t.Fatal(err)
				}
				return journal
			}
			applyList(100, 1, 99, 199, "x")
			stale, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 130, Sequence: 2, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ApplyRevocationListToJournalV2(ctx, store, stale, issuerID, 1, pub, policy, 140); err != nil {
				t.Fatal(err)
			}
			gapPush, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 4, PushedAt: 140, Revoked: []RevokedCertV2{{CertID: "z"}}}, issuerID, pub, private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ApplyRevocationPushToJournalV2(ctx, store, gapPush, issuerID, 1, pub, policy, 140); err != nil {
				t.Fatal(err)
			}

			var catchUp *RevocationListV2
			staleBytes, err := revocationListSignableBytesV2(stale)
			if err != nil {
				t.Fatal(err)
			}
			staleDigest := sha512.Sum384(staleBytes)
			for nextUpdate := int64(190); nextUpdate < 1000; nextUpdate++ {
				candidate, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 135, NextUpdate: nextUpdate, Sequence: 2, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
				if err != nil {
					t.Fatal(err)
				}
				candidateBytes, err := revocationListSignableBytesV2(candidate)
				if err != nil {
					t.Fatal(err)
				}
				candidateDigest := sha512.Sum384(candidateBytes)
				if (bytes.Compare(candidateDigest[:], staleDigest[:]) < 0) != gapFirst {
					catchUp = candidate
					break
				}
			}
			if catchUp == nil {
				t.Fatal("could not construct the requested semantic marker ordering")
			}
			if _, err := ApplyRevocationListToJournalV2(ctx, store, catchUp, issuerID, 1, pub, policy, 140); err != nil {
				t.Fatalf("valid partial catch-up was rejected: %v", err)
			}
			journal, _, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			state := journal.StatusByIssuer[issuerID]
			if !state.ReconciliationRequired || state.Floor != 2 || state.MaxObservedSequence != 4 || state.AcceptedSnapshot == nil || state.AcceptedSnapshot.Sequence != 2 {
				t.Fatalf("partial catch-up state is incorrect: %+v", state)
			}
		})
	}
}

func TestSecurityJournalV2SnapshotAtPushAdvancedFloorRepairsStaleFloorEvidence(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("c", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	base, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 199, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, base, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	advance, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 2, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "y"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationPushToJournalV2(ctx, store, advance, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	future, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 1, PushedAt: 200, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationPushToJournalV2(ctx, store, future, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	stale, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 130, Sequence: 2, Revoked: []RevokedCertV2{{CertID: "x"}, {CertID: "y"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, stale, issuerID, 1, pub, policy, 140); err != nil {
		t.Fatal(err)
	}
	fresh, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 135, NextUpdate: 190, Sequence: 2, Revoked: []RevokedCertV2{{CertID: "x"}, {CertID: "y"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := ApplyRevocationListToJournalV2(ctx, store, fresh, issuerID, 1, pub, policy, 140)
	if err != nil {
		t.Fatalf("fresh same-floor snapshot was rejected: %v", err)
	}
	state := journal.StatusByIssuer[issuerID]
	if state.AcceptedSnapshot == nil || state.AcceptedSnapshot.Sequence != 2 || state.Floor != 2 || state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("fresh snapshot did not replace the old base and repair status: %+v", state)
	}
}

func TestSecurityJournalV2CompactorClearsAcceptedBaseGapInEitherOrder(t *testing.T) {
	issuerID := strings.Repeat("e", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 199, Sequence: 5, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationList), list)
	if err != nil {
		t.Fatal(err)
	}
	setDigest, err := revokedSetDigestV2(list.Revoked)
	if err != nil {
		t.Fatal(err)
	}
	for _, acceptedFirst := range []bool{true, false} {
		acceptedBody := bytes.Repeat([]byte{2}, sha512.Size384)
		gapBody := bytes.Repeat([]byte{3}, sha512.Size384)
		if !acceptedFirst {
			acceptedBody, gapBody = gapBody, acceptedBody
		}
		state := RevocationStatusStateV2{
			IssuerID: issuerID, StatusKeyEpoch: 1, HasFloor: true, Floor: 5,
			AcceptedSnapshot: list, AcceptedCertIDs: []string{"x"}, DenyUnionCertIDs: []string{"x"},
			Observations: []RevocationObservationV2{
				{ObjectType: uint16(v2RevocationList), StatusKeyEpoch: 1, Sequence: 5, EvidenceDigest: bytes.Clone(digest), BodyDigest: acceptedBody, RevokedSetDigest: bytes.Clone(setDigest), RevokedCertIDs: []string{"x"}, Accepted: true},
				{ObjectType: uint16(v2RevocationList), StatusKeyEpoch: 1, Sequence: 5, EvidenceDigest: bytes.Repeat([]byte{4}, sha512.Size384), BodyDigest: gapBody, RevokedSetDigest: bytes.Clone(setDigest), RevokedCertIDs: []string{"x"}, Gap: true},
			},
		}
		compacted := compactRevocationStatusObservationsV2(state)
		if len(compacted.Observations) != 1 || compacted.Observations[0].Gap || !compacted.Observations[0].Accepted {
			t.Fatalf("accepted-base gap cleanup depends on digest ordering (acceptedFirst=%t): %+v", acceptedFirst, compacted.Observations)
		}
	}
}

func TestSecurityJournalV2RotatesStatusEpochAfterSequentialSnapshots(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("8", 64)
	oldPub, oldKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newPub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, oldPub); err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 2; seq++ {
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: seq, Revoked: []RevokedCertV2{}}, issuerID, oldPub, oldKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, oldPub, policy, 100); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 2, newPub)
	if err != nil {
		t.Fatal(err)
	}
	state := journal.StatusByIssuer[issuerID]
	if state.StatusKeyEpoch != 2 || state.HasFloor || state.HasPrecedingCheckpoint || state.PrecedingFloor != 0 || len(state.PrecedingAcceptedCertIDs) != 0 {
		t.Fatalf("status epoch rotation retained an old floor checkpoint: %+v", state)
	}
}

func TestSecurityJournalV2CompactsRepeatedFutureHeartbeats(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("7", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 150, MaxStatusAgeSeconds: 100, ClockSkewSeconds: 1}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	for updatedAt := int64(110); updatedAt <= 130; updatedAt++ {
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: 200, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "future"}}}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100); err != nil {
			t.Fatal(err)
		}
	}
	journal, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(journal.StatusByIssuer[issuerID].Observations); got != 1 {
		t.Fatalf("future-dated same-sequence heartbeats grew the compact journal: %d observations", got)
	}
}

func TestSecurityJournalV2ReplayOfCompactedAcceptedHeartbeatDoesNotRefork(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("6", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	apply := func(sequence, updatedAt, nextUpdate int64, ids ...string) SecurityJournalV2 {
		t.Helper()
		revoked := make([]RevokedCertV2, 0, len(ids))
		for _, id := range ids {
			revoked = append(revoked, RevokedCertV2{CertID: id})
		}
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: revoked}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, 100)
		if err != nil {
			t.Fatal(err)
		}
		return journal
	}
	apply(3, 99, 130, "x")
	first, _ := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 130, Sequence: 4, Revoked: []RevokedCertV2{{CertID: "x"}, {CertID: "y"}}}, issuerID, pub, private)
	if _, err := ApplyRevocationListToJournalV2(ctx, store, first, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	second, _ := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 100, NextUpdate: 130, Sequence: 4, Revoked: []RevokedCertV2{{CertID: "x"}, {CertID: "y"}}}, issuerID, pub, private)
	if _, err := ApplyRevocationListToJournalV2(ctx, store, second, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	apply(4, 100, 130, "x", "y", "z")
	journal := apply(5, 100, 130, "x", "y", "z")
	state := journal.StatusByIssuer[issuerID]
	if state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("setup did not reconcile the fork: %+v", state)
	}
	generation := journal.Generation
	if _, err := ApplyRevocationListToJournalV2(ctx, store, first, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	replayed, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state = replayed.StatusByIssuer[issuerID]
	if replayed.Generation != generation || state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 5 {
		t.Fatalf("replaying a compacted accepted heartbeat reopened reconciliation: %+v", state)
	}
}

func TestSecurityJournalV2ReplayOfReconciledFutureDatedForkDoesNotRefork(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("7", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	apply := func(now, sequence, updatedAt, nextUpdate int64, ids ...string) SecurityJournalV2 {
		t.Helper()
		revoked := make([]RevokedCertV2, 0, len(ids))
		for _, id := range ids {
			revoked = append(revoked, RevokedCertV2{CertID: id})
		}
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: revoked}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, now)
		if err != nil {
			t.Fatal(err)
		}
		return journal
	}
	apply(100, 3, 99, 130, "x")
	future, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 200, NextUpdate: 230, Sequence: 4, Revoked: []RevokedCertV2{{CertID: "x"}, {CertID: "y"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, future, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	apply(100, 4, 100, 130, "x", "y", "z")
	journal := apply(100, 5, 100, 130, "x", "y", "z")
	state := journal.StatusByIssuer[issuerID]
	if state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("setup did not reconcile the fork: %+v", state)
	}
	generation := journal.Generation
	if _, err := ApplyRevocationListToJournalV2(ctx, store, future, issuerID, 1, pub, policy, 200); err != nil {
		t.Fatal(err)
	}
	replayed, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state = replayed.StatusByIssuer[issuerID]
	if replayed.Generation != generation || state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 5 {
		t.Fatalf("replaying a reconciled future-dated fork reopened reconciliation: %+v", state)
	}
}

func TestSecurityJournalV2FutureSnapshotReplayAfterPushForkDoesNotRefork(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("a", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	applyList := func(now, sequence, updatedAt, nextUpdate int64, ids ...string) SecurityJournalV2 {
		t.Helper()
		revoked := make([]RevokedCertV2, 0, len(ids))
		for _, id := range ids {
			revoked = append(revoked, RevokedCertV2{CertID: id})
		}
		list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: revoked}, issuerID, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, policy, now)
		if err != nil {
			t.Fatal(err)
		}
		return journal
	}
	applyList(100, 3, 99, 130, "x")
	future, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 200, NextUpdate: 230, Sequence: 4, Revoked: []RevokedCertV2{{CertID: "x"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationListToJournalV2(ctx, store, future, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 4, PushedAt: 100, Revoked: []RevokedCertV2{{CertID: "y"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRevocationPushToJournalV2(ctx, store, push, issuerID, 1, pub, policy, 100); err != nil {
		t.Fatal(err)
	}
	journal := applyList(100, 5, 100, 130, "x", "y")
	state := journal.StatusByIssuer[issuerID]
	if state.ReconciliationRequired || state.ForkSequence != 0 {
		t.Fatalf("setup did not reconcile the push fork: %+v", state)
	}
	generation := journal.Generation
	if _, err := ApplyRevocationListToJournalV2(ctx, store, future, issuerID, 1, pub, policy, 200); err != nil {
		t.Fatal(err)
	}
	replayed, _, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state = replayed.StatusByIssuer[issuerID]
	if replayed.Generation != generation || state.ReconciliationRequired || state.ForkSequence != 0 || state.Floor != 5 {
		t.Fatalf("replaying a future snapshot after push-fork recovery reopened reconciliation: %+v", state)
	}
}
