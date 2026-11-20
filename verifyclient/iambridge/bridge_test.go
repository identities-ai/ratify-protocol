package iambridge

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type testSource struct {
	snapshot Snapshot
	err      error
}

func (s *testSource) Snapshot(context.Context) (Snapshot, error) { return s.snapshot, s.err }

// testPublisher models Verify: a delivered list at or above the floor is
// accepted. delivered makes an erroring send still reach Verify, as when
// only the response is lost.
//
// newPublisher models a publisher that does not hold the issuer: Verify
// refuses a list at or below the accepted floor or observed sequence with
// status_publication_conflict.
// leaseHeld models another live holder: lists that pass the guard are
// refused with status_publisher_conflict.
type testPublisher struct {
	wires        [][]byte
	err          error
	delivered    bool
	remote       *RemoteStatus
	newPublisher bool
	leaseHeld    bool
}

func (p *testPublisher) Publish(_ context.Context, wire []byte) error {
	p.wires = append(p.wires, append([]byte(nil), wire...))
	if p.newPublisher || p.leaseHeld {
		list, err := ratify.DecodeRevocationListV2(wire)
		if err != nil {
			panic(err)
		}
		if p.remote.HasFloor && list.Sequence <= p.remote.Floor || list.Sequence <= p.remote.MaxObserved {
			return ErrSequenceConflict
		}
		if p.leaseHeld {
			return ErrPublisherConflict
		}
	}
	if p.err == nil || p.delivered {
		list, err := ratify.DecodeRevocationListV2(wire)
		if err != nil {
			panic(err)
		}
		digest, err := ratify.StatusEvidenceDigest(revocationListObjectType, list)
		if err != nil {
			panic(err)
		}
		p.remote.MaxObserved = max(p.remote.MaxObserved, list.Sequence)
		if !p.remote.HasFloor || list.Sequence >= p.remote.Floor {
			p.remote.HasFloor, p.remote.Floor = true, list.Sequence
			p.remote.AcceptedDigest = "sha384:" + hex.EncodeToString(digest)
		}
	}
	return p.err
}

type testStatus struct {
	remote *RemoteStatus
	err    error
}

func (s *testStatus) IssuerStatus(context.Context) (RemoteStatus, error) { return *s.remote, s.err }

type testStore struct{ state State }

func (s *testStore) Load() (State, error) { return s.state, nil }
func (s *testStore) Save(state State) error {
	s.state = state
	return nil
}

func testBridge(t *testing.T) (*Bridge, *testSource, *testPublisher, *testStore) {
	t.Helper()
	_, key, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerID := strings.Repeat("a", 64)
	source := &testSource{snapshot: Snapshot{IssuerID: issuerID, Revision: "7", Complete: true,
		ObservedAt: time.Unix(1770000000, 0), RevokedCertIDs: []string{}}}
	remote := &RemoteStatus{Epoch: 1}
	publisher := &testPublisher{remote: remote}
	store := &testStore{}
	bridge := &Bridge{IssuerID: issuerID, Epoch: 1, StatusKey: key, Source: source,
		Publisher: publisher, Status: &testStatus{remote: remote}, Store: store, Now: func() time.Time { return time.Unix(1770000000, 0) },
		Lifetime: 5 * time.Minute, MaxSnapshotAge: 30 * time.Second}
	return bridge, source, publisher, store
}

func TestAmbiguousPublishRetriesExactWireBeforeReadingNewIAMState(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = errors.New("network timeout after send")
	if err := bridge.Reconcile(context.Background()); err == nil {
		t.Fatal("ambiguous publication was reported as accepted")
	}
	if store.state.Pending == nil || store.state.Sequence != 0 {
		t.Fatal("signed list was not saved before the ambiguous send")
	}
	// A restart during an IAM outage publishes nothing, not even the saved
	// bytes: IAM may have revoked more since they were signed.
	source.err = errors.New("IAM is unavailable")
	publisher.err = nil
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != 1 {
		t.Fatal("saved list was published during an IAM outage")
	}
	source.err = nil
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if string(publisher.wires[0]) != string(publisher.wires[1]) || store.state.Sequence != 1 {
		t.Fatal("retry changed the signed list or skipped its sequence")
	}
	source.err = errors.New("IAM is unavailable")
	if err := bridge.Reconcile(context.Background()); err == nil {
		t.Fatal("IAM outage produced a fresh status heartbeat")
	}
	if len(publisher.wires) != 2 {
		t.Fatal("IAM outage published a status list")
	}
}

func TestCompleteSnapshotsKeepRevocationMonotonic(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"parent-cert", "child-cert"}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstUpdatedAt := store.state.UpdatedAt
	source.snapshot.Revision = "8"
	source.snapshot.RevokedCertIDs = []string{} // A grant cannot be restored under the same cert ID.
	source.snapshot.ObservedAt = source.snapshot.ObservedAt.Add(time.Minute)
	bridge.Now = func() time.Time { return time.Unix(1770000060, 0) }
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[1])
	if err != nil {
		t.Fatal(err)
	}
	if list.Sequence != 1 || len(list.Revoked) != 2 || list.Revoked[0].CertID != "child-cert" ||
		list.Revoked[1].CertID != "parent-cert" || store.state.Sequence != 1 ||
		list.UpdatedAt <= firstUpdatedAt {
		t.Fatalf("revocation was lost after a later IAM snapshot: %+v", list)
	}
}

func TestExpiredAmbiguousListReadsIAMBeforeRestoringFreshStatus(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = errors.New("response lost")
	if err := bridge.Reconcile(context.Background()); err == nil {
		t.Fatal("ambiguous response was accepted")
	}
	first, err := ratify.DecodeRevocationListV2(publisher.wires[0])
	if err != nil {
		t.Fatal(err)
	}
	now := first.NextUpdate + 1
	bridge.Now = func() time.Time { return time.Unix(now, 0) }
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
	source.snapshot.ObservedAt = time.Unix(now, 0)
	source.err = errors.New("IAM unavailable")
	publisher.err = nil
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != 1 {
		t.Fatal("outage published fresh status without reading IAM")
	}
	source.err = nil
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	refreshed, err := ratify.DecodeRevocationListV2(publisher.wires[1])
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Sequence != first.Sequence+1 || refreshed.UpdatedAt <= first.UpdatedAt ||
		len(refreshed.Revoked) != 2 || refreshed.Revoked[0].CertID != "cert-a" ||
		refreshed.Revoked[1].CertID != "cert-b" || store.state.Sequence != 2 {
		t.Fatalf("expired ambiguous list omitted new IAM revocations: %+v", refreshed)
	}
	now++
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := ratify.DecodeRevocationListV2(publisher.wires[2])
	if err != nil {
		t.Fatal(err)
	}
	if next.Sequence != 2 || len(next.Revoked) != 2 || next.UpdatedAt <= refreshed.UpdatedAt {
		t.Fatalf("unchanged IAM snapshot did not heartbeat after recovery: %+v", next)
	}
}

func TestDefinitiveRejectionCannotAdvanceSequence(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = ErrDefinitivePublication
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) {
		t.Fatalf("expected definitive rejection, got %v", err)
	}
	if store.state.Pending == nil || !store.state.Pending.Blocked {
		t.Fatal("definitive rejection was not durably blocked")
	}
	bridge.Now = func() time.Time { return time.Unix(1770000120, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
	publisher.err = nil
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != 1 {
		t.Fatal("definitive rejection was retried or skipped")
	}
}

func TestStaleConflictRefreshesFromIAM(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = ErrRefreshRequired
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrRefreshRequired) {
		t.Fatalf("expected refresh request: %v", err)
	}
	if store.state.Pending == nil || !store.state.Pending.NeedsRefresh || store.state.Pending.Blocked {
		t.Fatal("refresh request was not saved as recoverable")
	}
	bridge.Now = func() time.Time { return time.Unix(1770000001, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
	publisher.err = nil
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[1])
	if err != nil || list.Sequence != 2 || len(list.Revoked) != 2 || store.state.Pending != nil {
		t.Fatalf("refresh lost current IAM revocations: %+v %v", list, err)
	}
}

func TestAmbiguousRetryKeepsSequenceForUnchangedIAM(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = errors.New("response lost")
	if err := bridge.Reconcile(context.Background()); err == nil {
		t.Fatal("ambiguous send was reported as accepted")
	}
	bridge.Now = func() time.Time { return time.Unix(1770000060, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); err == nil ||
		string(publisher.wires[0]) != string(publisher.wires[1]) {
		t.Fatal("first retry did not resend the exact signed wire")
	}
	bridge.Now = func() time.Time { return time.Unix(1770000120, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); err == nil {
		t.Fatal("ambiguous refreshed send was reported as accepted")
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[2])
	if err != nil || list.Sequence != 1 || store.state.Pending.Sequence != 1 ||
		list.UpdatedAt != 1770000090 {
		t.Fatalf("unchanged IAM consumed a new sequence: %+v %v", list, err)
	}
}

func TestPendingSameSequenceCannotChangeAcceptedRevocations(t *testing.T) {
	bridge, _, publisher, store := testBridge(t)
	store.state = State{IssuerID: bridge.IssuerID, Epoch: 1, Sequence: 1,
		UpdatedAt: 1770000000, Revoked: []string{"cert-a"},
		Pending: &Pending{Sequence: 1, UpdatedAt: 1770000001,
			Revoked: []string{"cert-b"}, Wire: []byte("wire")}}
	bridge.Now = func() time.Time { return time.Unix(1770000002, 0) }
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != 0 {
		t.Fatal("same-sequence pending fork was published")
	}
}

func TestIncompleteOrCrossIssuerSnapshotCannotPublish(t *testing.T) {
	for _, snapshot := range []Snapshot{
		{IssuerID: strings.Repeat("a", 64), Revision: "7", Complete: false, ObservedAt: time.Unix(1770000000, 0)},
		{IssuerID: "other-tenant", Revision: "7", Complete: true, ObservedAt: time.Unix(1770000000, 0)},
		{IssuerID: strings.Repeat("a", 64), Revision: "7", Complete: true, ObservedAt: time.Unix(1769999900, 0)},
	} {
		bridge, source, publisher, store := testBridge(t)
		source.snapshot = snapshot
		if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != 0 || store.state.Pending != nil {
			t.Fatalf("untrusted IAM snapshot published: %+v %v", snapshot, err)
		}
	}
}

// An ambiguous list that Verify did accept, but whose outcome was unknown
// until after it expired, is recognized by its digest. The bridge commits it
// and heartbeats the same sequence rather than consuming a new one.
func TestExpiredAmbiguousAcceptedListIsReconciledFromVerify(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err, publisher.delivered = errors.New("response lost"), true
	if err := bridge.Reconcile(context.Background()); err == nil {
		t.Fatal("ambiguous response was accepted locally")
	}
	first, err := ratify.DecodeRevocationListV2(publisher.wires[0])
	if err != nil {
		t.Fatal(err)
	}
	now := first.NextUpdate + 1
	bridge.Now = func() time.Time { return time.Unix(now, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	publisher.err, publisher.delivered = nil, false
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, err := ratify.DecodeRevocationListV2(publisher.wires[1])
	if err != nil || next.Sequence != 1 || store.state.Sequence != 1 || store.state.Pending != nil ||
		publisher.remote.MaxObserved != 1 {
		t.Fatalf("accepted ambiguous list consumed or forked a sequence: %+v state=%+v %v", next, store.state, err)
	}
}

// A same-sequence refresh keeps the digests of earlier signed wires, so an
// earlier wire that Verify accepted still proves acceptance.
func TestEarlierSameSequenceWireProvesAcceptance(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err, publisher.delivered = errors.New("response lost"), true
	_ = bridge.Reconcile(context.Background())
	publisher.delivered = false
	bridge.Now = func() time.Time { return time.Unix(1770000100, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	*publisher.remote = RemoteStatus{Epoch: 1} // Verify's answer was not yet visible.
	_ = bridge.Reconcile(context.Background())
	if store.state.Pending == nil || len(store.state.Pending.Digests) != 2 || store.state.Pending.Sequence != 1 {
		t.Fatalf("same-sequence refresh lost earlier digests: %+v", store.state.Pending)
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[0])
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ratify.StatusEvidenceDigest(revocationListObjectType, list)
	if err != nil {
		t.Fatal(err)
	}
	*publisher.remote = RemoteStatus{Epoch: 1, HasFloor: true, Floor: 1, MaxObserved: 1,
		AcceptedDigest: "sha384:" + hex.EncodeToString(digest)}
	bridge.Now = func() time.Time { return time.Unix(1770000200, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	publisher.err = nil
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.state.Sequence != 1 || store.state.Pending != nil {
		t.Fatalf("earlier accepted wire was not recognized: %+v", store.state)
	}
}

// When Verify has observed a sequence beyond this bridge's pending list
// without accepting anything at or above it, the history does not follow
// this bridge's state. The bridge blocks instead of signing over it.
func TestForeignAdvanceBlocksReconciliation(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = ErrRefreshRequired
	_ = bridge.Reconcile(context.Background())
	*publisher.remote = RemoteStatus{Epoch: 1, MaxObserved: 2}
	publisher.err = nil
	bridge.Now = func() time.Time { return time.Unix(1770000001, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) ||
		store.state.Pending == nil || !store.state.Pending.Blocked || len(publisher.wires) != 1 {
		t.Fatalf("foreign observation did not block: %v %+v", err, store.state.Pending)
	}
}

// When Verify's accepted floor already covers the pending sequence (a
// restored or restarted state, or a lapsed writer), the bridge does not need
// an operator: it republishes its complete revoked set above everything
// Verify accepted or observed, never at a sequence Verify already holds.
func TestFloorAtOrAbovePendingContinuesAboveVerify(t *testing.T) {
	for _, remote := range []RemoteStatus{
		// Another writer's list accepted at this bridge's pending sequence.
		{Epoch: 1, HasFloor: true, Floor: 1, MaxObserved: 1, AcceptedDigest: "sha384:other"},
		// This bridge's list was accepted, but a later list was observed.
		{Epoch: 1, HasFloor: true, Floor: 1, MaxObserved: 2, AcceptedDigest: "pending"},
		{Epoch: 1, HasFloor: true, Floor: 3, MaxObserved: 3, AcceptedDigest: "sha384:other"},
	} {
		bridge, source, publisher, store := testBridge(t)
		source.snapshot.RevokedCertIDs = []string{"cert-a"}
		publisher.err = ErrRefreshRequired
		_ = bridge.Reconcile(context.Background())
		if remote.AcceptedDigest == "pending" {
			remote.AcceptedDigest = store.state.Pending.Digests[0]
		}
		*publisher.remote = remote
		publisher.err = nil
		bridge.Now = func() time.Time { return time.Unix(1770000001, 0) }
		source.snapshot.ObservedAt = bridge.Now()
		if err := bridge.Reconcile(context.Background()); err != nil {
			t.Fatalf("covered pending %+v did not reconcile: %v", remote, err)
		}
		list := decodeLast(t, publisher)
		if len(publisher.wires) != 2 || list.Sequence != max(remote.Floor, remote.MaxObserved)+1 ||
			!slices.Equal(revokedIDs(list), []string{"cert-a"}) || store.state.Sequence != list.Sequence {
			t.Fatalf("covered pending %+v republished %+v state=%+v", remote, list, store.state)
		}
	}
}

// A new bridge state starts above whatever Verify already accepted or
// observed in this epoch, so it never forks an existing sequence.
func TestInitialSyncStartsAboveVerifyHistory(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	*publisher.remote = RemoteStatus{Epoch: 1, HasFloor: true, Floor: 4, MaxObserved: 6, AcceptedDigest: "sha384:console"}
	source.snapshot.RevokedCertIDs = []string{}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[0])
	if err != nil || list.Sequence != 7 || store.state.Sequence != 7 {
		t.Fatalf("initial sync did not start above Verify history: %+v state=%+v %v", list, store.state, err)
	}
}

// A writer for a rotated-out epoch never publishes again.
func TestRotatedEpochStopsWriter(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	*publisher.remote = RemoteStatus{Epoch: 2}
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) || len(publisher.wires) != 0 {
		t.Fatalf("fresh bridge published into a rotated epoch: %v", err)
	}
	*publisher.remote = RemoteStatus{Epoch: 1}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// After rotation an idle writer refuses before signing anything.
	*publisher.remote = RemoteStatus{Epoch: 2}
	bridge.Now = func() time.Time { return time.Unix(1770000060, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) ||
		len(publisher.wires) != 1 || store.state.Pending != nil {
		t.Fatalf("rotated-out writer signed a list: %v %+v", err, store.state.Pending)
	}
	// A writer with a list in flight is durably blocked.
	*publisher.remote = RemoteStatus{Epoch: 1, HasFloor: true, Floor: 1, MaxObserved: 1, AcceptedDigest: publisher.remote.AcceptedDigest}
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
	publisher.err = ErrRefreshRequired
	_ = bridge.Reconcile(context.Background())
	publisher.err = nil
	publisher.remote.Epoch = 2
	bridge.Now = func() time.Time { return time.Unix(1770000061, 0) }
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) ||
		store.state.Pending == nil || !store.state.Pending.Blocked {
		t.Fatalf("rotated-out writer was not durably blocked: %v %+v", err, store.state.Pending)
	}
}

// A writer whose lease lapsed resumes only from Verify's checkpoint: if
// another writer advanced the issuer, it signs nothing.
func TestResumedWriterRefusesWhenVerifyAdvanced(t *testing.T) {
	for _, remote := range []RemoteStatus{
		{Epoch: 1, HasFloor: true, Floor: 3, MaxObserved: 3, AcceptedDigest: "sha384:other"},
		{Epoch: 1, HasFloor: true, Floor: 1, MaxObserved: 2},
	} {
		bridge, source, publisher, store := testBridge(t)
		source.snapshot.RevokedCertIDs = []string{"cert-a"}
		if err := bridge.Reconcile(context.Background()); err != nil || store.state.Sequence != 1 {
			t.Fatalf("first publication: %v %+v", err, store.state)
		}
		*publisher.remote = remote
		bridge.Now = func() time.Time { return time.Unix(1770000060, 0) }
		source.snapshot.ObservedAt = bridge.Now()
		source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
		if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) || len(publisher.wires) != 1 {
			t.Fatalf("resumed writer signed over %+v: %v", remote, err)
		}
	}
}

// A writer refused by another publisher's lease keeps no claim on the
// issuer: it must reconcile with Verify before publishing again, and an
// unreachable Verify status publishes nothing.
func TestPublisherConflictRequiresVerifyReconciliation(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	status := bridge.Status.(*testStatus)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = ErrPublisherConflict
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrPublisherConflict) {
		t.Fatal(err)
	}
	if store.state.Pending == nil || store.state.Pending.Blocked || !store.state.Pending.NeedsRefresh {
		t.Fatalf("lease conflict was not saved as recoverable: %+v", store.state.Pending)
	}
	status.err = errors.New("Verify unavailable")
	publisher.err = nil
	bridge.Now = func() time.Time { return time.Unix(1770000001, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != 1 {
		t.Fatal("published without reconciling against Verify")
	}
}

// A crash after saving a list, followed by a new IAM revocation, must not
// publish the saved list that omits it; the bridge reconciles and signs the
// current set at the next sequence.
func TestSavedListIsNotSentAfterIAMRevokesMore(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = errors.New("process crashed before the send completed")
	_ = bridge.Reconcile(context.Background())
	saved := string(publisher.wires[0])
	publisher.err = nil
	bridge.Now = func() time.Time { return time.Unix(1770000005, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[1])
	if err != nil || string(publisher.wires[1]) == saved || list.Sequence != 2 || len(list.Revoked) != 2 || store.state.Sequence != 2 {
		t.Fatalf("saved list omitting a new revocation was sent: %+v %v", list, err)
	}
}

// staleRestart leaves the bridge as a stale restart does: accepted sequence 1
// with cert-a, and a pending list at sequence 2 with cert-a and cert-b that
// the previous process signed. Verify then accepts sequence 2 from that
// previous process (accepted is that list's digest, or another writer's when
// empty), and this process restarts under a new publisher fingerprint.
func staleRestart(t *testing.T, sameList bool) (*Bridge, *testSource, *testPublisher, *testStore) {
	t.Helper()
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	bridge.Now = func() time.Time { return time.Unix(1770000060, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-b"}
	publisher.err = errors.New("process stopped before the response")
	publisher.delivered = sameList
	_ = bridge.Reconcile(context.Background())
	publisher.err, publisher.delivered = nil, false
	if store.state.Pending == nil || store.state.Pending.Sequence != 2 || store.state.Sequence != 1 {
		t.Fatalf("setup: %+v", store.state)
	}
	if !sameList {
		*publisher.remote = RemoteStatus{Epoch: 1, HasFloor: true, Floor: 2, MaxObserved: 2, AcceptedDigest: "sha384:previous"}
	}
	publisher.newPublisher = true
	bridge.Now = func() time.Time { return time.Unix(1770000070, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	return bridge, source, publisher, store
}

func decodeLast(t *testing.T, publisher *testPublisher) *ratify.RevocationListV2 {
	t.Helper()
	list, err := ratify.DecodeRevocationListV2(publisher.wires[len(publisher.wires)-1])
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func revokedIDs(list *ratify.RevocationListV2) []string {
	ids := make([]string, 0, len(list.Revoked))
	for _, entry := range list.Revoked {
		ids = append(ids, entry.CertID)
	}
	return ids
}

// Issue #158: a restarted bridge with a new publisher fingerprint retried a
// pending sequence Verify had already accepted from the previous publisher
// and was refused forever. The refusal must not block the bridge: it learns
// Verify's floor and republishes the complete revoked set above it, without
// re-sending the stale sequence or dropping its revocations.
func TestRestartWithStalePendingRepublishesAboveVerifyFloor(t *testing.T) {
	bridge, _, publisher, store := staleRestart(t, false)
	err := bridge.Reconcile(context.Background())
	if !errors.Is(err, ErrSequenceConflict) || store.state.Pending == nil || store.state.Pending.Blocked {
		t.Fatalf("stale-sequence refusal was not saved as recoverable: %v %+v", err, store.state.Pending)
	}
	sent := len(publisher.wires)
	bridge.Now = func() time.Time { return time.Unix(1770000080, 0) }
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatalf("bridge stayed stuck on the stale sequence: %v", err)
	}
	list := decodeLast(t, publisher)
	if len(publisher.wires) != sent+1 || list.Sequence != 3 || !slices.Equal(revokedIDs(list), []string{"cert-a", "cert-b"}) {
		t.Fatalf("republication did not carry the complete set above the floor: %+v", list)
	}
	if store.state.Sequence != 3 || store.state.Pending != nil || publisher.remote.Floor != 3 {
		t.Fatalf("republished list was not committed: %+v remote=%+v", store.state, publisher.remote)
	}
}

// When the list Verify accepted at the pending sequence is this bridge's
// own, the pending list is delivered: the bridge commits it and does not
// sign a different list at that sequence.
func TestRestartWithIdenticalAcceptedListMarksItDelivered(t *testing.T) {
	bridge, _, publisher, store := staleRestart(t, true)
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("new publisher's retry at the floor: %v", err)
	}
	accepted := publisher.remote.AcceptedDigest
	bridge.Now = func() time.Time { return time.Unix(1770000080, 0) }
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, wire := range publisher.wires[2:] {
		list, err := ratify.DecodeRevocationListV2(wire)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := ratify.StatusEvidenceDigest(revocationListObjectType, list)
		if err != nil {
			t.Fatal(err)
		}
		if list.Sequence == 2 && "sha384:"+hex.EncodeToString(digest) != accepted {
			t.Fatal("a different list was signed at the delivered sequence")
		}
	}
	list := decodeLast(t, publisher)
	if store.state.Sequence != 3 || store.state.Pending != nil || list.Sequence != 3 ||
		!slices.Equal(revokedIDs(list), []string{"cert-a", "cert-b"}) {
		t.Fatalf("delivered list was not committed before continuing: %+v %+v", store.state, list)
	}
}

// A revocation that IAM reports while the bridge is stuck is published with
// every earlier one, in the list above Verify's floor.
func TestRevocationWhileStuckIsPublished(t *testing.T) {
	bridge, source, publisher, store := staleRestart(t, false)
	_ = bridge.Reconcile(context.Background())
	bridge.Now = func() time.Time { return time.Unix(1770000080, 0) }
	// IAM's complete set adds cert-c; a snapshot omitting cert-b still
	// cannot drop it, because the revoked set is cumulative.
	source.snapshot.ObservedAt = bridge.Now()
	source.snapshot.RevokedCertIDs = []string{"cert-a", "cert-c"}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list := decodeLast(t, publisher)
	if list.Sequence != 3 || !slices.Equal(revokedIDs(list), []string{"cert-a", "cert-b", "cert-c"}) ||
		!slices.Equal(store.state.Revoked, []string{"cert-a", "cert-b", "cert-c"}) {
		t.Fatalf("revocation during the stuck period was lost: %+v state=%+v", list, store.state)
	}
}

// While another bridge holds the issuer, the restarted bridge never forks
// Verify's history: every republication is above Verify's floor and is
// fenced by the holder's lease. Once the lease is released it takes over
// with the complete revoked set.
func TestConcurrentHolderFencesStaleRestart(t *testing.T) {
	bridge, source, publisher, store := staleRestart(t, false)
	publisher.leaseHeld = true
	_ = bridge.Reconcile(context.Background())
	bridge.Now = func() time.Time { return time.Unix(1770000080, 0) }
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrPublisherConflict) {
		t.Fatalf("live holder did not fence the republication: %v", err)
	}
	if store.state.Pending == nil || store.state.Pending.Sequence != 3 || !store.state.Pending.NeedsRefresh ||
		store.state.Sequence != 2 || publisher.remote.Floor != 2 {
		t.Fatalf("fenced republication changed Verify or lost its place: %+v remote=%+v", store.state, publisher.remote)
	}
	// The holder publishes sequence 3 itself.
	*publisher.remote = RemoteStatus{Epoch: 1, HasFloor: true, Floor: 3, MaxObserved: 3, AcceptedDigest: "sha384:holder"}
	bridge.Now = func() time.Time { return time.Unix(1770000090, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrPublisherConflict) ||
		decodeLast(t, publisher).Sequence != 4 || publisher.remote.Floor != 3 || publisher.remote.AcceptedDigest != "sha384:holder" {
		t.Fatalf("stale restart signed over a live holder: %v %+v remote=%+v", err, store.state.Pending, publisher.remote)
	}
	// The holder releases its lease.
	publisher.leaseHeld = false
	bridge.Now = func() time.Time { return time.Unix(1770000100, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list := decodeLast(t, publisher)
	if list.Sequence != 4 || !slices.Equal(revokedIDs(list), []string{"cert-a", "cert-b"}) ||
		store.state.Sequence != 4 || publisher.remote.Floor != 4 {
		t.Fatalf("takeover after release: %+v state=%+v", list, store.state)
	}
}

// A refusal above Verify's floor is a real history conflict, not a stale
// restart: the bridge blocks durably.
func TestSequenceConflictAboveFloorBlocks(t *testing.T) {
	bridge, source, publisher, store := testBridge(t)
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	publisher.err = ErrSequenceConflict
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrSequenceConflict) {
		t.Fatal(err)
	}
	publisher.err = nil
	bridge.Now = func() time.Time { return time.Unix(1770000010, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrDefinitivePublication) ||
		!store.state.Pending.Blocked || len(publisher.wires) != 1 {
		t.Fatalf("conflict above the floor did not block: %v %+v", err, store.state.Pending)
	}
}

// Without Verify's status the outcome is unknown, so nothing is signed and
// the stale-sequence refusal is kept for the next attempt.
func TestStaleRestartWaitsForVerifyStatus(t *testing.T) {
	bridge, _, publisher, store := staleRestart(t, false)
	_ = bridge.Reconcile(context.Background())
	bridge.Status.(*testStatus).err = errors.New("Verify unavailable")
	bridge.Now = func() time.Time { return time.Unix(1770000200, 0) }
	sent := len(publisher.wires)
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != sent ||
		store.state.Pending == nil || store.state.Pending.Blocked || !store.state.Pending.SequenceConflict {
		t.Fatalf("signed without Verify's status: %v %+v", err, store.state.Pending)
	}
}

// Verify refuses a recovery list that omits a revocation it already accepted
// from another publisher (status_revocation_omitted). The bridge cannot see
// the missing ID, so it must block for the customer to add it to IAM rather
// than reconcile and re-sign the same incomplete set.
func TestRevocationOmittedRecoveryBlocks(t *testing.T) {
	bridge, _, publisher, store := staleRestart(t, false)
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrSequenceConflict) {
		t.Fatal(err)
	}
	publisher.newPublisher, publisher.err = false, ErrRevocationOmitted
	bridge.Now = func() time.Time { return time.Unix(1770000080, 0) }
	if err := bridge.Reconcile(context.Background()); !errors.Is(err, ErrRevocationOmitted) {
		t.Fatalf("recovery list: %v", err)
	}
	if store.state.Pending == nil || !store.state.Pending.Blocked || store.state.Pending.SequenceConflict ||
		store.state.Pending.NeedsRefresh {
		t.Fatalf("an omitted revocation was not a durable block: %+v", store.state.Pending)
	}
	sent := len(publisher.wires)
	publisher.err = nil
	bridge.Now = func() time.Time { return time.Unix(1770000090, 0) }
	if err := bridge.Reconcile(context.Background()); err == nil || len(publisher.wires) != sent {
		t.Fatalf("a blocked bridge published again: %v", err)
	}
}
