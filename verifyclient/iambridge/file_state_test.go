package iambridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func TestFileStateRefusesToResetAfterLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status-state.json")
	first := &FileState{Path: path}
	if err := first.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Load(); err != nil {
		t.Fatalf("new bridge should start without state: %v", err)
	}
	if err := first.Save(State{IssuerID: "issuer", Epoch: 1, Sequence: 3}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	restarted := &FileState{Path: path}
	if err := restarted.Lock(); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err := restarted.Load(); err == nil {
		t.Fatal("lost state must not reset the sequence and revocations")
	}
}

func TestFileStateCanRestartBeforeFirstSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status-state.json")
	first := &FileState{Path: path}
	if err := first.Lock(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := &FileState{Path: path}
	if err := restarted.Lock(); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err := restarted.Load(); err != nil {
		t.Fatalf("an empty lock file should not mark unpublished state as lost: %v", err)
	}
}

func TestFileStateUnblockRequiresConfirmedAcceptedSequence(t *testing.T) {
	state := &FileState{Path: filepath.Join(t.TempDir(), "status-state.json")}
	if err := state.Lock(); err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Save(State{IssuerID: "issuer", Epoch: 1, Sequence: 2,
		Pending: &Pending{Sequence: 3, Blocked: true}}); err != nil {
		t.Fatal(err)
	}
	if err := state.Unblock(1, 3); err == nil {
		t.Fatal("operator supplied a different accepted sequence")
	}
	if err := state.Unblock(2, 1); err == nil {
		t.Fatal("operator supplied a maximum observation below the accepted floor")
	}
	if err := state.Unblock(2, 3); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load()
	if err != nil || loaded.Pending.Blocked || !loaded.Pending.NeedsRefresh || loaded.Pending.Sequence != 4 {
		t.Fatalf("unblock did not require a fresh IAM snapshot: %+v %v", loaded, err)
	}
}

func TestFileStateUnblockPublishesAboveObservedFork(t *testing.T) {
	bridge, source, publisher, _ := testBridge(t)
	state := &FileState{Path: filepath.Join(t.TempDir(), "status-state.json")}
	if err := state.Lock(); err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Save(State{IssuerID: bridge.IssuerID, Epoch: 1, Sequence: 2,
		UpdatedAt: 1770000000, Revoked: []string{"cert-a"},
		Pending: &Pending{Sequence: 3, Revoked: []string{"cert-a"},
			Wire: []byte("rejected"), UpdatedAt: 1770000001, Blocked: true}}); err != nil {
		t.Fatal(err)
	}
	if err := state.Unblock(2, 3); err != nil {
		t.Fatal(err)
	}
	bridge.Store = state
	*publisher.remote = RemoteStatus{Epoch: 1, HasFloor: true, Floor: 2, MaxObserved: 3}
	bridge.Now = func() time.Time { return time.Unix(1770000120, 0) }
	source.snapshot.ObservedAt = bridge.Now()
	source.snapshot.RevokedCertIDs = []string{"cert-a"}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := ratify.DecodeRevocationListV2(publisher.wires[0])
	if err != nil || list.Sequence != 4 {
		t.Fatalf("unblock did not advance above the observed fork: %+v %v", list, err)
	}
}

func TestFileStateUnblockBeforeFirstObservedList(t *testing.T) {
	state := &FileState{Path: filepath.Join(t.TempDir(), "status-state.json")}
	if err := state.Lock(); err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Save(State{IssuerID: "issuer", Epoch: 1,
		Pending: &Pending{Sequence: 1, Blocked: true}}); err != nil {
		t.Fatal(err)
	}
	if err := state.Unblock(0, 0); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load()
	if err != nil || loaded.Pending.Sequence != 1 || !loaded.Pending.NeedsRefresh {
		t.Fatalf("unobserved first list could not be retried after correction: %+v %v", loaded, err)
	}
}
