package v2reference

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func newTestDevice(t *testing.T) (*DevicePrimaryTestOnly, *DeviceComponentTestOnly, *DeviceCheckpointTestOnly) {
	t.Helper()
	return newTestDeviceWithCapacity(t, 4)
}

func newTestDeviceWithCapacity(t *testing.T, capacity int) (*DevicePrimaryTestOnly, *DeviceComponentTestOnly, *DeviceCheckpointTestOnly) {
	t.Helper()
	_, priv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(1_000, 30, "dddddddddddddddddddddddddddddd01", priv)
	if err != nil {
		t.Fatal(err)
	}
	store.SetAcknowledgementWithheld(true)
	primary, err := NewDevicePrimaryTestOnly(store, 3)
	if err != nil {
		t.Fatal(err)
	}
	component, err := NewDeviceComponentTestOnly(bytes.Repeat([]byte{7}, 32), capacity, store)
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewDeviceCheckpointTestOnly(primary, component, component.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Provision(); err != nil {
		t.Fatal(err)
	}
	return primary, component, device
}

func testChallengeRecord(b byte) ratify.ExpectedChallengeV2 {
	return ratify.ExpectedChallengeV2{Value: bytes.Repeat([]byte{b}, 32), IssuedAt: 990, ExpiresAt: 1_290, VerifierNamespace: "device-ns", ReplayEpoch: 3}
}

// Every member of the complete-state projection changes the digest on its
// own, so a rollback of any one durable record is detectable even when the
// receipt log and every other record are unchanged (SPEC-v2 §7.13).
func TestDeviceStateDigestCoversEveryMember(t *testing.T) {
	ctx := context.Background()
	primary, _, _ := newTestDevice(t)
	if _, err := primary.Store.ClaimV2(ctx, KeyedClaimForTest("claim-1", ratify.V2ChallengeClaim{Namespace: "device-ns", ReplayEpoch: 3, IssuedAt: 990, ExpiresAt: 1_290, MaxAgeSeconds: 300})); err != nil {
		t.Fatal(err)
	}
	base, err := primary.CompleteStateDigestTestOnly()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DevicePrimaryTestOnly){
		"claim state":     func(p *DevicePrimaryTestOnly) { p.Store.claims[claim1ID].state = stateTerminal },
		"claim lease":     func(p *DevicePrimaryTestOnly) { p.Store.claims[claim1ID].leaseExpiresAt++ },
		"claim progress":  func(p *DevicePrimaryTestOnly) { p.Store.claims[claim1ID].progress.TrustAssessment = "trusted" },
		"claim abandoned": func(p *DevicePrimaryTestOnly) { p.Store.claims[claim1ID].abandoned = true },
		"claim removed":   func(p *DevicePrimaryTestOnly) { delete(p.Store.claims, claim1ID) },
		"release record": func(p *DevicePrimaryTestOnly) {
			p.Store.claims[claim1ID].release = &ratify.V2ReleaseRecord{ClaimID: claim1ID, EntryHash: bytes.Repeat([]byte{1}, 48), AckTimestamp: 1_000, Outcome: ratify.V2ReleaseReleased}
		},
		"stream sequence": func(p *DevicePrimaryTestOnly) {
			p.Store.streams[streamKeyV2{namespace: "device-ns", agentID: "agent", streamID: "stream"}] = 2
		},
		"rate counter": func(p *DevicePrimaryTestOnly) { p.Store.rateCommits[rateKey{"issuer", "cert", 60}] = []int64{1_000} },
		"outbox entry": func(p *DevicePrimaryTestOnly) {
			p.Store.outbox = append(p.Store.outbox, outboxEntry{claimID: claim1ID, body: []byte("{}")})
		},
		"log frozen":   func(p *DevicePrimaryTestOnly) { p.Store.logFrozen = true },
		"replay epoch": func(p *DevicePrimaryTestOnly) { p.replayEpoch++ },
		"issuance record": func(p *DevicePrimaryTestOnly) {
			if err := p.Issuance.inner.PersistV2Challenge(ctx, testChallengeRecord(9)); err != nil {
				t.Fatal(err)
			}
		},
		"security journal": func(p *DevicePrimaryTestOnly) {
			pub, _, _ := ratify.GenerateHybridKeypair()
			if _, err := ratify.RecordSecurityKeyRoleV2(ctx, p.Journal.inner, "verifier", pub); err != nil {
				t.Fatal(err)
			}
		},
	} {
		mutated := primary.Clone()
		mutate(mutated)
		digest, err := mutated.CompleteStateDigestTestOnly()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(digest, base) {
			t.Errorf("changing the %s does not change the complete-state digest", name)
		}
	}
	// Every field of a release record is covered, not only its presence.
	released := primary.Clone()
	released.Store.claims[claim1ID].release = &ratify.V2ReleaseRecord{ClaimID: claim1ID, EntryHash: bytes.Repeat([]byte{1}, 48), AckTimestamp: 1_000, Outcome: ratify.V2ReleaseReleased}
	withRelease, _ := released.CompleteStateDigestTestOnly()
	for name, alter := range map[string]func(*ratify.V2ReleaseRecord){
		"release entry hash":    func(r *ratify.V2ReleaseRecord) { r.EntryHash = bytes.Repeat([]byte{2}, 48) },
		"release ack timestamp": func(r *ratify.V2ReleaseRecord) { r.AckTimestamp-- },
		"release outcome": func(r *ratify.V2ReleaseRecord) {
			r.Outcome, r.Reason = ratify.V2ReleaseWithheld, "challenge_expired"
		},
	} {
		mutated := released.Clone()
		alter(mutated.Store.claims[claim1ID].release)
		if digest, _ := mutated.CompleteStateDigestTestOnly(); bytes.Equal(digest, withRelease) {
			t.Errorf("changing the %s does not change the complete-state digest", name)
		}
	}
	// Excluded by design: clock readings and checkpoint acknowledgements.
	mutated := primary.Clone()
	mutated.Store.highWater += 100
	if digest, _ := mutated.CompleteStateDigestTestOnly(); !bytes.Equal(digest, base) {
		t.Error("a clock reading changed the complete-state digest")
	}
}

// Journal and issuance changes are anchored like claim-store changes: a
// restore that loses either is detected at startup, and a restored primary
// cannot make a new change.
func TestDeviceJournalAndIssuanceRollbackDetected(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(*DevicePrimaryTestOnly) error{
		"journal": func(p *DevicePrimaryTestOnly) error {
			pub, _, _ := ratify.GenerateHybridKeypair()
			_, err := ratify.RecordSecurityKeyRoleV2(ctx, p.Journal, "verifier", pub)
			return err
		},
		"issuance": func(p *DevicePrimaryTestOnly) error {
			return p.Issuance.PersistV2Challenge(ctx, testChallengeRecord(1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			primary, component, device := newTestDevice(t)
			snapshot := primary.Clone()
			if err := change(primary); err != nil {
				t.Fatal(err)
			}
			if got := device.Startup(); got != DeviceReady {
				t.Fatalf("after an anchored change: %s", got)
			}
			restored := snapshot.Clone()
			restoredDevice, err := NewDeviceCheckpointTestOnly(restored, component, component.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if got := restoredDevice.Startup(); got != DeviceStateDigestMismatch {
				t.Fatalf("after a rollback: %s", got)
			}
			before, _ := restored.CompleteStateDigestTestOnly()
			err = change(restored)
			if ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimStoreUnavailable {
				t.Fatalf("a rolled-back primary made a change: %v", err)
			}
			if after, _ := restored.CompleteStateDigestTestOnly(); !bytes.Equal(before, after) {
				t.Fatal("a refused change was not undone")
			}
		})
	}
}

// A different entry at an acknowledged sequence freezes the component; a
// frozen component anchors nothing more.
func TestDeviceComponentFreezesOnFork(t *testing.T) {
	ctx := context.Background()
	primary, component, device := newTestDevice(t)
	state, err := primary.anchoredDigest()
	if err != nil {
		t.Fatal(err)
	}
	entry, other := bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 48)
	if _, err := component.Commit(ctx, primary.Store.logID, 1, make([]byte, 48), entry, state); err != nil {
		t.Fatal(err)
	}
	if ack, err := component.Commit(ctx, primary.Store.logID, 1, make([]byte, 48), entry, state); err != nil || ack.Sequence != 1 {
		t.Fatalf("identical retry: %+v %v", ack, err)
	}
	if _, err := component.Commit(ctx, primary.Store.logID, 1, make([]byte, 48), other, state); !errors.Is(err, ErrDeviceFrozen) {
		t.Fatalf("fork: %v", err)
	}
	if err := component.AnchorState(state, state); !errors.Is(err, ErrDeviceFrozen) {
		t.Fatalf("anchor after freeze: %v", err)
	}
	if got := device.Startup(); got != DeviceCheckpointFrozen {
		t.Fatalf("startup: %s", got)
	}
	if err := component.ProvisionState(state); err == nil {
		t.Fatal("a provisioned component was provisioned again")
	}
}

// An acknowledgement racing anchored state changes never sees a stale
// anchored digest: the primary holds its anchor lock from composing the
// digest through the component commit, so a concurrent claim anchors either
// before or after it, never between (SPEC-v2 §7.13).
func TestDeviceAcknowledgementRacingClaimsNeverMismatches(t *testing.T) {
	ctx := context.Background()
	const entries, workers, claimsPerRound = 16, 4, 2
	primary, _, device := newTestDeviceWithCapacity(t, entries)
	store := primary.Store
	for sequence := int64(1); sequence <= entries; sequence++ {
		// Append an entry through the anchored change path, then acknowledge it
		// while claim workers anchor new state concurrently.
		store.mu.Lock()
		err := store.changeLocked(func() {
			store.outbox = append(store.outbox, outboxEntry{claimID: fmt.Sprintf("entry-%d", sequence), body: []byte("{}"), wire: []byte{1}, digest: bytes.Repeat([]byte{byte(sequence)}, 48)})
		})
		store.mu.Unlock()
		if err != nil {
			t.Fatalf("append %d: %v", sequence, err)
		}
		var wg sync.WaitGroup
		for worker := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := range claimsPerRound {
					id := fmt.Sprintf("claim-%d-%d-%d", sequence, worker, n)
					if _, err := store.ClaimV2(ctx, KeyedClaimForTest(id, ratify.V2ChallengeClaim{Namespace: "device-ns", ReplayEpoch: 3, IssuedAt: 990, ExpiresAt: 1_290, MaxAgeSeconds: 300})); err != nil {
						t.Errorf("claim %s: %v", id, err)
					}
				}
			}()
		}
		_, ackErr := device.Resubmit(ctx, sequence)
		wg.Wait()
		if ackErr != nil {
			t.Fatalf("acknowledging sequence %d while claims race: %v", sequence, ackErr)
		}
	}
	if got := device.Startup(); got != DeviceReady {
		t.Fatalf("startup after the race: %s", got)
	}
}

// An issuance record's context policy is part of the projection: two records
// that differ only in their policy have different digests (SPEC-v2 §7.13).
func TestDeviceStateCoversIssuanceContextPolicy(t *testing.T) {
	digestWith := func(profile string) []byte {
		primary, _, _ := newTestDevice(t)
		record := testChallengeRecord(5)
		policy, err := ratify.NewV2ContextPolicy(profile, false, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		record.ContextPolicy = policy
		if err := primary.Issuance.PersistV2Challenge(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		digest, err := primary.CompleteStateDigestTestOnly()
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	if bytes.Equal(digestWith("example.a/v1"), digestWith("example.b/v1")) {
		t.Fatal("changing an issuance record's context policy does not change the complete-state digest")
	}
}

// claim1ID is the derived claim ID of the "claim-1" test claim.
var claim1ID = KeyedClaimForTest("claim-1", ratify.V2ChallengeClaim{Namespace: "device-ns", ReplayEpoch: 3}).ClaimID
