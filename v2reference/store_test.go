package v2reference_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

var (
	_ ratify.ClaimStoreV2           = (*v2reference.Store)(nil)
	_ ratify.V2ReleaseClaimStore    = (*v2reference.Store)(nil)
	_ ratify.V2ReceiptPublisher     = (*v2reference.Store)(nil)
	_ ratify.V2ReceiptCheckpoint    = (*v2reference.Store)(nil)
	_ ratify.SecurityJournalStoreV2 = (*v2reference.JournalStore)(nil)
)

const now = 1800000000

func newStore(t *testing.T) *v2reference.Store {
	t.Helper()
	_, priv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := v2reference.NewStore(now, 30, "dddddddddddddddddddddddddddddd01", priv)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func claimFor(id string, seq int64) ratify.V2ChallengeClaim {
	streamID := make([]byte, 32)
	return ratify.V2ChallengeClaim{
		ClaimID: id, Namespace: "ns", AgentID: "agent", ProofDigest: "proof-" + id,
		IssuedAt: now - 10, ExpiresAt: now + 290, MaxAgeSeconds: 300, ClockSkewSeconds: 5,
		StreamID: streamID, StreamSeq: &seq,
	}
}

// Of many concurrent claims carrying the same stream sequence for one stream
// key, exactly one may commit; every other fails before claim with
// stream_sequence_mismatch (SPEC-v2 §7.4 rule 7).
func TestStoreSerializesConcurrentStreamClaims(t *testing.T) {
	store := newStore(t)
	const workers = 64
	var wg sync.WaitGroup
	results := make([]error, workers)
	dispositions := make([]ratify.V2ClaimDisposition, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := store.ClaimV2(context.Background(), claimFor(fmt.Sprintf("claim-%d", i), 1))
			results[i], dispositions[i] = err, result.Disposition
		}(i)
	}
	wg.Wait()
	created := 0
	for i := range results {
		switch {
		case results[i] == nil && dispositions[i] == ratify.V2ClaimCreated:
			created++
		case ratify.V2ErrorClassOf(results[i]) != ratify.V2ErrStreamSequenceMismatch:
			t.Fatalf("claim %d: unexpected outcome %v / %s", i, results[i], dispositions[i])
		}
	}
	if created != 1 {
		t.Fatalf("%d claims advanced the same stream sequence, want exactly 1", created)
	}
}

// Concurrent exact retries of one claim create it once and never hand the
// evaluator capability to a retry.
func TestStoreConcurrentExactRetriesCreateOnce(t *testing.T) {
	store := newStore(t)
	const workers = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, inProgress := 0, 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := store.ClaimV2(context.Background(), claimFor("same", 1))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("exact retry failed: %v", err)
			case result.Disposition == ratify.V2ClaimCreated && len(result.OwnerToken) == 32:
				created++
			case result.Disposition == ratify.V2ClaimInProgress && len(result.OwnerToken) == 0:
				inProgress++
			default:
				t.Errorf("unexpected result %+v", result)
			}
		}()
	}
	wg.Wait()
	if created != 1 || inProgress != workers-1 {
		t.Fatalf("created=%d in_progress=%d", created, inProgress)
	}
}

// A rejected stream advance consumes nothing: the same challenge can still be
// claimed later with a valid sequence.
func TestStoreRejectedStreamAdvanceConsumesNothing(t *testing.T) {
	store := newStore(t)
	if _, err := store.ClaimV2(context.Background(), claimFor("a", 2)); ratify.V2ErrorClassOf(err) != ratify.V2ErrStreamSequenceMismatch {
		t.Fatalf("first sequence 2 accepted: %v", err)
	}
	if result, err := store.ClaimV2(context.Background(), claimFor("a", 1)); err != nil || result.Disposition != ratify.V2ClaimCreated {
		t.Fatalf("claim after a rejected advance: %+v %v", result, err)
	}
}

func TestCheckV2StreamSequenceRule(t *testing.T) {
	for _, tc := range []struct {
		hasLast   bool
		last, seq int64
		ok        bool
	}{{false, 0, 1, true}, {false, 0, 2, false}, {true, 1, 2, true}, {true, 2, 2, false}, {true, 3, 2, false}, {true, 2, 4, false}, {false, 0, 0, false}} {
		err := ratify.CheckV2StreamSequence(tc.hasLast, tc.last, tc.seq)
		if (err == nil) != tc.ok {
			t.Errorf("hasLast=%t last=%d seq=%d: %v", tc.hasLast, tc.last, tc.seq, err)
		}
	}
}

// The reference store admits max_rate inside its terminal compare-and-set
// (SPEC-v2 §7.1, §7.6). Its provisional reservation call exists only to
// satisfy the rate-store interface and must never report capacity: if a
// verifier ever called it, the result has to fail closed.
func TestRateAtFinalizationStoreNeverReservesProvisionally(t *testing.T) {
	store := newStore(t).WithRateAtFinalization()
	var _ ratify.V2RateAtFinalizationStore = store
	err := store.ReserveV2RateBatch(context.Background(), "claim", make([]byte, 32), "sha384:x", []ratify.V2RateReservation{{IssuerID: "i", CertID: "c", WindowS: 60, Limit: 1}})
	if err == nil {
		t.Fatal("the reference provisional reservation reported capacity")
	}
}
