package ratify_test

import (
	"context"
	"errors"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// SPEC-v2 §7.11: after a terminal compare-and-set, recovery completes the
// same immutable work and never discards a committed result. A process that
// dies after the store commits an allow but before FinalizeV2Claim returns
// loses the only CommittedV2Outcome for that claim: the exact retry is a
// terminal replay with no handoff, and RecoverInterruptedClaimV2 refuses a
// claim that is terminal with anything other than evaluation_interrupted.
// Without resumption from the store's persisted record the committed outbox
// entry could never be published, the claim would never be released, and
// every later entry of the receipt log would wait behind it (§7.7).
//
// Crash after the first finalization of flow allow_then_release
// (presentations A then B), restart with no caller state, and require both
// to be released.
func TestV2CrashAfterFinalizationCompletesCommittedWork(t *testing.T) {
	fixture := loadV2CrashFixture(t)
	flow := v2CrashFlows()[0]
	ctx := context.Background()
	w := newV2CrashWorld(t, fixture, flow)
	w.inj.crashAt, w.inj.mode = 7, v2CrashAfter
	journal := newV2CrashCallerJournal()
	if !w.runProcess(journal) || w.inj.ops[6] != "finalize" {
		t.Fatalf("expected a death after the first finalization, writes %v", w.inj.ops)
	}
	a, b := w.presentations[0], w.presentations[1]
	if record, err := w.store.LoadV2TerminalClaim(ctx, a.claimID); err != nil || !record.Terminal || record.AllowHorizon == 0 {
		t.Fatalf("the allow for A was not committed before the death: %+v %v", record, err)
	}

	w.store.SetTime(w.store.Now() + w.lease)
	if w.runProcess(newV2CrashCallerJournal()) {
		t.Fatal("restarted process died with no crash armed")
	}

	// What the restarted service sees for A: a terminal replay and a refused
	// recovery; only resumption returns the handoff.
	a.req.Now = w.store.Now()
	retry, _ := ratify.VerifyProofBundleV2(ctx, a.req, a.cb)
	_, recoverErr := ratify.RecoverInterruptedClaimV2(ctx, w.store, a.claimID)
	t.Logf("A after restart: verify %s/%s, recovery %s", retry.Stage, retry.Disposition, ratify.V2ErrorClassOf(recoverErr))
	// B commits after the restart, but its entry waits behind A's.
	if commit, ok := w.oracle.commits[b.claimID]; ok {
		_, publishErr := w.store.PublishV2Receipt(ctx, b.claimID, commit.body)
		t.Logf("B after restart: committed, publish head-of-line blocked %t", errors.Is(publishErr, v2reference.ErrHeadOfLineBlocked))
	}

	for _, p := range w.presentations {
		if len(w.oracle.released[p.claimID]) == 0 {
			t.Errorf("%s was never released after the restart; service notes: %v", p.name, w.notes)
		}
	}
	if w.store.LogLength() != len(w.presentations) {
		t.Errorf("receipt log holds %d entries after restart, want %d: committed work was not completed", w.store.LogLength(), len(w.presentations))
	}
}
