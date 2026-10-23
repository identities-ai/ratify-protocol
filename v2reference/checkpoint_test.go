package v2reference_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// committedReceiptStore returns a reference store holding n claims whose
// interrupted results were committed by lease-expiry recovery, in log order,
// so their receipts can be published without a live evaluation.
func committedReceiptStore(t *testing.T, n int) (*v2reference.Store, []string) {
	t.Helper()
	_, priv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	verifierID, err := ratify.KeyIDV2(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	store, err := v2reference.NewStore(now, 30, "dddddddddddddddddddddddddddddd01", priv)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ids := []string{}
	for i := range n {
		claim := ratify.V2ChallengeClaim{
			ClaimID: "claim-" + string(rune('a'+i)), Namespace: "ns", AgentID: strings.Repeat("a", 64), ProofDigest: "sha384:" + strings.Repeat("0", 95) + string(rune('1'+i)),
			IssuerIDs: []string{strings.Repeat("b", 64)}, RequiredScope: "data:read", VerifierID: verifierID,
			IssuedAt: now - 10, ExpiresAt: now + 290, MaxAgeSeconds: 300, ClockSkewSeconds: 5,
		}
		claim.BundleHash = claim.ProofDigest
		if _, err := store.ClaimV2(ctx, claim); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, claim.ClaimID)
	}
	store.SetTime(now + 30)
	for _, id := range ids {
		loaded, err := store.LoadV2InterruptedClaim(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		terminal, body, err := ratify.V2EvaluationInterruptedResult(loaded.Claim, loaded.ClaimedAt, loaded.Progress)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RecoverInterruptedV2Claim(ctx, id, terminal, body); err != nil {
			t.Fatal(err)
		}
	}
	return store, ids
}

func publishedTuple(t *testing.T, store *v2reference.Store, claimID string) (*ratify.VerificationReceiptV2, []byte) {
	t.Helper()
	record, err := store.LoadV2InterruptedClaim(context.Background(), claimID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, body, err := ratify.V2EvaluationInterruptedResult(record.Claim, record.ClaimedAt, record.Progress)
	if err != nil || terminal == nil {
		t.Fatal(err)
	}
	wire, err := store.PublishV2Receipt(context.Background(), claimID, body)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ratify.DecodeVerificationReceiptV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ratify.VerificationReceiptV2Digest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, entry
}

// A different entry hash at an acknowledged sequence is a fork (SPEC-v2
// §7.8). If the checkpoint kept acknowledging after it, a forked log could
// keep releasing decisions; it must acknowledge nothing further for the log.
func TestCheckpointFreezesLogAfterFork(t *testing.T) {
	store, ids := committedReceiptStore(t, 2)
	ctx := context.Background()
	first, firstEntry := publishedTuple(t, store, ids[0])
	store.SetAcknowledgementWithheld(true)
	second, secondEntry := publishedTuple(t, store, ids[1])
	store.SetTime(now + 40)

	forked := bytes.Clone(firstEntry)
	forked[0] ^= 1
	if _, err := store.AcknowledgeV2Receipt(ctx, first.LogID, 1, first.PreviousReceiptHash, forked); !errors.Is(err, v2reference.ErrNotAcknowledged) {
		t.Fatalf("fork at an acknowledged sequence was not refused: %v", err)
	}
	if ack, err := store.AcknowledgeV2Receipt(ctx, first.LogID, 1, first.PreviousReceiptHash, firstEntry); err != nil || ack.Timestamp != now+30 {
		t.Fatalf("identical retry of a pre-fork acknowledgement: %+v %v", ack, err)
	}
	store.SetAcknowledgementWithheld(false)
	if _, err := store.AcknowledgeV2Receipt(ctx, second.LogID, 2, firstEntry, secondEntry); !errors.Is(err, v2reference.ErrNotAcknowledged) {
		t.Fatalf("a frozen log acknowledged its next entry: %v", err)
	}
	if _, err := store.GetV2Acknowledgement(ctx, second.LogID, 2); !errors.Is(err, ratify.ErrV2AcknowledgementNotFound) {
		t.Fatalf("the publisher's submission was acknowledged after the fork: %v", err)
	}
	if !bytes.Equal(second.PreviousReceiptHash, firstEntry) {
		t.Fatal("fixture receipts are not linked")
	}
}

// A refusal that is not a fork, such as an out-of-order sequence, must not
// freeze the log.
func TestCheckpointRefusalWithoutForkDoesNotFreeze(t *testing.T) {
	store, ids := committedReceiptStore(t, 2)
	ctx := context.Background()
	store.SetAcknowledgementWithheld(true)
	first, firstEntry := publishedTuple(t, store, ids[0])
	second, secondEntry := publishedTuple(t, store, ids[1])
	if _, err := store.AcknowledgeV2Receipt(ctx, second.LogID, 2, firstEntry, secondEntry); err == nil {
		t.Fatal("out-of-order acknowledgement accepted")
	}
	if _, err := store.AcknowledgeV2Receipt(ctx, first.LogID, 1, first.PreviousReceiptHash, firstEntry); err != nil {
		t.Fatalf("log froze without a fork: %v", err)
	}
	if _, err := store.AcknowledgeV2Receipt(ctx, second.LogID, 2, firstEntry, secondEntry); err != nil {
		t.Fatalf("log froze without a fork: %v", err)
	}
}
