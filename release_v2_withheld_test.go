package ratify_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// v2ReleaseFixture commits and publishes lifecycle request A against a fresh
// reference store and returns what release needs.
func v2ReleaseFixture(t *testing.T) (*v2reference.Store, *ratify.CommittedV2Outcome, []byte, ratify.V2ReleaseConfig) {
	t.Helper()
	_, fx := loadV2Keys(t)
	var f struct {
		VerifierKey  string                        `json:"verifier_key"`
		LogID        string                        `json:"log_id"`
		LeaseSeconds int64                         `json:"lease_seconds"`
		Bundles      map[string]string             `json:"bundles_b64"`
		Requests     map[string]v2LifecycleRequest `json:"requests"`
		// The scripts themselves run in TestV2ConformanceLifecycleScenarios.
		Version          json.RawMessage `json:"version"`
		Description      json.RawMessage `json:"description"`
		Semantics        json.RawMessage `json:"semantics"`
		Scenarios        json.RawMessage `json:"scenarios"`
		ProfileScenarios json.RawMessage `json:"profile_scenarios"`
	}
	loadV2Vector(t, "lifecycle-scenarios.json", &f)
	request := f.Requests["A"]
	store, err := v2reference.NewStore(request.Now, f.LeaseSeconds, f.LogID, fx.priv[f.VerifierKey])
	if err != nil {
		t.Fatal(err)
	}
	req, cb, _ := v2BuildVerifyRequest(t, request.v2OrderingInputs, unb64(t, f.Bundles[request.Bundle]), &v2Counts{})
	cb.ClaimStore = store
	outcome, err := ratify.VerifyProofBundleV2(context.Background(), req, cb)
	if err != nil || outcome.Stage != ratify.V2StageCommitted {
		t.Fatalf("fixture did not commit: %+v %v", outcome, err)
	}
	wire, err := store.PublishV2Receipt(context.Background(), outcome.Committed.ClaimID(), outcome.Committed.ReceiptBody())
	if err != nil {
		t.Fatal(err)
	}
	return store, outcome.Committed, wire, ratify.V2ReleaseConfig{VerifierPublicKey: fx.pub[f.VerifierKey], LogID: f.LogID, ClaimStore: store, Checkpoint: store}
}

// v2RecordFailingStore fails every RecordV2Release with err.
type v2RecordFailingStore struct {
	*v2reference.Store
	err   error
	calls int
}

func (s *v2RecordFailingStore) RecordV2Release(context.Context, ratify.V2ReleaseRecord) error {
	s.calls++
	return s.err
}

// A withheld result must never become released (SPEC-v2 §6.9). If recording
// it fails, the call is still withheld: failing open to pending would let a
// later call with a recovered clock release a decision already withheld.
func TestReleaseV2DecisionWithholdsWhenRecordingWithheldFails(t *testing.T) {
	store, committed, wire, config := v2ReleaseFixture(t)
	failing := &v2RecordFailingStore{Store: store, err: errors.New("store unavailable")}
	config.ClaimStore = failing
	store.SetTime(committed.ChallengeExpiresAt())
	result := ratify.ReleaseV2Decision(context.Background(), committed, wire, config)
	if result.Status != ratify.V2ReleaseWithheld || result.Reason != "challenge_expired" || result.Decision != nil || failing.calls != 1 {
		t.Fatalf("release with an unavailable store while withholding: %+v (record calls %d)", result, failing.calls)
	}
}

// The first record wins: a different record already present when release
// tries to record its withheld result is a state mismatch.
func TestReleaseV2DecisionWithheldRecordConflictIsRejected(t *testing.T) {
	store, committed, wire, config := v2ReleaseFixture(t)
	config.ClaimStore = &v2RecordFailingStore{Store: store, err: ratify.ErrV2ReleaseStateMismatch}
	store.SetTime(committed.ChallengeExpiresAt())
	result := ratify.ReleaseV2Decision(context.Background(), committed, wire, config)
	if result.Status != ratify.V2ReleaseRejected || result.Reason != "release_state_mismatch" {
		t.Fatalf("conflicting withheld record: %+v", result)
	}
}

// A recorded withheld result is returned right after the committed-state
// step, before any receipt or acknowledgement is consulted.
func TestReleaseV2DecisionAnswersRecordedWithheldFirst(t *testing.T) {
	store, committed, wire, config := v2ReleaseFixture(t)
	store.SetTime(committed.ChallengeExpiresAt())
	if result := ratify.ReleaseV2Decision(context.Background(), committed, wire, config); result.Status != ratify.V2ReleaseWithheld || result.Reason != "challenge_expired" {
		t.Fatalf("expiry was not withheld: %+v", result)
	}
	config.Checkpoint = nil
	if result := ratify.ReleaseV2Decision(context.Background(), committed, nil, config); result.Status != ratify.V2ReleaseRejected {
		t.Fatalf("missing checkpoint configuration is still a state mismatch: %+v", result)
	}
	config.Checkpoint = store
	if result := ratify.ReleaseV2Decision(context.Background(), committed, nil, config); result.Status != ratify.V2ReleaseWithheld || result.Reason != "challenge_expired" {
		t.Fatalf("a recorded withheld result was not returned before the receipt step: %+v", result)
	}
}

// The reference store keeps the first release record: an identical repeat is
// a no-op, a different outcome or reason is a state mismatch, and an outcome
// that is not a release record is refused before anything is stored.
func TestReferenceStoreRecordsWithheldFirstWins(t *testing.T) {
	store, committed, wire, _ := v2ReleaseFixture(t)
	receipt, err := ratify.DecodeVerificationReceiptV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ratify.VerificationReceiptV2Digest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	withheld := ratify.V2ReleaseRecord{ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7, Outcome: ratify.V2ReleaseWithheld, Reason: "clock_regressed"}
	for name, invalid := range map[string]ratify.V2ReleaseRecord{
		"no outcome":            {ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7},
		"released with reason":  {ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7, Outcome: ratify.V2ReleaseReleased, Reason: "clock_regressed"},
		"withheld, other cause": {ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7, Outcome: ratify.V2ReleaseWithheld, Reason: "receipt_invalid"},
		"rejected outcome":      {ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7, Outcome: ratify.V2ReleaseRejected, Reason: "receipt_invalid"},
	} {
		if err := store.RecordV2Release(ctx, invalid); ratify.V2ErrorClassOf(err) != ratify.V2ErrConfigurationInvalid {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := store.RecordV2Release(ctx, withheld); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordV2Release(ctx, withheld); err != nil {
		t.Fatalf("identical repeat: %v", err)
	}
	for name, other := range map[string]ratify.V2ReleaseRecord{
		"released":     {ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7, Outcome: ratify.V2ReleaseReleased},
		"other reason": {ClaimID: committed.ClaimID(), EntryHash: entry, AckTimestamp: 7, Outcome: ratify.V2ReleaseWithheld, Reason: "challenge_expired"},
	} {
		if err := store.RecordV2Release(ctx, other); !errors.Is(err, ratify.ErrV2ReleaseStateMismatch) {
			t.Fatalf("%s after withheld: %v", name, err)
		}
	}
	loaded, err := store.LoadV2TerminalClaim(ctx, committed.ClaimID())
	if err != nil || loaded.Release == nil || loaded.Release.Outcome != ratify.V2ReleaseWithheld || loaded.Release.Reason != "clock_regressed" {
		t.Fatalf("stored record: %+v %v", loaded.Release, err)
	}
}
