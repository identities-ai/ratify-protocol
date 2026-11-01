package ratify_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// v2CommittedRecordStore answers LoadV2CommittedClaim through edit, so a
// test can stand in for a claim store that returns a damaged record.
type v2CommittedRecordStore struct {
	*v2reference.Store
	edit func(*ratify.V2CommittedClaim) error
}

func (s *v2CommittedRecordStore) LoadV2CommittedClaim(ctx context.Context, claimID string) (ratify.V2CommittedClaim, error) {
	record, err := s.Store.LoadV2CommittedClaim(ctx, claimID)
	if err != nil {
		return record, err
	}
	return record, s.edit(&record)
}

// SPEC-v2 §7.11: a service whose handoff died after the terminal commit
// resumes it from the store, and the resumed handoff is the committed one:
// release answers it exactly as the original.
func TestResumeCommittedClaimV2ReturnsTheCommittedHandoff(t *testing.T) {
	store, committed, wire, config := v2ReleaseFixture(t)
	resumed, err := ratify.ResumeCommittedClaimV2(context.Background(), store, committed.ClaimID())
	if err != nil {
		t.Fatal(err)
	}
	gotHorizon, gotOK := resumed.AllowHorizon()
	wantHorizon, wantOK := committed.AllowHorizon()
	if resumed.ClaimID() != committed.ClaimID() || !bytes.Equal(resumed.ReceiptBody(), committed.ReceiptBody()) ||
		resumed.ChallengeExpiresAt() != committed.ChallengeExpiresAt() || gotHorizon != wantHorizon || gotOK != wantOK || !wantOK {
		t.Fatalf("resumed handoff differs from the committed allow")
	}
	result := ratify.ReleaseV2Decision(context.Background(), resumed, wire, config)
	if result.Status != ratify.V2ReleaseReleased || result.Decision == nil || result.Decision.Decision() != "allow" {
		t.Fatalf("release of the resumed handoff = %+v, want released allow", result)
	}
	again := ratify.ReleaseV2Decision(context.Background(), committed, wire, config)
	if again.Status != ratify.V2ReleaseReleased {
		t.Fatalf("release of the original handoff after resumption = %+v, want released (idempotent)", again)
	}
}

// The store's answers for a claim with no committed record pass through
// with their class; resumption commits nothing.
func TestResumeCommittedClaimV2RefusesAClaimWithNoCommittedRecord(t *testing.T) {
	ctx := context.Background()
	store, committed, _, _ := v2ReleaseFixture(t)
	if _, err := ratify.ResumeCommittedClaimV2(ctx, store, "unknown-claim"); ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimNotFound {
		t.Fatalf("unknown claim: %v, want claim_not_found", err)
	}
	record, err := store.LoadV2CommittedClaim(ctx, committed.ClaimID())
	if err != nil {
		t.Fatal(err)
	}
	const lease = 30
	var verifierKey ratify.HybridPrivateKey
	for _, key := range func() map[string]ratify.HybridPrivateKey { _, fx := loadV2Keys(t); return fx.priv }() {
		verifierKey = key
		break
	}
	evaluating, err := v2reference.NewStore(store.Now(), lease, strings.Repeat("ab", 16), verifierKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluating.ClaimV2(ctx, record.Claim); err != nil {
		t.Fatal(err)
	}
	if _, err := ratify.ResumeCommittedClaimV2(ctx, evaluating, record.Claim.ClaimID); ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimLeaseLive {
		t.Fatalf("claim evaluating under a live lease: %v, want claim_lease_live", err)
	}
	evaluating.SetTime(evaluating.Now() + lease)
	if _, err := ratify.ResumeCommittedClaimV2(ctx, evaluating, record.Claim.ClaimID); ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimLeaseLost {
		t.Fatalf("claim evaluating after its lease: %v, want claim_lease_lost", err)
	}
	if terminal, err := evaluating.LoadV2TerminalClaim(ctx, record.Claim.ClaimID); err != nil || terminal.Terminal {
		t.Fatalf("resumption committed a result: %+v %v", terminal, err)
	}
	if _, err := ratify.ResumeCommittedClaimV2(ctx, nil, committed.ClaimID()); ratify.V2ErrorClassOf(err) != ratify.V2ErrConfigurationInvalid {
		t.Fatalf("no store: %v, want configuration_invalid", err)
	}
	if _, err := ratify.ResumeCommittedClaimV2(ctx, store, ""); ratify.V2ErrorClassOf(err) != ratify.V2ErrConfigurationInvalid {
		t.Fatalf("no claim ID: %v, want configuration_invalid", err)
	}
}

// Resumption applies the terminal compare-and-set's checks to the record the
// store returns (§7.3, §7.5, §6.8). A record that fails one is the store's
// failure, never a handoff, so no damaged record can reach release.
func TestResumeCommittedClaimV2RefusesARecordThatFailsItsChecks(t *testing.T) {
	ctx := context.Background()
	base, committed, _, _ := v2ReleaseFixture(t)
	interruptedTerminal := func(r *ratify.V2CommittedClaim) error {
		terminal, body, err := ratify.V2EvaluationInterruptedResult(r.Claim, r.Claim.IssuedAt, ratify.InitialV2EvaluationProgress())
		r.TerminalResult, r.ReceiptBody = terminal, body
		return err
	}
	cases := map[string]func(*ratify.V2CommittedClaim) error{
		"record for another claim": func(r *ratify.V2CommittedClaim) error {
			r.Claim.ClaimID = strings.Repeat("0", len(r.Claim.ClaimID))
			return nil
		},
		"well-formed record of a different claim": func(r *ratify.V2CommittedClaim) error {
			r.Claim.ReplayEpoch++
			digest, err := hex.DecodeString(strings.TrimPrefix(r.Claim.ChallengeDigest, "sha384:"))
			if err != nil {
				return err
			}
			r.Claim.ClaimID, err = ratify.ProtocolClaimIDFromDigestV2(r.Claim.Namespace, r.Claim.ReplayEpoch, digest)
			return err
		},
		"claim ID not derived from the replay key": func(r *ratify.V2CommittedClaim) error {
			r.Claim.ReplayEpoch++
			return nil
		},
		"challenge digest not a sha384 digest": func(r *ratify.V2CommittedClaim) error {
			r.Claim.ChallengeDigest = strings.ToUpper(r.Claim.ChallengeDigest)
			return nil
		},
		"body for another agent": func(r *ratify.V2CommittedClaim) error {
			r.Claim.AgentID += "x"
			return nil
		},
		"terminal result differs from the body": func(r *ratify.V2CommittedClaim) error {
			r.TerminalResult = bytes.Replace(r.TerminalResult, []byte(`"allow"`), []byte(`"deny"`), 1)
			return nil
		},
		"allow with no horizon": func(r *ratify.V2CommittedClaim) error {
			r.AllowHorizon = 0
			return nil
		},
		"allow horizon outside the timestamp domain": func(r *ratify.V2CommittedClaim) error {
			r.AllowHorizon = ratify.V2MaxTimestampSeconds + 1
			return nil
		},
		"interrupted result with an allow horizon": interruptedTerminal,
		"store failure without a class": func(*ratify.V2CommittedClaim) error {
			return errors.New("disk read failed")
		},
		"store panics": func(*ratify.V2CommittedClaim) error {
			panic("disk read failed")
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			store := &v2CommittedRecordStore{Store: base, edit: edit}
			resumed, err := ratify.ResumeCommittedClaimV2(ctx, store, committed.ClaimID())
			if resumed != nil || ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimStoreUnavailable {
				t.Fatalf("got %v, %v; want claim_store_unavailable and no handoff", resumed, err)
			}
		})
	}
	// The interrupted result itself, with no horizon, is a valid record.
	store := &v2CommittedRecordStore{Store: base, edit: func(r *ratify.V2CommittedClaim) error {
		err := interruptedTerminal(r)
		r.AllowHorizon = 0
		return err
	}}
	if _, err := ratify.ResumeCommittedClaimV2(ctx, store, committed.ClaimID()); err != nil {
		t.Fatalf("a valid interrupted record was refused: %v", err)
	}
}
