package v2reference

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Vector input records of testvectors/v2/device-state.json (SPEC-v2 §7.13).
type dsSealedClaim struct {
	AgentID              string                            `json:"agent_id"`
	BundleHash           string                            `json:"bundle_hash"`
	ChallengeDigest      string                            `json:"challenge_digest"`
	ClaimID              string                            `json:"claim_id"`
	ClockSkewSeconds     int64                             `json:"clock_skew_seconds"`
	ConstraintEvaluators []ratify.ConstraintEvaluatorRefV2 `json:"constraint_evaluators"`
	ContextPolicyDigest  *string                           `json:"context_policy_digest"`
	ExpiresAt            int64                             `json:"expires_at"`
	IssuedAt             int64                             `json:"issued_at"`
	IssuerIDs            []string                          `json:"issuer_ids"`
	MaxAgeSeconds        int64                             `json:"max_age_seconds"`
	Namespace            string                            `json:"namespace"`
	ProofDigest          string                            `json:"proof_digest"`
	RateBatch            []struct {
		CertID   string `json:"cert_id"`
		IssuerID string `json:"issuer_id"`
		Limit    int64  `json:"limit"`
		WindowS  int64  `json:"window_s"`
	} `json:"rate_batch"`
	ReplayEpoch   int64  `json:"replay_epoch"`
	RequiredScope string `json:"required_scope"`
	RequiresRate  bool   `json:"requires_rate"`
	StreamID      []byte `json:"stream_id"`
	StreamSeq     *int64 `json:"stream_seq"`
	VerifierID    string `json:"verifier_id"`
}

type dsClaim struct {
	Abandoned      bool                        `json:"abandoned"`
	AllowHorizon   int64                       `json:"allow_horizon"`
	Claim          dsSealedClaim               `json:"claim"`
	ClaimID        string                      `json:"claim_id"`
	ClaimedAt      int64                       `json:"claimed_at"`
	FinalizedAt    int64                       `json:"finalized_at"`
	LeaseExpiresAt int64                       `json:"lease_expires_at"`
	LogSequence    *int64                      `json:"log_sequence"`
	OwnerDigest    []byte                      `json:"owner_digest"`
	Progress       ratify.V2EvaluationProgress `json:"progress"`
	ReceiptBody    []byte                      `json:"receipt_body_b64"`
	Release        *struct {
		AckTimestamp int64  `json:"ack_timestamp"`
		ClaimID      string `json:"claim_id"`
		EntryHash    []byte `json:"entry_hash"`
	} `json:"release"`
	State    string `json:"state"`
	Terminal []byte `json:"terminal_b64"`
}

type dsIssuance struct {
	ContextPolicy *struct {
		ExpectedSessionContext []byte   `json:"expected_session_context"`
		Profile                string   `json:"profile"`
		RequireBound           bool     `json:"require_bound"`
		RequiredFields         []string `json:"required_fields"`
	} `json:"context_policy"`
	ExpectedAgentID        string                  `json:"expected_agent_id"`
	ExpectedAgentPubKey    *ratify.HybridPublicKey `json:"expected_agent_pub_key"`
	ExpectedReceiverID     string                  `json:"expected_receiver_id"`
	ExpectedSessionContext []byte                  `json:"expected_session_context"`
	ExpiresAt              int64                   `json:"expires_at"`
	IssuedAt               int64                   `json:"issued_at"`
	ReplayEpoch            int64                   `json:"replay_epoch"`
	Value                  []byte                  `json:"value"`
	VerifierID             string                  `json:"verifier_id"`
	VerifierNamespace      string                  `json:"verifier_namespace"`
}

type dsCase struct {
	Name  string `json:"name"`
	State struct {
		Claims          []dsClaim    `json:"claims"`
		IssuanceRecords []dsIssuance `json:"issuance_records"`
		LogID           string       `json:"log_id"`
		RateCounters    []struct {
			CertID   string  `json:"cert_id"`
			Commits  []int64 `json:"commits"`
			IssuerID string  `json:"issuer_id"`
			WindowS  int64   `json:"window_s"`
		} `json:"rate_counters"`
		ReceiptLog struct {
			Entries []struct {
				Body      []byte `json:"body_b64"`
				ClaimID   string `json:"claim_id"`
				EntryHash []byte `json:"entry_hash"`
			} `json:"entries"`
			Frozen bool `json:"frozen"`
		} `json:"receipt_log"`
		ReplayEpoch     int64 `json:"replay_epoch"`
		SecurityJournal struct {
			Generation uint64 `json:"generation"`
			Snapshot   []byte `json:"snapshot_b64"`
		} `json:"security_journal"`
		Streams []struct {
			AgentID      string `json:"agent_id"`
			LastSequence int64  `json:"last_sequence"`
			Namespace    string `json:"namespace"`
			StreamID     []byte `json:"stream_id"`
		} `json:"streams"`
	} `json:"state"`
	Expect map[string]string `json:"expect"`
}

// loadDeviceStateCase builds a primary holding exactly the case's records.
func loadDeviceStateCase(t *testing.T, c dsCase) *DevicePrimaryTestOnly {
	t.Helper()
	_, priv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(1_800_000_000, 30, c.State.LogID, priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range c.State.Claims {
		sc := in.Claim
		claim := ratify.V2ChallengeClaim{
			ClaimID: sc.ClaimID, Namespace: sc.Namespace, ReplayEpoch: sc.ReplayEpoch, ChallengeDigest: sc.ChallengeDigest, ProofDigest: sc.ProofDigest,
			BundleHash: sc.BundleHash, IssuerIDs: sc.IssuerIDs, RequiredScope: sc.RequiredScope, VerifierID: sc.VerifierID, AgentID: sc.AgentID,
			RequiresRate: sc.RequiresRate, IssuedAt: sc.IssuedAt, ExpiresAt: sc.ExpiresAt, MaxAgeSeconds: sc.MaxAgeSeconds,
			ClockSkewSeconds: sc.ClockSkewSeconds, StreamID: sc.StreamID, StreamSeq: sc.StreamSeq, ConstraintEvaluators: sc.ConstraintEvaluators,
		}
		if sc.ContextPolicyDigest != nil {
			claim.ContextPolicyDigest = *sc.ContextPolicyDigest
		}
		for _, r := range sc.RateBatch {
			claim.RateBatch = append(claim.RateBatch, ratify.V2RateReservation{IssuerID: r.IssuerID, CertID: r.CertID, WindowS: r.WindowS, Limit: r.Limit})
		}
		record := &claimRecord{
			claim: claim, leaseExpiresAt: in.LeaseExpiresAt, state: claimState(in.State), terminal: in.Terminal, receiptBody: in.ReceiptBody,
			allowHorizon: in.AllowHorizon, claimedAt: in.ClaimedAt, finalizedAt: in.FinalizedAt, progress: in.Progress, abandoned: in.Abandoned, outboxIndex: -1,
		}
		copy(record.ownerDigest[:], in.OwnerDigest)
		if in.LogSequence != nil {
			record.outboxIndex = int(*in.LogSequence) - 1
		}
		if in.Release != nil {
			record.release = &ratify.V2ReleaseRecord{ClaimID: in.Release.ClaimID, EntryHash: in.Release.EntryHash, AckTimestamp: in.Release.AckTimestamp}
		}
		store.claims[in.ClaimID] = record
	}
	for _, s := range c.State.Streams {
		store.streams[streamKeyV2{namespace: s.Namespace, agentID: s.AgentID, streamID: string(s.StreamID)}] = s.LastSequence
	}
	for _, r := range c.State.RateCounters {
		store.rateCommits[rateKey{issuerID: r.IssuerID, certID: r.CertID, windowS: r.WindowS}] = r.Commits
	}
	for _, e := range c.State.ReceiptLog.Entries {
		store.outbox = append(store.outbox, outboxEntry{claimID: e.ClaimID, body: e.Body, digest: e.EntryHash})
	}
	store.logFrozen = c.State.ReceiptLog.Frozen
	primary, err := NewDevicePrimaryTestOnly(store, c.State.ReplayEpoch)
	if err != nil {
		t.Fatal(err)
	}
	primary.Journal.inner.head.Generation, primary.Journal.inner.snapshot = c.State.SecurityJournal.Generation, c.State.SecurityJournal.Snapshot
	for _, in := range c.State.IssuanceRecords {
		record := ratify.ExpectedChallengeV2{
			Value: in.Value, IssuedAt: in.IssuedAt, ExpiresAt: in.ExpiresAt, VerifierNamespace: in.VerifierNamespace, ReplayEpoch: in.ReplayEpoch,
			VerifierID: in.VerifierID, ExpectedAgentID: in.ExpectedAgentID, ExpectedAgentPublicKey: in.ExpectedAgentPubKey,
			ExpectedReceiverID: in.ExpectedReceiverID, ExpectedSessionContext: in.ExpectedSessionContext,
		}
		if p := in.ContextPolicy; p != nil {
			if record.ContextPolicy, err = ratify.NewV2ContextPolicy(p.Profile, p.RequireBound, p.RequiredFields, p.ExpectedSessionContext); err != nil {
				t.Fatal(err)
			}
		}
		digest, err := ratify.ChallengeClaimDigestV2(record.Value)
		if err != nil {
			t.Fatal(err)
		}
		primary.Issuance.inner.records[issuanceKey(record.VerifierNamespace, record.ReplayEpoch, digest)] = record
	}
	return primary
}

// The reference projection reproduces every byte of the shared complete-state
// known answers, so any SDK that matches the same vectors computes the same
// digest for the same records (SPEC-v2 §7.13).
func TestDeviceStateProjectionVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testvectors", "v2", "device-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Label   string   `json:"label"`
		Version int      `json:"version"`
		Cases   []dsCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.Label != deviceStateLabel || file.Version != deviceStateVersion || len(file.Cases) == 0 {
		t.Fatalf("label %q version %d cases %d", file.Label, file.Version, len(file.Cases))
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			primary := loadDeviceStateCase(t, c)
			claims, streams, rates, receiptLog, err := primary.Store.storeMembersLocked()
			if err != nil {
				t.Fatal(err)
			}
			primary.mu.Lock()
			issuance, err := primary.issuanceMemberLocked()
			primary.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string][]byte{"claims": claims, "streams": streams, "rate_counters": rates, "receipt_log": receiptLog, "issuance_records": issuance} {
				if want := c.Expect[name+"_canonical_json"]; string(got) != want {
					t.Errorf("%s:\n got %s\nwant %s", name, got, want)
				}
				if sha384Hex(got) != c.Expect[name+"_sha384"] {
					t.Errorf("%s digest differs", name)
				}
			}
			store, err := primary.Store.stateDigests()
			if err != nil {
				t.Fatal(err)
			}
			primary.mu.Lock()
			projection, err := primary.projectionLocked(store, sha384Hex(issuance))
			primary.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if string(projection) != c.Expect["projection_canonical_json"] {
				t.Errorf("projection:\n got %s\nwant %s", projection, c.Expect["projection_canonical_json"])
			}
			digest, err := primary.CompleteStateDigestTestOnly()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest) != c.Expect["complete_state_digest_hex"] || !bytes.Equal(digest, completeStateDigest(projection)) {
				t.Errorf("complete-state digest %x, want %s", digest, c.Expect["complete_state_digest_hex"])
			}
		})
	}
}
