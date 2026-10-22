package ratify_test

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// ---------------------------------------------------------------------------
// SecurityJournalV2 known answers (testvectors/v2/security-journal.json)

type v2JournalHead struct {
	Generation uint64 `json:"generation"`
	Digest     string `json:"digest"`
}

func TestV2ConformanceSecurityJournal(t *testing.T) {
	var f struct {
		Version         int               `json:"version"`
		Description     string            `json:"description"`
		Operations      map[string]string `json:"operations"`
		GenesisSnapshot string            `json:"genesis_snapshot"`
		GenesisDigest   string            `json:"genesis_digest"`
		Scenarios       []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Steps       []struct {
				Op             string `json:"op"`
				ObjectTypeCode int    `json:"object_type_code"`
				Role           string `json:"role"`
				IssuerID       string `json:"issuer_id"`
				Epoch          uint64 `json:"epoch"`
				Key            struct {
					Name      string                 `json:"name"`
					KeyIDV2   string                 `json:"key_id_v2"`
					PublicKey ratify.HybridPublicKey `json:"public_key"`
				} `json:"key"`
				WireB64           string          `json:"wire_b64"`
				Now               int64           `json:"now"`
				Policy            *v2StatusPolicy `json:"policy"`
				ExpectRejected    bool            `json:"expect_rejected"`
				ExpectChanged     bool            `json:"expect_changed"`
				ExpectHead        v2JournalHead   `json:"expect_head"`
				ExpectSnapshotB64 string          `json:"expect_snapshot_b64"`
			} `json:"steps"`
		} `json:"scenarios"`
		Migration struct {
			Description             string        `json:"description"`
			LegacyRecordB64         string        `json:"legacy_record_b64"`
			LegacyDigestInputB64    string        `json:"legacy_digest_input_b64"`
			LegacyDigest            string        `json:"legacy_digest"`
			ExpectHead              v2JournalHead `json:"expect_head"`
			ExpectPreviousDigest    string        `json:"expect_previous_digest"`
			ExpectSnapshotB64       string        `json:"expect_snapshot_b64"`
			TamperedLegacyRecordB64 string        `json:"tampered_legacy_record_b64"`
		} `json:"migration"`
		ImportNegatives []struct {
			Name             string        `json:"name"`
			Description      string        `json:"description"`
			SnapshotB64      string        `json:"snapshot_b64"`
			Head             v2JournalHead `json:"head"`
			ExpectErrorClass string        `json:"expect_error_class"`
		} `json:"import_negatives"`
	}
	loadV2Vector(t, "security-journal.json", &f)
	ctx := context.Background()
	genesis := ratify.EmptySecurityJournalV2()
	snapshot, err := ratify.ExportSecurityJournalSnapshotV2(genesis)
	if err != nil || string(snapshot) != f.GenesisSnapshot || genesis.Digest != f.GenesisDigest || ratify.SecurityJournalSnapshotDigestV2(snapshot) != f.GenesisDigest {
		t.Fatalf("genesis snapshot/digest mismatch: %v", err)
	}
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			store, err := v2reference.NewJournalStore()
			if err != nil {
				t.Fatal(err)
			}
			for i, step := range sc.Steps {
				before := store.Head()
				var stepErr error
				switch step.Op {
				case "record_key_role":
					_, stepErr = ratify.RecordSecurityKeyRoleV2(ctx, store, step.Role, step.Key.PublicKey)
				case "configure_status_key_epoch":
					_, stepErr = ratify.ConfigureStatusKeyEpochV2(ctx, store, step.IssuerID, step.Epoch, step.Key.PublicKey)
				case "apply_revocation_list":
					list, err := ratify.DecodeRevocationListV2(unb64(t, step.WireB64))
					if err != nil {
						t.Fatal(err)
					}
					_, stepErr = ratify.ApplyRevocationListToJournalV2(ctx, store, list, step.IssuerID, step.Epoch, step.Key.PublicKey, step.Policy.lib(), step.Now)
				case "apply_revocation_push":
					push, err := ratify.DecodeRevocationPushV2(unb64(t, step.WireB64))
					if err != nil {
						t.Fatal(err)
					}
					_, stepErr = ratify.ApplyRevocationPushToJournalV2(ctx, store, push, step.IssuerID, step.Epoch, step.Key.PublicKey, step.Policy.lib(), step.Now)
				default:
					t.Fatalf("unknown op %s", step.Op)
				}
				if (stepErr != nil) != step.ExpectRejected {
					t.Fatalf("step %d %s: error %v, expect rejected %t", i, step.Op, stepErr, step.ExpectRejected)
				}
				head := store.Head()
				if (head != before) != step.ExpectChanged || head.Generation != step.ExpectHead.Generation || head.Digest != step.ExpectHead.Digest {
					t.Fatalf("step %d %s: head %+v (changed %t), want %+v (changed %t)", i, step.Op, head, head != before, step.ExpectHead, step.ExpectChanged)
				}
				journal, _, err := store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				got, err := ratify.ExportSecurityJournalSnapshotV2(journal)
				if err != nil || !bytes.Equal(got, unb64(t, step.ExpectSnapshotB64)) || ratify.SecurityJournalSnapshotDigestV2(got) != head.Digest {
					t.Fatalf("step %d %s: snapshot differs (%v):\n got %s\nwant %s", i, step.Op, err, got, unb64(t, step.ExpectSnapshotB64))
				}
			}
		})
	}
	t.Run("migration", func(t *testing.T) {
		m := f.Migration
		input := unb64(t, m.LegacyDigestInputB64)
		sum := sha512.Sum384(input)
		if hex.EncodeToString(sum[:]) != m.LegacyDigest {
			t.Fatal("legacy digest is not SHA-384 of its input")
		}
		var legacy ratify.SecurityJournalV2
		if err := json.Unmarshal(unb64(t, m.LegacyRecordB64), &legacy); err != nil {
			t.Fatal(err)
		}
		migrated, err := ratify.MigrateSecurityJournalV2(legacy)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := ratify.ExportSecurityJournalSnapshotV2(migrated)
		if err != nil || migrated.Generation != m.ExpectHead.Generation || migrated.Digest != m.ExpectHead.Digest || migrated.PreviousDigest != m.ExpectPreviousDigest || !bytes.Equal(snapshot, unb64(t, m.ExpectSnapshotB64)) {
			t.Fatalf("migration result differs: %v", err)
		}
		var tampered ratify.SecurityJournalV2
		if err := json.Unmarshal(unb64(t, m.TamperedLegacyRecordB64), &tampered); err != nil {
			t.Fatal(err)
		}
		if _, err := ratify.MigrateSecurityJournalV2(tampered); err == nil {
			t.Fatal("migrated a tampered legacy record")
		}
	})
	for _, n := range f.ImportNegatives {
		t.Run("import_"+n.Name, func(t *testing.T) {
			_, err := ratify.ImportSecurityJournalSnapshotV2(unb64(t, n.SnapshotB64), ratify.SecurityJournalHeadV2{Generation: n.Head.Generation, Digest: n.Head.Digest})
			if err == nil || string(ratify.V2ErrorClassOf(err)) != n.ExpectErrorClass {
				t.Fatalf("import error %v (class %q), want class %q", err, ratify.V2ErrorClassOf(err), n.ExpectErrorClass)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Part B lifecycle scenarios (testvectors/v2/lifecycle-scenarios.json)

type v2LifecycleExpect struct {
	Stage          string `json:"stage"`
	ErrorClass     string `json:"error_class"`
	Disposition    string `json:"disposition"`
	Decision       string `json:"decision"`
	DecisionReason string `json:"decision_reason"`
	ReleaseStatus  string `json:"release_status"`
	ReleaseReason  string `json:"release_reason"`
	ReleaseTime    int64  `json:"release_time"`
	AllowHorizon   int64  `json:"allow_horizon"`
	ReceiptSeq     int64  `json:"receipt_sequence"`
	Failed         bool   `json:"failed"`
	PublishError   string `json:"publish_error"`

	TrustAssessment   string             `json:"trust_assessment"`
	StatusAssessment  string             `json:"status_assessment"`
	ContextAssessment string             `json:"context_assessment"`
	Abandoned         []string           `json:"abandoned"`
	Recovered         *v2LifecycleExpect `json:"recovered"`
}

type v2LifecycleRequest struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	Bundle             string `json:"bundle"`
	ClaimStore         string `json:"claim_store"`
	ClaimTimeOffset    int64  `json:"claim_time_offset"`
	FinalizeTimeOffset int64  `json:"finalize_time_offset"`
	Expected           struct {
		Stage          string   `json:"stage"`
		CallbackCounts v2Counts `json:"callback_counts"`
	} `json:"expected"`
	v2OrderingInputs
}

// v2WrongEntryCheckpoint reports acknowledgements for a different entry hash.
type v2WrongEntryCheckpoint struct{ inner ratify.V2ReceiptCheckpoint }

func (c v2WrongEntryCheckpoint) AcknowledgeV2Receipt(ctx context.Context, logID string, sequence int64, previous, entry []byte) (ratify.V2CheckpointAcknowledgement, error) {
	return c.inner.AcknowledgeV2Receipt(ctx, logID, sequence, previous, entry)
}

func (c v2WrongEntryCheckpoint) GetV2Acknowledgement(ctx context.Context, logID string, sequence int64) (ratify.V2CheckpointAcknowledgement, error) {
	ack, err := c.inner.GetV2Acknowledgement(ctx, logID, sequence)
	if err == nil {
		ack.EntryHash = bytes.Clone(ack.EntryHash)
		ack.EntryHash[0] ^= 1
	}
	return ack, err
}

func TestV2ConformanceLifecycleScenarios(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version      int                           `json:"version"`
		Description  string                        `json:"description"`
		Semantics    map[string]string             `json:"semantics"`
		VerifierKey  string                        `json:"verifier_key"`
		LogID        string                        `json:"log_id"`
		LeaseSeconds int64                         `json:"lease_seconds"`
		Bundles      map[string]string             `json:"bundles_b64"`
		Requests     map[string]v2LifecycleRequest `json:"requests"`
		Scenarios    []struct {
			Name               string `json:"name"`
			Description        string `json:"description"`
			StartTime          int64  `json:"start_time"`
			RateAtFinalization bool   `json:"rate_at_finalization"`
			Steps              []struct {
				Op          string            `json:"op"`
				Request     string            `json:"request"`
				Time        int64             `json:"time"`
				Withheld    *bool             `json:"withheld"`
				Mode        string            `json:"mode"`
				ReceiptOf   string            `json:"receipt_of"`
				Checkpoint  string            `json:"checkpoint"`
				ReplayEpoch int64             `json:"replay_epoch"`
				LogID       string            `json:"log_id"`
				Expect      v2LifecycleExpect `json:"expect"`
			} `json:"steps"`
		} `json:"scenarios"`
	}
	loadV2Vector(t, "lifecycle-scenarios.json", &f)
	if len(f.Scenarios) == 0 {
		t.Fatal("no lifecycle scenarios")
	}
	ctx := context.Background()
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			store, err := v2reference.NewStore(sc.StartTime, f.LeaseSeconds, f.LogID, fx.priv[f.VerifierKey])
			if err != nil {
				t.Fatal(err)
			}
			committed := map[string]*ratify.CommittedV2Outcome{}
			receipts := map[string][]byte{}
			claimIDs := map[string]string{}
			requestOf := map[string]string{}
			var epochOverride int64
			config := ratify.V2ReleaseConfig{VerifierPublicKey: fx.pub[f.VerifierKey], LogID: f.LogID, ClaimStore: store, Checkpoint: store}
			claimStore := func() ratify.ClaimStoreV2 {
				if sc.RateAtFinalization {
					return store.WithRateAtFinalization()
				}
				return store
			}
			recoverStep := func(i int, request string, want v2LifecycleExpect) {
				outcome, err := ratify.RecoverInterruptedClaimV2(ctx, store, claimIDs[request])
				if want.ErrorClass != "" {
					if string(ratify.V2ErrorClassOf(err)) != want.ErrorClass {
						t.Fatalf("step %d recover: %v (class %s), want %s", i, err, ratify.V2ErrorClassOf(err), want.ErrorClass)
					}
					return
				}
				if err != nil {
					t.Fatalf("step %d recover: %v", i, err)
				}
				checkV2CommittedDecision(t, i, outcome, want)
				committed[request] = outcome
			}
			for i, step := range sc.Steps {
				want := step.Expect
				now := store.Now()
				request := f.Requests[step.Request]
				switch step.Op {
				case "set_time":
					store.SetTime(step.Time)
				case "set_ack_withheld":
					store.SetAcknowledgementWithheld(*step.Withheld)
				case "verify":
					counts := &v2Counts{}
					inputs := request.v2OrderingInputs
					inputs.Now = now
					if epochOverride != 0 {
						inputs.ConfiguredReplayEpoch = epochOverride
					}
					req, cb, _ := v2BuildVerifyRequest(t, inputs, unb64(t, f.Bundles[request.Bundle]), counts)
					cs := claimStore()
					cb.ClaimStore = cs
					if sc.RateAtFinalization {
						cb.Rate = cs.(ratify.V2RateReservationStore)
					}
					claimID, err := ratify.ProtocolClaimIDV2(req.VerifierNamespace, req.ReplayEpoch, req.Expected.Value)
					if err != nil {
						t.Fatal(err)
					}
					claimIDs[step.Request], requestOf[claimID] = claimID, step.Request
					if step.Mode != "" {
						provider, fired := cb.StatusEvidence, false
						cb.StatusEvidence = func(c context.Context, r ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
							if !fired {
								fired = true
								store.SetTime(step.Time)
								switch step.Mode {
								case "recover_during_status":
									recoverStep(i, step.Request, *want.Recovered)
								case "expire_lease_during_status", "regress_clock_during_status":
								default:
									t.Fatalf("unknown verify mode %s", step.Mode)
								}
							}
							return provider(c, r)
						}
					}
					outcome, _ := ratify.VerifyProofBundleV2(ctx, req, cb)
					if string(outcome.Stage) != want.Stage || string(outcome.ErrorClass) != want.ErrorClass || want.Disposition != "" && string(outcome.Disposition) != want.Disposition {
						t.Fatalf("step %d verify %s: stage %s class %s disposition %s (%v), want %+v", i, step.Request, outcome.Stage, outcome.ErrorClass, outcome.Disposition, outcome.Error, want)
					}
					if outcome.Stage == ratify.V2StageCommitted {
						checkV2CommittedDecision(t, i, outcome.Committed, want)
						committed[step.Request] = outcome.Committed
					}
				case "claim_only":
					bundle, err := ratify.DecodeProofBundleV2(unb64(t, f.Bundles[request.Bundle]))
					if err != nil {
						t.Fatal(err)
					}
					req, _, _ := v2BuildVerifyRequest(t, request.v2OrderingInputs, nil, &v2Counts{})
					pre, err := ratify.PreflightProofBundleV2(bundle, req.Expected, req.ContextPolicy, req.RequiredScope, req.VerifierNamespace, req.ReplayEpoch, now, req.MaxChallengeAgeSeconds, req.FutureSkewSeconds)
					if err != nil {
						t.Fatal(err)
					}
					claim, disposition, _, err := ratify.ClaimProofBundleV2(ctx, claimStore(), bundle, pre, req.VerifierNamespace, req.ReplayEpoch, now)
					if string(ratify.V2ErrorClassOf(err)) != want.ErrorClass || string(disposition) != want.Disposition {
						t.Fatalf("step %d claim_only: disposition %s err %v, want %+v", i, disposition, err, want)
					}
					claimIDs[step.Request], requestOf[claim.ClaimID] = claim.ClaimID, step.Request
				case "recover":
					recoverStep(i, step.Request, want)
				case "publish":
					c := committed[step.Request]
					if step.Mode == "signer_failure" {
						store.SetSignerFailure(true)
					}
					wire, err := store.PublishV2Receipt(ctx, c.ClaimID(), c.ReceiptBody())
					store.SetSignerFailure(false)
					if want.Failed {
						reasons := map[string]error{"head_of_line_blocked": v2reference.ErrHeadOfLineBlocked, "signer_unavailable": v2reference.ErrSignerUnavailable, "log_frozen": v2reference.ErrLogFrozen}
						if wire != nil || !errors.Is(err, reasons[want.PublishError]) {
							t.Fatalf("step %d publish: %v, want failure %s", i, err, want.PublishError)
						}
						continue
					}
					if err != nil {
						t.Fatalf("step %d publish: %v", i, err)
					}
					receipt, err := ratify.DecodeVerificationReceiptV2(wire)
					if err != nil || receipt.Sequence != want.ReceiptSeq {
						t.Fatalf("step %d publish: sequence %v (%v), want %d", i, receipt, err, want.ReceiptSeq)
					}
					if step.Mode == "corrupt_signature" {
						receipt.Signature.Ed25519[0] ^= 1
						if wire, err = ratify.EncodeVerificationReceiptV2(receipt); err != nil {
							t.Fatal(err)
						}
					}
					receipts[step.Request] = wire
				case "abandon":
					got := []string{}
					for _, id := range store.AbandonPendingReceipts() {
						got = append(got, requestOf[id])
					}
					if !slices.Equal(got, want.Abandoned) {
						t.Fatalf("step %d abandon: %v, want %v", i, got, want.Abandoned)
					}
				case "restore":
					switch step.Mode {
					case "exact":
						store = store.Clone()
					case "lost_state_epoch_bump":
						if store, err = v2reference.NewStore(now, f.LeaseSeconds, step.LogID, fx.priv[f.VerifierKey]); err != nil {
							t.Fatal(err)
						}
						epochOverride = step.ReplayEpoch
						config.LogID = step.LogID
					default:
						t.Fatalf("unknown restore mode %s", step.Mode)
					}
					config.ClaimStore, config.Checkpoint = store, store
				case "release", "release_forged":
					c := committed[step.Request]
					receipt := receipts[step.Request]
					if step.ReceiptOf != "" {
						receipt = receipts[step.ReceiptOf]
					}
					cfg := config
					if step.Checkpoint == "wrong_entry" {
						cfg.Checkpoint = v2WrongEntryCheckpoint{inner: store}
					}
					if step.Op == "release_forged" {
						c, receipt = &ratify.CommittedV2Outcome{}, nil
					}
					result := ratify.ReleaseV2Decision(ctx, c, receipt, cfg)
					if string(result.Status) != want.ReleaseStatus || result.Reason != want.ReleaseReason {
						t.Fatalf("step %d release: %s/%s, want %s/%s", i, result.Status, result.Reason, want.ReleaseStatus, want.ReleaseReason)
					}
					if (result.Decision != nil) != (result.Status == ratify.V2ReleaseReleased) {
						t.Fatal("decision presence does not match release status")
					}
					if result.Decision != nil {
						d := result.Decision
						if d.Decision != want.Decision || d.ReleaseTime != want.ReleaseTime || d.Receipt.Sequence != want.ReceiptSeq {
							t.Fatalf("step %d release: decision %s time %d seq %d, want %+v", i, d.Decision, d.ReleaseTime, d.Receipt.Sequence, want)
						}
					}
				default:
					t.Fatalf("unknown op %s", step.Op)
				}
			}
		})
	}
}

// checkV2CommittedDecision reads the committed receipt body for the test
// only; applications must never authorize from it.
func checkV2CommittedDecision(t *testing.T, step int, c *ratify.CommittedV2Outcome, want v2LifecycleExpect) {
	t.Helper()
	body, err := ratify.DecodeVerificationReceiptBodyV2(c.ReceiptBody())
	if err != nil || body.Decision != want.Decision || body.DecisionReason != want.DecisionReason {
		t.Fatalf("step %d committed %v (%v), want %s/%s", step, body, err, want.Decision, want.DecisionReason)
	}
	if want.TrustAssessment != "" && body.TrustAssessment != want.TrustAssessment || want.StatusAssessment != "" && body.StatusAssessment != want.StatusAssessment ||
		want.ContextAssessment != "" && body.ContextAssessment != want.ContextAssessment {
		t.Fatalf("step %d committed assessments %s/%s/%s, want %s/%s/%s", step, body.TrustAssessment, body.StatusAssessment, body.ContextAssessment,
			want.TrustAssessment, want.StatusAssessment, want.ContextAssessment)
	}
	horizon, _ := c.AllowHorizon()
	if horizon != want.AllowHorizon {
		t.Fatalf("step %d allow horizon %d, want %d", step, horizon, want.AllowHorizon)
	}
}

// Cancelling the verification after the claim commits nothing: the outcome
// is evaluating/evaluation_cancelled, an exact retry sees the claim in
// progress, and lease-expiry recovery terminalizes it (SPEC-v2 §6.11).
func TestV2CancellationAfterClaimLeavesClaimRecoverable(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		LogID        string                        `json:"log_id"`
		LeaseSeconds int64                         `json:"lease_seconds"`
		Bundles      map[string]string             `json:"bundles_b64"`
		Requests     map[string]v2LifecycleRequest `json:"requests"`
	}
	data, err := os.ReadFile(filepath.Join("testvectors", "v2", "lifecycle-scenarios.json"))
	if err != nil || json.Unmarshal(data, &f) != nil {
		t.Fatalf("load lifecycle vectors: %v", err)
	}
	const start = 1800000000
	store, err := v2reference.NewStore(start, f.LeaseSeconds, f.LogID, fx.priv["verifier"])
	if err != nil {
		t.Fatal(err)
	}
	request := f.Requests["A"]
	request.Now = start
	bundle := unb64(t, f.Bundles[request.Bundle])
	ctx, cancel := context.WithCancel(context.Background())
	req, cb, _ := v2BuildVerifyRequest(t, request.v2OrderingInputs, bundle, &v2Counts{})
	cb.ClaimStore = store
	provider := cb.StatusEvidence
	cb.StatusEvidence = func(c context.Context, r ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
		cancel()
		if _, err := provider(c, r); err != nil {
			return ratify.V2StatusEvidenceBatch{}, err
		}
		return ratify.V2StatusEvidenceBatch{}, c.Err()
	}
	outcome, err := ratify.VerifyProofBundleV2(ctx, req, cb)
	if err == nil || outcome.Stage != ratify.V2StageEvaluating || outcome.ErrorClass != ratify.V2ErrEvaluationCancelled || outcome.Committed != nil {
		t.Fatalf("cancelled evaluation: stage %s class %s err %v", outcome.Stage, outcome.ErrorClass, err)
	}
	retryReq, retryCB, _ := v2BuildVerifyRequest(t, request.v2OrderingInputs, bundle, &v2Counts{})
	retryCB.ClaimStore = store
	retry, _ := ratify.VerifyProofBundleV2(context.Background(), retryReq, retryCB)
	if retry.Stage != ratify.V2StageReplay || retry.Disposition != ratify.V2ClaimInProgress {
		t.Fatalf("retry after cancellation: %s/%s", retry.Stage, retry.Disposition)
	}
	if _, err := ratify.RecoverInterruptedClaimV2(context.Background(), store, outcome.Claim.ClaimID); ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimLeaseLive {
		t.Fatalf("recovery during a live lease: %v", err)
	}
	store.SetTime(start + f.LeaseSeconds)
	committed, err := ratify.RecoverInterruptedClaimV2(context.Background(), store, outcome.Claim.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ratify.DecodeVerificationReceiptBodyV2(committed.ReceiptBody())
	if err != nil || body.DecisionReason != "evaluation_interrupted" {
		t.Fatalf("recovered result %v %v", body, err)
	}
}
