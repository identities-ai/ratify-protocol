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
	"sync"
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
		TransitionNegatives []struct {
			Name             string        `json:"name"`
			Description      string        `json:"description"`
			CurrentB64       string        `json:"current_snapshot_b64"`
			CurrentHead      v2JournalHead `json:"current_head"`
			NextB64          string        `json:"next_snapshot_b64"`
			NextHead         v2JournalHead `json:"next_head"`
			ExpectErrorClass string        `json:"expect_error_class"`
		} `json:"transition_negatives"`
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
	if len(f.TransitionNegatives) == 0 {
		t.Fatal("no journal transition negatives")
	}
	for _, n := range f.TransitionNegatives {
		t.Run("transition_"+n.Name, func(t *testing.T) {
			current, err := ratify.ImportSecurityJournalSnapshotV2(unb64(t, n.CurrentB64), ratify.SecurityJournalHeadV2{Generation: n.CurrentHead.Generation, Digest: n.CurrentHead.Digest})
			if err != nil {
				t.Fatalf("current snapshot: %v", err)
			}
			next, err := ratify.ImportSecurityJournalSnapshotV2(unb64(t, n.NextB64), ratify.SecurityJournalHeadV2{Generation: n.NextHead.Generation, Digest: n.NextHead.Digest})
			if err != nil {
				t.Fatalf("next snapshot: %v", err)
			}
			err = ratify.ValidateSecurityJournalTransitionV2(current, next)
			if err == nil || string(ratify.V2ErrorClassOf(err)) != n.ExpectErrorClass {
				t.Fatalf("transition error %v (class %q), want class %q", err, ratify.V2ErrorClassOf(err), n.ExpectErrorClass)
			}
		})
	}
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
	Outcomes          []string           `json:"outcomes"`
	FinalizeResult    string             `json:"finalize_result"`
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

// v2OwnerCapturingClaimStore records the evaluator owner token a claim store
// returns to the creator, so a finalize step can call the store directly.
type v2OwnerCapturingClaimStore struct {
	ratify.ClaimStoreV2
	owner []byte
}

func (s *v2OwnerCapturingClaimStore) ClaimV2(ctx context.Context, claim ratify.V2ChallengeClaim) (ratify.V2ClaimResult, error) {
	result, err := s.ClaimStoreV2.ClaimV2(ctx, claim)
	s.owner = bytes.Clone(result.OwnerToken)
	return result, err
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
				Op              string            `json:"op"`
				Request         string            `json:"request"`
				Requests        []string          `json:"requests"`
				Time            int64             `json:"time"`
				Withheld        *bool             `json:"withheld"`
				Mode            string            `json:"mode"`
				ReceiptOf       string            `json:"receipt_of"`
				Checkpoint      string            `json:"checkpoint"`
				ReplayEpoch     int64             `json:"replay_epoch"`
				LogID           string            `json:"log_id"`
				TerminalB64     string            `json:"terminal_b64"`
				BodyB64         string            `json:"body_b64"`
				AllowValidUntil int64             `json:"allow_valid_until"`
				Expect          v2LifecycleExpect `json:"expect"`
			} `json:"steps"`
		} `json:"scenarios"`
		// Profile scripts run in TestV2ConformanceProfileScenarios.
		ProfileScenarios json.RawMessage `json:"profile_scenarios"`
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
			owners := map[string][]byte{}
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
				claimID := claimIDs[request]
				if claimID == "" {
					// Never claimed: the request's own claim ID (claim_not_found).
					e := f.Requests[request].ExpectedChallenge
					var err error
					if claimID, err = ratify.ProtocolClaimIDV2(e.VerifierNamespace, e.ReplayEpoch, unb64(t, e.ValueB64)); err != nil {
						t.Fatal(err)
					}
				}
				outcome, err := ratify.RecoverInterruptedClaimV2(ctx, store, claimID)
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
			// runVerify runs one verify step. It is safe for concurrent use
			// with mode "" (verify_concurrent); the maps it writes are guarded.
			var mapsMu sync.Mutex
			runVerify := func(i int, name, mode string, at int64, want v2LifecycleExpect) ratify.V2VerifyOutcome {
				request := f.Requests[name]
				counts := &v2Counts{}
				inputs := request.v2OrderingInputs
				inputs.Now = store.Now()
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
					t.Error(err)
				}
				mapsMu.Lock()
				claimIDs[name], requestOf[claimID] = claimID, name
				mapsMu.Unlock()
				vctx, cancel := context.WithCancel(ctx)
				defer cancel()
				switch mode {
				case "":
				case "cancel_before_claim":
					cancel()
				default:
					provider, fired := cb.StatusEvidence, false
					cb.StatusEvidence = func(c context.Context, r ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
						if !fired {
							fired = true
							switch mode {
							case "cancel_during_status":
								cancel()
								return ratify.V2StatusEvidenceBatch{}, c.Err()
							case "recover_during_status":
								store.SetTime(at)
								recoverStep(i, name, *want.Recovered)
							case "expire_lease_during_status", "regress_clock_during_status":
								store.SetTime(at)
							default:
								t.Fatalf("unknown verify mode %s", mode)
							}
						}
						return provider(c, r)
					}
				}
				outcome, _ := ratify.VerifyProofBundleV2(vctx, req, cb)
				return outcome
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
					outcome := runVerify(i, step.Request, step.Mode, step.Time, want)
					if string(outcome.Stage) != want.Stage || string(outcome.ErrorClass) != want.ErrorClass || want.Disposition != "" && string(outcome.Disposition) != want.Disposition {
						t.Fatalf("step %d verify %s: stage %s class %s disposition %s (%v), want %+v", i, step.Request, outcome.Stage, outcome.ErrorClass, outcome.Disposition, outcome.Error, want)
					}
					if outcome.Stage == ratify.V2StageCommitted {
						checkV2CommittedDecision(t, i, outcome.Committed, want)
						committed[step.Request] = outcome.Committed
					}
				case "verify_concurrent":
					results := make([]ratify.V2VerifyOutcome, len(step.Requests))
					var wg sync.WaitGroup
					start := make(chan struct{})
					for k, name := range step.Requests {
						wg.Add(1)
						go func(k int, name string) {
							defer wg.Done()
							<-start
							results[k] = runVerify(i, name, "", 0, want)
						}(k, name)
					}
					close(start)
					wg.Wait()
					got := []string{}
					for k, outcome := range results {
						label := string(outcome.Stage)
						if outcome.Stage == ratify.V2StagePreflight || outcome.Stage == ratify.V2StageEvaluating {
							label += "/" + string(outcome.ErrorClass)
						}
						got = append(got, label)
						if outcome.Stage == ratify.V2StageCommitted {
							committed[step.Requests[k]] = outcome.Committed
						}
					}
					slices.Sort(got)
					if !slices.Equal(got, want.Outcomes) {
						t.Fatalf("step %d verify_concurrent %v: %v, want %v", i, step.Requests, got, want.Outcomes)
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
					capturing := &v2OwnerCapturingClaimStore{ClaimStoreV2: claimStore()}
					claim, disposition, _, err := ratify.ClaimProofBundleV2(ctx, capturing, bundle, pre, req.VerifierNamespace, req.ReplayEpoch, now)
					if string(ratify.V2ErrorClassOf(err)) != want.ErrorClass || string(disposition) != want.Disposition {
						t.Fatalf("step %d claim_only: disposition %s err %v, want %+v", i, disposition, err, want)
					}
					claimIDs[step.Request], requestOf[claim.ClaimID] = claim.ClaimID, step.Request
					owners[step.Request] = capturing.owner
				case "finalize":
					finalized, err := claimStore().FinalizeV2Claim(ctx, claimIDs[step.Request], owners[step.Request], unb64(t, step.TerminalB64), unb64(t, step.BodyB64), step.AllowValidUntil)
					if want.ErrorClass != "" {
						if finalized || string(ratify.V2ErrorClassOf(err)) != want.ErrorClass {
							t.Fatalf("step %d finalize: finalized=%t err=%v (class %s), want class %s", i, finalized, err, ratify.V2ErrorClassOf(err), want.ErrorClass)
						}
						continue
					}
					got := map[bool]string{true: "committed", false: "identical"}[finalized]
					if err != nil || got != want.FinalizeResult {
						t.Fatalf("step %d finalize: %s (%v), want %s", i, got, err, want.FinalizeResult)
					}
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
				case "plant_release":
					store.PlantReleaseTestOnly(committed[step.Request].ClaimID(), step.Time)
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
						receipt, err := d.Receipt()
						if err != nil || d.Decision() != want.Decision || d.ReleaseTime() != want.ReleaseTime || receipt.Sequence != want.ReceiptSeq {
							t.Fatalf("step %d release: decision %s time %d receipt %v (%v), want %+v", i, d.Decision(), d.ReleaseTime(), receipt, err, want)
						}
						checkV2ReleasedDecisionAllowed(t, i, d)
					}
				default:
					t.Fatalf("unknown op %s", step.Op)
				}
			}
		})
	}
}

// checkV2ReleasedDecisionAllowed checks that Allowed compares the receiver's
// authoritative time only with the sealed exclusive deadlines, and that
// changing values returned by the accessors does not change the decision.
func checkV2ReleasedDecisionAllowed(t *testing.T, step int, d *ratify.V2ReleasedDecision) {
	t.Helper()
	ctx := context.Background()
	at := func(now int64) bool { return d.Allowed(ctx, v2FixedClock(now)) }
	horizon, isAllow := d.AllowHorizon()
	if isAllow != (d.Decision() == "allow") {
		t.Fatalf("step %d: allow horizon present=%v for decision %s", step, isAllow, d.Decision())
	}
	if !isAllow {
		if at(d.ReleaseTime()) {
			t.Fatalf("step %d: a released %s is Allowed", step, d.Decision())
		}
		return
	}
	deadline := min(horizon, d.ChallengeExpiresAt())
	if !at(d.ReleaseTime()) || !at(deadline-1) || at(deadline) || at(deadline+1) {
		t.Fatalf("step %d: Allowed does not end exactly at the exclusive deadline %d", step, deadline)
	}
	scope, wire := d.GrantedScope(), d.ReceiptWire()
	receipt, err := d.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	for i := range scope {
		scope[i] = "mutated"
	}
	for i := range wire {
		wire[i] = 0
	}
	receipt.Decision, receipt.Sequence = "deny", receipt.Sequence+1
	again, err := d.Receipt()
	if err != nil || again.Decision != "allow" || again.Sequence != receipt.Sequence-1 || slices.Contains(d.GrantedScope(), "mutated") || !at(d.ReleaseTime()) {
		t.Fatalf("step %d: a returned copy changed the released decision", step)
	}
}

type v2FixedClock int64

func (c v2FixedClock) AuthoritativeTimeV2(context.Context) (int64, error) { return int64(c), nil }

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
