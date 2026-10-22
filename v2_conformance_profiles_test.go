package ratify_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// Part B profile scenarios (lifecycle-scenarios.json profile_scenarios):
// the single-device offline profile (SPEC-v2 §7.13) and the dual-root
// composition profile (§7.14).

type v2ProfileExpect struct {
	v2LifecycleExpect
	DeviceStatus   string  `json:"device_status"`
	DeviceError    string  `json:"device_error"`
	Acknowledged   []int64 `json:"acknowledged"`
	AckTime        int64   `json:"ack_time"`
	Uploaded       []int64 `json:"uploaded"`
	LedgerComplete bool    `json:"ledger_complete"`
	LedgerError    string  `json:"ledger_error"`
	Executed       int     `json:"executed"`
}

type v2ProfileStep struct {
	Op          string   `json:"op"`
	Request     string   `json:"request"`
	Requests    []string `json:"requests"`
	Time        int64    `json:"time"`
	Withheld    *bool    `json:"withheld"`
	Mode        string   `json:"mode"`
	Checkpoint  string   `json:"checkpoint"`
	Snapshot    string   `json:"snapshot"`
	Sequence    int64    `json:"sequence"`
	Slot        *int     `json:"slot"`
	Count       int      `json:"count"`
	ApprovalSet *struct {
		ID                string    `json:"id"`
		AgentID           string    `json:"agent_id"`
		RequiredScope     string    `json:"required_scope"`
		SessionContextB64 string    `json:"session_context_b64"`
		Roots             [2]string `json:"roots"`
	} `json:"approval_set"`
	Expect v2ProfileExpect `json:"expect"`
}

// v2DeviceClock is the device's one security clock: whichever primary store
// is current (a rollback replaces the store, not the clock).
type v2DeviceClock struct{ store **v2reference.Store }

func (c v2DeviceClock) AuthoritativeTimeV2(ctx context.Context) (int64, error) {
	return (*c.store).AuthoritativeTimeV2(ctx)
}

func v2DeviceErrorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, v2reference.ErrDevicePowerLoss):
		return "power_loss"
	case errors.Is(err, v2reference.ErrDeviceStorageFull):
		return "storage_full"
	case errors.Is(err, v2reference.ErrDeviceStateMismatch):
		return "state_mismatch"
	case errors.Is(err, v2reference.ErrDeviceFrozen):
		return "frozen"
	case ratify.V2ErrorClassOf(err) == ratify.V2ErrClockRegressed:
		return "clock_regressed"
	}
	return "unexpected: " + err.Error()
}

func v2LedgerErrorClass(err error) string {
	for class, target := range map[string]error{
		"approval_set_invalid": v2reference.ErrApprovalSetInvalid, "not_released": v2reference.ErrApprovalNotReleased,
		"action_mismatch": v2reference.ErrApprovalActionMismatch, "root_mismatch": v2reference.ErrApprovalRootMismatch,
		"slot_filled": v2reference.ErrApprovalSlotFilled, "incomplete": v2reference.ErrApprovalIncomplete,
		"expired": v2reference.ErrApprovalExpired, "already_executed": v2reference.ErrApprovalAlreadyExecuted,
	} {
		if errors.Is(err, target) {
			return class
		}
	}
	if err != nil {
		return "unexpected: " + err.Error()
	}
	return ""
}

func TestV2ConformanceProfileScenarios(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version          int                           `json:"version"`
		Description      string                        `json:"description"`
		Semantics        map[string]string             `json:"semantics"`
		Scenarios        json.RawMessage               `json:"scenarios"`
		LogID            string                        `json:"log_id"`
		LeaseSeconds     int64                         `json:"lease_seconds"`
		VerifierKey      string                        `json:"verifier_key"`
		Bundles          map[string]string             `json:"bundles_b64"`
		Requests         map[string]v2LifecycleRequest `json:"requests"`
		ProfileScenarios []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Profile     string `json:"profile"`
			StartTime   int64  `json:"start_time"`
			Device      *struct {
				ComponentSeedB64 string `json:"component_seed_b64"`
				Capacity         int    `json:"capacity"`
			} `json:"device"`
			Steps []v2ProfileStep `json:"steps"`
		} `json:"profile_scenarios"`
	}
	loadV2Vector(t, "lifecycle-scenarios.json", &f)
	profiles := map[string]int{}
	for _, sc := range f.ProfileScenarios {
		profiles[sc.Profile]++
	}
	if profiles["single_device_offline"] < 9 || profiles["dual_root"] < 9 || len(profiles) != 2 {
		t.Fatalf("profile scenarios %v", profiles)
	}
	ctx := context.Background()
	for _, sc := range f.ProfileScenarios {
		t.Run(sc.Name, func(t *testing.T) {
			store, err := v2reference.NewStore(sc.StartTime, f.LeaseSeconds, f.LogID, fx.priv[f.VerifierKey])
			if err != nil {
				t.Fatal(err)
			}
			var device *v2reference.DeviceCheckpointTestOnly
			var component *v2reference.DeviceComponentTestOnly
			var uplink *v2reference.DeviceUplinkTestOnly
			if sc.Profile == "single_device_offline" {
				store.SetAcknowledgementWithheld(true)
				component, err = v2reference.NewDeviceComponentTestOnly(unb64(t, sc.Device.ComponentSeedB64), sc.Device.Capacity, v2DeviceClock{&store})
				if err != nil {
					t.Fatal(err)
				}
				device = v2reference.NewDeviceCheckpointTestOnly(store, component, component.PublicKey())
				uplink = v2reference.NewDeviceUplinkTestOnly(device)
			}
			ledger := v2reference.NewApprovalLedgerTestOnly()
			var setID string
			committed := map[string]*ratify.CommittedV2Outcome{}
			receipts := map[string][]byte{}
			decisions := map[string]*ratify.V2ReleasedDecision{}
			snapshots := map[string]*v2reference.Store{}
			for i, step := range sc.Steps {
				want := step.Expect
				request := f.Requests[step.Request]
				switch step.Op {
				case "set_time":
					store.SetTime(step.Time)
				case "set_ack_withheld":
					store.SetAcknowledgementWithheld(*step.Withheld)
				case "verify":
					inputs := request.v2OrderingInputs
					inputs.Now = store.Now()
					req, cb, _ := v2BuildVerifyRequest(t, inputs, unb64(t, f.Bundles[request.Bundle]), &v2Counts{})
					cb.ClaimStore = store
					outcome, _ := ratify.VerifyProofBundleV2(ctx, req, cb)
					if string(outcome.Stage) != want.Stage || string(outcome.ErrorClass) != want.ErrorClass {
						t.Fatalf("step %d verify %s: stage %s class %s (%v), want %+v", i, step.Request, outcome.Stage, outcome.ErrorClass, outcome.Error, want.v2LifecycleExpect)
					}
					if outcome.Stage == ratify.V2StageCommitted {
						checkV2CommittedDecision(t, i, outcome.Committed, want.v2LifecycleExpect)
						committed[step.Request] = outcome.Committed
					}
				case "publish":
					c := committed[step.Request]
					wire, err := store.PublishV2Receipt(ctx, c.ClaimID(), c.ReceiptBody())
					if err != nil {
						t.Fatalf("step %d publish: %v", i, err)
					}
					receipt, err := ratify.DecodeVerificationReceiptV2(wire)
					if err != nil || receipt.Sequence != want.ReceiptSeq {
						t.Fatalf("step %d publish: sequence %v (%v), want %d", i, receipt, err, want.ReceiptSeq)
					}
					receipts[step.Request] = wire
				case "release":
					config := ratify.V2ReleaseConfig{VerifierPublicKey: fx.pub[f.VerifierKey], LogID: f.LogID, ClaimStore: store, Checkpoint: store}
					if step.Checkpoint == "device" {
						config.Checkpoint = device
					}
					result := ratify.ReleaseV2Decision(ctx, committed[step.Request], receipts[step.Request], config)
					if string(result.Status) != want.ReleaseStatus || result.Reason != want.ReleaseReason {
						t.Fatalf("step %d release %s: %s/%s, want %s/%s", i, step.Request, result.Status, result.Reason, want.ReleaseStatus, want.ReleaseReason)
					}
					decisions[step.Request] = result.Decision
					if d := result.Decision; d != nil {
						receipt, err := d.Receipt()
						if err != nil || d.Decision() != want.Decision || d.ReleaseTime() != want.ReleaseTime || receipt.Sequence != want.ReceiptSeq {
							t.Fatalf("step %d release: decision %s time %d receipt %v (%v), want %+v", i, d.Decision(), d.ReleaseTime(), receipt, err, want.v2LifecycleExpect)
						}
						checkV2ReleasedDecisionAllowed(t, i, d)
					}
				case "device_power_loss":
					modes := map[string]v2reference.DevicePowerLoss{"before_commit": v2reference.DevicePowerLossBeforeCommit, "after_commit": v2reference.DevicePowerLossAfterCommit}
					component.SetPowerLoss(modes[step.Mode])
				case "device_submit":
					acknowledged, err := device.SubmitPending(ctx)
					if got := v2DeviceErrorClass(err); got != want.DeviceError || !slices.Equal(acknowledged, append([]int64{}, want.Acknowledged...)) {
						t.Fatalf("step %d device_submit: acknowledged %v error %s, want %v %q", i, acknowledged, got, want.Acknowledged, want.DeviceError)
					}
				case "device_resubmit":
					ack, err := device.Resubmit(ctx, step.Sequence)
					if got := v2DeviceErrorClass(err); got != want.DeviceError || err == nil && ack.Timestamp != want.AckTime {
						t.Fatalf("step %d device_resubmit: %+v %s, want time %d %q", i, ack, got, want.AckTime, want.DeviceError)
					}
				case "device_startup":
					if got := device.Startup(); string(got) != want.DeviceStatus {
						t.Fatalf("step %d device_startup: %s, want %s", i, got, want.DeviceStatus)
					}
				case "snapshot":
					snapshots[step.Snapshot] = store.Clone()
				case "restore":
					now := store.Now()
					store = snapshots[step.Snapshot].Clone()
					store.SetTime(now)
					device = v2reference.NewDeviceCheckpointTestOnly(store, component, component.PublicKey())
					uplink = v2reference.NewDeviceUplinkTestOnly(device)
				case "corrupt_state":
					store.CorruptSealedStateTestOnly(committed[step.Request].ClaimID())
				case "upload":
					if got := uplink.Upload(ctx); !slices.Equal(got, append([]int64{}, want.Uploaded...)) {
						t.Fatalf("step %d upload: %v, want %v", i, got, want.Uploaded)
					}
				case "ledger_open":
					s := step.ApprovalSet
					err := ledger.Open(v2reference.ApprovalSetTestOnly{ApprovalSetID: s.ID, AgentID: s.AgentID, RequiredScope: s.RequiredScope, SessionContext: unb64(t, s.SessionContextB64), Roots: s.Roots})
					if got := v2LedgerErrorClass(err); got != want.LedgerError {
						t.Fatalf("step %d ledger_open: %s, want %q", i, got, want.LedgerError)
					}
					if err == nil {
						setID = s.ID
					}
				case "ledger_record":
					complete, err := ledger.RecordApproval(setID, *step.Slot, decisions[step.Request], unb64(t, f.Bundles[request.Bundle]))
					if got := v2LedgerErrorClass(err); got != want.LedgerError || complete != want.LedgerComplete {
						t.Fatalf("step %d ledger_record %s: complete %v %s, want %v %q", i, step.Request, complete, got, want.LedgerComplete, want.LedgerError)
					}
				case "ledger_record_concurrent":
					var wg sync.WaitGroup
					errs := make([]error, len(step.Requests))
					for slot, name := range step.Requests {
						wg.Add(1)
						go func() {
							defer wg.Done()
							_, errs[slot] = ledger.RecordApproval(setID, slot, decisions[name], unb64(t, f.Bundles[f.Requests[name].Bundle]))
						}()
					}
					wg.Wait()
					if err := errors.Join(errs...); err != nil {
						t.Fatalf("step %d ledger_record_concurrent: %v", i, err)
					}
					// An identical re-record reports the final state.
					complete, err := ledger.RecordApproval(setID, 0, decisions[step.Requests[0]], unb64(t, f.Bundles[f.Requests[step.Requests[0]].Bundle]))
					if err != nil || complete != want.LedgerComplete {
						t.Fatalf("step %d ledger_record_concurrent: complete %v (%v)", i, complete, err)
					}
				case "ledger_execute":
					if got := v2LedgerErrorClass(ledger.Execute(ctx, setID, store)); got != want.LedgerError {
						t.Fatalf("step %d ledger_execute: %s, want %q", i, got, want.LedgerError)
					}
				case "ledger_execute_concurrent":
					var wg sync.WaitGroup
					var mu sync.Mutex
					executed := 0
					for range step.Count {
						wg.Add(1)
						go func() {
							defer wg.Done()
							err := ledger.Execute(ctx, setID, store)
							mu.Lock()
							defer mu.Unlock()
							if err == nil {
								executed++
							} else if !errors.Is(err, v2reference.ErrApprovalAlreadyExecuted) {
								t.Errorf("concurrent execute: %v", err)
							}
						}()
					}
					wg.Wait()
					if executed != want.Executed {
						t.Fatalf("step %d ledger_execute_concurrent: %d executed, want %d", i, executed, want.Executed)
					}
				default:
					t.Fatalf("unknown profile op %s", step.Op)
				}
			}
		})
	}
}
