package ratify_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// ---------------------------------------------------------------------------
// Shared concurrency scenarios (testvectors/v2/concurrency-scenarios.json)
//
// Every participant is a goroutine; all of them are released together from
// one barrier, so the reference store's mutex sees real contention. Set
// RATIFY_RACE_ITERATIONS to change the per-scenario iteration count.

type v2ConcurrencyStep struct {
	Op              string            `json:"op"`
	Request         string            `json:"request"`
	Time            int64             `json:"time"`
	Withheld        *bool             `json:"withheld"`
	Mode            string            `json:"mode"`
	Checkpoint      string            `json:"checkpoint"`
	Expect          v2LifecycleExpect `json:"expect"`
	ExpectByOutcome *struct {
		Group string                       `json:"group"`
		Cases map[string]v2LifecycleExpect `json:"cases"`
	} `json:"expect_by_outcome"`
}

type v2ConcurrencyParticipant struct {
	Group           string `json:"group"`
	Count           int    `json:"count"`
	Op              string `json:"op"`
	Request         string `json:"request"`
	Time            int64  `json:"time"`
	Target          string `json:"target"`
	TerminalB64     string `json:"terminal_b64"`
	BodyB64         string `json:"body_b64"`
	AllowValidUntil int64  `json:"allow_valid_until"`
}

type v2ConcurrencyInvariant struct {
	Kind     string   `json:"kind"`
	Groups   []string `json:"groups"`
	Outcomes []string `json:"outcomes"`
	Equals   *int     `json:"equals"`
	AtMost   *int     `json:"at_most"`
	Winning  []string `json:"winning"`
	ByGroup  map[string]struct {
		IfWinner []string `json:"if_winner"`
		IfLoser  []string `json:"if_loser"`
	} `json:"by_group"`
}

type v2ConcurrencyFile struct {
	Version           int               `json:"version"`
	Description       string            `json:"description"`
	Inputs            string            `json:"inputs"`
	DefaultIterations int               `json:"default_iterations"`
	Labels            map[string]string `json:"labels"`
	Operations        map[string]string `json:"operations"`
	Invariants        map[string]string `json:"invariants"`
	Scenarios         []struct {
		Name               string                     `json:"name"`
		Description        string                     `json:"description"`
		StartTime          int64                      `json:"start_time"`
		RateAtFinalization bool                       `json:"rate_at_finalization"`
		Setup              []v2ConcurrencyStep        `json:"setup"`
		Participants       []v2ConcurrencyParticipant `json:"participants"`
		Invariants         []v2ConcurrencyInvariant   `json:"invariants"`
		After              []v2ConcurrencyStep        `json:"after"`
	} `json:"scenarios"`
}

type v2LifecycleInputs struct {
	VerifierKey  string                        `json:"verifier_key"`
	LogID        string                        `json:"log_id"`
	LeaseSeconds int64                         `json:"lease_seconds"`
	Bundles      map[string]string             `json:"bundles_b64"`
	Requests     map[string]v2LifecycleRequest `json:"requests"`
}

// v2RaceIteration is the state of one iteration of one scenario.
type v2RaceIteration struct {
	t          *testing.T
	in         *v2LifecycleInputs
	fx         v2Fixture
	store      *v2reference.Store
	rateStore  bool
	mu         sync.Mutex
	committed  map[string]*ratify.CommittedV2Outcome
	receipts   map[string][]byte
	claimIDs   map[string]string
	owners     map[string][]byte
	recorded   map[string][]byte // claim ID -> committed receipt body
	recordedAt []string          // claim IDs in first-recorded order
}

func (it *v2RaceIteration) claimStore() ratify.ClaimStoreV2 {
	if it.rateStore {
		return it.store.WithRateAtFinalization()
	}
	return it.store
}

func (it *v2RaceIteration) record(claimID string, body []byte) {
	it.mu.Lock()
	defer it.mu.Unlock()
	if _, ok := it.recorded[claimID]; !ok {
		it.recorded[claimID] = bytes.Clone(body)
		it.recordedAt = append(it.recordedAt, claimID)
	}
}

func (it *v2RaceIteration) recordOutcome(request string, c *ratify.CommittedV2Outcome) {
	it.mu.Lock()
	it.committed[request] = c
	it.mu.Unlock()
	it.record(c.ClaimID(), c.ReceiptBody())
}

// prepareVerify builds one verification of request at the current store
// clock. It runs on the test goroutine, before any participant starts.
func (it *v2RaceIteration) prepareVerify(name string) (ratify.V2VerifyRequest, ratify.V2VerifyCallbacks) {
	request := it.in.Requests[name]
	inputs := request.v2OrderingInputs
	inputs.Now = it.store.Now()
	req, cb, _ := v2BuildVerifyRequest(it.t, inputs, unb64(it.t, it.in.Bundles[request.Bundle]), &v2Counts{})
	cs := it.claimStore()
	cb.ClaimStore = cs
	if it.rateStore {
		cb.Rate = cs.(ratify.V2RateReservationStore)
	}
	return req, cb
}

func (it *v2RaceIteration) verifyLabel(ctx context.Context, name string, req ratify.V2VerifyRequest, cb ratify.V2VerifyCallbacks) (string, ratify.V2VerifyOutcome) {
	outcome, _ := ratify.VerifyProofBundleV2(ctx, req, cb)
	switch outcome.Stage {
	case ratify.V2StageCommitted:
		it.recordOutcome(name, outcome.Committed)
		body, err := ratify.DecodeVerificationReceiptBodyV2(outcome.Committed.ReceiptBody())
		if err != nil {
			return "undecodable committed body", outcome
		}
		return "committed/" + body.Decision + "/" + body.DecisionReason, outcome
	case ratify.V2StageReplay:
		return "replay/" + string(outcome.Disposition), outcome
	default:
		return string(outcome.Stage) + "/" + string(outcome.ErrorClass), outcome
	}
}

func v2ErrorLabel(err error) string { return "error/" + string(ratify.V2ErrorClassOf(err)) }

func (it *v2RaceIteration) releaseLabel(ctx context.Context, request string) string {
	it.mu.Lock()
	c, receipt := it.committed[request], it.receipts[request]
	it.mu.Unlock()
	config := ratify.V2ReleaseConfig{VerifierPublicKey: it.fx.pub[it.in.VerifierKey], LogID: it.in.LogID, ClaimStore: it.store, Checkpoint: it.store}
	result := ratify.ReleaseV2Decision(ctx, c, receipt, config)
	if result.Status != ratify.V2ReleaseReleased {
		return string(result.Status) + "/" + result.Reason
	}
	d := result.Decision
	r, err := d.Receipt()
	if err != nil {
		return "released with an undecodable receipt"
	}
	return fmt.Sprintf("released/%s/%d/%d", d.Decision(), d.ReleaseTime(), r.Sequence)
}

// step runs one setup or after step; want overrides step.Expect.
func (it *v2RaceIteration) step(ctx context.Context, i int, s v2ConcurrencyStep, want v2LifecycleExpect) {
	t := it.t
	switch s.Op {
	case "set_time":
		it.store.SetTime(s.Time)
	case "set_ack_withheld":
		it.store.SetAcknowledgementWithheld(*s.Withheld)
	case "verify":
		req, cb := it.prepareVerify(s.Request)
		_, outcome := it.verifyLabel(ctx, s.Request, req, cb)
		if string(outcome.Stage) != want.Stage || string(outcome.ErrorClass) != want.ErrorClass || want.Disposition != "" && string(outcome.Disposition) != want.Disposition {
			t.Fatalf("step %d verify %s: stage %s class %s disposition %s (%v), want %+v", i, s.Request, outcome.Stage, outcome.ErrorClass, outcome.Disposition, outcome.Error, want)
		}
		if outcome.Stage == ratify.V2StageCommitted {
			checkV2CommittedDecision(t, i, outcome.Committed, want)
		}
	case "claim_only":
		request := it.in.Requests[s.Request]
		bundle, err := ratify.DecodeProofBundleV2(unb64(t, it.in.Bundles[request.Bundle]))
		if err != nil {
			t.Fatal(err)
		}
		now := it.store.Now()
		req, _, _ := v2BuildVerifyRequest(t, request.v2OrderingInputs, nil, &v2Counts{})
		pre, err := ratify.PreflightProofBundleV2(bundle, req.Expected, req.ContextPolicy, req.RequiredScope, req.VerifierNamespace, req.ReplayEpoch, req.VerifierID, now, req.MaxChallengeAgeSeconds, req.FutureSkewSeconds)
		if err != nil {
			t.Fatal(err)
		}
		capturing := &v2OwnerCapturingClaimStore{ClaimStoreV2: it.claimStore()}
		claim, disposition, _, err := ratify.ClaimProofBundleV2(ctx, capturing, bundle, pre, req.VerifierNamespace, req.ReplayEpoch, now)
		if string(ratify.V2ErrorClassOf(err)) != want.ErrorClass || string(disposition) != want.Disposition {
			t.Fatalf("step %d claim_only: disposition %s err %v, want %+v", i, disposition, err, want)
		}
		it.claimIDs[s.Request], it.owners[s.Request] = claim.ClaimID, capturing.owner
	case "recover":
		outcome, err := ratify.RecoverInterruptedClaimV2(ctx, it.store, it.claimIDs[s.Request])
		if want.ErrorClass != "" {
			if string(ratify.V2ErrorClassOf(err)) != want.ErrorClass {
				t.Fatalf("step %d recover: %v, want %s", i, err, want.ErrorClass)
			}
			return
		}
		if err != nil {
			t.Fatalf("step %d recover: %v", i, err)
		}
		checkV2CommittedDecision(t, i, outcome, want)
		it.recordOutcome(s.Request, outcome)
	case "publish":
		c := it.committed[s.Request]
		wire, err := it.store.PublishV2Receipt(ctx, c.ClaimID(), c.ReceiptBody())
		if err != nil {
			t.Fatalf("step %d publish: %v", i, err)
		}
		receipt, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil || receipt.Sequence != want.ReceiptSeq {
			t.Fatalf("step %d publish: sequence %v (%v), want %d", i, receipt, err, want.ReceiptSeq)
		}
		it.receipts[s.Request] = wire
	case "release":
		got := it.releaseLabel(ctx, s.Request)
		wantLabel := want.ReleaseStatus + "/" + want.ReleaseReason
		if want.ReleaseStatus == string(ratify.V2ReleaseReleased) {
			wantLabel = fmt.Sprintf("released/%s/%d/%d", want.Decision, want.ReleaseTime, want.ReceiptSeq)
		}
		if got != wantLabel {
			t.Fatalf("step %d release: %s, want %s", i, got, wantLabel)
		}
	default:
		t.Fatalf("step %d: op %s is not a concurrency setup or after step", i, s.Op)
	}
}

// participant runs one participant's operation and returns its label.
// prepared runs a verify participant built before the start barrier.
func (it *v2RaceIteration) participant(p v2ConcurrencyParticipant, prepared func(context.Context) string) string {
	ctx := context.Background()
	switch p.Op {
	case "verify":
		return prepared(ctx)
	case "claim_only":
		request := it.in.Requests[p.Request]
		bundle, err := ratify.DecodeProofBundleV2(unb64(it.t, it.in.Bundles[request.Bundle]))
		if err != nil {
			return "undecodable bundle"
		}
		now := it.store.Now()
		req, _, _ := v2BuildVerifyRequest(it.t, request.v2OrderingInputs, nil, &v2Counts{})
		pre, err := ratify.PreflightProofBundleV2(bundle, req.Expected, req.ContextPolicy, req.RequiredScope, req.VerifierNamespace, req.ReplayEpoch, req.VerifierID, now, req.MaxChallengeAgeSeconds, req.FutureSkewSeconds)
		if err != nil {
			return "preflight/" + string(ratify.V2ErrorClassOf(err))
		}
		claim, disposition, _, err := ratify.ClaimProofBundleV2(ctx, it.claimStore(), bundle, pre, req.VerifierNamespace, req.ReplayEpoch, now)
		if err != nil {
			return v2ErrorLabel(err)
		}
		it.mu.Lock()
		it.claimIDs[p.Request] = claim.ClaimID
		it.mu.Unlock()
		return string(disposition)
	case "finalize", "recover_direct":
		it.mu.Lock()
		claimID, owner := it.claimIDs[p.Request], it.owners[p.Request]
		it.mu.Unlock()
		body := unb64(it.t, p.BodyB64)
		var ok bool
		var err error
		if p.Op == "finalize" {
			ok, err = it.claimStore().FinalizeV2Claim(ctx, claimID, owner, unb64(it.t, p.TerminalB64), body, p.AllowValidUntil)
		} else {
			ok, err = it.claimStore().RecoverInterruptedV2Claim(ctx, claimID, unb64(it.t, p.TerminalB64), body)
		}
		switch {
		case err != nil:
			return v2ErrorLabel(err)
		case ok:
			it.record(claimID, body)
			return "committed"
		default:
			return "identical"
		}
	case "recover":
		it.mu.Lock()
		claimID := it.claimIDs[p.Request]
		it.mu.Unlock()
		outcome, err := ratify.RecoverInterruptedClaimV2(ctx, it.store, claimID)
		if err != nil {
			return v2ErrorLabel(err)
		}
		it.recordOutcome(p.Request, outcome)
		body, err := ratify.DecodeVerificationReceiptBodyV2(outcome.ReceiptBody())
		if err != nil {
			return "undecodable recovered body"
		}
		return "committed/" + body.Decision + "/" + body.DecisionReason
	case "release":
		return it.releaseLabel(ctx, p.Request)
	case "acknowledge":
		it.mu.Lock()
		wire := it.receipts[p.Request]
		it.mu.Unlock()
		receipt, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil {
			return "undecodable receipt"
		}
		entry, err := ratify.VerificationReceiptV2Digest(receipt)
		if err != nil {
			return "undigestable receipt"
		}
		ack, err := it.store.AcknowledgeV2Receipt(ctx, receipt.LogID, receipt.Sequence, receipt.PreviousReceiptHash, entry)
		if err != nil {
			return "refused"
		}
		return "acknowledged/" + strconv.FormatInt(ack.Timestamp, 10)
	case "set_time":
		it.store.SetTime(p.Time)
		return "done"
	}
	return "unknown op " + p.Op
}

// receiptLogContiguous publishes every recorded result, retrying entries
// blocked behind an earlier one, and requires sequences 1..k.
func (it *v2RaceIteration) receiptLogContiguous(ctx context.Context) error {
	published := map[string][]byte{}
	for progress := true; progress; {
		progress = false
		for _, claimID := range it.recordedAt {
			if published[claimID] != nil {
				continue
			}
			wire, err := it.store.PublishV2Receipt(ctx, claimID, it.recorded[claimID])
			if errors.Is(err, v2reference.ErrHeadOfLineBlocked) {
				continue
			}
			if err != nil {
				return fmt.Errorf("publish %s: %w", claimID, err)
			}
			published[claimID], progress = wire, true
		}
	}
	sequences := []int64{}
	for _, claimID := range it.recordedAt {
		wire := published[claimID]
		if wire == nil {
			return fmt.Errorf("claim %s never published (head of line blocked)", claimID)
		}
		receipt, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil {
			return err
		}
		again, err := it.store.PublishV2Receipt(ctx, claimID, it.recorded[claimID])
		if err != nil || !bytes.Equal(again, wire) {
			return fmt.Errorf("claim %s republished differently (%v)", claimID, err)
		}
		sequences = append(sequences, receipt.Sequence)
	}
	slices.Sort(sequences)
	for i, seq := range sequences {
		if seq != int64(i+1) {
			return fmt.Errorf("receipt sequences %v, want 1..%d", sequences, len(sequences))
		}
	}
	return nil
}

func v2CheckConcurrencyInvariant(inv v2ConcurrencyInvariant, labels map[string][]string, all []string) error {
	of := func(groups []string) []string {
		if len(groups) == 0 {
			return all
		}
		out := []string{}
		for _, g := range groups {
			out = append(out, labels[g]...)
		}
		return out
	}
	switch inv.Kind {
	case "allowed":
		for _, l := range of(inv.Groups) {
			if !slices.Contains(inv.Outcomes, l) {
				return fmt.Errorf("outcome %q of %v is not one of %v", l, inv.Groups, inv.Outcomes)
			}
		}
	case "count":
		n := 0
		for _, l := range of(inv.Groups) {
			if slices.Contains(inv.Outcomes, l) {
				n++
			}
		}
		if inv.Equals != nil && n != *inv.Equals || inv.AtMost != nil && n > *inv.AtMost {
			return fmt.Errorf("%d outcomes of %v are in %v, want equals %v at most %v", n, inv.Groups, inv.Outcomes, inv.Equals, inv.AtMost)
		}
	case "all_equal":
		got := of(inv.Groups)
		for _, l := range got {
			if l != got[0] {
				return fmt.Errorf("outcomes of %v differ: %v", inv.Groups, got)
			}
		}
	case "one_winner":
		winners := []string{}
		for g := range inv.ByGroup {
			if slices.ContainsFunc(labels[g], func(l string) bool { return slices.Contains(inv.Winning, l) }) {
				winners = append(winners, g)
			}
		}
		if len(winners) > 1 {
			return fmt.Errorf("winning groups %v, want at most one", winners)
		}
		for g, rule := range inv.ByGroup {
			want := rule.IfLoser
			if slices.Contains(winners, g) {
				want = rule.IfWinner
			}
			for _, l := range labels[g] {
				if !slices.Contains(want, l) {
					return fmt.Errorf("group %s (winners %v) has outcome %q, not one of %v", g, winners, l, want)
				}
			}
		}
	default:
		return fmt.Errorf("unknown invariant kind %s", inv.Kind)
	}
	return nil
}

// v2MeasureVerification times one uncancelled verification of the request
// that group target verifies, on a scratch store.
func v2MeasureVerification(t *testing.T, in *v2LifecycleInputs, fx v2Fixture, start int64, participants []v2ConcurrencyParticipant, target string) time.Duration {
	for _, p := range participants {
		if p.Group != target || p.Op != "verify" {
			continue
		}
		store, err := v2reference.NewStore(start, in.LeaseSeconds, in.LogID, fx.priv[in.VerifierKey])
		if err != nil {
			t.Fatal(err)
		}
		it := &v2RaceIteration{t: t, in: in, fx: fx, store: store, committed: map[string]*ratify.CommittedV2Outcome{}, recorded: map[string][]byte{}}
		req, cb := it.prepareVerify(p.Request)
		began := time.Now()
		it.verifyLabel(context.Background(), p.Request, req, cb)
		return time.Since(began)
	}
	t.Fatalf("cancel target %s has no verify participant", target)
	return 0
}

func v2RaceIterations(t *testing.T, fileDefault int) int {
	if s := os.Getenv("RATIFY_RACE_ITERATIONS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			t.Fatalf("RATIFY_RACE_ITERATIONS=%q is not a positive integer", s)
		}
		return n
	}
	return fileDefault
}

func TestV2ConformanceConcurrencyScenarios(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f v2ConcurrencyFile
	loadV2Vector(t, "concurrency-scenarios.json", &f)
	if f.Version != 1 || len(f.Scenarios) == 0 {
		t.Fatalf("concurrency-scenarios.json version %d with %d scenarios", f.Version, len(f.Scenarios))
	}
	var in struct {
		v2LifecycleInputs
		Version          int               `json:"version"`
		Description      string            `json:"description"`
		Semantics        map[string]string `json:"semantics"`
		Scenarios        any               `json:"scenarios"`
		ProfileScenarios any               `json:"profile_scenarios"`
	}
	loadV2Vector(t, f.Inputs, &in)
	iterations := v2RaceIterations(t, f.DefaultIterations)
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			// seen counts each distinct outcome per group across iterations,
			// logged so a verbose run shows which interleavings occurred.
			seen := map[string]int{}
			defer func() { t.Logf("%d iterations, outcomes %v", iterations, seen) }()
			// span is the duration of one uncancelled verification of a
			// cancel target, measured once on a scratch store.
			var span time.Duration
			for iter := range iterations {
				store, err := v2reference.NewStore(sc.StartTime, in.LeaseSeconds, in.LogID, fx.priv[in.VerifierKey])
				if err != nil {
					t.Fatal(err)
				}
				it := &v2RaceIteration{t: t, in: &in.v2LifecycleInputs, fx: fx, store: store, rateStore: sc.RateAtFinalization,
					committed: map[string]*ratify.CommittedV2Outcome{}, receipts: map[string][]byte{}, claimIDs: map[string]string{},
					owners: map[string][]byte{}, recorded: map[string][]byte{}}
				ctx := context.Background()
				for i, s := range sc.Setup {
					it.step(ctx, i, s, s.Expect)
				}
				// Prepare every participant on the test goroutine, then
				// release them together.
				type slot struct {
					group string
					run   func() string
				}
				slots := []slot{}
				cancels := map[string][]context.CancelFunc{}
				for _, p := range sc.Participants {
					for range p.Count {
						var prepared func(context.Context) string
						if p.Op == "verify" {
							req, cb := it.prepareVerify(p.Request)
							vctx, cancel := context.WithCancel(ctx)
							cancels[p.Group] = append(cancels[p.Group], cancel)
							name := p.Request
							prepared = func(context.Context) string {
								label, _ := it.verifyLabel(vctx, name, req, cb)
								return label
							}
						}
						p := p
						run := func() string { return it.participant(p, prepared) }
						if p.Op == "cancel" {
							// Spread the signal over the target's verification
							// across iterations: 0 to 1.2 times its duration.
							if span == 0 {
								span = v2MeasureVerification(t, &in.v2LifecycleInputs, fx, sc.StartTime, sc.Participants, p.Target)
							}
							delay := span * time.Duration(iter%13) / 10
							run = func() string {
								time.Sleep(delay)
								for _, cancel := range cancels[p.Target] {
									cancel()
								}
								return "done"
							}
						}
						slots = append(slots, slot{p.Group, run})
					}
				}
				results := make([]string, len(slots))
				var wg sync.WaitGroup
				start := make(chan struct{})
				for k, s := range slots {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						results[k] = s.run()
					}()
				}
				close(start)
				wg.Wait()
				for _, cancels := range cancels {
					for _, cancel := range cancels {
						cancel()
					}
				}
				labels := map[string][]string{}
				all := []string{}
				for k, s := range slots {
					labels[s.group] = append(labels[s.group], results[k])
					all = append(all, results[k])
					seen[s.group+":"+results[k]]++
				}
				for _, inv := range sc.Invariants {
					var err error
					if inv.Kind == "receipt_log_contiguous" {
						err = it.receiptLogContiguous(ctx)
					} else {
						err = v2CheckConcurrencyInvariant(inv, labels, all)
					}
					if err != nil {
						t.Fatalf("iteration %d: invariant %s: %v (outcomes %v)", iter, inv.Kind, err, labels)
					}
				}
				for i, s := range sc.After {
					want := s.Expect
					if b := s.ExpectByOutcome; b != nil {
						got := labels[b.Group]
						if len(got) != 1 {
							t.Fatalf("iteration %d: expect_by_outcome group %s has %d participants", iter, b.Group, len(got))
						}
						var ok bool
						if want, ok = b.Cases[got[0]]; !ok {
							t.Fatalf("iteration %d: after step %d: no case for outcome %s", iter, i, got[0])
						}
					}
					it.step(ctx, i, s, want)
				}
			}
		})
	}
}
