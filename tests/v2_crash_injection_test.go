package ratify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// Crash injection (SPEC-v2 §6.7 to §6.9, §7.2 to §7.11). A fault-injecting
// wrapper around the reference store's durable interfaces counts every call
// that writes durable state and, at call N, kills the calling process either
// before the call reaches the store or after the store committed it but
// before the caller sees the result. The reference store is the disk and
// survives; every value the process held in memory is lost.
//
// Process death is modelled with runtime.Goexit, not a panic: the verifier
// and release paths contain store panics with recover and turn them into
// ordinary errors, which a dead process never returns. Goexit runs deferred
// calls (on these paths they only recover, classify, and unlock) but
// recover() returns nil for it, so no code after the crash point runs and no
// caller can observe the crash as an error.
//
// After the crash the service restarts against the same store, waits out the
// evaluator lease, and retries every presentation: verify (an in-progress
// claim is recovered with RecoverInterruptedClaimV2, and a committed claim
// whose handoff died is resumed with ResumeCommittedClaimV2), publish,
// acknowledge and release. Two restart models are run:
//
//   - volatile: the restarted service holds nothing but the claim store;
//   - journaled: the service is assumed to keep each committed handoff and
//     signed receipt once the call that produced it returned (a durable
//     caller journal the SDK does not provide), so publication,
//     acknowledgement and release crash points are exercised after restart.

// v2CrashMode is where the injected process death happens.
type v2CrashMode int

const (
	v2CrashNone v2CrashMode = iota
	v2CrashBefore
	v2CrashAfter
)

func (m v2CrashMode) String() string {
	return map[v2CrashMode]string{v2CrashNone: "none", v2CrashBefore: "before", v2CrashAfter: "after"}[m]
}

// v2CrashInjector counts durable writes and kills the process at one of them.
type v2CrashInjector struct {
	mu      sync.Mutex
	ops     []string
	crashAt int
	mode    v2CrashMode
	crashed bool
}

// write runs one durable write. At the armed call it ends the calling
// goroutine before or after the write reaches the store.
func (in *v2CrashInjector) write(op string, do func()) {
	in.mu.Lock()
	in.ops = append(in.ops, op)
	hit := in.mode != v2CrashNone && len(in.ops) == in.crashAt
	mode := in.mode
	if hit {
		in.crashed, in.mode = true, v2CrashNone
	}
	in.mu.Unlock()
	if hit && mode == v2CrashBefore {
		runtime.Goexit()
	}
	do()
	if hit {
		runtime.Goexit()
	}
}

// v2CrashCommit is a terminal result the store accepted.
type v2CrashCommit struct {
	terminal, body []byte
	recovered      bool
}

func (c v2CrashCommit) receipt(t *testing.T) *ratify.VerificationReceiptV2 {
	t.Helper()
	body, err := ratify.DecodeVerificationReceiptBodyV2(c.body)
	if err != nil {
		t.Fatalf("committed body does not decode: %v", err)
	}
	return body
}

// v2CrashOracle observes, on the disk side of the wrapper, every write the
// store accepted. It is the test's ground truth, never the service's.
type v2CrashOracle struct {
	mu          sync.Mutex
	claimedAt   map[string]int64
	progress    map[string]ratify.V2EvaluationProgress
	commits     map[string]v2CrashCommit
	commitOrder []string
	wires       map[int64][]byte
	released    map[string][]*ratify.V2ReleasedDecision
	violations  []string
}

func newV2CrashOracle() *v2CrashOracle {
	return &v2CrashOracle{claimedAt: map[string]int64{}, progress: map[string]ratify.V2EvaluationProgress{}, commits: map[string]v2CrashCommit{},
		wires: map[int64][]byte{}, released: map[string][]*ratify.V2ReleasedDecision{}}
}

func (o *v2CrashOracle) violate(format string, args ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.violations = append(o.violations, fmt.Sprintf(format, args...))
}

// commit records a terminal result the store accepted. I1 (SPEC-v2 §7.5):
// a claim's terminal result never changes after commit.
func (o *v2CrashOracle) commit(claimID string, terminal, body []byte, recovered bool) {
	o.mu.Lock()
	first, ok := o.commits[claimID]
	if !ok {
		o.commits[claimID] = v2CrashCommit{terminal: bytes.Clone(terminal), body: bytes.Clone(body), recovered: recovered}
		o.commitOrder = append(o.commitOrder, claimID)
	}
	o.mu.Unlock()
	if ok && (!bytes.Equal(first.terminal, terminal) || !bytes.Equal(first.body, body)) {
		o.violate("I1: claim %s accepted a second, different terminal result", claimID)
	}
}

// v2CrashDiskStore is every reference-store interface the service uses.
type v2CrashDiskStore interface {
	ratify.ClaimStoreV2
	ratify.V2CommittedClaimStore
	ratify.V2ReleaseClaimStore
	ratify.V2ReceiptPublisher
	ratify.V2ReceiptCheckpoint
}

// v2CrashDisk wraps the reference store. Reads pass through; every durable
// write goes through the injector and is observed by the oracle.
type v2CrashDisk struct {
	inner  v2CrashDiskStore
	inj    *v2CrashInjector
	oracle *v2CrashOracle
}

func (d *v2CrashDisk) AuthoritativeTimeV2(ctx context.Context) (int64, error) {
	return d.inner.AuthoritativeTimeV2(ctx)
}

func (d *v2CrashDisk) ClaimV2(ctx context.Context, claim ratify.V2ChallengeClaim) (result ratify.V2ClaimResult, err error) {
	d.inj.write("claim", func() {
		result, err = d.inner.ClaimV2(ctx, claim)
		if err == nil && result.Disposition == ratify.V2ClaimCreated {
			d.oracle.mu.Lock()
			d.oracle.claimedAt[claim.ClaimID] = result.ClaimedAt
			d.oracle.mu.Unlock()
		}
	})
	return result, err
}

func (d *v2CrashDisk) RecordV2EvaluationProgress(ctx context.Context, claimID string, owner []byte, progress ratify.V2EvaluationProgress) (err error) {
	d.inj.write("progress", func() {
		if err = d.inner.RecordV2EvaluationProgress(ctx, claimID, owner, progress); err == nil {
			d.oracle.mu.Lock()
			d.oracle.progress[claimID] = progress
			d.oracle.mu.Unlock()
		}
	})
	return err
}

func (d *v2CrashDisk) FinalizeV2Claim(ctx context.Context, claimID string, owner, terminal, body []byte, allowValidUntil int64) (finalized bool, err error) {
	d.inj.write("finalize", func() {
		if finalized, err = d.inner.FinalizeV2Claim(ctx, claimID, owner, terminal, body, allowValidUntil); err == nil {
			d.oracle.commit(claimID, terminal, body, false)
		}
	})
	return finalized, err
}

func (d *v2CrashDisk) LoadV2InterruptedClaim(ctx context.Context, claimID string) (ratify.V2InterruptedClaim, error) {
	return d.inner.LoadV2InterruptedClaim(ctx, claimID)
}

func (d *v2CrashDisk) RecoverInterruptedV2Claim(ctx context.Context, claimID string, terminal, body []byte) (recovered bool, err error) {
	d.inj.write("recover", func() {
		if recovered, err = d.inner.RecoverInterruptedV2Claim(ctx, claimID, terminal, body); err == nil {
			d.oracle.commit(claimID, terminal, body, true)
		}
	})
	return recovered, err
}

func (d *v2CrashDisk) LoadV2CommittedClaim(ctx context.Context, claimID string) (ratify.V2CommittedClaim, error) {
	return d.inner.LoadV2CommittedClaim(ctx, claimID)
}

func (d *v2CrashDisk) LoadV2TerminalClaim(ctx context.Context, claimID string) (ratify.V2TerminalClaimRecord, error) {
	return d.inner.LoadV2TerminalClaim(ctx, claimID)
}

func (d *v2CrashDisk) RecordV2Release(ctx context.Context, record ratify.V2ReleaseRecord) (err error) {
	d.inj.write("release_record", func() { err = d.inner.RecordV2Release(ctx, record) })
	return err
}

func (d *v2CrashDisk) PublishV2Receipt(ctx context.Context, claimID string, body []byte) (wire []byte, err error) {
	d.inj.write("publish", func() {
		if wire, err = d.inner.PublishV2Receipt(ctx, claimID, body); err != nil {
			return
		}
		receipt, decodeErr := ratify.DecodeVerificationReceiptV2(wire)
		if decodeErr != nil {
			d.oracle.violate("I6: published receipt for %s does not decode: %v", claimID, decodeErr)
			return
		}
		d.oracle.mu.Lock()
		previous, seen := d.oracle.wires[receipt.Sequence]
		d.oracle.wires[receipt.Sequence] = bytes.Clone(wire)
		d.oracle.mu.Unlock()
		if seen && !bytes.Equal(previous, wire) {
			d.oracle.violate("I6: receipt-log sequence %d was published with two different receipts (fork)", receipt.Sequence)
		}
	})
	return wire, err
}

func (d *v2CrashDisk) AcknowledgeV2Receipt(ctx context.Context, logID string, sequence int64, previous, entry []byte) (ack ratify.V2CheckpointAcknowledgement, err error) {
	d.inj.write("acknowledge", func() { ack, err = d.inner.AcknowledgeV2Receipt(ctx, logID, sequence, previous, entry) })
	return ack, err
}

func (d *v2CrashDisk) GetV2Acknowledgement(ctx context.Context, logID string, sequence int64) (ratify.V2CheckpointAcknowledgement, error) {
	return d.inner.GetV2Acknowledgement(ctx, logID, sequence)
}

// v2CrashRateDisk is the wrapper over a store that admits max_rate inside
// finalization (SPEC-v2 §7.6), so the verifier sees the same capability.
type v2CrashRateDisk struct{ *v2CrashDisk }

func (*v2CrashRateDisk) AdmitsV2RateAtFinalization() {}

func (d *v2CrashRateDisk) ReserveV2RateBatch(ctx context.Context, claimID string, owner []byte, bundleHash string, batch []ratify.V2RateReservation) (err error) {
	d.inj.write("rate_reserve", func() {
		err = d.inner.(ratify.V2RateReservationStore).ReserveV2RateBatch(ctx, claimID, owner, bundleHash, batch)
	})
	return err
}

// v2CrashJournal wraps the status security journal (SPEC-v2 §7.10); its
// compare-and-swap is a durable write.
type v2CrashJournal struct {
	inner ratify.SecurityJournalStoreV2
	inj   *v2CrashInjector
}

func (j *v2CrashJournal) Load(ctx context.Context) (ratify.SecurityJournalV2, ratify.SecurityJournalHeadV2, error) {
	return j.inner.Load(ctx)
}

func (j *v2CrashJournal) CompareAndSwap(ctx context.Context, head ratify.SecurityJournalHeadV2, next ratify.SecurityJournalV2) (err error) {
	j.inj.write("journal_cas", func() { err = j.inner.CompareAndSwap(ctx, head, next) })
	return err
}

// v2CrashPresentation is one presentation the service handles. Its request
// and callbacks are configuration; its status journal is durable.
type v2CrashPresentation struct {
	name    string
	claimID string
	req     ratify.V2VerifyRequest
	cb      ratify.V2VerifyCallbacks
}

// v2CrashCallerJournal is the service's handoff journal for the journaled
// restart model: an entry is written only after the call that produced it
// returned.
type v2CrashCallerJournal struct {
	handoff map[string]*ratify.CommittedV2Outcome
	wire    map[string][]byte
}

func newV2CrashCallerJournal() *v2CrashCallerJournal {
	return &v2CrashCallerJournal{handoff: map[string]*ratify.CommittedV2Outcome{}, wire: map[string][]byte{}}
}

// v2CrashWorld is the durable world for one run: the store, its wrapper, the
// presentations, and the oracle.
type v2CrashWorld struct {
	store         *v2reference.Store
	disk          *v2CrashDisk
	claimStore    ratify.ClaimStoreV2
	inj           *v2CrashInjector
	oracle        *v2CrashOracle
	presentations []*v2CrashPresentation
	config        ratify.V2ReleaseConfig
	logID         string
	lease         int64
	rateLimit     int64
	notes         []string
	// cancelDuringStatus makes the first status lookup cancel the verify
	// call (an evaluation that recorded progress and is then interrupted).
	cancelDuringStatus bool
	statusCancelled    bool
	cancelVerify       context.CancelFunc
}

// v2CrashFixture is the shared lifecycle fixture.
type v2CrashFixture struct {
	fx       v2Fixture
	verifier string
	logID    string
	lease    int64
	bundles  map[string]string
	requests map[string]v2LifecycleRequest
}

func loadV2CrashFixture(t *testing.T) v2CrashFixture {
	t.Helper()
	_, fx := loadV2Keys(t)
	var f struct {
		VerifierKey      string                        `json:"verifier_key"`
		LogID            string                        `json:"log_id"`
		LeaseSeconds     int64                         `json:"lease_seconds"`
		Bundles          map[string]string             `json:"bundles_b64"`
		Requests         map[string]v2LifecycleRequest `json:"requests"`
		Version          json.RawMessage               `json:"version"`
		Description      json.RawMessage               `json:"description"`
		Semantics        json.RawMessage               `json:"semantics"`
		Scenarios        json.RawMessage               `json:"scenarios"`
		ProfileScenarios json.RawMessage               `json:"profile_scenarios"`
	}
	loadV2Vector(t, "lifecycle-scenarios.json", &f)
	return v2CrashFixture{fx: fx, verifier: f.VerifierKey, logID: f.LogID, lease: f.LeaseSeconds, bundles: f.Bundles, requests: f.Requests}
}

// v2CrashFlow names a flow and the lifecycle requests it presents in order.
type v2CrashFlow struct {
	name               string
	requests           []string
	untrusted          bool // the trust provider answers untrusted: deny
	rateAtFinalization bool
	cancelDuringStatus bool
	// want is the terminal decision/reason of each presentation without a crash.
	want []string
}

func v2CrashFlows() []v2CrashFlow {
	return []v2CrashFlow{
		{name: "allow_then_release", requests: []string{"A", "B"}, want: []string{"allow/authorized", "allow/authorized"}},
		{name: "deny_then_release", requests: []string{"A"}, untrusted: true, want: []string{"deny/unauthorized"}},
		{name: "progress_then_interrupted", requests: []string{"A"}, cancelDuringStatus: true, want: []string{"indeterminate/evaluation_interrupted"}},
		{name: "rate_limited_batch_allow", requests: []string{"R1", "R2", "R3"}, rateAtFinalization: true,
			want: []string{"allow/authorized", "allow/authorized", "deny/constraint_denied"}},
		{name: "stream_advance", requests: []string{"S1", "S2"}, want: []string{"allow/authorized", "allow/authorized"}},
	}
}

func newV2CrashWorld(t *testing.T, fixture v2CrashFixture, flow v2CrashFlow) *v2CrashWorld {
	t.Helper()
	start := fixture.requests[flow.requests[0]].Now
	store, err := v2reference.NewStore(start, fixture.lease, fixture.logID, fixture.fx.priv[fixture.verifier])
	if err != nil {
		t.Fatal(err)
	}
	// The service drives acknowledgement itself, so a checkpoint submission is
	// its own durable write (SPEC-v2 §7.8).
	store.SetAcknowledgementWithheld(true)
	w := &v2CrashWorld{store: store, inj: &v2CrashInjector{}, oracle: newV2CrashOracle(), logID: fixture.logID, lease: fixture.lease,
		rateLimit: 2, cancelDuringStatus: flow.cancelDuringStatus}
	var inner v2CrashDiskStore = store
	if flow.rateAtFinalization {
		inner = store.WithRateAtFinalization()
	}
	w.disk = &v2CrashDisk{inner: inner, inj: w.inj, oracle: w.oracle}
	w.claimStore = w.disk
	if flow.rateAtFinalization {
		w.claimStore = &v2CrashRateDisk{w.disk}
	}
	w.config = ratify.V2ReleaseConfig{VerifierPublicKey: fixture.fx.pub[fixture.verifier], LogID: fixture.logID, ClaimStore: w.disk, Checkpoint: w.disk}
	for _, name := range flow.requests {
		request := fixture.requests[name]
		inputs := request.v2OrderingInputs
		if flow.untrusted {
			trust := *inputs.Trust
			trust.Outcome = string(ratify.V2TrustUntrusted)
			inputs.Trust = &trust
		}
		req, cb, _ := v2BuildVerifyRequest(t, inputs, unb64(t, fixture.bundles[request.Bundle]), &v2Counts{})
		cb.ClaimStore = w.claimStore
		if flow.rateAtFinalization {
			cb.Rate = w.claimStore.(ratify.V2RateReservationStore)
		}
		if cb.StatusJournal != nil {
			cb.StatusJournal = &v2CrashJournal{inner: cb.StatusJournal, inj: w.inj}
		}
		provider := cb.StatusEvidence
		cb.StatusEvidence = func(ctx context.Context, r ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
			if w.cancelDuringStatus && !w.statusCancelled {
				w.statusCancelled = true
				w.cancelVerify()
				return ratify.V2StatusEvidenceBatch{}, ctx.Err()
			}
			return provider(ctx, r)
		}
		claimID, err := ratify.ProtocolClaimIDV2(req.VerifierNamespace, req.ReplayEpoch, req.Expected.Value)
		if err != nil {
			t.Fatal(err)
		}
		w.presentations = append(w.presentations, &v2CrashPresentation{name: name, claimID: claimID, req: req, cb: cb})
	}
	return w
}

func (w *v2CrashWorld) note(format string, args ...any) {
	w.notes = append(w.notes, fmt.Sprintf(format, args...))
}

// runProcess runs one service process to completion or to its injected
// death, and reports whether it died.
func (w *v2CrashWorld) runProcess(journal *v2CrashCallerJournal) (died bool) {
	done := make(chan bool)
	go func() {
		completed := false
		defer func() { done <- completed }()
		w.serve(journal)
		completed = true
	}()
	return !<-done
}

// serve is the service: for each presentation in order it obtains the
// committed handoff (verify, or recovery for an in-progress or interrupted
// claim), publishes the receipt, submits it to the checkpoint, and releases.
func (w *v2CrashWorld) serve(journal *v2CrashCallerJournal) {
	ctx := context.Background()
	for _, p := range w.presentations {
		handoff := journal.handoff[p.name]
		if handoff == nil {
			p.req.Now = w.store.Now()
			w.oracle.mu.Lock()
			_, existed := w.oracle.claimedAt[p.claimID]
			w.oracle.mu.Unlock()
			vctx, cancel := context.WithCancel(ctx)
			w.cancelVerify = cancel
			outcome, _ := ratify.VerifyProofBundleV2(vctx, p.req, p.cb)
			cancel()
			switch {
			case outcome.Stage == ratify.V2StageCommitted:
				// I3 (SPEC-v2 §7.3, §7.5): a presentation whose claim already
				// exists never starts a second evaluation.
				if existed {
					w.oracle.violate("I3: retry of %s committed a second evaluation of an existing claim", p.name)
				}
				handoff = outcome.Committed
			case outcome.Stage == ratify.V2StageEvaluating, outcome.Stage == ratify.V2StageReplay && outcome.Disposition == ratify.V2ClaimInProgress:
				handoff = w.recoverAfterLease(ctx, p)
			case outcome.Stage == ratify.V2StageReplay && outcome.Disposition == ratify.V2ClaimTerminalReplay:
				// SPEC-v2 §7.11: resume the committed work from the store's
				// persisted record; the presentation retry discloses nothing.
				resumed, err := ratify.ResumeCommittedClaimV2(ctx, w.disk, p.claimID)
				if err != nil {
					w.note("%s: terminal replay with no resumable handoff (%s)", p.name, ratify.V2ErrorClassOf(err))
					continue
				}
				handoff = resumed
			default:
				w.note("%s: verify stopped at %s/%s", p.name, outcome.Stage, outcome.ErrorClass)
				continue
			}
			if handoff == nil {
				continue
			}
			journal.handoff[p.name] = handoff
		}
		wire := journal.wire[p.name]
		if wire == nil {
			var err error
			if wire, err = w.disk.PublishV2Receipt(ctx, handoff.ClaimID(), handoff.ReceiptBody()); err != nil {
				w.note("%s: publish: %v", p.name, err)
				continue
			}
			journal.wire[p.name] = wire
		}
		receipt, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil {
			w.oracle.violate("I6: %s: published receipt does not decode: %v", p.name, err)
			continue
		}
		entry, err := ratify.VerificationReceiptV2Digest(receipt)
		if err != nil {
			w.oracle.violate("I6: %s: receipt digest: %v", p.name, err)
			continue
		}
		if _, err := w.disk.AcknowledgeV2Receipt(ctx, receipt.LogID, receipt.Sequence, receipt.PreviousReceiptHash, entry); err != nil {
			w.note("%s: acknowledge: %v", p.name, err)
		}
		result := ratify.ReleaseV2Decision(ctx, handoff, wire, w.config)
		if result.Status == ratify.V2ReleaseReleased {
			w.oracle.mu.Lock()
			w.oracle.released[p.claimID] = append(w.oracle.released[p.claimID], result.Decision)
			w.oracle.mu.Unlock()
		} else {
			w.note("%s: release %s/%s", p.name, result.Status, result.Reason)
		}
	}
}

// recoverAfterLease runs lease-expiry recovery, waiting out a live lease.
func (w *v2CrashWorld) recoverAfterLease(ctx context.Context, p *v2CrashPresentation) *ratify.CommittedV2Outcome {
	committed, err := ratify.RecoverInterruptedClaimV2(ctx, w.claimStore, p.claimID)
	if ratify.V2ErrorClassOf(err) == ratify.V2ErrClaimLeaseLive {
		w.store.SetTime(w.store.Now() + w.lease)
		committed, err = ratify.RecoverInterruptedClaimV2(ctx, w.claimStore, p.claimID)
	}
	if err != nil {
		w.note("%s: recovery: %v", p.name, err)
		return nil
	}
	return committed
}

// v2CrashRun is the result of one crash point: the world after the crash,
// restart and retry, and what was durable at the moment of death.
type v2CrashRun struct {
	world *v2CrashWorld
	died  bool
	// evaluatingAtCrash are the claims that existed with no terminal result
	// when the process died.
	evaluatingAtCrash []string
}

// runV2CrashPoint runs the flow once with a crash armed at write n (mode
// none: no crash), then restarts per the model and reruns the service.
func runV2CrashPoint(t *testing.T, fixture v2CrashFixture, flow v2CrashFlow, n int, mode v2CrashMode, journaled bool) v2CrashRun {
	t.Helper()
	w := newV2CrashWorld(t, fixture, flow)
	w.inj.crashAt, w.inj.mode = n, mode
	journal := newV2CrashCallerJournal()
	run := v2CrashRun{world: w}
	run.died = w.runProcess(journal)
	if mode != v2CrashNone && !run.died {
		t.Fatalf("crash at write %d (%s) was armed but the process completed (%d writes)", n, mode, len(w.inj.ops))
	}
	if !run.died {
		return run
	}
	// What was durable at the moment of death.
	w.oracle.mu.Lock()
	for _, p := range w.presentations {
		if _, claimed := w.oracle.claimedAt[p.claimID]; !claimed {
			continue
		}
		if _, terminal := w.oracle.commits[p.claimID]; !terminal {
			run.evaluatingAtCrash = append(run.evaluatingAtCrash, p.claimID)
		}
	}
	w.oracle.mu.Unlock()
	ctx := context.Background()
	// I5 (SPEC-v2 §7.5): while the dead evaluator's lease is live, recovery is
	// refused and commits nothing.
	for _, claimID := range run.evaluatingAtCrash {
		w.oracle.mu.Lock()
		claimedAt := w.oracle.claimedAt[claimID]
		w.oracle.mu.Unlock()
		if w.store.Now() >= claimedAt+w.lease {
			continue
		}
		if _, err := ratify.RecoverInterruptedClaimV2(ctx, w.store, claimID); ratify.V2ErrorClassOf(err) != ratify.V2ErrClaimLeaseLive {
			w.oracle.violate("I5: recovery of %s during the live lease returned %v, want claim_lease_live", claimID, err)
		}
	}
	// Restart: fresh process state, the clock past every lease, and the
	// same presentations retried.
	if !journaled {
		journal = newV2CrashCallerJournal()
	}
	w.store.SetTime(w.store.Now() + w.lease)
	if w.runProcess(journal) {
		t.Fatal("restarted process died with no crash armed")
	}
	return run
}

// checkV2CrashInvariants checks I1 to I6 after the restarted service ran,
// and liveness where the restart model can complete the work.
func checkV2CrashInvariants(t *testing.T, flow v2CrashFlow, run v2CrashRun) {
	t.Helper()
	w, o := run.world, run.world.oracle
	ctx := context.Background()
	for _, v := range o.violations {
		t.Error(v)
	}
	decisionOf := func(claimID string) string {
		c, ok := o.commits[claimID]
		if !ok {
			return ""
		}
		r := c.receipt(t)
		return r.Decision + "/" + r.DecisionReason
	}

	// I1 (SPEC-v2 §7.3, §7.5): the store holds exactly the first committed
	// terminal result for each claim; an allow and only an allow carries a
	// horizon.
	for claimID, c := range o.commits {
		record, err := w.store.LoadV2TerminalClaim(ctx, claimID)
		if err != nil || !record.Terminal || record.ReceiptOutboxDigest != ratify.ReceiptOutboxDigestV2(c.body) {
			t.Errorf("I1: claim %s holds %+v (%v), want the first committed body", claimID, record, err)
		}
		if (record.AllowHorizon > 0) != (c.receipt(t).Decision == "allow") {
			t.Errorf("I1: claim %s allow horizon %d for decision %s", claimID, record.AllowHorizon, c.receipt(t).Decision)
		}
	}

	// I5 (SPEC-v2 §6.7, §7.5, §7.11): no claim is stranded in progress, and a
	// claim whose evaluator died before commit ends as evaluation_interrupted
	// built from its last recorded progress, never as an allow.
	for claimID := range o.claimedAt {
		if _, ok := o.commits[claimID]; !ok {
			t.Errorf("I5: claim %s is still evaluating after restart and lease-expiry recovery", claimID)
		}
	}
	for _, claimID := range run.evaluatingAtCrash {
		c, ok := o.commits[claimID]
		if !ok {
			continue
		}
		if got := decisionOf(claimID); got != "indeterminate/evaluation_interrupted" || !c.recovered {
			t.Errorf("I5: claim %s whose evaluator died before commit ended as %s (recovered %t)", claimID, got, c.recovered)
			continue
		}
		body, progress := c.receipt(t), o.progress[claimID]
		if progress.TrustAssessment == "" {
			progress = ratify.InitialV2EvaluationProgress()
		}
		if body.TrustAssessment != progress.TrustAssessment || body.StatusAssessment != progress.StatusAssessment || body.ContextAssessment != progress.ContextAssessment {
			t.Errorf("I5: claim %s interrupted receipt %s/%s/%s differs from its last recorded progress %+v",
				claimID, body.TrustAssessment, body.StatusAssessment, body.ContextAssessment, progress)
		}
	}

	// I2 (SPEC-v2 §6.9, §7.9): a released decision is the committed terminal
	// result, its receipt is the published, acknowledged entry for the sealed
	// body, the release is durably recorded, and every release of a claim
	// names the same decision and receipt.
	for claimID, decisions := range o.released {
		c, ok := o.commits[claimID]
		if !ok {
			t.Errorf("I2: claim %s released with no committed terminal result", claimID)
			continue
		}
		for _, d := range decisions {
			receipt, err := d.Receipt()
			if err != nil {
				t.Errorf("I2: claim %s released receipt: %v", claimID, err)
				continue
			}
			body, err := ratify.VerificationReceiptV2Body(receipt)
			if err != nil || !bytes.Equal(body, c.body) || d.Decision()+"/"+d.Reason() != decisionOf(claimID) {
				t.Errorf("I2: claim %s released %s/%s, committed %s", claimID, d.Decision(), d.Reason(), decisionOf(claimID))
			}
			entry, _ := ratify.VerificationReceiptV2Digest(receipt)
			ack, err := w.store.GetV2Acknowledgement(ctx, receipt.LogID, receipt.Sequence)
			if err != nil || !bytes.Equal(ack.EntryHash, entry) || ack.Timestamp != d.ReleaseTime() {
				t.Errorf("I2: claim %s released without the checkpoint acknowledgement of its entry: %+v (%v)", claimID, ack, err)
			}
			if !bytes.Equal(d.ReceiptWire(), decisions[0].ReceiptWire()) || d.Decision() != decisions[0].Decision() {
				t.Errorf("I2: claim %s released with two different outcomes", claimID)
			}
		}
		record, err := w.store.LoadV2TerminalClaim(ctx, claimID)
		if err != nil || record.Release == nil || record.Release.Outcome != ratify.V2ReleaseReleased {
			t.Errorf("I2: claim %s released but the store records %+v (%v)", claimID, record.Release, err)
		}
	}

	// I3 (SPEC-v2 §7.3): at most one allow per claim, and a retried
	// presentation never adds a claim. (Second evaluations are recorded
	// during serve.)
	if len(o.claimedAt) > len(w.presentations) {
		t.Errorf("I3: %d claims for %d presentations", len(o.claimedAt), len(w.presentations))
	}

	// I4 (SPEC-v2 §7.6): in commit order, an allow is admitted only below the
	// limit and a rate denial only at it, so each committed allow is counted
	// exactly once, including across a restart and retry.
	if flow.rateAtFinalization {
		allows := int64(0)
		for _, claimID := range o.commitOrder {
			switch decisionOf(claimID) {
			case "allow/authorized":
				if allows >= w.rateLimit {
					t.Errorf("I4: claim %s admitted with %d allows already counted (limit %d)", claimID, allows, w.rateLimit)
				}
				allows++
			case "deny/constraint_denied":
				if allows < w.rateLimit {
					t.Errorf("I4: claim %s rate-denied with only %d allows committed (limit %d): an allow was counted twice", claimID, allows, w.rateLimit)
				}
			}
		}
	}

	// I6 (SPEC-v2 §7.7, §7.8): the appended log is a gap-free, linked
	// prefix with one receipt per sequence, and acknowledgements are an
	// in-order prefix of it naming the appended entries.
	length := int64(w.store.LogLength())
	previous := make([]byte, 48)
	acked, lastAck := true, int64(0)
	for seq := int64(1); seq <= length; seq++ {
		wire, ok := o.wires[seq]
		if !ok {
			t.Errorf("I6: appended sequence %d was never returned by a publication", seq)
			break
		}
		receipt, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil || receipt.Sequence != seq || receipt.LogID != w.logID || !bytes.Equal(receipt.PreviousReceiptHash, previous) {
			t.Errorf("I6: sequence %d is not linked to its predecessor", seq)
			break
		}
		entry, _ := ratify.VerificationReceiptV2Digest(receipt)
		ack, err := w.store.GetV2Acknowledgement(ctx, w.logID, seq)
		switch {
		case err == nil && !acked:
			t.Errorf("I6: sequence %d acknowledged after an unacknowledged predecessor", seq)
		case err == nil && (!bytes.Equal(ack.EntryHash, entry) || ack.Timestamp < lastAck):
			t.Errorf("I6: acknowledgement of sequence %d names another entry or goes back in time", seq)
		case err == nil:
			lastAck = ack.Timestamp
		default:
			acked = false
		}
		previous = entry
	}
	for seq := range o.wires {
		if seq > length {
			t.Errorf("I6: a publication returned sequence %d beyond the appended log of %d", seq, length)
		}
	}

	// Liveness (SPEC-v2 §7.11): every presentation reaches its expected
	// terminal result and is released, including a committed result whose
	// handoff died with the process.
	allows := int64(0)
	for i, p := range w.presentations {
		if len(o.released[p.claimID]) == 0 {
			t.Errorf("liveness: %s was never released; service notes: %s", p.name, strings.Join(w.notes, "; "))
			continue
		}
		want := flow.want[i]
		if flow.rateAtFinalization {
			// An interrupted allow counts nothing, so a later request may be
			// admitted in its place.
			want = "deny/constraint_denied"
			if allows < w.rateLimit {
				want = "allow/authorized"
			}
		}
		if slices.Contains(run.evaluatingAtCrash, p.claimID) {
			want = "indeterminate/evaluation_interrupted"
		}
		got := decisionOf(p.claimID)
		if got == "allow/authorized" {
			allows++
		}
		if got != want {
			t.Errorf("liveness: %s ended as %s, want %s", p.name, got, want)
		}
	}
}

// Every durable write of every flow, crashed before and after it reaches the
// store, under both restart models, must keep I1 to I6.
func TestV2CrashInjectionPreservesInvariants(t *testing.T) {
	fixture := loadV2CrashFixture(t)
	flows := v2CrashFlows()
	if v2RaceDetector {
		// Each crash point runs one process at a time, so the race detector
		// adds cost but no coverage; the full sweep runs without it.
		flows = flows[:1]
	}
	for _, flow := range flows {
		t.Run(flow.name, func(t *testing.T) {
			// Discover the durable-write sequence with a counting-only run.
			baseline := runV2CrashPoint(t, fixture, flow, 0, v2CrashNone, false)
			checkV2CrashInvariants(t, flow, baseline)
			ops := slices.Clone(baseline.world.inj.ops)
			if len(ops) == 0 {
				t.Fatal("the flow made no durable writes")
			}
			t.Logf("%d durable writes: %s", len(ops), strings.Join(ops, ","))
			for _, journaled := range []bool{false, true} {
				model := map[bool]string{false: "volatile", true: "journaled"}[journaled]
				for _, mode := range []v2CrashMode{v2CrashBefore, v2CrashAfter} {
					for n := 1; n <= len(ops); n++ {
						t.Run(fmt.Sprintf("%s/%s/%02d_%s", model, mode, n, ops[n-1]), func(t *testing.T) {
							checkV2CrashInvariants(t, flow, runV2CrashPoint(t, fixture, flow, n, mode, journaled))
						})
					}
				}
			}
		})
	}
}
