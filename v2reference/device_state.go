package v2reference

// Complete security state of a single-device offline primary (SPEC-v2
// §7.13), TEST ONLY.
//
// DevicePrimaryTestOnly groups every durable security record the primary
// holds: the claim store with its stream sequences, rate counters and
// receipt log (Store), its anchored SecurityJournalV2 store, its challenge
// issuance records, and its replay epoch. Its complete-state digest is a
// labelled SHA-384 over a versioned canonical projection of all of them.
// Once bound to a device component, every durable change in any of these
// stores is anchored in the component before it takes effect; a change the
// component refuses is undone.

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// deviceStateLabel is the domain label of the complete-state digest.
const deviceStateLabel = "ratify/device-complete-state/v2"

// deviceStateVersion is the projection version.
const deviceStateVersion = 1

// storeStateTestOnly holds the member digests of a Store's durable state.
type storeStateTestOnly struct {
	claims, streams, rateCounters, receiptLog string
}

func sha384Hex(b []byte) string {
	sum := sha512.Sum384(b)
	return hex.EncodeToString(sum[:])
}

// memberDigest is lowercase hex SHA-384 of the canonical JSON of v.
func memberDigest(v any) (string, error) {
	body, err := ratify.CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return sha384Hex(body), nil
}

// recordDigest digests a record whose Go encoding is deterministic but whose
// members are not in canonical key order; it is embedded as one string.
func recordDigest(v any) (string, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return sha384Hex(body), nil
}

func optionalDigest(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return sha384Hex(b)
}

// Projection records. Struct members are declared in canonical key order.
type claimProjection struct {
	Abandoned         bool   `json:"abandoned"`
	AllowHorizon      int64  `json:"allow_horizon"`
	ClaimID           string `json:"claim_id"`
	ClaimSHA384       string `json:"claim_sha384"`
	ClaimedAt         int64  `json:"claimed_at"`
	FinalizedAt       int64  `json:"finalized_at"`
	LeaseExpiresAt    int64  `json:"lease_expires_at"`
	OutboxIndex       int    `json:"outbox_index"`
	OwnerDigest       string `json:"owner_digest"`
	ProgressSHA384    string `json:"progress_sha384"`
	ReceiptBodySHA384 string `json:"receipt_body_sha384"`
	State             string `json:"state"`
	TerminalSHA384    string `json:"terminal_sha384"`
}

type streamProjection struct {
	LastSeq int64  `json:"last_seq"`
	Stream  string `json:"stream"`
}

type rateProjection struct {
	CertID   string  `json:"cert_id"`
	Commits  []int64 `json:"commits"`
	IssuerID string  `json:"issuer_id"`
	WindowS  int64   `json:"window_s"`
}

type receiptEntryProjection struct {
	BodySHA384 string `json:"body_sha384"`
	ClaimID    string `json:"claim_id"`
	EntryHash  string `json:"entry_hash"`
	Sequence   int    `json:"sequence"`
}

type receiptLogProjection struct {
	Entries []receiptEntryProjection `json:"entries"`
	Frozen  bool                     `json:"frozen"`
	LogID   string                   `json:"log_id"`
}

type issuanceProjection struct {
	Key          string `json:"key"`
	RecordSHA384 string `json:"record_sha384"`
}

type journalProjection struct {
	Generation     uint64 `json:"generation"`
	SnapshotSHA384 string `json:"snapshot_sha384"`
}

type deviceStateProjection struct {
	Claims          string            `json:"claims"`
	IssuanceRecords string            `json:"issuance_records"`
	LogID           string            `json:"log_id"`
	RateCounters    string            `json:"rate_counters"`
	ReceiptLog      string            `json:"receipt_log"`
	ReplayEpoch     int64             `json:"replay_epoch"`
	SecurityJournal journalProjection `json:"security_journal"`
	Streams         string            `json:"streams"`
	Version         int               `json:"version"`
}

// stateDigestsLocked digests every durable security record of the store:
// claims in every state (evaluating, terminal, interrupted, abandoned) with
// their sealed values, stream sequences, rate counters, and the receipt log
// with its outbox. Checkpoint acknowledgements, release records (derived
// release state), and clock readings are excluded.
func (s *Store) stateDigestsLocked() (storeStateTestOnly, error) {
	var out storeStateTestOnly
	ids := make([]string, 0, len(s.claims))
	for id := range s.claims {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	claims := make([]claimProjection, 0, len(ids))
	for _, id := range ids {
		r := s.claims[id]
		claimDigest, err := recordDigest(r.claim)
		if err != nil {
			return out, err
		}
		progressDigest, err := recordDigest(r.progress)
		if err != nil {
			return out, err
		}
		claims = append(claims, claimProjection{
			Abandoned: r.abandoned, AllowHorizon: r.allowHorizon, ClaimID: id, ClaimSHA384: claimDigest, ClaimedAt: r.claimedAt,
			FinalizedAt: r.finalizedAt, LeaseExpiresAt: r.leaseExpiresAt, OutboxIndex: r.outboxIndex, OwnerDigest: hex.EncodeToString(r.ownerDigest[:]),
			ProgressSHA384: progressDigest, ReceiptBodySHA384: optionalDigest(r.receiptBody), State: string(r.state), TerminalSHA384: optionalDigest(r.terminal),
		})
	}
	streams := make([]streamProjection, 0, len(s.streams))
	for key, seq := range s.streams {
		streams = append(streams, streamProjection{LastSeq: seq, Stream: key})
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].Stream < streams[j].Stream })
	rates := make([]rateProjection, 0, len(s.rateCommits))
	for key, commits := range s.rateCommits {
		rates = append(rates, rateProjection{CertID: key.certID, Commits: slices.Clone(commits), IssuerID: key.issuerID, WindowS: key.windowS})
	}
	sort.Slice(rates, func(i, j int) bool {
		a, b := rates[i], rates[j]
		if c := strings.Compare(a.IssuerID, b.IssuerID); c != 0 {
			return c < 0
		}
		if c := strings.Compare(a.CertID, b.CertID); c != 0 {
			return c < 0
		}
		return a.WindowS < b.WindowS
	})
	log := receiptLogProjection{Entries: make([]receiptEntryProjection, 0, len(s.outbox)), Frozen: s.logFrozen, LogID: s.logID}
	for i, entry := range s.outbox {
		log.Entries = append(log.Entries, receiptEntryProjection{BodySHA384: optionalDigest(entry.body), ClaimID: entry.claimID, EntryHash: hex.EncodeToString(entry.digest), Sequence: i + 1})
	}
	var err error
	if out.claims, err = memberDigest(claims); err != nil {
		return out, err
	}
	if out.streams, err = memberDigest(streams); err != nil {
		return out, err
	}
	if out.rateCounters, err = memberDigest(rates); err != nil {
		return out, err
	}
	out.receiptLog, err = memberDigest(log)
	return out, err
}

func (s *Store) stateDigests() (storeStateTestOnly, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateDigestsLocked()
}

// DevicePrimaryTestOnly is the primary of the single-device offline profile.
// Lock order: a sub-store's own lock, then the primary's anchor lock, then
// the journal or issuance store lock and the component lock.
type DevicePrimaryTestOnly struct {
	Store    *Store
	Journal  *DeviceJournalTestOnly
	Issuance *DeviceIssuanceTestOnly

	replayEpoch int64
	mu          sync.Mutex // serializes anchoring across the sub-stores
	component   *DeviceComponentTestOnly
	lastStore   storeStateTestOnly
}

// NewDevicePrimaryTestOnly wraps store with an empty anchored journal store
// and an empty issuance store, serving replayEpoch.
func NewDevicePrimaryTestOnly(store *Store, replayEpoch int64) (*DevicePrimaryTestOnly, error) {
	if store == nil || replayEpoch < 0 {
		return nil, fmt.Errorf("v2reference: device primary needs a store and a non-negative replay epoch")
	}
	journal, err := NewJournalStore()
	if err != nil {
		return nil, err
	}
	p := &DevicePrimaryTestOnly{Store: store, replayEpoch: replayEpoch}
	p.Journal = &DeviceJournalTestOnly{primary: p, inner: journal}
	p.Issuance = &DeviceIssuanceTestOnly{primary: p, inner: NewTestOnlyChallengeIssuanceStore()}
	return p, nil
}

// Clone copies the complete primary state, modelling a backup or snapshot.
// The copy is not bound to any component.
func (p *DevicePrimaryTestOnly) Clone() *DevicePrimaryTestOnly {
	out := &DevicePrimaryTestOnly{Store: p.Store.Clone(), replayEpoch: p.replayEpoch}
	p.Journal.inner.mu.Lock()
	journal := &JournalStore{head: p.Journal.inner.head, snapshot: bytes.Clone(p.Journal.inner.snapshot)}
	p.Journal.inner.mu.Unlock()
	p.Issuance.inner.mu.Lock()
	issuance := NewTestOnlyChallengeIssuanceStore()
	for key, record := range p.Issuance.inner.records {
		issuance.records[key] = cloneExpected(record)
	}
	p.Issuance.inner.mu.Unlock()
	out.Journal = &DeviceJournalTestOnly{primary: out, inner: journal}
	out.Issuance = &DeviceIssuanceTestOnly{primary: out, inner: issuance}
	return out
}

// bind attaches the component and anchors every later durable change in it.
func (p *DevicePrimaryTestOnly) bind(component *DeviceComponentTestOnly) error {
	current, err := p.Store.stateDigests()
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.component, p.lastStore = component, current
	p.mu.Unlock()
	p.Store.mu.Lock()
	p.Store.anchor = p.anchorStore
	p.Store.mu.Unlock()
	return nil
}

// anchorStore is the Store hook; it runs with the store lock held.
func (p *DevicePrimaryTestOnly) anchorStore(previous, next storeStateTestOnly) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	before, err := p.composeLocked(previous)
	if err != nil {
		return err
	}
	after, err := p.composeLocked(next)
	if err != nil {
		return err
	}
	if err := p.component.AnchorState(before, after); err != nil {
		return err
	}
	p.lastStore = next
	return nil
}

// composeLocked returns the complete-state digest for the given store
// member digests and the current journal and issuance records.
func (p *DevicePrimaryTestOnly) composeLocked(store storeStateTestOnly) ([]byte, error) {
	journal := p.Journal.inner
	journal.mu.Lock()
	journalMember := journalProjection{Generation: journal.head.Generation, SnapshotSHA384: sha384Hex(journal.snapshot)}
	journal.mu.Unlock()
	issuance := p.Issuance.inner
	issuance.mu.Lock()
	records := make([]issuanceProjection, 0, len(issuance.records))
	for key, record := range issuance.records {
		digest, err := recordDigest(record)
		if err != nil {
			issuance.mu.Unlock()
			return nil, err
		}
		records = append(records, issuanceProjection{Key: key, RecordSHA384: digest})
	}
	issuance.mu.Unlock()
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })
	issuanceMember, err := memberDigest(records)
	if err != nil {
		return nil, err
	}
	body, err := ratify.CanonicalJSON(deviceStateProjection{
		Claims: store.claims, IssuanceRecords: issuanceMember, LogID: p.Store.logID, RateCounters: store.rateCounters, ReceiptLog: store.receiptLog,
		ReplayEpoch: p.replayEpoch, SecurityJournal: journalMember, Streams: store.streams, Version: deviceStateVersion,
	})
	if err != nil {
		return nil, err
	}
	h := sha512.New384()
	h.Write([]byte(deviceStateLabel))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil), nil
}

// CompleteStateDigestTestOnly recomputes the complete-state digest from the
// primary's current records.
func (p *DevicePrimaryTestOnly) CompleteStateDigestTestOnly() ([]byte, error) {
	current, err := p.Store.stateDigests()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.composeLocked(current)
}

// anchoredDigest is the digest of the last anchored state.
func (p *DevicePrimaryTestOnly) anchoredDigest() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.composeLocked(p.lastStore)
}

// changeOther applies a journal or issuance change: with a bound
// component, the change is anchored before it takes effect and undone if
// the component refuses it. apply's own error is returned when anchoring
// succeeds or nothing changed.
func (p *DevicePrimaryTestOnly) changeOther(apply func() error, undo func()) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.component == nil {
		return apply()
	}
	before, err := p.composeLocked(p.lastStore)
	if err != nil {
		return err
	}
	applyErr := apply()
	after, err := p.composeLocked(p.lastStore)
	if err == nil && !bytes.Equal(before, after) {
		err = p.component.AnchorState(before, after)
	}
	if err != nil {
		undo()
		return &ratify.V2Error{Class: ratify.V2ErrClaimStoreUnavailable, Err: fmt.Errorf("v2reference: durable state change was not anchored: %w", err)}
	}
	return applyErr
}

// DeviceJournalTestOnly is the primary's anchored SecurityJournalV2 store.
type DeviceJournalTestOnly struct {
	primary *DevicePrimaryTestOnly
	inner   *JournalStore
}

// Load implements ratify.SecurityJournalStoreV2.
func (j *DeviceJournalTestOnly) Load(ctx context.Context) (ratify.SecurityJournalV2, ratify.SecurityJournalHeadV2, error) {
	return j.inner.Load(ctx)
}

// CompareAndSwap implements ratify.SecurityJournalStoreV2; the new journal
// state is anchored with the rest of the primary's state.
func (j *DeviceJournalTestOnly) CompareAndSwap(ctx context.Context, expected ratify.SecurityJournalHeadV2, next ratify.SecurityJournalV2) error {
	j.inner.mu.Lock()
	head, snapshot := j.inner.head, j.inner.snapshot
	j.inner.mu.Unlock()
	return j.primary.changeOther(func() error { return j.inner.CompareAndSwap(ctx, expected, next) }, func() {
		j.inner.mu.Lock()
		j.inner.head, j.inner.snapshot = head, snapshot
		j.inner.mu.Unlock()
	})
}

// Head returns the journal's anchored head.
func (j *DeviceJournalTestOnly) Head() ratify.SecurityJournalHeadV2 { return j.inner.Head() }

// DeviceIssuanceTestOnly is the primary's challenge issuance store.
type DeviceIssuanceTestOnly struct {
	primary *DevicePrimaryTestOnly
	inner   *TestOnlyChallengeIssuanceStore
}

// PersistV2Challenge implements ratify.V2ChallengeIssuanceStore; the new
// record is anchored with the rest of the primary's state.
func (i *DeviceIssuanceTestOnly) PersistV2Challenge(ctx context.Context, record ratify.ExpectedChallengeV2) error {
	i.inner.mu.Lock()
	saved := make(map[string]ratify.ExpectedChallengeV2, len(i.inner.records))
	for key, value := range i.inner.records {
		saved[key] = value
	}
	i.inner.mu.Unlock()
	return i.primary.changeOther(func() error { return i.inner.PersistV2Challenge(ctx, record) }, func() {
		i.inner.mu.Lock()
		i.inner.records = saved
		i.inner.mu.Unlock()
	})
}

// LoadV2Challenge implements ratify.V2ChallengeIssuanceStore.
func (i *DeviceIssuanceTestOnly) LoadV2Challenge(ctx context.Context, namespace string, epoch int64, digest []byte) (ratify.ExpectedChallengeV2, error) {
	return i.inner.LoadV2Challenge(ctx, namespace, epoch, digest)
}
