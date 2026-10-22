package v2reference

// Complete security state of a single-device offline primary (SPEC-v2
// §7.13), TEST ONLY.
//
// DevicePrimaryTestOnly groups every durable security record the primary
// holds: the claim store with its release records, stream sequences, rate
// counters and receipt log (Store), its anchored SecurityJournalV2 store, its challenge
// issuance records, and its replay epoch. Its complete-state digest is a
// labelled SHA-384 over a versioned canonical projection of all of them.
// Once bound to a device component, every durable change in any of these
// stores is anchored in the component before it takes effect; a change the
// component refuses is undone.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
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

// Projection values follow the normative record encodings of SPEC-v2 §7.13.
// Objects are maps, so RatifyCanonicalJSON orders their members by UTF-8
// byte order; every collection is sorted explicitly before encoding.
type object = map[string]any

// bytesOrNull is padded base64 of a stored byte string, or null when the
// store holds none.
func bytesOrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return base64.StdEncoding.EncodeToString(b)
}

// sha384OrNull is lowercase hex SHA-384 of exact stored bytes, or null when
// the store holds none.
func sha384OrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return sha384Hex(b)
}

func stringOrNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func sealedClaimProjection(c ratify.V2ChallengeClaim) object {
	evaluators := make([]any, 0, len(c.ConstraintEvaluators))
	for _, e := range c.ConstraintEvaluators {
		evaluators = append(evaluators, object{"profile_digest": e.ProfileDigest, "type": string(e.Type)})
	}
	rateBatch := make([]any, 0, len(c.RateBatch))
	for _, r := range c.RateBatch {
		rateBatch = append(rateBatch, object{"cert_id": r.CertID, "issuer_id": r.IssuerID, "limit": r.Limit, "window_s": r.WindowS})
	}
	var streamSeq any
	if c.StreamSeq != nil {
		streamSeq = *c.StreamSeq
	}
	return object{
		"agent_id": c.AgentID, "bundle_hash": c.BundleHash, "challenge_digest": c.ChallengeDigest, "claim_id": c.ClaimID,
		"clock_skew_seconds": c.ClockSkewSeconds, "constraint_evaluators": evaluators, "context_policy_digest": stringOrNull(c.ContextPolicyDigest),
		"expires_at": c.ExpiresAt, "issued_at": c.IssuedAt, "issuer_ids": append([]string{}, c.IssuerIDs...), "max_age_seconds": c.MaxAgeSeconds,
		"namespace": c.Namespace, "proof_digest": c.ProofDigest, "rate_batch": rateBatch, "replay_epoch": c.ReplayEpoch,
		"required_scope": c.RequiredScope, "requires_rate": c.RequiresRate, "stream_id": bytesOrNull(c.StreamID), "stream_seq": streamSeq,
		"verifier_id": c.VerifierID,
	}
}

func progressProjection(p ratify.V2EvaluationProgress) object {
	evidence := make([]any, 0, len(p.StatusEvidence))
	for _, e := range p.StatusEvidence {
		evidence = append(evidence, object{"digest": e.Digest, "issuer_id": e.IssuerID, "object_type_code": int64(e.ObjectType), "sequence": e.Sequence, "status_key_id": e.StatusKeyID})
	}
	var policyDigest any
	if p.ContextPolicyDigest != nil {
		policyDigest = *p.ContextPolicyDigest
	}
	return object{
		"context_assessment": p.ContextAssessment, "context_policy_digest": policyDigest, "status_assessment": p.StatusAssessment,
		"status_evidence_digests": evidence, "trust_assessment": p.TrustAssessment,
	}
}

func claimProjection(id string, r *claimRecord) object {
	var release, logSequence any
	if r.release != nil {
		release = object{"ack_timestamp": r.release.AckTimestamp, "claim_id": r.release.ClaimID, "entry_hash": base64.StdEncoding.EncodeToString(r.release.EntryHash)}
	}
	if r.outboxIndex >= 0 {
		logSequence = int64(r.outboxIndex) + 1
	}
	return object{
		"abandoned": r.abandoned, "allow_horizon": r.allowHorizon, "claim": sealedClaimProjection(r.claim), "claim_id": id,
		"claimed_at": r.claimedAt, "finalized_at": r.finalizedAt, "lease_expires_at": r.leaseExpiresAt, "log_sequence": logSequence,
		"owner_digest": base64.StdEncoding.EncodeToString(r.ownerDigest[:]), "progress": progressProjection(r.progress),
		"receipt_body_sha384": sha384OrNull(r.receiptBody), "release": release, "state": string(r.state), "terminal_sha384": sha384OrNull(r.terminal),
	}
}

func issuanceProjection(e ratify.ExpectedChallengeV2) object {
	var agentKey, policy any
	if e.ExpectedAgentPublicKey != nil {
		agentKey = object{"ed25519": base64.StdEncoding.EncodeToString(e.ExpectedAgentPublicKey.Ed25519), "ml_dsa_65": base64.StdEncoding.EncodeToString(e.ExpectedAgentPublicKey.MLDSA65)}
	}
	if e.ContextPolicy != nil {
		profile, requireBound, fields, context := e.ContextPolicy.Fields()
		policy = object{"expected_session_context": bytesOrNull(context), "profile": profile, "require_bound": requireBound, "required_fields": fields, "version": int64(1)}
	}
	return object{
		"context_policy": policy, "expected_agent_id": e.ExpectedAgentID, "expected_agent_pub_key": agentKey, "expected_receiver_id": e.ExpectedReceiverID,
		"expected_session_context": bytesOrNull(e.ExpectedSessionContext), "expires_at": e.ExpiresAt, "issued_at": e.IssuedAt,
		"replay_epoch": e.ReplayEpoch, "value": base64.StdEncoding.EncodeToString(e.Value), "verifier_id": e.VerifierID,
		"verifier_namespace": e.VerifierNamespace,
	}
}

// storeMembersLocked returns the RatifyCanonicalJSON of the claims, streams,
// rate_counters, and receipt_log members: every claim in every state
// (evaluating, terminal, interrupted, abandoned) with its sealed values and
// release record, every stream sequence, every rate counter, and the receipt
// log with its outbox. Checkpoint acknowledgements and clock readings are
// excluded.
func (s *Store) storeMembersLocked() (claims, streams, rateCounters, receiptLog []byte, err error) {
	ids := make([]string, 0, len(s.claims))
	for id := range s.claims {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	claimRecords := make([]any, 0, len(ids))
	for _, id := range ids {
		claimRecords = append(claimRecords, claimProjection(id, s.claims[id]))
	}
	keys := slices.Collect(maps.Keys(s.streams))
	slices.SortFunc(keys, func(a, b streamKeyV2) int {
		return cmp.Or(strings.Compare(a.namespace, b.namespace), strings.Compare(a.agentID, b.agentID), strings.Compare(a.streamID, b.streamID))
	})
	streamRecords := make([]any, 0, len(keys))
	for _, key := range keys {
		streamRecords = append(streamRecords, object{"agent_id": key.agentID, "last_sequence": s.streams[key], "namespace": key.namespace, "stream_id": base64.StdEncoding.EncodeToString([]byte(key.streamID))})
	}
	rateKeys := slices.Collect(maps.Keys(s.rateCommits))
	slices.SortFunc(rateKeys, func(a, b rateKey) int {
		return cmp.Or(strings.Compare(a.issuerID, b.issuerID), strings.Compare(a.certID, b.certID), cmp.Compare(a.windowS, b.windowS))
	})
	rateRecords := make([]any, 0, len(rateKeys))
	for _, key := range rateKeys {
		rateRecords = append(rateRecords, object{"cert_id": key.certID, "commits": append([]int64{}, s.rateCommits[key]...), "issuer_id": key.issuerID, "window_s": key.windowS})
	}
	entries := make([]any, 0, len(s.outbox))
	for i, entry := range s.outbox {
		entries = append(entries, object{"body_sha384": sha384Hex(entry.body), "claim_id": entry.claimID, "entry_hash": bytesOrNull(entry.digest), "sequence": int64(i) + 1})
	}
	if claims, err = ratify.CanonicalJSON(claimRecords); err != nil {
		return
	}
	if streams, err = ratify.CanonicalJSON(streamRecords); err != nil {
		return
	}
	if rateCounters, err = ratify.CanonicalJSON(rateRecords); err != nil {
		return
	}
	receiptLog, err = ratify.CanonicalJSON(object{"entries": entries, "frozen": s.logFrozen, "log_id": s.logID})
	return
}

// stateDigestsLocked digests the store members of the projection.
func (s *Store) stateDigestsLocked() (storeStateTestOnly, error) {
	claims, streams, rateCounters, receiptLog, err := s.storeMembersLocked()
	if err != nil {
		return storeStateTestOnly{}, err
	}
	return storeStateTestOnly{claims: sha384Hex(claims), streams: sha384Hex(streams), rateCounters: sha384Hex(rateCounters), receiptLog: sha384Hex(receiptLog)}, nil
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
	issuance, err := p.issuanceMemberLocked()
	if err != nil {
		return nil, err
	}
	body, err := p.projectionLocked(store, sha384Hex(issuance))
	if err != nil {
		return nil, err
	}
	return completeStateDigest(body), nil
}

// issuanceMemberLocked returns the RatifyCanonicalJSON of the
// issuance_records member, sorted by (verifier_namespace, replay_epoch,
// value).
func (p *DevicePrimaryTestOnly) issuanceMemberLocked() ([]byte, error) {
	issuance := p.Issuance.inner
	issuance.mu.Lock()
	records := slices.Collect(maps.Values(issuance.records))
	issuance.mu.Unlock()
	slices.SortFunc(records, func(a, b ratify.ExpectedChallengeV2) int {
		return cmp.Or(strings.Compare(a.VerifierNamespace, b.VerifierNamespace), cmp.Compare(a.ReplayEpoch, b.ReplayEpoch), bytes.Compare(a.Value, b.Value))
	})
	projected := make([]any, 0, len(records))
	for _, record := range records {
		projected = append(projected, issuanceProjection(record))
	}
	return ratify.CanonicalJSON(projected)
}

// projectionLocked returns the RatifyCanonicalJSON of the version 1
// projection object.
func (p *DevicePrimaryTestOnly) projectionLocked(store storeStateTestOnly, issuanceDigest string) ([]byte, error) {
	journal := p.Journal.inner
	journal.mu.Lock()
	journalMember := object{"generation": journal.head.Generation, "snapshot_sha384": sha384Hex(journal.snapshot)}
	journal.mu.Unlock()
	return ratify.CanonicalJSON(object{
		"claims": store.claims, "issuance_records": issuanceDigest, "log_id": p.Store.logID, "rate_counters": store.rateCounters,
		"receipt_log": store.receiptLog, "replay_epoch": p.replayEpoch, "security_journal": journalMember, "streams": store.streams,
		"version": int64(deviceStateVersion),
	})
}

// completeStateDigest is the labelled SHA-384 of the projection bytes.
func completeStateDigest(projection []byte) []byte {
	h := sha512.New384()
	h.Write([]byte(deviceStateLabel))
	h.Write([]byte{0})
	h.Write(projection)
	return h.Sum(nil)
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
