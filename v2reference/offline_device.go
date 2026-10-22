package v2reference

// Single-device offline profile (SPEC-v2 §7.13), TEST ONLY.
//
// DeviceComponentTestOnly models the independent component the profile
// requires on one device: an independently programmed secure element or
// TPM-backed module with its own key that persistently records, for every
// receipt-log entry, the entry hash and the primary's complete-state digest,
// advances monotonically, and signs each acknowledgement. Nothing here is
// durable or independent; it exists so the shared profile scenarios can
// exercise power loss, primary rollback, digest mismatch, full storage,
// clock regression, and offline recovery against exact semantics.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

var (
	// ErrDevicePowerLoss is returned when power is lost during a checkpoint
	// submission. Before the component commits, nothing is recorded; after
	// it commits, the acknowledgement is durable but its response is lost.
	ErrDevicePowerLoss = errors.New("v2reference: power lost during the device checkpoint submission")
	// ErrDeviceStorageFull is returned when the component has no space for
	// another acknowledgement. It never overwrites or wraps.
	ErrDeviceStorageFull = errors.New("v2reference: device checkpoint storage is full")
	// ErrDeviceStateMismatch is returned when a submission does not extend
	// the component's head: the previous entry hash or the previous
	// complete-state digest differs, or the sequence is not the next one.
	ErrDeviceStateMismatch = errors.New("v2reference: submission does not extend the device checkpoint head")
	// ErrDeviceFrozen is returned after a different entry was submitted at an
	// acknowledged sequence; the component then acknowledges nothing further.
	ErrDeviceFrozen = errors.New("v2reference: device checkpoint is frozen after a conflicting entry")
)

// DevicePowerLoss selects where the next submission loses power.
type DevicePowerLoss int

const (
	DevicePowerOK DevicePowerLoss = iota
	DevicePowerLossBeforeCommit
	DevicePowerLossAfterCommit
)

// DeviceAcknowledgementTestOnly is one signed component record.
type DeviceAcknowledgementTestOnly struct {
	LogID       string
	Sequence    int64
	EntryHash   []byte
	StateDigest []byte
	Timestamp   int64
	Signature   []byte
}

func lpBytes(b []byte) []byte {
	out := binary.BigEndian.AppendUint64(nil, uint64(len(b)))
	return append(out, b...)
}

// deviceAckMessage is the exact byte string the component signs.
func deviceAckMessage(a DeviceAcknowledgementTestOnly) []byte {
	m := append([]byte("ratify-test-device-checkpoint-v2"), 0)
	m = append(m, lpBytes([]byte(a.LogID))...)
	m = binary.BigEndian.AppendUint64(m, uint64(a.Sequence))
	m = append(m, lpBytes(a.EntryHash)...)
	m = append(m, lpBytes(a.StateDigest)...)
	return binary.BigEndian.AppendUint64(m, uint64(a.Timestamp))
}

// VerifyDeviceAcknowledgementTestOnly checks a record under the pinned
// component public key.
func VerifyDeviceAcknowledgementTestOnly(pub ed25519.PublicKey, a DeviceAcknowledgementTestOnly) error {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, deviceAckMessage(a), a.Signature) {
		return fmt.Errorf("v2reference: device acknowledgement signature does not verify")
	}
	return nil
}

func cloneDeviceAck(a DeviceAcknowledgementTestOnly) DeviceAcknowledgementTestOnly {
	a.EntryHash, a.StateDigest, a.Signature = bytes.Clone(a.EntryHash), bytes.Clone(a.StateDigest), bytes.Clone(a.Signature)
	return a
}

// DeviceComponentTestOnly is the independent monotonic authenticated
// component. Its clock is the device's configured security-clock source.
type DeviceComponentTestOnly struct {
	mu       sync.Mutex
	key      ed25519.PrivateKey
	clock    ratify.V2AuthoritativeClock
	capacity int
	records  []DeviceAcknowledgementTestOnly
	frozen   bool
	fault    DevicePowerLoss
}

// NewDeviceComponentTestOnly returns a component with its own signing key
// (from a 32-byte test seed) and room for capacity acknowledgements.
func NewDeviceComponentTestOnly(seed []byte, capacity int, clock ratify.V2AuthoritativeClock) (*DeviceComponentTestOnly, error) {
	if len(seed) != ed25519.SeedSize || capacity < 1 || clock == nil {
		return nil, fmt.Errorf("v2reference: device component needs a 32-byte seed, positive capacity, and a clock")
	}
	return &DeviceComponentTestOnly{key: ed25519.NewKeyFromSeed(seed), clock: clock, capacity: capacity}, nil
}

// PublicKey returns the component key the primary pins.
func (c *DeviceComponentTestOnly) PublicKey() ed25519.PublicKey {
	return bytes.Clone(c.key.Public().(ed25519.PublicKey))
}

// SetPowerLoss arms a power loss for the next submission only.
func (c *DeviceComponentTestOnly) SetPowerLoss(f DevicePowerLoss) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fault = f
}

// Head returns the acknowledged sequence and complete-state digest (zero and
// 32 zero bytes before the first acknowledgement), and whether it is frozen.
func (c *DeviceComponentTestOnly) Head() (int64, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.records) == 0 {
		return 0, make([]byte, 32), c.frozen
	}
	last := c.records[len(c.records)-1]
	return last.Sequence, bytes.Clone(last.StateDigest), c.frozen
}

// Commit records the next entry. It accepts only sequence head+1 whose
// previous entry hash and previous state digest equal the head's; an
// identical retry of an acknowledged sequence returns the original record,
// and a different entry or state at an acknowledged sequence freezes the
// component.
func (c *DeviceComponentTestOnly) Commit(ctx context.Context, logID string, sequence int64, previousEntryHash, entryHash, previousState, state []byte) (DeviceAcknowledgementTestOnly, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return DeviceAcknowledgementTestOnly{}, ErrDeviceFrozen
	}
	if sequence >= 1 && sequence <= int64(len(c.records)) {
		existing := c.records[sequence-1]
		if existing.LogID == logID && bytes.Equal(existing.EntryHash, entryHash) && bytes.Equal(existing.StateDigest, state) {
			return cloneDeviceAck(existing), nil
		}
		c.frozen = true
		return DeviceAcknowledgementTestOnly{}, ErrDeviceFrozen
	}
	headEntry, headState := make([]byte, 48), make([]byte, 32)
	if n := len(c.records); n > 0 {
		headEntry, headState = c.records[n-1].EntryHash, c.records[n-1].StateDigest
		if c.records[n-1].LogID != logID {
			return DeviceAcknowledgementTestOnly{}, ErrDeviceStateMismatch
		}
	}
	if sequence != int64(len(c.records))+1 || !bytes.Equal(headEntry, previousEntryHash) || !bytes.Equal(headState, previousState) {
		return DeviceAcknowledgementTestOnly{}, ErrDeviceStateMismatch
	}
	if len(c.records) >= c.capacity {
		return DeviceAcknowledgementTestOnly{}, ErrDeviceStorageFull
	}
	fault := c.fault
	c.fault = DevicePowerOK
	if fault == DevicePowerLossBeforeCommit {
		return DeviceAcknowledgementTestOnly{}, ErrDevicePowerLoss
	}
	now, err := c.clock.AuthoritativeTimeV2(ctx)
	if err != nil {
		return DeviceAcknowledgementTestOnly{}, err
	}
	ack := DeviceAcknowledgementTestOnly{LogID: logID, Sequence: sequence, EntryHash: bytes.Clone(entryHash), StateDigest: bytes.Clone(state), Timestamp: now}
	ack.Signature = ed25519.Sign(c.key, deviceAckMessage(ack))
	c.records = append(c.records, ack)
	if fault == DevicePowerLossAfterCommit {
		return DeviceAcknowledgementTestOnly{}, ErrDevicePowerLoss
	}
	return cloneDeviceAck(ack), nil
}

// Get returns the record for sequence, or ratify.ErrV2AcknowledgementNotFound.
func (c *DeviceComponentTestOnly) Get(logID string, sequence int64) (DeviceAcknowledgementTestOnly, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sequence < 1 || sequence > int64(len(c.records)) || c.records[sequence-1].LogID != logID {
		return DeviceAcknowledgementTestOnly{}, ratify.ErrV2AcknowledgementNotFound
	}
	return cloneDeviceAck(c.records[sequence-1]), nil
}

// DeviceStateDigestTestOnly returns the primary's complete-state digest after
// receipt-log entry sequence (32 zero bytes for sequence 0). Each step binds
// the claim ID, the sealed terminal result, the sealed outbox body, and the
// signed entry hash, so a primary restored to an earlier or altered state
// cannot reproduce the digest the component acknowledged. A production
// primary digests every durable security record (SPEC-v2 §7.13).
func (s *Store) DeviceStateDigestTestOnly(sequence int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceStateDigestLocked(sequence)
}

func (s *Store) deviceStateDigestLocked(sequence int64) ([]byte, error) {
	state := make([]byte, 32)
	if sequence < 0 || sequence > int64(len(s.outbox)) {
		return nil, fmt.Errorf("v2reference: no receipt-log entry %d", sequence)
	}
	for i := int64(0); i < sequence; i++ {
		entry := s.outbox[i]
		if entry.wire == nil {
			return nil, fmt.Errorf("v2reference: receipt-log entry %d is not appended", i+1)
		}
		record := s.claims[entry.claimID]
		terminal, body := sha256.Sum256(record.terminal), sha256.Sum256(record.receiptBody)
		h := sha256.New()
		h.Write(append([]byte("ratify-test-device-state-v2"), 0))
		h.Write(state)
		h.Write(lpBytes([]byte(entry.claimID)))
		h.Write(terminal[:])
		h.Write(body[:])
		h.Write(lpBytes(entry.digest))
		state = h.Sum(nil)
	}
	return state, nil
}

// CorruptSealedStateTestOnly flips one byte of a committed claim's sealed
// terminal result, modelling corrupted primary storage.
func (s *Store) CorruptSealedStateTestOnly(claimID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.claims[claimID]; ok && len(record.terminal) > 0 {
		record.terminal = bytes.Clone(record.terminal)
		record.terminal[0] ^= 1
	}
}

// appendedEntry returns the entry hash of an appended receipt-log entry.
func (s *Store) appendedEntry(sequence int64) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence < 1 || sequence > int64(len(s.outbox)) || s.outbox[sequence-1].wire == nil {
		return nil, false
	}
	return bytes.Clone(s.outbox[sequence-1].digest), true
}

// DeviceStartupStatus is the result of the primary's startup comparison with
// the component head.
type DeviceStartupStatus string

const (
	// DeviceReady: the primary's state at the component head equals the
	// acknowledged digest; any later appended entries are submitted in order.
	DeviceReady DeviceStartupStatus = "ready"
	// DevicePrimaryBehind: the primary holds fewer appended entries than the
	// component acknowledged (rollback or lost state). The device stays
	// recovering until its recovery authority advances the replay epoch.
	DevicePrimaryBehind DeviceStartupStatus = "primary_behind"
	// DeviceStateDigestMismatch: same length, different complete state.
	DeviceStateDigestMismatch DeviceStartupStatus = "state_digest_mismatch"
	// DeviceCheckpointFrozen: the component saw a conflicting entry.
	DeviceCheckpointFrozen DeviceStartupStatus = "checkpoint_frozen"
)

// DeviceCheckpointTestOnly is the primary's view of the component. It
// implements ratify.V2ReceiptCheckpoint: every acknowledgement it returns
// carries a component signature verified under the pinned key.
type DeviceCheckpointTestOnly struct {
	primary   *Store
	component *DeviceComponentTestOnly
	pinned    ed25519.PublicKey
}

// NewDeviceCheckpointTestOnly binds a primary store to a component whose key
// the primary pinned at provisioning. The primary must not self-acknowledge
// (SetAcknowledgementWithheld(true)).
func NewDeviceCheckpointTestOnly(primary *Store, component *DeviceComponentTestOnly, pinned ed25519.PublicKey) *DeviceCheckpointTestOnly {
	return &DeviceCheckpointTestOnly{primary: primary, component: component, pinned: bytes.Clone(pinned)}
}

func (d *DeviceCheckpointTestOnly) toAck(a DeviceAcknowledgementTestOnly) (ratify.V2CheckpointAcknowledgement, error) {
	if err := VerifyDeviceAcknowledgementTestOnly(d.pinned, a); err != nil {
		return ratify.V2CheckpointAcknowledgement{}, err
	}
	return ratify.V2CheckpointAcknowledgement{LogID: a.LogID, Sequence: a.Sequence, EntryHash: bytes.Clone(a.EntryHash), Timestamp: a.Timestamp}, nil
}

// AcknowledgeV2Receipt submits the primary's appended entry with its
// previous and current complete-state digests.
func (d *DeviceCheckpointTestOnly) AcknowledgeV2Receipt(ctx context.Context, logID string, sequence int64, previousEntryHash, entryHash []byte) (ratify.V2CheckpointAcknowledgement, error) {
	if appended, ok := d.primary.appendedEntry(sequence); !ok || !bytes.Equal(appended, entryHash) {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	previousState, err := d.primary.DeviceStateDigestTestOnly(sequence - 1)
	if err != nil {
		return ratify.V2CheckpointAcknowledgement{}, err
	}
	state, err := d.primary.DeviceStateDigestTestOnly(sequence)
	if err != nil {
		return ratify.V2CheckpointAcknowledgement{}, err
	}
	ack, err := d.component.Commit(ctx, logID, sequence, previousEntryHash, entryHash, previousState, state)
	if err != nil {
		return ratify.V2CheckpointAcknowledgement{}, err
	}
	return d.toAck(ack)
}

// GetV2Acknowledgement reads and verifies the component record.
func (d *DeviceCheckpointTestOnly) GetV2Acknowledgement(_ context.Context, logID string, sequence int64) (ratify.V2CheckpointAcknowledgement, error) {
	ack, err := d.component.Get(logID, sequence)
	if err != nil {
		return ratify.V2CheckpointAcknowledgement{}, err
	}
	return d.toAck(ack)
}

// SubmitPending submits, in log order, every appended entry of the primary
// that the component has not acknowledged with the same entry hash, and
// returns the sequences acknowledged by this call. It stops at the first
// failure and returns it. A rolled-back primary therefore resubmits its own
// version of an acknowledged sequence, which the component refuses.
func (d *DeviceCheckpointTestOnly) SubmitPending(ctx context.Context) ([]int64, error) {
	acknowledged := []int64{}
	for next := int64(1); ; next++ {
		entry, ok := d.primary.appendedEntry(next)
		if !ok {
			return acknowledged, nil
		}
		if existing, err := d.component.Get(d.primary.logID, next); err == nil && bytes.Equal(existing.EntryHash, entry) {
			continue
		}
		if _, err := d.Resubmit(ctx, next); err != nil {
			return acknowledged, err
		}
		acknowledged = append(acknowledged, next)
	}
}

// Resubmit retries the exact tuple for sequence (for example after a power
// loss whose outcome is unknown) and returns the acknowledgement.
func (d *DeviceCheckpointTestOnly) Resubmit(ctx context.Context, sequence int64) (ratify.V2CheckpointAcknowledgement, error) {
	entry, ok := d.primary.appendedEntry(sequence)
	if !ok {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	previous := make([]byte, 48)
	if sequence > 1 {
		if previous, ok = d.primary.appendedEntry(sequence - 1); !ok {
			return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
		}
	}
	return d.AcknowledgeV2Receipt(ctx, d.primary.logID, sequence, previous, entry)
}

// Startup compares the primary with the component head before the device
// serves any request.
func (d *DeviceCheckpointTestOnly) Startup() DeviceStartupStatus {
	head, headState, frozen := d.component.Head()
	if frozen {
		return DeviceCheckpointFrozen
	}
	state, err := d.primary.DeviceStateDigestTestOnly(head)
	if err != nil {
		return DevicePrimaryBehind
	}
	if !bytes.Equal(state, headState) {
		return DeviceStateDigestMismatch
	}
	return DeviceReady
}

// DeviceUplinkTestOnly is the outbox upload after reconnection. It uploads
// signed receipts only from the component-acknowledged prefix, in log order,
// once each. Upload is an outbox operation: it never releases a decision,
// changes a release record, or makes a withheld result actionable.
type DeviceUplinkTestOnly struct {
	mu        sync.Mutex
	device    *DeviceCheckpointTestOnly
	uploaded  int64
	collected [][]byte
}

// NewDeviceUplinkTestOnly returns an uplink for the device.
func NewDeviceUplinkTestOnly(device *DeviceCheckpointTestOnly) *DeviceUplinkTestOnly {
	return &DeviceUplinkTestOnly{device: device}
}

// Upload sends every acknowledged receipt not yet uploaded and returns their
// sequences.
func (u *DeviceUplinkTestOnly) Upload(context.Context) []int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	head, _, _ := u.device.component.Head()
	sent := []int64{}
	for u.uploaded < head {
		next := u.uploaded + 1
		u.device.primary.mu.Lock()
		if next > int64(len(u.device.primary.outbox)) || u.device.primary.outbox[next-1].wire == nil {
			u.device.primary.mu.Unlock()
			break
		}
		u.collected = append(u.collected, bytes.Clone(u.device.primary.outbox[next-1].wire))
		u.device.primary.mu.Unlock()
		u.uploaded = next
		sent = append(sent, next)
	}
	return sent
}
