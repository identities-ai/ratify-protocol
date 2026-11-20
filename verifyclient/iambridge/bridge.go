// Package iambridge reconciles an authoritative customer IAM snapshot into
// customer-signed Protocol v2 status lists. It never treats event payloads as
// authority; events only cause another snapshot read.
package iambridge

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Snapshot must be a complete, authenticated view for one pinned issuer.
// RevokedCertIDs are exact DelegationCertV2 cert_id values, not IAM user IDs.
type Snapshot struct {
	IssuerID       string
	Revision       string
	Complete       bool
	ObservedAt     time.Time
	RevokedCertIDs []string
}

type Source interface {
	Snapshot(context.Context) (Snapshot, error)
}

type Publisher interface {
	Publish(context.Context, []byte) error
}

// RemoteStatus is Verify's checkpoint-bound view of this issuer for the
// receiver: the accepted floor, the digest of the accepted list, and the
// highest sequence Verify has observed in the bound epoch.
type RemoteStatus struct {
	Epoch          uint64
	HasFloor       bool
	Floor          int64
	AcceptedDigest string
	MaxObserved    int64
}

type StatusReader interface {
	IssuerStatus(context.Context) (RemoteStatus, error)
}

type StateStore interface {
	Load() (State, error)
	Save(State) error
}

type Pending struct {
	Sequence  int64    `json:"sequence"`
	Revoked   []string `json:"revoked"`
	Wire      []byte   `json:"wire"`
	UpdatedAt int64    `json:"updated_at"`
	// Digests lists every list signed at Sequence with these revocations, so
	// an earlier same-sequence wire that Verify accepted is recognized.
	Digests      []string `json:"digests,omitempty"`
	Blocked      bool     `json:"blocked,omitempty"`
	NeedsRefresh bool     `json:"needs_refresh,omitempty"`
	// SequenceConflict records Verify's status_publication_conflict for this
	// list; the next attempt reconciles against Verify's accepted floor.
	SequenceConflict bool `json:"sequence_conflict,omitempty"`
}

// State is durable bridge state. A pending wire is saved before publication;
// an ambiguous network response is retried with exactly the same wire.
type State struct {
	IssuerID  string   `json:"issuer_id"`
	Epoch     uint64   `json:"epoch"`
	Sequence  int64    `json:"sequence"`
	UpdatedAt int64    `json:"updated_at"`
	Revoked   []string `json:"revoked"`
	Pending   *Pending `json:"pending,omitempty"`
}

type Bridge struct {
	IssuerID       string
	Epoch          uint64
	StatusKey      ratify.HybridPrivateKey
	Source         Source
	Publisher      Publisher
	Status         StatusReader
	Store          StateStore
	Now            func() time.Time
	Lifetime       time.Duration
	MaxSnapshotAge time.Duration
}

// Reconcile publishes one complete status snapshot. The caller must hold a
// single-writer lease for this bridge state across the entire call.
func (b *Bridge) Reconcile(ctx context.Context) error {
	if b.IssuerID == "" || b.Epoch == 0 || b.Source == nil || b.Publisher == nil || b.Status == nil || b.Store == nil ||
		b.Now == nil || b.Lifetime < 3*time.Minute || b.Lifetime > 10*time.Minute ||
		b.MaxSnapshotAge <= 0 || b.MaxSnapshotAge > time.Minute {
		return errors.New("IAM bridge configuration is incomplete")
	}
	state, err := b.Store.Load()
	if err != nil {
		return fmt.Errorf("load IAM bridge state: %w", err)
	}
	if state.IssuerID == "" && state.Epoch == 0 && state.Sequence == 0 && state.Pending == nil {
		state.IssuerID, state.Epoch = b.IssuerID, b.Epoch
	}
	if state.IssuerID != b.IssuerID || state.Epoch != b.Epoch || state.Sequence < 0 {
		return errors.New("IAM bridge state does not match pinned issuer and epoch")
	}
	if state.Pending != nil {
		if state.Pending.Sequence < state.Sequence ||
			(state.Pending.Sequence == state.Sequence && state.Sequence == 0) ||
			(state.Pending.Sequence == state.Sequence && !slices.Equal(state.Pending.Revoked, state.Revoked)) ||
			!containsRevocations(state.Pending.Revoked, state.Revoked) ||
			state.Pending.UpdatedAt <= state.UpdatedAt || len(state.Pending.Wire) == 0 {
			return errors.New("IAM bridge pending publication is malformed")
		}
		if state.Pending.Blocked {
			return errors.New("IAM bridge publication was definitively rejected; operator reconciliation is required")
		}
		if state.Pending.SequenceConflict {
			return b.resolveSequenceConflict(ctx, &state)
		}
		// Every send, including an exact retry, needs a fresh complete IAM
		// snapshot: during an IAM outage nothing is published.
		var ids []string
		if !state.Pending.NeedsRefresh && b.Now().Unix() < state.Pending.UpdatedAt+90 {
			if ids, err = b.snapshotRevocations(ctx, append(state.Revoked, state.Pending.Revoked...)); err != nil {
				return err
			}
			if slices.Equal(ids, state.Pending.Revoked) {
				return b.publishPending(ctx, &state)
			}
		}
		// The pending outcome is unknown, IAM changed, or Verify asked for a
		// fresh list. Learn the outcome from Verify's checkpoint before
		// signing anything, so no sequence is skipped or forked.
		remote, err := b.remoteStatus(ctx, &state)
		if err != nil {
			return err
		}
		if remote.HasFloor && remote.Floor == state.Pending.Sequence && remote.MaxObserved == remote.Floor &&
			slices.Contains(state.Pending.Digests, remote.AcceptedDigest) {
			state.Sequence, state.UpdatedAt, state.Revoked = state.Pending.Sequence, state.Pending.UpdatedAt, state.Pending.Revoked
			state.Pending = nil
			if err := b.Store.Save(state); err != nil {
				return fmt.Errorf("save reconciled IAM status list: %w", err)
			}
			return b.publishNext(ctx, state, state.Sequence+1)
		}
		if remote.HasFloor && remote.Floor >= state.Pending.Sequence {
			// Verify already holds the pending sequence, typically from this
			// bridge's previous process: continue above it.
			return b.resolveSequenceConflict(ctx, &state)
		}
		if remoteFloor(remote) != state.Sequence || remote.MaxObserved > state.Pending.Sequence {
			return b.block(&state, fmt.Errorf("%w: Verify floor %d and observed sequence %d do not follow local sequence %d",
				ErrDefinitivePublication, remoteFloor(remote), remote.MaxObserved, state.Sequence))
		}
		if ids == nil {
			if ids, err = b.snapshotRevocations(ctx, append(state.Revoked, state.Pending.Revoked...)); err != nil {
				return err
			}
		}
		updatedAt := b.Now().Unix()
		if updatedAt <= state.Pending.UpdatedAt {
			return errors.New("IAM bridge clock has not advanced for a safe status retry")
		}
		// The pending sequence is reused only for the same revocations. Its
		// signed bytes may still arrive, so a different set takes the next
		// sequence instead of forking this one.
		sequence, digests := state.Pending.Sequence, state.Pending.Digests
		if !slices.Equal(ids, state.Pending.Revoked) {
			sequence, digests = sequence+1, nil
		}
		return b.savePendingAndPublish(ctx, state, sequence, ids, updatedAt, digests)
	}
	// Every new list starts from Verify's checkpoint-bound status. This
	// bridge may have lost its lease meanwhile, and another writer may have
	// advanced the issuer; signing from stale local state could fork it.
	remote, err := b.remoteStatus(ctx, &state)
	if err != nil {
		return err
	}
	minNext := state.Sequence + 1
	if state.Sequence == 0 && state.UpdatedAt == 0 && len(state.Revoked) == 0 {
		// Initial sync: Verify may already hold accepted status for this
		// epoch, from a console import or a restored bridge. Start above it.
		state.Sequence = remoteFloor(remote)
		minNext = max(state.Sequence, remote.MaxObserved) + 1
	} else if remoteFloor(remote) != state.Sequence || remote.MaxObserved > state.Sequence {
		return fmt.Errorf("%w: Verify floor %d and observed sequence %d are beyond local accepted sequence %d; another writer advanced the issuer",
			ErrDefinitivePublication, remoteFloor(remote), remote.MaxObserved, state.Sequence)
	}
	return b.publishNext(ctx, state, minNext)
}

// publishNext signs the current IAM snapshot. An unchanged set after this
// bridge's own accepted list is a same-sequence heartbeat; anything else
// takes at least minNext.
func (b *Bridge) publishNext(ctx context.Context, state State, minNext int64) error {
	ids, err := b.snapshotRevocations(ctx, state.Revoked)
	if err != nil {
		return err
	}
	now := b.Now().Unix()
	if now <= state.UpdatedAt {
		return errors.New("IAM bridge clock has not advanced for a new status list")
	}
	sequence := minNext
	if state.UpdatedAt > 0 && slices.Equal(ids, state.Revoked) {
		sequence = state.Sequence
	}
	return b.savePendingAndPublish(ctx, state, sequence, ids, now, nil)
}

func (b *Bridge) savePendingAndPublish(ctx context.Context, state State, sequence int64, ids []string, updatedAt int64, digests []string) error {
	wire, digest, err := b.signList(sequence, ids, updatedAt)
	if err != nil {
		return err
	}
	state.Pending = &Pending{Sequence: sequence, Revoked: ids, Wire: wire, UpdatedAt: updatedAt,
		Digests: append(slices.Clone(digests), digest)}
	if err := b.Store.Save(state); err != nil {
		return fmt.Errorf("save pending IAM status list: %w", err)
	}
	return b.publishPending(ctx, &state)
}

// remoteStatus reads Verify's checkpointed issuer status. A receiver bound to
// another epoch means this writer was rotated out: a pending list is then
// durably blocked, and a bridge with nothing pending keeps refusing to start.
func (b *Bridge) remoteStatus(ctx context.Context, state *State) (RemoteStatus, error) {
	remote, err := b.Status.IssuerStatus(ctx)
	if err != nil {
		return RemoteStatus{}, fmt.Errorf("read Verify issuer status: %w", err)
	}
	if remote.Epoch != b.Epoch {
		err := fmt.Errorf("%w: receiver is bound to status-key epoch %d, not %d", ErrDefinitivePublication, remote.Epoch, b.Epoch)
		if state.Pending == nil {
			return RemoteStatus{}, err
		}
		return RemoteStatus{}, b.block(state, err)
	}
	if remote.MaxObserved < 0 || remote.HasFloor && remote.Floor < 0 {
		return RemoteStatus{}, errors.New("Verify issuer status is malformed")
	}
	return remote, nil
}

func remoteFloor(remote RemoteStatus) int64 {
	if remote.HasFloor {
		return remote.Floor
	}
	return 0
}

// resolveSequenceConflict handles Verify's status_publication_conflict, or a
// checkpoint read before a send, for the pending list. A pending sequence at
// or below Verify's accepted floor
// was already filled, typically by this bridge's previous process before a
// restart under a new publisher ID. If Verify accepted this bridge's own list
// there, it is delivered; otherwise the stale pending list is dropped. Either
// way the bridge signs the complete cumulative revoked set (accepted, pending,
// and a fresh IAM snapshot) above every sequence Verify has accepted or
// observed, so no revocation is dropped and no sequence is forked. A refusal
// above the floor is a real history conflict and blocks for an operator.
func (b *Bridge) resolveSequenceConflict(ctx context.Context, state *State) error {
	remote, err := b.remoteStatus(ctx, state)
	if err != nil {
		return err
	}
	pending := state.Pending
	if !remote.HasFloor || remote.Floor < pending.Sequence {
		return b.block(state, fmt.Errorf("%w: Verify refused sequence %d above its accepted sequence %d",
			ErrDefinitivePublication, pending.Sequence, remoteFloor(remote)))
	}
	ids, err := b.snapshotRevocations(ctx, append(slices.Clone(state.Revoked), pending.Revoked...))
	if err != nil {
		return err
	}
	updatedAt := b.Now().Unix()
	if remote.Floor == pending.Sequence && slices.Contains(pending.Digests, remote.AcceptedDigest) {
		state.Sequence, state.UpdatedAt, state.Revoked = pending.Sequence, pending.UpdatedAt, pending.Revoked
	} else {
		// Verify's floor holds another publisher's list; state.Revoked stays
		// as revocations this bridge must keep publishing.
		state.Sequence = remote.Floor
	}
	if updatedAt <= state.UpdatedAt {
		return errors.New("IAM bridge clock has not advanced for a new status list")
	}
	return b.savePendingAndPublish(ctx, *state, max(remote.Floor, remote.MaxObserved)+1, ids, updatedAt, nil)
}

// block durably stops this writer's pending list until an operator
// reconciles it with the unblock command.
func (b *Bridge) block(state *State, cause error) error {
	state.Pending.Blocked, state.Pending.NeedsRefresh, state.Pending.SequenceConflict = true, false, false
	if err := b.Store.Save(*state); err != nil {
		return fmt.Errorf("save blocked IAM status publication: %w", err)
	}
	return cause
}

func (b *Bridge) snapshotRevocations(ctx context.Context, retained []string) ([]string, error) {
	snapshot, err := b.Source.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("read authoritative IAM snapshot: %w", err)
	}
	observedAge := b.Now().Sub(snapshot.ObservedAt)
	if !snapshot.Complete || snapshot.IssuerID != b.IssuerID || snapshot.Revision == "" ||
		snapshot.RevokedCertIDs == nil || observedAge < 0 || observedAge > b.MaxSnapshotAge {
		return nil, errors.New("IAM snapshot is incomplete or belongs to another issuer")
	}
	revoked := make(map[string]struct{}, len(retained)+len(snapshot.RevokedCertIDs))
	for _, id := range retained {
		revoked[id] = struct{}{}
	}
	for _, id := range snapshot.RevokedCertIDs {
		if id == "" {
			return nil, errors.New("IAM snapshot has an empty grant ID")
		}
		revoked[id] = struct{}{}
	}
	if len(revoked) > ratify.MaxRevocationListRefsV2 {
		return nil, errors.New("IAM snapshot exceeds the Protocol status-list limit")
	}
	ids := make([]string, 0, len(revoked))
	for id := range revoked {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func containsRevocations(all, required []string) bool {
	set := make(map[string]struct{}, len(all))
	for _, id := range all {
		set[id] = struct{}{}
	}
	for _, id := range required {
		if _, ok := set[id]; !ok {
			return false
		}
	}
	return true
}

func (b *Bridge) signList(sequence int64, ids []string, updatedAt int64) ([]byte, string, error) {
	// The receiver's Protocol proof and status skew must match. Dating the
	// customer list 30 seconds behind this host tolerates ordinary clock drift
	// without widening the verifier's proof acceptance window.
	statusUpdatedAt := updatedAt - 30
	entries := make([]ratify.RevokedCertV2, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, ratify.RevokedCertV2{CertID: id})
	}
	list, err := ratify.SignRevocationListV2(&ratify.RevocationListV2{
		Version: 2, IssuerID: b.IssuerID, Sequence: sequence,
		UpdatedAt: statusUpdatedAt, NextUpdate: statusUpdatedAt + int64(b.Lifetime.Seconds()), Revoked: entries,
	}, b.IssuerID, b.StatusKey.Public(), b.StatusKey)
	if err != nil {
		return nil, "", fmt.Errorf("sign IAM status list: %w", err)
	}
	wire, err := ratify.EncodeRevocationListV2(list)
	if err != nil {
		return nil, "", fmt.Errorf("encode IAM status list: %w", err)
	}
	digest, err := ratify.StatusEvidenceDigest(revocationListObjectType, list)
	if err != nil {
		return nil, "", fmt.Errorf("digest IAM status list: %w", err)
	}
	return wire, "sha384:" + hex.EncodeToString(digest), nil
}

// revocationListObjectType is the Protocol v2 status object type of a full
// revocation list, as used in Verify's accepted-list digest.
const revocationListObjectType = uint16(0x0003)

func (b *Bridge) publishPending(ctx context.Context, state *State) error {
	if err := b.Publisher.Publish(ctx, state.Pending.Wire); err != nil {
		if errors.Is(err, ErrDefinitivePublication) || errors.Is(err, ErrRefreshRequired) || errors.Is(err, ErrPublisherConflict) {
			// A refused writer reconciles with Verify before it may publish
			// again, because the lease holder may have advanced the issuer.
			// A sequence conflict is reconciled against Verify's floor.
			state.Pending.SequenceConflict = errors.Is(err, ErrSequenceConflict)
			state.Pending.Blocked = errors.Is(err, ErrDefinitivePublication) && !state.Pending.SequenceConflict
			state.Pending.NeedsRefresh = !state.Pending.Blocked && !state.Pending.SequenceConflict
			if saveErr := b.Store.Save(*state); saveErr != nil {
				return fmt.Errorf("save IAM status publication response: %w", saveErr)
			}
		}
		return fmt.Errorf("publish IAM status list sequence %d: %w", state.Pending.Sequence, err)
	}
	state.Sequence = state.Pending.Sequence
	state.UpdatedAt = state.Pending.UpdatedAt
	state.Revoked = state.Pending.Revoked
	state.Pending = nil
	if err := b.Store.Save(*state); err != nil {
		return fmt.Errorf("save accepted IAM status list: %w", err)
	}
	return nil
}
