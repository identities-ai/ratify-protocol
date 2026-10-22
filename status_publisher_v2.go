package ratify

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"unicode/utf8"
)

// Minimal signed-status publisher (SPEC-v2 §5.4, status publisher duties).
//
// A v2 allow needs current signed status for every certificate in the
// chain. V2StatusPublisher produces that feed for one issuer under a
// separate status key: a genesis full list, same-sequence heartbeats that
// refresh freshness, and revocations as a push plus the cumulative full
// list at the next sequence. Each operation is a pure transition of
// V2StatusPublisherState; the caller MUST durably persist the returned
// state before publishing the returned objects, so a crash can never sign
// two different bodies at one sequence.

// V2StatusPublisherState is the publisher's durable state.
type V2StatusPublisherState struct {
	IssuerID    string
	StatusKeyID string
	// Sequence is the last signed sequence; UpdatedAt is the updated_at of
	// the last signed full list; Revoked is the cumulative sorted set.
	Sequence  int64
	UpdatedAt int64
	Revoked   []string
}

// V2StatusPublication is one transition's output: the next state and the
// signed objects to publish after that state is durable. Push is nil except
// for a revocation.
type V2StatusPublication struct {
	State V2StatusPublisherState
	List  *RevocationListV2
	Push  *RevocationPushV2
}

// V2StatusPublisher signs status for one issuer under one status key.
type V2StatusPublisher struct {
	issuerID    string
	statusKey   HybridPublicKey
	statusKeyID string
	signer      SignerV2
	lifetime    int64
}

// NewV2StatusPublisher binds an issuer's complete key to a separate status
// signer. It refuses, before any signature exists, a status key whose key ID
// or either component equals the issuer key or any key in otherRoleKeys (for
// example the organization root, other issuers, or agents): status-key role
// separation is mandatory (SPEC-v2 §5.4). lifetimeSeconds sets next_update -
// updated_at for every full list and is 1..86400; it must not exceed the
// relying verifiers' configured maximum list lifetime.
func NewV2StatusPublisher(issuerKey HybridPublicKey, statusSigner SignerV2, otherRoleKeys []HybridPublicKey, lifetimeSeconds int64) (*V2StatusPublisher, error) {
	if lifetimeSeconds < 1 || lifetimeSeconds > V2MaxStatusLifetimeSeconds {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 status list lifetime must be 1..%d seconds", V2MaxStatusLifetimeSeconds)
	}
	issuerID, err := keyIDV2(issuerKey)
	if err != nil {
		return nil, v2Classify(V2ErrConfigurationInvalid, fmt.Errorf("v2 status publisher issuer key: %w", err))
	}
	if statusSigner == nil {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 status publisher requires a status signer")
	}
	statusKey, err := signerPublicKeyV2(statusSigner)
	if err != nil {
		return nil, v2Classify(V2ErrConfigurationInvalid, err)
	}
	statusKeyID, err := keyIDV2(statusKey)
	if err != nil {
		return nil, v2Classify(V2ErrConfigurationInvalid, err)
	}
	for _, other := range append([]HybridPublicKey{issuerKey}, otherRoleKeys...) {
		otherID, err := keyIDV2(other)
		if err != nil {
			return nil, v2Classify(V2ErrConfigurationInvalid, fmt.Errorf("v2 status publisher role key: %w", err))
		}
		if otherID == statusKeyID || bytes.Equal(other.Ed25519, statusKey.Ed25519) || bytes.Equal(other.MLDSA65, statusKey.MLDSA65) {
			return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 status key reuses an issuer or other non-status key or component; status keys must be role-separated")
		}
	}
	return &V2StatusPublisher{issuerID: issuerID, statusKey: cloneHybridPublicKeyV2(statusKey), statusKeyID: statusKeyID, signer: statusSigner, lifetime: lifetimeSeconds}, nil
}

// IssuerID and StatusKey report the binding a verifier configures.
func (p *V2StatusPublisher) IssuerID() string { return p.issuerID }

// StatusKey returns a copy of the complete status public key.
func (p *V2StatusPublisher) StatusKey() HybridPublicKey { return cloneHybridPublicKeyV2(p.statusKey) }

// Genesis signs the first full list: sequence 1, an empty revoked set.
func (p *V2StatusPublisher) Genesis(ctx context.Context, updatedAt int64) (V2StatusPublication, error) {
	state := V2StatusPublisherState{IssuerID: p.issuerID, StatusKeyID: p.statusKeyID, Revoked: []string{}}
	return p.list(ctx, state, 1, updatedAt)
}

// Heartbeat re-signs the current sequence and revoked set with a later
// updated_at, which refreshes freshness without a new sequence (SPEC-v2 §5.4).
func (p *V2StatusPublisher) Heartbeat(ctx context.Context, state V2StatusPublisherState, updatedAt int64) (V2StatusPublication, error) {
	if err := p.checkState(state, updatedAt); err != nil {
		return V2StatusPublication{}, err
	}
	return p.list(ctx, state, state.Sequence, updatedAt)
}

// Revoke advances one sequence: a push carrying exactly the newly revoked
// certificate IDs, and the cumulative full list at the same sequence, both
// timestamped at. Every ID must be new, unique, and 1..512 bytes of UTF-8.
func (p *V2StatusPublisher) Revoke(ctx context.Context, state V2StatusPublisherState, certIDs []string, at int64) (V2StatusPublication, error) {
	if err := p.checkState(state, at); err != nil {
		return V2StatusPublication{}, err
	}
	if len(certIDs) == 0 || len(certIDs) > MaxRevocationPushRefsV2 {
		return V2StatusPublication{}, fmt.Errorf("v2 status revocation must name 1..%d certificate IDs", MaxRevocationPushRefsV2)
	}
	added := slices.Clone(certIDs)
	slices.Sort(added)
	for i, id := range added {
		if id == "" || len(id) > MaxIdentifierLengthBytes || !utf8.ValidString(id) || i > 0 && added[i-1] == id {
			return V2StatusPublication{}, fmt.Errorf("v2 status revocation IDs must be unique UTF-8 of 1..%d bytes", MaxIdentifierLengthBytes)
		}
		if _, found := slices.BinarySearch(state.Revoked, id); found {
			return V2StatusPublication{}, fmt.Errorf("v2 certificate %q is already revoked; revocation is monotonic", id)
		}
	}
	if len(state.Revoked)+len(added) > MaxRevocationListRefsV2 {
		return V2StatusPublication{}, fmt.Errorf("v2 status list would exceed %d revoked references", MaxRevocationListRefsV2)
	}
	sequence := state.Sequence + 1
	if sequence > maxSafeInteger {
		return V2StatusPublication{}, fmt.Errorf("v2 status sequence is exhausted")
	}
	refs := make([]RevokedCertV2, len(added))
	for i, id := range added {
		refs[i] = RevokedCertV2{CertID: id}
	}
	push, err := SignRevocationPushV2WithSigner(ctx, &RevocationPushV2{Version: 2, IssuerID: p.issuerID, Sequence: sequence, PushedAt: at, Revoked: refs, Signature: placeholderV2Signature()}, p.issuerID, p.statusKey, p.signer)
	if err != nil {
		return V2StatusPublication{}, err
	}
	next := state
	next.Revoked = append(slices.Clone(state.Revoked), added...)
	slices.Sort(next.Revoked)
	out, err := p.list(ctx, next, sequence, at)
	if err != nil {
		return V2StatusPublication{}, err
	}
	out.Push = push
	return out, nil
}

func (p *V2StatusPublisher) checkState(state V2StatusPublisherState, at int64) error {
	if state.IssuerID != p.issuerID || state.StatusKeyID != p.statusKeyID || state.Sequence < 1 || state.Sequence > maxSafeInteger ||
		!validV2Timestamp(state.UpdatedAt) || !slices.IsSorted(state.Revoked) || len(slices.Compact(slices.Clone(state.Revoked))) != len(state.Revoked) {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 status publisher state does not belong to this issuer and status key, or its revoked set is not sorted and unique")
	}
	if at <= state.UpdatedAt {
		return fmt.Errorf("v2 status update time %d must be later than the last list's updated_at %d", at, state.UpdatedAt)
	}
	return nil
}

func (p *V2StatusPublisher) list(ctx context.Context, state V2StatusPublisherState, sequence, updatedAt int64) (V2StatusPublication, error) {
	nextUpdate, ok := checkedAddV2(updatedAt, p.lifetime)
	if !validV2Timestamp(updatedAt) || !ok || !validV2Timestamp(nextUpdate) {
		return V2StatusPublication{}, fmt.Errorf("v2 status list times leave the timestamp domain")
	}
	refs := make([]RevokedCertV2, len(state.Revoked))
	for i, id := range state.Revoked {
		refs[i] = RevokedCertV2{CertID: id}
	}
	list, err := SignRevocationListV2WithSigner(ctx, &RevocationListV2{Version: 2, IssuerID: p.issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: refs, Signature: placeholderV2Signature()}, p.issuerID, p.statusKey, p.signer)
	if err != nil {
		return V2StatusPublication{}, err
	}
	next := state
	next.Sequence, next.UpdatedAt = sequence, updatedAt
	next.Revoked = slices.Clone(state.Revoked)
	return V2StatusPublication{State: next, List: list}, nil
}
