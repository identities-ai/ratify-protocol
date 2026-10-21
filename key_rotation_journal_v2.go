package ratify

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	// ErrKeyRotationForkV2 reports two different validly signed rotation bodies
	// at one accepted sequence. The returned journal is frozen and the caller
	// must persist it before reporting the error.
	ErrKeyRotationForkV2 = errors.New("key rotation fork")
	// ErrKeyRotationFrozenV2 reports an authority frozen by a detected fork.
	ErrKeyRotationFrozenV2 = errors.New("key rotation authority is frozen")
)

// KeyRotationV2AcceptedEntry records one accepted statement in the current
// recovery epoch. OldKey is retained so a later conflicting statement at the
// same sequence can be authenticated before it is declared a fork.
type KeyRotationV2AcceptedEntry struct {
	Sequence   int64
	BodyDigest []byte
	OldKey     HybridPublicKey
}

// KeyRotationV2Journal is the caller-persisted continuity state for one
// authority. Accepted holds sequences 1..State.Sequence of the current
// recovery epoch. UsedKeyIDs in State spans every epoch and is never reset.
type KeyRotationV2Journal struct {
	State    KeyRotationV2State
	Accepted []KeyRotationV2AcceptedEntry
	Frozen   bool
}

// NewKeyRotationV2Journal creates the SPEC-v2 §5.4 initial state from a
// caller-authenticated genesis key and recovery epoch.
func NewKeyRotationV2Journal(authorityID string, recoveryEpoch int64, role string, genesisKey HybridPublicKey) (KeyRotationV2Journal, error) {
	genesisID, err := keyIDV2(genesisKey)
	if err != nil {
		return KeyRotationV2Journal{}, v2Errorf(V2ErrConfigurationInvalid, "rotation genesis key: %w", err)
	}
	if len(authorityID) != 32 || !lowerHexString(authorityID) || recoveryEpoch <= 0 || recoveryEpoch > maxSafeInteger {
		return KeyRotationV2Journal{}, v2Errorf(V2ErrConfigurationInvalid, "rotation authority or recovery epoch is invalid")
	}
	switch role {
	case "organization_root", "issuer", "agent":
	default:
		return KeyRotationV2Journal{}, v2Errorf(V2ErrConfigurationInvalid, "rotation role is invalid")
	}
	return KeyRotationV2Journal{State: KeyRotationV2State{
		AuthorityID: authorityID, RecoveryEpoch: recoveryEpoch, Role: role,
		HeadHash: make([]byte, 48), CurrentKey: cloneHybridPublicKeyV2(genesisKey),
		UsedKeyIDs: []string{genesisID},
	}}, nil
}

// AcceptKeyRotationStatementV2 implements AcceptRotation from SPEC-v2 §5.4.
// It returns Appended with the advanced journal, Replay with the unchanged
// journal for a statement whose body digest equals the accepted digest at its
// sequence (new signature bytes over that body are the same statement), or an
// error. A validly signed different body at an accepted sequence returns
// ErrKeyRotationForkV2 together with a frozen journal the caller must persist.
// Any other error leaves the journal unchanged.
func AcceptKeyRotationStatementV2(stmt *KeyRotationStatementV2, journal KeyRotationV2Journal, nowUnix, futureSkew int64) (KeyRotationV2Journal, WitnessEntryV2Result, error) {
	if err := validateKeyRotationStatementV2(stmt, true); err != nil {
		return journal, 0, v2Classify(V2ErrMalformed, err)
	}
	if int64(len(journal.Accepted)) != journal.State.Sequence {
		return journal, 0, v2Errorf(V2ErrConfigurationInvalid, "rotation journal accepted history does not match its sequence")
	}
	if journal.Frozen {
		return journal, 0, fmt.Errorf("%w: authority %s requires recovery", ErrKeyRotationFrozenV2, journal.State.AuthorityID)
	}
	state := journal.State
	if stmt.AuthorityID != state.AuthorityID || stmt.RecoveryEpoch != state.RecoveryEpoch || stmt.Role != state.Role {
		return journal, 0, v2Errorf(V2ErrRotationStateMismatch, "rotation statement authority, recovery epoch, or role does not match caller state")
	}
	if stmt.Sequence <= state.Sequence {
		accepted := journal.Accepted[stmt.Sequence-1]
		if accepted.Sequence != stmt.Sequence || !equalHybridPublicKeys(stmt.OldKey, accepted.OldKey) {
			return journal, 0, v2Errorf(V2ErrRotationStateMismatch, "rotation statement old key does not match the key accepted at sequence %d", stmt.Sequence)
		}
		signable, err := keyRotationSignableBytesV2(stmt)
		if err != nil {
			return journal, 0, v2Classify(V2ErrMalformed, err)
		}
		if err := verifyV2Statement(v2KeyRotationAuthorization, signable, stmt.OldSignature, accepted.OldKey); err != nil {
			return journal, 0, fmt.Errorf("old-key rotation authorization: %w", err)
		}
		if err := verifyV2Statement(v2KeyRotationProofOfPossession, signable, stmt.NewSignature, stmt.NewKey); err != nil {
			return journal, 0, fmt.Errorf("new-key proof of possession: %w", err)
		}
		digest, err := StatementBodyDigestV2(uint16(v2KeyRotationAuthorization), signable)
		if err != nil {
			return journal, 0, v2Classify(V2ErrMalformed, err)
		}
		if bytes.Equal(digest, accepted.BodyDigest) {
			return journal, WitnessEntryV2Replay, nil
		}
		frozen := cloneKeyRotationV2Journal(journal)
		frozen.Frozen = true
		return frozen, 0, fmt.Errorf("%w at sequence %d for authority %s", ErrKeyRotationForkV2, stmt.Sequence, state.AuthorityID)
	}
	if err := VerifyKeyRotationStatementV2(stmt, state, nowUnix, futureSkew); err != nil {
		return journal, 0, err
	}
	digest, err := KeyRotationStatementV2Digest(stmt)
	if err != nil {
		return journal, 0, v2Classify(V2ErrMalformed, err)
	}
	next := cloneKeyRotationV2Journal(journal)
	next.Accepted = append(next.Accepted, KeyRotationV2AcceptedEntry{Sequence: stmt.Sequence, BodyDigest: digest, OldKey: cloneHybridPublicKeyV2(stmt.OldKey)})
	next.State.Sequence = stmt.Sequence
	next.State.HeadHash = bytes.Clone(digest)
	next.State.CurrentKey = cloneHybridPublicKeyV2(stmt.NewKey)
	next.State.UsedKeyIDs = append(next.State.UsedKeyIDs, stmt.NewKeyID)
	return next, WitnessEntryV2Appended, nil
}

// RecoverKeyRotationV2 applies a root-authorized recovery supplied by the
// caller's independently authenticated control plane: it increments the
// recovery epoch, anchors a new genesis to a never-used key, and preserves the
// complete used-key history. Resetting without an epoch increase is rejected.
func RecoverKeyRotationV2(journal KeyRotationV2Journal, newRecoveryEpoch int64, newGenesisKey HybridPublicKey) (KeyRotationV2Journal, error) {
	newID, err := keyIDV2(newGenesisKey)
	if err != nil {
		return journal, v2Errorf(V2ErrRotationRecoveryInvalid, "recovery genesis key: %w", err)
	}
	if newRecoveryEpoch <= journal.State.RecoveryEpoch || newRecoveryEpoch > maxSafeInteger {
		return journal, v2Errorf(V2ErrRotationRecoveryInvalid, "rotation recovery must increase the recovery epoch")
	}
	for _, used := range journal.State.UsedKeyIDs {
		if used == newID {
			return journal, v2Errorf(V2ErrRotationRecoveryInvalid, "rotation recovery cannot anchor a previously used key")
		}
	}
	next := cloneKeyRotationV2Journal(journal)
	next.State.RecoveryEpoch = newRecoveryEpoch
	next.State.Sequence = 0
	next.State.HeadHash = make([]byte, 48)
	next.State.CurrentKey = cloneHybridPublicKeyV2(newGenesisKey)
	next.State.UsedKeyIDs = append(next.State.UsedKeyIDs, newID)
	next.Accepted = nil
	next.Frozen = false
	return next, nil
}

func cloneHybridPublicKeyV2(key HybridPublicKey) HybridPublicKey {
	return HybridPublicKey{Ed25519: bytes.Clone(key.Ed25519), MLDSA65: bytes.Clone(key.MLDSA65)}
}

func cloneKeyRotationV2Journal(journal KeyRotationV2Journal) KeyRotationV2Journal {
	next := journal
	next.State.HeadHash = bytes.Clone(journal.State.HeadHash)
	next.State.CurrentKey = cloneHybridPublicKeyV2(journal.State.CurrentKey)
	next.State.UsedKeyIDs = append([]string(nil), journal.State.UsedKeyIDs...)
	next.Accepted = make([]KeyRotationV2AcceptedEntry, len(journal.Accepted))
	for i, entry := range journal.Accepted {
		next.Accepted[i] = KeyRotationV2AcceptedEntry{Sequence: entry.Sequence, BodyDigest: bytes.Clone(entry.BodyDigest), OldKey: cloneHybridPublicKeyV2(entry.OldKey)}
	}
	return next
}
