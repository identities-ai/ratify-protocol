package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// KeyRotationStatementV2 proves continuity from a caller-authenticated current
// key to a replacement key. It does not establish trust or mutate trust state.
type KeyRotationStatementV2 struct {
	Version               int             `json:"version"`
	AuthorityID           string          `json:"authority_id"`
	RecoveryEpoch         int64           `json:"recovery_epoch"`
	Role                  string          `json:"role"`
	Sequence              int64           `json:"sequence"`
	PreviousStatementHash []byte          `json:"previous_statement_hash"`
	OldKey                HybridPublicKey `json:"old_key"`
	NewKey                HybridPublicKey `json:"new_key"`
	OldKeyID              string          `json:"old_key_id"`
	NewKeyID              string          `json:"new_key_id"`
	IssuedAt              int64           `json:"issued_at"`
	NotBefore             int64           `json:"not_before"`
	OldSignature          HybridSignature `json:"old_signature"`
	NewSignature          HybridSignature `json:"new_signature"`
}

// KeyRotationV2State is caller-authenticated state immediately before the
// candidate statement. UsedKeyIDs must be the complete retained history for
// this authority, including CurrentKey's ID.
type KeyRotationV2State struct {
	AuthorityID   string
	RecoveryEpoch int64
	Role          string
	Sequence      int64
	HeadHash      []byte
	CurrentKey    HybridPublicKey
	UsedKeyIDs    []string
}

// keyRotationSignableV2 is kept in canonical JSON key order. Signatures are
// excluded because both keys sign this exact same body under distinct codes.
type keyRotationSignableV2 struct {
	AuthorityID           string          `json:"authority_id"`
	IssuedAt              int64           `json:"issued_at"`
	NewKey                HybridPublicKey `json:"new_key"`
	NewKeyID              string          `json:"new_key_id"`
	NotBefore             int64           `json:"not_before"`
	OldKey                HybridPublicKey `json:"old_key"`
	OldKeyID              string          `json:"old_key_id"`
	PreviousStatementHash []byte          `json:"previous_statement_hash"`
	RecoveryEpoch         int64           `json:"recovery_epoch"`
	Role                  string          `json:"role"`
	Sequence              int64           `json:"sequence"`
	Version               int             `json:"version"`
}

type keyRotationCanonicalV2 struct {
	AuthorityID           string          `json:"authority_id"`
	IssuedAt              int64           `json:"issued_at"`
	NewKey                HybridPublicKey `json:"new_key"`
	NewKeyID              string          `json:"new_key_id"`
	NewSignature          HybridSignature `json:"new_signature"`
	NotBefore             int64           `json:"not_before"`
	OldKey                HybridPublicKey `json:"old_key"`
	OldKeyID              string          `json:"old_key_id"`
	OldSignature          HybridSignature `json:"old_signature"`
	PreviousStatementHash []byte          `json:"previous_statement_hash"`
	RecoveryEpoch         int64           `json:"recovery_epoch"`
	Role                  string          `json:"role"`
	Sequence              int64           `json:"sequence"`
	Version               int             `json:"version"`
}

var keyRotationV2Fields = []string{
	"version", "authority_id", "recovery_epoch", "role", "sequence",
	"previous_statement_hash", "old_key", "new_key", "old_key_id", "new_key_id",
	"issued_at", "not_before", "old_signature", "new_signature",
}

func validateKeyRotationStatementV2(stmt *KeyRotationStatementV2, signatures bool) error {
	if stmt == nil || stmt.Version != 2 {
		return fmt.Errorf("wire v2: rotation version must be 2")
	}
	if len(stmt.AuthorityID) != 32 || !lowerHexString(stmt.AuthorityID) {
		return fmt.Errorf("wire v2: authority_id must be 32 lowercase hexadecimal characters")
	}
	if stmt.RecoveryEpoch <= 0 || stmt.RecoveryEpoch > maxSafeInteger || stmt.Sequence <= 0 || stmt.Sequence > maxSafeInteger {
		return fmt.Errorf("wire v2: recovery_epoch and sequence must be positive safe integers")
	}
	if stmt.IssuedAt < -maxSafeInteger || stmt.IssuedAt > maxSafeInteger || stmt.NotBefore < -maxSafeInteger || stmt.NotBefore > maxSafeInteger {
		return fmt.Errorf("wire v2: issued_at and not_before must be safe integers")
	}
	switch stmt.Role {
	case "organization_root", "issuer", "agent":
	default:
		return fmt.Errorf("wire v2: rotation role is invalid")
	}
	if len(stmt.PreviousStatementHash) != 48 {
		return fmt.Errorf("wire v2: previous_statement_hash must be 48 bytes")
	}
	if stmt.Sequence == 1 && !bytes.Equal(stmt.PreviousStatementHash, make([]byte, 48)) {
		return fmt.Errorf("wire v2: genesis rotation must use a zero previous_statement_hash")
	}
	if stmt.Sequence > 1 && bytes.Equal(stmt.PreviousStatementHash, make([]byte, 48)) {
		return fmt.Errorf("wire v2: non-genesis rotation must link to a prior statement")
	}
	if !validV2ID(stmt.OldKeyID) || !validV2ID(stmt.NewKeyID) {
		return fmt.Errorf("wire v2: old_key_id and new_key_id must be 64 lowercase hexadecimal characters")
	}
	oldID, err := keyIDV2(stmt.OldKey)
	if err != nil {
		return fmt.Errorf("wire v2: old_key: %w", err)
	}
	newID, err := keyIDV2(stmt.NewKey)
	if err != nil {
		return fmt.Errorf("wire v2: new_key: %w", err)
	}
	if oldID != stmt.OldKeyID || newID != stmt.NewKeyID {
		return v2Errorf(V2ErrKeyIDMismatch, "wire v2: rotation key IDs must match distinct complete keys")
	}
	if oldID == newID || equalHybridPublicKeys(stmt.OldKey, stmt.NewKey) {
		return fmt.Errorf("wire v2: rotation key IDs must match distinct complete keys")
	}
	if signatures {
		if err := validateHybridSignatureV2(stmt.OldSignature); err != nil {
			return fmt.Errorf("wire v2: old_signature: %w", err)
		}
		if err := validateHybridSignatureV2(stmt.NewSignature); err != nil {
			return fmt.Errorf("wire v2: new_signature: %w", err)
		}
	}
	return nil
}

func lowerHexString(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func keyRotationSignableBytesV2(stmt *KeyRotationStatementV2) ([]byte, error) {
	if err := validateKeyRotationStatementV2(stmt, false); err != nil {
		return nil, err
	}
	return CanonicalJSON(keyRotationSignableV2{
		AuthorityID: stmt.AuthorityID, IssuedAt: stmt.IssuedAt,
		NewKey: stmt.NewKey, NewKeyID: stmt.NewKeyID, NotBefore: stmt.NotBefore,
		OldKey: stmt.OldKey, OldKeyID: stmt.OldKeyID,
		PreviousStatementHash: stmt.PreviousStatementHash,
		RecoveryEpoch:         stmt.RecoveryEpoch, Role: stmt.Role,
		Sequence: stmt.Sequence, Version: stmt.Version,
	})
}

// StatementBodyDigestV2 hashes the canonical signable projection for a v2
// rotation, witness, or verification-receipt object. The caller supplies the
// object-specific projection with signature fields excluded. Each supported
// object body is schema-validated before its digest is computed.
func StatementBodyDigestV2(objectType uint16, signableBody []byte) ([]byte, error) {
	code := v2ObjectType(objectType)
	if code != v2KeyRotationAuthorization && code != v2WitnessEntry && code != v2VerificationReceipt {
		return nil, fmt.Errorf("object type 0x%04x does not use StatementBodyDigestV2", objectType)
	}
	var wireErr error
	if code == v2VerificationReceipt {
		wireErr = checkWireJSONV2WithTextTopLevel(signableBody, map[string]bool{"previous_receipt_hash": true}, map[string]bool{"bundle_hash": true})
	} else {
		wireErr = checkWireJSONV2(signableBody, "previous_statement_hash", "delegation_digest", "previous_receipt_hash")
	}
	if wireErr != nil {
		return nil, fmt.Errorf("signable body: %w", wireErr)
	}
	var value any
	if err := json.Unmarshal(signableBody, &value); err != nil {
		return nil, fmt.Errorf("signable body: %w", err)
	}
	if code != v2KeyRotationAuthorization {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(signableBody, &fields); err != nil {
			return nil, fmt.Errorf("signable body: %w", err)
		}
		for _, signatureField := range []string{"signature", "old_signature", "new_signature"} {
			if _, exists := fields[signatureField]; exists {
				return nil, fmt.Errorf("signable body must exclude %q", signatureField)
			}
		}
	}
	canonical, err := CanonicalJSON(value)
	if err != nil || !bytes.Equal(signableBody, canonical) {
		return nil, fmt.Errorf("signable body must use RatifyCanonicalJSON")
	}
	if code == v2KeyRotationAuthorization {
		if err := validateKeyRotationSignableBodyV2(signableBody); err != nil {
			return nil, err
		}
	} else if code == v2WitnessEntry {
		if err := validateWitnessSignableBodyV2(signableBody); err != nil {
			return nil, err
		}
	} else if code == v2VerificationReceipt {
		if err := validateVerificationReceiptSignableV2(signableBody); err != nil {
			return nil, err
		}
	}
	h := sha512.New384()
	h.Write([]byte("ratify-protocol-statement-body-v2\x00"))
	var typeCode [2]byte
	binary.BigEndian.PutUint16(typeCode[:], objectType)
	h.Write(typeCode[:])
	h.Write(signableBody)
	return h.Sum(nil), nil
}

func validateKeyRotationSignableBodyV2(body []byte) error {
	names := []string{"authority_id", "issued_at", "new_key", "new_key_id", "not_before", "old_key", "old_key_id", "previous_statement_hash", "recovery_epoch", "role", "sequence", "version"}
	if err := requireV2Fields(body, names); err != nil {
		return fmt.Errorf("rotation signable body: %w", err)
	}
	var signable keyRotationSignableV2
	if err := strictUnmarshal(body, &signable); err != nil {
		return fmt.Errorf("rotation signable body: %w", err)
	}
	canonical, err := CanonicalJSON(signable)
	if err != nil || !bytes.Equal(body, canonical) {
		return fmt.Errorf("rotation signable body must use RatifyCanonicalJSON")
	}
	stmt := &KeyRotationStatementV2{
		Version: signable.Version, AuthorityID: signable.AuthorityID,
		RecoveryEpoch: signable.RecoveryEpoch, Role: signable.Role, Sequence: signable.Sequence,
		PreviousStatementHash: signable.PreviousStatementHash, OldKey: signable.OldKey,
		NewKey: signable.NewKey, OldKeyID: signable.OldKeyID, NewKeyID: signable.NewKeyID,
		IssuedAt: signable.IssuedAt, NotBefore: signable.NotBefore,
	}
	if err := validateKeyRotationStatementV2(stmt, false); err != nil {
		return fmt.Errorf("rotation signable body: %w", err)
	}
	return nil
}

// KeyRotationStatementV2Digest returns StatementBodyDigestV2(0x0004, body).
// Both signatures are excluded so randomized signature bytes cannot fork the
// rotation chain.
func KeyRotationStatementV2Digest(stmt *KeyRotationStatementV2) ([]byte, error) {
	body, err := keyRotationSignableBytesV2(stmt)
	if err != nil {
		return nil, err
	}
	return StatementBodyDigestV2(uint16(v2KeyRotationAuthorization), body)
}

// DecodeKeyRotationStatementV2 strictly decodes one v2 rotation statement.
func DecodeKeyRotationStatementV2(data []byte) (_ *KeyRotationStatementV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "rotation statement", "MAX_KEY_ROTATION_STATEMENT_BYTES_V2", MaxKeyRotationStatementBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2(data, "previous_statement_hash"); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, keyRotationV2Fields); err != nil {
		return nil, err
	}
	var stmt KeyRotationStatementV2
	if err := strictUnmarshal(data, &stmt); err != nil {
		return nil, err
	}
	if err := validateKeyRotationStatementV2(&stmt, true); err != nil {
		return nil, err
	}
	return &stmt, nil
}

// EncodeKeyRotationStatementV2 returns the strict v2 wire representation.
func EncodeKeyRotationStatementV2(stmt *KeyRotationStatementV2) ([]byte, error) {
	if err := validateKeyRotationStatementV2(stmt, true); err != nil {
		return nil, err
	}
	return CanonicalJSON(keyRotationCanonicalV2{
		AuthorityID: stmt.AuthorityID, IssuedAt: stmt.IssuedAt,
		NewKey: stmt.NewKey, NewKeyID: stmt.NewKeyID, NewSignature: stmt.NewSignature,
		NotBefore: stmt.NotBefore, OldKey: stmt.OldKey, OldKeyID: stmt.OldKeyID,
		OldSignature: stmt.OldSignature, PreviousStatementHash: stmt.PreviousStatementHash,
		RecoveryEpoch: stmt.RecoveryEpoch, Role: stmt.Role, Sequence: stmt.Sequence,
		Version: stmt.Version,
	})
}

// SignKeyRotationStatementV2 returns a signed copy. Callers remain responsible
// for authenticating the current key and validating rotation-chain state.
func SignKeyRotationStatementV2(stmt *KeyRotationStatementV2, oldKey, newKey HybridPrivateKey) (*KeyRotationStatementV2, error) {
	if err := validateKeyRotationStatementV2(stmt, false); err != nil {
		return nil, err
	}
	if err := validateV2PrivateKey(oldKey); err != nil {
		return nil, fmt.Errorf("old rotation key: %w", err)
	}
	if err := validateV2PrivateKey(newKey); err != nil {
		return nil, fmt.Errorf("new rotation key: %w", err)
	}
	oldPub := oldKey.Public()
	newPub := newKey.Public()
	if !equalHybridPublicKeys(oldPub, stmt.OldKey) || !equalHybridPublicKeys(newPub, stmt.NewKey) {
		return nil, fmt.Errorf("rotation private keys do not match the statement keys")
	}
	signable, err := keyRotationSignableBytesV2(stmt)
	if err != nil {
		return nil, err
	}
	oldSignature, err := signV2Statement(v2KeyRotationAuthorization, signable, oldKey)
	if err != nil {
		return nil, err
	}
	newSignature, err := signV2Statement(v2KeyRotationProofOfPossession, signable, newKey)
	if err != nil {
		return nil, err
	}
	result := *stmt
	result.PreviousStatementHash = bytes.Clone(stmt.PreviousStatementHash)
	result.OldKey = HybridPublicKey{Ed25519: bytes.Clone(stmt.OldKey.Ed25519), MLDSA65: bytes.Clone(stmt.OldKey.MLDSA65)}
	result.NewKey = HybridPublicKey{Ed25519: bytes.Clone(stmt.NewKey.Ed25519), MLDSA65: bytes.Clone(stmt.NewKey.MLDSA65)}
	result.OldSignature = oldSignature
	result.NewSignature = newSignature
	return &result, nil
}

// VerifyKeyRotationStatementV2 checks the candidate signatures and linkage
// against caller-authenticated state. A nil result is not acceptance: callers
// must atomically persist the new head and used-key history, and handle
// idempotency, forks, rollback, and recovery in a durable journal.
func VerifyKeyRotationStatementV2(stmt *KeyRotationStatementV2, state KeyRotationV2State, nowUnix, futureSkew int64) error {
	if err := validateKeyRotationStatementV2(stmt, true); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	currentID, err := keyIDV2(state.CurrentKey)
	if err != nil {
		return v2Errorf(V2ErrConfigurationInvalid, "caller state current key: %w", err)
	}
	if state.Sequence < 0 || state.Sequence >= maxSafeInteger || state.RecoveryEpoch <= 0 || state.RecoveryEpoch > maxSafeInteger || len(state.HeadHash) != 48 {
		return v2Errorf(V2ErrConfigurationInvalid, "caller rotation state is invalid")
	}
	if state.Sequence == 0 && !bytes.Equal(state.HeadHash, make([]byte, 48)) {
		return v2Errorf(V2ErrConfigurationInvalid, "caller genesis state must have a zero head hash")
	}
	if state.Sequence > 0 && bytes.Equal(state.HeadHash, make([]byte, 48)) {
		return v2Errorf(V2ErrConfigurationInvalid, "caller non-genesis state must have a linked head hash")
	}
	if len(state.UsedKeyIDs) == 0 {
		return v2Errorf(V2ErrConfigurationInvalid, "caller state must include retained used key IDs")
	}
	usedKeyIDs := make(map[string]struct{}, len(state.UsedKeyIDs))
	for _, id := range state.UsedKeyIDs {
		if !validV2ID(id) {
			return v2Errorf(V2ErrConfigurationInvalid, "caller state contains an invalid used key ID")
		}
		if _, exists := usedKeyIDs[id]; exists {
			return v2Errorf(V2ErrConfigurationInvalid, "caller state contains duplicate used key IDs")
		}
		usedKeyIDs[id] = struct{}{}
	}
	if _, ok := usedKeyIDs[currentID]; !ok {
		return v2Errorf(V2ErrConfigurationInvalid, "caller used-key history does not contain the current key")
	}
	if _, ok := usedKeyIDs[stmt.NewKeyID]; ok {
		return v2Errorf(V2ErrRotationKeyReused, "rotation replacement key was already used by this authority")
	}
	if futureSkew < 0 || nowUnix < -maxSafeInteger || nowUnix > maxSafeInteger || futureSkew > maxSafeInteger {
		return v2Errorf(V2ErrConfigurationInvalid, "rotation verification clock inputs are outside safe bounds")
	}
	if nowUnix > maxSafeInteger-futureSkew {
		futureSkew = maxSafeInteger - nowUnix
	}
	if !equalHybridPublicKeys(stmt.OldKey, state.CurrentKey) || stmt.AuthorityID != state.AuthorityID || stmt.RecoveryEpoch != state.RecoveryEpoch || stmt.Role != state.Role || stmt.Sequence != state.Sequence+1 || !bytes.Equal(stmt.PreviousStatementHash, state.HeadHash) {
		return v2Errorf(V2ErrRotationStateMismatch, "rotation statement does not extend the caller-authenticated authority state")
	}
	if stmt.IssuedAt > nowUnix+futureSkew || stmt.NotBefore > nowUnix+futureSkew {
		return v2Errorf(V2ErrRotationFutureDated, "rotation statement is future-dated")
	}
	signable, err := keyRotationSignableBytesV2(stmt)
	if err != nil {
		return err
	}
	if err := verifyV2Statement(v2KeyRotationAuthorization, signable, stmt.OldSignature, state.CurrentKey); err != nil {
		return fmt.Errorf("old-key rotation authorization: %w", err)
	}
	if err := verifyV2Statement(v2KeyRotationProofOfPossession, signable, stmt.NewSignature, stmt.NewKey); err != nil {
		return fmt.Errorf("new-key proof of possession: %w", err)
	}
	return nil
}
