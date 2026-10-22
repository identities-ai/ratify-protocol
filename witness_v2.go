package ratify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

var (
	ErrWitnessLogFork   = errors.New("witness log fork")
	ErrWitnessLogGap    = errors.New("witness log sequence gap")
	ErrWitnessLogOrphan = errors.New("orphaned witness entry")
	ErrWitnessLogFrozen = errors.New("witness log is frozen")
)

// WitnessEntryV2Result distinguishes a newly appendable entry from an
// idempotent replay of an entry already present in caller-authenticated state.
type WitnessEntryV2Result uint8

const (
	WitnessEntryV2Appended WitnessEntryV2Result = iota + 1
	WitnessEntryV2Replay
)

// WitnessEntryV2 is one signed entry in a caller-operated v2 witness log.
// Trust in the witness key and durable log state remain caller responsibilities.
type WitnessEntryV2 struct {
	Version   int             `json:"version"`
	LogID     string          `json:"log_id"`
	Sequence  int64           `json:"sequence"`
	PrevHash  []byte          `json:"prev_hash"`
	EntryData []byte          `json:"entry_data"`
	Timestamp int64           `json:"timestamp"`
	WitnessID string          `json:"witness_id"`
	Signature HybridSignature `json:"signature"`
}

// WitnessV2Head is caller-authenticated log state before an entry. Operators
// retain every accepted sequence digest for historical replay and fork checks.
// State and Frozen transitions must be persisted atomically; this package has
// no durable storage.
type WitnessV2Head struct {
	LogID           string
	Sequence        int64
	HeadHash        []byte
	AcceptedDigests map[int64][]byte
	Frozen          bool
}

type witnessEntrySignableV2 struct {
	EntryData []byte `json:"entry_data"`
	LogID     string `json:"log_id"`
	PrevHash  []byte `json:"prev_hash"`
	Sequence  int64  `json:"sequence"`
	Timestamp int64  `json:"timestamp"`
	Version   int    `json:"version"`
	WitnessID string `json:"witness_id"`
}

type witnessEntryWireV2 struct {
	EntryData []byte          `json:"entry_data"`
	LogID     string          `json:"log_id"`
	PrevHash  []byte          `json:"prev_hash"`
	Sequence  int64           `json:"sequence"`
	Signature HybridSignature `json:"signature"`
	Timestamp int64           `json:"timestamp"`
	Version   int             `json:"version"`
	WitnessID string          `json:"witness_id"`
}

var witnessEntryV2Fields = []string{"version", "log_id", "sequence", "prev_hash", "entry_data", "timestamp", "witness_id", "signature"}

func validateWitnessSignableBodyV2(body []byte) error {
	names := []string{"entry_data", "log_id", "prev_hash", "sequence", "timestamp", "version", "witness_id"}
	if err := requireV2Fields(body, names); err != nil {
		return fmt.Errorf("witness signable body: %w", err)
	}
	var signable witnessEntrySignableV2
	if err := strictUnmarshal(body, &signable); err != nil {
		return fmt.Errorf("witness signable body: %w", err)
	}
	canonical, err := CanonicalJSON(signable)
	if err != nil || !bytes.Equal(body, canonical) {
		return fmt.Errorf("witness signable body must use RatifyCanonicalJSON")
	}
	entry := &WitnessEntryV2{
		Version: signable.Version, LogID: signable.LogID, Sequence: signable.Sequence,
		PrevHash: signable.PrevHash, EntryData: signable.EntryData,
		Timestamp: signable.Timestamp, WitnessID: signable.WitnessID,
	}
	return validateWitnessEntryV2(entry, false)
}

func validateWitnessEntryV2(entry *WitnessEntryV2, signature bool) error {
	if entry == nil || entry.Version != 2 {
		return fmt.Errorf("wire v2: witness entry version must be 2")
	}
	if len(entry.LogID) != 32 || !lowerHexString(entry.LogID) {
		return fmt.Errorf("wire v2: log_id must be 32 lowercase hexadecimal characters")
	}
	if entry.Sequence <= 0 || entry.Sequence > maxSafeInteger || !validV2Timestamp(entry.Timestamp) {
		return fmt.Errorf("wire v2: sequence and timestamp must be safe integers")
	}
	if len(entry.PrevHash) != 48 {
		return fmt.Errorf("wire v2: prev_hash must be 48 bytes")
	}
	if entry.EntryData == nil {
		return fmt.Errorf("wire v2: entry_data must be a base64 byte string, not null")
	}
	if len(entry.EntryData) > MaxWitnessEntryDataBytesV2 {
		return fmt.Errorf("wire v2: entry_data exceeds MAX_WITNESS_ENTRY_DATA_BYTES_V2 (%d bytes)", MaxWitnessEntryDataBytesV2)
	}
	if entry.Sequence == 1 && !bytes.Equal(entry.PrevHash, make([]byte, 48)) {
		return fmt.Errorf("wire v2: genesis witness entry must use a zero prev_hash")
	}
	if entry.Sequence > 1 && bytes.Equal(entry.PrevHash, make([]byte, 48)) {
		return fmt.Errorf("wire v2: non-genesis witness entry must link to a prior entry")
	}
	if !validV2ID(entry.WitnessID) {
		return fmt.Errorf("wire v2: witness_id must be a 64-character lowercase hexadecimal v2 key ID")
	}
	if signature {
		return validateHybridSignatureV2(entry.Signature)
	}
	return nil
}

func witnessEntrySignableBytesV2(entry *WitnessEntryV2) ([]byte, error) {
	if err := validateWitnessEntryV2(entry, false); err != nil {
		return nil, err
	}
	return CanonicalJSON(witnessEntrySignableV2{
		EntryData: entry.EntryData, LogID: entry.LogID, PrevHash: entry.PrevHash,
		Sequence: entry.Sequence, Timestamp: entry.Timestamp, Version: entry.Version,
		WitnessID: entry.WitnessID,
	})
}

// WitnessEntryV2Digest returns StatementBodyDigestV2(0x0006, signable body).
func WitnessEntryV2Digest(entry *WitnessEntryV2) ([]byte, error) {
	body, err := witnessEntrySignableBytesV2(entry)
	if err != nil {
		return nil, err
	}
	return StatementBodyDigestV2(uint16(v2WitnessEntry), body)
}

// EncodeWitnessEntryV2 returns the canonical v2 wire representation.
func EncodeWitnessEntryV2(entry *WitnessEntryV2) ([]byte, error) {
	if err := validateWitnessEntryV2(entry, true); err != nil {
		return nil, err
	}
	wire, err := CanonicalJSON(witnessEntryWireV2{
		EntryData: entry.EntryData, LogID: entry.LogID, PrevHash: entry.PrevHash,
		Sequence: entry.Sequence, Signature: entry.Signature, Timestamp: entry.Timestamp,
		Version: entry.Version, WitnessID: entry.WitnessID,
	})
	if err != nil {
		return nil, err
	}
	if err := checkV2WireSize(wire, "witness entry", "MAX_WITNESS_ENTRY_BYTES_V2", MaxWitnessEntryBytesV2); err != nil {
		return nil, err
	}
	return wire, nil
}

// DecodeWitnessEntryV2 strictly decodes one canonical v2 witness entry.
func DecodeWitnessEntryV2(data []byte) (_ *WitnessEntryV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "witness entry", "MAX_WITNESS_ENTRY_BYTES_V2", MaxWitnessEntryBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2(data); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, witnessEntryV2Fields); err != nil {
		return nil, err
	}
	var entry WitnessEntryV2
	if err := strictUnmarshal(data, &entry); err != nil {
		return nil, err
	}
	if err := validateWitnessEntryV2(&entry, true); err != nil {
		return nil, err
	}
	canonical, err := EncodeWitnessEntryV2(&entry)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, fmt.Errorf("wire v2: witness entry is not canonical Ratify JSON")
	}
	return &entry, nil
}

// SignWitnessEntryV2 signs the v2 witness body with object code 0x0006.
func SignWitnessEntryV2(entry *WitnessEntryV2, witnessPrivate HybridPrivateKey) (*WitnessEntryV2, error) {
	return SignWitnessEntryV2WithSigner(context.Background(), entry, localSignerV2{witnessPrivate})
}

// SignWitnessEntryV2WithSigner is SignWitnessEntryV2 with an external signer
// whose key ID must equal witness_id.
func SignWitnessEntryV2WithSigner(ctx context.Context, entry *WitnessEntryV2, signer SignerV2) (*WitnessEntryV2, error) {
	if err := validateWitnessEntryV2(entry, false); err != nil {
		return nil, err
	}
	witnessPublic, err := signerPublicKeyV2(signer)
	if err != nil {
		return nil, err
	}
	witnessID, err := keyIDV2(witnessPublic)
	if err != nil || witnessID != entry.WitnessID {
		return nil, fmt.Errorf("witness_id does not match signing key")
	}
	body, err := witnessEntrySignableBytesV2(entry)
	if err != nil {
		return nil, err
	}
	signature, err := signV2StatementWithSigner(ctx, v2WitnessEntry, body, signer, witnessPublic)
	if err != nil {
		return nil, err
	}
	result := *entry
	result.PrevHash = bytes.Clone(entry.PrevHash)
	result.EntryData = bytes.Clone(entry.EntryData)
	result.Signature = signature
	if _, err := EncodeWitnessEntryV2(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyWitnessEntryV2 checks key identity, expected log position and both
// signatures against caller-authenticated log state and witness key. An
// ErrWitnessLogFork result is authenticated fork evidence; the caller must
// durably freeze that log ID. Exact accepted entries are idempotent. The
// caller remains responsible for atomically storing a newly accepted digest.
// The result is Replay for an exact accepted entry and Appended for the next
// valid entry. Verification itself never mutates caller state. Validation of
// the caller-supplied history is O(number of accepted entries).
func VerifyWitnessEntryV2(entry *WitnessEntryV2, head WitnessV2Head, witnessPublic HybridPublicKey) (WitnessEntryV2Result, error) {
	if err := validateWitnessEntryV2(entry, true); err != nil {
		return 0, v2Classify(V2ErrMalformed, err)
	}
	if _, err := EncodeWitnessEntryV2(entry); err != nil {
		return 0, v2Classify(V2ErrMalformed, err)
	}
	if len(head.LogID) != 32 || !lowerHexString(head.LogID) || head.Sequence < 0 || head.Sequence > maxSafeInteger || len(head.HeadHash) != 48 {
		return 0, v2Errorf(V2ErrConfigurationInvalid, "caller witness head is invalid")
	}
	if head.Sequence == 0 && (!bytes.Equal(head.HeadHash, make([]byte, 48)) || len(head.AcceptedDigests) != 0) || head.Sequence > 0 && bytes.Equal(head.HeadHash, make([]byte, 48)) {
		return 0, v2Errorf(V2ErrConfigurationInvalid, "caller witness head has inconsistent genesis state")
	}
	if head.Sequence > 0 && int64(len(head.AcceptedDigests)) != head.Sequence {
		return 0, v2Errorf(V2ErrConfigurationInvalid, "caller witness head is missing accepted sequence digests")
	}
	if head.Sequence > 0 && !bytes.Equal(head.AcceptedDigests[head.Sequence], head.HeadHash) {
		return 0, v2Errorf(V2ErrConfigurationInvalid, "caller witness head hash does not match its accepted digest history")
	}
	for sequence, acceptedDigest := range head.AcceptedDigests {
		if sequence <= 0 || sequence > head.Sequence || len(acceptedDigest) != 48 {
			return 0, v2Errorf(V2ErrConfigurationInvalid, "caller witness head contains invalid accepted digest history")
		}
	}
	witnessID, err := keyIDV2(witnessPublic)
	if err != nil {
		return 0, err
	}
	if entry.WitnessID != witnessID || entry.LogID != head.LogID {
		return 0, v2Errorf(V2ErrLogStateMismatch, "witness entry key or log ID does not match caller-authenticated state")
	}
	body, err := witnessEntrySignableBytesV2(entry)
	if err != nil {
		return 0, err
	}
	if err := verifyV2Statement(v2WitnessEntry, body, entry.Signature, witnessPublic); err != nil {
		return 0, err
	}
	digest, err := WitnessEntryV2Digest(entry)
	if err != nil {
		return 0, err
	}
	if entry.Sequence <= head.Sequence {
		acceptedDigest := head.AcceptedDigests[entry.Sequence]
		if bytes.Equal(acceptedDigest, digest) {
			return WitnessEntryV2Replay, nil
		}
		return 0, fmt.Errorf("%w at sequence %d; caller must freeze log %s", ErrWitnessLogFork, entry.Sequence, head.LogID)
	}
	if head.Frozen {
		return 0, fmt.Errorf("%w", ErrWitnessLogFrozen)
	}
	if entry.Sequence > head.Sequence+1 {
		return 0, fmt.Errorf("%w: got %d after %d", ErrWitnessLogGap, entry.Sequence, head.Sequence)
	}
	if entry.Sequence != head.Sequence+1 || !bytes.Equal(entry.PrevHash, head.HeadHash) {
		return 0, fmt.Errorf("%w: entry does not link to the current head", ErrWitnessLogOrphan)
	}
	return WitnessEntryV2Appended, nil
}
