package ratify

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// MaxCheckpointAcknowledgementBytesV2 bounds one encoded checkpoint
// acknowledgement. The four members fit far below it.
const MaxCheckpointAcknowledgementBytesV2 = 1024

var checkpointAcknowledgementV2Fields = []string{"entry_hash", "log_id", "sequence", "timestamp"}

type checkpointAcknowledgementWireV2 struct {
	EntryHash string `json:"entry_hash"`
	LogID     string `json:"log_id"`
	Sequence  int64  `json:"sequence"`
	Timestamp int64  `json:"timestamp"`
}

func validateV2CheckpointAcknowledgement(ack V2CheckpointAcknowledgement) error {
	if len(ack.LogID) != 32 || !lowerHexString(ack.LogID) || ack.Sequence < 1 || ack.Sequence > maxSafeInteger || len(ack.EntryHash) != 48 || !validV2Timestamp(ack.Timestamp) {
		return fmt.Errorf("wire v2: checkpoint acknowledgement log_id, sequence, entry_hash, or timestamp is invalid")
	}
	return nil
}

// EncodeV2CheckpointAcknowledgement returns the canonical JSON wire form of
// an independent checkpoint acknowledgement (SPEC-v2 §7.8):
// {"entry_hash":<base64 of 48 bytes>,"log_id":<32 lowercase hex>,"sequence":<integer>,"timestamp":<integer>}.
func EncodeV2CheckpointAcknowledgement(ack V2CheckpointAcknowledgement) ([]byte, error) {
	if err := validateV2CheckpointAcknowledgement(ack); err != nil {
		return nil, v2Classify(V2ErrMalformed, err)
	}
	return CanonicalJSON(checkpointAcknowledgementWireV2{EntryHash: base64.StdEncoding.EncodeToString(ack.EntryHash), LogID: ack.LogID, Sequence: ack.Sequence, Timestamp: ack.Timestamp})
}

// DecodeV2CheckpointAcknowledgement strictly decodes the acknowledgement wire
// form; it accepts only the canonical encoding.
func DecodeV2CheckpointAcknowledgement(data []byte) (_ V2CheckpointAcknowledgement, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "checkpoint acknowledgement", "MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2", MaxCheckpointAcknowledgementBytesV2); err != nil {
		return V2CheckpointAcknowledgement{}, err
	}
	if err := checkWireJSONV2(data, "entry_hash"); err != nil {
		return V2CheckpointAcknowledgement{}, err
	}
	if err := requireV2Fields(data, checkpointAcknowledgementV2Fields); err != nil {
		return V2CheckpointAcknowledgement{}, err
	}
	var wire checkpointAcknowledgementWireV2
	if err := strictUnmarshalV2(data, &wire); err != nil {
		return V2CheckpointAcknowledgement{}, err
	}
	hash, err := base64.StdEncoding.Strict().DecodeString(wire.EntryHash)
	if err != nil {
		return V2CheckpointAcknowledgement{}, fmt.Errorf("wire v2: checkpoint acknowledgement entry_hash is not canonical base64")
	}
	ack := V2CheckpointAcknowledgement{LogID: wire.LogID, Sequence: wire.Sequence, EntryHash: hash, Timestamp: wire.Timestamp}
	canonical, err := EncodeV2CheckpointAcknowledgement(ack)
	if err != nil {
		return V2CheckpointAcknowledgement{}, err
	}
	if !bytes.Equal(canonical, data) {
		return V2CheckpointAcknowledgement{}, fmt.Errorf("wire v2: checkpoint acknowledgement is not canonically encoded")
	}
	return ack, nil
}
