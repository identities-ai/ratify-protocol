package ratify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Status evidence batch wire form (SPEC-v2 §6.5 step 3). A status provider
// that crosses a process or language boundary returns this JSON array:
//
//	[{"object":<complete signed RevocationList or RevocationPush>,"object_type_code":3|5}, ...]
//
// with at most MaxStatusEvidenceBatchObjectsV2 entries and at most
// MaxStatusEvidenceBatchBytesV2 encoded bytes. Each entry has exactly these two
// members. The batch may be empty. The canonical encoding sorts each entry's
// members and re-encodes each object canonically; a decoder accepts any
// strict JSON spelling and keeps each object's exact received bytes, which
// the verifier then decodes and authenticates under the object's own limits.
// The strict JSON value model applies to the whole document, nested objects
// included; each object's schema (member names, nulls, byte-field
// spellings, required members) is checked only when it is decoded under its
// code (SPEC-v2 §2.1, §6.5).

// EncodeV2StatusEvidenceBatch returns the canonical JSON encoding of batch.
// Every object must decode strictly under its code.
func EncodeV2StatusEvidenceBatch(batch V2StatusEvidenceBatch) ([]byte, error) {
	if len(batch.Objects) > MaxStatusEvidenceBatchObjectsV2 {
		return nil, v2Errorf(V2ErrMalformed, "v2 status batch exceeds %d objects", MaxStatusEvidenceBatchObjectsV2)
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, object := range batch.Objects {
		var canonical []byte
		var err error
		switch object.ObjectType {
		case uint16(v2RevocationList):
			var list *RevocationListV2
			if list, err = DecodeRevocationListV2(object.Wire); err == nil {
				canonical, err = EncodeRevocationListV2(list)
			}
		case uint16(v2RevocationPush):
			var push *RevocationPushV2
			if push, err = DecodeRevocationPushV2(object.Wire); err == nil {
				canonical, err = EncodeRevocationPushV2(push)
			}
		default:
			err = fmt.Errorf("v2 status batch object type 0x%04x is not 3 or 5", object.ObjectType)
		}
		if err != nil {
			return nil, v2Classify(V2ErrMalformed, err)
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"object":`)
		buf.Write(canonical)
		buf.WriteString(`,"object_type_code":`)
		buf.WriteString(strconv.Itoa(int(object.ObjectType)))
		buf.WriteByte('}')
	}
	buf.WriteByte(']')
	if buf.Len() > MaxStatusEvidenceBatchBytesV2 {
		return nil, v2Errorf(V2ErrMalformed, "v2 status batch exceeds %d bytes", MaxStatusEvidenceBatchBytesV2)
	}
	return buf.Bytes(), nil
}

// DecodeV2StatusEvidenceBatch strictly decodes a status evidence batch. The
// byte limit is checked before parsing; any violation is malformed. The JSON
// value model applies to the whole document and the schema to the envelope
// only. It does not authenticate the objects.
func DecodeV2StatusEvidenceBatch(data []byte) (_ V2StatusEvidenceBatch, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "status evidence batch", "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2", MaxStatusEvidenceBatchBytesV2); err != nil {
		return V2StatusEvidenceBatch{}, err
	}
	if err := checkWireValueModelV2(data); err != nil {
		return V2StatusEvidenceBatch{}, err
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil || entries == nil {
		return V2StatusEvidenceBatch{}, fmt.Errorf("wire v2: status evidence batch must be a JSON array of objects")
	}
	if len(entries) > MaxStatusEvidenceBatchObjectsV2 {
		return V2StatusEvidenceBatch{}, fmt.Errorf("wire v2: status evidence batch exceeds %d objects", MaxStatusEvidenceBatchObjectsV2)
	}
	batch := V2StatusEvidenceBatch{Objects: make([]V2StatusEvidenceObject, 0, len(entries))}
	for _, entry := range entries {
		code, object := entry["object_type_code"], entry["object"]
		if len(entry) != 2 || code == nil || object == nil {
			return V2StatusEvidenceBatch{}, fmt.Errorf("wire v2: status evidence entry must have exactly object and object_type_code")
		}
		switch string(code) {
		case "3", "5":
		default:
			return V2StatusEvidenceBatch{}, fmt.Errorf("wire v2: status evidence object_type_code must be 3 or 5")
		}
		trimmed := bytes.TrimSpace(object)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return V2StatusEvidenceBatch{}, fmt.Errorf("wire v2: status evidence object must be a JSON object")
		}
		value, err := strconv.ParseUint(string(code), 10, 16)
		if err != nil {
			return V2StatusEvidenceBatch{}, fmt.Errorf("wire v2: status evidence object_type_code must be 3 or 5")
		}
		batch.Objects = append(batch.Objects, V2StatusEvidenceObject{ObjectType: uint16(value), Wire: bytes.Clone(trimmed)})
	}
	return batch, nil
}

// MarshalJSON encodes the batch in its canonical wire form.
func (b V2StatusEvidenceBatch) MarshalJSON() ([]byte, error) { return EncodeV2StatusEvidenceBatch(b) }

// UnmarshalJSON strictly decodes the batch wire form.
func (b *V2StatusEvidenceBatch) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeV2StatusEvidenceBatch(data)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// v2StatusEvidenceBatchEncodedLength is the length of the batch wire form
// carrying each object's bytes exactly as received, which is what the byte
// limit bounds for a batch handed over as Go values.
func v2StatusEvidenceBatchEncodedLength(batch V2StatusEvidenceBatch) int {
	total := 2 // [ ]
	for i, object := range batch.Objects {
		if i > 0 {
			total++
		}
		total += len(`{"object":`) + len(object.Wire) + len(`,"object_type_code":`) + len(strconv.Itoa(int(object.ObjectType))) + 1
	}
	return total
}
