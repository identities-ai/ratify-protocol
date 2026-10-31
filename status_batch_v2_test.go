package ratify

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func signedStatusBatchFixtureV2(t testing.TB) (V2StatusEvidenceBatch, string) {
	t.Helper()
	issuerPub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	statusPub, statusPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerID, _ := KeyIDV2(issuerPub)
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 5, NextUpdate: 80, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "leaf"}}}, issuerID, statusPub, statusPriv)
	if err != nil {
		t.Fatal(err)
	}
	push, err := SignRevocationPushV2(&RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: 2, PushedAt: 6, Revoked: []RevokedCertV2{{CertID: "other"}}}, issuerID, statusPub, statusPriv)
	if err != nil {
		t.Fatal(err)
	}
	listWire, _ := EncodeRevocationListV2(list)
	pushWire, _ := EncodeRevocationPushV2(push)
	return V2StatusEvidenceBatch{Objects: []V2StatusEvidenceObject{{ObjectType: 3, Wire: listWire}, {ObjectType: 5, Wire: pushWire}}}, issuerID
}

// SPEC-v2 §6.5 step 3: the batch wire form is a JSON array of exactly
// {"object","object_type_code"} entries; encoding is canonical and decoding
// keeps each object's received bytes.
func TestV2StatusEvidenceBatchWireForm(t *testing.T) {
	batch, _ := signedStatusBatchFixtureV2(t)
	wire, err := EncodeV2StatusEvidenceBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(wire, []byte(`[{"object":{`)) || !bytes.HasSuffix(wire, []byte(`,"object_type_code":5}]`)) {
		t.Fatalf("unexpected canonical form: %.80s", wire)
	}
	if v2StatusEvidenceBatchEncodedLength(batch) != len(wire) {
		t.Fatalf("encoded length %d, want %d", v2StatusEvidenceBatchEncodedLength(batch), len(wire))
	}
	decoded, err := DecodeV2StatusEvidenceBatch(wire)
	if err != nil || len(decoded.Objects) != 2 || !bytes.Equal(decoded.Objects[0].Wire, batch.Objects[0].Wire) || decoded.Objects[1].ObjectType != 5 {
		t.Fatalf("round trip: %+v %v", decoded, err)
	}
	viaJSON, err := json.Marshal(batch)
	if err != nil || !bytes.Equal(viaJSON, wire) {
		t.Fatalf("MarshalJSON differs: %v", err)
	}
	var unmarshalled V2StatusEvidenceBatch
	if err := json.Unmarshal(wire, &unmarshalled); err != nil || len(unmarshalled.Objects) != 2 {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if empty, err := DecodeV2StatusEvidenceBatch([]byte(`[]`)); err != nil || len(empty.Objects) != 0 {
		t.Fatalf("empty batch: %v", err)
	}
	list := string(batch.Objects[0].Wire)
	for name, input := range map[string]string{
		"not an array":         `{}`,
		"null":                 `null`,
		"missing code":         `[{"object":` + list + `}]`,
		"extra member":         `[{"object":` + list + `,"object_type_code":3,"x":1}]`,
		"unregistered code":    `[{"object":` + list + `,"object_type_code":7}]`,
		"string code":          `[{"object":` + list + `,"object_type_code":"3"}]`,
		"object not an object": `[{"object":[1],"object_type_code":3}]`,
		"duplicate member":     `[{"object":` + list + `,"object_type_code":3,"object_type_code":3}]`,
		"trailing data":        `[] []`,
	} {
		if _, err := DecodeV2StatusEvidenceBatch([]byte(input)); V2ErrorClassOf(err) != V2ErrMalformed {
			t.Errorf("%s: class %q (%v)", name, V2ErrorClassOf(err), err)
		}
	}
}

func TestV2StatusEvidenceBatchLimits(t *testing.T) {
	batch, _ := signedStatusBatchFixtureV2(t)
	entry := batch.Objects[0]
	full := V2StatusEvidenceBatch{}
	for range MaxStatusEvidenceBatchObjectsV2 {
		full.Objects = append(full.Objects, entry)
	}
	wire, err := EncodeV2StatusEvidenceBatch(full)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV2StatusEvidenceBatch(wire); err != nil {
		t.Fatalf("64 objects: %v", err)
	}
	over := append([]byte(`[{"object":`+string(entry.Wire)+`,"object_type_code":3},`), wire[1:]...)
	if _, err := DecodeV2StatusEvidenceBatch(over); V2ErrorClassOf(err) != V2ErrMalformed {
		t.Fatalf("65 objects: %v", err)
	}
	if _, err := EncodeV2StatusEvidenceBatch(V2StatusEvidenceBatch{Objects: append(full.Objects, entry)}); V2ErrorClassOf(err) != V2ErrMalformed {
		t.Fatalf("encode 65 objects: %v", err)
	}
	padded := []byte("[]" + strings.Repeat(" ", MaxStatusEvidenceBatchBytesV2-2))
	if _, err := DecodeV2StatusEvidenceBatch(padded); err != nil {
		t.Fatalf("batch at the byte limit: %v", err)
	}
	if _, err := DecodeV2StatusEvidenceBatch(append(padded, ' ')); V2ErrorClassOf(err) != V2ErrMalformed || !strings.Contains(err.Error(), "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2") {
		t.Fatalf("batch one byte over the limit: %v", err)
	}
}

func FuzzDecodeV2StatusEvidenceBatchNeverPanics(f *testing.F) {
	batch, _ := signedStatusBatchFixtureV2(f)
	wire, err := EncodeV2StatusEvidenceBatch(batch)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"object":{},"object_type_code":3}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeV2StatusEvidenceBatch(data)
		if err != nil {
			if V2ErrorClassOf(err) != V2ErrMalformed {
				t.Fatalf("decode error is not malformed: %v", err)
			}
			return
		}
		if len(decoded.Objects) > MaxStatusEvidenceBatchObjectsV2 {
			t.Fatalf("decoded %d objects", len(decoded.Objects))
		}
		if reencoded, err := EncodeV2StatusEvidenceBatch(decoded); err == nil {
			again, err := DecodeV2StatusEvidenceBatch(reencoded)
			if err != nil || len(again.Objects) != len(decoded.Objects) {
				t.Fatalf("canonical re-encoding does not decode: %v", err)
			}
		}
	})
}
