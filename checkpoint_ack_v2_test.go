package ratify

import (
	"bytes"
	"strings"
	"testing"
)

func TestV2CheckpointAcknowledgementWireForm(t *testing.T) {
	ack := V2CheckpointAcknowledgement{LogID: strings.Repeat("d", 31) + "1", Sequence: 7, EntryHash: bytes.Repeat([]byte{0xab}, 48), Timestamp: 1800000000}
	wire, err := EncodeV2CheckpointAcknowledgement(ack)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"entry_hash":"` + strings.Repeat("q6ur", 16) + `","log_id":"ddddddddddddddddddddddddddddddd1","sequence":7,"timestamp":1800000000}`
	if string(wire) != want {
		t.Fatalf("wire = %s", wire)
	}
	got, err := DecodeV2CheckpointAcknowledgement(wire)
	if err != nil || got.LogID != ack.LogID || got.Sequence != 7 || !bytes.Equal(got.EntryHash, ack.EntryHash) || got.Timestamp != ack.Timestamp {
		t.Fatalf("round trip %+v %v", got, err)
	}
	for name, input := range map[string]string{
		"noncanonical whitespace": strings.Replace(want, `,"log_id"`, `, "log_id"`, 1),
		"short entry hash":        strings.Replace(want, strings.Repeat("q6ur", 16), "q6ur", 1),
		"uppercase log id":        strings.Replace(want, "ddddddddddddddddddddddddddddddd1", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD1", 1),
		"zero sequence":           strings.Replace(want, `"sequence":7`, `"sequence":0`, 1),
		"timestamp past domain":   strings.Replace(want, "1800000000", "253402300800", 1),
		"missing member":          strings.Replace(want, `,"timestamp":1800000000`, ``, 1),
		"unknown member":          strings.Replace(want, `}`, `,"x":1}`, 1),
	} {
		if _, err := DecodeV2CheckpointAcknowledgement([]byte(input)); V2ErrorClassOf(err) != V2ErrMalformed {
			t.Errorf("%s: class %q (%v)", name, V2ErrorClassOf(err), err)
		}
	}
}

func FuzzDecodeV2CheckpointAcknowledgementNeverPanics(f *testing.F) {
	f.Add([]byte(`{"entry_hash":"` + strings.Repeat("q6ur", 16) + `","log_id":"ddddddddddddddddddddddddddddddd1","sequence":7,"timestamp":1800000000}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ack, err := DecodeV2CheckpointAcknowledgement(data)
		if err != nil {
			if V2ErrorClassOf(err) != V2ErrMalformed {
				t.Fatalf("decode error is not malformed: %v", err)
			}
			return
		}
		wire, err := EncodeV2CheckpointAcknowledgement(ack)
		if err != nil || !bytes.Equal(wire, data) {
			t.Fatalf("accepted acknowledgement does not re-encode identically: %v", err)
		}
	})
}
