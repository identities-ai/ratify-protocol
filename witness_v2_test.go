package ratify

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validWitnessEntryV2Test(t *testing.T) (*WitnessEntryV2, HybridPrivateKey, HybridPublicKey) {
	t.Helper()
	pub, priv := rotationTestKey(t, 121)
	witnessID, err := keyIDV2(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &WitnessEntryV2{
		Version: 2, LogID: "0123456789abcdef0123456789abcdef", Sequence: 1,
		PrevHash: make([]byte, 48), EntryData: []byte(`{"event":"test"}`),
		Timestamp: 1800000000, WitnessID: witnessID,
	}, priv, pub
}

func TestWitnessEntryV2CanonicalSignAndVerify(t *testing.T) {
	entry, priv, pub := validWitnessEntryV2Test(t)
	signed, err := SignWitnessEntryV2(entry, priv)
	if err != nil {
		t.Fatal(err)
	}
	initial := WitnessV2Head{LogID: entry.LogID, HeadHash: make([]byte, 48)}
	if result, err := VerifyWitnessEntryV2(signed, initial, pub); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("valid genesis witness entry rejected: %v", err)
	}
	wrongPub, _ := rotationTestKey(t, 124)
	if _, err := VerifyWitnessEntryV2(signed, initial, wrongPub); err == nil {
		t.Fatal("witness entry verified with a different key")
	}
	_, wrongPrivate := rotationTestKey(t, 125)
	if _, err := SignWitnessEntryV2(entry, wrongPrivate); err == nil {
		t.Fatal("witness entry was signed with a key that does not match witness_id")
	}
	wire, err := EncodeWitnessEntryV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeWitnessEntryV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeWitnessEntryV2(decoded)
	if err != nil || !bytes.Equal(wire, reencoded) {
		t.Fatal("witness wire encoding is not canonical and stable")
	}
	digest, err := WitnessEntryV2Digest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	secondValue := *decoded
	secondValue.Sequence = 2
	secondValue.PrevHash = digest
	secondValue.Timestamp++
	second, err := SignWitnessEntryV2(&secondValue, priv)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := WitnessEntryV2Digest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	acceptedHead := WitnessV2Head{
		LogID: entry.LogID, Sequence: 1, HeadHash: digest,
		AcceptedDigests: map[int64][]byte{1: firstDigest},
	}
	if result, err := VerifyWitnessEntryV2(second, acceptedHead, pub); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("valid linked witness entry rejected: %v", err)
	}
	acceptedSecondDigest, err := WitnessEntryV2Digest(second)
	if err != nil {
		t.Fatal(err)
	}
	secondHead := WitnessV2Head{
		LogID: entry.LogID, Sequence: 2, HeadHash: acceptedSecondDigest,
		AcceptedDigests: map[int64][]byte{1: firstDigest, 2: acceptedSecondDigest},
	}
	if result, err := VerifyWitnessEntryV2(second, secondHead, pub); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("exact accepted witness replay was not idempotent: %v", err)
	}
	// A caller can safely avoid advancing its durable log head on replay.
	if result, err := VerifyWitnessEntryV2(decoded, secondHead, pub); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("older exact accepted entry was not classified as replay: %v", err)
	}
	forkValue := *second
	forkValue.EntryData = []byte(`{"event":"fork"}`)
	fork, err := SignWitnessEntryV2(&forkValue, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWitnessEntryV2(fork, secondHead, pub); !errors.Is(err, ErrWitnessLogFork) {
		t.Fatalf("valid conflicting entry did not report a fork: %v", err)
	}
	frozenSecondHead := secondHead
	frozenSecondHead.Frozen = true
	if _, err := VerifyWitnessEntryV2(fork, frozenSecondHead, pub); !errors.Is(err, ErrWitnessLogFork) {
		t.Fatalf("conflicting accepted entry on frozen log did not report fork evidence: %v", err)
	}
	wrongLog := WitnessV2Head{LogID: "fedcba9876543210fedcba9876543210", Sequence: 1, HeadHash: digest, AcceptedDigests: map[int64][]byte{1: firstDigest}}
	if _, err := VerifyWitnessEntryV2(second, wrongLog, pub); err == nil {
		t.Fatal("cross-log witness entry was accepted")
	}
	orphanValue := *second
	orphanValue.PrevHash = bytes.Repeat([]byte{1}, 48)
	orphanFromWrongHead, err := SignWitnessEntryV2(&orphanValue, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWitnessEntryV2(orphanFromWrongHead, acceptedHead, pub); !errors.Is(err, ErrWitnessLogOrphan) {
		t.Fatal("orphaned witness entry was accepted")
	}
	frozen := WitnessV2Head{LogID: entry.LogID, Sequence: 1, HeadHash: digest, AcceptedDigests: map[int64][]byte{1: firstDigest}, Frozen: true}
	if result, err := VerifyWitnessEntryV2(signed, frozen, pub); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("frozen log rejected an idempotent accepted entry: %v", err)
	}
	if _, err := VerifyWitnessEntryV2(second, frozen, pub); !errors.Is(err, ErrWitnessLogFrozen) {
		t.Fatal("frozen witness log accepted a new entry")
	}
	gapValue := *second
	gapValue.Sequence = 4
	gapValue.PrevHash = acceptedSecondDigest
	gap, err := SignWitnessEntryV2(&gapValue, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWitnessEntryV2(gap, secondHead, pub); !errors.Is(err, ErrWitnessLogGap) {
		t.Fatalf("sequence gap did not return its distinct error: %v", err)
	}
	orphanValue = *second
	orphanValue.Sequence = 3
	orphanValue.PrevHash = bytes.Repeat([]byte{8}, 48)
	orphan, err := SignWitnessEntryV2(&orphanValue, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWitnessEntryV2(orphan, secondHead, pub); !errors.Is(err, ErrWitnessLogOrphan) {
		t.Fatalf("orphaned entry did not return its distinct error: %v", err)
	}
	changed := *decoded
	changed.EntryData = []byte(`{"event":"altered"}`)
	if _, err := VerifyWitnessEntryV2(&changed, initial, pub); err == nil {
		t.Fatal("tampered witness data retained a valid signature")
	}
}

func TestVerifyWitnessEntryV2RejectsInvalidHeadHistory(t *testing.T) {
	entry, priv, pub := validWitnessEntryV2Test(t)
	signed, err := SignWitnessEntryV2(entry, priv)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := WitnessEntryV2Digest(signed)
	if err != nil {
		t.Fatal(err)
	}
	secondValue := *signed
	secondValue.Sequence = 2
	secondValue.PrevHash = digest
	secondValue.Timestamp++
	second, err := SignWitnessEntryV2(&secondValue, priv)
	if err != nil {
		t.Fatal(err)
	}
	digestTwo, err := WitnessEntryV2Digest(second)
	if err != nil {
		t.Fatal(err)
	}
	head := WitnessV2Head{LogID: entry.LogID, Sequence: 2, HeadHash: digestTwo,
		AcceptedDigests: map[int64][]byte{1: digest, 2: digestTwo}}
	if result, err := VerifyWitnessEntryV2(signed, head, pub); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("valid history did not accept its first entry as replay: result=%v err=%v", result, err)
	}
	tests := map[string]struct {
		mutate        func(*WitnessV2Head)
		wantErrorPart string
	}{
		"missing sequence": {func(h *WitnessV2Head) { delete(h.AcceptedDigests, 1) }, "missing accepted sequence digests"},
		"wrong head hash":  {func(h *WitnessV2Head) { h.HeadHash = bytes.Repeat([]byte{2}, 48) }, "head hash does not match"},
		"nonpositive sequence": {func(h *WitnessV2Head) {
			delete(h.AcceptedDigests, 1)
			h.AcceptedDigests[0] = bytes.Repeat([]byte{3}, 48)
		}, "invalid accepted digest history"},
		"sequence beyond head": {func(h *WitnessV2Head) {
			delete(h.AcceptedDigests, 1)
			h.AcceptedDigests[3] = bytes.Repeat([]byte{3}, 48)
		}, "invalid accepted digest history"},
		"wrong digest length": {func(h *WitnessV2Head) { h.AcceptedDigests[1] = []byte{1} }, "invalid accepted digest history"},
		"genesis with history": {func(h *WitnessV2Head) {
			h.Sequence, h.HeadHash = 0, make([]byte, 48)
		}, "inconsistent genesis state"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			bad := WitnessV2Head{LogID: head.LogID, Sequence: head.Sequence,
				HeadHash: bytes.Clone(head.HeadHash), AcceptedDigests: map[int64][]byte{}}
			for sequence, accepted := range head.AcceptedDigests {
				bad.AcceptedDigests[sequence] = bytes.Clone(accepted)
			}
			test.mutate(&bad)
			if _, err := VerifyWitnessEntryV2(signed, bad, pub); err == nil {
				t.Fatal("invalid caller-supplied history was accepted")
			} else if !strings.Contains(err.Error(), test.wantErrorPart) {
				t.Fatalf("unexpected error, want %q but got %v", test.wantErrorPart, err)
			}
		})
	}
}

func TestWitnessEntryV2StrictSchemaAndDigest(t *testing.T) {
	entry, priv, pub := validWitnessEntryV2Test(t)
	signed, err := SignWitnessEntryV2(entry, priv)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeWitnessEntryV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWitnessEntryV2(append(bytes.Clone(wire), ' ')); err == nil {
		t.Fatal("trailing wire content was accepted")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	malformed := func(change func(map[string]json.RawMessage)) []byte {
		t.Helper()
		copyFields := make(map[string]json.RawMessage, len(fields))
		for key, value := range fields {
			copyFields[key] = bytes.Clone(value)
		}
		change(copyFields)
		encoded, err := json.Marshal(copyFields)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for name, candidate := range map[string][]byte{
		"null entry data":  malformed(func(m map[string]json.RawMessage) { m["entry_data"] = json.RawMessage(`null`) }),
		"missing field":    malformed(func(m map[string]json.RawMessage) { delete(m, "witness_id") }),
		"unknown field":    malformed(func(m map[string]json.RawMessage) { m["extra"] = json.RawMessage(`true`) }),
		"wrong field case": malformed(func(m map[string]json.RawMessage) { m["LogID"] = m["log_id"]; delete(m, "log_id") }),
		"zero sequence":    malformed(func(m map[string]json.RawMessage) { m["sequence"] = json.RawMessage(`0`) }),
		"uppercase log ID": malformed(func(m map[string]json.RawMessage) {
			m["log_id"] = json.RawMessage(`"ABCDEF0123456789ABCDEF0123456789"`)
		}),
		"noncanonical base64": malformed(func(m map[string]json.RawMessage) { m["entry_data"] = json.RawMessage(`"eyJldmVudCI6InRlc3QifQ"`) }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeWitnessEntryV2(candidate); err == nil {
				t.Fatalf("malformed witness entry was accepted: %s", name)
			}
		})
	}
	body, err := witnessEntrySignableBytesV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	var bodyFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &bodyFields); err != nil {
		t.Fatal(err)
	}
	bodyFields["signature"] = json.RawMessage(`"x"`)
	withSignature, err := CanonicalJSON(bodyFields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StatementBodyDigestV2(0x0006, withSignature); err == nil {
		t.Fatal("witness body digest accepted a signature-bearing projection")
	}
	if _, err := StatementBodyDigestV2(0x0006, []byte(`{"statement_body":"test"}`)); err == nil {
		t.Fatal("witness body digest accepted an object outside the witness schema")
	}
	badID := *signed
	badID.WitnessID = "not-a-key-id"
	if _, err := EncodeWitnessEntryV2(&badID); err == nil {
		t.Fatal("witness entry with a malformed key ID was encoded")
	}
	badPrev := *signed
	badPrev.PrevHash = bytes.Repeat([]byte{1}, 48)
	if _, err := EncodeWitnessEntryV2(&badPrev); err == nil {
		t.Fatal("genesis witness entry with a nonzero predecessor was encoded")
	}
	nullData := *signed
	nullData.EntryData = nil
	if _, err := EncodeWitnessEntryV2(&nullData); err == nil {
		t.Fatal("null entry_data was encoded instead of a base64 byte string")
	}
	oversized := *signed
	oversized.EntryData = bytes.Repeat([]byte{0x41}, 100_000)
	if _, err := EncodeWitnessEntryV2(&oversized); err == nil {
		t.Fatal("oversized witness entry was encoded")
	}
	if _, err := VerifyWitnessEntryV2(&oversized, WitnessV2Head{LogID: entry.LogID, HeadHash: make([]byte, 48)}, pub); err == nil {
		t.Fatal("oversized in-memory witness entry bypassed the wire size limit")
	}
	if _, err := SignWitnessEntryV2(&oversized, priv); err == nil {
		t.Fatal("signer returned an entry that its own decoder rejects for size")
	}
}
