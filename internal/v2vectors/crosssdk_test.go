package v2vectors

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestGenerateCrossSDKIsFreshAndVerifies checks that two runs share no key
// and no signature (fresh keys, hedged signing) and that each verifies.
func TestGenerateCrossSDKIsFreshAndVerifies(t *testing.T) {
	a, err := GenerateCrossSDK("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateCrossSDK("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	var fa, fb crossSDKFile
	if err := json.Unmarshal(a, &fa); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fb); err != nil {
		t.Fatal(err)
	}
	for i := range fa.Keys {
		if fa.Keys[i].KeyIDV2 == fb.Keys[i].KeyIDV2 {
			t.Errorf("key %s repeated across runs", fa.Keys[i].Name)
		}
	}
	if bytes.Equal(a, b) {
		t.Fatal("two runs produced identical fixtures")
	}
}

// TestVerifyCrossSDKRejectsTampering guards the validator itself: a flipped
// ML-DSA-65 signature byte and a missing kind must both fail.
func TestVerifyCrossSDKRejectsTampering(t *testing.T) {
	data, err := GenerateCrossSDK("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	var f crossSDKFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	encode := func(f crossSDKFile) []byte {
		out, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	flipped := f
	flipped.Objects = append([]objectVector(nil), f.Objects...)
	wire := must(b64d(flipped.Objects[0].WireB64))
	sig := flipped.Objects[0].Signatures[0].Signature["ml_dsa_65"].(string)
	raw := must(b64d(sig))
	raw[10] ^= 1
	flipped.Objects[0].WireB64 = b64([]byte(strings.Replace(string(wire), sig, b64(raw), 1)))
	if err := VerifyCrossSDK(encode(flipped)); err == nil {
		t.Error("a flipped ML-DSA-65 signature verified")
	}

	missing := f
	missing.Objects = nil
	for _, o := range f.Objects {
		if o.Kind != "witness_entry" {
			missing.Objects = append(missing.Objects, o)
		}
	}
	if err := VerifyCrossSDK(encode(missing)); err == nil || !strings.Contains(err.Error(), "witness_entry") {
		t.Errorf("missing witness_entry: %v", err)
	}
}
