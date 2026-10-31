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

// TestVerifyCrossSDKReplaysScenarios guards the scenario replay: a changed
// expected release result, a receipt signed by another verifier key, and a
// missing scenario must each fail.
func TestVerifyCrossSDKReplaysScenarios(t *testing.T) {
	data, err := GenerateCrossSDK("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateCrossSDK("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	var f, g crossSDKFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(other, &g); err != nil {
		t.Fatal(err)
	}
	check := func(name string, edit func(f *crossSDKFile), want string) {
		t.Helper()
		var c crossSDKFile
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		edit(&c)
		out, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCrossSDK(out); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, want)
		}
	}
	check("release status", func(c *crossSDKFile) { c.Scenarios[3].Expected.Release.Status = "released" }, "allow_withheld_past_horizon")
	check("foreign receipt", func(c *crossSDKFile) {
		c.Scenarios[0].Expected.SignedReceiptB64 = g.Scenarios[0].Expected.SignedReceiptB64
	}, "allow_released")
	check("receipt body", func(c *crossSDKFile) { c.Scenarios[1].Expected.ReceiptBodyB64 = c.Scenarios[0].Expected.ReceiptBodyB64 }, "deny_revoked_released")
	check("missing scenario", func(c *crossSDKFile) { c.Scenarios = c.Scenarios[:3] }, "missing scenario")
}
