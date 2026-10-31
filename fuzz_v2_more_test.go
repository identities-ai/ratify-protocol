package ratify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func FuzzV2WitnessEntryCodec(f *testing.F) {
	fuzzV2Codec(f, "witness_entry", DecodeWitnessEntryV2, EncodeWitnessEntryV2)
}

func FuzzV2KeyRotationStatementCodec(f *testing.F) {
	fuzzV2Codec(f, "key_rotation_statement", DecodeKeyRotationStatementV2, EncodeKeyRotationStatementV2)
}

func FuzzV2TransactionReceiptCodec(f *testing.F) {
	fuzzV2Codec(f, "transaction_receipt", DecodeTransactionReceiptV2, EncodeTransactionReceiptV2)
}

// FuzzV2VerificationReceiptBodyCodec: an accepted prepared body is exactly
// its own canonical re-encoding.
func FuzzV2VerificationReceiptBodyCodec(f *testing.F) {
	data, err := os.ReadFile("testvectors/v2/objects.json")
	if err != nil {
		f.Fatal(err)
	}
	var corpus struct {
		Objects []struct {
			Digests map[string]string `json:"digests"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		f.Fatal(err)
	}
	for _, o := range corpus.Objects {
		if body, ok := o.Digests["receipt_outbox_body_b64"]; ok {
			raw, err := base64.StdEncoding.DecodeString(body)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(raw)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		receipt, err := DecodeVerificationReceiptBodyV2(data)
		if err != nil {
			return
		}
		again, err := VerificationReceiptV2Body(receipt)
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("accepted receipt body is not its canonical encoding: %v", err)
		}
	})
}

// FuzzV2Constraint: any constraint the closed v2 registry accepts re-encodes
// canonically and decodes to the same encoding.
func FuzzV2Constraint(f *testing.F) {
	for _, seed := range []string{
		`{"end":"06:00","start":"22:00","tz":"UTC","type":"time_window"}`,
		`{"currency":"USD","max_amount_micros":5000000,"type":"max_amount"}`,
		`{"count":5,"type":"max_rate","window_s":60}`,
		`{"path_prefix":"/a/","resource_id":"r","type":"resource_path"}`,
		`{"params":{"exact_receiver_ids":["r"],"trust_domain_ids":[]},"type":"ratify.receiver_audience"}`,
		`{"params":{"radius_mm":1},"type":"geo_circle"}`,
		`{"lat":1.5,"type":"geo_circle"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if checkWireJSONV2(data) != nil {
			return
		}
		var c ConstraintV2
		if json.Unmarshal(data, &c) != nil {
			return
		}
		first, err := CanonicalJSON(c)
		if err != nil {
			t.Fatalf("accepted constraint does not re-encode: %v", err)
		}
		var again ConstraintV2
		if err := json.Unmarshal(first, &again); err != nil {
			t.Fatalf("re-encoded constraint does not decode: %v", err)
		}
		second, err := CanonicalJSON(again)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("constraint canonical encoding is unstable")
		}
	})
}

// FuzzVerifyArchivalProofBundleV2NeverPanics: the archival entry point never
// panics and its result is never actionable, whatever the input (SPEC-v2
// §6.10). An accepted input has no error class and a bundle hash.
func FuzzVerifyArchivalProofBundleV2NeverPanics(f *testing.F) {
	v2FuzzSeeds(f, "proof_bundle")
	f.Fuzz(func(t *testing.T, data []byte) {
		result := VerifyArchivalProofBundleV2(data)
		if result.Actionable || result.Assessment != FreshnessUnverifiedV2 {
			t.Fatalf("archival result is actionable or not freshness_unverified: %+v", result)
		}
		if result.ErrorClass == "" && result.BundleHash == "" {
			t.Fatalf("accepted archival bundle has no bundle hash: %+v", result)
		}
	})
}
