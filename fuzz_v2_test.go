package ratify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// v2FuzzSeeds returns every positive and negative corpus wire object of kind.
func v2FuzzSeeds(f *testing.F, kind string) {
	f.Helper()
	for _, file := range []string{"testvectors/v2/objects.json", "testvectors/v2/object-negatives.json"} {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		var corpus struct {
			Objects []struct {
				Kind    string `json:"kind"`
				WireB64 string `json:"wire_b64"`
			} `json:"objects"`
			Vectors []struct {
				Kind    string `json:"kind"`
				WireB64 string `json:"wire_b64"`
			} `json:"vectors"`
		}
		if err := json.Unmarshal(data, &corpus); err != nil {
			f.Fatal(err)
		}
		for _, item := range append(corpus.Objects, corpus.Vectors...) {
			if item.Kind != kind {
				continue
			}
			wire, err := base64.StdEncoding.DecodeString(item.WireB64)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(wire)
		}
	}
}

// fuzzV2Codec checks that decoding never panics and that anything accepted
// re-encodes to bytes that decode to the identical canonical encoding.
func fuzzV2Codec[T any](f *testing.F, kind string, decode func([]byte) (*T, error), encode func(*T) ([]byte, error)) {
	v2FuzzSeeds(f, kind)
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := decode(data)
		if err != nil {
			return
		}
		first, err := encode(value)
		if err != nil {
			t.Fatalf("accepted %s does not re-encode: %v", kind, err)
		}
		again, err := decode(first)
		if err != nil {
			t.Fatalf("re-encoded %s does not decode: %v", kind, err)
		}
		second, err := encode(again)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("%s canonical encoding is unstable", kind)
		}
	})
}

func FuzzV2DelegationCertCodec(f *testing.F) {
	fuzzV2Codec(f, "delegation_certificate", DecodeDelegationCertV2, EncodeDelegationCertV2)
}

func FuzzV2ProofBundleCodec(f *testing.F) {
	fuzzV2Codec(f, "proof_bundle", DecodeProofBundleV2, EncodeProofBundleV2)
}

func FuzzV2RevocationListCodec(f *testing.F) {
	fuzzV2Codec(f, "revocation_list", DecodeRevocationListV2, EncodeRevocationListV2)
}

func FuzzV2RevocationPushCodec(f *testing.F) {
	fuzzV2Codec(f, "revocation_push", DecodeRevocationPushV2, EncodeRevocationPushV2)
}

func FuzzV2VerificationReceiptCodec(f *testing.F) {
	fuzzV2Codec(f, "verification_receipt", DecodeVerificationReceiptV2, EncodeVerificationReceiptV2)
}
