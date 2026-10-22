package ratify_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/internal/v2vectors"
)

// TestV2ConformanceLimits runs testvectors/v2/limits.json: every per-object
// byte limit at limit and limit+1, and every count limit at limit and
// limit+1. The size gate must be the first check: an over-limit input fails
// with the named limit, and an at-limit input never does.
func TestV2ConformanceLimits(t *testing.T) {
	raw, err := os.ReadFile("testvectors/v2/limits.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Limits  map[string]int `json:"limits"`
		Vectors []struct {
			Name               string                      `json:"name"`
			Kind               string                      `json:"kind"`
			Limit              string                      `json:"limit"`
			LimitValue         int                         `json:"limit_value"`
			Construction       v2vectors.LimitConstruction `json:"construction"`
			Length             int                         `json:"length"`
			SHA256Hex          string                      `json:"sha256_hex"`
			Expected           string                      `json:"expected"`
			ExpectedErrorClass string                      `json:"expected_error_class"`
			SizeGate           string                      `json:"size_gate"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	decoders := map[string]func([]byte) error{
		"delegation_certificate":    func(b []byte) error { _, err := ratify.DecodeDelegationCertV2(b); return err },
		"proof_bundle":              func(b []byte) error { _, err := ratify.DecodeProofBundleV2(b); return err },
		"key_rotation_statement":    func(b []byte) error { _, err := ratify.DecodeKeyRotationStatementV2(b); return err },
		"revocation_list":           func(b []byte) error { _, err := ratify.DecodeRevocationListV2(b); return err },
		"revocation_push":           func(b []byte) error { _, err := ratify.DecodeRevocationPushV2(b); return err },
		"witness_entry":             func(b []byte) error { _, err := ratify.DecodeWitnessEntryV2(b); return err },
		"verification_receipt":      func(b []byte) error { _, err := ratify.DecodeVerificationReceiptV2(b); return err },
		"verification_receipt_body": func(b []byte) error { _, err := ratify.DecodeVerificationReceiptBodyV2(b); return err },
		"transaction_receipt":       func(b []byte) error { _, err := ratify.DecodeTransactionReceiptV2(b); return err },
	}
	if len(file.Vectors) == 0 {
		t.Fatal("limits.json has no vectors")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if file.Limits[v.Limit] != v.LimitValue {
				t.Fatalf("limit %s=%d disagrees with the limits table", v.Limit, v.LimitValue)
			}
			data, err := v2vectors.BuildLimitBytes(v.Construction)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			if len(data) != v.Length || hex.EncodeToString(sum[:]) != v.SHA256Hex {
				t.Fatalf("constructed %d bytes with a different digest; want %d", len(data), v.Length)
			}
			decode, ok := decoders[v.Kind]
			if !ok {
				t.Fatalf("no decoder for %s", v.Kind)
			}
			err = decode(data)
			switch v.Expected {
			case "accept":
				if err != nil {
					t.Fatalf("at-limit input rejected: %v", err)
				}
			case "reject":
				if err == nil || string(ratify.V2ErrorClassOf(err)) != v.ExpectedErrorClass {
					t.Fatalf("got class %q (%v), want %q", ratify.V2ErrorClassOf(err), err, v.ExpectedErrorClass)
				}
			default:
				t.Fatalf("unknown expectation %q", v.Expected)
			}
			sizeGateFailed := err != nil && strings.Contains(err.Error(), "exceeds "+v.Limit+" (") && strings.Contains(err.Error(), "rejected before parsing")
			if (v.SizeGate == "fail") != sizeGateFailed {
				t.Fatalf("size gate = %q, but error was %v", v.SizeGate, err)
			}
		})
	}
}
