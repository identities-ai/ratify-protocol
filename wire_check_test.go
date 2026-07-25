package ratify_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/identities-ai/ratify-protocol"
)

// Negative wire-acceptance corpus (testvectors/wire-negative): documents
// that the untrusted decode path must never accept as a valid bundle or
// session token. The strict path is CheckWireJSON followed by a
// DisallowUnknownFields decode — the same pattern the bundled CLI and
// reference verifier use.
//
// Contract (see testvectors/wire-negative/README.md):
//   - strictness "decode": the strict decode itself must fail;
//   - strictness "decode_or_verify": the decode may succeed structurally,
//     but Verify must then return Valid=false.

type negativeCase struct {
	Name        string `json:"name"`
	Target      string `json:"target"`
	DocB64      string `json:"doc_b64"`
	Strictness  string `json:"strictness"`
	Description string `json:"description"`
}

type negativeDoc struct {
	Cases []negativeCase `json:"cases"`
}

func loadNegativeCases(t *testing.T) []negativeCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testvectors", "wire-negative", "cases.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var doc negativeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(doc.Cases) < 10 {
		t.Fatalf("corpus too small: %d cases", len(doc.Cases))
	}
	return doc.Cases
}

// strictDecode mirrors the untrusted-path decode used by cmd/ratify and
// cmd/ratify-verifier.
func strictDecode(data []byte, out any) error {
	if err := CheckWireJSON(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func TestNegativeWireCorpus(t *testing.T) {
	for _, c := range loadNegativeCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(c.DocB64)
			if err != nil {
				t.Fatalf("corpus doc_b64: %v", err)
			}
			switch c.Target {
			case "bundle":
				var bundle ProofBundle
				decodeErr := strictDecode(data, &bundle)
				if decodeErr != nil {
					return // rejected at decode — always acceptable
				}
				if c.Strictness == "decode" {
					t.Fatalf("strict decode accepted a %q-class document", c.Name)
				}
				// decode_or_verify: the public verify entry point must reject.
				result := Verify(&bundle, VerifyOptions{})
				if result.Valid {
					t.Fatalf("Verify accepted corpus case %q as valid", c.Name)
				}
			case "token":
				var token SessionToken
				decodeErr := strictDecode(data, &token)
				if decodeErr != nil {
					return
				}
				if c.Strictness == "decode" {
					t.Fatalf("strict decode accepted a %q-class token document", c.Name)
				}
			default:
				t.Fatalf("unknown corpus target %q", c.Target)
			}
		})
	}
}
