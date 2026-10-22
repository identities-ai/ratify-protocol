package ratify_test

// Cross-SDK fixtures (SPEC-v2 §8.1). Each SDK writes
// testvectors/v2/cross-sdk/<sdk>.json from fresh keys and hedged signatures;
// this test verifies every fixture present with the objects.json positive
// procedure. Fixtures from other SDKs are optional here; go.json is required.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type v2CrossSDKFile struct {
	Version     int              `json:"version"`
	Description string           `json:"description"`
	SDK         string           `json:"sdk"`
	SDKVersion  string           `json:"sdk_version"`
	Generator   string           `json:"generator"`
	Kinds       map[string]int   `json:"kind_object_type_codes"`
	Keys        []v2KeyEntry     `json:"keys"`
	Objects     []v2ObjectVector `json:"objects"`
}

var v2CrossSDKKinds = []string{
	"delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement",
	"witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding",
}

func TestV2CrossSDKFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testvectors", "v2", "cross-sdk", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	foundGo := false
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		foundGo = foundGo || name == "go"
		t.Run(name, func(t *testing.T) { v2CheckCrossSDKFile(t, path, name) })
	}
	if !foundGo {
		t.Fatal("testvectors/v2/cross-sdk/go.json is missing; run go run ./cmd/ratify-v2-cross-sdk")
	}
}

func v2CheckCrossSDKFile(t *testing.T, path, name string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f v2CrossSDKFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Version != 2 || f.SDK != name || f.SDKVersion == "" || f.Generator == "" {
		t.Fatalf("header: version %d, sdk %q (file %q), sdk_version %q, generator %q", f.Version, f.SDK, name, f.SDKVersion, f.Generator)
	}
	fx := v2FixtureFromKeys(t, f.Keys)
	for _, k := range f.Keys {
		if !bytes.Equal(fx.pub[k.Name].Ed25519, k.PublicKey.Ed25519) || !bytes.Equal(fx.pub[k.Name].MLDSA65, k.PublicKey.MLDSA65) {
			t.Errorf("%s: seeds do not derive the public key", k.Name)
		}
		if got := independentKeyIDV2(k.PublicKey); got != k.KeyIDV2 {
			t.Errorf("%s: key_id_v2 = %s, want %s", k.Name, got, k.KeyIDV2)
		}
		if got := ratify.DeriveID(k.PublicKey); got != k.V1KeyID128 {
			t.Errorf("%s: v1 ID %s, want %s", k.Name, got, k.V1KeyID128)
		}
	}
	seenCodes, seenKinds := map[int]bool{}, map[string]bool{}
	allConstraints, evaluators := false, false
	for _, o := range f.Objects {
		seenKinds[o.Kind] = true
		t.Run(o.Name, func(t *testing.T) {
			if o.Kind != "receipt_bundle_binding" {
				v2CheckPositiveObject(t, fx, o, seenCodes)
			} else {
				wire, bundle := unb64(t, o.WireB64), unb64(t, o.BundleB64)
				if !bytes.Equal(v2Reencode(t, "verification_receipt", wire), wire) || !bytes.Equal(v2Reencode(t, "proof_bundle", bundle), bundle) {
					t.Fatalf("re-encoding is not byte-identical")
				}
				if err := v2VerifyObject(t, fx, o.Kind, wire, bundle, o.Verify); err != nil {
					t.Fatalf("binding: %v", err)
				}
				if len(o.Signatures) != 0 || len(o.Digests) != 0 {
					t.Errorf("a binding object carries no signatures or digests")
				}
			}
			wire := unb64(t, o.WireB64)
			switch o.Kind {
			case "delegation_certificate":
				c, _ := ratify.DecodeDelegationCertV2(wire)
				types, extension := map[ratify.ConstraintType]bool{}, false
				for _, k := range c.Constraints {
					types[k.Type] = true
					extension = extension || !ratify.IsRegisteredConstraintTypeV2(k.Type)
				}
				if extension && types[ratify.ConstraintMaxRate] && types[ratify.ConstraintReceiverAudience] && types[ratify.ConstraintResourcePath] && types[ratify.ConstraintTimeWindow] && types[ratify.ConstraintMaxAmount] {
					allConstraints = true
				}
			case "verification_receipt":
				r, _ := ratify.DecodeVerificationReceiptV2(wire)
				evaluators = evaluators || len(r.ConstraintEvaluators) > 0
			}
		})
	}
	for _, kind := range v2CrossSDKKinds {
		if !seenKinds[kind] {
			t.Errorf("no %s object", kind)
		}
	}
	for code := 1; code <= 9; code++ {
		if !seenCodes[code] {
			t.Errorf("no signature for object_type_code %d", code)
		}
	}
	if !allConstraints {
		t.Error("no delegation certificate carries every registered constraint type and an extension type")
	}
	if !evaluators {
		t.Error("no verification receipt carries constraint_evaluators")
	}
}
