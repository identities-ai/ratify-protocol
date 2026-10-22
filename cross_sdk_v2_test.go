package ratify_test

// Cross-SDK fixtures (SPEC-v2 §8.1). Each SDK writes
// testvectors/v2/cross-sdk/<sdk>.json from fresh keys and hedged signatures;
// this test verifies every fixture present with the objects.json positive
// procedure. Fixtures from other SDKs are optional here; go.json is required.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
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
	// Verifier and release scenarios (SPEC-v2 §8.1).
	ScenarioConfiguration *v2CrossScenarioConfig `json:"scenario_configuration"`
	Scenarios             []v2CrossScenario      `json:"scenarios"`
}

type v2CrossScenarioConfig struct {
	VerifierNamespace      string         `json:"verifier_namespace"`
	ReplayEpoch            int64          `json:"replay_epoch"`
	VerifierKey            string         `json:"verifier_key"`
	ReceiptLogID           string         `json:"receipt_log_id"`
	LeaseSeconds           int64          `json:"lease_seconds"`
	MaxChallengeAgeSeconds int64          `json:"max_challenge_age_seconds"`
	FutureSkewSeconds      int64          `json:"future_skew_seconds"`
	StatusPolicy           v2StatusPolicy `json:"status_policy"`
	TZDBVersion            string         `json:"tzdb_version"`
}

type v2CrossScenario struct {
	Name              string                   `json:"name"`
	Description       string                   `json:"description"`
	BundleB64         string                   `json:"bundle_b64"`
	RequiredScope     string                   `json:"required_scope"`
	ExpectedChallenge *v2ExpectedChallengeJSON `json:"expected_challenge"`
	ContextPolicy     *v2ContextPolicyJSON     `json:"context_policy"`
	TrustRootKey      string                   `json:"trust_root_key"`
	StatusKeys        map[string]struct {
		Epoch uint64 `json:"epoch"`
		Key   string `json:"key"`
	} `json:"status_keys"`
	StatusEvidence map[string][]v2EvidenceObjectJSON `json:"status_evidence"`
	VerifyTime     int64                             `json:"verify_time"`
	PublishTime    int64                             `json:"publish_time"`
	ReleaseTime    int64                             `json:"release_time"`
	Expected       struct {
		ReceiptBodyB64   string `json:"receipt_body_b64"`
		AllowHorizon     *int64 `json:"allow_horizon"`
		SignedReceiptB64 string `json:"signed_receipt_b64"`
		Release          struct {
			Status      string  `json:"status"`
			Reason      *string `json:"reason"`
			Decision    *string `json:"decision"`
			ReleaseTime *int64  `json:"release_time"`
		} `json:"release"`
	} `json:"expected"`
}

var v2CrossScenarioNames = []string{"allow_released", "deny_revoked_released", "indeterminate_status_unavailable_released", "allow_withheld_past_horizon"}

// v2CheckCrossScenarios replays each producer scenario through the Go
// verifier, reference store and release gate, releasing with the producer's
// signed receipt.
func v2CheckCrossScenarios(t *testing.T, fx v2Fixture, f v2CrossSDKFile) {
	t.Helper()
	if f.ScenarioConfiguration == nil || len(f.Scenarios) == 0 {
		if f.SDK == "go" {
			t.Fatal("go.json has no verifier and release scenarios")
		}
		t.Skipf("%s.json predates the SPEC-v2 §8.1 verifier and release scenarios; SPEC-v2 §8.1 is not met for %s until that SDK regenerates its fixture", f.SDK, f.SDK)
	}
	cfg := *f.ScenarioConfiguration
	if cfg != (v2CrossScenarioConfig{VerifierNamespace: "verify-test", ReplayEpoch: 3, VerifierKey: "verifier", ReceiptLogID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01", LeaseSeconds: 30,
		MaxChallengeAgeSeconds: 300, FutureSkewSeconds: 5, StatusPolicy: v2StatusPolicy{MaxListLifetimeSeconds: 7200, MaxStatusAgeSeconds: 3660, ClockSkewSeconds: 5}, TZDBVersion: ratify.TZDBVersionV2}) {
		t.Fatalf("scenario_configuration %+v differs from the fixed values", cfg)
	}
	seen := map[string]bool{}
	ctx := context.Background()
	for _, sc := range f.Scenarios {
		seen[sc.Name] = true
		t.Run("scenario/"+sc.Name, func(t *testing.T) {
			in := v2OrderingInputs{
				RequiredScope: sc.RequiredScope, ExpectedChallenge: sc.ExpectedChallenge, ContextPolicy: sc.ContextPolicy,
				ConfiguredNamespace: cfg.VerifierNamespace, ConfiguredReplayEpoch: cfg.ReplayEpoch, Now: sc.VerifyTime,
				MaxChallengeAgeSeconds: cfg.MaxChallengeAgeSeconds, FutureSkewSeconds: cfg.FutureSkewSeconds, TZDBVersion: cfg.TZDBVersion,
				ReceiverBindingHook: "absent", StatusKeys: map[string]v2StatusKeyJSON{}, StatusPolicy: cfg.StatusPolicy,
				Journal: v2JournalJSON{Mode: "anchored"}, AudienceMode: "ok", Rate: "absent",
			}
			rootKey, ok := fx.pub[sc.TrustRootKey]
			if !ok {
				t.Fatalf("trust root key %q is not in the fixture", sc.TrustRootKey)
			}
			in.Trust = &struct {
				Mode          string                   `json:"mode"`
				Outcome       string                   `json:"outcome"`
				RootPublicKey *ratify.HybridPublicKey  `json:"root_public_key"`
				Registry      []ratify.HybridPublicKey `json:"registry"`
			}{Mode: "ok", Outcome: "trusted", RootPublicKey: &rootKey}
			for issuer, k := range sc.StatusKeys {
				key, ok := fx.pub[k.Key]
				if !ok {
					t.Fatalf("status key %q is not in the fixture", k.Key)
				}
				in.StatusKeys[issuer] = v2StatusKeyJSON{Epoch: k.Epoch, StatusKeyID: fx.id[k.Key], PublicKey: key}
			}
			in.StatusEvidence = map[string]struct {
				Mode    string                 `json:"mode"`
				Objects []v2EvidenceObjectJSON `json:"objects"`
			}{}
			for issuer, objects := range sc.StatusEvidence {
				in.StatusEvidence[issuer] = struct {
					Mode    string                 `json:"mode"`
					Objects []v2EvidenceObjectJSON `json:"objects"`
				}{Mode: "ok", Objects: objects}
			}
			store, err := v2reference.NewStore(sc.VerifyTime, cfg.LeaseSeconds, cfg.ReceiptLogID, fx.priv[cfg.VerifierKey])
			if err != nil {
				t.Fatal(err)
			}
			req, cb, _ := v2BuildVerifyRequest(t, in, unb64(t, sc.BundleB64), &v2Counts{})
			cb.ClaimStore = store
			outcome, _ := ratify.VerifyProofBundleV2(ctx, req, cb)
			if outcome.Stage != ratify.V2StageCommitted {
				t.Fatalf("stage %s class %s (%v), want committed", outcome.Stage, outcome.ErrorClass, outcome.Error)
			}
			c := outcome.Committed
			horizon, isAllow := c.AllowHorizon()
			want := sc.Expected
			if !bytes.Equal(c.ReceiptBody(), unb64(t, want.ReceiptBodyB64)) || isAllow != (want.AllowHorizon != nil) || isAllow && horizon != *want.AllowHorizon {
				t.Fatalf("committed outcome differs: body %s horizon %d/%v", c.ReceiptBody(), horizon, isAllow)
			}
			store.SetTime(sc.PublishTime)
			if _, err := store.PublishV2Receipt(ctx, c.ClaimID(), c.ReceiptBody()); err != nil {
				t.Fatalf("publish: %v", err)
			}
			store.SetTime(sc.ReleaseTime)
			result := ratify.ReleaseV2Decision(ctx, c, unb64(t, want.SignedReceiptB64), ratify.V2ReleaseConfig{
				VerifierPublicKey: fx.pub[cfg.VerifierKey], LogID: cfg.ReceiptLogID, ClaimStore: store, Checkpoint: store})
			w := want.Release
			reason := ""
			if w.Reason != nil {
				reason = *w.Reason
			}
			if string(result.Status) != w.Status || result.Reason != reason || (result.Decision != nil) != (w.Decision != nil) {
				t.Fatalf("release %s/%s, want %+v", result.Status, result.Reason, w)
			}
			if d := result.Decision; d != nil && (d.Decision() != *w.Decision || w.ReleaseTime == nil || d.ReleaseTime() != *w.ReleaseTime) {
				t.Fatalf("released %s at %d, want %+v", d.Decision(), d.ReleaseTime(), w)
			}
		})
	}
	for _, name := range v2CrossScenarioNames {
		if !seen[name] {
			t.Errorf("missing scenario %s", name)
		}
	}
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
	t.Run("scenarios", func(t *testing.T) { v2CheckCrossScenarios(t, fx, f) })
}
