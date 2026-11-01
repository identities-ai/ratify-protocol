package ratify_test

// Shared archival (SPEC-v2 §6.10), external signer (§3.2), and digest
// function (§4) vectors.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func TestV2ConformanceArchival(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version         int               `json:"version"`
		Description     string            `json:"description"`
		ProcedureByKind map[string]string `json:"procedure_by_kind"`
		Cases           []struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			Description string `json:"description"`
			WireB64     string `json:"wire_b64"`
			Verify      *struct {
				IssuerID    string `json:"issuer_id"`
				StatusKey   string `json:"status_key"`
				WitnessKey  string `json:"witness_key"`
				VerifierKey string `json:"verifier_key"`
			} `json:"verify"`
			Expected           json.RawMessage `json:"expected"`
			ExpectedErrorClass string          `json:"expected_error_class"`
		} `json:"cases"`
	}
	loadV2Vector(t, "archival.json", &f)
	kinds := map[string]bool{}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			kinds[c.Kind] = true
			wire := unb64(t, c.WireB64)
			var got any
			var err error
			switch c.Kind {
			case "proof_bundle":
				got = ratify.VerifyArchivalProofBundleV2(wire)
			case "delegation_certificate":
				got, err = ratify.VerifyArchivalDelegationCertV2(wire)
			case "revocation_list":
				got, err = ratify.VerifyArchivalRevocationListV2(wire, c.Verify.IssuerID, fx.pub[c.Verify.StatusKey])
			case "revocation_push":
				got, err = ratify.VerifyArchivalRevocationPushV2(wire, c.Verify.IssuerID, fx.pub[c.Verify.StatusKey])
			case "key_rotation_statement":
				got, err = ratify.VerifyArchivalKeyRotationStatementV2(wire)
			case "witness_entry":
				got, err = ratify.VerifyArchivalWitnessEntryV2(wire, fx.pub[c.Verify.WitnessKey])
			case "verification_receipt":
				got, err = ratify.VerifyArchivalVerificationReceiptV2(wire, fx.pub[c.Verify.VerifierKey])
			case "transaction_receipt":
				got, err = ratify.VerifyArchivalTransactionReceiptV2(wire)
			default:
				t.Fatalf("unknown kind %s", c.Kind)
			}
			if c.ExpectedErrorClass != "" {
				if err == nil || string(ratify.V2ErrorClassOf(err)) != c.ExpectedErrorClass {
					t.Fatalf("error %v (class %q), want class %q", err, ratify.V2ErrorClassOf(err), c.ExpectedErrorClass)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var generic any
			if err := json.Unmarshal(raw, &generic); err != nil {
				t.Fatal(err)
			}
			gotJSON, err := ratify.CanonicalJSON(generic)
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal(c.Expected, &want); err != nil {
				t.Fatal(err)
			}
			wantJSON, err := ratify.CanonicalJSON(want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("result\n got %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
	for _, kind := range []string{"proof_bundle", "delegation_certificate", "revocation_list", "revocation_push", "key_rotation_statement", "witness_entry", "verification_receipt", "transaction_receipt"} {
		if !kinds[kind] {
			t.Errorf("no archival case for %s", kind)
		}
	}
}

// v2ScriptedSigner answers every request with fixed bytes and records it.
type v2ScriptedSigner struct {
	pub      ratify.HybridPublicKey
	mode     ratify.SignerModeV2
	response string
	sig      ratify.HybridSignature
	cancel   context.CancelFunc
	requests []ratify.SignRequestV2
}

func (s *v2ScriptedSigner) PublicKeyV2() ratify.HybridPublicKey { return s.pub }
func (s *v2ScriptedSigner) ModeV2() ratify.SignerModeV2         { return s.mode }
func (s *v2ScriptedSigner) SignV2(_ context.Context, req ratify.SignRequestV2) (ratify.HybridSignature, error) {
	s.requests = append(s.requests, req)
	switch s.response {
	case "error":
		return ratify.HybridSignature{}, errors.New("scripted provider failure")
	case "cancel":
		s.cancel()
	}
	return s.sig, nil
}

func TestV2ConformanceExternalSigner(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version     int               `json:"version"`
		Description string            `json:"description"`
		Semantics   map[string]string `json:"semantics"`
		Cases       []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Kind        string `json:"kind"`
			ObjectB64   string `json:"object_b64"`
			Binding     *struct {
				IssuerID  string `json:"issuer_id"`
				StatusKey string `json:"status_key"`
			} `json:"binding"`
			CallerCancelled bool `json:"caller_cancelled"`
			Provider        struct {
				PublicKey string            `json:"public_key"`
				Mode      string            `json:"mode"`
				Response  string            `json:"response"`
				Signature map[string]string `json:"signature"`
			} `json:"provider"`
			Expected struct {
				Result        string `json:"result"`
				ErrorClass    string `json:"error_class"`
				ProviderCalls int    `json:"provider_calls"`
				Request       *struct {
					Mode         string  `json:"mode"`
					MessageB64   string  `json:"message_b64"`
					MLDSAContext *string `json:"mldsa_context"`
					MLDSAMuB64   *string `json:"mldsa_mu_b64"`
					KeyIDV2      string  `json:"key_id_v2"`
				} `json:"request"`
				SignedWireB64 string `json:"signed_wire_b64"`
			} `json:"expected"`
		} `json:"cases"`
	}
	loadV2Vector(t, "external-signer.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			signer := &v2ScriptedSigner{pub: fx.pub[c.Provider.PublicKey], response: c.Provider.Response, cancel: cancel}
			switch c.Provider.Mode {
			case "direct":
				signer.mode = ratify.SignerModeDirectV2
			case "external_mu":
				signer.mode = ratify.SignerModeExternalMuV2
			default:
				t.Fatalf("unknown mode %s", c.Provider.Mode)
			}
			if c.Provider.Signature != nil {
				signer.sig = ratify.HybridSignature{Ed25519: unb64(t, c.Provider.Signature["ed25519"]), MLDSA65: unb64(t, c.Provider.Signature["ml_dsa_65"])}
			}
			if c.CallerCancelled {
				cancel()
			}
			wire := unb64(t, c.ObjectB64)
			var signed []byte
			var err error
			switch c.Kind {
			case "delegation_certificate":
				cert, derr := ratify.DecodeDelegationCertV2(wire)
				if derr != nil {
					t.Fatal(derr)
				}
				var out *ratify.DelegationCertV2
				if out, err = ratify.SignDelegationCertV2WithSigner(ctx, cert, signer); err == nil {
					signed, err = ratify.EncodeDelegationCertV2(out)
				}
			case "revocation_list":
				list, derr := ratify.DecodeRevocationListV2(wire)
				if derr != nil {
					t.Fatal(derr)
				}
				var out *ratify.RevocationListV2
				if out, err = ratify.SignRevocationListV2WithSigner(ctx, list, c.Binding.IssuerID, fx.pub[c.Binding.StatusKey], signer); err == nil {
					signed, err = ratify.EncodeRevocationListV2(out)
				}
			case "proof_bundle":
				bundle, derr := ratify.DecodeProofBundleV2(wire)
				if derr != nil {
					t.Fatal(derr)
				}
				var out *ratify.ProofBundleV2
				if out, err = ratify.SignProofBundleV2WithSigner(ctx, bundle, signer); err == nil {
					signed, err = ratify.EncodeProofBundleV2(out)
				}
			default:
				t.Fatalf("unknown kind %s", c.Kind)
			}
			e := c.Expected
			if len(signer.requests) != e.ProviderCalls {
				t.Fatalf("provider calls %d, want %d", len(signer.requests), e.ProviderCalls)
			}
			if e.Request != nil {
				r := signer.requests[0]
				mode := map[ratify.SignerModeV2]string{ratify.SignerModeDirectV2: "direct", ratify.SignerModeExternalMuV2: "external_mu"}[r.Mode]
				ctxMatch := (e.Request.MLDSAContext == nil && r.MLDSAContext == nil) || (e.Request.MLDSAContext != nil && string(r.MLDSAContext) == *e.Request.MLDSAContext)
				muMatch := (e.Request.MLDSAMuB64 == nil && r.MLDSAMu == nil) || (e.Request.MLDSAMuB64 != nil && bytes.Equal(r.MLDSAMu, unb64(t, *e.Request.MLDSAMuB64)))
				if mode != e.Request.Mode || !bytes.Equal(r.Message, unb64(t, e.Request.MessageB64)) || !ctxMatch || !muMatch || r.KeyID != e.Request.KeyIDV2 {
					t.Fatalf("provider request %+v differs from %+v", r, e.Request)
				}
			}
			if e.Result == "signed" {
				if err != nil || !bytes.Equal(signed, unb64(t, e.SignedWireB64)) {
					t.Fatalf("signed object differs (%v)", err)
				}
				return
			}
			if err == nil || signed != nil || string(ratify.V2ErrorClassOf(err)) != e.ErrorClass {
				t.Fatalf("error %v (class %q), want class %q and no object", err, ratify.V2ErrorClassOf(err), e.ErrorClass)
			}
		})
	}
}

func TestV2ConformanceDigestFunctions(t *testing.T) {
	var f struct {
		Version     int               `json:"version"`
		Description string            `json:"description"`
		Functions   map[string]string `json:"functions"`
		Cases       []struct {
			Name               string `json:"name"`
			Description        string `json:"description"`
			Function           string `json:"function"`
			ObjectTypeCode     int    `json:"object_type_code"`
			InputB64           string `json:"input_b64"`
			ExpectedDigest     string `json:"expected_digest"`
			ExpectedErrorClass string `json:"expected_error_class"`
		} `json:"cases"`
	}
	loadV2Vector(t, "digest-functions.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			input := unb64(t, c.InputB64)
			var digest []byte
			var err error
			switch c.Function {
			case "statement_body_digest":
				if c.ObjectTypeCode < 0 || c.ObjectTypeCode > 0xffff {
					// The code parameter is 16 bits: such a code cannot be
					// passed, and must never be truncated to one that can.
					if c.ExpectedErrorClass != "unsupported_object_type" {
						t.Fatalf("code %#x outside 16 bits, want class %q", c.ObjectTypeCode, c.ExpectedErrorClass)
					}
					return
				}
				digest, err = ratify.StatementBodyDigestV2(uint16(c.ObjectTypeCode), input)
			case "status_evidence_digest":
				list, derr := ratify.DecodeRevocationListV2(input)
				if derr != nil {
					t.Fatal(derr)
				}
				digest, err = ratify.StatusEvidenceDigest(uint16(c.ObjectTypeCode), list)
			default:
				t.Fatalf("unknown function %s", c.Function)
			}
			if c.ExpectedErrorClass != "" {
				if err == nil || digest != nil || string(ratify.V2ErrorClassOf(err)) != c.ExpectedErrorClass {
					t.Fatalf("error %v (class %q), want class %q", err, ratify.V2ErrorClassOf(err), c.ExpectedErrorClass)
				}
				return
			}
			if got := fmt.Sprintf("sha384:%s", hex.EncodeToString(digest)); err != nil || got != c.ExpectedDigest {
				t.Fatalf("digest %s (%v), want %s", got, err, c.ExpectedDigest)
			}
		})
	}
}
