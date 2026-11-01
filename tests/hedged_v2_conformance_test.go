package ratify_test

import (
	"bytes"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// TestV2ConformanceHedgedSignatures runs testvectors/v2/hedged-signatures.json.
// Each object carries the same signed bodies as objects.json with ML-DSA-65
// components produced by hedged (randomized) signing. A verifier must accept
// every variant, derive identical signable projections and statement body
// digests, and treat a re-signed identical body as a replay, never a fork.
func TestV2ConformanceHedgedSignatures(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version     int    `json:"version"`
		Description string `json:"description"`
		Objects     []struct {
			Name                 string          `json:"name"`
			Kind                 string          `json:"kind"`
			Verify               v2VerifyContext `json:"verify"`
			ResignedFields       []string        `json:"resigned_fields"`
			DeterministicWireB64 string          `json:"deterministic_wire_b64"`
			HedgedWireB64        []string        `json:"hedged_wire_b64"`
		} `json:"objects"`
	}
	loadV2Vector(t, "hedged-signatures.json", &f)
	kinds := map[string]bool{}
	for _, o := range f.Objects {
		kinds[o.Kind] = true
		t.Run(o.Name, func(t *testing.T) {
			deterministic := unb64(t, o.DeterministicWireB64)
			if len(o.HedgedWireB64) < 2 || len(o.ResignedFields) == 0 {
				t.Fatal("each object needs at least two hedged variants and one re-signed field")
			}
			seen := [][]byte{deterministic}
			for i, encoded := range o.HedgedWireB64 {
				wire := unb64(t, encoded)
				for _, prior := range seen {
					if bytes.Equal(prior, wire) {
						t.Fatalf("variant %d repeats an earlier signature; hedging was not exercised", i)
					}
				}
				seen = append(seen, wire)
				if got := v2Reencode(t, o.Kind, wire); !bytes.Equal(got, wire) {
					t.Fatalf("variant %d does not re-encode identically", i)
				}
				if err := v2VerifyObject(t, fx, o.Kind, wire, nil, o.Verify); err != nil {
					t.Fatalf("variant %d: %v", i, err)
				}
				for _, field := range o.ResignedFields {
					if !bytes.Equal(v2Projection(t, wire, field), v2Projection(t, deterministic, field)) {
						t.Fatalf("variant %d: %s signable projection differs from the deterministic fixture", i, field)
					}
				}
				checkHedgedIdempotency(t, fx, o.Kind, o.Verify, deterministic, wire)
			}
		})
	}
	for _, kind := range []string{"delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement", "witness_entry", "transaction_receipt", "verification_receipt"} {
		if !kinds[kind] {
			t.Errorf("hedged-signatures.json has no %s", kind)
		}
	}
}

// checkHedgedIdempotency proves that log replay is decided by the statement
// body digest: once the deterministic object is accepted, the hedged variant
// of the same body is a replay rather than a fork.
func checkHedgedIdempotency(t *testing.T, fx v2Fixture, kind string, vc v2VerifyContext, deterministic, hedged []byte) {
	t.Helper()
	switch kind {
	case "witness_entry":
		first, err := ratify.DecodeWitnessEntryV2(deterministic)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ratify.DecodeWitnessEntryV2(hedged)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := ratify.WitnessEntryV2Digest(first)
		if err != nil {
			t.Fatal(err)
		}
		other, err := ratify.WitnessEntryV2Digest(again)
		if err != nil || !bytes.Equal(digest, other) {
			t.Fatalf("hedged witness entry has a different body digest: %v", err)
		}
		head := vc.Head.witness(t)
		head.Sequence, head.HeadHash, head.AcceptedDigests = first.Sequence, digest, map[int64][]byte{first.Sequence: digest}
		result, err := ratify.VerifyWitnessEntryV2(again, head, fx.pub[vc.WitnessKey])
		if err != nil || result != ratify.WitnessEntryV2Replay {
			t.Fatalf("hedged re-signing of an accepted witness entry was not a replay: %v %v", result, err)
		}
	case "verification_receipt":
		first, err := ratify.DecodeVerificationReceiptV2(deterministic)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ratify.DecodeVerificationReceiptV2(hedged)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := ratify.VerificationReceiptV2Digest(first)
		if err != nil {
			t.Fatal(err)
		}
		other, err := ratify.VerificationReceiptV2Digest(again)
		if err != nil || !bytes.Equal(digest, other) {
			t.Fatalf("hedged receipt has a different body digest: %v", err)
		}
		head := vc.Head.receipt(t)
		head.Sequence, head.HeadHash, head.AcceptedDigests = first.Sequence, digest, map[int64][]byte{first.Sequence: digest}
		result, err := ratify.VerifyVerificationReceiptV2(again, fx.pub[vc.VerifierKey], head)
		if err != nil || result != ratify.WitnessEntryV2Replay {
			t.Fatalf("hedged re-signing of an accepted receipt was not a replay: %v %v", result, err)
		}
	case "key_rotation_statement":
		first, err := ratify.DecodeKeyRotationStatementV2(deterministic)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ratify.DecodeKeyRotationStatementV2(hedged)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := ratify.KeyRotationStatementV2Digest(first)
		if err != nil {
			t.Fatal(err)
		}
		other, err := ratify.KeyRotationStatementV2Digest(again)
		if err != nil || !bytes.Equal(digest, other) {
			t.Fatalf("hedged rotation statement has a different body digest: %v", err)
		}
	}
}
