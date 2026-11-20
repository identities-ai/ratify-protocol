package verifyclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/exportsig"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/feedbatch"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

// testdata/v2_wire_golden.json holds files and signatures in the formats
// Verify already uses. Customers' tools and Verify must keep
// reading and writing exactly these bytes: a change here breaks files and
// signatures already in the field. ML-DSA-65 signing is randomized, so a
// re-signed object is compared by its body bytes and its deterministic
// Ed25519 signature.
type wireGolden struct {
	Now                  int64  `json:"now"`
	OrganizationID       string `json:"organization_id"`
	RootKeyID            string `json:"root_key_id"`
	IssuerKeyID          string `json:"issuer_key_id"`
	StatusKeyID          string `json:"status_key_id"`
	ChallengeValue       string `json:"challenge_value"`
	SetupRequest         string `json:"setup_request"`
	SetupRequestDigest   string `json:"setup_request_digest"`
	RenewalRequest       string `json:"renewal_request"`
	PossessionProof      string `json:"possession_proof"`
	SetupProofs          string `json:"setup_proofs"`
	ReceiverConfig       string `json:"receiver_config"`
	ReceiverConfigDigest string `json:"receiver_config_digest"`
	ExportDigest         string `json:"export_digest"`
	FeedBatch            string `json:"feed_batch"`
	FeedBatchDigest      string `json:"feed_batch_digest"`
}

type signedObject struct {
	Body      json.RawMessage        `json:"body"`
	Signature ratify.HybridSignature `json:"signature"`
}

func goldenKey(t *testing.T, seed byte) (ratify.HybridPublicKey, ratify.HybridPrivateKey, string) {
	t.Helper()
	var ed, ml [32]byte
	for i := range ed {
		ed[i], ml[i] = seed, seed+1
	}
	pub, private, err := ratify.HybridKeypairFromSeeds(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	id, err := setup.V2KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, private, id
}

// sameSigned requires two signed objects to carry the same body and the
// same Ed25519 signature over it.
func sameSigned(t *testing.T, name string, got, want signedObject) {
	t.Helper()
	if !bytes.Equal(got.Body, want.Body) || !bytes.Equal(got.Signature.Ed25519, want.Signature.Ed25519) {
		t.Errorf("%s: re-signed object differs from the golden bytes", name)
	}
}

func TestWireFormatsMatchGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/v2_wire_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g wireGolden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	_, rootPriv, rootID := goldenKey(t, 11)
	_, issuerPriv, issuerID := goldenKey(t, 21)
	_, _, statusID := goldenKey(t, 31)
	if rootID != g.RootKeyID || issuerID != g.IssuerKeyID || statusID != g.StatusKeyID {
		t.Fatal("V2KeyID changed")
	}
	if setup.V2KeySetupChallengeValue(g.OrganizationID, "issuer", issuerID, "00112233") != g.ChallengeValue {
		t.Error("V2KeySetupChallengeValue changed")
	}

	plan, err := setup.ParseV2KeySetupRequest([]byte(g.SetupRequest), g.Now)
	if err != nil || plan.RequestDigest != g.SetupRequestDigest || plan.RootKeyID != rootID ||
		plan.IssuerKeyID != issuerID || plan.StatusKeyID != statusID {
		t.Fatalf("setup request: %v", err)
	}
	if again, _ := ratify.CanonicalJSON(plan.Request); !bytes.Equal(again, []byte(g.SetupRequest)) {
		t.Error("setup request does not re-encode to the golden bytes")
	}
	if request, _, err := setup.ParseV2IssuerRenewalRequest([]byte(g.RenewalRequest), g.Now); err != nil {
		t.Errorf("renewal request: %v", err)
	} else if again, _ := ratify.CanonicalJSON(request); !bytes.Equal(again, []byte(g.RenewalRequest)) {
		t.Error("renewal request does not re-encode to the golden bytes")
	}
	proofs, err := setup.ParseV2KeySetupProofs([]byte(g.SetupProofs))
	if err != nil {
		t.Fatalf("setup proofs: %v", err)
	}
	if again, _ := ratify.CanonicalJSON(proofs); !bytes.Equal(again, []byte(g.SetupProofs)) {
		t.Error("setup proofs do not re-encode to the golden bytes")
	}

	expected := setup.V2KeyEnrollmentExpectation{Audience: "https://verify.example", Challenge: g.ChallengeValue,
		ChallengeID: "0123456789abcdef0123456789abcdef", CustodyMode: "customer_held", OwnerID: g.OrganizationID, Role: "issuer"}
	if _, id, err := setup.VerifyV2KeyPossessionProof([]byte(g.PossessionProof), expected, g.Now); err != nil || id != issuerID {
		t.Fatalf("possession proof: %v", err)
	}
	resigned, err := setup.SignV2KeyPossessionProof(setup.V2KeyPossessionProof{Audience: expected.Audience,
		Challenge: expected.Challenge, ChallengeID: expected.ChallengeID, CustodyMode: expected.CustodyMode,
		IssuedAt: g.Now - 5, ExpiresAt: g.Now + 600, OwnerID: expected.OwnerID, Role: expected.Role}, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	var gotProof, wantProof signedObject
	_ = json.Unmarshal(resigned, &gotProof)
	_ = json.Unmarshal([]byte(g.PossessionProof), &wantProof)
	sameSigned(t, "possession proof", gotProof, wantProof)

	config, err := setup.ParseV2ReceiverConfig([]byte(g.ReceiverConfig), nil, g.Now)
	if err != nil || config.Digest != g.ReceiverConfigDigest {
		t.Fatalf("receiver config: %v", err)
	}
	head := config.Head
	head.ContentDigest, head.Schema, head.VerifyCode, head.Version = "", "", 0, 0
	resignedConfig, err := setup.SignV2ReceiverConfig(config.Content, head, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	var gotConfig, wantConfig struct{ Content, Head signedObject }
	_ = json.Unmarshal(resignedConfig, &gotConfig)
	_ = json.Unmarshal([]byte(g.ReceiverConfig), &wantConfig)
	sameSigned(t, "receiver config content", gotConfig.Content, wantConfig.Content)
	sameSigned(t, "receiver config head", gotConfig.Head, wantConfig.Head)

	signedAt := time.Unix(g.Now, 0).UTC()
	digest, err := exportsig.Digest(exportsig.ArtifactFeedBatch, "1", "export-key-1", signedAt, []byte("payload"))
	if err != nil || hex.EncodeToString(digest) != g.ExportDigest {
		t.Errorf("export digest changed: %v", err)
	}
	batch, err := json.Marshal(feedbatch.Batch{Type: feedbatch.Type, Version: feedbatch.Version, OrgID: g.OrganizationID,
		DestinationID: "dest-1", BatchSeq: 1, LastSeq: 1, CreatedAt: signedAt, Events: []feedbatch.Event{{
			ID: feedbatch.EventID(g.OrganizationID, 1), Seq: 1, Source: "verify", Kind: "decision", OccurredAt: signedAt,
			Payload: json.RawMessage(`{"a":1}`)}}})
	if err != nil || string(batch) != g.FeedBatch || feedbatch.Digest(batch) != g.FeedBatchDigest {
		t.Errorf("feed batch encoding changed: %v", err)
	}
}
