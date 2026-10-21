package ratify

import (
	"bytes"
	"strings"
	"testing"
)

func TestArchivalV2ResultsAreLabelledAndNonActionable(t *testing.T) {
	bundle := signedV2TestBundle(t)
	wire, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyProofBundleV2Archival(wire)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := BundleHashV2(bundle)
	if FreshnessUnverifiedV2 != "freshness_unverified" || got.Freshness != FreshnessUnverifiedV2 || got.Actionable || got.Digest != hash || got.ObjectType != 2 || got.SignerKeyIDs[len(got.SignerKeyIDs)-1] != bundle.AgentID {
		t.Fatalf("archival bundle result = %+v", got)
	}
	tampered := bytes.Replace(wire, []byte(`"challenge_at":`), []byte(`"challenge_at":1`), 1)
	if _, err := VerifyProofBundleV2Archival(tampered); err == nil {
		t.Fatal("tampered bundle passed archival verification")
	}
	certWire, err := EncodeDelegationCertV2(&bundle.Delegations[0])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyDelegationCertV2Archival(certWire); err != nil || got.Actionable || got.Freshness != FreshnessUnverifiedV2 || got.Digest != "" {
		t.Fatalf("archival certificate = %+v, %v", got, err)
	}
}

func TestArchivalV2StatusAndLogObjectsUseCallerKeys(t *testing.T) {
	statusPub, statusPriv, _ := GenerateHybridKeypair()
	otherPub, _, _ := GenerateHybridKeypair()
	issuer := strings.Repeat("b", 64)
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuer, UpdatedAt: 1, NextUpdate: 10, Sequence: 1, Revoked: []RevokedCertV2{}}, issuer, statusPub, statusPriv)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := EncodeRevocationListV2(list)
	if got, err := VerifyRevocationListV2Archival(wire, issuer, statusPub); err != nil || got.Actionable || got.Freshness != FreshnessUnverifiedV2 {
		t.Fatalf("archival list = %+v, %v", got, err)
	}
	if _, err := VerifyRevocationListV2Archival(wire, issuer, otherPub); V2ErrorClassOf(err) != V2ErrInvalidSignature {
		t.Fatalf("list under another status key: %v", err)
	}
	witnessPub, witnessPriv, _ := GenerateHybridKeypair()
	entry := &WitnessEntryV2{Version: 2, LogID: strings.Repeat("a", 32), Sequence: 7, PrevHash: bytes.Repeat([]byte{1}, 48), EntryData: []byte("x"), Timestamp: 1}
	entry.WitnessID, _ = KeyIDV2(witnessPub)
	signed, err := SignWitnessEntryV2(entry, witnessPriv)
	if err != nil {
		t.Fatal(err)
	}
	entryWire, _ := EncodeWitnessEntryV2(signed)
	got, err := VerifyWitnessEntryV2Archival(entryWire, witnessPub)
	digest, _ := WitnessEntryV2Digest(signed)
	if err != nil || got.Actionable || !strings.HasSuffix(got.Digest, strings.ToLower(hexV2Test(digest))) {
		t.Fatalf("archival witness entry (no log head needed) = %+v, %v", got, err)
	}
	if _, err := VerifyWitnessEntryV2Archival(entryWire, otherPub); V2ErrorClassOf(err) != V2ErrKeyIDMismatch {
		t.Fatalf("witness entry under another key: %v", err)
	}
}

func hexV2Test(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
