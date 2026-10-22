package ratify

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func signedTransactionReceiptV2Test(t testing.TB) (*TransactionReceiptV2, HybridPrivateKey) {
	t.Helper()
	issuerPub, issuerKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	intermediatePub, intermediateKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerID, err := keyIDV2(issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := keyIDV2(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	intermediateID, err := keyIDV2(intermediatePub)
	if err != nil {
		t.Fatal(err)
	}
	const terms = `{"amount":7,"currency":"USD"}`
	receipt := &TransactionReceiptV2{
		Version: 2, TransactionID: "tx-v2-1", CreatedAt: 10,
		TermsSchemaURI: "https://example.test/schemas/payment/v1", TermsCanonicalJSON: []byte(terms),
		Parties: []TransactionReceiptPartyV2{{
			PartyID: "buyer", Role: "buyer", AgentID: agentID, AgentPubKey: agentPub,
			VerifierID: strings.Repeat("a", 64), WorkspaceID: "7c66c74c-6a2e-4363-9c05-22651535803c",
			SessionID: "session-1", InvocationID: "invoke-1", RequiredScope: "execute:tool",
		}},
	}
	transactionHash := transactionContextHashV2(receipt)
	partyHash := transactionPartyRequestHashV2(transactionHash, "execute:tool")
	context, err := BuildSessionContextV2(SessionContextV2Inputs{
		VerifierID: receipt.Parties[0].VerifierID, WorkspaceID: receipt.Parties[0].WorkspaceID,
		AgentID: agentID, SessionID: receipt.Parties[0].SessionID,
		InvocationID: receipt.Parties[0].InvocationID, RequestHash: partyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := SignDelegationCertV2(&DelegationCertV2{
		Version: 2, CertID: "tx-cert-root", IssuerID: issuerID, IssuerPubKey: issuerPub,
		SubjectID: intermediateID, SubjectPubKey: intermediatePub, Scope: []string{"execute:tool"},
		Constraints: []ConstraintV2{}, IssuedAt: 1, ExpiresAt: 20,
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := &DelegationCertV2{
		Version: 2, CertID: "tx-cert-1", IssuerID: intermediateID, IssuerPubKey: intermediatePub,
		SubjectID: agentID, SubjectPubKey: agentPub, Scope: []string{"execute:tool"},
		Constraints: []ConstraintV2{}, IssuedAt: 1, ExpiresAt: 20,
	}
	cert, err = SignDelegationCertV2(cert, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &ProofBundleV2{
		Version: 2, VerifierID: receipt.Parties[0].VerifierID, AgentID: agentID, AgentPubKey: agentPub,
		Delegations: []DelegationCertV2{*cert, *rootCert}, Challenge: bytes.Repeat([]byte{0x42}, 32), ChallengeAt: 10,
		SessionContext: &context,
	}
	bundle, err = SignProofBundleV2(bundle, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Parties[0].ProofBundle = bundle
	receipt.Parties[0].ProofBundleHash, err = BundleHashV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignTransactionReceiptPartyV2(receipt, "buyer", agentKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt.PartySignatures = []TransactionReceiptSignatureV2{signature}
	return receipt, agentKey
}

func transactionPartyV2Test(t testing.TB, receipt *TransactionReceiptV2, partyID, role string) (TransactionReceiptPartyV2, HybridPrivateKey) {
	t.Helper()
	issuerPub, issuerKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerID, err := keyIDV2(issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := keyIDV2(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	party := TransactionReceiptPartyV2{
		PartyID: partyID, Role: role, AgentID: agentID, AgentPubKey: agentPub,
		VerifierID: strings.Repeat("a", 64), WorkspaceID: "7c66c74c-6a2e-4363-9c05-22651535803c",
		SessionID: "session-" + partyID, InvocationID: "invoke-" + partyID, RequiredScope: "execute:tool",
	}
	transactionHash := transactionContextHashV2(receipt)
	requestHash := transactionPartyRequestHashV2(transactionHash, party.RequiredScope)
	context, err := BuildSessionContextV2(SessionContextV2Inputs{
		VerifierID: party.VerifierID, WorkspaceID: party.WorkspaceID, AgentID: party.AgentID,
		SessionID: party.SessionID, InvocationID: party.InvocationID, RequestHash: requestHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignDelegationCertV2(&DelegationCertV2{
		Version: 2, CertID: "tx-cert-" + partyID, IssuerID: issuerID, IssuerPubKey: issuerPub,
		SubjectID: agentID, SubjectPubKey: agentPub, Scope: []string{"execute:tool"},
		Constraints: []ConstraintV2{}, IssuedAt: 1, ExpiresAt: 20,
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	party.ProofBundle, err = SignProofBundleV2(&ProofBundleV2{
		Version: 2, VerifierID: party.VerifierID, AgentID: party.AgentID, AgentPubKey: party.AgentPubKey,
		Delegations: []DelegationCertV2{*cert}, Challenge: bytes.Repeat([]byte{0x55}, 32), ChallengeAt: 10,
		SessionContext: &context,
	}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	party.ProofBundleHash, err = BundleHashV2(party.ProofBundle)
	if err != nil {
		t.Fatal(err)
	}
	return party, agentKey
}

func TestTransactionReceiptV2RoundTripAndBindings(t *testing.T) {
	receipt, agentKey := signedTransactionReceiptV2Test(t)
	wire, err := EncodeTransactionReceiptV2(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTransactionReceiptV2(wire)
	if err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if decoded.TransactionID != receipt.TransactionID || decoded.Parties[0].PartyID != "buyer" {
		t.Fatalf("decoded receipt mismatch: %+v", decoded)
	}
	_, wrongKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignTransactionReceiptPartyV2(receipt, "buyer", wrongKey); err == nil {
		t.Fatal("signed party statement with a key that does not belong to the named agent")
	}
	if _, err := SignTransactionReceiptPartyV2(receipt, "buyer", agentKey); err != nil {
		t.Fatalf("named party could not produce its signature: %v", err)
	}

	t.Run("proof hash mismatch", func(t *testing.T) {
		tampered := *receipt
		tampered.Parties = append([]TransactionReceiptPartyV2(nil), receipt.Parties...)
		tampered.Parties[0].ProofBundleHash = strings.Repeat("0", len(receipt.Parties[0].ProofBundleHash))
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted mismatched embedded bundle hash")
		}
	})
	t.Run("scope context mismatch", func(t *testing.T) {
		tampered := *receipt
		tampered.Parties = append([]TransactionReceiptPartyV2(nil), receipt.Parties...)
		tampered.Parties[0].RequiredScope = "data:read"
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted bundle context for a different requested scope")
		}
	})
	t.Run("missing party signature", func(t *testing.T) {
		tampered := *receipt
		tampered.PartySignatures = nil
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted receipt without the required party signature")
		}
	})
	t.Run("unknown party signature", func(t *testing.T) {
		tampered := *receipt
		tampered.PartySignatures = []TransactionReceiptSignatureV2{{PartyID: "unknown", Signature: receipt.PartySignatures[0].Signature}}
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted a signature for a party absent from the receipt")
		}
	})
	t.Run("party text must be valid UTF-8", func(t *testing.T) {
		tampered := *receipt
		tampered.Parties = append([]TransactionReceiptPartyV2(nil), receipt.Parties...)
		tampered.Parties[0].Role = string([]byte{0xff})
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted malformed Unicode in a signed party field")
		}
	})
	t.Run("signatures remain bound to object code 0x0007", func(t *testing.T) {
		signable, err := transactionReceiptV2SignableBytes(receipt)
		if err != nil {
			t.Fatal(err)
		}
		wrongCodeSignature, err := signV2Statement(v2ChallengePresentation, signable, agentKey)
		if err != nil {
			t.Fatal(err)
		}
		tampered := *receipt
		tampered.PartySignatures = []TransactionReceiptSignatureV2{{PartyID: "buyer", Signature: wrongCodeSignature}}
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted party signature under the challenge-presentation object code")
		}
	})
	t.Run("agent cannot represent two parties", func(t *testing.T) {
		tampered := *receipt
		tampered.Parties = append([]TransactionReceiptPartyV2(nil), receipt.Parties...)
		secondParty := tampered.Parties[0]
		secondParty.PartyID = "seller"
		secondParty.Role = "seller"
		tampered.Parties = append(tampered.Parties, secondParty)
		if err := VerifyTransactionReceiptV2Signatures(&tampered); err == nil {
			t.Fatal("accepted one agent key as two transaction parties")
		}
	})
	t.Run("multiple parties have a single deterministic signature order", func(t *testing.T) {
		mutated := *receipt
		mutated.Parties = append([]TransactionReceiptPartyV2(nil), receipt.Parties...)
		secondParty, sellerKey := transactionPartyV2Test(t, &mutated, "seller", "seller")
		mutated.Parties = append(mutated.Parties, secondParty)
		mutated.PartySignatures = nil
		for _, party := range []struct {
			id  string
			key HybridPrivateKey
		}{{"seller", sellerKey}, {"buyer", agentKey}} {
			signature, err := SignTransactionReceiptPartyV2(&mutated, party.id, party.key)
			if err != nil {
				t.Fatal(err)
			}
			mutated.PartySignatures = append(mutated.PartySignatures, signature)
		}
		if err := VerifyTransactionReceiptV2Signatures(&mutated); err != nil {
			t.Fatalf("signature order changed receipt semantics: %v", err)
		}
		wire, err := EncodeTransactionReceiptV2(&mutated)
		if err != nil {
			t.Fatal(err)
		}
		mutated.PartySignatures[0], mutated.PartySignatures[1] = mutated.PartySignatures[1], mutated.PartySignatures[0]
		reordered, err := EncodeTransactionReceiptV2(&mutated)
		if err != nil || !bytes.Equal(wire, reordered) {
			t.Fatalf("signature input order did not normalize deterministically: %v", err)
		}
		if _, err := DecodeTransactionReceiptV2(wire); err != nil {
			t.Fatalf("canonical sorted signature records did not decode: %v", err)
		}
	})
}

func TestEncodeTransactionReceiptV2UsesCanonicalObjectKeyOrder(t *testing.T) {
	receipt, _ := signedTransactionReceiptV2Test(t)
	wire, err := EncodeTransactionReceiptV2(receipt)
	if err != nil {
		t.Fatal(err)
	}
	objectKeys := func(object []byte) []string {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(object))
		token, err := decoder.Token()
		if err != nil || token != json.Delim('{') {
			t.Fatalf("expected JSON object: %v", err)
		}
		var keys []string
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				t.Fatal(err)
			}
			key, ok := token.(string)
			if !ok {
				t.Fatalf("expected object key, got %T", token)
			}
			keys = append(keys, key)
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
		}
		return keys
	}
	if got, want := objectKeys(wire), []string{
		"created_at", "parties", "party_signatures", "terms_canonical_json",
		"terms_schema_uri", "transaction_id", "version",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("top-level transaction receipt keys are not canonical: %v", got)
	}
	var partyWire struct {
		Parties []json.RawMessage `json:"parties"`
	}
	if err := json.Unmarshal(wire, &partyWire); err != nil || len(partyWire.Parties) != 1 {
		t.Fatalf("decode party fixture: parties=%d err=%v", len(partyWire.Parties), err)
	}
	if got, want := objectKeys(partyWire.Parties[0]), []string{
		"agent_id", "agent_pub_key", "invocation_id", "party_id", "proof_bundle",
		"proof_bundle_hash", "required_scope", "role", "session_id", "verifier_id", "workspace_id",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction party keys are not canonical: %v", got)
	}
}

func TestDecodeTransactionReceiptV2RejectsMalformedCanonicalTermsAndDuplicateKeys(t *testing.T) {
	receipt, _ := signedTransactionReceiptV2Test(t)
	for name, terms := range map[string][]byte{
		"whitespace":     []byte(`{ "amount":7,"currency":"USD"}`),
		"duplicate key":  []byte(`{"amount":7,"amount":8,"currency":"USD"}`),
		"non-object":     []byte(`[]`),
		"fraction":       []byte(`{"amount":7.5,"currency":"USD"}`),
		"exponent":       []byte(`{"amount":7e0,"currency":"USD"}`),
		"negative zero":  []byte(`{"amount":-0,"currency":"USD"}`),
		"unsafe integer": []byte(`{"amount":9007199254740992,"currency":"USD"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCanonicalTransactionTermsV2(terms); err == nil {
				t.Fatal("accepted noncanonical transaction terms")
			}
		})
	}
	if err := validateCanonicalTransactionTermsV2([]byte(`{"amount":9007199254740991}`)); err != nil {
		t.Fatalf("rejected maximum safe JSON integer: %v", err)
	}
	nestedTerms := func(depth int) []byte {
		value := []byte(`{}`)
		for i := 1; i < depth; i++ {
			value = append(append([]byte(`{"v":`), value...), '}')
		}
		return value
	}
	if err := validateCanonicalTransactionTermsV2(nestedTerms(MaxJSONNestingDepth)); err != nil {
		t.Fatalf("rejected terms at maximum JSON nesting depth: %v", err)
	}
	if err := validateCanonicalTransactionTermsV2(nestedTerms(MaxJSONNestingDepth + 1)); err == nil || !strings.Contains(err.Error(), "MAX_JSON_NESTING_DEPTH") {
		t.Fatalf("terms beyond JSON nesting limit were accepted: %v", err)
	}
	wire, err := EncodeTransactionReceiptV2(receipt)
	if err != nil {
		t.Fatal(err)
	}
	withDuplicate := bytes.Replace(wire, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1)
	if _, err := DecodeTransactionReceiptV2(withDuplicate); err == nil {
		t.Fatal("accepted duplicate receipt field")
	}
	if _, err := DecodeTransactionReceiptV2(append([]byte{' '}, wire...)); err == nil {
		t.Fatal("accepted a non-canonical receipt wire encoding")
	}
	if _, err := DecodeTransactionReceiptV2([]byte(`{"version":2}`)); err == nil {
		t.Fatal("accepted incomplete transaction receipt")
	}
	if err := validateCanonicalTransactionTermsV2([]byte(`{"amount":9007199254740992}`)); err == nil {
		t.Fatal("accepted integer just above the safe JSON boundary")
	}
}

func TestDecodeTransactionReceiptV2ChecksBundleHashBeforeBundleSignatures(t *testing.T) {
	receipt, _ := signedTransactionReceiptV2Test(t)
	wire, err := EncodeTransactionReceiptV2(receipt)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(wire, []byte(`"challenge_at":10`), []byte(`"challenge_at":11`), 1)
	if bytes.Equal(mutated, wire) {
		t.Fatal("fixture did not contain the v2 proof challenge timestamp")
	}
	_, err = DecodeTransactionReceiptV2(mutated)
	if err == nil || !strings.Contains(err.Error(), "proof_bundle_hash") {
		t.Fatalf("bundle was decoded or verified before its hash was checked: %v", err)
	}
}

func TestTransactionReceiptV2EnforcesPublishedBounds(t *testing.T) {
	receipt, _ := signedTransactionReceiptV2Test(t)
	tooManyParties := *receipt
	tooManyParties.Parties = make([]TransactionReceiptPartyV2, MaxTransactionParties+1)
	if err := validateTransactionReceiptV2(&tooManyParties, false); err == nil || !strings.Contains(err.Error(), "MAX_TRANSACTION_PARTIES") {
		t.Fatalf("party-count bound was not enforced: %v", err)
	}
	manyParties := []byte(`{"created_at":1,"parties":[` + strings.TrimSuffix(strings.Repeat("null,", MaxTransactionParties+1), ",") + `],"party_signatures":[],"terms_canonical_json":"e30=","terms_schema_uri":"schema:v1","transaction_id":"tx","version":2}`)
	if _, err := DecodeTransactionReceiptV2(manyParties); err == nil || !strings.Contains(err.Error(), "MAX_TRANSACTION_PARTIES") {
		t.Fatalf("wire party-count bound was not enforced before bundle parsing: %v", err)
	}
	if _, err := DecodeTransactionReceiptV2(bytes.Repeat([]byte{' '}, MaxTransactionReceiptBytes+1)); err == nil || !strings.Contains(err.Error(), "MAX_TRANSACTION_RECEIPT_BYTES") {
		t.Fatalf("receipt byte bound was not enforced before parsing: %v", err)
	}
}

func TestTransactionReceiptV2OrdersUnicodePartyIDsByUTF8Bytes(t *testing.T) {
	receipt, firstKey := signedTransactionReceiptV2Test(t)
	receipt.Parties = append([]TransactionReceiptPartyV2(nil), receipt.Parties...)
	receipt.Parties[0].PartyID = "𐀀"
	receipt.Parties[0].Role = "first"
	receipt.PartySignatures = nil
	secondParty, secondKey := transactionPartyV2Test(t, receipt, "", "second")
	receipt.Parties = []TransactionReceiptPartyV2{secondParty, receipt.Parties[0]}
	unsorted := *receipt
	unsorted.Parties = []TransactionReceiptPartyV2{receipt.Parties[1], receipt.Parties[0]}
	if err := validateTransactionReceiptV2(&unsorted, false); err == nil || !strings.Contains(err.Error(), "sorted by unique party_id") {
		t.Fatalf("unsorted UTF-16 order was not rejected specifically for party order: %v", err)
	}
	for _, party := range []struct {
		id  string
		key HybridPrivateKey
	}{{"𐀀", firstKey}, {"", secondKey}} {
		signature, err := SignTransactionReceiptPartyV2(receipt, party.id, party.key)
		if err != nil {
			t.Fatal(err)
		}
		receipt.PartySignatures = append(receipt.PartySignatures, signature)
	}
	wire, err := EncodeTransactionReceiptV2(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTransactionReceiptV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Parties[0].PartyID != "" || decoded.Parties[1].PartyID != "𐀀" {
		t.Fatalf("parties not ordered by UTF-8 bytes: %q, %q", decoded.Parties[0].PartyID, decoded.Parties[1].PartyID)
	}
	if strings.Index(string(wire), `"party_id":""`) > strings.Index(string(wire), `"party_id":"𐀀"`) {
		t.Fatal("canonical party array did not use UTF-8 byte order")
	}
}

func FuzzDecodeTransactionReceiptV2NeverPanics(f *testing.F) {
	receipt, _ := signedTransactionReceiptV2Test(f)
	wire, err := EncodeTransactionReceiptV2(receipt)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeTransactionReceiptV2(data)
	})
}
