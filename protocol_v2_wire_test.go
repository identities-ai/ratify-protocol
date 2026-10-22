package ratify

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func signedV2TestBundle(t testing.TB) *ProofBundleV2 {
	bundle, _ := signedV2TestBundleWithScopes(t, []string{"execute:tool"})
	return bundle
}

func signedV2TestBundleWithScopes(t testing.TB, scopes []string) (*ProofBundleV2, HybridPublicKey) {
	t.Helper()
	issuerPub, issuerPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerID, _ := keyIDV2(issuerPub)
	agentID, _ := keyIDV2(agentPub)
	cert := DelegationCertV2{Version: 2, CertID: "cert-1", IssuerID: issuerID, IssuerPubKey: issuerPub, SubjectID: agentID, SubjectPubKey: agentPub, Scope: scopes, Constraints: []ConstraintV2{}, IssuedAt: 10, ExpiresAt: 20}
	certBytes, err := certSignableBytesV2(&cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.Signature, err = signV2Statement(v2DelegationCertificate, certBytes, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &ProofBundleV2{Version: 2, VerifierID: strings.Repeat("a", 64), AgentID: agentID, AgentPubKey: agentPub, Delegations: []DelegationCertV2{cert}, Challenge: bytes.Repeat([]byte{0x42}, 32), ChallengeAt: 10}
	digest, err := delegationDigestV2(bundle.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DelegationDigest = digest
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, issuerPub
}

func TestDecodeAndVerifyProofBundleV2(t *testing.T) {
	bundle := signedV2TestBundle(t)
	encoded, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProofBundleV2(encoded)
	if err != nil {
		t.Fatalf("DecodeProofBundleV2: %v", err)
	}
	if err := VerifyProofBundleV2Signatures(decoded); err != nil {
		t.Fatalf("VerifyProofBundleV2Signatures: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &obj); err != nil {
		t.Fatal(err)
	}
	delete(obj, "session_context")
	missing, _ := json.Marshal(obj)
	if _, err := DecodeProofBundleV2(missing); err == nil {
		t.Fatal("accepted omitted required nullable field")
	}

	tampered := *decoded
	tampered.DelegationDigest = append([]byte(nil), decoded.DelegationDigest...)
	tampered.DelegationDigest[0] ^= 1
	if err := VerifyProofBundleV2Signatures(&tampered); err == nil {
		t.Fatal("accepted incorrect delegation digest")
	}
	tampered = *decoded
	tampered.Challenge = append([]byte(nil), decoded.Challenge...)
	tampered.Challenge[0] ^= 1
	if err := VerifyProofBundleV2Signatures(&tampered); err == nil {
		t.Fatal("accepted modified signed challenge")
	}
}

func TestDecodeProofBundleV2RejectsV1AndMalformedShape(t *testing.T) {
	for _, input := range []string{
		`{"version":1}`,
		`{"version":2,"unknown":true}`,
		`{"version":2,"verifier_id":"` + strings.Repeat("A", 64) + `"}`,
	} {
		if _, err := DecodeProofBundleV2([]byte(input)); err == nil {
			t.Errorf("accepted malformed v2 object %s", input)
		}
	}
	valid, err := EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(valid, &obj); err != nil {
		t.Fatal(err)
	}
	obj["version"] = json.RawMessage(`1`)
	wrongVersion, _ := json.Marshal(obj)
	if _, err := DecodeProofBundleV2(wrongVersion); err == nil {
		t.Fatal("accepted v1 version in v2 decoder")
	}
}

func TestDecodeProofBundleV2RejectsNestedOmissionsAndBindingMismatch(t *testing.T) {
	encoded, err := EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	var certs []map[string]json.RawMessage
	if err := json.Unmarshal(root["delegations"], &certs); err != nil {
		t.Fatal(err)
	}
	delete(certs[0], "issued_at")
	root["delegations"], _ = json.Marshal(certs)
	missingNested, _ := json.Marshal(root)
	if _, err := DecodeProofBundleV2(missingNested); err == nil {
		t.Fatal("accepted delegation missing required issued_at")
	}

	encoded, err = EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	root["stream_id"] = json.RawMessage(`null`)
	root["stream_seq"] = json.RawMessage(`1`)
	wrongBinding, _ := json.Marshal(root)
	if _, err := DecodeProofBundleV2(wrongBinding); err == nil {
		t.Fatal("accepted stream ID/sequence nullability mismatch")
	}
}

func TestDecodeProofBundleV2RejectsUnsafeCertificateTimes(t *testing.T) {
	encoded, err := EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &bundle); err != nil {
		t.Fatal(err)
	}
	var certs []map[string]json.RawMessage
	if err := json.Unmarshal(bundle["delegations"], &certs); err != nil {
		t.Fatal(err)
	}
	certs[0]["issued_at"] = json.RawMessage("9007199254740992")
	bundle["delegations"], err = json.Marshal(certs)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProofBundleV2(encoded); err == nil {
		t.Fatal("accepted certificate timestamp outside the safe integer range")
	}
}

func TestV2RejectsNullCaseVariantIncompleteConstraintsAndUnsafeSequence(t *testing.T) {
	encoded, err := EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	var certs []map[string]json.RawMessage
	if err := json.Unmarshal(root["delegations"], &certs); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(){
		"null timestamp":              func() { root["challenge_at"] = json.RawMessage(`null`) },
		"case variant":                func() { certs[0]["Expires_At"] = certs[0]["expires_at"]; delete(certs[0], "expires_at") },
		"missing constraint value":    func() { certs[0]["constraints"] = json.RawMessage(`[{"type":"geo_circle","lat":0,"lon":0}]`) },
		"Unicode case-fold duplicate": func() { certs[0]["ſcope"] = certs[0]["scope"] },
	} {
		encoded, err = EncodeProofBundleV2(signedV2TestBundle(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &root); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(root["delegations"], &certs); err != nil {
			t.Fatal(err)
		}
		mutate()
		root["delegations"], _ = json.Marshal(certs)
		bad, _ := json.Marshal(root)
		if _, err := DecodeProofBundleV2(bad); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	encoded, err = EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	var decoded ProofBundleV2
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	certJSON, err := EncodeDelegationCertV2(&decoded.Delegations[0])
	if err != nil {
		t.Fatal(err)
	}
	var certObject map[string]json.RawMessage
	if err := json.Unmarshal(certJSON, &certObject); err != nil {
		t.Fatal(err)
	}
	certObject["constraints"] = json.RawMessage(`[{"type":"geo_circle","lat":0,"lon":0}]`)
	invalidStandalone, _ := json.Marshal(certObject)
	if _, err := DecodeDelegationCertV2(invalidStandalone); err == nil {
		t.Fatal("standalone v2 certificate decoder accepted incomplete constraint")
	}

	encoded, err = EncodeProofBundleV2(signedV2TestBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	root["challenge_at"] = json.RawMessage(`9007199254740992`)
	unsafeTime, _ := json.Marshal(root)
	if _, err := DecodeProofBundleV2(unsafeTime); err == nil {
		t.Fatal("accepted challenge timestamp outside safe integer range")
	}

	bundle := signedV2TestBundle(t)
	sequence := int64(maxSafeInteger + 1)
	stream := bytes.Repeat([]byte{7}, 32)
	bundle.StreamID, bundle.StreamSeq = &stream, &sequence
	if err := VerifyProofBundleV2Signatures(bundle); err == nil {
		t.Fatal("accepted unsafe stream sequence from in-memory input")
	}
}

func TestV2ObjectTypeContextsAreDistinct(t *testing.T) {
	delegation, err := v2MLDSAContext(v2DelegationCertificate)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := v2MLDSAContext(v2ChallengePresentation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(delegation, presentation) {
		t.Fatal("v2 object types share an ML-DSA context")
	}
}

func TestV2InMemoryNilSlicesMatchWireNull(t *testing.T) {
	bundle := signedV2TestBundle(t)
	bundle.SessionContext = new([]byte)
	bundle.StreamID = new([]byte)
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		t.Fatalf("nil slices representing wire null rejected: %v", err)
	}
	encoded, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatalf("encode nil slices representing wire null: %v", err)
	}
	if _, err := DecodeProofBundleV2(encoded); err != nil {
		t.Fatalf("decode encoded null fields: %v", err)
	}
}

func TestV2AuthenticatedChallengePreflight(t *testing.T) {
	bundle := signedV2TestBundle(t)
	leaf := bundle.Delegations[0]
	expected := ExpectedChallengeV2{Value: bundle.Challenge, IssuedAt: bundle.ChallengeAt, ExpiresAt: 20, VerifierNamespace: "local-verifier", ReplayEpoch: 4, VerifierID: bundle.VerifierID, ExpectedAgentID: bundle.AgentID, ExpectedAgentPublicKey: &leaf.SubjectPubKey}
	if err := ValidateProofBundleV2Preflight(bundle, expected, "execute:tool", "local-verifier", 4, 15, 10, 0); err != nil {
		t.Fatalf("valid expected challenge rejected: %v", err)
	}
	maxAgeBoundary := expected
	maxAgeBoundary.ExpiresAt = 30
	// The maximum-age deadline is exclusive (SPEC-v2 §2.5): one second before
	// issued_at+max_age is current, the deadline itself is not.
	if err := ValidateProofBundleV2Preflight(bundle, maxAgeBoundary, "execute:tool", "local-verifier", 4, 19, 10, 0); err != nil {
		t.Fatalf("challenge one second before the maximum-age deadline rejected: %v", err)
	}
	if err := ValidateProofBundleV2Preflight(bundle, maxAgeBoundary, "execute:tool", "local-verifier", 4, 20, 10, 0); err == nil {
		t.Fatal("accepted challenge at the exclusive maximum-age deadline")
	}
	for name, mutate := range map[string]func(*ExpectedChallengeV2, *ProofBundleV2, *int64){
		"expiry boundary": func(_ *ExpectedChallengeV2, _ *ProofBundleV2, now *int64) { *now = 20 },
		"replay epoch":    func(e *ExpectedChallengeV2, _ *ProofBundleV2, _ *int64) { e.ReplayEpoch++ },
		"namespace":       func(e *ExpectedChallengeV2, _ *ProofBundleV2, _ *int64) { e.VerifierNamespace = "other" },
		"challenge":       func(e *ExpectedChallengeV2, _ *ProofBundleV2, _ *int64) { e.Value = bytes.Repeat([]byte{0x33}, 32) },
		"expected agent":  func(e *ExpectedChallengeV2, _ *ProofBundleV2, _ *int64) { e.ExpectedAgentID = strings.Repeat("f", 64) },
		"expected session": func(e *ExpectedChallengeV2, _ *ProofBundleV2, _ *int64) {
			e.ExpectedSessionContext = bytes.Repeat([]byte{1}, 32)
		},
	} {
		e, now := expected, int64(15)
		b := bundle
		mutate(&e, b, &now)
		if err := ValidateProofBundleV2Preflight(b, e, "execute:tool", "local-verifier", 4, now, 10, 0); err == nil {
			t.Errorf("accepted invalid %s", name)
		}
	}
	for _, invalid := range []string{"", "custom:", "custom:*", "data:*"} {
		if err := ValidateProofBundleV2Preflight(bundle, expected, invalid, "local-verifier", 4, 15, 10, 0); err == nil {
			t.Errorf("accepted invalid required scope %q", invalid)
		}
	}
}

func TestV2CertificateScopeRegistryFailureIsDeferredUntilAuthorization(t *testing.T) {
	bundle, rootKey := signedV2TestBundleWithScopes(t, []string{"custom:*"})
	encoded, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatalf("encode signed invalid-scope proof: %v", err)
	}
	decoded, err := DecodeProofBundleV2(encoded)
	if err != nil {
		t.Fatalf("decode signed invalid-scope proof before claim: %v", err)
	}
	if err := VerifyProofBundleV2Signatures(decoded); err != nil {
		t.Fatalf("cryptographic preflight rejected signed invalid scope: %v", err)
	}
	root := decoded.Delegations[0]
	policy := testUnboundContextPolicy(t)
	expected := &ExpectedChallengeV2{
		Value: decoded.Challenge, IssuedAt: decoded.ChallengeAt, ExpiresAt: decoded.ChallengeAt + 30,
		VerifierNamespace: "local-verifier", VerifierID: decoded.VerifierID,
	}
	pre, err := PreflightProofBundleV2(decoded, expected, policy, "execute:tool", "local-verifier", 0, 15, 10, 0)
	if err != nil {
		t.Fatalf("signed invalid-scope proof failed structural preflight: %v", err)
	}
	if _, _, _, err := ClaimProofBundleV2(context.Background(), &recordingClaimStoreV2{disposition: V2ClaimCreated}, decoded, pre, "local-verifier", 0, 15); err != nil {
		t.Fatalf("signed invalid-scope proof could not be claimed after structural preflight: %v", err)
	}
	got := EvaluateProofBundleV2LocalAuthorization(decoded, V2LocalAuthorizationOptions{
		TrustedRootID: root.IssuerID, TrustedRootKey: rootKey,
		TrustConfigured: true, RequiredScope: "execute:tool", ContextPolicy: policy, ExpectedChallenge: expected,
		ClaimToken: testTokenFromPreflightV2(t, pre),
	})
	if got.Status != "invalid_scope" || got.Reason != "invalid_scope" || got.Detail == "" {
		t.Fatalf("signed invalid registry scope must fail in post-claim authorization: %+v", got)
	}
}

func FuzzDecodeProofBundleV2NeverPanics(f *testing.F) {
	valid, err := EncodeProofBundleV2(signedV2TestBundle(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		bundle, err := DecodeProofBundleV2(data)
		if err == nil {
			_ = VerifyProofBundleV2Signatures(bundle)
			if bundle.ChallengeAt < maxSafeInteger {
				expected := ExpectedChallengeV2{Value: bundle.Challenge, IssuedAt: bundle.ChallengeAt, ExpiresAt: bundle.ChallengeAt + 1, VerifierNamespace: "fuzz", ReplayEpoch: 0, VerifierID: bundle.VerifierID}
				_ = ValidateProofBundleV2Preflight(bundle, expected, "execute:tool", "fuzz", 0, bundle.ChallengeAt, 1, 0)
			}
		}
	})
}

func TestPublicV2SigningAPIsProduceVerifiableChain(t *testing.T) {
	issuerPub, issuerKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentKey, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	issuerID, _ := keyIDV2(issuerPub)
	agentID, _ := keyIDV2(agentPub)
	unsignedCert := &DelegationCertV2{
		Version: 2, CertID: "public-api-test", IssuerID: issuerID, IssuerPubKey: issuerPub,
		SubjectID: agentID, SubjectPubKey: agentPub, Scope: []string{"execute:tool"},
		Constraints: []ConstraintV2{}, IssuedAt: 1, ExpiresAt: 100,
	}
	cert, err := SignDelegationCertV2(unsignedCert, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	unsignedCert.Scope[0] = "data:read"
	certSignable, err := certSignableBytesV2(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyV2Statement(v2DelegationCertificate, certSignable, cert.Signature, issuerPub); err != nil {
		t.Fatalf("signing API output was affected by later input mutation: %v", err)
	}
	inputBundle := &ProofBundleV2{
		Version: 2, VerifierID: strings.Repeat("c", 64), AgentID: agentID, AgentPubKey: agentPub,
		Delegations: []DelegationCertV2{*cert}, Challenge: bytes.Repeat([]byte{7}, 32), ChallengeAt: 2,
	}
	bundle, err := SignProofBundleV2(inputBundle, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	inputBundle.Delegations[0].Scope[0] = "data:read"
	if bundle.Delegations[0].Scope[0] != "execute:tool" {
		t.Fatal("signed proof bundle aliases mutable input data")
	}
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		t.Fatalf("public signing API produced an invalid chain: %v", err)
	}
	if _, err := SignDelegationCertV2(&DelegationCertV2{IssuerID: issuerID}, agentKey); err == nil {
		t.Fatal("signed a certificate with a key that does not match its issuer")
	}
	malformedIssuerKey := issuerKey
	malformedIssuerKey.Ed25519 = append([]byte(nil), issuerKey.Ed25519...)
	malformedIssuerKey.Ed25519[63] ^= 1
	if _, err := SignDelegationCertV2(&DelegationCertV2{}, malformedIssuerKey); err == nil {
		t.Fatal("accepted an Ed25519 private key whose public half does not match its seed")
	}
	if _, err := SignProofBundleV2(bundle, HybridPrivateKey{}); err == nil {
		t.Fatal("accepted an incomplete agent private key")
	}
	malformedAgentKey := agentKey
	malformedAgentKey.Ed25519 = append([]byte(nil), agentKey.Ed25519...)
	malformedAgentKey.Ed25519[63] ^= 1
	if _, err := SignProofBundleV2(bundle, malformedAgentKey); err == nil {
		t.Fatal("accepted an Ed25519 private key whose public half does not match its seed")
	}
	empty := &ProofBundleV2{Version: 2, VerifierID: strings.Repeat("c", 64), AgentID: agentID, AgentPubKey: agentPub, Delegations: []DelegationCertV2{}, Challenge: bytes.Repeat([]byte{1}, 32)}
	emptySigned, err := SignProofBundleV2(empty, agentKey)
	if err != nil {
		t.Fatalf("validly signed empty-chain proof should remain parseable for terminal trust evaluation: %v", err)
	}
	if err := VerifyProofBundleV2Signatures(emptySigned); err != nil {
		t.Fatalf("valid challenge presentation with empty chain should pass signature-only validation: %v", err)
	}
}

func FuzzDecodeRevocationListV2NeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":2,"issuer_id":"` + strings.Repeat("a", 64) + `","updated_at":1,"next_update":2,"sequence":1,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`))
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeRevocationListV2(data)
	})
}

func FuzzDecodeRevocationPushV2NeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":2,"issuer_id":"` + strings.Repeat("a", 64) + `","sequence":1,"pushed_at":1,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`))
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeRevocationPushV2(data)
	})
}
