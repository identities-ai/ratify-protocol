package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rotationTestKey(t testing.TB, seed byte) (HybridPublicKey, HybridPrivateKey) {
	t.Helper()
	var edSeed, mlSeed [32]byte
	for i := range edSeed {
		edSeed[i] = seed + byte(i)
		mlSeed[i] = seed + byte(2*i)
	}
	pub, priv, err := HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func validRotationTestStatement(t testing.TB) (*KeyRotationStatementV2, HybridPrivateKey, HybridPrivateKey) {
	t.Helper()
	oldPub, oldPrivate := rotationTestKey(t, 1)
	newPub, newPrivate := rotationTestKey(t, 37)
	oldID, err := keyIDV2(oldPub)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := keyIDV2(newPub)
	if err != nil {
		t.Fatal(err)
	}
	return &KeyRotationStatementV2{
		Version: 2, AuthorityID: strings.Repeat("a", 32), RecoveryEpoch: 4,
		Role: "organization_root", Sequence: 1,
		PreviousStatementHash: make([]byte, 48), OldKey: oldPub, NewKey: newPub,
		OldKeyID: oldID, NewKeyID: newID, IssuedAt: 100, NotBefore: 105,
	}, oldPrivate, newPrivate
}

type rotationVectorSeeds struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"ml_dsa_65"`
}

func rotationTestState(stmt *KeyRotationStatementV2) KeyRotationV2State {
	return KeyRotationV2State{
		AuthorityID: stmt.AuthorityID, RecoveryEpoch: stmt.RecoveryEpoch,
		Role: stmt.Role, Sequence: 0, HeadHash: make([]byte, 48),
		CurrentKey: stmt.OldKey, UsedKeyIDs: []string{stmt.OldKeyID},
	}
}

func TestKeyRotationStatementV2RoundTripAndDualSignatures(t *testing.T) {
	stmt, oldPrivate, newPrivate := validRotationTestStatement(t)
	signed, err := SignKeyRotationStatementV2(stmt, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeKeyRotationStatementV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeKeyRotationStatementV2(encoded)
	if err != nil {
		t.Fatal(err)
	}
	state := rotationTestState(stmt)
	if err := VerifyKeyRotationStatementV2(decoded, state, 106, 2); err != nil {
		t.Fatalf("valid rotation rejected: %v", err)
	}
	if err := VerifyKeyRotationStatementV2(decoded, state, 103, 2); err != nil {
		t.Fatalf("not_before == now + skew was rejected: %v", err)
	}
	encodedAgain, err := EncodeKeyRotationStatementV2(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, encodedAgain) {
		t.Fatal("rotation wire encoding changed after decode")
	}

	wrongNewKey := *decoded
	wrongNewKey.NewSignature = decoded.OldSignature
	if err := VerifyKeyRotationStatementV2(&wrongNewKey, state, 106, 2); err == nil {
		t.Fatal("old-key signature was accepted as new-key proof of possession")
	}
	wrongOldKey := *decoded
	wrongOldKey.OldSignature = decoded.NewSignature
	if err := VerifyKeyRotationStatementV2(&wrongOldKey, state, 106, 2); err == nil {
		t.Fatal("new-key proof of possession was accepted as old-key authorization")
	}
	wrongState := state
	wrongState.CurrentKey, _ = rotationTestKey(t, 99)
	wrongStateCurrentID, err := keyIDV2(wrongState.CurrentKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongState.UsedKeyIDs = append(wrongState.UsedKeyIDs, wrongStateCurrentID)
	if err := VerifyKeyRotationStatementV2(decoded, wrongState, 106, 2); err == nil {
		t.Fatal("rotation accepted from a caller state with the wrong current key")
	}
	changedBody := *decoded
	changedBody.IssuedAt++
	if err := VerifyKeyRotationStatementV2(&changedBody, state, 106, 2); err == nil {
		t.Fatal("changed body field retained a valid signature")
	}
}

func TestKeyRotationV2SharedCrossSDKVector(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testvectors", "v2", "key-rotation-signature.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version               int                 `json:"version"`
		ObjectTypeCode        int                 `json:"object_type_code"`
		AuthorityID           string              `json:"authority_id"`
		RecoveryEpoch         int64               `json:"recovery_epoch"`
		Role                  string              `json:"role"`
		Sequence              int64               `json:"sequence"`
		PreviousStatementHash string              `json:"previous_statement_hash"`
		IssuedAt              int64               `json:"issued_at"`
		NotBefore             int64               `json:"not_before"`
		OldKeyID              string              `json:"old_key_id"`
		NewKeyID              string              `json:"new_key_id"`
		OldKeySeeds           rotationVectorSeeds `json:"old_key_seeds"`
		NewKeySeeds           rotationVectorSeeds `json:"new_key_seeds"`
		OldKey                HybridPublicKey     `json:"old_key"`
		NewKey                HybridPublicKey     `json:"new_key"`
		SignableBytes         string              `json:"signable_bytes"`
		StatementBodyDigest   string              `json:"statement_body_digest"`
		OldMLDSAContext       string              `json:"old_mldsa_context"`
		NewMLDSAContext       string              `json:"new_mldsa_context"`
		OldSignature          HybridSignature     `json:"old_signature"`
		NewSignature          HybridSignature     `json:"new_signature"`
		Wire                  string              `json:"wire"`
		Continuation          *struct {
			Version               int                 `json:"version"`
			ObjectTypeCode        int                 `json:"object_type_code"`
			AuthorityID           string              `json:"authority_id"`
			RecoveryEpoch         int64               `json:"recovery_epoch"`
			Role                  string              `json:"role"`
			Sequence              int64               `json:"sequence"`
			PreviousStatementHash string              `json:"previous_statement_hash"`
			IssuedAt              int64               `json:"issued_at"`
			NotBefore             int64               `json:"not_before"`
			OldKeyID              string              `json:"old_key_id"`
			NewKeyID              string              `json:"new_key_id"`
			OldKeySeeds           rotationVectorSeeds `json:"old_key_seeds"`
			NewKeySeeds           rotationVectorSeeds `json:"new_key_seeds"`
			OldKey                HybridPublicKey     `json:"old_key"`
			NewKey                HybridPublicKey     `json:"new_key"`
			SignableBytes         string              `json:"signable_bytes"`
			StatementBodyDigest   string              `json:"statement_body_digest"`
			OldMLDSAContext       string              `json:"old_mldsa_context"`
			NewMLDSAContext       string              `json:"new_mldsa_context"`
			OldSignature          HybridSignature     `json:"old_signature"`
			NewSignature          HybridSignature     `json:"new_signature"`
			Wire                  string              `json:"wire"`
		} `json:"continuation"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 2 || fixture.ObjectTypeCode != 4 {
		t.Fatalf("vector version/type = %d/%04x", fixture.Version, fixture.ObjectTypeCode)
	}
	decodeSeed := func(value string) [32]byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("invalid vector seed: length=%d err=%v", len(decoded), err)
		}
		var seed [32]byte
		copy(seed[:], decoded)
		return seed
	}
	oldPub, oldPriv, err := HybridKeypairFromSeeds(decodeSeed(fixture.OldKeySeeds.Ed25519), decodeSeed(fixture.OldKeySeeds.MLDSA65))
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := HybridKeypairFromSeeds(decodeSeed(fixture.NewKeySeeds.Ed25519), decodeSeed(fixture.NewKeySeeds.MLDSA65))
	if err != nil {
		t.Fatal(err)
	}
	if !equalHybridPublicKeys(oldPub, fixture.OldKey) || !equalHybridPublicKeys(newPub, fixture.NewKey) {
		t.Fatal("seed-derived keys do not match shared vector")
	}
	prev, err := base64.StdEncoding.DecodeString(fixture.PreviousStatementHash)
	if err != nil {
		t.Fatal(err)
	}
	stmt := &KeyRotationStatementV2{
		Version: fixture.Version, AuthorityID: fixture.AuthorityID,
		RecoveryEpoch: fixture.RecoveryEpoch, Role: fixture.Role, Sequence: fixture.Sequence,
		PreviousStatementHash: prev, OldKey: oldPub, NewKey: newPub,
		OldKeyID: fixture.OldKeyID, NewKeyID: fixture.NewKeyID,
		IssuedAt: fixture.IssuedAt, NotBefore: fixture.NotBefore,
	}
	signed, err := SignKeyRotationStatementV2(stmt, oldPriv, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	signable, err := keyRotationSignableBytesV2(stmt)
	if err != nil {
		t.Fatal(err)
	}
	expectedSignable, err := base64.StdEncoding.DecodeString(fixture.SignableBytes)
	if err != nil || !bytes.Equal(signable, expectedSignable) {
		t.Fatal("Go signable bytes do not match shared vector")
	}
	digest, err := KeyRotationStatementV2Digest(signed)
	if err != nil || hex.EncodeToString(digest) != fixture.StatementBodyDigest {
		t.Fatalf("statement body digest mismatch: %x, %v", digest, err)
	}
	independentDigest := sha512.New384()
	independentDigest.Write([]byte("ratify-protocol-statement-body-v2\x00"))
	var typeCode [2]byte
	binary.BigEndian.PutUint16(typeCode[:], 0x0004)
	independentDigest.Write(typeCode[:])
	independentDigest.Write(signable)
	if !bytes.Equal(digest, independentDigest.Sum(nil)) {
		t.Fatal("shared vector digest differs from independent SHA-384 transcript")
	}
	oldContext, err := v2MLDSAContext(v2KeyRotationAuthorization)
	if err != nil || string(oldContext) != fixture.OldMLDSAContext {
		t.Fatal("old-key ML-DSA context does not match vector")
	}
	newContext, err := v2MLDSAContext(v2KeyRotationProofOfPossession)
	if err != nil || string(newContext) != fixture.NewMLDSAContext {
		t.Fatal("new-key ML-DSA context does not match vector")
	}
	if err := verifyV2Statement(v2KeyRotationAuthorization, signable, fixture.OldSignature, oldPub); err != nil {
		t.Fatalf("old signature in shared vector is invalid: %v", err)
	}
	if err := verifyV2Statement(v2KeyRotationProofOfPossession, signable, fixture.NewSignature, newPub); err != nil {
		t.Fatalf("new signature in shared vector is invalid: %v", err)
	}
	if err := verifyV2Statement(v2KeyRotationAuthorization, signable, signed.OldSignature, oldPub); err != nil {
		t.Fatalf("old signature from public signer is invalid: %v", err)
	}
	if err := verifyV2Statement(v2KeyRotationProofOfPossession, signable, signed.NewSignature, newPub); err != nil {
		t.Fatalf("new signature from public signer is invalid: %v", err)
	}
	fixtureWire, err := base64.StdEncoding.DecodeString(fixture.Wire)
	if err != nil {
		t.Fatal(err)
	}
	vectorWire, err := DecodeKeyRotationStatementV2(fixtureWire)
	if err != nil {
		t.Fatalf("shared vector wire is invalid: %v", err)
	}
	reencodedVector, err := EncodeKeyRotationStatementV2(vectorWire)
	if err != nil || !bytes.Equal(reencodedVector, fixtureWire) {
		t.Fatal("shared vector wire is not canonical or stable")
	}
	wireSignable, err := keyRotationSignableBytesV2(vectorWire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wireSignable, expectedSignable) {
		t.Fatal("genesis wire signable projection does not match the published vector")
	}
	wireDigest, err := KeyRotationStatementV2Digest(vectorWire)
	if err != nil || hex.EncodeToString(wireDigest) != fixture.StatementBodyDigest {
		t.Fatalf("genesis wire digest does not match the published vector: %x, %v", wireDigest, err)
	}
	if vectorWire.IssuedAt != fixture.IssuedAt || vectorWire.NotBefore != fixture.NotBefore || vectorWire.OldKeyID != fixture.OldKeyID || vectorWire.NewKeyID != fixture.NewKeyID || !equalHybridPublicKeys(vectorWire.OldKey, fixture.OldKey) || !equalHybridPublicKeys(vectorWire.NewKey, fixture.NewKey) {
		t.Fatal("genesis wire fields do not match the published vector fields")
	}
	if vectorWire.Version != fixture.Version || fixture.ObjectTypeCode != int(v2KeyRotationAuthorization) || vectorWire.AuthorityID != fixture.AuthorityID || vectorWire.RecoveryEpoch != fixture.RecoveryEpoch || vectorWire.Role != fixture.Role || vectorWire.Sequence != fixture.Sequence || base64.StdEncoding.EncodeToString(vectorWire.PreviousStatementHash) != fixture.PreviousStatementHash {
		t.Fatal("genesis wire identity, chain, or type fields do not match the published vector")
	}
	if !bytes.Equal(vectorWire.OldSignature.Ed25519, fixture.OldSignature.Ed25519) || !bytes.Equal(vectorWire.OldSignature.MLDSA65, fixture.OldSignature.MLDSA65) || !bytes.Equal(vectorWire.NewSignature.Ed25519, fixture.NewSignature.Ed25519) || !bytes.Equal(vectorWire.NewSignature.MLDSA65, fixture.NewSignature.MLDSA65) {
		t.Fatal("genesis wire signatures do not match the published vector signatures")
	}
	if fixture.Continuation == nil || fixture.Continuation.Sequence != 2 {
		t.Fatal("shared vector lacks a sequence-2 continuation")
	}
	if fixture.Continuation.Version != 2 || fixture.Continuation.ObjectTypeCode != int(v2KeyRotationAuthorization) || fixture.Continuation.AuthorityID != fixture.AuthorityID || fixture.Continuation.RecoveryEpoch != fixture.RecoveryEpoch || fixture.Continuation.Role != fixture.Role {
		t.Fatal("continuation identity or type fields do not match genesis")
	}
	continuationWire, err := base64.StdEncoding.DecodeString(fixture.Continuation.Wire)
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := DecodeKeyRotationStatementV2(continuationWire)
	if err != nil {
		t.Fatalf("continuation vector wire is invalid: %v", err)
	}
	if !bytes.Equal(continuation.PreviousStatementHash, digest) || hex.EncodeToString(mustRotationDigest(t, continuation)) != fixture.Continuation.StatementBodyDigest {
		t.Fatal("continuation vector does not link to genesis digest")
	}
	if continuation.Version != fixture.Continuation.Version || continuation.AuthorityID != fixture.Continuation.AuthorityID || continuation.RecoveryEpoch != fixture.Continuation.RecoveryEpoch || continuation.Role != fixture.Continuation.Role || continuation.Sequence != fixture.Continuation.Sequence || base64.StdEncoding.EncodeToString(continuation.PreviousStatementHash) != fixture.Continuation.PreviousStatementHash || continuation.IssuedAt != fixture.Continuation.IssuedAt || continuation.NotBefore != fixture.Continuation.NotBefore || continuation.OldKeyID != fixture.Continuation.OldKeyID || continuation.NewKeyID != fixture.Continuation.NewKeyID || !equalHybridPublicKeys(continuation.OldKey, fixture.Continuation.OldKey) || !equalHybridPublicKeys(continuation.NewKey, fixture.Continuation.NewKey) {
		t.Fatal("continuation wire fields do not match the published vector fields")
	}
	continuationSignable, err := keyRotationSignableBytesV2(continuation)
	if err != nil {
		t.Fatal(err)
	}
	wantContinuationSignable, err := base64.StdEncoding.DecodeString(fixture.Continuation.SignableBytes)
	if err != nil || !bytes.Equal(continuationSignable, wantContinuationSignable) {
		t.Fatal("continuation signable bytes do not match the published vector")
	}
	if err := verifyV2Statement(v2KeyRotationAuthorization, continuationSignable, fixture.Continuation.OldSignature, continuation.OldKey); err != nil {
		t.Fatalf("continuation old-key vector signature is invalid: %v", err)
	}
	if err := verifyV2Statement(v2KeyRotationProofOfPossession, continuationSignable, fixture.Continuation.NewSignature, continuation.NewKey); err != nil {
		t.Fatalf("continuation new-key vector signature is invalid: %v", err)
	}
	continuationOldContext, err := v2MLDSAContext(v2KeyRotationAuthorization)
	if err != nil || string(continuationOldContext) != fixture.Continuation.OldMLDSAContext {
		t.Fatal("continuation old-key ML-DSA context does not match vector")
	}
	continuationNewContext, err := v2MLDSAContext(v2KeyRotationProofOfPossession)
	if err != nil || string(continuationNewContext) != fixture.Continuation.NewMLDSAContext {
		t.Fatal("continuation new-key ML-DSA context does not match vector")
	}
	if !bytes.Equal(fixture.Continuation.OldSignature.Ed25519, continuation.OldSignature.Ed25519) || !bytes.Equal(fixture.Continuation.OldSignature.MLDSA65, continuation.OldSignature.MLDSA65) || !bytes.Equal(fixture.Continuation.NewSignature.Ed25519, continuation.NewSignature.Ed25519) || !bytes.Equal(fixture.Continuation.NewSignature.MLDSA65, continuation.NewSignature.MLDSA65) {
		t.Fatal("continuation wire signatures do not match the published vector signatures")
	}
	continuationOldPub, _, err := HybridKeypairFromSeeds(decodeSeed(fixture.Continuation.OldKeySeeds.Ed25519), decodeSeed(fixture.Continuation.OldKeySeeds.MLDSA65))
	if err != nil || !equalHybridPublicKeys(continuationOldPub, continuation.OldKey) {
		t.Fatal("continuation old-key seeds do not derive the published key")
	}
	continuationNewPub, _, err := HybridKeypairFromSeeds(decodeSeed(fixture.Continuation.NewKeySeeds.Ed25519), decodeSeed(fixture.Continuation.NewKeySeeds.MLDSA65))
	if err != nil || !equalHybridPublicKeys(continuationNewPub, continuation.NewKey) {
		t.Fatal("continuation new-key seeds do not derive the published key")
	}
	state := rotationTestState(stmt)
	if err := VerifyKeyRotationStatementV2(vectorWire, state, stmt.NotBefore, 0); err != nil {
		t.Fatalf("genesis vector rejected against initial state: %v", err)
	}
	continuedState := KeyRotationV2State{
		AuthorityID: stmt.AuthorityID, RecoveryEpoch: stmt.RecoveryEpoch, Role: stmt.Role,
		Sequence: 1, HeadHash: digest, CurrentKey: stmt.NewKey,
		UsedKeyIDs: []string{stmt.OldKeyID, stmt.NewKeyID},
	}
	if err := VerifyKeyRotationStatementV2(continuation, continuedState, continuation.NotBefore, 0); err != nil {
		t.Fatalf("sequence-2 vector rejected against genesis state: %v", err)
	}
}

func mustRotationDigest(t *testing.T, stmt *KeyRotationStatementV2) []byte {
	t.Helper()
	digest, err := KeyRotationStatementV2Digest(stmt)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestDecodeKeyRotationStatementV2RejectsMalformedWireAndState(t *testing.T) {
	stmt, oldPrivate, newPrivate := validRotationTestStatement(t)
	signed, err := SignKeyRotationStatementV2(stmt, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeKeyRotationStatementV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = json.RawMessage(`true`)
	extraField, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKeyRotationStatementV2(extraField); err == nil {
		t.Fatal("unknown signed field was accepted")
	}
	delete(object, "unexpected")
	var previousHashText string
	if err := json.Unmarshal(object["previous_statement_hash"], &previousHashText); err != nil {
		t.Fatal(err)
	}
	object["previous_statement_hash"], err = json.Marshal(previousHashText[:20] + "\r\n" + previousHashText[20:])
	if err != nil {
		t.Fatal(err)
	}
	wrappedBase64, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKeyRotationStatementV2(wrappedBase64); err == nil {
		t.Fatal("noncanonical base64 line break was accepted")
	}

	state := rotationTestState(stmt)
	wrongEpoch := state
	wrongEpoch.RecoveryEpoch++
	if err := VerifyKeyRotationStatementV2(signed, wrongEpoch, 106, 2); err == nil {
		t.Fatal("rotation from a different recovery epoch was accepted")
	}
	wrongAuthority := state
	wrongAuthority.AuthorityID = strings.Repeat("b", 32)
	if err := VerifyKeyRotationStatementV2(signed, wrongAuthority, 106, 2); err == nil {
		t.Fatal("rotation for another authority was accepted")
	}
	wrongRole := state
	wrongRole.Role = "issuer"
	if err := VerifyKeyRotationStatementV2(signed, wrongRole, 106, 2); err == nil {
		t.Fatal("rotation for another role was accepted")
	}
	wrongSequence := state
	wrongSequence.Sequence = 1
	wrongSequence.HeadHash = bytes.Repeat([]byte{7}, 48)
	wrongSequenceCandidate := *stmt
	wrongSequenceCandidate.Sequence = 3
	wrongSequenceCandidate.PreviousStatementHash = bytes.Clone(wrongSequence.HeadHash)
	wrongSequenceSigned, err := SignKeyRotationStatementV2(&wrongSequenceCandidate, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyRotationStatementV2(wrongSequenceSigned, wrongSequence, 106, 2); err == nil {
		t.Fatal("rotation with a wrong prior sequence was accepted")
	}
	if err := VerifyKeyRotationStatementV2(signed, state, 102, 2); err == nil {
		t.Fatal("future-dated rotation was accepted")
	}
	futureIssued := *stmt
	futureIssued.IssuedAt = 109
	futureSigned, err := SignKeyRotationStatementV2(&futureIssued, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyRotationStatementV2(futureSigned, state, 106, 2); err == nil {
		t.Fatal("future issued_at was accepted")
	}
	boundaryIssued := *stmt
	boundaryIssued.IssuedAt = 108
	boundarySigned, err := SignKeyRotationStatementV2(&boundaryIssued, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyRotationStatementV2(boundarySigned, state, 106, 2); err != nil {
		t.Fatalf("issued_at == now + skew was rejected: %v", err)
	}

	badRole := *signed
	badRole.Role = "verifier"
	if _, err := EncodeKeyRotationStatementV2(&badRole); err == nil {
		t.Fatal("unknown rotation role was encoded")
	}
}

func TestKeyRotationStatementV2NextLinkAndUsedKeyHistory(t *testing.T) {
	first, oldPrivate, newPrivate := validRotationTestStatement(t)
	acceptedFirst, err := SignKeyRotationStatementV2(first, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := KeyRotationStatementV2Digest(acceptedFirst)
	if err != nil {
		t.Fatal(err)
	}
	thirdPub, thirdPrivate := rotationTestKey(t, 73)
	thirdID, err := keyIDV2(thirdPub)
	if err != nil {
		t.Fatal(err)
	}
	next := *first
	next.Sequence = 2
	next.PreviousStatementHash = firstDigest
	next.OldKey = acceptedFirst.NewKey
	next.OldKeyID = acceptedFirst.NewKeyID
	next.NewKey = thirdPub
	next.NewKeyID = thirdID
	next.IssuedAt = 107
	next.NotBefore = 110
	acceptedNext, err := SignKeyRotationStatementV2(&next, newPrivate, thirdPrivate)
	if err != nil {
		t.Fatal(err)
	}
	state := KeyRotationV2State{
		AuthorityID: first.AuthorityID, RecoveryEpoch: first.RecoveryEpoch,
		Role: first.Role, Sequence: 1, HeadHash: firstDigest,
		CurrentKey: acceptedFirst.NewKey, UsedKeyIDs: []string{first.OldKeyID, first.NewKeyID},
	}
	if err := VerifyKeyRotationStatementV2(acceptedNext, state, 108, 2); err != nil {
		t.Fatalf("valid linked rotation rejected: %v", err)
	}
	wrongHead := state
	wrongHead.HeadHash = bytes.Repeat([]byte{1}, 48)
	if err := VerifyKeyRotationStatementV2(acceptedNext, wrongHead, 108, 2); err == nil {
		t.Fatal("rotation with the wrong prior statement hash was accepted")
	}

	reusedKey := *acceptedNext
	reusedKey.NewKey = first.OldKey
	reusedKey.NewKeyID = first.OldKeyID
	reusedSigned, err := SignKeyRotationStatementV2(&reusedKey, newPrivate, oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyRotationStatementV2(reusedSigned, state, 108, 2); err == nil {
		t.Fatal("previously used key was accepted as a replacement")
	}
}

func TestKeyRotationStatementV2DigestExcludesSignaturesAndEnforcesGenesis(t *testing.T) {
	stmt, oldPrivate, newPrivate := validRotationTestStatement(t)
	signed, err := SignKeyRotationStatementV2(stmt, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := KeyRotationStatementV2Digest(signed)
	if err != nil {
		t.Fatal(err)
	}
	mutatedSignature := *signed
	mutatedSignature.OldSignature.Ed25519 = bytes.Clone(signed.OldSignature.Ed25519)
	mutatedSignature.OldSignature.Ed25519[0] ^= 1
	mutatedDigest, err := KeyRotationStatementV2Digest(&mutatedSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, mutatedDigest) {
		t.Fatal("signature bytes changed the rotation statement digest")
	}
	body, err := keyRotationSignableBytesV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []uint16{0x0002} {
		if _, err := StatementBodyDigestV2(code, body); err == nil {
			t.Fatalf("statement body digest accepted unsupported object type 0x%04x", code)
		}
	}
	witness, _, _ := validWitnessEntryV2Test(t)
	witnessBody, err := witnessEntrySignableBytesV2(witness)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _, _ := validVerificationReceiptV2Test(t)
	receiptBody, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		code uint16
		body []byte
	}{{0x0006, witnessBody}, {0x0008, receiptBody}} {
		if _, err := StatementBodyDigestV2(test.code, test.body); err != nil {
			t.Fatalf("statement body digest rejected spec-defined object type 0x%04x: %v", test.code, err)
		}
		if _, err := StatementBodyDigestV2(test.code, []byte(`{"signature":"test","statement_body":"test"}`)); err == nil {
			t.Fatalf("statement body digest accepted a signature field for object type 0x%04x", test.code)
		}
	}
	if _, err := StatementBodyDigestV2(0x0004, append(bytes.Clone(body), ' ')); err == nil {
		t.Fatal("statement body digest accepted noncanonical JSON")
	}
	fullLengthBase64 := base64.StdEncoding.EncodeToString(make([]byte, 48))
	wrappedFullLengthBase64 := fullLengthBase64[:32] + `\r\n` + fullLengthBase64[32:]
	quotedPreviousHash := `"` + base64.StdEncoding.EncodeToString(stmt.PreviousStatementHash) + `"`
	quotedWrappedHash := `"` + wrappedFullLengthBase64 + `"`
	invalidRotationBody := bytes.Replace(body, []byte(quotedPreviousHash), []byte(quotedWrappedHash), 1)
	if _, err := StatementBodyDigestV2(0x0004, invalidRotationBody); err == nil || !strings.Contains(err.Error(), "non-canonical base64") {
		t.Fatalf("rotation digest did not reject noncanonical top-level base64: %v", err)
	}
	if _, err := StatementBodyDigestV2(0x0004, []byte(`{"anything":"x"}`)); err == nil {
		t.Fatal("rotation digest accepted a body outside the rotation signable schema")
	}
	// Check the protocol transcript independently from the production helper.
	independent := sha512.New384()
	independent.Write([]byte("ratify-protocol-statement-body-v2\x00"))
	var typeCode [2]byte
	binary.BigEndian.PutUint16(typeCode[:], 0x0004)
	independent.Write(typeCode[:])
	independent.Write(body)
	if !bytes.Equal(digest, independent.Sum(nil)) {
		t.Fatal("rotation digest does not match independent SHA-384 transcript")
	}

	nonZeroGenesis := *stmt
	nonZeroGenesis.PreviousStatementHash = bytes.Repeat([]byte{1}, 48)
	if _, err := keyRotationSignableBytesV2(&nonZeroGenesis); err == nil {
		t.Fatal("genesis rotation accepted a nonzero previous hash")
	}
	nonGenesisZero := *stmt
	nonGenesisZero.Sequence = 2
	if _, err := keyRotationSignableBytesV2(&nonGenesisZero); err == nil {
		t.Fatal("non-genesis rotation accepted the zero previous hash")
	}
}

func TestSignKeyRotationStatementV2ValidatesAndCopiesInputs(t *testing.T) {
	stmt, oldPrivate, newPrivate := validRotationTestStatement(t)
	signed, err := SignKeyRotationStatementV2(stmt, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	originalPrevious := bytes.Clone(signed.PreviousStatementHash)
	originalOldPublic := bytes.Clone(signed.OldKey.Ed25519)
	stmt.PreviousStatementHash[0] = 9
	stmt.OldKey.Ed25519[0] ^= 1
	if !bytes.Equal(signed.PreviousStatementHash, originalPrevious) || !bytes.Equal(signed.OldKey.Ed25519, originalOldPublic) {
		t.Fatal("signed result aliases caller-owned input bytes")
	}
	if _, err := SignKeyRotationStatementV2(signed, newPrivate, oldPrivate); err == nil {
		t.Fatal("mismatched private keys signed the statement")
	}

	bad := *signed
	bad.AuthorityID = strings.ToUpper(bad.AuthorityID)
	if _, err := EncodeKeyRotationStatementV2(&bad); err == nil {
		t.Fatal("uppercase authority ID was encoded")
	}
	bad = *signed
	bad.RecoveryEpoch = 0
	if _, err := EncodeKeyRotationStatementV2(&bad); err == nil {
		t.Fatal("zero recovery epoch was encoded")
	}
	bad = *signed
	bad.Sequence = 0
	if _, err := EncodeKeyRotationStatementV2(&bad); err == nil {
		t.Fatal("zero sequence was encoded")
	}
	bad = *signed
	bad.NewKey = bad.OldKey
	bad.NewKeyID = bad.OldKeyID
	if _, err := EncodeKeyRotationStatementV2(&bad); err == nil {
		t.Fatal("same key was accepted as both old and new key")
	}
}

func FuzzDecodeKeyRotationStatementV2NeverPanics(f *testing.F) {
	stmt, oldPrivate, newPrivate := validRotationTestStatement(f)
	signed, err := SignKeyRotationStatementV2(stmt, oldPrivate, newPrivate)
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := EncodeKeyRotationStatementV2(signed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"version":2}`))
	state := rotationTestState(stmt)
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeKeyRotationStatementV2(data)
		if err == nil {
			_ = VerifyKeyRotationStatementV2(decoded, state, 106, 2)
		}
	})
}

// Revocation list and push bodies are the status observations' signed intent
// (SPEC-v2 §4). The public helper must accept exactly the signable bytes the
// reducer derives from a decoded object, and nothing else, so two SDKs that
// compare these digests never disagree about which bodies are the same.
func TestStatementBodyDigestV2RevocationBodies(t *testing.T) {
	issuer := strings.Repeat("ab", 32)
	list := &RevocationListV2{Version: 2, IssuerID: issuer, UpdatedAt: 100, NextUpdate: 200, Sequence: 2, Revoked: []RevokedCertV2{{CertID: "c1"}, {CertID: "c2"}}}
	push := &RevocationPushV2{Version: 2, IssuerID: issuer, Sequence: 3, PushedAt: 150, Revoked: []RevokedCertV2{{CertID: "c3"}}}
	listBody, err := revocationListSignableBytesV2(list)
	if err != nil {
		t.Fatal(err)
	}
	pushBody, err := revocationPushSignableBytesV2(push)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		code      uint16
		body      []byte
		otherBody []byte
	}{{0x0003, listBody, pushBody}, {0x0005, pushBody, listBody}} {
		got, err := StatementBodyDigestV2(test.code, test.body)
		if err != nil {
			t.Fatalf("0x%04x: %v", test.code, err)
		}
		independent := sha512.New384()
		independent.Write([]byte("ratify-protocol-statement-body-v2\x00"))
		independent.Write(binary.BigEndian.AppendUint16(nil, test.code))
		independent.Write(test.body)
		if !bytes.Equal(got, independent.Sum(nil)) {
			t.Fatalf("0x%04x digest does not match the labelled transcript", test.code)
		}
		if _, err := StatementBodyDigestV2(test.code, test.otherBody); V2ErrorClassOf(err) != V2ErrMalformed {
			t.Fatalf("0x%04x accepted the other status object's body: %v", test.code, err)
		}
		var fields map[string]any
		if err := json.Unmarshal(test.body, &fields); err != nil {
			t.Fatal(err)
		}
		fields["signature"] = map[string]any{"ed25519": "", "ml_dsa_65": ""}
		withSignature, err := CanonicalJSON(fields)
		if err != nil {
			t.Fatal(err)
		}
		delete(fields, "signature")
		fields["extra"] = 1
		withExtra, err := CanonicalJSON(fields)
		if err != nil {
			t.Fatal(err)
		}
		delete(fields, "extra")
		fields["revoked"] = nil
		withNullRevoked, err := CanonicalJSON(fields)
		if err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{
			"signature field":   withSignature,
			"unknown field":     withExtra,
			"noncanonical JSON": append(bytes.Clone(test.body), ' '),
			"null revoked":      withNullRevoked,
		} {
			if digest, err := StatementBodyDigestV2(test.code, body); err == nil || digest != nil || V2ErrorClassOf(err) != V2ErrMalformed {
				t.Fatalf("0x%04x %s: digest %x, error %v", test.code, name, digest, err)
			}
		}
	}
	for _, code := range []uint16{0x0000, 0x0001, 0x0002, 0x0007, 0x0009, 0x000a, 0xffff} {
		if digest, err := StatementBodyDigestV2(code, listBody); digest != nil || V2ErrorClassOf(err) != V2ErrUnsupportedObjectType {
			t.Fatalf("0x%04x: digest %x, error %v; want unsupported_object_type", code, digest, err)
		}
	}
}

// SPEC-v2 §2.5: rotation verification applies the configured bounds to the
// caller's clock inputs. A skew of 301 must not admit what 300 rejects.
func TestVerifyKeyRotationStatementV2ClockConfigurationBounds(t *testing.T) {
	stmt, oldPrivate, newPrivate := validRotationTestStatement(t)
	signed, err := SignKeyRotationStatementV2(stmt, oldPrivate, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	state := rotationTestState(stmt)
	for _, c := range []struct {
		now, skew int64
		class     V2ErrorClass
	}{
		{106, 301, V2ErrConfigurationInvalid},
		{106, -1, V2ErrConfigurationInvalid},
		{-1, 2, V2ErrConfigurationInvalid},
		{V2MaxTimestampSeconds + 1, 2, V2ErrConfigurationInvalid},
		{0, signed.NotBefore - 1, V2ErrRotationFutureDated},
	} {
		err := VerifyKeyRotationStatementV2(signed, state, c.now, c.skew)
		if V2ErrorClassOf(err) != c.class {
			t.Errorf("now %d skew %d: %v, want %s", c.now, c.skew, err, c.class)
		}
	}
	for _, c := range []struct{ now, skew int64 }{{0, signed.NotBefore}, {V2MaxTimestampSeconds, 0}} {
		if err := VerifyKeyRotationStatementV2(signed, state, c.now, c.skew); err != nil {
			t.Errorf("now %d skew %d: %v", c.now, c.skew, err)
		}
	}
}
