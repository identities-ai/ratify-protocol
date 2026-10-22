package ratify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha3"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// remoteSignerV2Test simulates an external provider. It is deliberately not
// localSignerV2, so every call takes the external-signer path.
type remoteSignerV2Test struct {
	priv     HybridPrivateKey
	mode     SignerModeV2
	calls    int
	requests []SignRequestV2
	tamper   func(*HybridSignature)
	err      error
	onSign   func()
	// muContext is the registry context the test provider uses to emulate
	// external-mu signing; a real provider signs MLDSAMu directly.
	muContext []byte
}

func (s *remoteSignerV2Test) PublicKeyV2() HybridPublicKey { return s.priv.Public() }
func (s *remoteSignerV2Test) ModeV2() SignerModeV2         { return s.mode }
func (s *remoteSignerV2Test) SignV2(ctx context.Context, req SignRequestV2) (HybridSignature, error) {
	s.calls++
	s.requests = append(s.requests, req)
	if s.onSign != nil {
		s.onSign()
	}
	if s.err != nil {
		return HybridSignature{}, s.err
	}
	// In external-mu mode a real provider signs MLDSAMu; circl has no
	// external-mu signing entry point, so the test provider signs the same
	// statement in pure mode, which yields an equally valid signature.
	mlContext := req.MLDSAContext
	if req.Mode == SignerModeExternalMuV2 {
		mlContext = s.muContext
	}
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.priv.MLDSA65, req.Message, mlContext, true, ml); err != nil {
		return HybridSignature{}, err
	}
	sig := HybridSignature{Ed25519: ed25519.Sign(s.priv.Ed25519, req.Message), MLDSA65: ml}
	if s.tamper != nil {
		s.tamper(&sig)
	}
	return sig, nil
}

func unsignedCertV2Test(t *testing.T, issuer HybridPublicKey) *DelegationCertV2 {
	t.Helper()
	subjectPub, _, _ := GenerateHybridKeypair()
	issuerID, _ := KeyIDV2(issuer)
	subjectID, _ := KeyIDV2(subjectPub)
	return &DelegationCertV2{Version: 2, CertID: "c1", IssuerID: issuerID, IssuerPubKey: issuer, SubjectID: subjectID, SubjectPubKey: subjectPub,
		Scope: []string{"data:read"}, Constraints: []ConstraintV2{}, IssuedAt: 1, ExpiresAt: 100}
}

func TestKeyIDV2Exported(t *testing.T) {
	pub, _, _ := GenerateHybridKeypair()
	id, err := KeyIDV2(pub)
	want, _ := keyIDV2(pub)
	if err != nil || id != want || !validV2ID(id) {
		t.Fatalf("KeyIDV2 = %q, %v", id, err)
	}
	if _, err := KeyIDV2(HybridPublicKey{Ed25519: pub.Ed25519, MLDSA65: pub.MLDSA65[:10]}); V2ErrorClassOf(err) != V2ErrMalformed {
		t.Fatalf("truncated key: %v", err)
	}
}

func TestSignerV2DirectModeRequestAndVerification(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	signer := &remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2}
	cert, err := SignDelegationCertV2WithSigner(context.Background(), unsignedCertV2Test(t, pub), signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegationCertV2Signature(cert); err != nil {
		t.Fatal(err)
	}
	req := signer.requests[0]
	keyID, _ := KeyIDV2(pub)
	if signer.calls != 1 || req.Message[len("ratify-protocol-signature\x00\x02")+1] != 1 || len(req.Message) != 77 || string(req.MLDSAContext) != "ratify-protocol/2/0001" || req.MLDSAMu != nil || req.KeyID != keyID || !equalHybridPublicKeys(req.PublicKey, pub) {
		t.Fatalf("direct-mode request = %+v", req)
	}
}

func TestSignerV2ExternalMuRequest(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	signer := &remoteSignerV2Test{priv: priv, mode: SignerModeExternalMuV2, muContext: []byte("ratify-protocol/2/0001")}
	if _, err := SignDelegationCertV2WithSigner(context.Background(), unsignedCertV2Test(t, pub), signer); err != nil {
		t.Fatal(err)
	}
	req := signer.requests[0]
	ctx := []byte("ratify-protocol/2/0001")
	tr := sha3.SumSHAKE256(pub.MLDSA65, 64)
	mu := sha3.SumSHAKE256(append(append(append(append([]byte{}, tr...), 0, byte(len(ctx))), ctx...), req.Message...), 64)
	if req.MLDSAContext != nil || !bytes.Equal(req.MLDSAMu, mu) || len(req.MLDSAMu) != 64 {
		t.Fatalf("external-mu request = %+v", req)
	}
}

func TestSignerV2RejectsBadProviderOutput(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	_, otherPriv, _ := GenerateHybridKeypair()
	for name, signer := range map[string]*remoteSignerV2Test{
		"ml-dsa bit flip":  {priv: priv, mode: SignerModeDirectV2, tamper: func(s *HybridSignature) { s.MLDSA65[0] ^= 1 }},
		"ed25519 bit flip": {priv: priv, mode: SignerModeDirectV2, tamper: func(s *HybridSignature) { s.Ed25519[40] ^= 1 }},
		"other ml-dsa key": {priv: priv, mode: SignerModeDirectV2, tamper: func(s *HybridSignature) {
			other := make([]byte, mldsa65.SignatureSize)
			_ = mldsa65.SignTo(otherPriv.MLDSA65, []byte("x"), nil, true, other)
			s.MLDSA65 = other
		}},
		"short signature": {priv: priv, mode: SignerModeDirectV2, tamper: func(s *HybridSignature) { s.MLDSA65 = s.MLDSA65[:10] }},
		"unknown mode":    {priv: priv, mode: 9},
	} {
		t.Run(name, func(t *testing.T) {
			if cert, err := SignDelegationCertV2WithSigner(context.Background(), unsignedCertV2Test(t, pub), signer); err == nil || cert != nil {
				t.Fatalf("bad provider output was used: %v", err)
			}
		})
	}
}

func TestSignerV2KeyBindingErrorsAndCancellation(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	_, otherPriv, _ := GenerateHybridKeypair()
	wrongKey := &remoteSignerV2Test{priv: otherPriv, mode: SignerModeDirectV2}
	if _, err := SignDelegationCertV2WithSigner(context.Background(), unsignedCertV2Test(t, pub), wrongKey); err == nil || wrongKey.calls != 0 {
		t.Fatalf("signer for another key was called or accepted: calls=%d err=%v", wrongKey.calls, err)
	}
	providerErr := errors.New("hsm offline")
	failing := &remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2, err: providerErr}
	if _, err := SignDelegationCertV2WithSigner(context.Background(), unsignedCertV2Test(t, pub), failing); !errors.Is(err, providerErr) {
		t.Fatalf("provider error not propagated: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := &remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2}
	if _, err := SignDelegationCertV2WithSigner(ctx, unsignedCertV2Test(t, pub), before); !errors.Is(err, context.Canceled) || before.calls != 0 {
		t.Fatalf("cancelled context: calls=%d err=%v", before.calls, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	during := &remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2, onSign: cancel}
	if cert, err := SignDelegationCertV2WithSigner(ctx, unsignedCertV2Test(t, pub), during); !errors.Is(err, context.Canceled) || cert != nil {
		t.Fatalf("signature returned after cancellation was used: %v", err)
	}
	if _, err := SignDelegationCertV2WithSigner(context.Background(), unsignedCertV2Test(t, pub), nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}

// TestSignerV2HedgedRetriesDifferOnlyInSignature: hedged ML-DSA yields new
// signature bytes on every call while the signed body digest is unchanged.
func TestSignerV2HedgedRetriesDifferOnlyInSignature(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	entry := &WitnessEntryV2{Version: 2, LogID: strings.Repeat("a", 32), Sequence: 1, PrevHash: make([]byte, 48), EntryData: []byte("x"), Timestamp: 1}
	entry.WitnessID, _ = KeyIDV2(pub)
	first, err := SignWitnessEntryV2(entry, priv)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignWitnessEntryV2WithSigner(context.Background(), entry, &remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2})
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := WitnessEntryV2Digest(first)
	d2, _ := WitnessEntryV2Digest(second)
	if bytes.Equal(first.Signature.MLDSA65, second.Signature.MLDSA65) || !bytes.Equal(d1, d2) {
		t.Fatal("hedged retries must differ in signature bytes but share the body digest")
	}
	head := WitnessV2Head{LogID: entry.LogID, Sequence: 1, HeadHash: d1, AcceptedDigests: map[int64][]byte{1: d1}}
	if result, err := VerifyWitnessEntryV2(second, head, pub); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("re-signed accepted entry = %v, %v; want replay", result, err)
	}
}

// TestSignerV2CoversEveryTypedSigner signs every object type through an
// external signer and checks the result with the ordinary verifier.
func TestSignerV2CoversEveryTypedSigner(t *testing.T) {
	ctx := context.Background()
	remote := func(priv HybridPrivateKey) SignerV2 { return &remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2} }

	statusPub, statusPriv, _ := GenerateHybridKeypair()
	issuer := strings.Repeat("b", 64)
	list, err := SignRevocationListV2WithSigner(ctx, &RevocationListV2{Version: 2, IssuerID: issuer, UpdatedAt: 1, NextUpdate: 10, Sequence: 1, Revoked: []RevokedCertV2{}}, issuer, statusPub, remote(statusPriv))
	if err != nil || VerifyRevocationListV2Signature(list, issuer, statusPub) != nil {
		t.Fatalf("list: %v", err)
	}
	push, err := SignRevocationPushV2WithSigner(ctx, &RevocationPushV2{Version: 2, IssuerID: issuer, Sequence: 2, PushedAt: 1, Revoked: []RevokedCertV2{{CertID: "c"}}}, issuer, statusPub, remote(statusPriv))
	if err != nil || VerifyRevocationPushV2Signature(push, issuer, statusPub) != nil {
		t.Fatalf("push: %v", err)
	}

	bundle, _, _, _, agentPriv := signedV2DelegationChainTest(t, true)
	bundle.ChallengeSig = HybridSignature{}
	signedBundle, err := SignProofBundleV2WithSigner(ctx, bundle, remote(agentPriv))
	if err != nil || VerifyProofBundleV2Signatures(signedBundle) != nil {
		t.Fatalf("bundle: %v", err)
	}

	oldPub, oldPriv, _ := GenerateHybridKeypair()
	newPub, newPriv, _ := GenerateHybridKeypair()
	oldID, _ := KeyIDV2(oldPub)
	newID, _ := KeyIDV2(newPub)
	stmt := &KeyRotationStatementV2{Version: 2, AuthorityID: strings.Repeat("c", 32), RecoveryEpoch: 1, Role: "issuer", Sequence: 1,
		PreviousStatementHash: make([]byte, 48), OldKey: oldPub, NewKey: newPub, OldKeyID: oldID, NewKeyID: newID, IssuedAt: 1, NotBefore: 1}
	rotated, err := SignKeyRotationStatementV2WithSigners(ctx, stmt, remote(oldPriv), remote(newPriv))
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	state := KeyRotationV2State{AuthorityID: stmt.AuthorityID, RecoveryEpoch: 1, Role: "issuer", HeadHash: make([]byte, 48), CurrentKey: oldPub, UsedKeyIDs: []string{oldID}}
	if err := VerifyKeyRotationStatementV2(rotated, state, 10, 0); err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	if _, err := SignKeyRotationStatementV2WithSigners(ctx, stmt, remote(newPriv), remote(oldPriv)); err == nil {
		t.Fatal("rotation signers in the wrong roles were accepted")
	}

	receipt, agentKey := signedTransactionReceiptV2Test(t)
	partySig, err := SignTransactionReceiptPartyV2WithSigner(ctx, receipt, "buyer", remote(agentKey))
	if err != nil {
		t.Fatalf("transaction party: %v", err)
	}
	receipt.PartySignatures = []TransactionReceiptSignatureV2{partySig}
	if err := VerifyTransactionReceiptV2Signatures(receipt); err != nil {
		t.Fatalf("transaction verify: %v", err)
	}
}

// TestNoExportedLocalSignerV2 pins SPEC-v2 §3.2: no exported function or
// method returns a SignerV2, so the only SignerV2 values a caller holds are
// providers it implemented itself. A returned local signer would sign any
// well-formed message under any context the caller chose.
func TestNoExportedLocalSignerV2(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			for _, res := range fn.Type.Results.List {
				if id, ok := res.Type.(*ast.Ident); ok && id.Name == "SignerV2" {
					t.Errorf("%s: exported %s returns a SignerV2", fset.Position(fn.Pos()), fn.Name.Name)
				}
			}
		}
	}
}
