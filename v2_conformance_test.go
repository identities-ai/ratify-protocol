package ratify_test

// Shared Protocol v2 conformance corpus runner. Every file under
// testvectors/v2 produced by cmd/ratify-v2-vectors is loaded here, and the Go
// reference implementation must agree with every vector. Expected values are
// written by the generator from SPEC-v2 rules, so a disagreement is either a
// reference bug or a vector bug and must be investigated, never re-baselined.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func loadV2Vector(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testvectors", "v2", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Keys

type v2KeyEntry struct {
	Name           string                 `json:"name"`
	Ed25519SeedHex string                 `json:"ed25519_seed_hex"`
	MLDSA65SeedHex string                 `json:"ml_dsa_65_seed_hex"`
	PublicKey      ratify.HybridPublicKey `json:"public_key"`
	KeyIDV2        string                 `json:"key_id_v2"`
	V1KeyID128     string                 `json:"v1_key_id_128"`
}

type v2KeysFile struct {
	Version       int          `json:"version"`
	Description   string       `json:"description"`
	KeyIDPreimage string       `json:"key_id_preimage"`
	Keys          []v2KeyEntry `json:"keys"`
	InvalidKeyIDs []struct {
		Name               string `json:"name"`
		Value              string `json:"value"`
		ExpectedErrorClass string `json:"expected_error_class"`
	} `json:"invalid_v2_key_ids"`
}

type v2Fixture struct {
	pub  map[string]ratify.HybridPublicKey
	priv map[string]ratify.HybridPrivateKey
	id   map[string]string
}

func loadV2Keys(t *testing.T) (v2KeysFile, v2Fixture) {
	t.Helper()
	var f v2KeysFile
	loadV2Vector(t, "keys.json", &f)
	return f, v2FixtureFromKeys(t, f.Keys)
}

// v2FixtureFromKeys derives every key from its seeds.
func v2FixtureFromKeys(t *testing.T, keys []v2KeyEntry) v2Fixture {
	t.Helper()
	fx := v2Fixture{pub: map[string]ratify.HybridPublicKey{}, priv: map[string]ratify.HybridPrivateKey{}, id: map[string]string{}}
	for _, k := range keys {
		var ed, ml [32]byte
		copy(ed[:], mustHex(t, k.Ed25519SeedHex))
		copy(ml[:], mustHex(t, k.MLDSA65SeedHex))
		pub, priv, err := ratify.HybridKeypairFromSeeds(ed, ml)
		if err != nil {
			t.Fatal(err)
		}
		fx.pub[k.Name], fx.priv[k.Name], fx.id[k.Name] = pub, priv, k.KeyIDV2
	}
	return fx
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func independentKeyIDV2(pub ratify.HybridPublicKey) string {
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2\x00"))
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	return hex.EncodeToString(h.Sum(nil))
}

func TestV2ConformanceKeys(t *testing.T) {
	f, fx := loadV2Keys(t)
	if len(f.Keys) == 0 {
		t.Fatal("no keys")
	}
	for _, k := range f.Keys {
		if !bytes.Equal(fx.pub[k.Name].Ed25519, k.PublicKey.Ed25519) || !bytes.Equal(fx.pub[k.Name].MLDSA65, k.PublicKey.MLDSA65) {
			t.Errorf("%s: seeds do not derive the pinned public key", k.Name)
		}
		if got := independentKeyIDV2(k.PublicKey); got != k.KeyIDV2 || len(got) != 64 {
			t.Errorf("%s: key_id_v2 = %s, want %s", k.Name, got, k.KeyIDV2)
		}
		if got := ratify.DeriveID(k.PublicKey); got != k.V1KeyID128 || got == k.KeyIDV2[:32] {
			t.Errorf("%s: v1 ID %s does not match pinned %s or aliases the v2 prefix", k.Name, got, k.V1KeyID128)
		}
	}
	// Every invalid v2 key ID must be rejected wherever a v2 key ID is
	// required: as a bundle verifier_id and as a witness_id.
	var objs v2ObjectsFile
	loadV2Vector(t, "objects.json", &objs)
	bundleWire := v2ObjectByKind(t, objs, "proof_bundle").WireB64
	witnessWire := v2ObjectByKind(t, objs, "witness_entry").WireB64
	for _, bad := range f.InvalidKeyIDs {
		for field, wire := range map[string]string{"verifier_id": bundleWire, "witness_id": witnessWire} {
			mutated := v2SetTopLevelString(t, unb64(t, wire), field, bad.Value)
			var err error
			if field == "verifier_id" {
				_, err = ratify.DecodeProofBundleV2(mutated)
			} else {
				_, err = ratify.DecodeWitnessEntryV2(mutated)
			}
			if got := ratify.V2ErrorClassOf(err); string(got) != bad.ExpectedErrorClass {
				t.Errorf("%s as %s: class %q (err %v), want %q", bad.Name, field, got, err, bad.ExpectedErrorClass)
			}
		}
	}
}

func v2SetTopLevelString(t *testing.T, wire []byte, field, value string) []byte {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(wire, &obj); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(value)
	obj[field] = encoded
	out, err := ratify.CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Objects

type v2SigVector struct {
	Field          string                 `json:"field"`
	ObjectTypeCode int                    `json:"object_type_code"`
	Signer         string                 `json:"signer"`
	SignerKeyIDV2  string                 `json:"signer_key_id_v2"`
	SignableB64    string                 `json:"signable_b64"`
	SignableSHA384 string                 `json:"signable_sha384_hex"`
	MessageB64     string                 `json:"message_b64"`
	MLDSAContext   string                 `json:"mldsa_context"`
	MLDSATrB64     string                 `json:"mldsa_tr_b64"`
	MLDSAMuB64     string                 `json:"mldsa_mu_b64"`
	Signature      ratify.HybridSignature `json:"signature"`
}

type v2Head struct {
	LogID           string            `json:"log_id"`
	VerifierID      string            `json:"verifier_id"`
	Sequence        int64             `json:"sequence"`
	HeadHashB64     string            `json:"head_hash_b64"`
	AcceptedDigests map[string]string `json:"accepted_digests_b64"`
	Frozen          bool              `json:"frozen"`
}

type v2RotationState struct {
	AuthorityID   string   `json:"authority_id"`
	RecoveryEpoch int64    `json:"recovery_epoch"`
	Role          string   `json:"role"`
	Sequence      int64    `json:"sequence"`
	HeadHashB64   string   `json:"head_hash_b64"`
	CurrentKey    string   `json:"current_key"`
	UsedKeyIDs    []string `json:"used_key_ids"`
}

type v2VerifyContext struct {
	BoundIssuerID string           `json:"bound_issuer_id"`
	StatusKey     string           `json:"status_key"`
	RotationState *v2RotationState `json:"rotation_state"`
	WitnessKey    string           `json:"witness_key"`
	VerifierKey   string           `json:"verifier_key"`
	Head          *v2Head          `json:"head"`
	Now           int64            `json:"now"`
	FutureSkew    int64            `json:"future_skew_seconds"`
}

type v2ObjectVector struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Description string            `json:"description"`
	WireB64     string            `json:"wire_b64"`
	BundleB64   string            `json:"bundle_b64"`
	Verify      v2VerifyContext   `json:"verify"`
	Signatures  []v2SigVector     `json:"signatures"`
	Digests     map[string]string `json:"digests"`
}

type v2ObjectsFile struct {
	Version     int              `json:"version"`
	Description string           `json:"description"`
	Kinds       map[string]int   `json:"kind_object_type_codes"`
	Objects     []v2ObjectVector `json:"objects"`
}

func v2ObjectByKind(t *testing.T, f v2ObjectsFile, kind string) v2ObjectVector {
	t.Helper()
	for _, o := range f.Objects {
		if o.Kind == kind {
			return o
		}
	}
	t.Fatalf("no %s object", kind)
	return v2ObjectVector{}
}

func (h *v2Head) witness(t *testing.T) ratify.WitnessV2Head {
	head := ratify.WitnessV2Head{LogID: h.LogID, Sequence: h.Sequence, HeadHash: unb64(t, h.HeadHashB64), AcceptedDigests: map[int64][]byte{}, Frozen: h.Frozen}
	for seq, d := range h.AcceptedDigests {
		n, _ := strconv.ParseInt(seq, 10, 64)
		head.AcceptedDigests[n] = unb64(t, d)
	}
	return head
}

func (h *v2Head) receipt(t *testing.T) ratify.ReceiptV2Head {
	w := h.witness(t)
	return ratify.ReceiptV2Head{LogID: w.LogID, VerifierID: h.VerifierID, Sequence: w.Sequence, HeadHash: w.HeadHash, AcceptedDigests: w.AcceptedDigests, Frozen: w.Frozen}
}

func (s *v2RotationState) state(t *testing.T, fx v2Fixture) ratify.KeyRotationV2State {
	return ratify.KeyRotationV2State{AuthorityID: s.AuthorityID, RecoveryEpoch: s.RecoveryEpoch, Role: s.Role, Sequence: s.Sequence,
		HeadHash: unb64(t, s.HeadHashB64), CurrentKey: fx.pub[s.CurrentKey], UsedKeyIDs: append([]string(nil), s.UsedKeyIDs...)}
}

// v2VerifyObject runs the per-kind decode and verify procedure documented in
// object-negatives.json.
func v2VerifyObject(t *testing.T, fx v2Fixture, kind string, wire, bundleWire []byte, vc v2VerifyContext) error {
	t.Helper()
	switch kind {
	case "delegation_certificate":
		c, err := ratify.DecodeDelegationCertV2(wire)
		if err != nil {
			return err
		}
		return ratify.VerifyDelegationCertV2Signature(c)
	case "proof_bundle":
		b, err := ratify.DecodeProofBundleV2(wire)
		if err != nil {
			return err
		}
		return ratify.VerifyProofBundleV2Signatures(b)
	case "revocation_list":
		l, err := ratify.DecodeRevocationListV2(wire)
		if err != nil {
			return err
		}
		return ratify.VerifyRevocationListV2Signature(l, vc.BoundIssuerID, fx.pub[vc.StatusKey])
	case "revocation_push":
		p, err := ratify.DecodeRevocationPushV2(wire)
		if err != nil {
			return err
		}
		return ratify.VerifyRevocationPushV2Signature(p, vc.BoundIssuerID, fx.pub[vc.StatusKey])
	case "key_rotation_statement":
		s, err := ratify.DecodeKeyRotationStatementV2(wire)
		if err != nil {
			return err
		}
		return ratify.VerifyKeyRotationStatementV2(s, vc.RotationState.state(t, fx), vc.Now, vc.FutureSkew)
	case "witness_entry":
		e, err := ratify.DecodeWitnessEntryV2(wire)
		if err != nil {
			return err
		}
		_, err = ratify.VerifyWitnessEntryV2(e, vc.Head.witness(t), fx.pub[vc.WitnessKey])
		return err
	case "transaction_receipt":
		r, err := ratify.DecodeTransactionReceiptV2(wire)
		if err != nil {
			return err
		}
		return ratify.VerifyTransactionReceiptV2Signatures(r)
	case "verification_receipt":
		r, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil {
			return err
		}
		_, err = ratify.VerifyVerificationReceiptV2(r, fx.pub[vc.VerifierKey], vc.Head.receipt(t))
		return err
	case "receipt_bundle_binding":
		r, err := ratify.DecodeVerificationReceiptV2(wire)
		if err != nil {
			return err
		}
		b, err := ratify.DecodeProofBundleV2(bundleWire)
		if err != nil {
			return err
		}
		return ratify.CheckVerificationReceiptV2BundleBinding(r, b)
	}
	t.Fatalf("unknown kind %q", kind)
	return nil
}

// v2Reencode decodes and re-encodes wire, which must be byte-identical.
func v2Reencode(t *testing.T, kind string, wire []byte) []byte {
	t.Helper()
	var out []byte
	var err error
	switch kind {
	case "delegation_certificate":
		var c *ratify.DelegationCertV2
		if c, err = ratify.DecodeDelegationCertV2(wire); err == nil {
			out, err = ratify.EncodeDelegationCertV2(c)
		}
	case "proof_bundle":
		var b *ratify.ProofBundleV2
		if b, err = ratify.DecodeProofBundleV2(wire); err == nil {
			out, err = ratify.EncodeProofBundleV2(b)
		}
	case "revocation_list":
		var l *ratify.RevocationListV2
		if l, err = ratify.DecodeRevocationListV2(wire); err == nil {
			out, err = ratify.EncodeRevocationListV2(l)
		}
	case "revocation_push":
		var p *ratify.RevocationPushV2
		if p, err = ratify.DecodeRevocationPushV2(wire); err == nil {
			out, err = ratify.EncodeRevocationPushV2(p)
		}
	case "key_rotation_statement":
		var s *ratify.KeyRotationStatementV2
		if s, err = ratify.DecodeKeyRotationStatementV2(wire); err == nil {
			out, err = ratify.EncodeKeyRotationStatementV2(s)
		}
	case "witness_entry":
		var e *ratify.WitnessEntryV2
		if e, err = ratify.DecodeWitnessEntryV2(wire); err == nil {
			out, err = ratify.EncodeWitnessEntryV2(e)
		}
	case "transaction_receipt":
		var r *ratify.TransactionReceiptV2
		if r, err = ratify.DecodeTransactionReceiptV2(wire); err == nil {
			out, err = ratify.EncodeTransactionReceiptV2(r)
		}
	case "verification_receipt":
		var r *ratify.VerificationReceiptV2
		if r, err = ratify.DecodeVerificationReceiptV2(wire); err == nil {
			out, err = ratify.EncodeVerificationReceiptV2(r)
		}
	}
	if err != nil {
		t.Fatalf("%s re-encode: %v", kind, err)
	}
	return out
}

// v2Projection derives a signature's signable bytes from the wire object by
// the SPEC-v2 §5 projection rule for that signature field.
func v2Projection(t *testing.T, wire []byte, field string) []byte {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(wire, &obj); err != nil {
		t.Fatal(err)
	}
	drop := func(fields ...string) []byte {
		for _, f := range fields {
			delete(obj, f)
		}
		out, err := ratify.CanonicalJSON(obj)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	switch {
	case field == "signature":
		return drop("signature")
	case field == "challenge_sig":
		return drop("delegations", "challenge_sig")
	case field == "old_signature" || field == "new_signature":
		return drop("old_signature", "new_signature")
	case strings.HasPrefix(field, "delegations["):
		var certs []json.RawMessage
		_ = json.Unmarshal(obj["delegations"], &certs)
		i, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(field, "delegations["), "].signature"))
		return v2Projection(t, certs[i], "signature")
	case strings.HasPrefix(field, "party_signatures["):
		r, err := ratify.DecodeTransactionReceiptV2(wire)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ratify.TransactionReceiptV2SignBytes(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Fatalf("unknown signature field %q", field)
	return nil
}

func v2Message(code uint16, signable []byte) []byte {
	d := sha512.Sum384(signable)
	m := append([]byte("ratify-protocol-signature\x00\x02"), byte(code>>8), byte(code))
	return append(m, d[:]...)
}

func TestV2ConformanceObjects(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f v2ObjectsFile
	loadV2Vector(t, "objects.json", &f)
	seenCodes := map[int]bool{}
	for _, o := range f.Objects {
		t.Run(o.Name, func(t *testing.T) { v2CheckPositiveObject(t, fx, o, seenCodes) })
	}
	for code := 1; code <= 9; code++ {
		if !seenCodes[code] {
			t.Errorf("objects.json has no signature for object_type_code %d", code)
		}
	}
}

// v2CheckPositiveObject runs the objects.json positive procedure on one
// object: byte-identical re-encode, verify, every signature transcript, and
// every digest. Cross-SDK fixtures reuse it with their own keys.
func v2CheckPositiveObject(t *testing.T, fx v2Fixture, o v2ObjectVector, seenCodes map[int]bool) {
	t.Helper()
	wire := unb64(t, o.WireB64)
	if got := v2Reencode(t, o.Kind, wire); !bytes.Equal(got, wire) {
		t.Fatalf("re-encoding is not byte-identical")
	}
	if err := v2VerifyObject(t, fx, o.Kind, wire, nil, o.Verify); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, s := range o.Signatures {
		seenCodes[s.ObjectTypeCode] = true
		signable := unb64(t, s.SignableB64)
		if got := v2Projection(t, wire, s.Field); !bytes.Equal(got, signable) {
			t.Errorf("%s: signable projection differs:\n got %s\nwant %s", s.Field, got, signable)
		}
		if d := sha512.Sum384(signable); hex.EncodeToString(d[:]) != s.SignableSHA384 {
			t.Errorf("%s: signable SHA-384 differs", s.Field)
		}
		m := v2Message(uint16(s.ObjectTypeCode), signable)
		if !bytes.Equal(m, unb64(t, s.MessageB64)) || len(m) != 77 {
			t.Errorf("%s: transcript M differs", s.Field)
		}
		ctx := fmt.Sprintf("ratify-protocol/2/%04x", s.ObjectTypeCode)
		if s.MLDSAContext != ctx || len(ctx) != 22 {
			t.Errorf("%s: context %q, want %q", s.Field, s.MLDSAContext, ctx)
		}
		signer := fx.pub[s.Signer]
		if fx.id[s.Signer] != s.SignerKeyIDV2 {
			t.Errorf("%s: signer key ID differs", s.Field)
		}
		tr := sha3.SumSHAKE256(signer.MLDSA65, 64)
		mu := sha3.SumSHAKE256(append(append(append(append([]byte{}, tr...), 0, byte(len(ctx))), ctx...), m...), 64)
		if !bytes.Equal(tr, unb64(t, s.MLDSATrB64)) || !bytes.Equal(mu, unb64(t, s.MLDSAMuB64)) {
			t.Errorf("%s: external-mu tr/mu differ", s.Field)
		}
		if !bytes.Contains(wire, []byte(base64.StdEncoding.EncodeToString(s.Signature.MLDSA65))) || !bytes.Contains(wire, []byte(base64.StdEncoding.EncodeToString(s.Signature.Ed25519))) {
			t.Errorf("%s: pinned signature is not the one carried by the wire object", s.Field)
		}
	}
	v2CheckObjectDigests(t, o, wire)
}

func v2CheckObjectDigests(t *testing.T, o v2ObjectVector, wire []byte) {
	t.Helper()
	for name, want := range o.Digests {
		var got string
		switch name {
		case "issuer_key_id_v2", "subject_key_id_v2":
			c, _ := ratify.DecodeDelegationCertV2(wire)
			if name == "issuer_key_id_v2" {
				got = independentKeyIDV2(c.IssuerPubKey)
			} else {
				got = independentKeyIDV2(c.SubjectPubKey)
			}
		case "delegation_digest_hex":
			b, _ := ratify.DecodeProofBundleV2(wire)
			got = hex.EncodeToString(b.DelegationDigest)
		case "bundle_hash_v2":
			b, _ := ratify.DecodeProofBundleV2(wire)
			got, _ = ratify.BundleHashV2(b)
		case "session_context_hex":
			b, _ := ratify.DecodeProofBundleV2(wire)
			ctx, err := ratify.BuildSessionContextV2(ratify.SessionContextV2Inputs{
				VerifierID: b.VerifierID, WorkspaceID: "00000000-0000-4000-8000-000000000001", AgentID: b.AgentID,
				SessionID: "session-01", InvocationID: "invocation-01",
				RequestHash: mustOperationContext(t, "data:read", "records.get", "customer/123", "/v1/customers/123"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if b.SessionContext == nil || !bytes.Equal(*b.SessionContext, ctx) {
				t.Errorf("bundle session_context does not match the recomputed fixture context")
			}
			got = hex.EncodeToString(ctx)
		case "challenge_claim_digest_hex":
			b, _ := ratify.DecodeProofBundleV2(wire)
			d, _ := ratify.ChallengeClaimDigestV2(b.Challenge)
			got = hex.EncodeToString(d)
		case "claim_id":
			b, _ := ratify.DecodeProofBundleV2(wire)
			epoch, _ := strconv.ParseInt(o.Digests["claim_replay_epoch"], 10, 64)
			got, _ = ratify.ProtocolClaimIDV2(o.Digests["claim_verifier_namespace"], epoch, b.Challenge)
		case "claim_verifier_namespace", "claim_replay_epoch", "receipt_outbox_body_b64":
			if name == "receipt_outbox_body_b64" {
				r, _ := ratify.DecodeVerificationReceiptV2(wire)
				body, err := ratify.VerificationReceiptV2Body(r)
				if err != nil {
					t.Fatal(err)
				}
				got = base64.StdEncoding.EncodeToString(body)
			} else {
				continue
			}
		case "status_evidence_digest":
			var d []byte
			if o.Kind == "revocation_list" {
				l, _ := ratify.DecodeRevocationListV2(wire)
				d, _ = ratify.StatusEvidenceDigest(3, l)
			} else {
				p, _ := ratify.DecodeRevocationPushV2(wire)
				d, _ = ratify.StatusEvidenceDigest(5, p)
			}
			got = "sha384:" + hex.EncodeToString(d)
		case "statement_body_digest_hex":
			var d []byte
			switch o.Kind {
			case "key_rotation_statement":
				s, _ := ratify.DecodeKeyRotationStatementV2(wire)
				d, _ = ratify.KeyRotationStatementV2Digest(s)
			case "witness_entry":
				e, _ := ratify.DecodeWitnessEntryV2(wire)
				d, _ = ratify.WitnessEntryV2Digest(e)
			case "verification_receipt":
				r, _ := ratify.DecodeVerificationReceiptV2(wire)
				d, _ = ratify.VerificationReceiptV2Digest(r)
			}
			got = hex.EncodeToString(d)
		case "transaction_context_hex":
			continue // checked through party session contexts below
		default:
			if strings.HasPrefix(name, "party-") {
				got = v2TransactionPartyDigest(t, wire, name, o.Digests["transaction_context_hex"])
				break
			}
			t.Fatalf("unknown digest %q", name)
		}
		if got != want {
			t.Errorf("digest %s = %s, want %s", name, got, want)
		}
	}
}

func mustOperationContext(t *testing.T, scope, operation, resource, path string) []byte {
	t.Helper()
	h, err := ratify.BuildOperationContextV2(ratify.OperationContextV2Inputs{RequiredScope: scope, Operation: operation, ResourceID: resource, RequestedPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func v2LP(b []byte) []byte { return append(binary.BigEndian.AppendUint64(nil, uint64(len(b))), b...) }

func v2TransactionPartyDigest(t *testing.T, wire []byte, name, txContextHex string) string {
	t.Helper()
	r, err := ratify.DecodeTransactionReceiptV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	partyID, field, _ := strings.Cut(name, ".")
	txc := sha256.New()
	txc.Write([]byte("ratify/transaction-context/v2"))
	txc.Write(v2LP([]byte(r.TransactionID)))
	txc.Write(v2LP([]byte(r.TermsSchemaURI)))
	terms := sha512.Sum384(r.TermsCanonicalJSON)
	txc.Write(terms[:])
	txContext := txc.Sum(nil)
	if hex.EncodeToString(txContext) != txContextHex {
		t.Errorf("transaction context differs")
	}
	for _, p := range r.Parties {
		if p.PartyID != partyID {
			continue
		}
		req := sha256.Sum256(append(append([]byte("ratify/transaction-party-request/v2"), v2LP(txContext)...), v2LP([]byte(p.RequiredScope))...))
		switch field {
		case "transaction_party_request_hash_hex":
			return hex.EncodeToString(req[:])
		case "session_context_hex":
			ctx, err := ratify.BuildSessionContextV2(ratify.SessionContextV2Inputs{VerifierID: p.VerifierID, WorkspaceID: p.WorkspaceID, AgentID: p.AgentID, SessionID: p.SessionID, InvocationID: p.InvocationID, RequestHash: req[:]})
			if err != nil {
				t.Fatal(err)
			}
			return hex.EncodeToString(ctx)
		case "proof_bundle_hash":
			h, _ := ratify.BundleHashV2(p.ProofBundle)
			return h
		}
	}
	t.Fatalf("unknown transaction digest %q", name)
	return ""
}

// ---------------------------------------------------------------------------
// Object negatives

type v2NegativeVector struct {
	Name               string          `json:"name"`
	Kind               string          `json:"kind"`
	Mutation           string          `json:"mutation"`
	WireB64            string          `json:"wire_b64"`
	BundleB64          string          `json:"bundle_b64"`
	Verify             v2VerifyContext `json:"verify"`
	ExpectedErrorClass string          `json:"expected_error_class"`
}

func TestV2ConformanceObjectNegatives(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version     int                `json:"version"`
		Description string             `json:"description"`
		Procedure   map[string]string  `json:"procedure_by_kind"`
		Vectors     []v2NegativeVector `json:"vectors"`
	}
	loadV2Vector(t, "object-negatives.json", &f)
	kinds := map[string]int{}
	for _, v := range f.Vectors {
		kinds[v.Kind]++
		t.Run(v.Name, func(t *testing.T) {
			var bundle []byte
			if v.BundleB64 != "" {
				bundle = unb64(t, v.BundleB64)
			}
			err := v2VerifyObject(t, fx, v.Kind, unb64(t, v.WireB64), bundle, v.Verify)
			if err == nil {
				t.Fatalf("accepted; want %s (%s)", v.ExpectedErrorClass, v.Mutation)
			}
			if got := ratify.V2ErrorClassOf(err); string(got) != v.ExpectedErrorClass {
				t.Fatalf("class %q, want %q (%s): %v", got, v.ExpectedErrorClass, v.Mutation, err)
			}
		})
	}
	for _, kind := range []string{"delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement", "witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding"} {
		if kinds[kind] == 0 {
			t.Errorf("no negative vectors for %s", kind)
		}
	}
}

// ---------------------------------------------------------------------------
// Status sequences

type v2StatusPolicy struct {
	MaxListLifetimeSeconds int64 `json:"max_list_lifetime_seconds"`
	MaxStatusAgeSeconds    int64 `json:"max_status_age_seconds"`
	ClockSkewSeconds       int64 `json:"clock_skew_seconds"`
}

func (p v2StatusPolicy) lib() ratify.RevocationStatusPolicyV2 {
	return ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: p.MaxListLifetimeSeconds, MaxStatusAgeSeconds: p.MaxStatusAgeSeconds, ClockSkewSeconds: p.ClockSkewSeconds}
}

type v2StatusState struct {
	HasFloor                  *bool     `json:"has_floor"`
	Floor                     *int64    `json:"floor"`
	MaxObservedSequence       *int64    `json:"max_observed_sequence"`
	ForkSequence              *int64    `json:"fork_sequence"`
	ReconciliationRequired    *bool     `json:"reconciliation_required"`
	FutureDatedObjectObserved *bool     `json:"future_dated_object_observed"`
	AcceptedSet               *[]string `json:"accepted_set"`
	DenyUnion                 *[]string `json:"deny_union"`
}

func TestV2ConformanceStatusSequences(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version     int               `json:"version"`
		Description string            `json:"description"`
		Operations  map[string]string `json:"operations"`
		Scenarios   []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			IssuerID    string         `json:"issuer_id"`
			Policy      v2StatusPolicy `json:"policy"`
			Steps       []struct {
				Op               string          `json:"op"`
				Label            string          `json:"label"`
				WireB64          string          `json:"wire_b64"`
				StatusKey        string          `json:"status_key"`
				StatusKeyEpoch   uint64          `json:"status_key_epoch"`
				Now              int64           `json:"now"`
				CertID           string          `json:"cert_id"`
				Policy           *v2StatusPolicy `json:"policy"`
				ExpectErrorClass string          `json:"expect_error_class"`
				ExpectState      *v2StatusState  `json:"expect_state"`
				ExpectResult     *struct {
					Status   string       `json:"status"`
					Reason   string       `json:"reason"`
					Evidence []v2Evidence `json:"evidence"`
				} `json:"expect_result"`
			} `json:"steps"`
		} `json:"scenarios"`
	}
	loadV2Vector(t, "status-sequences.json", &f)
	if len(f.Scenarios) == 0 {
		t.Fatal("no status scenarios")
	}
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			state := ratify.RevocationStatusStateV2{}
			for i, step := range sc.Steps {
				key := fx.pub[step.StatusKey]
				policy := sc.Policy.lib()
				if step.Policy != nil {
					policy = step.Policy.lib()
				}
				var err error
				next := state
				switch step.Op {
				case "apply_list":
					var l *ratify.RevocationListV2
					if l, err = ratify.DecodeRevocationListV2(unb64(t, step.WireB64)); err == nil {
						next, err = ratify.ApplyRevocationListV2(state, l, sc.IssuerID, step.StatusKeyEpoch, key, policy, step.Now)
					}
				case "apply_push":
					var p *ratify.RevocationPushV2
					if p, err = ratify.DecodeRevocationPushV2(unb64(t, step.WireB64)); err == nil {
						next, err = ratify.ApplyRevocationPushV2(state, p, sc.IssuerID, step.StatusKeyEpoch, key, policy, step.Now)
					}
				case "transition_epoch":
					next, err = ratify.TransitionRevocationStatusEpochV2(state, sc.IssuerID, step.StatusKeyEpoch, key)
				case "query":
					var r ratify.RevocationStatusResultV2
					r, err = ratify.RevocationStatusForCertV2(state, sc.IssuerID, step.CertID, step.StatusKeyEpoch, key, policy, step.Now)
					if err != nil {
						t.Fatalf("step %d query: %v", i, err)
					}
					want := step.ExpectResult
					if r.Status != want.Status || r.Reason != want.Reason {
						t.Errorf("step %d query %s: %s/%s, want %s/%s", i, step.CertID, r.Status, r.Reason, want.Status, want.Reason)
					}
					wantEv := make([]ratify.StatusEvidenceEntryV2, len(want.Evidence))
					for j, e := range want.Evidence {
						wantEv[j] = e.lib()
					}
					if fmt.Sprint(r.Evidence) != fmt.Sprint(wantEv) {
						t.Errorf("step %d query %s evidence:\n got %v\nwant %v", i, step.CertID, r.Evidence, wantEv)
					}
					continue
				default:
					t.Fatalf("unknown op %q", step.Op)
				}
				if step.ExpectErrorClass != "" {
					if got := ratify.V2ErrorClassOf(err); string(got) != step.ExpectErrorClass {
						t.Fatalf("step %d %s %s: class %q (%v), want %q", i, step.Op, step.Label, got, err, step.ExpectErrorClass)
					}
					continue
				}
				if err != nil {
					t.Fatalf("step %d %s %s: %v", i, step.Op, step.Label, err)
				}
				state = next
				if w := step.ExpectState; w != nil {
					checkV2StatusState(t, fmt.Sprintf("step %d %s %s", i, step.Op, step.Label), state, w)
				}
			}
		})
	}
}

func checkV2StatusState(t *testing.T, where string, s ratify.RevocationStatusStateV2, w *v2StatusState) {
	t.Helper()
	cmp := func(name string, got, want any) {
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %s = %v, want %v", where, name, got, want)
		}
	}
	if w.HasFloor != nil {
		cmp("has_floor", s.HasFloor, *w.HasFloor)
	}
	if w.Floor != nil {
		cmp("floor", s.Floor, *w.Floor)
	}
	if w.MaxObservedSequence != nil {
		cmp("max_observed_sequence", s.MaxObservedSequence, *w.MaxObservedSequence)
	}
	if w.ForkSequence != nil {
		cmp("fork_sequence", s.ForkSequence, *w.ForkSequence)
	}
	if w.ReconciliationRequired != nil {
		cmp("reconciliation_required", s.ReconciliationRequired, *w.ReconciliationRequired)
	}
	if w.FutureDatedObjectObserved != nil {
		cmp("future_dated_object_observed", s.FutureDatedObjectObserved, *w.FutureDatedObjectObserved)
	}
	if w.AcceptedSet != nil {
		cmp("accepted_set", append([]string{}, s.AcceptedCertIDs...), *w.AcceptedSet)
	}
	if w.DenyUnion != nil {
		cmp("deny_union", append([]string{}, s.DenyUnionCertIDs...), *w.DenyUnion)
	}
}

// ---------------------------------------------------------------------------
// Witness and receipt logs

func TestV2ConformanceLogSequences(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version     int               `json:"version"`
		Description string            `json:"description"`
		HeadRules   map[string]string `json:"head_rules"`
		Scenarios   []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Kind        string `json:"kind"`
			VerifierID  string `json:"verifier_id"`
			LogID       string `json:"initial_log_id"`
			Steps       []struct {
				Op      string `json:"op"`
				Label   string `json:"label"`
				WireB64 string `json:"wire_b64"`
				Key     string `json:"key"`
				LogID   string `json:"log_id"`
				Expect  string `json:"expect"`
			} `json:"steps"`
		} `json:"scenarios"`
	}
	loadV2Vector(t, "log-sequences.json", &f)
	if len(f.Scenarios) != 2 {
		t.Fatalf("want witness and receipt log scenarios, got %d", len(f.Scenarios))
	}
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			genesis := func(logID string) ratify.WitnessV2Head {
				return ratify.WitnessV2Head{LogID: logID, HeadHash: make([]byte, 48), AcceptedDigests: map[int64][]byte{}}
			}
			head := genesis(sc.LogID)
			for i, step := range sc.Steps {
				if step.Op == "recover" {
					head = genesis(step.LogID)
					continue
				}
				wire := unb64(t, step.WireB64)
				var result ratify.WitnessEntryV2Result
				var digest []byte
				var seq int64
				var err error
				if sc.Kind == "witness_entry" {
					var e *ratify.WitnessEntryV2
					if e, err = ratify.DecodeWitnessEntryV2(wire); err == nil {
						result, err = ratify.VerifyWitnessEntryV2(e, head, fx.pub[step.Key])
						digest, _ = ratify.WitnessEntryV2Digest(e)
						seq = e.Sequence
					}
				} else {
					var r *ratify.VerificationReceiptV2
					if r, err = ratify.DecodeVerificationReceiptV2(wire); err == nil {
						rh := ratify.ReceiptV2Head{LogID: head.LogID, VerifierID: sc.VerifierID, Sequence: head.Sequence, HeadHash: head.HeadHash, AcceptedDigests: head.AcceptedDigests, Frozen: head.Frozen}
						result, err = ratify.VerifyVerificationReceiptV2(r, fx.pub[step.Key], rh)
						digest, _ = ratify.VerificationReceiptV2Digest(r)
						seq = r.Sequence
					}
				}
				got := ""
				switch {
				case err != nil:
					got = string(ratify.V2ErrorClassOf(err))
				case result == ratify.WitnessEntryV2Appended:
					got = "appended"
				case result == ratify.WitnessEntryV2Replay:
					got = "replay"
				}
				if got != step.Expect {
					t.Fatalf("step %d %s: %q (%v), want %q", i, step.Label, got, err, step.Expect)
				}
				switch got {
				case "appended":
					head.Sequence = seq
					head.HeadHash = digest
					head.AcceptedDigests[seq] = digest
				case "log_fork":
					head.Frozen = true
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Rotation sequences

func TestV2ConformanceRotationSequences(t *testing.T) {
	_, fx := loadV2Keys(t)
	var f struct {
		Version     int               `json:"version"`
		Description string            `json:"description"`
		Operations  map[string]string `json:"operations"`
		Scenarios   []struct {
			Name          string `json:"name"`
			Description   string `json:"description"`
			AuthorityID   string `json:"authority_id"`
			RecoveryEpoch int64  `json:"recovery_epoch"`
			Role          string `json:"role"`
			GenesisKey    string `json:"genesis_key"`
			FutureSkew    int64  `json:"future_skew_seconds"`
			Steps         []struct {
				Op               string `json:"op"`
				Label            string `json:"label"`
				WireB64          string `json:"wire_b64"`
				Now              int64  `json:"now"`
				NewRecoveryEpoch int64  `json:"new_recovery_epoch"`
				NewGenesisKey    string `json:"new_genesis_key"`
				Expect           string `json:"expect"`
				ExpectSequence   int64  `json:"expect_sequence"`
				ExpectCurrentKey string `json:"expect_current_key"`
				ExpectEpoch      int64  `json:"expect_recovery_epoch"`
				ExpectFrozen     bool   `json:"expect_frozen"`
			} `json:"steps"`
		} `json:"scenarios"`
	}
	loadV2Vector(t, "rotation-sequences.json", &f)
	if len(f.Scenarios) == 0 {
		t.Fatal("no rotation scenarios")
	}
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			journal, err := ratify.NewKeyRotationV2Journal(sc.AuthorityID, sc.RecoveryEpoch, sc.Role, fx.pub[sc.GenesisKey])
			if err != nil {
				t.Fatal(err)
			}
			for i, step := range sc.Steps {
				got := ""
				if step.Op == "recover" {
					next, err := ratify.RecoverKeyRotationV2(journal, step.NewRecoveryEpoch, fx.pub[step.NewGenesisKey])
					if err != nil {
						got = string(ratify.V2ErrorClassOf(err))
					} else {
						got, journal = "recovered", next
					}
				} else {
					var result ratify.WitnessEntryV2Result
					s, decodeErr := ratify.DecodeKeyRotationStatementV2(unb64(t, step.WireB64))
					if decodeErr != nil {
						t.Fatalf("step %d decode: %v", i, decodeErr)
					}
					journal, result, err = ratify.AcceptKeyRotationStatementV2(s, journal, step.Now, sc.FutureSkew)
					switch {
					case err != nil:
						got = string(ratify.V2ErrorClassOf(err))
					case result == ratify.WitnessEntryV2Appended:
						got = "appended"
					case result == ratify.WitnessEntryV2Replay:
						got = "replay"
					}
				}
				if got != step.Expect {
					t.Fatalf("step %d %s: %q (%v), want %q", i, step.Label, got, err, step.Expect)
				}
				if journal.State.Sequence != step.ExpectSequence || !bytes.Equal(journal.State.CurrentKey.MLDSA65, fx.pub[step.ExpectCurrentKey].MLDSA65) || journal.State.RecoveryEpoch != step.ExpectEpoch || journal.Frozen != step.ExpectFrozen {
					t.Fatalf("step %d %s: state seq=%d epoch=%d frozen=%v, want seq=%d key=%s epoch=%d frozen=%v", i, step.Label, journal.State.Sequence, journal.State.RecoveryEpoch, journal.Frozen, step.ExpectSequence, step.ExpectCurrentKey, step.ExpectEpoch, step.ExpectFrozen)
				}
			}
		})
	}
}
