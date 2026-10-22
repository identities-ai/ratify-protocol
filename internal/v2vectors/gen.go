// Package v2vectors deterministically generates the shared Protocol v2
// conformance corpus under testvectors/v2. Every private seed is public test
// data and must never be used as a production key.
//
// Expected results are written from SPEC-v2 rules in this package, not read
// back from the verifier under test. The Go conformance test then checks that
// the reference implementation agrees with every vector.
package v2vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Now is the fixed evaluation time used by every vector.
const Now int64 = 1800000000

// domainEndNow is 9999-12-31T23:59:00Z, the start of the last minute of the
// v2 timestamp domain, used only by the timestamp-domain boundary vectors.
const domainEndNow int64 = 253402300740

// Files lists every file this generator owns, relative to testvectors/v2.
var Files = []string{
	"key-rotation-signature.json",
	"keys.json",
	"objects.json",
	"object-negatives.json",
	"verifier-ordering.json",
	"status-sequences.json",
	"log-sequences.json",
	"rotation-sequences.json",
	"limits.json",
	"security-journal.json",
	"lifecycle-scenarios.json",
	"transaction-verification.json",
	"annex-a.json",
	"issuer-duties.json",
	"challenge-issuance.json",
	"status-publisher.json",
	"evaluator-profiles.json",
	deviceStateFile,
	archivalFile,
	externalSignerFile,
	digestFunctionsFile,
}

// Generate returns the exact bytes of every generated vector file.
func Generate() (map[string][]byte, error) {
	g := newGen()
	out := map[string][]byte{}
	builders := map[string]func() any{
		"key-rotation-signature.json":   g.legacyRotationVector,
		"keys.json":                     g.keysFile,
		"objects.json":                  g.objectsFile,
		"object-negatives.json":         g.objectNegativesFile,
		"verifier-ordering.json":        g.orderingFile,
		"status-sequences.json":         g.statusFile,
		"log-sequences.json":            g.logFile,
		"rotation-sequences.json":       g.rotationFile,
		"limits.json":                   g.limitsFile,
		"security-journal.json":         g.journalFile,
		"lifecycle-scenarios.json":      g.lifecycleFile,
		"transaction-verification.json": g.txVerifyFile,
		"annex-a.json":                  g.annexFile,
		"issuer-duties.json":            g.issuerDutiesFile,
		"challenge-issuance.json":       g.challengeIssuanceFile,
		"status-publisher.json":         g.statusPublisherFile,
		"evaluator-profiles.json":       g.evaluatorProfilesFile,
		deviceStateFile:                 g.deviceStateFile,
		archivalFile:                    g.archivalFile,
		externalSignerFile:              g.externalSignerFile,
		digestFunctionsFile:             g.digestFunctionsFile,
	}
	for _, name := range Files {
		var value any
		if err := catch(func() { value = builders[name]() }); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = append(encoded, '\n')
	}
	return out, nil
}

func catch(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	f()
	return nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// ---------------------------------------------------------------------------
// Keys

// Key is a deterministic fixture key.
type Key struct {
	Name   string
	Pub    ratify.HybridPublicKey
	Priv   ratify.HybridPrivateKey
	ID     string
	EdSeed [32]byte
	MLSeed [32]byte
	// Hedged keys sign ML-DSA-65 with fresh FIPS 204 randomness. Only the
	// cross-SDK fixture generator sets it; the deterministic corpus never does.
	Hedged bool
}

type gen struct {
	keys  map[string]*Key
	order []string
}

// Fixture key names and seed bytes. Each seed is 32 repetitions of one byte.
var keySeeds = []struct {
	name   string
	ed, ml byte
}{
	{"root", 0x41, 0xc1},
	{"intermediate", 0x42, 0xc2},
	{"agent", 0x43, 0xc3},
	{"verifier", 0x44, 0xc4},
	{"status_root", 0x45, 0xc5},
	{"status_intermediate", 0x46, 0xc6},
	{"witness", 0x47, 0xc7},
	{"party_b_agent", 0x48, 0xc8},
	{"attacker", 0x49, 0xc9},
	{"untrusted_root", 0x4a, 0xca},
	{"intermediate_2", 0x4b, 0xcb},
	{"rotation_genesis", 0x4c, 0xcc},
	{"rotation_second", 0x4d, 0xcd},
	{"rotation_third", 0x4e, 0xce},
	{"rotation_recovery", 0x4f, 0xcf},
	{"party_b_root", 0x50, 0xd0},
	{"status_party_b", 0x51, 0xd1},
	{"status_root_epoch_2", 0x52, 0xd2},
}

func newGen() *gen {
	g := &gen{keys: map[string]*Key{}}
	for _, s := range keySeeds {
		g.addKey(s.name, s.ed, s.ml)
	}
	return g
}

func (g *gen) addKey(name string, edByte, mlByte byte) {
	var edSeed, mlSeed [32]byte
	for i := range edSeed {
		edSeed[i], mlSeed[i] = edByte, mlByte
	}
	g.addSeededKey(name, edSeed, mlSeed, false)
}

func (g *gen) addSeededKey(name string, edSeed, mlSeed [32]byte, hedged bool) {
	pub, priv := must2(ratify.HybridKeypairFromSeeds(edSeed, mlSeed))
	g.keys[name] = &Key{Name: name, Pub: pub, Priv: priv, ID: keyIDV2(pub), EdSeed: edSeed, MLSeed: mlSeed, Hedged: hedged}
	g.order = append(g.order, name)
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func (g *gen) k(name string) *Key {
	key, ok := g.keys[name]
	if !ok {
		panic("unknown fixture key " + name)
	}
	return key
}

// keyIDV2 is computed independently from SPEC-v2 §2.1.
func keyIDV2(pub ratify.HybridPublicKey) string {
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2"))
	h.Write([]byte{0})
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Signing transcript (SPEC-v2 §3), computed independently of the library.

func message(code uint16, signable []byte) []byte {
	d := sha512.Sum384(signable)
	m := append([]byte("ratify-protocol-signature"), 0x00, 0x02)
	m = binary.BigEndian.AppendUint16(m, code)
	return append(m, d[:]...)
}

func mldsaContext(code uint16) []byte {
	return []byte(fmt.Sprintf("ratify-protocol/2/%04x", code))
}

func externalMu(mlPub []byte, code uint16, m []byte) (tr, mu []byte) {
	tr = sha3.SumSHAKE256(mlPub, 64)
	ctx := mldsaContext(code)
	pre := append(append([]byte{}, tr...), 0x00, byte(len(ctx)))
	pre = append(append(pre, ctx...), m...)
	return tr, sha3.SumSHAKE256(pre, 64)
}

// signDet signs with deterministic Ed25519 and deterministic (non-hedged)
// ML-DSA-65 so the corpus is reproducible byte for byte. A Hedged key (cross-SDK
// fixtures only) signs ML-DSA-65 with fresh randomness instead.
func signDet(key *Key, code uint16, signable []byte) ratify.HybridSignature {
	m := message(code, signable)
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(key.Priv.MLDSA65, m, mldsaContext(code), key.Hedged, ml); err != nil {
		panic(err)
	}
	return ratify.HybridSignature{Ed25519: ed25519.Sign(key.Priv.Ed25519, m), MLDSA65: ml}
}

// ed25519WithNonce produces a valid RFC 8032 signature with a caller-chosen
// nonce, giving a second valid signature over the same message. It is used
// only to test that idempotency compares body digests, not signature bytes.
func ed25519WithNonce(key *Key, m []byte, nonceByte byte) []byte {
	h := sha512.Sum512(key.EdSeed[:])
	a := must(new(edwards25519.Scalar).SetBytesWithClamping(h[:32]))
	nonceInput := make([]byte, 64)
	for i := range nonceInput {
		nonceInput[i] = nonceByte
	}
	r := must(new(edwards25519.Scalar).SetUniformBytes(nonceInput))
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	kh := sha512.New()
	kh.Write(R)
	kh.Write(key.Pub.Ed25519)
	kh.Write(m)
	k := must(new(edwards25519.Scalar).SetUniformBytes(kh.Sum(nil)))
	S := new(edwards25519.Scalar).MultiplyAdd(k, a, r)
	return append(R, S.Bytes()...)
}

func placeholderSig() ratify.HybridSignature {
	return ratify.HybridSignature{Ed25519: make([]byte, 64), MLDSA65: make([]byte, 3309)}
}

// ---------------------------------------------------------------------------
// JSON helpers

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func canon(v any) []byte { return must(ratify.CanonicalJSON(v)) }

func parse(data []byte) any {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		panic(err)
	}
	return v
}

// without returns the canonical JSON of a wire object minus the named
// top-level fields: the signable projection rule of SPEC-v2 §5.
func without(wire []byte, fields ...string) []byte {
	obj := parse(wire).(map[string]any)
	for _, f := range fields {
		delete(obj, f)
	}
	return canon(obj)
}

// mutate applies f to a parsed copy of wire and returns canonical bytes.
func mutate(wire []byte, f func(map[string]any)) []byte {
	obj := parse(wire).(map[string]any)
	f(obj)
	return canon(obj)
}

func obj(v any) map[string]any { return v.(map[string]any) }
func arr(v any) []any          { return v.([]any) }

func num(v int64) json.Number { return json.Number(fmt.Sprint(v)) }

func addNum(v any, delta int64) json.Number {
	n := must(v.(json.Number).Int64())
	return num(n + delta)
}

// flipB64 flips the low bit of the first decoded byte of a base64 value.
func flipB64(v any) string {
	raw := must(base64.StdEncoding.DecodeString(v.(string)))
	raw[0] ^= 1
	return b64(raw)
}

func flipHexDigest(v string) string {
	prefix := ""
	if len(v) > 7 && v[:7] == "sha384:" {
		prefix, v = "sha384:", v[7:]
	}
	raw := must(hex.DecodeString(v))
	raw[0] ^= 1
	return prefix + hex.EncodeToString(raw)
}

func pubJSON(pub ratify.HybridPublicKey) map[string]any {
	return map[string]any{"ed25519": b64(pub.Ed25519), "ml_dsa_65": b64(pub.MLDSA65)}
}

func sigJSON(sig ratify.HybridSignature) map[string]any {
	return map[string]any{"ed25519": b64(sig.Ed25519), "ml_dsa_65": b64(sig.MLDSA65)}
}

func sha384Prefixed(prefix string, parts ...[]byte) []byte {
	h := sha512.New384()
	h.Write([]byte(prefix))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func statementBodyDigest(code uint16, body []byte) []byte {
	return sha384Prefixed("ratify-protocol-statement-body-v2", binary.BigEndian.AppendUint16(nil, code), body)
}

func statusEvidenceDigest(code uint16, wire []byte) string {
	return "sha384:" + hex.EncodeToString(sha384Prefixed("ratify-protocol-status-evidence-v2", binary.BigEndian.AppendUint16(nil, code), wire))
}

func bundleHash(wire []byte) string {
	return "sha384:" + hex.EncodeToString(sha384Prefixed("ratify-protocol-bundle-v2", wire))
}

func sortedStrings(values ...string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// KeyRef is the language-neutral key representation used across files.
type KeyRef struct {
	Name      string         `json:"name"`
	KeyIDV2   string         `json:"key_id_v2"`
	PublicKey map[string]any `json:"public_key"`
}

func (g *gen) ref(name string) KeyRef {
	k := g.k(name)
	return KeyRef{Name: name, KeyIDV2: k.ID, PublicKey: pubJSON(k.Pub)}
}
