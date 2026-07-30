package ratify

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

type testEntity struct {
	id   string
	pub  HybridPublicKey
	priv HybridPrivateKey
}

func testKeypair(t *testing.T, _ byte) testEntity {
	t.Helper()
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return testEntity{id: DeriveID(pub), pub: pub, priv: priv}
}

func signHybridForTest(data []byte, priv HybridPrivateKey) (HybridSignature, error) {
	return signBoth(data, priv)
}

func TestNormalizeResourcePath(t *testing.T) {
	valid := map[string]string{
		"/":                  "/",
		"/docs":              "/docs",
		"/docs/":             "/docs",
		"/docs/setup/g.md":   "/docs/setup/g.md",
		"/docs/%2e%2e/notes": "/docs/%2e%2e/notes", // % is a literal byte
		"/a b/c":             "/a b/c",
		"/UPPER/Case":        "/UPPER/Case", // byte-exact; no case folding
	}
	for in, want := range valid {
		got, err := NormalizeResourcePath(in)
		if err != nil {
			t.Errorf("NormalizeResourcePath(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeResourcePath(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"",             // empty
		"docs",         // no leading slash
		"docs/",        // no leading slash
		"/docs/../x",   // dot-segment
		"/./x",         // dot-segment
		"/..",          // dot-segment
		"/a//b",        // empty interior segment
		"/docs//",      // empty segment after one-trailing-slash trim
		"//",           // empty segment
		"/a\\b",        // backslash
		"\\docs",       // backslash, no leading slash
		"/a\x00b",      // NUL
		"/docs/./g.md", // dot-segment mid-path
	}
	for _, in := range invalid {
		if _, err := NormalizeResourcePath(in); err == nil {
			t.Errorf("NormalizeResourcePath(%q): expected error, got nil", in)
		}
	}
}

func TestResourcePathMatches(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"/docs", "/docs", true},
		{"/docs", "/docs/a.md", true},
		{"/docs/", "/docs", true},   // trailing slash trims
		{"/docs", "/docs/", true},   // both directions
		{"/", "/anything", true},    // root matches everything
		{"/", "/", true},            // root matches root
		{"/docs", "/docs-old", false},  // segment boundary, not string prefix
		{"/docs", "/docsx/a", false},   // segment boundary
		{"/docs", "/doc", false},       // shorter
		{"/docs", "/", false},          // parent of prefix
		{"/src/security", "/src", false}, // narrower prefix does not match wider path
		{"/docs", "/docs/../x", false},   // invalid path never matches
		{"/docs/../x", "/docs", false},   // invalid prefix never matches
	}
	for _, c := range cases {
		if got := ResourcePathMatches(c.prefix, c.path); got != c.want {
			t.Errorf("ResourcePathMatches(%q, %q) = %v, want %v", c.prefix, c.path, got, c.want)
		}
	}
}

func TestValidateResourceConstraints(t *testing.T) {
	rp := func(id, prefix string) Constraint {
		return Constraint{Type: ConstraintResourcePath, ResourceID: id, PathPrefix: prefix}
	}

	ok := [][]Constraint{
		{},
		{rp("git:github.com/acme/widgets", "/docs")},
		{rp("git:github.com/acme/widgets", "")}, // whole resource
		{rp("git:github.com/acme/widgets", "/src"), rp("git:github.com/acme/widgets", "/src/security")}, // nested
		{rp("git:github.com/acme/widgets", ""), rp("git:github.com/acme/widgets", "/docs")},             // absent orders as /
		{{Type: ConstraintGeoCircle, Lat: 1, Lon: 1, RadiusM: 5}},                                       // non-resource untouched
	}
	for i, cs := range ok {
		if err := ValidateResourceConstraints(cs); err != nil {
			t.Errorf("case %d: unexpected issuance rejection: %v", i, err)
		}
	}

	bad := [][]Constraint{
		{rp("", "/docs")}, // empty resource_id
		{rp(strings.Repeat("x", MaxIdentifierLengthBytes+1), "")},                                    // oversized id
		{rp("git:github.com/acme/widgets", "docs")},                                                  // invalid prefix
		{rp("git:github.com/acme/widgets", "/docs"), rp("git:github.com/acme/other", "/docs")},       // different resources
		{rp("git:github.com/acme/widgets", "/src"), rp("git:github.com/acme/widgets", "/docs")},      // incomparable prefixes
	}
	for i, cs := range bad {
		if err := ValidateResourceConstraints(cs); err == nil {
			t.Errorf("bad case %d: expected issuance rejection, got nil", i)
		}
	}
}

func TestValidateParamsValue(t *testing.T) {
	ok := []any{
		nil, true, "s", int64(5), float64(42), // integral float64 = wire integer
		float64(-9007199254740991),
		[]any{int64(1), "two", nil},
		map[string]any{"a": int64(1), "b": []any{true}},
	}
	for i, v := range ok {
		if err := ValidateParamsValue(v, 0); err != nil {
			t.Errorf("ok case %d (%v): unexpected error %v", i, v, err)
		}
	}

	bad := []any{
		float64(1.5),                  // non-integer number
		float64(9007199254740993),     // beyond safe range
		int64(9007199254740992),       // beyond safe range
		uint64(1) << 60,               // beyond safe range
		[]byte{1},                     // raw bytes
		map[string]any{"a": 1.25},     // nested float
		[]any{[]any{[]any{1.5}}},      // nested float in arrays
	}
	for i, v := range bad {
		if err := ValidateParamsValue(v, 0); err == nil {
			t.Errorf("bad case %d (%v): expected error, got nil", i, v)
		}
	}

	// Nesting bound: a chain of arrays deeper than MaxJSONNestingDepth.
	deep := any("leaf")
	for i := 0; i < MaxJSONNestingDepth+1; i++ {
		deep = []any{deep}
	}
	if err := ValidateParamsValue(deep, 0); err == nil {
		t.Errorf("expected nesting-depth rejection")
	}
}

func TestIssueDelegationRejectsUnsatisfiableAndParamsOnCanonical(t *testing.T) {
	root, agent := testKeypair(t, 0x51), testKeypair(t, 0x52)

	base := DelegationCert{
		CertID: "t-issue-1", Version: ProtocolVersion,
		IssuerID: root.id, IssuerPubKey: root.pub,
		SubjectID: agent.id, SubjectPubKey: agent.pub,
		Scope: []string{ScopeFilesWrite}, IssuedAt: 1000, ExpiresAt: 2000,
	}

	cert := base
	cert.Constraints = []Constraint{
		{Type: ConstraintResourcePath, ResourceID: "r1", PathPrefix: "/docs"},
		{Type: ConstraintResourcePath, ResourceID: "r2", PathPrefix: "/docs"},
	}
	if err := IssueDelegation(&cert, root.priv); err == nil {
		t.Fatal("expected rejection of different-resource constraint pair")
	}
	// The same shape signed without issuance hygiene (as a non-conforming
	// external issuer would) must still be signable and must fail closed
	// at verification — covered by the unsatisfiable-pair fixture; here we
	// confirm the internal signer accepts it.
	data, err := delegationSignBytes(&cert)
	if err != nil {
		t.Fatalf("sign bytes for unsatisfiable cert: %v", err)
	}
	if _, err := signBoth(data, root.priv); err != nil {
		t.Fatalf("signing externally shaped cert: %v", err)
	}

	cert2 := base
	cert2.Constraints = []Constraint{{Type: ConstraintGeoCircle, Lat: 1, Lon: 1, RadiusM: 5, Params: map[string]any{"x": int64(1)}}}
	if err := IssueDelegation(&cert2, root.priv); err == nil {
		t.Fatal("expected rejection of params on a canonical constraint type")
	}

	cert3 := base
	cert3.Constraints = []Constraint{{Type: "com.example.limit", Params: map[string]any{"max": 1.5}}}
	if err := IssueDelegation(&cert3, root.priv); err == nil {
		t.Fatal("expected rejection of a float params value")
	}
}

func TestDecodeProofBundleLimits(t *testing.T) {
	// Oversized payload is rejected before parsing: even garbage bytes of
	// the right size never reach the JSON parser, and the error names the
	// bundle limit.
	oversized := bytes.Repeat([]byte("x"), MaxProofBundleBytes+1)
	if _, err := DecodeProofBundle(oversized); err == nil || !strings.Contains(err.Error(), "MAX_PROOF_BUNDLE_BYTES") {
		t.Fatalf("expected pre-parse size rejection, got %v", err)
	}

	// Nesting beyond MaxJSONNestingDepth is rejected during parse.
	deep := strings.Repeat("[", MaxJSONNestingDepth+1) + strings.Repeat("]", MaxJSONNestingDepth+1)
	if err := CheckWireJSON([]byte(deep)); err == nil || !strings.Contains(err.Error(), "MAX_JSON_NESTING_DEPTH") {
		t.Fatalf("expected nesting-depth rejection, got %v", err)
	}
}

func TestVerificationReceiptCodecRoundTrip(t *testing.T) {
	verifier := testKeypair(t, 0x53)

	r := &VerificationReceipt{
		Version:     ProtocolVersion,
		VerifierID:  verifier.id,
		VerifierPub: verifier.pub,
		BundleHash:  bytes.Repeat([]byte{0xAB}, 32),
		Decision:    "revoked",
		AgentID:     "b4a4c71795d676b69f454881a8300000",
		ErrorReason: "delegation certificate has been revoked",
		VerifiedAt:  1800000000,
		PrevHash:    make([]byte, 32),
	}
	signBytes, err := VerificationReceiptSignBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signHybridForTest(signBytes, verifier.priv)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = sig

	encoded, err := EncodeVerificationReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeVerificationReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reEncoded, err := EncodeVerificationReceipt(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatal("receipt round-trip is not byte-identical")
	}
}

func TestVerificationReceiptEncoderRejectsInvalid(t *testing.T) {
	verifier := testKeypair(t, 0x54)
	valid := func() *VerificationReceipt {
		return &VerificationReceipt{
			Version: ProtocolVersion, VerifierID: verifier.id, VerifierPub: verifier.pub,
			BundleHash: bytes.Repeat([]byte{1}, 32), Decision: "authorized_agent",
			VerifiedAt: 1800000000, PrevHash: make([]byte, 32),
			Signature: HybridSignature{Ed25519: make([]byte, 64), MLDSA65: make([]byte, 3309)},
		}
	}

	if _, err := EncodeVerificationReceipt(nil); err == nil {
		t.Fatal("expected rejection of a nil receipt")
	}
	mutations := []struct {
		name   string
		mutate func(*VerificationReceipt)
	}{
		{"short bundle_hash", func(r *VerificationReceipt) { r.BundleHash = r.BundleHash[:16] }},
		{"short prev_hash", func(r *VerificationReceipt) { r.PrevHash = r.PrevHash[:31] }},
		{"unknown decision", func(r *VerificationReceipt) { r.Decision = "approved" }},
		{"empty verifier_id", func(r *VerificationReceipt) { r.VerifierID = "" }},
		{"wrong version", func(r *VerificationReceipt) { r.Version = 2 }},
		{"short ed25519 sig", func(r *VerificationReceipt) { r.Signature.Ed25519 = r.Signature.Ed25519[:63] }},
		{"short ml_dsa_65 sig", func(r *VerificationReceipt) { r.Signature.MLDSA65 = r.Signature.MLDSA65[:100] }},
		{"short verifier pub", func(r *VerificationReceipt) { r.VerifierPub.MLDSA65 = r.VerifierPub.MLDSA65[:100] }},
	}
	for _, m := range mutations {
		r := valid()
		m.mutate(r)
		if _, err := EncodeVerificationReceipt(r); err == nil {
			t.Errorf("%s: encoder emitted a document its decoder rejects", m.name)
		}
	}
}

func TestVerificationReceiptDecoderRejectsMalformedWire(t *testing.T) {
	verifier := testKeypair(t, 0x55)
	r := &VerificationReceipt{
		Version: ProtocolVersion, VerifierID: verifier.id, VerifierPub: verifier.pub,
		BundleHash: bytes.Repeat([]byte{2}, 32), Decision: "authorized_agent",
		VerifiedAt: 1800000000, PrevHash: make([]byte, 32),
		Signature: HybridSignature{Ed25519: make([]byte, 64), MLDSA65: make([]byte, 3309)},
	}
	encoded, err := EncodeVerificationReceipt(r)
	if err != nil {
		t.Fatal(err)
	}

	// Malformed wire is constructed by mutating valid encoded JSON — never
	// by asking the encoder to produce an invalid document.
	mutate := func(old, new string) []byte {
		out := strings.Replace(string(encoded), old, new, 1)
		if out == string(encoded) {
			t.Fatalf("mutation %q not applied", old)
		}
		return []byte(out)
	}
	cases := map[string][]byte{
		"unknown field":     mutate(`"version":`, `"versionx":1,"version":`),
		"wrong version":     mutate(`"version":1`, `"version":2`),
		"unknown decision":  mutate(`"decision":"authorized_agent"`, `"decision":"approved"`),
		"null verifier_id":  mutate(`"verifier_id":"`+verifier.id+`"`, `"verifier_id":""`),
		"truncated hash":    mutate(`"bundle_hash":"`+b64of(t, r.BundleHash)+`"`, `"bundle_hash":"`+b64of(t, r.BundleHash[:16])+`"`),
		"non-object":        []byte(`[1,2,3]`),
	}
	for name, doc := range cases {
		if _, err := DecodeVerificationReceipt(doc); err == nil {
			t.Errorf("%s: expected decoder rejection", name)
		}
	}
}

func TestGenerateAgentKeypairNameBound(t *testing.T) {
	if _, _, err := GenerateAgentKeypair(strings.Repeat("n", MaxAgentNameLengthBytes), "custom"); err != nil {
		t.Fatalf("name of exactly %d bytes must be accepted: %v", MaxAgentNameLengthBytes, err)
	}
	if _, _, err := GenerateAgentKeypair(strings.Repeat("n", MaxAgentNameLengthBytes+1), "custom"); err == nil {
		t.Fatalf("name of %d bytes must be rejected", MaxAgentNameLengthBytes+1)
	}
}

// TestConstraintPathPrefixPresence proves that a present-but-forbidden
// path_prefix (empty string, null, non-string) is rejected at decode
// through both DecodeDelegationCert and DecodeProofBundle — it can never
// silently widen into whole-resource authority. Absence remains the sole
// encoding of "entire resource".
func TestConstraintPathPrefixPresence(t *testing.T) {
	root, agent := testKeypair(t, 0x56), testKeypair(t, 0x57)
	cert := DelegationCert{
		CertID: "t-presence-1", Version: ProtocolVersion,
		IssuerID: root.id, IssuerPubKey: root.pub,
		SubjectID: agent.id, SubjectPubKey: agent.pub,
		Scope: []string{ScopeFilesWrite},
		Constraints: []Constraint{{
			Type: ConstraintResourcePath, ResourceID: "git:github.com/acme/widgets", PathPrefix: "/docs",
		}},
		IssuedAt: 1000, ExpiresAt: 4070908799,
	}
	if err := IssueDelegation(&cert, root.priv); err != nil {
		t.Fatal(err)
	}
	certJSON, err := EncodeDelegationCert(&cert)
	if err != nil {
		t.Fatal(err)
	}
	// Valid form decodes.
	if _, err := DecodeDelegationCert(certJSON); err != nil {
		t.Fatalf("valid cert must decode: %v", err)
	}

	forbidden := map[string]string{
		"empty string": `"path_prefix":""`,
		"null":         `"path_prefix":null`,
		"non-string":   `"path_prefix":42`,
	}
	for name, replacement := range forbidden {
		doc := strings.Replace(string(certJSON), `"path_prefix":"/docs"`, replacement, 1)
		if doc == string(certJSON) {
			t.Fatalf("%s: mutation not applied", name)
		}
		if _, err := DecodeDelegationCert([]byte(doc)); err == nil {
			t.Errorf("%s: DecodeDelegationCert accepted a forbidden path_prefix — this would widen a malformed restriction into whole-resource authority", name)
		}
	}

	// The same forbidden forms inside a full bundle must be rejected by
	// DecodeProofBundle.
	challenge := bytes.Repeat([]byte{7}, 32)
	sig, err := SignChallenge(challenge, 2000, agent.priv)
	if err != nil {
		t.Fatal(err)
	}
	bundle := ProofBundle{
		AgentID: agent.id, AgentPubKey: agent.pub,
		Delegations: []DelegationCert{cert},
		Challenge:   challenge, ChallengeAt: 2000, ChallengeSig: sig,
	}
	bundleJSON, err := EncodeProofBundle(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProofBundle(bundleJSON); err != nil {
		t.Fatalf("valid bundle must decode: %v", err)
	}
	for name, replacement := range forbidden {
		doc := strings.Replace(string(bundleJSON), `"path_prefix":"/docs"`, replacement, 1)
		if doc == string(bundleJSON) {
			t.Fatalf("%s: mutation not applied", name)
		}
		if _, err := DecodeProofBundle([]byte(doc)); err == nil {
			t.Errorf("%s: DecodeProofBundle accepted a forbidden path_prefix", name)
		}
	}
}

func b64of(t *testing.T, b []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(b)
}
