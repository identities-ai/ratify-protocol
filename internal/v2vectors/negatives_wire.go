package v2vectors

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// wireLayerNegatives are single-fault vectors whose fault survives a full
// re-signing: every digest, key ID and signature the fault does not target
// is recomputed, so a decoder or verifier that is lenient about the targeted
// rule accepts the vector instead of rejecting it for an unrelated reason.
func (g *gen) wireLayerNegatives(n *negBuilder) {
	g.cofactorlessKeyNegatives(n)
	g.mldsaContextNegatives(n)
	g.keyOrderNegatives(n)
	g.escapeSpellingNegatives(n)
	g.resignedLengthNegatives(n)
}

// ---------------------------------------------------------------------------
// SPEC-v2 §2: the public key A must be a non-identity point of the
// prime-order subgroup. Each certificate below satisfies the cofactorless
// RFC 8032 equation [S]B = R + [k]A exactly, so a verifier that checks only
// the equation, or only canonical encoding, accepts it. The issuer ID is
// recomputed from the crafted key, and the ML-DSA-65 component is valid.

// torsionPoint is a point of order 8.
func torsionPoint() *edwards25519.Point {
	return must(new(edwards25519.Point).SetBytes(must(hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))))
}

// edChallenge is k = SHA-512(R || A || M) mod L.
func edChallenge(R, A, m []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(R)
	h.Write(A)
	h.Write(m)
	return must(new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil)))
}

// kTimesAIsIdentity reports whether [k]A is the identity, which for a point
// of order dividing 8 depends only on k mod 8.
func kTimesAIsIdentity(k *edwards25519.Scalar, T *edwards25519.Point) bool {
	return new(edwards25519.Point).ScalarMult(k, T).Equal(edwards25519.NewIdentityPoint()) == 1
}

// groundEd25519 grinds a deterministic nonce until the cofactorless equation
// holds for the public key A = [a]B + T, where T has order dividing 8 and a
// may be zero (A is then T itself). It returns R || S.
func groundEd25519(a *edwards25519.Scalar, T *edwards25519.Point, A, m []byte, label string) []byte {
	for i := 0; i < 1024; i++ {
		r := must(new(edwards25519.Scalar).SetUniformBytes(sha512Bytes([]byte(fmt.Sprintf("%s-%d-%x", label, i, m)))))
		R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
		k := edChallenge(R, A, m)
		if !kTimesAIsIdentity(k, T) {
			continue
		}
		S := new(edwards25519.Scalar).MultiplyAdd(k, a, r)
		// Check [S]B = R + [k]A with A as encoded.
		lhs := new(edwards25519.Point).ScalarBaseMult(S)
		rhs := new(edwards25519.Point).Add(must(new(edwards25519.Point).SetBytes(R)), new(edwards25519.Point).ScalarMult(k, must(new(edwards25519.Point).SetBytes(A))))
		if lhs.Equal(rhs) != 1 {
			panic("ground Ed25519 signature does not satisfy the cofactorless equation")
		}
		return append(R, S.Bytes()...)
	}
	panic("no nonce satisfied k*T = identity")
}

func (g *gen) cofactorlessKeyNegatives(n *negBuilder) {
	root, inter := g.k("root"), g.k("intermediate")
	h := sha512.Sum512(root.EdSeed[:])
	a := must(new(edwards25519.Scalar).SetBytesWithClamping(h[:32]))
	zero := edwards25519.NewScalar()
	T := torsionPoint()
	build := func(name, mutation string, edPub []byte, secret *edwards25519.Scalar, torsion *edwards25519.Point) {
		issuer := ratify.HybridPublicKey{Ed25519: edPub, MLDSA65: root.Pub.MLDSA65}
		o := map[string]any{
			"cert_id": "cert-ed25519-" + name, "version": num(2), "issuer_id": keyIDV2(issuer), "issuer_pub_key": pubJSON(issuer),
			"subject_id": inter.ID, "subject_pub_key": pubJSON(inter.Pub), "scope": []any{"data:read"},
			"constraints": []any{}, "issued_at": num(Now - 3600), "expires_at": num(Now + 86400), "signature": sigJSON(placeholderSig()),
		}
		msg := message(codeDelegation, without(canon(o), "signature"))
		ml := make([]byte, mldsa65.SignatureSize)
		must0(mldsa65.SignTo(root.Priv.MLDSA65, msg, mldsaContext(codeDelegation), false, ml))
		o["signature"] = sigJSON(ratify.HybridSignature{Ed25519: groundEd25519(secret, torsion, edPub, msg, name), MLDSA65: ml})
		n.add("ed25519_"+name, "delegation_certificate", mutation, canon(o), verifyContext{}, "invalid_signature")
	}
	identity := edwards25519.NewIdentityPoint()
	build("identity_public_key_cofactorless_valid", "A is the identity point; issuer_id recomputed; S = r and R = [r]B, so [S]B = R + [k]A holds", identity.Bytes(), zero, identity)
	build("small_order_public_key_cofactorless_valid", "A is a point of order 8; issuer_id recomputed; the nonce is ground until [k]A is the identity, so [S]B = R + [k]A holds", T.Bytes(), zero, T)
	mixed := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(a), T).Bytes()
	build("mixed_order_public_key_cofactorless_valid", "A' = A + an order-8 point; issuer_id recomputed; the nonce is ground until [k]T is the identity, so [S]B = R + [k]A' holds", mixed, a, T)
}

// ---------------------------------------------------------------------------
// SPEC-v2 §3: the ML-DSA-65 component signs M under the context of the
// object's own code. Each certificate has a valid Ed25519 component.

func (g *gen) mldsaContextNegatives(n *negBuilder) {
	root, inter := g.k("root"), g.k("intermediate")
	_, wire, sg := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	build := func(name, mutation string, m, ctx []byte) {
		ml := make([]byte, mldsa65.SignatureSize)
		must0(mldsa65.SignTo(root.Priv.MLDSA65, m, ctx, false, ml))
		sig := ratify.HybridSignature{Ed25519: ed25519Sign(root, message(codeDelegation, sg.signable)), MLDSA65: ml}
		n.add(name, "delegation_certificate", mutation, mutate(wire, func(o map[string]any) { o["signature"] = sigJSON(sig) }), verifyContext{}, "invalid_signature")
	}
	m := message(codeDelegation, sg.signable)
	build("mldsa_context_of_revocation_list", "ML-DSA-65 over M under the context ratify-protocol/2/0003; Ed25519 valid", m, mldsaContext(codeList))
	build("mldsa_empty_context", "ML-DSA-65 over M under the empty context; Ed25519 valid", m, nil)
	build("mldsa_message_of_revocation_list", "ML-DSA-65 under the certificate context over M built for code 0x0003; Ed25519 valid", message(codeList, sg.signable), mldsaContext(codeDelegation))
}

// ---------------------------------------------------------------------------
// RatifyCanonicalJSON sorts member names by UTF-8 bytes (Annex A §A.3). The
// names below sort differently by UTF-16 code units (the default string
// order of JavaScript): U+FFFF precedes U+10000 in UTF-8 but follows it in
// UTF-16, where U+10000 is the surrogate pair D800 DC00.

const (
	keyBMPLast = "\uffff"
	keyAstral  = "\U00010000"
)

func (g *gen) keyOrderNegatives(n *negBuilder) {
	root, inter := g.k("root"), g.k("intermediate")
	utf8Order := `{"` + keyBMPLast + `":0,"` + keyAstral + `":1}`
	utf16Order := `{"` + keyAstral + `":1,"` + keyBMPLast + `":0}`
	if string(canon(parse([]byte(utf16Order)))) != utf8Order {
		panic("key order trap: the UTF-8 order is not the canonical order")
	}

	// A semantic kind: the certificate is signed over a signable whose
	// params member names are in UTF-16 order. The wire is sent in either
	// order; a verifier that re-encodes canonically checks the signature
	// over the UTF-8 order and rejects it.
	o := map[string]any{
		"cert_id": "cert-params-key-order", "version": num(2), "issuer_id": root.ID, "issuer_pub_key": pubJSON(root.Pub),
		"subject_id": inter.ID, "subject_pub_key": pubJSON(inter.Pub), "scope": []any{"data:read"},
		"constraints": []any{map[string]any{"type": "geo_circle", "params": parse([]byte(utf8Order))}},
		"issued_at":   num(Now - 3600), "expires_at": num(Now + 86400), "signature": sigJSON(placeholderSig()),
	}
	canonicalSignable := without(canon(o), "signature")
	if bytes.Count(canonicalSignable, []byte(utf8Order)) != 1 {
		panic("key order trap: params not found once in the signable")
	}
	utf16Signable := bytes.Replace(canonicalSignable, []byte(utf8Order), []byte(utf16Order), 1)
	o["signature"] = sigJSON(signDet(root, codeDelegation, utf16Signable))
	wire := canon(o)
	reordered := bytes.Replace(wire, []byte(utf8Order), []byte(utf16Order), 1)
	// Control: the same certificate signed over the canonical signable
	// verifies from either spelling, so the signed order is the only fault.
	control := map[string]any{}
	for k, v := range o {
		control[k] = v
	}
	control["signature"] = sigJSON(signDet(root, codeDelegation, canonicalSignable))
	for _, w := range [][]byte{canon(control), bytes.Replace(canon(control), []byte(utf8Order), []byte(utf16Order), 1)} {
		if err := ratify.VerifyDelegationCertV2Signature(must(ratify.DecodeDelegationCertV2(w))); err != nil {
			panic("key order trap control does not verify: " + err.Error())
		}
	}
	kind := "delegation_certificate"
	n.add("params_signed_in_utf16_key_order", kind, "constraint params members U+FFFF and U+10000 signed in UTF-16 order; wire in UTF-8 (canonical) order", wire, verifyContext{}, "invalid_signature")
	n.add("params_signed_in_utf16_key_order_wire_utf16", kind, "constraint params members U+FFFF and U+10000 signed in UTF-16 order; wire also in UTF-16 order", reordered, verifyContext{}, "invalid_signature")

	// A canonical-only value: terms_canonical_json carries exact canonical
	// bytes. Terms in UTF-16 order are bound into every party's session
	// context and signed, so the order is the only fault.
	terms := func(members string) string { return `{"item":"widget","params":` + members + `}` }
	ok := g.txFixtureWith("tx-0001", terms(utf8Order), "buyer")
	if _, err := ratify.DecodeTransactionReceiptV2(ok.wire); err != nil {
		panic("key order trap: canonical terms do not decode: " + err.Error())
	}
	bad := g.txFixtureWith("tx-0001", terms(utf16Order), "buyer")
	n.add("terms_utf16_key_order", "transaction_receipt", "terms_canonical_json with members U+FFFF and U+10000 in UTF-16 order; transaction context, party bundles and party signatures computed over those bytes", bad.wire, verifyContext{}, "malformed")
}

// ---------------------------------------------------------------------------
// Canonical-only decoders (SPEC-v2 §2.1) accept only the minimal escaping of
// Annex A §A.3: the short escapes \b \f \n \r \t, lowercase \u00XX for other
// controls, \u2028 and \u2029 escaped, and every other character literal.
// Each vector signs the value and sends one alternative spelling of it.

func (g *gen) escapeSpellingNegatives(n *negBuilder) {
	type spelling struct{ name, value, canonical, alternative, mutation string }
	spellings := []spelling{
		{"backspace_as_u0008", "\b", `\b`, `\u0008`, `U+0008 spelled \u0008 instead of \b`},
		{"control_uppercase_hex", "\x1f", `\u001f`, `\u001F`, `U+001F spelled \u001F instead of \u001f`},
		{"e_acute_escaped", "\u00e9", "\u00e9", `\u00e9`, `U+00E9 spelled \u00e9 instead of literally`},
		{"astral_surrogate_pair", "\U0001f600", "\U0001f600", `\ud83d\ude00`, `U+1F600 spelled as the surrogate pair \ud83d\ude00 instead of literally`},
		{"line_separator_literal", "\u2028", `\u2028`, "\u2028", `U+2028 sent literally instead of \u2028`},
	}
	respell := func(wire []byte, s spelling, field string) []byte {
		if bytes.Count(wire, []byte(s.canonical)) != 1 {
			panic(fmt.Sprintf("%s: canonical spelling of %s does not occur once", s.name, field))
		}
		out := bytes.Replace(wire, []byte(s.canonical), []byte(s.alternative), 1)
		if bytes.Equal(out, wire) {
			panic(s.name + ": spelling unchanged")
		}
		return out
	}

	// Transaction receipt: parties[0].role is covered by the party
	// signatures only; transaction_id also enters every session context.
	for _, s := range spellings {
		f := g.txFixtureWith("tx-0001", txTerms, "buyer"+s.value)
		if _, err := ratify.DecodeTransactionReceiptV2(f.wire); err != nil {
			panic("escape control does not decode: " + err.Error())
		}
		n.add("role_"+s.name, "transaction_receipt", "parties[0].role ends in "+s.mutation+"; signed over the value", respell(f.wire, s, "role"), verifyContext{}, "malformed")
	}
	for _, s := range spellings {
		if s.name != "line_separator_literal" && s.name != "e_acute_escaped" {
			continue
		}
		f := g.txFixtureWith("tx-0001"+s.value, txTerms, "buyer")
		if _, err := ratify.DecodeTransactionReceiptV2(f.wire); err != nil {
			panic("escape control does not decode: " + err.Error())
		}
		n.add("transaction_id_"+s.name, "transaction_receipt", "transaction_id ends in "+s.mutation+"; transaction context, party bundles and party signatures computed over the value", respell(f.wire, s, "transaction_id"), verifyContext{}, "malformed")
	}

	// Verification receipt: human_id is signed metadata.
	verifier := g.k("verifier")
	for _, s := range spellings {
		body := g.receiptFixtureBody()
		body.HumanID = "user" + s.value
		_, wire, _ := g.receipt(verifier, body, receiptLogA, 1, make([]byte, 48), 0)
		if _, err := ratify.DecodeVerificationReceiptV2(wire); err != nil {
			panic("escape control does not decode: " + err.Error())
		}
		n.add("human_id_"+s.name, "verification_receipt", "human_id ends in "+s.mutation+"; signed over the value", respell(wire, s, "human_id"),
			verifyContext{VerifierKey: "verifier", Head: genesisHead(receiptLogA, verifier.ID)}, "malformed")
	}
}

// ---------------------------------------------------------------------------
// Fixed-width byte fields (SPEC-v2 §4) at a wrong decoded length, with every
// dependent key ID, digest and signature recomputed over the wrong length,
// so only the length is at fault.

func rawKeyIDV2(ed, ml []byte) string {
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2\x00"))
	h.Write(ed)
	h.Write(ml)
	return hex.EncodeToString(h.Sum(nil))
}

func (g *gen) resignedLengthNegatives(n *negBuilder) {
	root, inter, agent := g.k("root"), g.k("intermediate"), g.k("agent")
	_, certWire, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	key := func(name, component string, size int) {
		o := parse(certWire).(map[string]any)
		pub := obj(o["issuer_pub_key"])
		ed, ml := root.Pub.Ed25519, root.Pub.MLDSA65
		resize := func(b []byte) []byte {
			if size < len(b) {
				return bytes.Clone(b[:size])
			}
			return append(bytes.Clone(b), make([]byte, size-len(b))...)
		}
		if component == "ed25519" {
			ed = resize(ed)
		} else {
			ml = resize(ml)
		}
		pub["ed25519"], pub["ml_dsa_65"] = b64(ed), b64(ml)
		o["issuer_id"] = rawKeyIDV2(ed, ml)
		n.add(name, "delegation_certificate", fmt.Sprintf("issuer_pub_key.%s is %d bytes; issuer_id recomputed over it; re-signed", component, size),
			resignObject(o, "signature", root, codeDelegation), verifyContext{}, "malformed")
	}
	key("issuer_ed25519_31_bytes_resigned", "ed25519", 31)
	key("issuer_ed25519_33_bytes_resigned", "ed25519", 33)
	key("issuer_mldsa_1951_bytes_resigned", "ml_dsa_65", mldsa65.PublicKeySize-1)
	key("issuer_mldsa_1953_bytes_resigned", "ml_dsa_65", mldsa65.PublicKeySize+1)

	_, bundleWire, _ := g.bundle(bundleSpec{agent: agent, certs: g.chain(chainSpec{}), session: g.fixtureSessionContext(agent)})
	bundle := func(name, mutation string, f func(map[string]any), keepDigest bool) {
		o := parse(bundleWire).(map[string]any)
		var wire []byte
		if keepDigest {
			// The digest is the field at fault: sign over it as it is.
			f(o)
			o["challenge_sig"] = sigJSON(placeholderSig())
			o["challenge_sig"] = sigJSON(signDet(agent, codePresentation, without(canon(o), "delegations", "challenge_sig")))
			wire = canon(o)
		} else {
			f(o)
			wire = g.resign(o, agent)
		}
		n.add(name, "proof_bundle", mutation, wire, verifyContext{}, "malformed")
	}
	sizedB64 := func(v any, size int) string {
		raw := must(b64d(v.(string)))
		if size < len(raw) {
			return b64(raw[:size])
		}
		return b64(append(raw, make([]byte, size-len(raw))...))
	}
	bundle("session_context_31_bytes_resigned", "session_context decodes to 31 bytes; challenge signature recomputed", func(o map[string]any) { o["session_context"] = sizedB64(o["session_context"], 31) }, false)
	bundle("session_context_33_bytes_resigned", "session_context decodes to 33 bytes; challenge signature recomputed", func(o map[string]any) { o["session_context"] = sizedB64(o["session_context"], 33) }, false)
	bundle("delegation_digest_47_bytes_resigned", "delegation_digest decodes to 47 bytes; challenge signature recomputed over it", func(o map[string]any) { o["delegation_digest"] = sizedB64(o["delegation_digest"], 47) }, true)
	bundle("delegation_digest_49_bytes_resigned", "delegation_digest decodes to 49 bytes; challenge signature recomputed over it", func(o map[string]any) { o["delegation_digest"] = sizedB64(o["delegation_digest"], 49) }, true)

	witness := g.k("witness")
	_, witnessWire, _ := g.witness(witness, witnessLogA, 2, bytes.Repeat([]byte{0x11}, 48), "entry-2", Now-20, "", 0)
	for _, size := range []int{47, 49} {
		o := parse(witnessWire).(map[string]any)
		o["prev_hash"] = b64(bytes.Repeat([]byte{0x11}, size))
		n.add(fmt.Sprintf("prev_hash_%d_bytes_resigned", size), "witness_entry", fmt.Sprintf("sequence 2 with a %d-byte prev_hash; re-signed", size),
			resignObject(o, "signature", witness, codeWitness), verifyContext{WitnessKey: "witness", Head: genesisHead(witnessLogA, "")}, "malformed")
	}
}
