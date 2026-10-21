package v2vectors

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type negativeVector struct {
	Name               string        `json:"name"`
	Kind               string        `json:"kind"`
	Mutation           string        `json:"mutation"`
	WireB64            string        `json:"wire_b64"`
	BundleB64          string        `json:"bundle_b64,omitempty"`
	Verify             verifyContext `json:"verify"`
	ExpectedErrorClass string        `json:"expected_error_class"`
}

type negativesFile struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Procedure   map[string]string `json:"procedure_by_kind"`
	Vectors     []negativeVector  `json:"vectors"`
}

type negBuilder struct {
	out []negativeVector
}

func (n *negBuilder) add(name, kind, mutation string, wire []byte, verify verifyContext, class string) {
	n.out = append(n.out, negativeVector{Name: kind + "/" + name, Kind: kind, Mutation: mutation, WireB64: b64(wire), Verify: verify, ExpectedErrorClass: class})
}

// resignField re-signs a parsed object so that a mutated field is covered by
// a fresh valid signature. Used for consistent-substitution vectors.
func resignObject(o map[string]any, sigField string, signer *Key, code uint16, exclude ...string) []byte {
	o[sigField] = sigJSON(placeholderSig())
	wire := canon(o)
	signable := without(wire, append([]string{sigField}, exclude...)...)
	o[sigField] = sigJSON(signDet(signer, code, signable))
	return canon(o)
}

func (g *gen) objectNegativesFile() any {
	n := &negBuilder{}
	g.certNegatives(n)
	g.ed25519Negatives(n)
	g.bundleNegatives(n)
	g.statusNegatives(n)
	g.rotationNegatives(n)
	g.witnessNegatives(n)
	g.transactionNegatives(n)
	g.receiptNegatives(n)
	return negativesFile{
		Version:     2,
		Description: "Single-fault negative vectors. Every vector MUST be rejected with expected_error_class. Mutations of signed fields that keep the object structurally valid MUST fail as invalid_signature; mutations that break structure, key-ID derivation, or caller-authenticated state fail with the structural class. Precedence: strict decode and field format (malformed) before key-ID derivation (key_id_mismatch) before delegation digest, duplicate CertificateRef and chain linkage before any signature check.",
		Procedure: map[string]string{
			"delegation_certificate": "strict decode; then verify the issuer signature (code 0x0001) with the certificate's issuer_pub_key",
			"proof_bundle":           "strict decode; then structural checks (key IDs, delegation_digest, duplicate CertificateRef, linkage); then every certificate signature and the challenge signature",
			"revocation_list":        "strict decode; then verify under code 0x0003 with verify.status_key bound to verify.bound_issuer_id",
			"revocation_push":        "strict decode; then verify under code 0x0005 with verify.status_key bound to verify.bound_issuer_id",
			"key_rotation_statement": "strict decode; then verify against verify.rotation_state at verify.now with verify.future_skew_seconds",
			"witness_entry":          "strict decode; then verify against verify.head with verify.witness_key",
			"transaction_receipt":    "strict decode (including party bindings, bundle hashes, bundle signatures, and transaction-derived session contexts); then every party signature (code 0x0007)",
			"verification_receipt":   "strict decode; then verify against verify.head with verify.verifier_key",
			"receipt_bundle_binding": "strict decode of wire_b64 (receipt) and bundle_b64; then compare receipt bundle_hash, verifier_id, agent_id, and issuer_ids with the bundle",
		},
		Vectors: n.out,
	}
}

// ---------------------------------------------------------------------------

func (g *gen) certNegatives(n *negBuilder) {
	root, inter, attacker := g.k("root"), g.k("intermediate"), g.k("attacker")
	_, base, sg := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	kind, v := "delegation_certificate", verifyContext{}
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(base, f), v, class)
	}
	m("version_3", "version=3", "malformed", func(o map[string]any) { o["version"] = num(3) })
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("cert_id_changed", "cert_id changed", "invalid_signature", func(o map[string]any) { o["cert_id"] = "cert-root-x" })
	m("cert_id_empty", "cert_id empty", "malformed", func(o map[string]any) { o["cert_id"] = "" })
	m("issuer_id_other_key", "issuer_id set to another key's ID", "key_id_mismatch", func(o map[string]any) { o["issuer_id"] = attacker.ID })
	m("issuer_ed25519_substituted", "issuer_pub_key.ed25519 replaced", "key_id_mismatch", func(o map[string]any) { obj(o["issuer_pub_key"])["ed25519"] = b64(attacker.Pub.Ed25519) })
	m("issuer_mldsa_substituted", "issuer_pub_key.ml_dsa_65 replaced", "key_id_mismatch", func(o map[string]any) { obj(o["issuer_pub_key"])["ml_dsa_65"] = b64(attacker.Pub.MLDSA65) })
	m("subject_id_other_key", "subject_id set to another key's ID", "key_id_mismatch", func(o map[string]any) { o["subject_id"] = attacker.ID })
	m("subject_ed25519_substituted", "subject_pub_key.ed25519 replaced", "key_id_mismatch", func(o map[string]any) { obj(o["subject_pub_key"])["ed25519"] = b64(attacker.Pub.Ed25519) })
	m("subject_mldsa_substituted", "subject_pub_key.ml_dsa_65 replaced", "key_id_mismatch", func(o map[string]any) { obj(o["subject_pub_key"])["ml_dsa_65"] = b64(attacker.Pub.MLDSA65) })
	m("issuer_key_and_id_substituted", "issuer key and ID consistently replaced (old-key substitution)", "invalid_signature", func(o map[string]any) {
		o["issuer_pub_key"], o["issuer_id"] = pubJSON(attacker.Pub), attacker.ID
	})
	m("subject_key_and_id_substituted", "subject key and ID consistently replaced", "invalid_signature", func(o map[string]any) {
		o["subject_pub_key"], o["subject_id"] = pubJSON(attacker.Pub), attacker.ID
	})
	m("issuer_id_v1_128_bit", "issuer_id replaced by the issuer's v1 128-bit ID", "malformed", func(o map[string]any) { o["issuer_id"] = ratify.DeriveID(root.Pub) })
	m("issuer_id_uppercase", "issuer_id uppercased", "malformed", func(o map[string]any) { o["issuer_id"] = strings.ToUpper(root.ID) })
	m("scope_added", "scope gains meeting:attend", "invalid_signature", func(o map[string]any) { o["scope"] = append(arr(o["scope"]), "meeting:attend") })
	m("scope_reordered", "scope order reversed", "invalid_signature", func(o map[string]any) {
		s := arr(o["scope"])
		s[0], s[len(s)-1] = s[len(s)-1], s[0]
	})
	m("scope_not_array", "scope is a string", "malformed", func(o map[string]any) { o["scope"] = "data:read" })
	m("scope_element_number", "scope element is a number", "malformed", func(o map[string]any) { o["scope"] = []any{num(1)} })
	m("constraints_added", "constraints gains max_rate", "invalid_signature", func(o map[string]any) {
		o["constraints"] = []any{map[string]any{"type": "max_rate", "count": num(1), "window_s": num(60)}}
	})
	m("constraints_null", "constraints is null", "malformed", func(o map[string]any) { o["constraints"] = nil })
	m("constraint_unknown_field", "max_rate constraint has an unknown field", "malformed", func(o map[string]any) {
		o["constraints"] = []any{map[string]any{"type": "max_rate", "count": num(1), "window_s": num(60), "burst": num(2)}}
	})
	m("audience_both_arrays_empty", "receiver_audience with no receivers or domains", "malformed", func(o map[string]any) {
		o["constraints"] = []any{map[string]any{"type": "ratify.receiver_audience", "params": map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{}}}}
	})
	m("audience_age_without_domains", "receiver_audience carries max_membership_age_seconds without domains", "malformed", func(o map[string]any) {
		o["constraints"] = []any{map[string]any{"type": "ratify.receiver_audience", "params": map[string]any{"exact_receiver_ids": []any{"r"}, "trust_domain_ids": []any{}, "max_membership_age_seconds": num(60)}}}
	})
	m("audience_domains_without_age", "receiver_audience names domains without max_membership_age_seconds", "malformed", func(o map[string]any) {
		o["constraints"] = []any{map[string]any{"type": "ratify.receiver_audience", "params": map[string]any{"exact_receiver_ids": []any{}, "trust_domain_ids": []any{"d"}}}}
	})
	// Closed v2 constraint registry (SPEC-v2 §5.1): explicit schemas, no
	// floating point, v1-only member names are malformed.
	constraint := func(name, mutation string, c map[string]any) {
		m(name, mutation, "malformed", func(o map[string]any) { o["constraints"] = []any{c} })
	}
	usd := func(amount any) map[string]any {
		return map[string]any{"type": "max_amount", "currency": "USD", "max_amount_micros": amount}
	}
	constraint("constraint_max_amount_v1_field", "max_amount uses the v1 float member max_amount", map[string]any{"type": "max_amount", "currency": "USD", "max_amount": json.Number("5.5")})
	constraint("constraint_max_amount_micros_fraction", "max_amount_micros spelled 5000000.0", usd(json.Number("5000000.0")))
	constraint("constraint_max_amount_micros_exponent", "max_amount_micros spelled 5e6", usd(json.Number("5e6")))
	constraint("constraint_max_amount_micros_negative", "max_amount_micros is -1", usd(num(-1)))
	constraint("constraint_max_amount_micros_string", "max_amount_micros is a string", usd("5000000"))
	constraint("constraint_max_amount_currency_lowercase", "currency is usd", map[string]any{"type": "max_amount", "currency": "usd", "max_amount_micros": num(1)})
	constraint("constraint_max_amount_currency_length", "currency is US", map[string]any{"type": "max_amount", "currency": "US", "max_amount_micros": num(1)})
	constraint("constraint_max_rate_count_zero", "max_rate count is 0", map[string]any{"type": "max_rate", "count": num(0), "window_s": num(60)})
	constraint("constraint_max_rate_window_over_limit", "max_rate window_s is 86401", map[string]any{"type": "max_rate", "count": num(1), "window_s": num(86401)})
	constraint("constraint_max_rate_window_fraction", "max_rate window_s spelled 60.0", map[string]any{"type": "max_rate", "count": num(1), "window_s": json.Number("60.0")})
	constraint("constraint_time_window_hour_24", "time_window start is 24:00", map[string]any{"type": "time_window", "start": "24:00", "end": "23:59", "tz": "UTC"})
	constraint("constraint_time_window_single_digit_hour", "time_window start is 9:00", map[string]any{"type": "time_window", "start": "9:00", "end": "17:00", "tz": "UTC"})
	constraint("constraint_time_window_empty_tz", "time_window tz is empty", map[string]any{"type": "time_window", "start": "09:00", "end": "17:00", "tz": ""})
	constraint("constraint_resource_path_empty_prefix", "resource_path path_prefix is empty", map[string]any{"type": "resource_path", "resource_id": "r", "path_prefix": ""})
	constraint("constraint_resource_path_long_id", "resource_path resource_id exceeds 512 bytes", map[string]any{"type": "resource_path", "resource_id": strings.Repeat("r", 513)})
	constraint("constraint_registered_type_with_params", "max_rate carries params", map[string]any{"type": "max_rate", "count": num(1), "window_s": num(60), "params": map[string]any{}})
	constraint("constraint_type_missing", "constraint has no type", map[string]any{"count": num(1), "window_s": num(60)})
	constraint("constraint_geo_circle_v1_members", "geo_circle (unregistered in v2) carries v1 members lat/lon/radius_m", map[string]any{"type": "geo_circle", "lat": num(1), "lon": num(2), "radius_m": num(3)})
	constraint("constraint_geo_bbox_v1_members", "geo_bbox (unregistered in v2) carries v1 members", map[string]any{"type": "geo_bbox", "min_lat": num(0), "min_lon": num(0), "max_lat": num(1), "max_lon": num(1)})
	constraint("constraint_max_speed_v1_member", "max_speed_mps (unregistered in v2) carries max_mps", map[string]any{"type": "max_speed_mps", "max_mps": num(3)})
	constraint("constraint_unregistered_params_float", "unregistered constraint params carry a float", map[string]any{"type": "geo_circle", "params": map[string]any{"lat": json.Number("0.5")}})
	constraint("constraint_unregistered_params_not_object", "unregistered constraint params is an array", map[string]any{"type": "vendor.example", "params": []any{}})
	m("issued_at_changed", "issued_at+1", "invalid_signature", func(o map[string]any) { o["issued_at"] = addNum(o["issued_at"], 1) })
	m("expires_at_changed", "expires_at+1", "invalid_signature", func(o map[string]any) { o["expires_at"] = addNum(o["expires_at"], 1) })
	m("signature_ed25519_flipped", "Ed25519 component bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("signature_mldsa_flipped", "ML-DSA-65 component bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("signature_ed25519_short", "Ed25519 component 63 bytes", "malformed", func(o map[string]any) {
		s := obj(o["signature"])
		raw := must(base64.StdEncoding.DecodeString(s["ed25519"].(string)))
		s["ed25519"] = b64(raw[:63])
	})
	m("signature_missing", "signature field removed", "malformed", func(o map[string]any) { delete(o, "signature") })
	m("signature_null", "signature is null", "malformed", func(o map[string]any) { o["signature"] = nil })
	m("signature_extra_component", "signature object has an extra member", "malformed", func(o map[string]any) { obj(o["signature"])["algorithm"] = "ed25519" })
	m("unknown_top_level_field", "unknown field added", "malformed", func(o map[string]any) { o["extensions"] = map[string]any{} })
	m("pub_key_unknown_member", "issuer_pub_key has an extra member", "malformed", func(o map[string]any) { obj(o["issuer_pub_key"])["x25519"] = "AA==" })
	m("field_case_variant", "Cert_ID instead of cert_id", "malformed", func(o map[string]any) { o["Cert_ID"] = o["cert_id"]; delete(o, "cert_id") })

	// Component swaps and cross-code signatures. Each keeps one valid component.
	signable := sg.signable
	other := signDet(root, codePresentation, signable)
	m("ed25519_from_code_0002", "Ed25519 component signed over the 0x0002 transcript", "invalid_signature", func(o map[string]any) { obj(o["signature"])["ed25519"] = b64(other.Ed25519) })
	m("mldsa_from_code_0002", "ML-DSA component signed over the 0x0002 transcript and context", "invalid_signature", func(o map[string]any) { obj(o["signature"])["ml_dsa_65"] = b64(other.MLDSA65) })
	for _, code := range []uint16{0x0000, 0x000a, 0xffff} {
		bad := signDetUnchecked(root, code, signable)
		m("signed_under_unknown_code_"+hex.EncodeToString([]byte{byte(code >> 8), byte(code)}), "both components signed over an unregistered object_type_code transcript and context", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(bad) })
	}
	mlWrongContext := make([]byte, mldsa65.SignatureSize)
	must0(mldsa65.SignTo(root.Priv.MLDSA65, message(codeDelegation, signable), []byte("ratify-protocol/2/0002"), false, mlWrongContext))
	m("mldsa_wrong_context", "ML-DSA signed over the correct M with context ratify-protocol/2/0002", "invalid_signature", func(o map[string]any) { obj(o["signature"])["ml_dsa_65"] = b64(mlWrongContext) })
	mlEmptyContext := make([]byte, mldsa65.SignatureSize)
	must0(mldsa65.SignTo(root.Priv.MLDSA65, message(codeDelegation, signable), nil, false, mlEmptyContext))
	m("mldsa_empty_context", "ML-DSA signed over the correct M with an empty context", "invalid_signature", func(o map[string]any) { obj(o["signature"])["ml_dsa_65"] = b64(mlEmptyContext) })
	mlOverSignable := make([]byte, mldsa65.SignatureSize)
	must0(mldsa65.SignTo(root.Priv.MLDSA65, signable, mldsaContext(codeDelegation), false, mlOverSignable))
	m("mldsa_over_raw_signable", "ML-DSA signed over the raw signable bytes instead of M", "invalid_signature", func(o map[string]any) { obj(o["signature"])["ml_dsa_65"] = b64(mlOverSignable) })
	_, _, leafSig := g.cert(certSpec{issuer: inter, subject: g.k("agent"), certID: "cert-leaf", scope: []string{"data:read"}})
	m("signature_from_other_certificate", "complete signature copied from a different certificate", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(leafSig.sig) })

	// Raw encoding negatives.
	text := string(base)
	n.add("duplicate_json_key", kind, "cert_id appears twice", []byte(strings.Replace(text, `"cert_id":"cert-root"`, `"cert_id":"cert-root","cert_id":"cert-root"`, 1)), v, "malformed")
	n.add("expires_at_unsafe_integer", kind, "expires_at = 2^53 (outside the safe-integer range)", []byte(strings.Replace(text, `"expires_at":`+itoa(Now+86400), `"expires_at":9007199254740992`, 1)), v, "malformed")
	n.add("trailing_data", kind, "bytes after the JSON object", append(append([]byte{}, base...), []byte(" {}")...), v, "malformed")
	n.add("truncated", kind, "object truncated", base[:len(base)/2], v, "malformed")
	n.add("negative_zero_integer", kind, "issued_at encoded as -0 after a valid signature over 0 would decode identically", []byte(strings.Replace(text, `"issued_at":`+itoa(Now-3600), `"issued_at":-0`, 1)), v, "malformed")
	surrogate := parse(base).(map[string]any)
	surrogate["cert_id"] = "cert-root\ufffd"
	resigned := string(resignObject(surrogate, "signature", root, codeDelegation))
	n.add("unpaired_surrogate_escape", kind, "cert_id signed with U+FFFD but sent as an unpaired \\ud800 escape that a lenient decoder maps to U+FFFD", []byte(strings.Replace(resigned, "cert-root\ufffd", `cert-root\ud800`, 1)), v, "malformed")
	n.add("float_integer", kind, "issued_at encoded as 1.0e9 style float", []byte(strings.Replace(text, `"issued_at":`+itoa(Now-3600), `"issued_at":`+itoa(Now-3600)+".0", 1)), v, "malformed")
	edB64 := b64(sg.sig.Ed25519)
	n.add("base64_unpadded", kind, "Ed25519 signature base64 without padding", []byte(strings.Replace(text, edB64, strings.TrimRight(edB64, "="), 1)), v, "malformed")
	n.add("base64_url_alphabet", kind, "issuer ML-DSA key in base64url alphabet", []byte(strings.Replace(text, b64(root.Pub.MLDSA65), base64.URLEncoding.EncodeToString(root.Pub.MLDSA65), 1)), v, "malformed")

	// A v1-shaped certificate presented to the v2 decoder.
	v1 := map[string]any{
		"cert_id": "cert-v1", "version": num(1), "issuer_id": ratify.DeriveID(root.Pub), "issuer_pub_key": pubJSON(root.Pub),
		"subject_id": ratify.DeriveID(inter.Pub), "subject_pub_key": pubJSON(inter.Pub), "scope": []any{"data:read"},
		"constraints": []any{}, "issued_at": num(Now - 3600), "expires_at": num(Now + 86400), "signature": sigJSON(placeholderSig()),
	}
	n.add("v1_certificate", kind, "complete v1 certificate (version 1, 128-bit IDs)", canon(v1), v, "malformed")
}

func itoa(v int64) string { return num(v).String() }

func must0(err error) {
	if err != nil {
		panic(err)
	}
}

// signDetUnchecked signs any 16-bit code, including unregistered ones, to
// build negative vectors. Conforming signers never expose this capability.
func signDetUnchecked(key *Key, code uint16, signable []byte) ratify.HybridSignature {
	return signDet(key, code, signable)
}

// ---------------------------------------------------------------------------
// Canonical Ed25519 rejection (SPEC-v2 §2). Each certificate has a valid
// ML-DSA-65 component, so only the Ed25519 rule decides the outcome.

func (g *gen) ed25519Negatives(n *negBuilder) {
	root, inter := g.k("root"), g.k("intermediate")
	kind, v := "delegation_certificate", verifyContext{}
	build := func(name, mutation string, edPub []byte, edSig func(m []byte) []byte) {
		issuer := ratify.HybridPublicKey{Ed25519: edPub, MLDSA65: root.Pub.MLDSA65}
		o := map[string]any{
			"cert_id": "cert-ed25519-" + name, "version": num(2), "issuer_id": keyIDV2(issuer), "issuer_pub_key": pubJSON(issuer),
			"subject_id": inter.ID, "subject_pub_key": pubJSON(inter.Pub), "scope": []any{"data:read"},
			"constraints": []any{}, "issued_at": num(Now - 3600), "expires_at": num(Now + 86400), "signature": sigJSON(placeholderSig()),
		}
		signable := without(canon(o), "signature")
		msg := message(codeDelegation, signable)
		ml := make([]byte, mldsa65.SignatureSize)
		must0(mldsa65.SignTo(root.Priv.MLDSA65, msg, mldsaContext(codeDelegation), false, ml))
		o["signature"] = sigJSON(ratify.HybridSignature{Ed25519: edSig(msg), MLDSA65: ml})
		n.add("ed25519_"+name, kind, mutation, canon(o), v, "invalid_signature")
	}
	h := sha512.Sum512(root.EdSeed[:])
	a := must(new(edwards25519.Scalar).SetBytesWithClamping(h[:32]))
	order := []byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}

	build("s_plus_order", "S replaced by S+L (non-canonical scalar)", root.Pub.Ed25519, func(m []byte) []byte {
		sig := ed25519Sign(root, m)
		s := sig[32:]
		var carry uint16
		for i := 0; i < 32; i++ {
			sum := uint16(s[i]) + uint16(order[i]) + carry
			s[i], carry = byte(sum), sum>>8
		}
		return sig
	})
	identity := append([]byte{1}, make([]byte, 31)...)
	build("identity_public_key", "A is the identity point (small order)", identity, func(m []byte) []byte { return ed25519Sign(root, m) })
	build("identity_r", "R is the identity point", root.Pub.Ed25519, func(m []byte) []byte {
		sig := ed25519Sign(root, m)
		copy(sig[:32], identity)
		return sig
	})
	nonCanonical := []byte{0xee}
	for i := 0; i < 30; i++ {
		nonCanonical = append(nonCanonical, 0xff)
	}
	nonCanonical = append(nonCanonical, 0x7f)
	build("noncanonical_public_key", "A encodes y = p+1 (y >= p)", nonCanonical, func(m []byte) []byte { return ed25519Sign(root, m) })

	// Mixed-order key A' = A + T8. The signature satisfies the cofactored
	// (ZIP-215) equation but not the cofactorless RFC 8032 equation, and A'
	// is not in the prime-order subgroup.
	torsion := must(new(edwards25519.Point).SetBytes(must(hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))))
	eight := new(edwards25519.Point).Add(torsion, torsion)
	eight.Add(eight, eight)
	eight.Add(eight, eight)
	four := new(edwards25519.Point).Add(torsion, torsion)
	four.Add(four, four)
	if eight.Equal(edwards25519.NewIdentityPoint()) != 1 || four.Equal(edwards25519.NewIdentityPoint()) == 1 {
		panic("fixture torsion point is not of order 8")
	}
	mixed := new(edwards25519.Point).Add(must(new(edwards25519.Point).SetBytes(root.Pub.Ed25519)), torsion).Bytes()
	build("mixed_order_public_key", "A' = A + order-8 torsion point with a cofactored-valid signature", mixed, func(m []byte) []byte {
		r := must(new(edwards25519.Scalar).SetUniformBytes(sha512Bytes(append([]byte("mixed-order-nonce"), m...))))
		R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
		kh := sha512.New()
		kh.Write(R)
		kh.Write(mixed)
		kh.Write(m)
		k := must(new(edwards25519.Scalar).SetUniformBytes(kh.Sum(nil)))
		return append(R, new(edwards25519.Scalar).MultiplyAdd(k, a, r).Bytes()...)
	})
}

func sha512Bytes(b []byte) []byte {
	h := sha512.Sum512(b)
	return h[:]
}

func ed25519Sign(k *Key, m []byte) []byte { return ed25519.Sign(k.Priv.Ed25519, m) }
