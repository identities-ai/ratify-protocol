package v2vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// LimitConstruction is an exact, language-neutral recipe for the vector
// bytes, so megabyte-scale inputs are not embedded in the corpus.
type LimitConstruction struct {
	// Method is "inline", "pad", "repeat_items" or "repeat_item".
	Method string `json:"method"`
	// inline: the complete object.
	WireB64 string `json:"wire_b64,omitempty"`
	// pad: insert PadCount bytes 0x20 immediately before the final byte of
	// BaseB64 (the closing '}' of the object).
	BaseB64  string `json:"base_b64,omitempty"`
	PadCount int    `json:"pad_count,omitempty"`
	// repeat_items: prefix || item(0) || "," || ... || item(count-1) || suffix,
	// where item(i) = item_prefix || decimal(i) left-padded with '0' to
	// item_index_digits || item_suffix.
	PrefixB64       string `json:"prefix_b64,omitempty"`
	ItemPrefix      string `json:"item_prefix,omitempty"`
	ItemIndexDigits int    `json:"item_index_digits,omitempty"`
	ItemSuffix      string `json:"item_suffix,omitempty"`
	Count           int    `json:"count,omitempty"`
	SuffixB64       string `json:"suffix_b64,omitempty"`
	// repeat_item: prefix || item || "," || ... || item (count times) || suffix.
	ItemB64 string `json:"item_b64,omitempty"`
}

type limitVector struct {
	Name               string            `json:"name"`
	Kind               string            `json:"kind"`
	Limit              string            `json:"limit"`
	LimitValue         int               `json:"limit_value"`
	Construction       LimitConstruction `json:"construction"`
	Length             int               `json:"length"`
	SHA256Hex          string            `json:"sha256_hex"`
	Expected           string            `json:"expected"`
	ExpectedErrorClass string            `json:"expected_error_class,omitempty"`
	SizeGate           string            `json:"size_gate"`
	Note               string            `json:"note,omitempty"`
}

type limitsFile struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Limits      map[string]int    `json:"limits"`
	Procedure   map[string]string `json:"procedure_by_kind"`
	Vectors     []limitVector     `json:"vectors"`
}

// BuildLimitBytes reconstructs a limits.json vector input from its recipe.
func BuildLimitBytes(c LimitConstruction) ([]byte, error) {
	switch c.Method {
	case "inline":
		return b64d(c.WireB64)
	case "pad":
		base, err := b64d(c.BaseB64)
		if err != nil || len(base) == 0 {
			return nil, fmt.Errorf("pad: invalid base")
		}
		out := make([]byte, 0, len(base)+c.PadCount)
		out = append(out, base[:len(base)-1]...)
		out = append(out, bytes.Repeat([]byte{' '}, c.PadCount)...)
		return append(out, base[len(base)-1]), nil
	case "repeat_items":
		prefix, err := b64d(c.PrefixB64)
		if err != nil {
			return nil, err
		}
		suffix, err := b64d(c.SuffixB64)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		out.Write(prefix)
		for i := 0; i < c.Count; i++ {
			if i > 0 {
				out.WriteByte(',')
			}
			fmt.Fprintf(&out, "%s%0*d%s", c.ItemPrefix, c.ItemIndexDigits, i, c.ItemSuffix)
		}
		out.Write(suffix)
		return out.Bytes(), nil
	case "repeat_item":
		prefix, err := b64d(c.PrefixB64)
		if err != nil {
			return nil, err
		}
		item, err := b64d(c.ItemB64)
		if err != nil {
			return nil, err
		}
		suffix, err := b64d(c.SuffixB64)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		out.Write(prefix)
		for i := 0; i < c.Count; i++ {
			if i > 0 {
				out.WriteByte(',')
			}
			out.Write(item)
		}
		out.Write(suffix)
		return out.Bytes(), nil
	}
	return nil, fmt.Errorf("unknown construction method %q", c.Method)
}

func (g *gen) limitsFile() any {
	f := limitsFile{
		Version:     2,
		Description: "Byte-boundary, count-boundary, identifier-length and timestamp-domain vectors for the SPEC-v2 per-object limits (§2.5, §2.6). A byte limit bounds the complete encoded object as received, including signatures and any insignificant whitespace, and is checked before parsing. Build each input from construction, confirm length and sha256_hex, then decode it with the strict decoder for kind. expected=accept: decoding succeeds. expected=reject: decoding fails with expected_error_class. size_gate records whether the input passes the pre-parse byte gate: an input at a limit always passes it (it may still be rejected later, for example because a canonical-only object cannot carry padding); an input one byte over always fails it.",
		Limits: map[string]int{
			"MAX_DELEGATION_CERT_BYTES_V2":           ratify.MaxDelegationCertBytesV2,
			"MAX_PROOF_BUNDLE_BYTES_V2":              ratify.MaxProofBundleBytesV2,
			"MAX_KEY_ROTATION_STATEMENT_BYTES_V2":    ratify.MaxKeyRotationStatementBytesV2,
			"MAX_REVOCATION_PUSH_BYTES_V2":           ratify.MaxRevocationPushBytesV2,
			"MAX_REVOCATION_PUSH_REFS_V2":            ratify.MaxRevocationPushRefsV2,
			"MAX_REVOCATION_LIST_BYTES_V2":           ratify.MaxRevocationListBytesV2,
			"MAX_REVOCATION_LIST_REFS_V2":            ratify.MaxRevocationListRefsV2,
			"MAX_WITNESS_ENTRY_BYTES_V2":             ratify.MaxWitnessEntryBytesV2,
			"MAX_WITNESS_ENTRY_DATA_BYTES_V2":        ratify.MaxWitnessEntryDataBytesV2,
			"MAX_VERIFICATION_RECEIPT_BYTES_V2":      ratify.MaxVerificationReceiptBytesV2,
			"MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2": ratify.MaxVerificationReceiptBodyBytesV2,
			"MAX_TRANSACTION_RECEIPT_BYTES_V2":       ratify.MaxTransactionReceiptBytesV2,
			"MAX_TIMESTAMP_SECONDS_V2":               int(ratify.V2MaxTimestampSeconds),
			"MAX_STATUS_EVIDENCE_BATCH_BYTES_V2":     ratify.MaxStatusEvidenceBatchBytesV2,
			"MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2":   ratify.MaxStatusEvidenceBatchObjectsV2,
			"MAX_IDENTIFIER_LENGTH_BYTES":            ratify.MaxIdentifierLengthBytes,
		},
		Procedure: map[string]string{
			"delegation_certificate":    "strict v2 certificate decode",
			"proof_bundle":              "strict v2 proof bundle decode",
			"key_rotation_statement":    "strict v2 rotation statement decode",
			"revocation_list":           "strict v2 revocation list decode",
			"revocation_push":           "strict v2 revocation push decode",
			"witness_entry":             "strict canonical v2 witness entry decode",
			"verification_receipt":      "strict canonical v2 verification receipt decode",
			"verification_receipt_body": "strict canonical v2 prepared receipt body decode",
			"transaction_receipt":       "strict canonical v2 transaction receipt decode (party signatures and embedded bundles verified)",
			"status_evidence_batch":     "strict v2 status evidence batch decode (SPEC-v2 §6.5): a JSON array of at most 64 entries of exactly {object, object_type_code 3|5}; objects are not authenticated by this decoder",
		},
	}
	add := func(name, kind, limit string, value int, c LimitConstruction, expected, gate, note string) {
		data := must(BuildLimitBytes(c))
		sum := sha256.Sum256(data)
		v := limitVector{Name: kind + "/" + name, Kind: kind, Limit: limit, LimitValue: value, Construction: c,
			Length: len(data), SHA256Hex: hex.EncodeToString(sum[:]), Expected: expected, SizeGate: gate, Note: note}
		if expected == "reject" {
			v.ExpectedErrorClass = "malformed"
		}
		f.Vectors = append(f.Vectors, v)
	}
	pad := func(base []byte, length int) LimitConstruction {
		if length < len(base) {
			panic(fmt.Sprintf("limit %d is below base length %d", length, len(base)))
		}
		return LimitConstruction{Method: "pad", BaseB64: b64(base), PadCount: length - len(base)}
	}
	bytesPair := func(kind, limit string, value int, base []byte, atLimit, atNote string) {
		add("bytes_at_limit", kind, limit, value, pad(base, value), atLimit, "pass", atNote)
		add("bytes_over_limit", kind, limit, value, pad(base, value+1), "reject", "fail", "")
	}
	const canonicalOnly = "this decoder accepts only the canonical encoding, so a padded input passes the byte gate and is then rejected as noncanonical"

	root, inter, agent := g.k("root"), g.k("intermediate"), g.k("agent")
	_, certWire, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	bytesPair("delegation_certificate", "MAX_DELEGATION_CERT_BYTES_V2", ratify.MaxDelegationCertBytesV2, certWire, "accept", "")

	_, bundleWire, _ := g.bundle(bundleSpec{agent: agent, certs: g.chain(chainSpec{}), session: g.fixtureSessionContext(agent)})
	bytesPair("proof_bundle", "MAX_PROOF_BUNDLE_BYTES_V2", ratify.MaxProofBundleBytesV2, bundleWire, "accept", "")

	_, rotationWire, _, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: g.k("rotation_genesis"), newKey: g.k("rotation_second")})
	bytesPair("key_rotation_statement", "MAX_KEY_ROTATION_STATEMENT_BYTES_V2", ratify.MaxKeyRotationStatementBytesV2, rotationWire, "accept", "")

	_, pushWire, _ := g.push(g.k("status_root"), root.ID, 8, Now-30, "cert-c")
	bytesPair("revocation_push", "MAX_REVOCATION_PUSH_BYTES_V2", ratify.MaxRevocationPushBytesV2, pushWire, "accept", "")
	_, listWire, _ := g.list(g.k("status_root"), root.ID, 7, Now-60, Now+3600, "cert-a", "cert-b")
	bytesPair("revocation_list", "MAX_REVOCATION_LIST_BYTES_V2", ratify.MaxRevocationListBytesV2, listWire, "accept", "")

	// Revoked-reference counts: a signed object at the count limit, and the
	// same prefix and suffix with one more reference.
	refs := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("r%05d", i)
		}
		return out
	}
	repeat := func(wire []byte, count int) LimitConstruction {
		start := bytes.Index(wire, []byte(`"revoked":[`)) + len(`"revoked":[`)
		end := bytes.Index(wire, []byte(`],"sequence"`))
		c := LimitConstruction{Method: "repeat_items", PrefixB64: b64(wire[:start]), ItemPrefix: `{"cert_id":"r`, ItemIndexDigits: 5, ItemSuffix: `"}`, Count: count, SuffixB64: b64(wire[end:])}
		check := c
		check.Count = strings.Count(string(wire[start:end]), `{"cert_id"`)
		if !bytes.Equal(must(BuildLimitBytes(check)), wire) {
			panic("repeat_items recipe does not reproduce the signed object")
		}
		return c
	}
	_, pushRefs, _ := g.push(g.k("status_root"), root.ID, 9, Now-30, refs(ratify.MaxRevocationPushRefsV2)...)
	add("refs_at_limit", "revocation_push", "MAX_REVOCATION_PUSH_REFS_V2", ratify.MaxRevocationPushRefsV2, repeat(pushRefs, ratify.MaxRevocationPushRefsV2), "accept", "pass", "signed under status_root for issuer root")
	add("refs_over_limit", "revocation_push", "MAX_REVOCATION_PUSH_REFS_V2", ratify.MaxRevocationPushRefsV2, repeat(pushRefs, ratify.MaxRevocationPushRefsV2+1), "reject", "pass", "")
	_, listRefs, _ := g.list(g.k("status_root"), root.ID, 10, Now-60, Now+3600, refs(ratify.MaxRevocationListRefsV2)...)
	add("refs_at_limit", "revocation_list", "MAX_REVOCATION_LIST_REFS_V2", ratify.MaxRevocationListRefsV2, repeat(listRefs, ratify.MaxRevocationListRefsV2), "accept", "pass", "signed under status_root for issuer root")
	add("refs_over_limit", "revocation_list", "MAX_REVOCATION_LIST_REFS_V2", ratify.MaxRevocationListRefsV2, repeat(listRefs, ratify.MaxRevocationListRefsV2+1), "reject", "pass", "")

	// Revoked cert_id length (SPEC-v2 §2.6): every cert_id is at most 512
	// bytes, counted in UTF-8 bytes, in a list and in a push. Each input is
	// validly signed under status_root for issuer root.
	certIDCase := func(kind, name, certID, expected, note string) {
		var wire []byte
		var code uint16
		if kind == "revocation_list" {
			_, wire, _ = g.list(g.k("status_root"), root.ID, 11, Now-60, Now+3600, "cert-a")
			code = codeList
		} else {
			_, wire, _ = g.push(g.k("status_root"), root.ID, 12, Now-30, "cert-a")
			code = codePush
		}
		o := parse(wire).(map[string]any)
		o["revoked"] = []any{map[string]any{"cert_id": certID}}
		signedWire := resignObject(o, "signature", g.k("status_root"), code)
		add(name, kind, "MAX_IDENTIFIER_LENGTH_BYTES", ratify.MaxIdentifierLengthBytes, LimitConstruction{Method: "inline", WireB64: b64(signedWire)}, expected, "pass", note)
	}
	for _, kind := range []string{"revocation_list", "revocation_push"} {
		certIDCase(kind, "cert_id_at_limit", strings.Repeat("a", ratify.MaxIdentifierLengthBytes), "accept", "one revoked cert_id of 512 ASCII bytes")
		certIDCase(kind, "cert_id_over_limit", strings.Repeat("a", ratify.MaxIdentifierLengthBytes+1), "reject", "one revoked cert_id of 513 ASCII bytes")
		certIDCase(kind, "cert_id_multibyte_at_limit", strings.Repeat("\u00e9", ratify.MaxIdentifierLengthBytes/2), "accept", "one revoked cert_id of 256 two-byte characters (512 bytes)")
		certIDCase(kind, "cert_id_multibyte_over_limit", strings.Repeat("\u00e9", ratify.MaxIdentifierLengthBytes/2)+"a", "reject", "one revoked cert_id of 256 two-byte characters and one ASCII byte (513 bytes, 257 characters)")
	}

	_, witnessWire, _ := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	bytesPair("witness_entry", "MAX_WITNESS_ENTRY_BYTES_V2", ratify.MaxWitnessEntryBytesV2, witnessWire, "reject", canonicalOnly)
	_, dataAtLimit, _ := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), strings.Repeat("w", ratify.MaxWitnessEntryDataBytesV2), Now-20, "", 0)
	add("entry_data_at_limit", "witness_entry", "MAX_WITNESS_ENTRY_DATA_BYTES_V2", ratify.MaxWitnessEntryDataBytesV2, LimitConstruction{Method: "inline", WireB64: b64(dataAtLimit)}, "accept", "pass", "entry_data is 16384 bytes of 0x77")
	dataOver := mutate(dataAtLimit, func(o map[string]any) {
		o["entry_data"] = b64([]byte(strings.Repeat("w", ratify.MaxWitnessEntryDataBytesV2+1)))
	})
	add("entry_data_over_limit", "witness_entry", "MAX_WITNESS_ENTRY_DATA_BYTES_V2", ratify.MaxWitnessEntryDataBytesV2, LimitConstruction{Method: "inline", WireB64: b64(dataOver)}, "reject", "pass", "entry_data is 16385 bytes of 0x77")

	body := g.receiptFixtureBody()
	_, receiptWire, _ := g.receipt(g.k("verifier"), body, receiptLogA, 1, make([]byte, 48), 0)
	bytesPair("verification_receipt", "MAX_VERIFICATION_RECEIPT_BYTES_V2", ratify.MaxVerificationReceiptBytesV2, receiptWire, "reject", canonicalOnly)
	bytesPair("verification_receipt_body", "MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2", ratify.MaxVerificationReceiptBodyBytesV2, must(ratify.VerificationReceiptV2Body(body)), "reject", canonicalOnly)

	bytesPair("transaction_receipt", "MAX_TRANSACTION_RECEIPT_BYTES_V2", ratify.MaxTransactionReceiptBytesV2, g.txFixture().wire, "reject", canonicalOnly)

	// Status evidence batch (SPEC-v2 §6.5): byte limit by padding the
	// canonical one-entry batch before its closing bracket, and the entry
	// count by repeating one canonical entry.
	entry := []byte(`{"object":` + string(listWire) + `,"object_type_code":3}`)
	bytesPair("status_evidence_batch", "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2", ratify.MaxStatusEvidenceBatchBytesV2, append(append([]byte("["), entry...), ']'), "accept", "")
	repeatEntry := func(count int) LimitConstruction {
		return LimitConstruction{Method: "repeat_item", PrefixB64: b64([]byte("[")), ItemB64: b64(entry), Count: count, SuffixB64: b64([]byte("]"))}
	}
	add("objects_at_limit", "status_evidence_batch", "MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2", ratify.MaxStatusEvidenceBatchObjectsV2, repeatEntry(ratify.MaxStatusEvidenceBatchObjectsV2), "accept", "pass", "64 copies of one signed list entry")
	add("objects_over_limit", "status_evidence_batch", "MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2", ratify.MaxStatusEvidenceBatchObjectsV2, repeatEntry(ratify.MaxStatusEvidenceBatchObjectsV2+1), "reject", "pass", "")
	// The batch decoder checks the envelope schema (SPEC-v2 §2.1, §6.5 step
	// 3): the array, exactly the two entry members, the code 3 or 5 as a
	// JSON integer, a JSON object for each object, and the size and count.
	// The JSON value model applies to the whole document, nested objects
	// included: duplicate member names, the number grammar and safe-integer
	// range, -0, unpaired surrogate escapes, UTF-8 and the nesting depth.
	// Each nested object's schema stays opaque until it is authenticated
	// (step 4), so its member names, nulls, byte-field spellings, required
	// members, and agreement with the code are not checked here.
	const envelope = "MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2"
	batchCase := func(name, wire, expected, note string) {
		add(name, "status_evidence_batch", envelope, ratify.MaxStatusEvidenceBatchObjectsV2, LimitConstruction{Method: "inline", WireB64: b64([]byte(wire))}, expected, "pass", note)
	}
	batchCase("empty_array", `[]`, "accept", "an empty batch")
	batchCase("nested_object_empty", `[{"object":{},"object_type_code":3}]`, "accept", "the nested object is opaque at decode; it fails authentication later")
	batchCase("nested_null_member", `[{"object":{"a":null},"object_type_code":3}]`, "accept", "a null inside the opaque nested object is not checked by the batch decoder")
	batchCase("nested_null_nullable_name", `[{"object":{"stream_id":null},"object_type_code":5}]`, "accept", "a null inside the opaque nested object is not checked by the batch decoder")
	batchCase("nested_unknown_and_case_variant_members", `[{"object":{"Issuer_ID":"x","extra":1},"object_type_code":3}]`, "accept", "nested member names are checked when the object is authenticated, not here")
	batchCase("code_does_not_match_object", `[{"object":`+string(listWire)+`,"object_type_code":5}]`, "accept", "a signed list labelled code 5; the label is checked when the object is authenticated")
	nested := func(object string) string { return `[{"object":` + object + `,"object_type_code":3}]` }
	deep := func(levels int) string { return strings.Repeat(`{"a":`, levels-1) + `{}` + strings.Repeat(`}`, levels-1) }
	valueModel := "the JSON value model applies to the whole batch document, including the nested object"
	batchCase("nested_duplicate_member", nested(`{"a":1,"a":2}`), "reject", valueModel)
	batchCase("nested_duplicate_member_escaped", nested(`{"a":1,"\u0061":2}`), "reject", valueModel+"; member names compare after escapes are decoded")
	batchCase("nested_number_fraction", nested(`{"a":1.5}`), "reject", valueModel)
	batchCase("nested_number_integral_fraction", nested(`{"a":1.0}`), "reject", valueModel)
	batchCase("nested_number_exponent", nested(`{"a":1e3}`), "reject", valueModel)
	batchCase("nested_number_unsafe_integer", nested(`{"a":9007199254740992}`), "reject", valueModel)
	batchCase("nested_negative_zero", nested(`{"a":-0}`), "reject", valueModel)
	batchCase("nested_unpaired_high_surrogate", nested(`{"a":"\ud800"}`), "reject", valueModel)
	batchCase("nested_unpaired_low_surrogate", nested(`{"a":"\udc00x"}`), "reject", valueModel)
	batchCase("nested_invalid_utf8", nested("{\"a\":\"\xff\"}"), "reject", valueModel)
	batchCase("nested_depth_at_limit", nested(deep(ratify.MaxJSONNestingDepth-2)), "accept", "the whole document nests exactly MAX_JSON_NESTING_DEPTH levels: the array, the entry and the nested object")
	batchCase("nested_depth_over_limit", nested(deep(ratify.MaxJSONNestingDepth-1)), "reject", valueModel+"; the depth limit counts from the batch array")
	schema := "a schema rule of the nested object, checked when it is authenticated, not here"
	batchCase("nested_byte_field_noncanonical_base64", nested(`{"signature":{"ed25519":"AB==","ml_dsa_65":"AB=="}}`), "accept", schema)
	batchCase("nested_byte_field_not_base64", nested(`{"challenge":"AB==","session_context":"!!"}`), "accept", schema)
	batchCase("nested_byte_field_array_of_numbers", nested(`{"signature":{"ed25519":[1,2],"ml_dsa_65":"AA=="}}`), "accept", schema)
	batchCase("nested_null_signature", nested(`{"signature":null}`), "accept", schema)
	batchCase("nested_null_array_element", nested(`{"revoked":[null]}`), "accept", schema)
	batchCase("nested_case_variant_beside_exact_member", nested(`{"Issuer_ID":"x","issuer_id":"y"}`), "accept", schema)
	batchCase("nested_required_members_missing", nested(`{"signature":{}}`), "accept", schema)
	batchCase("not_an_array", `{"object":{},"object_type_code":3}`, "reject", "")
	batchCase("entry_null", `[null]`, "reject", "")
	batchCase("object_null", `[{"object":null,"object_type_code":3}]`, "reject", "")
	batchCase("object_array", `[{"object":[],"object_type_code":3}]`, "reject", "")
	batchCase("object_missing", `[{"object_type_code":3}]`, "reject", "")
	batchCase("entry_extra_member", `[{"extra":1,"object":{},"object_type_code":3}]`, "reject", "")
	batchCase("entry_case_variant_member", `[{"Object":{},"object_type_code":3}]`, "reject", "")
	batchCase("entry_duplicate_member", `[{"object":{},"object":{},"object_type_code":3}]`, "reject", "")
	batchCase("code_4", `[{"object":{},"object_type_code":4}]`, "reject", "")
	batchCase("code_string", `[{"object":{},"object_type_code":"3"}]`, "reject", "")
	batchCase("code_fraction", `[{"object":{},"object_type_code":3.0}]`, "reject", "")
	if !bytes.Equal(must(ratify.EncodeV2StatusEvidenceBatch(ratify.V2StatusEvidenceBatch{Objects: []ratify.V2StatusEvidenceObject{{ObjectType: 3, Wire: listWire}}})), append(append([]byte("["), entry...), ']')) {
		panic("status evidence batch entry is not the canonical encoding")
	}

	// Timestamp domain (SPEC-v2 §2.5): a signed object whose timestamp is
	// exactly 9999-12-31T23:59:59Z decodes; one second later is malformed at
	// decode. The delegation lifetime bound is a post-claim check, so the
	// at-limit certificate decodes even though its lifetime exceeds it.
	maxTS := int(ratify.V2MaxTimestampSeconds)
	_, certMaxTS, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read"}, issuedAt: Now - 3600, expiresAt: ratify.V2MaxTimestampSeconds})
	add("expires_at_at_limit", "delegation_certificate", "MAX_TIMESTAMP_SECONDS_V2", maxTS, LimitConstruction{Method: "inline", WireB64: b64(certMaxTS)}, "accept", "pass", "expires_at = 253402300799, signed")
	add("expires_at_over_limit", "delegation_certificate", "MAX_TIMESTAMP_SECONDS_V2", maxTS, LimitConstruction{Method: "inline", WireB64: b64(mutate(certMaxTS, func(o map[string]any) { o["expires_at"] = num(ratify.V2MaxTimestampSeconds + 1) }))}, "reject", "pass", "expires_at = 253402300800")
	_, listMaxTS, _ := g.list(g.k("status_root"), root.ID, 7, Now-60, ratify.V2MaxTimestampSeconds, "cert-a")
	add("next_update_at_limit", "revocation_list", "MAX_TIMESTAMP_SECONDS_V2", maxTS, LimitConstruction{Method: "inline", WireB64: b64(listMaxTS)}, "accept", "pass", "next_update = 253402300799, signed")
	add("next_update_over_limit", "revocation_list", "MAX_TIMESTAMP_SECONDS_V2", maxTS, LimitConstruction{Method: "inline", WireB64: b64(mutate(listMaxTS, func(o map[string]any) { o["next_update"] = num(ratify.V2MaxTimestampSeconds + 1) }))}, "reject", "pass", "next_update = 253402300800")
	return f
}

func b64d(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(s) }
