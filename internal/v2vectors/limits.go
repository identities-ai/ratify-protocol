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
	// Method is "inline", "pad" or "repeat_items".
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
	}
	return nil, fmt.Errorf("unknown construction method %q", c.Method)
}

func (g *gen) limitsFile() any {
	f := limitsFile{
		Version:     2,
		Description: "Byte-boundary and count-boundary vectors for the SPEC-v2 per-object limits. A byte limit bounds the complete encoded object as received, including signatures and any insignificant whitespace, and is checked before parsing. Build each input from construction, confirm length and sha256_hex, then decode it with the strict decoder for kind. expected=accept: decoding succeeds. expected=reject: decoding fails with expected_error_class. size_gate records whether the input passes the pre-parse byte gate: an input at a limit always passes it (it may still be rejected later, for example because a canonical-only object cannot carry padding); an input one byte over always fails it.",
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
	return f
}

func b64d(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(s) }
