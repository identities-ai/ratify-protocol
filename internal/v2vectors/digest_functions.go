package v2vectors

import (
	"encoding/hex"
	"fmt"
)

// Digest-function vectors (SPEC-v2 §4, §2.7): StatementBodyDigest and
// StatusEvidenceDigest over registered codes, and unsupported_object_type
// for codes outside the registry.

const digestFunctionsFile = "digest-functions.json"

type digestCaseJSON struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	Function           string `json:"function"`
	ObjectTypeCode     int    `json:"object_type_code"`
	InputB64           string `json:"input_b64"`
	ExpectedDigest     string `json:"expected_digest,omitempty"`
	ExpectedErrorClass string `json:"expected_error_class,omitempty"`
}

type digestFunctionsFileJSON struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Functions   map[string]string `json:"functions"`
	Cases       []digestCaseJSON  `json:"cases"`
}

func (g *gen) digestFunctionsFile() any {
	f := digestFunctionsFileJSON{
		Version:     1,
		Description: "Digest functions over explicit object type codes (SPEC-v2 §4). StatementBodyDigest is defined exactly for codes 0x0003, 0x0004, 0x0005, 0x0006 and 0x0008; any other registered code, and any code outside the registry of §4 (0x0000 is reserved and invalid; 0x000a and above are unassigned, including codes above 0xffff, which are never truncated to 16 bits), is unsupported_object_type and produces no digest. A body that is not exactly the canonical signable projection of the code's own kind is malformed. A binding whose code parameter cannot represent object_type_code (16 bits) treats the case as unsupported_object_type without a call. expected_digest is sha384: and 96 lowercase hexadecimal characters.",
		Functions: map[string]string{
			"statement_body_digest":  "StatementBodyDigest(object_type_code, input), where input_b64 is the canonical signable body",
			"status_evidence_digest": "StatusEvidenceDigest(object_type_code, object), where input_b64 is a complete signed revocation list wire object decoded strictly before the call",
		},
	}
	add := func(c digestCaseJSON) { f.Cases = append(f.Cases, c) }
	_, _, listSig := g.list(g.k("status_root"), g.k("root").ID, 1, Now-60, Now+3600)
	_, _, pushSig := g.push(g.k("status_root"), g.k("root").ID, 2, Now-30, "cert-leaf")
	_, _, rotSignable, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: g.k("rotation_genesis"), newKey: g.k("rotation_second")})
	_, _, witnessSig := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	_, _, receiptSig := g.receipt(g.k("verifier"), g.receiptFixtureBody(), receiptLogA, 1, make([]byte, 48), 0)
	for _, c := range []struct {
		name string
		code uint16
		body []byte
	}{{"revocation_list", codeList, listSig.signable}, {"rotation", codeRotationOld, rotSignable}, {"revocation_push", codePush, pushSig.signable},
		{"witness_entry", codeWitness, witnessSig.signable}, {"verification_receipt", codeReceipt, receiptSig.signable}} {
		add(digestCaseJSON{Name: "statement_body_" + c.name, Description: "StatementBodyDigest of a " + c.name + " signable body", Function: "statement_body_digest",
			ObjectTypeCode: int(c.code), InputB64: b64(c.body), ExpectedDigest: "sha384:" + hex.EncodeToString(statementBodyDigest(c.code, c.body))})
	}
	list := g.statusFixtures()["root_current"]
	add(digestCaseJSON{Name: "status_evidence_revocation_list", Description: "StatusEvidenceDigest of a complete signed revocation list", Function: "status_evidence_digest",
		ObjectTypeCode: int(codeList), InputB64: b64(list.wire), ExpectedDigest: statusEvidenceDigest(codeList, list.wire)})
	for _, code := range []uint16{0x0001, 0x0002, 0x0007, 0x0009} {
		hexCode := hex.EncodeToString([]byte{byte(code >> 8), byte(code)})
		add(digestCaseJSON{Name: "statement_body_registered_" + hexCode, Description: "StatementBodyDigest asked for registered code 0x" + hexCode + ", which has no statement body digest", Function: "statement_body_digest",
			ObjectTypeCode: int(code), InputB64: b64(receiptSig.signable), ExpectedErrorClass: "unsupported_object_type"})
	}
	// A body that is not exactly the canonical signable projection of the
	// code's own kind is malformed (SPEC-v2 §4): another kind's signable
	// body, a body with insignificant whitespace, and the complete signed
	// object including its signature.
	bodies := map[uint16][]byte{codeList: listSig.signable, codeRotationOld: rotSignable, codePush: pushSig.signable, codeWitness: witnessSig.signable, codeReceipt: receiptSig.signable}
	names := map[uint16]string{codeList: "revocation_list", codeRotationOld: "rotation", codePush: "revocation_push", codeWitness: "witness_entry", codeReceipt: "verification_receipt"}
	for _, c := range []struct{ code, other uint16 }{{codeList, codePush}, {codeRotationOld, codeWitness}, {codePush, codeList}, {codeWitness, codeReceipt}, {codeReceipt, codeWitness}} {
		add(digestCaseJSON{Name: "statement_body_" + names[c.code] + "_given_" + names[c.other] + "_body", Description: "StatementBodyDigest for code " + hexCode16(c.code) + " over the signable body of a " + names[c.other] + ", which is not this code's projection",
			Function: "statement_body_digest", ObjectTypeCode: int(c.code), InputB64: b64(bodies[c.other]), ExpectedErrorClass: "malformed"})
	}
	add(digestCaseJSON{Name: "statement_body_witness_entry_noncanonical", Description: "StatementBodyDigest for code 0x0006 over the witness entry signable body with a space after its opening brace",
		Function: "statement_body_digest", ObjectTypeCode: int(codeWitness), InputB64: b64(append([]byte("{ "), witnessSig.signable[1:]...)), ExpectedErrorClass: "malformed"})
	_, witnessWire, _ := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	add(digestCaseJSON{Name: "statement_body_witness_entry_with_signature", Description: "StatementBodyDigest for code 0x0006 over the complete signed witness entry, signature included",
		Function: "statement_body_digest", ObjectTypeCode: int(codeWitness), InputB64: b64(witnessWire), ExpectedErrorClass: "malformed"})
	// Codes above 0xFFFF are outside the registry, including those whose low
	// 16 bits name a defined code: an implementation must not truncate them.
	// A binding whose code parameter is 16 bits cannot express these inputs.
	for _, c := range []struct {
		code int
		body []byte
		name string
	}{{0x10003, listSig.signable, "revocation_list"}, {0x10008, receiptSig.signable, "verification_receipt"}} {
		add(digestCaseJSON{Name: fmt.Sprintf("statement_body_code_%#x", c.code), Description: fmt.Sprintf("StatementBodyDigest asked for code %#x, above 0xffff, over a %s signable body: its low 16 bits name a defined code, but the code is outside the registry", c.code, c.name),
			Function: "statement_body_digest", ObjectTypeCode: c.code, InputB64: b64(c.body), ExpectedErrorClass: "unsupported_object_type"})
	}
	for _, code := range []uint16{0x0000, 0x000a, 0xffff} {
		hexCode := hex.EncodeToString([]byte{byte(code >> 8), byte(code)})
		add(digestCaseJSON{Name: "statement_body_unregistered_" + hexCode, Description: "StatementBodyDigest asked for code 0x" + hexCode + ", outside the registry", Function: "statement_body_digest",
			ObjectTypeCode: int(code), InputB64: b64(receiptSig.signable), ExpectedErrorClass: "unsupported_object_type"})
		add(digestCaseJSON{Name: "status_evidence_unregistered_" + hexCode, Description: "StatusEvidenceDigest asked for code 0x" + hexCode + ", outside the registry", Function: "status_evidence_digest",
			ObjectTypeCode: int(code), InputB64: b64(list.wire), ExpectedErrorClass: "unsupported_object_type"})
	}
	return f
}

func hexCode16(code uint16) string { return fmt.Sprintf("0x%04x", code) }
