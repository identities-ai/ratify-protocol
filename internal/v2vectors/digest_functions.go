package v2vectors

import "encoding/hex"

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
		Description: "Digest functions over explicit object type codes (SPEC-v2 §4). StatementBodyDigest is defined exactly for codes 0x0003, 0x0004, 0x0005, 0x0006 and 0x0008; any other registered code, and any code outside the registry of §4 (0x0000 is reserved and invalid; 0x000a and above are unassigned), is unsupported_object_type and produces no digest. expected_digest is sha384: and 96 lowercase hexadecimal characters.",
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
	for _, code := range []uint16{0x0000, 0x000a, 0xffff} {
		hexCode := hex.EncodeToString([]byte{byte(code >> 8), byte(code)})
		add(digestCaseJSON{Name: "statement_body_unregistered_" + hexCode, Description: "StatementBodyDigest asked for code 0x" + hexCode + ", outside the registry", Function: "statement_body_digest",
			ObjectTypeCode: int(code), InputB64: b64(receiptSig.signable), ExpectedErrorClass: "unsupported_object_type"})
		add(digestCaseJSON{Name: "status_evidence_unregistered_" + hexCode, Description: "StatusEvidenceDigest asked for code 0x" + hexCode + ", outside the registry", Function: "status_evidence_digest",
			ObjectTypeCode: int(code), InputB64: b64(list.wire), ExpectedErrorClass: "unsupported_object_type"})
	}
	return f
}
