package v2vectors

import "encoding/hex"

// Archival verification vectors (SPEC-v2 §6.10). Every expected result is
// written here from the §6.10 result shape and the §4 digests computed
// independently, never read back from the reference verifier.

const archivalFile = "archival.json"

// archivalVerifyJSON names the caller-authenticated inputs: key names refer
// to keys.json.
type archivalVerifyJSON struct {
	IssuerID    string `json:"issuer_id,omitempty"`
	StatusKey   string `json:"status_key,omitempty"`
	WitnessKey  string `json:"witness_key,omitempty"`
	VerifierKey string `json:"verifier_key,omitempty"`
}

type archivalCaseJSON struct {
	Name               string              `json:"name"`
	Kind               string              `json:"kind"`
	Description        string              `json:"description"`
	WireB64            string              `json:"wire_b64"`
	Verify             *archivalVerifyJSON `json:"verify,omitempty"`
	Expected           map[string]any      `json:"expected,omitempty"`
	ExpectedErrorClass string              `json:"expected_error_class,omitempty"`
}

type archivalFileJSON struct {
	Version         int                `json:"version"`
	Description     string             `json:"description"`
	ProcedureByKind map[string]string  `json:"procedure_by_kind"`
	Cases           []archivalCaseJSON `json:"cases"`
}

func archivalObject(code uint16, digest string, signers ...string) map[string]any {
	if signers == nil {
		signers = []string{}
	}
	return map[string]any{"object_type_code": int(code), "freshness": "freshness_unverified", "actionable": false, "digest": digest, "signer_key_ids": signers}
}

func (g *gen) archivalFile() any {
	root, inter, agent := g.k("root"), g.k("intermediate"), g.k("agent")
	f := archivalFileJSON{
		Version: 1,
		Description: "Archival verification results for every signed object kind (SPEC-v2 §6.10). Each case is verified offline: no challenge is consumed, no provider runs, and no time is evaluated. " +
			"A positive case gives the exact result object; compare every member. A proof_bundle case always returns a result whose error_class is null when every check passed or the §2.7 class otherwise. Every other kind returns either the result or an error with expected_error_class. A result never carries a decision and is never actionable.",
		ProcedureByKind: map[string]string{
			"proof_bundle":           "VerifyArchivalProofBundleV2(wire): §6.2 pre-claim steps 1, 3, 4 and 5 only; result {assessment, actionable, bundle_hash, agent_id, issuer_ids (sorted, unique), error_class}",
			"delegation_certificate": "VerifyArchivalDelegationCert(wire) under the issuer key the certificate carries",
			"revocation_list":        "VerifyArchivalRevocationList(wire, verify.issuer_id, public key of verify.status_key); digest is StatusEvidenceDigest(0x0003, object)",
			"revocation_push":        "VerifyArchivalRevocationPush(wire, verify.issuer_id, public key of verify.status_key); digest is StatusEvidenceDigest(0x0005, object)",
			"key_rotation_statement": "VerifyArchivalKeyRotationStatement(wire) under the old and new keys it names; object_type_code is 4 and digest is StatementBodyDigest(0x0004, signable body)",
			"witness_entry":          "VerifyArchivalWitnessEntry(wire, public key of verify.witness_key); a key whose ID is not witness_id is key_id_mismatch; digest is StatementBodyDigest(0x0006, signable body)",
			"verification_receipt":   "VerifyArchivalVerificationReceipt(wire, public key of verify.verifier_key), without log position, fork or bundle binding; a key whose ID is not verifier_id is key_id_mismatch; digest is StatementBodyDigest(0x0008, signable body)",
			"transaction_receipt":    "VerifyArchivalTransactionReceipt(wire): canonical form, every party signature, and every embedded bundle's signatures, hash and transaction context; signer_key_ids are the party agent IDs in party order and digest is empty",
		},
	}
	add := func(c archivalCaseJSON) { f.Cases = append(f.Cases, c) }
	flipSig := func(wire []byte, field, component string) []byte {
		return mutate(wire, func(o map[string]any) { s := obj(o[field]); s[component] = flipB64(s[component]) })
	}
	bundleResult := func(wire []byte, agentID string, issuers []string, class any) map[string]any {
		ids := []any{}
		for _, id := range issuers {
			ids = append(ids, id)
		}
		return map[string]any{"assessment": "freshness_unverified", "actionable": false, "bundle_hash": bundleHash(wire), "agent_id": agentID, "issuer_ids": ids, "error_class": class}
	}
	issuers := sortedStrings(root.ID, inter.ID)

	// Proof bundles.
	bundleWire, _, _ := g.base()
	add(archivalCaseJSON{Name: "proof_bundle_two_link", Kind: "proof_bundle", Description: "the default two-link bound proof: every structural and signature check passes",
		WireB64: b64(bundleWire), Expected: bundleResult(bundleWire, agent.ID, issuers, nil)})
	expiredCerts := g.chain(chainSpec{leafIssued: Now - 7200, leafExpires: Now - 3600})
	_, expiredWire, _ := g.bundle(bundleSpec{agent: agent, certs: expiredCerts, session: g.fixtureSessionContext(agent)})
	add(archivalCaseJSON{Name: "proof_bundle_expired_leaf", Kind: "proof_bundle", Description: "a leaf that expired an hour before the fixture time still verifies: archival verification evaluates no time and is freshness_unverified",
		WireB64: b64(expiredWire), Expected: bundleResult(expiredWire, agent.ID, issuers, nil)})
	_, emptyWire, _ := g.bundle(bundleSpec{agent: agent})
	add(archivalCaseJSON{Name: "proof_bundle_empty_chain", Kind: "proof_bundle", Description: "an empty delegation chain with a valid challenge signature: no issuers, and the result is still not actionable",
		WireB64: b64(emptyWire), Expected: bundleResult(emptyWire, agent.ID, nil, nil)})
	badChallenge := flipSig(bundleWire, "challenge_sig", "ml_dsa_65")
	add(archivalCaseJSON{Name: "proof_bundle_bad_challenge_signature", Kind: "proof_bundle", Description: "the challenge ML-DSA-65 component is flipped: the result carries invalid_signature with the decoded identity",
		WireB64: b64(badChallenge), Expected: bundleResult(badChallenge, agent.ID, issuers, "invalid_signature")})

	// Delegation certificate.
	_, certWire, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	add(archivalCaseJSON{Name: "delegation_certificate", Kind: "delegation_certificate", Description: "root to intermediate under the issuer key it carries",
		WireB64: b64(certWire), Expected: archivalObject(codeDelegation, "", root.ID)})
	add(archivalCaseJSON{Name: "delegation_certificate_bad_signature", Kind: "delegation_certificate", Description: "the issuer Ed25519 component is flipped",
		WireB64: b64(flipSig(certWire, "signature", "ed25519")), ExpectedErrorClass: "invalid_signature"})

	// Status objects.
	st := g.statusFixtures()
	list := st["intermediate_revoked_leaf"]
	statusKey := g.k(list.keyName)
	add(archivalCaseJSON{Name: "revocation_list", Kind: "revocation_list", Description: "a signed list under the caller-authenticated status key bound to its issuer",
		WireB64: b64(list.wire), Verify: &archivalVerifyJSON{IssuerID: list.issuerID, StatusKey: list.keyName},
		Expected: archivalObject(codeList, statusEvidenceDigest(codeList, list.wire), statusKey.ID)})
	add(archivalCaseJSON{Name: "revocation_list_wrong_status_key", Kind: "revocation_list", Description: "the same list verified under another issuer's status key",
		WireB64: b64(list.wire), Verify: &archivalVerifyJSON{IssuerID: list.issuerID, StatusKey: "status_root"}, ExpectedErrorClass: "invalid_signature"})
	add(archivalCaseJSON{Name: "revocation_list_wrong_issuer", Kind: "revocation_list", Description: "the list names its issuer, but the caller-authenticated binding is for another issuer",
		WireB64: b64(list.wire), Verify: &archivalVerifyJSON{IssuerID: root.ID, StatusKey: list.keyName}, ExpectedErrorClass: "status_key_binding_mismatch"})
	_, pushWire, _ := g.push(g.k("status_root"), root.ID, 8, Now-30, "cert-c")
	add(archivalCaseJSON{Name: "revocation_push", Kind: "revocation_push", Description: "a signed push under the status key bound to the root issuer",
		WireB64: b64(pushWire), Verify: &archivalVerifyJSON{IssuerID: root.ID, StatusKey: "status_root"},
		Expected: archivalObject(codePush, statusEvidenceDigest(codePush, pushWire), g.k("status_root").ID)})
	add(archivalCaseJSON{Name: "revocation_push_bad_signature", Kind: "revocation_push", Description: "the push ML-DSA-65 component is flipped",
		WireB64: b64(flipSig(pushWire, "signature", "ml_dsa_65")), Verify: &archivalVerifyJSON{IssuerID: root.ID, StatusKey: "status_root"}, ExpectedErrorClass: "invalid_signature"})

	// Key rotation statement.
	_, rotWire, rotSignable, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: g.k("rotation_genesis"), newKey: g.k("rotation_second")})
	add(archivalCaseJSON{Name: "key_rotation_statement", Kind: "key_rotation_statement", Description: "old-key authorization and new-key proof of possession under the keys the statement names; whether the old key was current is not established",
		WireB64: b64(rotWire), Expected: archivalObject(codeRotationOld, "sha384:"+hex.EncodeToString(statementBodyDigest(codeRotationOld, rotSignable)), g.k("rotation_genesis").ID, g.k("rotation_second").ID)})
	add(archivalCaseJSON{Name: "key_rotation_statement_bad_new_signature", Kind: "key_rotation_statement", Description: "the new-key proof of possession ML-DSA-65 component is flipped",
		WireB64: b64(flipSig(rotWire, "new_signature", "ml_dsa_65")), ExpectedErrorClass: "invalid_signature"})

	// Witness entry.
	_, witnessWire, witnessSig := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	add(archivalCaseJSON{Name: "witness_entry", Kind: "witness_entry", Description: "a witness entry under the caller-authenticated witness key, without log position or fork checks",
		WireB64: b64(witnessWire), Verify: &archivalVerifyJSON{WitnessKey: "witness"},
		Expected: archivalObject(codeWitness, "sha384:"+hex.EncodeToString(statementBodyDigest(codeWitness, witnessSig.signable)), g.k("witness").ID)})
	add(archivalCaseJSON{Name: "witness_entry_wrong_key", Kind: "witness_entry", Description: "the caller-authenticated witness key is not the key the entry names",
		WireB64: b64(witnessWire), Verify: &archivalVerifyJSON{WitnessKey: "attacker"}, ExpectedErrorClass: "key_id_mismatch"})

	// Verification receipt.
	_, receiptWire, receiptSig := g.receipt(g.k("verifier"), g.receiptFixtureBody(), receiptLogA, 1, make([]byte, 48), 0)
	add(archivalCaseJSON{Name: "verification_receipt", Kind: "verification_receipt", Description: "an allow receipt under the caller-authenticated verifier key, without log position, fork or bundle binding; the result is never a decision",
		WireB64: b64(receiptWire), Verify: &archivalVerifyJSON{VerifierKey: "verifier"},
		Expected: archivalObject(codeReceipt, "sha384:"+hex.EncodeToString(statementBodyDigest(codeReceipt, receiptSig.signable)), g.k("verifier").ID)})
	add(archivalCaseJSON{Name: "verification_receipt_wrong_key", Kind: "verification_receipt", Description: "the caller-authenticated verifier key is not the key the receipt names",
		WireB64: b64(receiptWire), Verify: &archivalVerifyJSON{VerifierKey: "attacker"}, ExpectedErrorClass: "key_id_mismatch"})

	// Transaction receipt.
	tx := g.txFixture()
	signers := []string{}
	for _, p := range tx.receipt.Parties {
		signers = append(signers, p.AgentID)
	}
	add(archivalCaseJSON{Name: "transaction_receipt", Kind: "transaction_receipt", Description: "two parties: canonical form, both party signatures, and each embedded bundle's signatures, hash and transaction context",
		WireB64: b64(tx.wire), Expected: archivalObject(codeParty, "", signers...)})
	badTx := mutate(tx.wire, func(o map[string]any) {
		s := obj(obj(arr(o["party_signatures"])[1])["signature"])
		s["ed25519"] = flipB64(s["ed25519"])
	})
	add(archivalCaseJSON{Name: "transaction_receipt_bad_party_signature", Kind: "transaction_receipt", Description: "party-b's Ed25519 component is flipped",
		WireB64: b64(badTx), ExpectedErrorClass: "invalid_signature"})
	return f
}
