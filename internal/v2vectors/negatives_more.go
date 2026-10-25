package v2vectors

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

func (g *gen) bundleNegatives(n *negBuilder) {
	agent, root, inter, attacker := g.k("agent"), g.k("root"), g.k("intermediate"), g.k("attacker")
	chain := g.chain(chainSpec{})
	_, base, _ := g.bundle(bundleSpec{agent: agent, certs: chain, session: g.fixtureSessionContext(agent)})
	kind, v := "proof_bundle", verifyContext{}
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(base, f), v, class)
	}
	resigned := func(name, mutation, class string, f func(map[string]any)) {
		o := parse(base).(map[string]any)
		f(o)
		n.add(name, kind, mutation, g.resign(o, agent), v, class)
	}
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("challenge_at_after_max_timestamp", "challenge_at = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["challenge_at"] = num(maxTimestampV2 + 1) })
	m("challenge_at_negative", "challenge_at = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["challenge_at"] = num(-1) })
	m("verifier_id_changed", "verifier_id set to another valid v2 key ID", "invalid_signature", func(o map[string]any) { o["verifier_id"] = attacker.ID })
	m("verifier_id_v1_128_bit", "verifier_id is a 128-bit v1 ID", "malformed", func(o map[string]any) { o["verifier_id"] = ratify.DeriveID(g.k("verifier").Pub) })
	m("agent_id_other_key", "agent_id set to another key's ID", "key_id_mismatch", func(o map[string]any) { o["agent_id"] = attacker.ID })
	m("agent_id_v1_128_bit", "agent_id is the agent's 128-bit v1 ID", "malformed", func(o map[string]any) { o["agent_id"] = ratify.DeriveID(agent.Pub) })
	m("agent_key_and_id_substituted", "agent key and ID consistently replaced; leaf subject unchanged", "chain_linkage_mismatch", func(o map[string]any) {
		o["agent_pub_key"], o["agent_id"] = pubJSON(attacker.Pub), attacker.ID
	})
	m("delegation_digest_flipped", "delegation_digest bit flip", "delegation_digest_mismatch", func(o map[string]any) { o["delegation_digest"] = flipB64(o["delegation_digest"]) })
	m("delegation_digest_47_bytes", "delegation_digest is 47 bytes", "malformed", func(o map[string]any) {
		raw := must(base64.StdEncoding.DecodeString(o["delegation_digest"].(string)))
		o["delegation_digest"] = b64(raw[:47])
	})
	m("certificate_field_changed", "delegations[0].cert_id changed without updating the digest", "delegation_digest_mismatch", func(o map[string]any) { obj(arr(o["delegations"])[0])["cert_id"] = "cert-leaf-x" })
	resigned("certificate_signature_broken", "delegations[0] ML-DSA bit flip with recomputed digest and challenge signature", "invalid_signature", func(o map[string]any) {
		s := obj(obj(arr(o["delegations"])[0])["signature"])
		s["ml_dsa_65"] = flipB64(s["ml_dsa_65"])
	})
	resigned("root_certificate_signature_broken", "delegations[1] Ed25519 bit flip with recomputed digest and challenge signature", "invalid_signature", func(o map[string]any) {
		s := obj(obj(arr(o["delegations"])[1])["signature"])
		s["ed25519"] = flipB64(s["ed25519"])
	})
	resigned("chain_swapped", "delegations reversed (root first) with recomputed digest and signature", "chain_linkage_mismatch", func(o map[string]any) {
		d := arr(o["delegations"])
		d[0], d[1] = d[1], d[0]
	})
	resigned("leaf_subject_not_agent", "only the root certificate is presented", "chain_linkage_mismatch", func(o map[string]any) { o["delegations"] = arr(o["delegations"])[1:] })
	resigned("v1_certificate_in_v2_bundle", "a v1 certificate is mixed into the chain", "malformed", func(o map[string]any) {
		c := obj(arr(o["delegations"])[1])
		c["version"], c["issuer_id"], c["subject_id"] = num(1), ratify.DeriveID(root.Pub), ratify.DeriveID(inter.Pub)
	})
	resigned("delegations_null", "delegations is null", "malformed", func(o map[string]any) { o["delegations"] = nil })
	m("challenge_flipped", "challenge bit flip", "invalid_signature", func(o map[string]any) { o["challenge"] = flipB64(o["challenge"]) })
	m("challenge_31_bytes", "challenge decodes to 31 bytes", "malformed", func(o map[string]any) { o["challenge"] = b64(defaultChallenge()[:31]) })
	m("challenge_33_bytes", "challenge decodes to 33 bytes", "malformed", func(o map[string]any) { o["challenge"] = b64(append(defaultChallenge(), 0)) })
	m("challenge_at_changed", "challenge_at+1", "invalid_signature", func(o map[string]any) { o["challenge_at"] = addNum(o["challenge_at"], 1) })
	m("challenge_sig_ed25519_flipped", "challenge_sig Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["challenge_sig"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("challenge_sig_mldsa_flipped", "challenge_sig ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["challenge_sig"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("session_context_flipped", "session_context bit flip", "invalid_signature", func(o map[string]any) { o["session_context"] = flipB64(o["session_context"]) })
	m("session_context_nulled", "session_context set to null", "invalid_signature", func(o map[string]any) { o["session_context"] = nil })
	m("session_context_31_bytes", "session_context decodes to 31 bytes", "malformed", func(o map[string]any) {
		o["session_context"] = b64(must(base64.StdEncoding.DecodeString(o["session_context"].(string)))[:31])
	})
	m("session_context_missing", "session_context field omitted instead of null", "malformed", func(o map[string]any) { delete(o, "session_context") })
	m("stream_id_without_seq", "stream_id set while stream_seq is null", "malformed", func(o map[string]any) { o["stream_id"] = b64(make([]byte, 32)) })
	m("stream_bound_added", "stream_id and stream_seq set on an unbound presentation", "invalid_signature", func(o map[string]any) {
		o["stream_id"], o["stream_seq"] = b64(make([]byte, 32)), num(1)
	})
	m("stream_seq_zero", "stream_seq 0 with a stream_id", "malformed", func(o map[string]any) { o["stream_id"], o["stream_seq"] = b64(make([]byte, 32)), num(0) })
	m("unknown_field", "unknown top-level field", "malformed", func(o map[string]any) { o["audience"] = "x" })
	presentation := without(base, "delegations", "challenge_sig")
	m("challenge_signed_by_root", "challenge signed by the root key", "invalid_signature", func(o map[string]any) { o["challenge_sig"] = sigJSON(signDet(root, codePresentation, presentation)) })
	m("challenge_signed_as_certificate", "challenge signed by the agent under code 0x0001", "invalid_signature", func(o map[string]any) { o["challenge_sig"] = sigJSON(signDet(agent, codeDelegation, presentation)) })

	// Duplicate CertificateRef: two links share issuer and cert_id.
	dupLeaf, _, _ := g.cert(certSpec{issuer: inter, subject: agent, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	dupSelf, _, _ := g.cert(certSpec{issuer: inter, subject: inter, certID: "dup", scope: []string{"data:read", "identity:delegate"}})
	dupRoot, _, _ := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "identity:delegate"}})
	_, dupWire, _ := g.bundle(bundleSpec{agent: agent, certs: []ratify.DelegationCertV2{dupLeaf, dupSelf, dupRoot}})
	n.add("duplicate_certificate_ref", kind, "two links carry the same (issuer_id, cert_id)", dupWire, v, "duplicate_certificate_ref")

	// Empty chain with an invalid challenge signature.
	_, emptyBad, _ := g.bundle(bundleSpec{agent: agent, signer: attacker})
	n.add("empty_chain_bad_signature", kind, "empty delegations; challenge signed by a different key", emptyBad, v, "invalid_signature")

	v1 := map[string]any{
		"agent_id": ratify.DeriveID(agent.Pub), "agent_pub_key": pubJSON(agent.Pub), "delegations": []any{},
		"challenge": b64(defaultChallenge()), "challenge_at": num(Now - 10), "challenge_sig": sigJSON(placeholderSig()),
	}
	n.add("v1_bundle", kind, "a v1 proof bundle", canon(v1), v, "malformed")
	n.add("not_json", kind, "non-JSON input", []byte("ratify"), v, "malformed")
}

func (g *gen) statusNegatives(n *negBuilder) {
	root, inter := g.k("root"), g.k("intermediate")
	v := verifyContext{BoundIssuerID: root.ID, StatusKey: "status_root"}
	_, list, lsig := g.list(g.k("status_root"), root.ID, 7, Now-60, Now+3600, "cert-a", "cert-b")
	kind := "revocation_list"
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(list, f), v, class)
	}
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("updated_at_after_max_timestamp", "updated_at = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["updated_at"] = num(maxTimestampV2 + 1) })
	m("updated_at_negative", "updated_at = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["updated_at"] = num(-1) })
	m("next_update_after_max_timestamp", "next_update = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["next_update"] = num(maxTimestampV2 + 1) })
	m("next_update_negative", "next_update = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["next_update"] = num(-1) })
	m("issuer_id_other", "issuer_id names a different issuer", "status_key_binding_mismatch", func(o map[string]any) { o["issuer_id"] = inter.ID })
	m("issuer_id_v1_128_bit", "issuer_id is a 128-bit v1 ID", "malformed", func(o map[string]any) { o["issuer_id"] = ratify.DeriveID(root.Pub) })
	m("updated_at_changed", "updated_at+1", "invalid_signature", func(o map[string]any) { o["updated_at"] = addNum(o["updated_at"], 1) })
	m("next_update_changed", "next_update+1", "invalid_signature", func(o map[string]any) { o["next_update"] = addNum(o["next_update"], 1) })
	m("sequence_changed", "sequence+1", "invalid_signature", func(o map[string]any) { o["sequence"] = addNum(o["sequence"], 1) })
	m("revoked_added", "revoked gains cert-z", "invalid_signature", func(o map[string]any) { o["revoked"] = append(arr(o["revoked"]), map[string]any{"cert_id": "cert-z"}) })
	m("revoked_removed", "revoked loses cert-b", "invalid_signature", func(o map[string]any) { o["revoked"] = arr(o["revoked"])[:1] })
	m("revoked_duplicate", "revoked repeats cert-a", "malformed", func(o map[string]any) { o["revoked"] = append(arr(o["revoked"]), map[string]any{"cert_id": "cert-a"}) })
	m("revoked_entry_extra_field", "revoked entry carries issuer_id", "malformed", func(o map[string]any) { obj(arr(o["revoked"])[0])["issuer_id"] = root.ID })
	m("sequence_zero", "sequence 0", "malformed", func(o map[string]any) { o["sequence"] = num(0) })
	m("next_update_not_after_updated_at", "next_update == updated_at", "malformed", func(o map[string]any) { o["next_update"] = o["updated_at"] })
	m("signature_ed25519_flipped", "Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("signature_mldsa_flipped", "ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("signed_by_unbound_status_key", "signed by another issuer's status key", "invalid_signature", func(o map[string]any) {
		o["signature"] = sigJSON(signDet(g.k("status_intermediate"), codeList, lsig.signable))
	})
	m("signed_by_issuer_delegation_key", "signed by the issuer's delegation key", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(signDet(root, codeList, lsig.signable)) })
	m("signed_as_push", "list body signed under code 0x0005", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(signDet(g.k("status_root"), codePush, lsig.signable)) })
	m("unknown_field", "unknown field", "malformed", func(o map[string]any) { o["epoch"] = num(1) })
	m("revoked_null", "revoked is null", "malformed", func(o map[string]any) { o["revoked"] = nil })

	_, push, psig := g.push(g.k("status_root"), root.ID, 8, Now-30, "cert-c")
	kind = "revocation_push"
	m = func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(push, f), v, class)
	}
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("pushed_at_after_max_timestamp", "pushed_at = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["pushed_at"] = num(maxTimestampV2 + 1) })
	m("pushed_at_negative", "pushed_at = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["pushed_at"] = num(-1) })
	m("issuer_id_other", "issuer_id names a different issuer", "status_key_binding_mismatch", func(o map[string]any) { o["issuer_id"] = inter.ID })
	m("pushed_at_changed", "pushed_at+1", "invalid_signature", func(o map[string]any) { o["pushed_at"] = addNum(o["pushed_at"], 1) })
	m("sequence_changed", "sequence+1", "invalid_signature", func(o map[string]any) { o["sequence"] = addNum(o["sequence"], 1) })
	m("revoked_changed", "revoked cert_id changed", "invalid_signature", func(o map[string]any) { obj(arr(o["revoked"])[0])["cert_id"] = "cert-d" })
	m("signature_ed25519_flipped", "Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("signature_mldsa_flipped", "ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("signed_as_list", "push body signed under code 0x0003", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(signDet(g.k("status_root"), codeList, psig.signable)) })
	m("next_update_field_added", "push carries a list-only field", "malformed", func(o map[string]any) { o["next_update"] = num(Now + 10) })
	m("sequence_negative", "sequence -1", "malformed", func(o map[string]any) { o["sequence"] = num(-1) })
}

// rotationBase returns the accepted genesis and the sequence-2 statement plus
// the caller state after genesis.
func (g *gen) rotationBase() (genesisWire []byte, genesisDigest []byte, nextWire []byte, state *RotationStateJSON) {
	_, gw, gs, _, _ := g.rotation(rotationSpec{sequence: 1, oldKey: g.k("rotation_genesis"), newKey: g.k("rotation_second")})
	digest := statementBodyDigest(codeRotationOld, gs)
	_, nw, _, _, _ := g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: g.k("rotation_second"), newKey: g.k("rotation_third")})
	state = &RotationStateJSON{AuthorityID: rotationAuthority, RecoveryEpoch: 1, Role: "issuer", Sequence: 1, HeadHashB64: b64(digest), CurrentKey: "rotation_second",
		UsedKeyIDs: []string{g.k("rotation_genesis").ID, g.k("rotation_second").ID}}
	return gw, digest, nw, state
}

func (g *gen) rotationNegatives(n *negBuilder) {
	_, digest, base, state := g.rotationBase()
	attacker, second, third := g.k("attacker"), g.k("rotation_second"), g.k("rotation_third")
	kind, v := "key_rotation_statement", verifyContext{RotationState: state, Now: Now, FutureSkew: 5}
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(base, f), v, class)
	}
	add := func(name, mutation, class string, wire []byte) { n.add(name, kind, mutation, wire, v, class) }
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("issued_at_after_max_timestamp", "issued_at = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["issued_at"] = num(maxTimestampV2 + 1) })
	m("issued_at_negative", "issued_at = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["issued_at"] = num(-1) })
	m("not_before_after_max_timestamp", "not_before = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["not_before"] = num(maxTimestampV2 + 1) })
	m("not_before_negative", "not_before = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["not_before"] = num(-1) })
	m("authority_uppercase", "authority_id uppercased", "malformed", func(o map[string]any) { o["authority_id"] = strings.ToUpper(rotationAuthority) })
	m("role_unknown", "role=admin", "malformed", func(o map[string]any) { o["role"] = "admin" })
	m("recovery_epoch_zero", "recovery_epoch 0", "malformed", func(o map[string]any) { o["recovery_epoch"] = num(0) })
	m("previous_hash_47_bytes", "previous_statement_hash is 47 bytes", "malformed", func(o map[string]any) { o["previous_statement_hash"] = b64(digest[:47]) })
	m("old_equals_new", "new key equals old key", "malformed", func(o map[string]any) { o["new_key"], o["new_key_id"] = o["old_key"], o["old_key_id"] })
	m("old_key_id_v1_128_bit", "old_key_id is a 128-bit v1 ID", "malformed", func(o map[string]any) { o["old_key_id"] = ratify.DeriveID(second.Pub) })
	m("old_key_id_mismatch", "old_key_id names another key", "key_id_mismatch", func(o map[string]any) { o["old_key_id"] = attacker.ID })
	m("new_key_id_mismatch", "new_key_id names another key", "key_id_mismatch", func(o map[string]any) { o["new_key_id"] = attacker.ID })
	m("issued_at_changed", "issued_at+1", "invalid_signature", func(o map[string]any) { o["issued_at"] = addNum(o["issued_at"], 1) })
	m("not_before_changed", "not_before+1", "invalid_signature", func(o map[string]any) { o["not_before"] = addNum(o["not_before"], 1) })
	m("old_signature_ed25519_flipped", "old_signature Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["old_signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("old_signature_mldsa_flipped", "old_signature ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["old_signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("new_signature_ed25519_flipped", "new_signature Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["new_signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("new_signature_mldsa_flipped", "new_signature ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["new_signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("signatures_swapped", "old_signature and new_signature swapped", "invalid_signature", func(o map[string]any) {
		o["old_signature"], o["new_signature"] = o["new_signature"], o["old_signature"]
	})
	m("new_signature_missing", "new_signature removed (stripped signature)", "malformed", func(o map[string]any) { delete(o, "new_signature") })
	m("authority_changed", "authority_id names another authority", "rotation_state_mismatch", func(o map[string]any) { o["authority_id"] = "fedcba9876543210fedcba9876543210" })
	m("recovery_epoch_changed", "recovery_epoch+1", "rotation_state_mismatch", func(o map[string]any) { o["recovery_epoch"] = addNum(o["recovery_epoch"], 1) })
	m("role_changed", "role=agent", "rotation_state_mismatch", func(o map[string]any) { o["role"] = "agent" })
	m("sequence_skipped", "sequence 3 after head 1", "rotation_state_mismatch", func(o map[string]any) { o["sequence"] = num(3) })
	m("previous_hash_flipped", "previous_statement_hash does not equal the stored head", "rotation_state_mismatch", func(o map[string]any) { o["previous_statement_hash"] = flipB64(o["previous_statement_hash"]) })

	_, w, _, _, _ := g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: attacker, newKey: third})
	add("old_key_substitution", "validly signed statement whose old key is not the caller's current key", "rotation_state_mismatch", w)
	_, w, _, _, _ = g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: second, newKey: attacker, newSigner: third})
	add("new_key_proof_failure", "new key replaced; new_signature made by a different key", "invalid_signature", w)
	_, w, _, _, _ = g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: second, newKey: third, newCode: codeRotationOld})
	add("new_signature_under_0x0004", "new key signs code 0x0004 instead of 0x0009", "invalid_signature", w)
	_, w, _, _, _ = g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: second, newKey: third, oldCode: codeRotationNew})
	add("old_signature_under_0x0009", "old key signs code 0x0009 instead of 0x0004", "invalid_signature", w)
	_, w, _, _, _ = g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: second, newKey: g.k("rotation_genesis")})
	add("new_key_reused", "new key already appears in retained rotation history", "rotation_key_reused", w)
	_, w, _, _, _ = g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: second, newKey: third, issuedAt: Now + 1000})
	add("issued_at_future", "issued_at beyond now + skew", "rotation_future_dated", w)
	_, w, _, _, _ = g.rotation(rotationSpec{sequence: 2, prev: digest, oldKey: second, newKey: third, notBefore: Now + 1000})
	add("not_before_future", "not_before beyond now + skew", "rotation_future_dated", w)
}

func (g *gen) witnessNegatives(n *negBuilder) {
	witness, attacker := g.k("witness"), g.k("attacker")
	_, base, sg := g.witness(witness, witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	kind, v := "witness_entry", verifyContext{WitnessKey: "witness", Head: genesisHead(witnessLogA, "")}
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(base, f), v, class)
	}
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("timestamp_after_max_timestamp", "timestamp = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["timestamp"] = num(maxTimestampV2 + 1) })
	m("timestamp_negative", "timestamp = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["timestamp"] = num(-1) })
	m("cross_log_replay", "log_id of another log (signature valid for that log)", "log_state_mismatch", func(o map[string]any) { o["log_id"] = witnessLogB })
	m("log_id_31_chars", "log_id has 31 characters", "malformed", func(o map[string]any) { o["log_id"] = witnessLogA[:31] })
	m("genesis_nonzero_prev", "sequence 1 with a non-zero prev_hash", "malformed", func(o map[string]any) { o["prev_hash"] = b64(append([]byte{1}, make([]byte, 47)...)) })
	m("non_genesis_zero_prev", "sequence 2 with a zero prev_hash", "malformed", func(o map[string]any) { o["sequence"] = num(2) })
	m("entry_data_changed", "entry_data bit flip", "invalid_signature", func(o map[string]any) { o["entry_data"] = flipB64(o["entry_data"]) })
	m("entry_data_null", "entry_data null", "malformed", func(o map[string]any) { o["entry_data"] = nil })
	m("timestamp_changed", "timestamp+1", "invalid_signature", func(o map[string]any) { o["timestamp"] = addNum(o["timestamp"], 1) })
	m("witness_id_other_key", "witness_id names another key", "log_state_mismatch", func(o map[string]any) { o["witness_id"] = attacker.ID })
	m("witness_id_uppercase", "witness_id uppercased", "malformed", func(o map[string]any) { o["witness_id"] = strings.ToUpper(witness.ID) })
	m("witness_id_v1_128_bit", "witness_id is a 128-bit v1 ID", "malformed", func(o map[string]any) { o["witness_id"] = ratify.DeriveID(witness.Pub) })
	m("signature_ed25519_flipped", "Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("signature_mldsa_flipped", "ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("signed_by_other_key", "witness_id unchanged; signed by another key", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(signDet(attacker, codeWitness, sg.signable)) })
	m("signed_as_receipt", "signed under code 0x0008", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(signDet(witness, codeReceipt, sg.signable)) })
}

func (g *gen) transactionNegatives(n *negBuilder) {
	tx := g.txFixture()
	base := tx.wire
	kind, v := "transaction_receipt", verifyContext{}
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(base, f), v, class)
	}
	party := func(o map[string]any, i int) map[string]any { return obj(arr(o["parties"])[i]) }
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("created_at_after_max_timestamp", "created_at = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["created_at"] = num(maxTimestampV2 + 1) })
	m("created_at_negative", "created_at = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["created_at"] = num(-1) })
	m("transaction_id_changed", "transaction_id changed; bundles bind the old transaction context", "transaction_context_mismatch", func(o map[string]any) { o["transaction_id"] = "tx-0002" })
	m("terms_changed", "terms_canonical_json amount changed", "transaction_context_mismatch", func(o map[string]any) {
		o["terms_canonical_json"] = b64([]byte(`{"amount":101,"currency":"USD","item":"widget"}`))
	})
	m("terms_noncanonical", "terms_canonical_json contains insignificant whitespace", "malformed", func(o map[string]any) {
		o["terms_canonical_json"] = b64([]byte(`{"amount": 100,"currency":"USD","item":"widget"}`))
	})
	// SPEC-v2 §5.7: the terms are one JSON object. A canonical value of any
	// other kind is malformed at decode, before any context binding.
	for _, t := range []struct{ name, terms string }{
		{"integer", `1`}, {"string", `"x"`}, {"null", `null`}, {"boolean", `true`}, {"array", `[1,2]`}, {"empty_array", `[]`},
	} {
		m("terms_not_object_"+t.name, "terms_canonical_json is the canonical JSON "+t.name+" "+t.terms+", not an object", "malformed", func(o map[string]any) {
			o["terms_canonical_json"] = b64([]byte(t.terms))
		})
	}
	// SPEC-v2 §5.7, §2.7: a party proof_bundle_hash that is not sha384:
	// followed by 96 lowercase hex characters is a shape failure (malformed),
	// checked before the hash is compared. Both party signatures are
	// recomputed over the altered value, so only the shape is at fault.
	resigned := func(name, mutation string, edit func(hash string) string) {
		o := parse(base).(map[string]any)
		pa := party(o, 0)
		pa["proof_bundle_hash"] = edit(pa["proof_bundle_hash"].(string))
		signable := mutate(canon(o), func(v map[string]any) {
			delete(v, "party_signatures")
			for _, p := range arr(v["parties"]) {
				delete(obj(p), "proof_bundle")
			}
		})
		for i, signer := range []*Key{g.k("agent"), g.k("party_b_agent")} {
			obj(arr(o["party_signatures"])[i])["signature"] = sigJSON(signDet(signer, codeParty, signable))
		}
		n.add(name, kind, mutation, canon(o), v, "malformed")
	}
	resigned("party_bundle_hash_uppercase_hex", "parties[0].proof_bundle_hash with its hex digits uppercased; party signatures recomputed", func(h string) string {
		return "sha384:" + strings.ToUpper(strings.TrimPrefix(h, "sha384:"))
	})
	resigned("party_bundle_hash_uppercase_prefix", "parties[0].proof_bundle_hash with the prefix spelled SHA384:; party signatures recomputed", func(h string) string {
		return "SHA384:" + strings.TrimPrefix(h, "sha384:")
	})
	resigned("party_bundle_hash_short", "parties[0].proof_bundle_hash with 95 hex characters; party signatures recomputed", func(h string) string { return h[:len(h)-1] })
	resigned("party_bundle_hash_non_hex", "parties[0].proof_bundle_hash whose last character is g; party signatures recomputed", func(h string) string { return h[:len(h)-1] + "g" })
	m("terms_schema_changed", "terms_schema_uri changed", "transaction_context_mismatch", func(o map[string]any) { o["terms_schema_uri"] = "https://example.com/terms/purchase/v2" })
	m("created_at_changed", "created_at+1", "invalid_signature", func(o map[string]any) { o["created_at"] = addNum(o["created_at"], 1) })
	m("party_role_changed", "parties[0].role changed", "invalid_signature", func(o map[string]any) { party(o, 0)["role"] = "approver" })
	m("party_required_scope_changed", "parties[0].required_scope changed to another valid scope", "transaction_context_mismatch", func(o map[string]any) { party(o, 0)["required_scope"] = "transact:sell" })
	m("party_required_scope_wildcard", "parties[0].required_scope is a wildcard", "malformed", func(o map[string]any) { party(o, 0)["required_scope"] = "transact:*" })
	m("party_session_changed", "parties[0].session_id changed", "transaction_context_mismatch", func(o map[string]any) { party(o, 0)["session_id"] = "session-x" })
	m("party_invocation_changed", "parties[1].invocation_id changed", "transaction_context_mismatch", func(o map[string]any) { party(o, 1)["invocation_id"] = "invocation-x" })
	m("bundle_hash_flipped", "parties[0].proof_bundle_hash changed", "bundle_hash_mismatch", func(o map[string]any) {
		party(o, 0)["proof_bundle_hash"] = flipHexDigest(party(o, 0)["proof_bundle_hash"].(string))
	})
	m("bundle_tampered", "parties[1].proof_bundle.challenge changed", "bundle_hash_mismatch", func(o map[string]any) {
		b := obj(party(o, 1)["proof_bundle"])
		b["challenge"] = flipB64(b["challenge"])
	})
	// A malformed nested bundle is malformed, never bundle_hash_mismatch:
	// the bundle is strictly decoded, and must be canonical, before its
	// hash is compared (SPEC-v2 §2.1, §5.7). Party signatures cover only
	// proof_bundle_hash, so they stay valid.
	m("bundle_byte_string_as_number_array", "parties[0].proof_bundle.agent_pub_key.ed25519 spelled as an array of its byte values; proof_bundle_hash still names the canonical bundle", "malformed", func(o map[string]any) {
		key := obj(obj(party(o, 0)["proof_bundle"])["agent_pub_key"])
		raw := must(base64.StdEncoding.DecodeString(key["ed25519"].(string)))
		values := make([]any, len(raw))
		for i, b := range raw {
			values[i] = num(int64(b))
		}
		key["ed25519"] = values
	})
	m("bundle_digest_base64url", "parties[0].proof_bundle.delegation_digest in base64url; proof_bundle_hash still names the canonical bundle", "malformed", func(o map[string]any) {
		b := obj(party(o, 0)["proof_bundle"])
		std := b["delegation_digest"].(string)
		b["delegation_digest"] = base64.URLEncoding.EncodeToString(must(base64.StdEncoding.DecodeString(std)))
		if b["delegation_digest"] == std {
			panic("delegation_digest has no base64url-specific character")
		}
	})
	whitespace := bytes.Replace(base, []byte(`"proof_bundle":{`), []byte(`"proof_bundle":{ `), 1)
	n.add("bundle_whitespace", kind, "a space after the opening brace of parties[0].proof_bundle; the bundle decodes semantically but is not canonical", whitespace, v, "malformed")
	m("parties_unsorted", "parties order reversed", "malformed", func(o map[string]any) { p := arr(o["parties"]); p[0], p[1] = p[1], p[0] })
	m("agent_represents_two_parties", "parties[1] reuses parties[0]'s agent", "malformed", func(o map[string]any) {
		party(o, 1)["agent_id"], party(o, 1)["agent_pub_key"] = party(o, 0)["agent_id"], party(o, 0)["agent_pub_key"]
	})
	m("signature_missing", "party-b signature removed", "transaction_signature_set_invalid", func(o map[string]any) { o["party_signatures"] = arr(o["party_signatures"])[:1] })
	m("signature_duplicate", "party-a signature repeated in place of party-b", "transaction_signature_set_invalid", func(o map[string]any) { s := arr(o["party_signatures"]); s[1] = s[0] })
	m("signature_unknown_party", "signature names an unlisted party", "transaction_signature_set_invalid", func(o map[string]any) { obj(arr(o["party_signatures"])[1])["party_id"] = "party-z" })
	m("signature_flipped", "party-a ML-DSA bit flip", "invalid_signature", func(o map[string]any) {
		s := obj(obj(arr(o["party_signatures"])[0])["signature"])
		s["ml_dsa_65"] = flipB64(s["ml_dsa_65"])
	})
	m("signatures_swapped_between_parties", "party signature objects exchanged", "invalid_signature", func(o map[string]any) {
		s := arr(o["party_signatures"])
		a, b := obj(s[0]), obj(s[1])
		a["signature"], b["signature"] = b["signature"], a["signature"]
	})
	m("signed_as_receipt", "party-a signs code 0x0008", "invalid_signature", func(o map[string]any) {
		obj(arr(o["party_signatures"])[0])["signature"] = sigJSON(signDet(g.k("agent"), codeReceipt, tx.signable))
	})
	// Party binding failures (SPEC-v2 §5.7): party-b's bundle is replaced
	// by a validly signed bundle that does not belong to its signed party;
	// its proof_bundle_hash and both party signatures are recomputed, so
	// only the binding fails.
	variant := func(name, mutation string, spec bundleSpec) {
		_, bwire, _ := g.bundle(spec)
		o := parse(base).(map[string]any)
		pb := party(o, 1)
		pb["proof_bundle"], pb["proof_bundle_hash"] = parse(bwire), bundleHash(bwire)
		signable := mutate(canon(o), func(v map[string]any) {
			delete(v, "party_signatures")
			for _, p := range arr(v["parties"]) {
				delete(obj(p), "proof_bundle")
			}
		})
		for i, signer := range []*Key{g.k("agent"), g.k("party_b_agent")} {
			obj(arr(o["party_signatures"])[i])["signature"] = sigJSON(signDet(signer, codeParty, signable))
		}
		n.add(name, kind, mutation, canon(o), v, "transaction_party_mismatch")
	}
	bAgent := g.k("party_b_agent")
	bCtx := tx.partyCtx["party-b"]
	variant("party_bundle_empty_delegations", "party-b presents a validly signed proof bundle with no delegation certificates; its hash and both party signatures are consistent",
		bundleSpec{agent: bAgent, session: bCtx})
	bCert, _, _ := g.cert(certSpec{issuer: g.k("party_b_root"), subject: bAgent, certID: "cert-party-b", scope: []string{"transact:sell"}})
	variant("party_bundle_other_verifier", "party-b's proof bundle names another verifier_id than its party entry; its hash and both party signatures are consistent",
		bundleSpec{agent: bAgent, certs: []ratify.DelegationCertV2{bCert}, session: bCtx, verifierID: g.k("attacker").ID})
}

func (g *gen) receiptNegatives(n *negBuilder) {
	verifier, attacker := g.k("verifier"), g.k("attacker")
	body := g.receiptFixtureBody()
	_, base, sg := g.receipt(verifier, body, receiptLogA, 1, make([]byte, 48), 0)
	kind, v := "verification_receipt", verifyContext{VerifierKey: "verifier", Head: genesisHead(receiptLogA, verifier.ID)}
	m := func(name, mutation, class string, f func(map[string]any)) {
		n.add(name, kind, mutation, mutate(base, f), v, class)
	}
	m("version_1", "version=1", "malformed", func(o map[string]any) { o["version"] = num(1) })
	m("verified_at_after_max_timestamp", "verified_at = 253402300800, one past the v2 timestamp bound", "malformed", func(o map[string]any) { o["verified_at"] = num(maxTimestampV2 + 1) })
	m("verified_at_negative", "verified_at = -1, below the v2 timestamp bound", "malformed", func(o map[string]any) { o["verified_at"] = num(-1) })
	m("log_id_other", "log_id of another log", "log_state_mismatch", func(o map[string]any) { o["log_id"] = "dddddddddddddddddddddddddddddd02" })
	m("verifier_id_other", "verifier_id names another key", "log_state_mismatch", func(o map[string]any) { o["verifier_id"] = attacker.ID })
	m("genesis_nonzero_previous", "sequence 1 with a non-zero previous_receipt_hash", "malformed", func(o map[string]any) { o["previous_receipt_hash"] = b64(append([]byte{1}, make([]byte, 47)...)) })
	m("bundle_hash_changed", "bundle_hash bit flip", "invalid_signature", func(o map[string]any) { o["bundle_hash"] = flipHexDigest(o["bundle_hash"].(string)) })
	m("verified_at_changed", "verified_at+1", "invalid_signature", func(o map[string]any) { o["verified_at"] = addNum(o["verified_at"], 1) })
	m("context_policy_digest_changed", "context_policy_digest bit flip", "invalid_signature", func(o map[string]any) {
		o["context_policy_digest"] = flipHexDigest(o["context_policy_digest"].(string))
	})
	m("evidence_digest_changed", "status evidence digest bit flip", "invalid_signature", func(o map[string]any) {
		e := obj(arr(o["status_evidence_digests"])[0])
		e["digest"] = flipHexDigest(e["digest"].(string))
	})
	m("agent_id_changed", "agent_id names another key", "invalid_signature", func(o map[string]any) { o["agent_id"] = attacker.ID })
	m("agent_id_removed", "optional agent_id removed", "invalid_signature", func(o map[string]any) { delete(o, "agent_id") })
	// constraint_evaluators (SPEC-v2 §5.8): optional, signed, non-empty when
	// present, sorted and unique by type, registrable extension types only.
	ref := func(kind, digest string) map[string]any {
		return map[string]any{"profile_digest": digest, "type": kind}
	}
	countRef, allowedRef := ref(maxCountType, profileDigest(maxCountProfile, maxCountType)), ref(allowedType, profileDigest(allowedProfile, allowedType))
	m("constraint_evaluators_added", "a valid constraint_evaluators member added after signing", "invalid_signature", func(o map[string]any) { o["constraint_evaluators"] = []any{countRef} })
	m("constraint_evaluators_empty", "constraint_evaluators present but empty (absence is the only empty form)", "malformed", func(o map[string]any) { o["constraint_evaluators"] = []any{} })
	m("constraint_evaluators_unsorted", "constraint_evaluators not sorted by type", "malformed", func(o map[string]any) { o["constraint_evaluators"] = []any{countRef, allowedRef} })
	m("constraint_evaluators_duplicate_type", "constraint_evaluators repeats a type", "malformed", func(o map[string]any) { o["constraint_evaluators"] = []any{countRef, countRef} })
	m("constraint_evaluators_bad_digest", "constraint_evaluators profile_digest is not sha384: and 96 lowercase hex", "malformed", func(o map[string]any) {
		o["constraint_evaluators"] = []any{ref(maxCountType, "sha256:"+strings.Repeat("a", 64))}
	})
	m("constraint_evaluators_registered_type", "constraint_evaluators names a closed-registry type", "malformed", func(o map[string]any) {
		o["constraint_evaluators"] = []any{ref("max_rate", profileDigest(maxCountProfile, maxCountType))}
	})
	m("constraint_evaluators_extra_member", "constraint_evaluators entry carries an extra member", "malformed", func(o map[string]any) {
		e := ref(maxCountType, profileDigest(maxCountProfile, maxCountType))
		e["profile"] = maxCountProfile
		o["constraint_evaluators"] = []any{e}
	})
	m("human_id_added", "optional human_id added", "invalid_signature", func(o map[string]any) { o["human_id"] = "user-1" })
	m("human_id_empty", "human_id is empty", "malformed", func(o map[string]any) { o["human_id"] = "" })
	m("decision_changed", "decision=deny with granted scope", "malformed", func(o map[string]any) { o["decision"] = "deny" })
	m("reason_unknown", "decision_reason=approved", "malformed", func(o map[string]any) { o["decision_reason"] = "approved" })
	m("challenge_freshness_unverified", "challenge_assessment=freshness_unverified", "malformed", func(o map[string]any) { o["challenge_assessment"] = "freshness_unverified" })
	m("allow_status_unavailable", "allow with status_assessment=unavailable", "malformed", func(o map[string]any) { o["status_assessment"] = "unavailable" })
	m("allow_trust_untrusted", "allow with trust_assessment=untrusted", "malformed", func(o map[string]any) { o["trust_assessment"] = "untrusted" })
	m("allow_context_unbound", "allow with context_assessment=unbound and no policy digest", "malformed", func(o map[string]any) { o["context_assessment"], o["context_policy_digest"] = "unbound", nil })
	m("allow_policy_digest_null", "allow with bound context but null policy digest", "malformed", func(o map[string]any) { o["context_policy_digest"] = nil })
	m("allow_without_evidence", "allow with empty status evidence", "malformed", func(o map[string]any) { o["status_evidence_digests"] = []any{} })
	m("granted_scope_missing_required", "granted_scope omits required_scope", "malformed", func(o map[string]any) { o["granted_scope"] = []any{"files:read"} })
	m("granted_scope_unsorted", "granted_scope not sorted", "malformed", func(o map[string]any) { o["granted_scope"] = []any{"files:read", "data:read"} })
	m("granted_scope_wildcard", "granted_scope contains data:*", "malformed", func(o map[string]any) { o["granted_scope"] = []any{"data:*", "data:read"} })
	m("required_scope_wildcard", "required_scope=data:*", "malformed", func(o map[string]any) { o["required_scope"] = "data:*" })
	m("required_scope_custom_wildcard", "required_scope=custom:* (an exact custom: scope is valid; custom:* never is)", "malformed", func(o map[string]any) { o["required_scope"] = "custom:*" })
	m("required_scope_custom_bare_prefix", "required_scope=custom: with no name", "malformed", func(o map[string]any) { o["required_scope"] = "custom:" })
	m("issuer_ids_unsorted", "issuer_ids reversed", "malformed", func(o map[string]any) { s := arr(o["issuer_ids"]); s[0], s[1] = s[1], s[0] })
	m("evidence_unsorted", "status evidence reversed", "malformed", func(o map[string]any) { s := arr(o["status_evidence_digests"]); s[0], s[1] = s[1], s[0] })
	m("evidence_bad_object_code", "status evidence object_type_code=4", "malformed", func(o map[string]any) { obj(arr(o["status_evidence_digests"])[0])["object_type_code"] = num(4) })
	m("evidence_extra_field", "status evidence entry carries an extra field", "malformed", func(o map[string]any) { obj(arr(o["status_evidence_digests"])[0])["status"] = "current" })
	m("signature_ed25519_flipped", "Ed25519 bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ed25519"] = flipB64(s["ed25519"]) })
	m("signature_mldsa_flipped", "ML-DSA bit flip", "invalid_signature", func(o map[string]any) { s := obj(o["signature"]); s["ml_dsa_65"] = flipB64(s["ml_dsa_65"]) })
	m("key_substitution", "verifier_id unchanged; signed by another key", "invalid_signature", func(o map[string]any) { o["signature"] = sigJSON(signDet(attacker, codeReceipt, sg.signable)) })
	m("unknown_field", "unknown field", "malformed", func(o map[string]any) { o["released"] = true })

	// Receipt and bundle binding.
	agent := g.k("agent")
	_, bundleWire, _ := g.bundle(bundleSpec{agent: agent, certs: g.chain(chainSpec{}), session: g.fixtureSessionContext(agent)})
	_, emptyWire, _ := g.bundle(bundleSpec{agent: agent})
	bind := func(name, mutation string, receiptWire, bwire []byte) {
		n.out = append(n.out, negativeVector{Name: "receipt_bundle_binding/" + name, Kind: "receipt_bundle_binding", Mutation: mutation, WireB64: b64(receiptWire), BundleB64: b64(bwire), ExpectedErrorClass: "receipt_bundle_mismatch"})
	}
	bind("bundle_hash_other_bundle", "receipt presented with a different bundle (same agent and verifier)", base, emptyWire)
	_, otherVerifierBundle, _ := g.bundle(bundleSpec{agent: agent, certs: g.chain(chainSpec{}), session: g.fixtureSessionContext(agent), verifierID: attacker.ID})
	bind("verifier_audience_mismatch", "bundle names a different verifier_id", base, otherVerifierBundle)
	issuerBody := *body
	issuerBody.IssuerIDs = []string{g.k("root").ID}
	issuerBody.StatusEvidence = toLibEvidence([]EvidenceJSON{g.evidence(g.statusFixtures()["root_current"])})
	_, issuerWire, _ := g.receipt(verifier, &issuerBody, receiptLogA, 1, make([]byte, 48), 0)
	bind("issuer_ids_mismatch", "receipt issuer_ids omit a chain issuer", issuerWire, bundleWire)
}

// canonicalOnlyNegatives covers the decoders SPEC-v2 §2.1 names as
// canonical-only (witness entry, verification receipt, transaction receipt):
// an equivalent but non-canonical spelling is malformed, even though a
// semantic decoder would read the same signed value from it.
func (g *gen) canonicalOnlyNegatives(n *negBuilder) {
	verifier := g.k("verifier")
	_, witnessWire, _ := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	_, receiptWire, _ := g.receipt(verifier, g.receiptFixtureBody(), receiptLogA, 1, make([]byte, 48), 0)
	for _, c := range []struct {
		kind, stringMember string
		base               []byte
		verify             verifyContext
	}{
		{"witness_entry", "log_id", witnessWire, verifyContext{WitnessKey: "witness", Head: genesisHead(witnessLogA, "")}},
		{"verification_receipt", "log_id", receiptWire, verifyContext{VerifierKey: "verifier", Head: genesisHead(receiptLogA, verifier.ID)}},
		{"transaction_receipt", "transaction_id", g.txFixture().wire, verifyContext{}},
	} {
		add := func(name, mutation string, wire []byte) {
			if bytes.Equal(wire, c.base) {
				panic(c.kind + "/" + name + " did not change the canonical wire")
			}
			n.add("noncanonical_"+name, c.kind, mutation, wire, c.verify, "malformed")
		}
		// The top-level version member is the last "version" in each wire.
		at := bytes.LastIndex(c.base, []byte(`,"version":2`))
		if at < 0 {
			panic(c.kind + " has no top-level version member after another member")
		}
		reordered := append([]byte(`{"version":2,`), c.base[1:at]...)
		reordered = append(reordered, c.base[at+len(`,"version":2`):]...)
		escapedName := append(bytes.Clone(c.base[:at+1]), []byte(`"versio\u006e"`)...)
		escapedName = append(escapedName, c.base[at+1+len(`"version"`):]...)
		value := bytes.Index(c.base, []byte(`"`+c.stringMember+`":"`)) + len(`"`+c.stringMember+`":"`)
		escapedValue := append(bytes.Clone(c.base[:value]), []byte(fmt.Sprintf(`\u%04x`, c.base[value]))...)
		escapedValue = append(escapedValue, c.base[value+1:]...)
		add("trailing_newline", "the canonical wire followed by one newline byte", append(bytes.Clone(c.base), '\n'))
		add("leading_space", "one space before the canonical wire", append([]byte(" "), c.base...))
		add("members_reordered", "the top-level version member moved first", reordered)
		add("escaped_member_name", "the top-level member name version spelled with a \\u006e escape", escapedName)
		add("escaped_value", "the first character of "+c.stringMember+" spelled as a \\u escape", escapedValue)
	}
}
