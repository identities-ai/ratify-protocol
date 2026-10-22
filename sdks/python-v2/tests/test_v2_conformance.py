"""Protocol v2 object conformance: keys, objects, single-fault negatives, the
witness and receipt log sequences, rotation journals, and the hand-maintained
primitive vectors.

Files consumed: "keys.json", "objects.json", "object-negatives.json",
"log-sequences.json", "rotation-sequences.json", "delegation-signature.json",
"operation-session-context.json", "challenge-claim.json",
"key-rotation-signature.json", and "derive-external-mu.py".

Positive vectors are reproduced byte for byte; negatives must fail with the
exact error class. Verification is pure Python. Re-deriving keys from seeds
and re-signing with the typed signers need the native extension (the only
signer); those tests skip only when it is absent and RATIFY_REQUIRE_NATIVE is
unset.
"""
from __future__ import annotations

import base64
import hashlib
import subprocess
import sys

import pytest

from corpus import V2_DIR, b64, load, pubkey, sig
from ratify_protocol_v2 import _mldsa65, _native, _v2json
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import transaction_receipt_v2 as txv2
from ratify_protocol_v2 import verification_receipt_v2 as vrv2
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2._testing import deterministic_test_vector_signing
from ratify_protocol_v2.challenge_claim_v2 import challenge_claim_digest_v2, protocol_claim_id_v2
from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.operation_context_v2 import (
    decode_payload_digest,
    operation_context_v2_hash,
    session_context_v2_hash,
)
from ratify_protocol_v2.scope import validate_required_scope_v2
from ratify_protocol_v2.signing_v2 import (
    external_mu_v2,
    key_id_v2,
    key_id_v2_classified,
    keypair_from_seeds_v2,
    mldsa_context_v2,
    signing_message_v2,
    verify_v2_statement,
)
from ratify_protocol_v2.types import HybridPublicKey, HybridSignature

requires_native = pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")


def derive_id(pub: HybridPublicKey) -> str:
    """The v1 128-bit key ID of the same key, for v1/v2 aliasing checks."""
    return hashlib.sha256(bytes(pub.ed25519) + bytes(pub.ml_dsa_65)).hexdigest()[:32]


KEYS = load("keys.json")
PUB = {k["name"]: pubkey(k["public_key"]) for k in KEYS["keys"]}
KEY_ID = {k["name"]: k["key_id_v2"] for k in KEYS["keys"]}
_PRIV_CACHE: dict = {}


def private_key(name: str):
    if name not in _PRIV_CACHE:
        entry = next(k for k in KEYS["keys"] if k["name"] == name)
        _PRIV_CACHE[name] = keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]),
                                                  bytes.fromhex(entry["ml_dsa_65_seed_hex"]))[1]
    return _PRIV_CACHE[name]


# ---------------------------------------------------------------------------
# keys.json


@pytest.mark.parametrize("entry", KEYS["keys"], ids=lambda e: e["name"])
def test_keys(entry):
    pub = pubkey(entry["public_key"])
    independent = hashlib.sha256(b"ratify-key-id-v2\x00" + pub.ed25519 + pub.ml_dsa_65).hexdigest()
    assert key_id_v2(pub) == key_id_v2_classified(pub) == entry["key_id_v2"] == independent
    assert derive_id(pub) == entry["v1_key_id_128"] != entry["key_id_v2"][:32]


def test_key_id_v2_rejects_incomplete_keys_as_malformed():
    pub = PUB["root"]
    for bad in (HybridPublicKey(pub.ed25519[:31], pub.ml_dsa_65), HybridPublicKey(pub.ed25519, pub.ml_dsa_65[:-1])):
        with pytest.raises(Exception) as info:
            key_id_v2_classified(bad)
        assert error_class_of(info.value) == "malformed"


@requires_native
@pytest.mark.parametrize("entry", KEYS["keys"], ids=lambda e: e["name"])
def test_keys_derive_from_seeds(entry):
    pub, _ = keypair_from_seeds_v2(bytes.fromhex(entry["ed25519_seed_hex"]), bytes.fromhex(entry["ml_dsa_65_seed_hex"]))
    assert pub == pubkey(entry["public_key"]), "seeds do not derive the pinned public key"


def _set_top_level_string(wire: bytes, name: str, value: str) -> bytes:
    obj = _v2json.parse(wire)
    obj[name] = value
    return _v2json.canonical(obj)


OBJECTS = load("objects.json")


def _object_by_kind(kind: str) -> dict:
    return next(o for o in OBJECTS["objects"] if o["kind"] == kind)


@pytest.mark.parametrize("bad", KEYS["invalid_v2_key_ids"], ids=lambda e: e["name"])
def test_invalid_key_ids(bad):
    bundle_wire = b64(_object_by_kind("proof_bundle")["wire_b64"])
    witness_wire = b64(_object_by_kind("witness_entry")["wire_b64"])
    receipt_wire = b64(_object_by_kind("verification_receipt")["wire_b64"])
    for decode, wire, name in ((pv2.decode_proof_bundle_v2, bundle_wire, "verifier_id"),
                               (pv2.decode_proof_bundle_v2, bundle_wire, "agent_id"),
                               (wv2.decode_witness_entry_v2, witness_wire, "witness_id"),
                               (vrv2.decode_verification_receipt_v2, receipt_wire, "verifier_id")):
        with pytest.raises(Exception) as info:
            decode(_set_top_level_string(wire, name, bad["value"]))
        assert error_class_of(info.value) == bad["expected_error_class"], (name, info.value)


# ---------------------------------------------------------------------------
# objects.json and object-negatives.json


def _head(h: dict) -> dict:
    return dict(log_id=h["log_id"], sequence=h["sequence"], head_hash=b64(h["head_hash_b64"]),
                accepted_digests={int(k): b64(v) for k, v in h["accepted_digests_b64"].items()}, frozen=h["frozen"])


def _rotation_state(rs: dict) -> kr.KeyRotationV2State:
    return kr.KeyRotationV2State(rs["authority_id"], rs["recovery_epoch"], rs["role"], rs["sequence"],
                                 b64(rs["head_hash_b64"]), PUB[rs["current_key"]], list(rs["used_key_ids"]))


def verify_object(kind: str, wire: bytes, bundle_wire, v: dict, pub=PUB):
    """The per-kind procedure of object-negatives.json procedure_by_kind."""
    if kind == "delegation_certificate":
        return pv2.verify_delegation_cert_v2_signature(pv2.decode_delegation_cert_v2(wire))
    if kind == "proof_bundle":
        return pv2.verify_proof_bundle_v2_signatures(pv2.decode_proof_bundle_v2(wire))
    if kind == "revocation_list":
        return pv2.verify_revocation_list_v2_signature(pv2.decode_revocation_list_v2(wire), v["bound_issuer_id"],
                                                       pub[v["status_key"]])
    if kind == "revocation_push":
        return pv2.verify_revocation_push_v2_signature(pv2.decode_revocation_push_v2(wire), v["bound_issuer_id"],
                                                       pub[v["status_key"]])
    if kind == "key_rotation_statement":
        rs = dict(v["rotation_state"])
        state = kr.KeyRotationV2State(rs["authority_id"], rs["recovery_epoch"], rs["role"], rs["sequence"],
                                      b64(rs["head_hash_b64"]), pub[rs["current_key"]], list(rs["used_key_ids"]))
        return kr.verify_key_rotation_statement_v2(kr.decode_key_rotation_statement_v2(wire), state, v["now"],
                                                   v["future_skew_seconds"])
    if kind == "witness_entry":
        return wv2.verify_witness_entry_v2(wv2.decode_witness_entry_v2(wire), wv2.WitnessV2Head(**_head(v["head"])),
                                           pub[v["witness_key"]])
    if kind == "transaction_receipt":
        return txv2.verify_transaction_receipt_v2_signatures(txv2.decode_transaction_receipt_v2(wire))
    if kind == "verification_receipt":
        head = vrv2.ReceiptV2Head(verifier_id=v["head"]["verifier_id"], **_head(v["head"]))
        return vrv2.verify_verification_receipt_v2(vrv2.decode_verification_receipt_v2(wire), pub[v["verifier_key"]], head)
    if kind == "receipt_bundle_binding":
        return vrv2.check_verification_receipt_v2_bundle_binding(vrv2.decode_verification_receipt_v2(wire),
                                                                 pv2.decode_proof_bundle_v2(bundle_wire))
    pytest.fail(f"unknown vector kind {kind!r}")


CODECS = {
    "delegation_certificate": (pv2.decode_delegation_cert_v2, pv2.encode_delegation_cert_v2),
    "proof_bundle": (pv2.decode_proof_bundle_v2, pv2.encode_proof_bundle_v2),
    "revocation_list": (pv2.decode_revocation_list_v2, pv2.encode_revocation_list_v2),
    "revocation_push": (pv2.decode_revocation_push_v2, pv2.encode_revocation_push_v2),
    "key_rotation_statement": (kr.decode_key_rotation_statement_v2, kr.encode_key_rotation_statement_v2),
    "witness_entry": (wv2.decode_witness_entry_v2, wv2.encode_witness_entry_v2),
    "transaction_receipt": (txv2.decode_transaction_receipt_v2, txv2.encode_transaction_receipt_v2),
    "verification_receipt": (vrv2.decode_verification_receipt_v2, vrv2.encode_verification_receipt_v2),
}


def projection(wire: bytes, name: str) -> bytes:
    obj = _v2json.parse(wire)

    def drop(*names):
        for n in names:
            obj.pop(n, None)
        return _v2json.canonical(obj)

    if name == "signature":
        return drop("signature")
    if name == "challenge_sig":
        return drop("delegations", "challenge_sig")
    if name in ("old_signature", "new_signature"):
        return drop("old_signature", "new_signature")
    if name.startswith("delegations["):
        index = int(name[len("delegations["):].split("]")[0])
        return projection(_v2json.canonical(obj["delegations"][index]), "signature")
    if name.startswith("party_signatures["):
        return txv2.transaction_receipt_v2_sign_bytes(txv2.decode_transaction_receipt_v2(wire))
    pytest.fail(f"unknown signature field {name!r}")


def check_object_digests(o: dict, wire: bytes) -> None:
    digests = o["digests"]
    for name, want in digests.items():
        if name in ("issuer_key_id_v2", "subject_key_id_v2"):
            c = pv2.decode_delegation_cert_v2(wire)
            got = key_id_v2(c.issuer_pub_key if name == "issuer_key_id_v2" else c.subject_pub_key)
        elif name == "delegation_digest_hex":
            b = pv2.decode_proof_bundle_v2(wire)
            got = pv2.delegation_digest_v2(b.delegations).hex()
            assert b.delegation_digest.hex() == got
        elif name == "bundle_hash_v2":
            got = pv2.bundle_hash_v2(pv2.decode_proof_bundle_v2(wire))
        elif name == "session_context_hex":
            b = pv2.decode_proof_bundle_v2(wire)
            request = operation_context_v2_hash("data:read", "records.get", "customer/123", "/v1/customers/123")
            ctx = session_context_v2_hash(b.verifier_id, "00000000-0000-4000-8000-000000000001", b.agent_id,
                                          "session-01", "invocation-01", request)
            assert b.session_context == ctx, "bundle session_context differs from the recomputed fixture context"
            got = ctx.hex()
        elif name == "challenge_claim_digest_hex":
            got = challenge_claim_digest_v2(pv2.decode_proof_bundle_v2(wire).challenge).hex()
        elif name == "claim_id":
            got = protocol_claim_id_v2(digests["claim_verifier_namespace"], int(digests["claim_replay_epoch"]),
                                       pv2.decode_proof_bundle_v2(wire).challenge)
        elif name in ("claim_verifier_namespace", "claim_replay_epoch", "transaction_context_hex"):
            continue  # inputs to claim_id / party digests, checked there
        elif name == "receipt_outbox_body_b64":
            got = base64.b64encode(vrv2.verification_receipt_v2_body(vrv2.decode_verification_receipt_v2(wire))).decode()
        elif name == "status_evidence_digest":
            if o["kind"] == "revocation_list":
                d = pv2.status_evidence_digest(3, pv2.decode_revocation_list_v2(wire))
            else:
                d = pv2.status_evidence_digest(5, pv2.decode_revocation_push_v2(wire))
            got = "sha384:" + d.hex()
        elif name == "statement_body_digest_hex":
            if o["kind"] == "key_rotation_statement":
                d = kr.key_rotation_statement_v2_digest(kr.decode_key_rotation_statement_v2(wire))
            elif o["kind"] == "witness_entry":
                d = wv2.witness_entry_v2_digest(wv2.decode_witness_entry_v2(wire))
            elif o["kind"] == "verification_receipt":
                d = vrv2.verification_receipt_v2_digest(vrv2.decode_verification_receipt_v2(wire))
            else:
                pytest.fail(f"statement digest for unexpected kind {o['kind']}")
            got = d.hex()
        elif name.startswith("party-"):
            got = party_digest(wire, name, digests["transaction_context_hex"])
        else:
            pytest.fail(f"unknown digest {name!r}")
        assert got == want, f"digest {name}"


def party_digest(wire: bytes, name: str, tx_context_hex: str) -> str:
    receipt = txv2.decode_transaction_receipt_v2(wire)
    party_id, _, field_name = name.partition(".")
    tx_context = txv2.transaction_context_hash_v2(receipt)
    assert tx_context.hex() == tx_context_hex
    party = next(p for p in receipt.parties if p.party_id == party_id)
    request = txv2.transaction_party_request_hash_v2(tx_context, party.required_scope)
    if field_name == "transaction_party_request_hash_hex":
        return request.hex()
    if field_name == "session_context_hex":
        return session_context_v2_hash(party.verifier_id, party.workspace_id, party.agent_id, party.session_id,
                                       party.invocation_id, request).hex()
    if field_name == "proof_bundle_hash":
        return pv2.bundle_hash_v2(party.proof_bundle)
    pytest.fail(f"unknown transaction digest {name!r}")


def check_object(o: dict, pub=PUB, key_id=KEY_ID) -> None:
    """The objects.json procedure: decode, re-encode identically, reproduce
    every projection, M, context, tr, mu and digest, and verify."""
    wire = b64(o["wire_b64"])
    decode, encode = CODECS[o["kind"]]
    assert encode(decode(wire)) == wire, "re-encoding is not byte-identical"
    verify_object(o["kind"], wire, None, o["verify"], pub)
    for s in o["signatures"]:
        signable = b64(s["signable_b64"])
        assert projection(wire, s["field"]) == signable, f"{s['field']}: signable projection differs"
        assert hashlib.sha384(signable).hexdigest() == s["signable_sha384_hex"]
        code = s["object_type_code"]
        message = signing_message_v2(code, signable)
        assert message == b64(s["message_b64"]) and len(message) == 77
        context = mldsa_context_v2(code)
        assert s["mldsa_context"] == context.decode() and len(context) == 22
        assert key_id[s["signer"]] == s["signer_key_id_v2"]
        signer = pub[s["signer"]]
        assert _mldsa65.compute_tr(signer.ml_dsa_65) == b64(s["mldsa_tr_b64"])
        assert _mldsa65.compute_mu(signer.ml_dsa_65, message, context) == b64(s["mldsa_mu_b64"])
        assert external_mu_v2(signer.ml_dsa_65, context, message) == b64(s["mldsa_mu_b64"])
        pinned = sig(s["signature"])
        assert base64.b64encode(pinned.ml_dsa_65) in wire and base64.b64encode(pinned.ed25519) in wire
        verify_v2_statement(code, signable, pinned, signer)
    check_object_digests(o, wire)


@pytest.mark.parametrize("o", OBJECTS["objects"], ids=lambda o: o["name"])
def test_object(o):
    check_object(o)


def resign_object(o: dict, priv) -> bytes:
    """Re-sign an object with its typed signer and return the new wire bytes."""
    wire = b64(o["wire_b64"])
    kind = o["kind"]
    signers = {s["field"]: s["signer"] for s in o["signatures"]}
    if kind == "delegation_certificate":
        return pv2.encode_delegation_cert_v2(pv2.sign_delegation_cert_v2(pv2.decode_delegation_cert_v2(wire),
                                                                          priv(signers["signature"])))
    if kind == "proof_bundle":
        return pv2.encode_proof_bundle_v2(pv2.sign_proof_bundle_v2(pv2.decode_proof_bundle_v2(wire),
                                                                    priv(signers["challenge_sig"])))
    if kind == "revocation_list":
        v = o["verify"]
        return pv2.encode_revocation_list_v2(pv2.sign_revocation_list_v2(
            pv2.decode_revocation_list_v2(wire), v["bound_issuer_id"], PUB[v["status_key"]], priv(v["status_key"])))
    if kind == "revocation_push":
        v = o["verify"]
        return pv2.encode_revocation_push_v2(pv2.sign_revocation_push_v2(
            pv2.decode_revocation_push_v2(wire), v["bound_issuer_id"], PUB[v["status_key"]], priv(v["status_key"])))
    if kind == "key_rotation_statement":
        stmt = kr.decode_key_rotation_statement_v2(wire)
        return kr.encode_key_rotation_statement_v2(kr.sign_key_rotation_statement_v2(
            stmt, priv(signers["old_signature"]), priv(signers["new_signature"])))
    if kind == "witness_entry":
        return wv2.encode_witness_entry_v2(wv2.sign_witness_entry_v2(wv2.decode_witness_entry_v2(wire),
                                                                      priv(signers["signature"])))
    if kind == "verification_receipt":
        return vrv2.encode_verification_receipt_v2(vrv2.sign_verification_receipt_v2(
            vrv2.decode_verification_receipt_v2(wire), priv(signers["signature"])))
    if kind == "transaction_receipt":
        receipt = txv2.decode_transaction_receipt_v2(wire)
        signatures = []
        for item in receipt.party_signatures:
            signer = signers[f"party_signatures[{item.party_id}]"]
            signatures.append(txv2.sign_transaction_receipt_party_v2(receipt, item.party_id, priv(signer)))
        receipt.party_signatures = signatures
        return txv2.encode_transaction_receipt_v2(receipt)
    pytest.fail(f"unknown kind {kind}")


@requires_native
@pytest.mark.parametrize("o", OBJECTS["objects"], ids=lambda o: o["name"])
def test_object_typed_signer_resign(o):
    """Each typed signer reproduces every pinned object byte for byte
    (deterministic Ed25519, unhedged ML-DSA-65 from the fixture seeds)."""
    with deterministic_test_vector_signing():
        assert resign_object(o, private_key) == b64(o["wire_b64"])


def test_objects_cover_every_object_code():
    codes = {s["object_type_code"] for o in OBJECTS["objects"] for s in o["signatures"]}
    assert codes == set(range(1, 10))
    assert len(OBJECTS["objects"]) == 10


NEGATIVES = load("object-negatives.json")


@pytest.mark.parametrize("v", NEGATIVES["vectors"], ids=lambda v: v["name"])
def test_object_negative(v):
    bundle = b64(v["bundle_b64"]) if v.get("bundle_b64") else None
    with pytest.raises(Exception) as info:
        verify_object(v["kind"], b64(v["wire_b64"]), bundle, v.get("verify") or {})
    assert error_class_of(info.value) == v["expected_error_class"], f"{v['mutation']}: {info.value!r}"


def test_object_negatives_cover_every_kind():
    kinds = {v["kind"] for v in NEGATIVES["vectors"]}
    assert kinds == {"delegation_certificate", "proof_bundle", "revocation_list", "revocation_push",
                     "key_rotation_statement", "witness_entry", "transaction_receipt", "verification_receipt",
                     "receipt_bundle_binding"}
    assert len(NEGATIVES["vectors"]) == 281


# ---------------------------------------------------------------------------
# log-sequences.json

LOGS = load("log-sequences.json")


def test_log_sequences_have_both_logs():
    assert sorted(sc["kind"] for sc in LOGS["scenarios"]) == ["verification_receipt", "witness_entry"]


def run_log_step(kind: str, wire: bytes, key: HybridPublicKey, head: wv2.WitnessV2Head, verifier_id: str):
    if kind == "witness_entry":
        obj = wv2.decode_witness_entry_v2(wire)
        return obj, wv2.verify_witness_entry_v2(obj, head, key), wv2.witness_entry_v2_digest(obj)
    if kind == "verification_receipt":
        obj = vrv2.decode_verification_receipt_v2(wire)
        receipt_head = vrv2.ReceiptV2Head(head.log_id, verifier_id, head.sequence, head.head_hash,
                                          head.accepted_digests, head.frozen)
        return obj, vrv2.verify_verification_receipt_v2(obj, key, receipt_head), vrv2.verification_receipt_v2_digest(obj)
    pytest.fail(f"unknown log kind {kind!r}")


RESULT_NAMES = {wv2.WitnessEntryV2Result.APPENDED: "appended", wv2.WitnessEntryV2Result.REPLAY: "replay"}


@pytest.mark.parametrize("sc", LOGS["scenarios"], ids=lambda s: s["name"])
def test_log_sequence(sc):
    def genesis(log_id):
        return wv2.WitnessV2Head(log_id=log_id, sequence=0, head_hash=bytes(48), accepted_digests={})

    head = genesis(sc["initial_log_id"])
    for i, step in enumerate(sc["steps"]):
        if step["op"] == "recover":
            head = genesis(step["log_id"])
            continue
        err = None
        try:
            obj, result, digest = run_log_step(sc["kind"], b64(step["wire_b64"]), PUB[step["key"]], head,
                                               sc.get("verifier_id", ""))
            got = RESULT_NAMES[result]
        except Exception as exc:  # noqa: BLE001
            err, got = exc, error_class_of(exc)
        assert got == step["expect"], (i, step.get("label"), err)
        if got == "appended":
            head.sequence = obj.sequence
            head.head_hash = digest
            head.accepted_digests[obj.sequence] = digest
        elif got == "log_fork":
            head.frozen = True


# ---------------------------------------------------------------------------
# rotation-sequences.json

ROTATION = load("rotation-sequences.json")


@pytest.mark.parametrize("sc", ROTATION["scenarios"], ids=lambda s: s["name"])
def test_rotation_sequence(sc):
    journal = kr.new_key_rotation_v2_journal(sc["authority_id"], sc["recovery_epoch"], sc["role"], PUB[sc["genesis_key"]])
    for i, step in enumerate(sc["steps"]):
        err = None
        if step["op"] == "recover":
            try:
                journal = kr.recover_key_rotation_v2(journal, step["new_recovery_epoch"], PUB[step["new_genesis_key"]])
                got = "recovered"
            except Exception as exc:  # noqa: BLE001
                err, got = exc, error_class_of(exc)
        elif step["op"] == "accept":
            stmt = kr.decode_key_rotation_statement_v2(b64(step["wire_b64"]))
            try:
                journal, result = kr.accept_key_rotation_statement_v2(stmt, journal, step["now"], sc["future_skew_seconds"])
                got = RESULT_NAMES[result]
            except Exception as exc:  # noqa: BLE001
                err, got = exc, error_class_of(exc)
                if hasattr(exc, "journal"):
                    journal = exc.journal  # the frozen journal the caller must persist
        else:
            pytest.fail(f"unknown rotation op {step['op']!r}")
        assert got == step["expect"], (i, step.get("label"), err)
        st = journal.state
        assert st.sequence == step["expect_sequence"], (i, step.get("label"))
        assert st.current_key.ml_dsa_65 == PUB[step["expect_current_key"]].ml_dsa_65, (i, step.get("label"))
        assert st.recovery_epoch == step["expect_recovery_epoch"], (i, step.get("label"))
        assert journal.frozen == step["expect_frozen"], (i, step.get("label"))


# ---------------------------------------------------------------------------
# Hand-maintained vectors


def test_delegation_signature_vector():
    v = load("delegation-signature.json")
    assert v["object_type_code"] == 1
    signable, message = b64(v["signable_bytes"]), b64(v["message"])
    context = b64(v["mldsa_context"])
    pub = pubkey(v["issuer_public_key"])
    assert signing_message_v2(1, signable) == message and mldsa_context_v2(1) == context
    assert key_id_v2(pub) == v["key_id_v2"]
    assert _mldsa65.compute_tr(pub.ml_dsa_65) == b64(v["mldsa_tr"])
    assert _mldsa65.compute_mu(pub.ml_dsa_65, message, context) == b64(v["mldsa_mu"])
    assert external_mu_v2(pub.ml_dsa_65, context, message) == b64(v["mldsa_mu"])
    signature = sig(v["signature"])
    verify_v2_statement(1, signable, signature, pub)
    assert not _mldsa65.verify(pub.ml_dsa_65, message, b64(v["alternate_mldsa_context"]), signature.ml_dsa_65)
    mask = v["negative_mutations"]["xor_mask"]
    targets = v["negative_mutations"]["targets"]
    assert targets, "no negative mutations"
    for target in targets:
        s, k, data = HybridSignature(signature.ed25519, signature.ml_dsa_65), HybridPublicKey(pub.ed25519, pub.ml_dsa_65), signable
        flip = lambda b: bytes([b[0] ^ mask]) + b[1:]  # noqa: E731
        if target == "signable_bytes":
            data = flip(data)
        elif target == "signature.ed25519":
            s.ed25519 = flip(s.ed25519)
        elif target == "signature.ml_dsa_65":
            s.ml_dsa_65 = flip(s.ml_dsa_65)
        elif target == "issuer_public_key.ed25519":
            k.ed25519 = flip(k.ed25519)
        elif target == "issuer_public_key.ml_dsa_65":
            k.ml_dsa_65 = flip(k.ml_dsa_65)
        else:
            pytest.fail(f"unknown mutation target {target!r}")
        with pytest.raises(Exception) as info:
            verify_v2_statement(1, data, s, k)
        assert error_class_of(info.value) == "invalid_signature", target


@requires_native
def test_delegation_signature_vector_native_resign():
    """The native backend reproduces the pinned primitive signature from the
    seeds over the SDK-computed M and context (the signable bytes here are a
    primitive fixture, not a complete certificate, so no typed signer
    applies; the backend is not part of the SDK's public API)."""
    v = load("delegation-signature.json")
    derived, priv = keypair_from_seeds_v2(b64(v["issuer_seeds"]["ed25519"]), b64(v["issuer_seeds"]["ml_dsa_65"]))
    assert derived == pubkey(v["issuer_public_key"])
    native = _native.signing_key(priv.ed25519, priv.ml_dsa_65)
    signable = b64(v["signable_bytes"])
    ed, ml = native.sign(signing_message_v2(1, signable), mldsa_context_v2(1), deterministic_for_test_vectors=True)
    assert HybridSignature(bytes(ed), bytes(ml)) == sig(v["signature"])


def test_derive_external_mu_script():
    script = V2_DIR / "derive-external-mu.py"
    out = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, check=True).stdout
    v = load("delegation-signature.json")
    assert f"mldsa_tr: {v['mldsa_tr']}" in out and f"mldsa_mu: {v['mldsa_mu']}" in out


def test_operation_session_context_vector():
    from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy

    v = load("operation-session-context.json")
    policy = v["context_policy"]
    built = new_v2_context_policy(policy["profile"], policy["require_bound"], policy["required_fields"], bytes(32))
    assert policy["version"] == 1 and built.digest == v["context_policy_digest"]
    i = v["input"]
    assert session_context_v2_hash(i["verifier_id"], i["workspace_id"], i["agent_id"], i["session_id"],
                                   i["invocation_id"], bytes.fromhex(i["request_hash_hex"])).hex() == v["expected_session_context_hex"]

    def op_hash(o, digest):
        return operation_context_v2_hash(o["required_scope"], o["operation"], o["resource_id"], o["requested_path"], digest)

    o = v["operation_input"]
    assert op_hash(o, bytes.fromhex(o["payload_digest_hex"])).hex() == v["expected_request_hash_hex"]
    e = v["empty_payload_operation_input"]
    assert e["payload_digest_hex"] is None
    empty = op_hash(e, None)
    assert empty.hex() == v["expected_empty_request_hash_hex"]
    assert session_context_v2_hash(i["verifier_id"], i["workspace_id"], i["agent_id"], i["session_id"],
                                   i["invocation_id"], empty).hex() == v["expected_empty_session_context_hex"]
    api = v["verify_api_operation_input"]
    assert op_hash(api, decode_payload_digest(api["payload_digest"])).hex() == v["expected_verify_api_request_hash_hex"]
    assert v["invalid_required_scopes"]
    for scope in v["invalid_required_scopes"]:
        with pytest.raises(ValueError):
            operation_context_v2_hash(scope, "op", "res", "/p")
        with pytest.raises(ValueError):
            validate_required_scope_v2(scope)
    # An exact custom: scope is a valid required scope (SPEC-v2 §2.4).
    operation_context_v2_hash("custom:invoice:read", "op", "res", "/p")
    for case in v["verify_api_payload_digest_decode_cases"]:
        if case["valid"]:
            decoded = decode_payload_digest(case["encoded"])
            assert (decoded or b"").hex() == case["expected_hex"], case["name"]
        else:
            with pytest.raises((ValueError, TypeError)):
                decode_payload_digest(case["encoded"])


def test_challenge_claim_vector():
    v = load("challenge-claim.json")
    challenge = bytes.fromhex(v["challenge_hex"])
    assert challenge_claim_digest_v2(challenge).hex() == v["expected_challenge_claim_digest_hex"]
    c = v["claim_id_input"]
    assert protocol_claim_id_v2(c["verifier_namespace"], c["replay_epoch"], challenge) == v["expected_claim_id"]
    assert v["additional_claim_id_cases"]
    for case in v["additional_claim_id_cases"]:
        assert protocol_claim_id_v2(case["verifier_namespace"], case["replay_epoch"], challenge) == case["expected_claim_id"]


ROTATION_SIGNATURE = load("key-rotation-signature.json")


@pytest.mark.parametrize("v", [ROTATION_SIGNATURE, ROTATION_SIGNATURE["continuation"]], ids=["genesis", "continuation"])
def test_key_rotation_signature_vector(v):
    wire = b64(v["wire"])
    stmt = kr.decode_key_rotation_statement_v2(wire)
    assert kr.encode_key_rotation_statement_v2(stmt) == wire
    assert (stmt.version, stmt.authority_id, stmt.recovery_epoch, stmt.role, stmt.sequence, stmt.issued_at,
            stmt.not_before, stmt.old_key_id, stmt.new_key_id) == (
        int(v["version"]), v["authority_id"], int(v["recovery_epoch"]), v["role"], int(v["sequence"]),
        int(v["issued_at"]), int(v["not_before"]), v["old_key_id"], v["new_key_id"])
    assert int(v["object_type_code"]) == 4
    assert stmt.previous_statement_hash == b64(v["previous_statement_hash"])
    assert stmt.old_key == pubkey(v["old_key"]) and stmt.new_key == pubkey(v["new_key"])
    signable = kr.key_rotation_signable_bytes_v2(stmt)
    assert signable == b64(v["signable_bytes"])
    assert kr.key_rotation_statement_v2_digest(stmt).hex() == v["statement_body_digest"]
    assert mldsa_context_v2(4).decode() == v["old_mldsa_context"] and mldsa_context_v2(9).decode() == v["new_mldsa_context"]
    assert stmt.old_signature == sig(v["old_signature"]) and stmt.new_signature == sig(v["new_signature"])
    old_pub, new_pub = stmt.old_key, stmt.new_key
    verify_v2_statement(4, signable, stmt.old_signature, old_pub)
    verify_v2_statement(9, signable, stmt.new_signature, new_pub)
    for code, signature, key in ((9, stmt.old_signature, old_pub), (4, stmt.new_signature, new_pub)):
        with pytest.raises(Exception) as info:
            verify_v2_statement(code, signable, signature, key)
        assert error_class_of(info.value) == "invalid_signature"


@requires_native
@pytest.mark.parametrize("v", [ROTATION_SIGNATURE, ROTATION_SIGNATURE["continuation"]], ids=["genesis", "continuation"])
def test_key_rotation_signature_vector_native_resign(v):
    wire = b64(v["wire"])
    stmt = kr.decode_key_rotation_statement_v2(wire)
    old_pub, old_priv = keypair_from_seeds_v2(bytes.fromhex(v["old_key_seeds"]["ed25519"]), bytes.fromhex(v["old_key_seeds"]["ml_dsa_65"]))
    new_pub, new_priv = keypair_from_seeds_v2(bytes.fromhex(v["new_key_seeds"]["ed25519"]), bytes.fromhex(v["new_key_seeds"]["ml_dsa_65"]))
    assert old_pub == stmt.old_key and new_pub == stmt.new_key
    with deterministic_test_vector_signing():
        signed = kr.sign_key_rotation_statement_v2(stmt, old_priv, new_priv)
    assert kr.encode_key_rotation_statement_v2(signed) == wire
