"""Archival verification (SPEC-v2 §6.10), ported from Go archival_v2_test.go.

Uses the signed objects of objects.json, so it runs without the native
signer: archival verification handles only public data.
"""
from __future__ import annotations

import json

import pytest

from corpus import b64, load, pubkey
from ratify_protocol_v2 import archival_v2 as av
from ratify_protocol_v2.errors_v2 import V2Error, V2ErrorClass, error_class_of

OBJECTS = {o["name"]: o for o in load("objects.json")["objects"]}
KEYS = {k["name"]: k for k in load("keys.json")["keys"]}


def wire(name: str) -> bytes:
    return b64(OBJECTS[name]["wire_b64"])


def key(name: str):
    return pubkey(KEYS[name]["public_key"])


def key_id(name: str) -> str:
    return KEYS[name]["key_id_v2"]


def _assert_labelled(result):
    assert result.freshness == av.FRESHNESS_UNVERIFIED_V2 == "freshness_unverified"
    assert result.actionable is False


@pytest.mark.parametrize("name", ["proof_bundle_two_link_bound_context", "proof_bundle_empty_chain_stream_bound"])
def test_proof_bundle_result_is_labelled_and_not_actionable(name):
    obj = OBJECTS[name]
    got = av.verify_archival_proof_bundle_v2(wire(name))
    assert got.assessment == av.FRESHNESS_UNVERIFIED_V2
    assert got.actionable is False
    assert got.error_class == ""
    assert got.bundle_hash == obj["digests"]["bundle_hash_v2"]
    assert got.agent_id == key_id("agent")
    assert got.issuer_ids == sorted(set(got.issuer_ids))
    if name == "proof_bundle_empty_chain_stream_bound":
        assert got.issuer_ids == []


def test_proof_bundle_tampered_and_malformed():
    data = wire("proof_bundle_two_link_bound_context")
    tampered = data.replace(b'"challenge_at":', b'"challenge_at":1', 1)
    got = av.verify_archival_proof_bundle_v2(tampered)
    assert got.error_class == V2ErrorClass.INVALID_SIGNATURE
    assert got.actionable is False and got.assessment == av.FRESHNESS_UNVERIFIED_V2
    assert got.err is not None
    assert av.verify_archival_proof_bundle_v2(b"{").error_class == V2ErrorClass.MALFORMED


def test_proof_bundle_result_json():
    ok = av.ArchivalProofBundleResultV2(bundle_hash="sha384:x", agent_id="a", issuer_ids=["i"])
    assert ok.to_json() == (
        b'{"actionable":false,"agent_id":"a","assessment":"freshness_unverified",'
        b'"bundle_hash":"sha384:x","error_class":null,"issuer_ids":["i"]}'
    )
    failed = av.ArchivalProofBundleResultV2(error_class=V2ErrorClass.INVALID_SIGNATURE, issuer_ids=None)
    text = failed.to_json().decode()
    assert '"error_class":"invalid_signature"' in text and '"issuer_ids":[]' in text


@pytest.mark.parametrize("name", ["delegation_root_to_intermediate", "delegation_with_every_v2_constraint_shape"])
def test_delegation_certificate(name):
    got = av.verify_archival_delegation_cert_v2(wire(name))
    _assert_labelled(got)
    assert got.object_type == 0x0001 and got.digest == ""
    assert got.signer_key_ids == (OBJECTS[name]["signatures"][0]["signer_key_id_v2"],)


@pytest.mark.parametrize("name,code", [("revocation_list", 3), ("revocation_push", 5)])
def test_status_objects_use_caller_keys(name, code):
    obj = OBJECTS[name]
    fn = av.verify_archival_revocation_list_v2 if code == 3 else av.verify_archival_revocation_push_v2
    issuer = obj["verify"]["bound_issuer_id"]
    status = obj["verify"]["status_key"]
    got = fn(wire(name), issuer, key(status))
    _assert_labelled(got)
    assert got.object_type == code
    assert got.digest == "sha384:" + _hex(obj["digests"]["status_evidence_digest"])
    assert got.signer_key_ids == (key_id(status),)
    with pytest.raises(V2Error) as other:
        fn(wire(name), issuer, key("agent"))
    assert other.value.error_class == V2ErrorClass.INVALID_SIGNATURE
    with pytest.raises(V2Error) as unbound:
        fn(wire(name), "0" * 64, key(status))
    assert unbound.value.error_class == V2ErrorClass.STATUS_KEY_BINDING_MISMATCH


def _hex(value: str) -> str:
    value = value.removeprefix("sha384:")
    try:
        bytes.fromhex(value)
        return value
    except ValueError:
        return b64(value).hex()


def test_key_rotation_statement():
    obj = OBJECTS["key_rotation_genesis"]
    got = av.verify_archival_key_rotation_statement_v2(wire("key_rotation_genesis"))
    _assert_labelled(got)
    assert got.object_type == 0x0004
    assert got.digest == "sha384:" + obj["digests"]["statement_body_digest_hex"]
    assert got.signer_key_ids == tuple(s["signer_key_id_v2"] for s in obj["signatures"])


def test_witness_entry_needs_no_head_and_binds_the_key():
    obj = OBJECTS["witness_entry_genesis"]
    witness = obj["verify"]["witness_key"]
    got = av.verify_archival_witness_entry_v2(wire("witness_entry_genesis"), key(witness))
    _assert_labelled(got)
    assert got.digest == "sha384:" + obj["digests"]["statement_body_digest_hex"]
    assert got.signer_key_ids == (key_id(witness),)
    with pytest.raises(V2Error) as other:
        av.verify_archival_witness_entry_v2(wire("witness_entry_genesis"), key("agent"))
    assert other.value.error_class == V2ErrorClass.KEY_ID_MISMATCH


def test_verification_receipt():
    obj = OBJECTS["verification_receipt_allow_genesis"]
    verifier = obj["verify"]["verifier_key"]
    got = av.verify_archival_verification_receipt_v2(wire("verification_receipt_allow_genesis"), key(verifier))
    _assert_labelled(got)
    assert got.object_type == 0x0008
    assert got.digest == "sha384:" + obj["digests"]["statement_body_digest_hex"]
    with pytest.raises(V2Error) as other:
        av.verify_archival_verification_receipt_v2(wire("verification_receipt_allow_genesis"), key("agent"))
    assert other.value.error_class == V2ErrorClass.KEY_ID_MISMATCH


def test_transaction_receipt():
    got = av.verify_archival_transaction_receipt_v2(wire("transaction_receipt_two_parties"))
    _assert_labelled(got)
    assert got.object_type == 0x0007 and got.digest == ""
    assert len(got.signer_key_ids) == 2


@pytest.mark.parametrize("fn,args", [
    (av.verify_archival_delegation_cert_v2, ()),
    (av.verify_archival_key_rotation_statement_v2, ()),
    (av.verify_archival_transaction_receipt_v2, ()),
])
def test_malformed_input_is_malformed(fn, args):
    with pytest.raises(V2Error) as exc:
        fn(b"{", *args)
    assert exc.value.error_class == V2ErrorClass.MALFORMED


def test_results_never_expose_an_actionable_flag():
    got = av.verify_archival_delegation_cert_v2(wire("delegation_root_to_intermediate"))
    assert json.loads(_canonical(got)) ["actionable"] is False
    assert error_class_of(None) == ""


def _canonical(result) -> bytes:
    from ratify_protocol_v2 import _v2json

    return _v2json.canonical(result.to_canonical_dict())
