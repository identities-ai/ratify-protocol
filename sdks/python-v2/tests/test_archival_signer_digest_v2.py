"""Shared archival (SPEC-v2 §6.10), external signer (§3.2), and digest
function (§4) vectors: archival.json, external-signer.json and
digest-functions.json (mirrors Go v2_conformance_archival_signer_test.go).

None of these cases needs the native signer: the external signer is a
scripted provider and every returned signature is verified, so they run with
either hybrid verifier.
"""
from __future__ import annotations

import json
from hashlib import sha384

import pytest

from corpus import b64, load
from v2_harness import keys

from ratify_protocol_v2 import _v2json
from ratify_protocol_v2 import archival_v2 as av
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2.context_v2 import background, with_cancel
from ratify_protocol_v2.errors_v2 import V2ErrorClass, error_class_of
from ratify_protocol_v2.signing_v2 import SignerModeV2
from ratify_protocol_v2.types import HybridSignature
from ratify_protocol_v2.witness_v2 import statement_body_digest_v2

FX = keys()
ARCHIVAL = load("archival.json")
SIGNER = load("external-signer.json")
DIGESTS = load("digest-functions.json")

ARCHIVAL_KINDS = ("proof_bundle", "delegation_certificate", "revocation_list", "revocation_push",
                  "key_rotation_statement", "witness_entry", "verification_receipt", "transaction_receipt")


def test_corpus_shape():
    assert len(ARCHIVAL["cases"]) == 19
    assert {c["kind"] for c in ARCHIVAL["cases"]} == set(ARCHIVAL_KINDS)
    assert len(SIGNER["cases"]) == 17
    assert len(DIGESTS["cases"]) == 25


def _archival(c: dict):
    wire, v = b64(c["wire_b64"]), c.get("verify") or {}
    kind = c["kind"]
    if kind == "proof_bundle":
        return json.loads(av.verify_archival_proof_bundle_v2(wire).to_json())
    if kind == "delegation_certificate":
        got = av.verify_archival_delegation_cert_v2(wire)
    elif kind == "revocation_list":
        got = av.verify_archival_revocation_list_v2(wire, v["issuer_id"], FX.pub[v["status_key"]])
    elif kind == "revocation_push":
        got = av.verify_archival_revocation_push_v2(wire, v["issuer_id"], FX.pub[v["status_key"]])
    elif kind == "key_rotation_statement":
        got = av.verify_archival_key_rotation_statement_v2(wire)
    elif kind == "witness_entry":
        got = av.verify_archival_witness_entry_v2(wire, FX.pub[v["witness_key"]])
    elif kind == "verification_receipt":
        got = av.verify_archival_verification_receipt_v2(wire, FX.pub[v["verifier_key"]])
    elif kind == "transaction_receipt":
        got = av.verify_archival_transaction_receipt_v2(wire)
    else:
        raise AssertionError(f"unknown kind {kind}")
    return got.to_canonical_dict()


@pytest.mark.parametrize("c", ARCHIVAL["cases"], ids=lambda c: c["name"])
def test_archival(c):
    if c.get("expected_error_class"):
        with pytest.raises(Exception) as excinfo:
            _archival(c)
        assert error_class_of(excinfo.value) == c["expected_error_class"], excinfo.value
        return
    got = _archival(c)
    assert _v2json.canonical(got) == _v2json.canonical(c["expected"])


class ScriptedSigner:
    """Answers every request with fixed bytes and records it (Go
    v2ScriptedSigner)."""

    def __init__(self, pub, mode, response, sig, ctx):
        self.pub, self.mode, self.response, self.sig, self.ctx = pub, mode, response, sig, ctx
        self.requests = []

    def public_key_v2(self):
        return self.pub

    def mode_v2(self):
        return self.mode

    def sign_v2(self, ctx, req):
        self.requests.append(req)
        if self.response == "error":
            raise RuntimeError("scripted provider failure")
        if self.response == "cancel":
            self.ctx.cancel()
        return self.sig


@pytest.mark.parametrize("c", SIGNER["cases"], ids=lambda c: c["name"])
def test_external_signer(c):
    ctx = with_cancel(background())
    p = c["provider"]
    mode = {"direct": SignerModeV2.DIRECT, "external_mu": SignerModeV2.EXTERNAL_MU}[p["mode"]]
    sig = None
    if p.get("signature") is not None:
        sig = HybridSignature(ed25519=b64(p["signature"]["ed25519"]), ml_dsa_65=b64(p["signature"]["ml_dsa_65"]))
    signer = ScriptedSigner(FX.pub[p["public_key"]], mode, p["response"], sig, ctx)
    if c.get("caller_cancelled"):
        ctx.cancel()
    wire = b64(c["object_b64"])
    signed, err = None, None
    try:
        if c["kind"] == "delegation_certificate":
            signed = pv2.encode_delegation_cert_v2(
                pv2.sign_delegation_cert_v2_with_signer(ctx, pv2.decode_delegation_cert_v2(wire), signer))
        elif c["kind"] == "revocation_list":
            b = c["binding"]
            signed = pv2.encode_revocation_list_v2(pv2.sign_revocation_list_v2_with_signer(
                ctx, pv2.decode_revocation_list_v2(wire), b["issuer_id"], FX.pub[b["status_key"]], signer))
        elif c["kind"] == "proof_bundle":
            signed = pv2.encode_proof_bundle_v2(
                pv2.sign_proof_bundle_v2_with_signer(ctx, pv2.decode_proof_bundle_v2(wire), signer))
        else:
            raise AssertionError(f"unknown kind {c['kind']}")
    except Exception as exc:  # noqa: BLE001 - every failure is classified below
        signed, err = None, exc
    e = c["expected"]
    assert len(signer.requests) == e["provider_calls"]
    if e.get("request") is not None:
        r, w = signer.requests[0], e["request"]
        assert {SignerModeV2.DIRECT: "direct", SignerModeV2.EXTERNAL_MU: "external_mu"}[r.mode] == w["mode"]
        assert r.message == b64(w["message_b64"])
        assert r.mldsa_context == (None if w["mldsa_context"] is None else w["mldsa_context"].encode())
        assert r.mldsa_mu == (None if w["mldsa_mu_b64"] is None else b64(w["mldsa_mu_b64"]))
        assert r.key_id == w["key_id_v2"]
    if e["result"] == "signed":
        assert err is None, err
        assert signed == b64(e["signed_wire_b64"])
        return
    assert signed is None and err is not None
    assert error_class_of(err) == e["error_class"], err


@pytest.mark.parametrize("c", DIGESTS["cases"], ids=lambda c: c["name"])
def test_digest_function(c):
    data = b64(c["input_b64"])
    digest, err = None, None
    try:
        if c["function"] == "statement_body_digest":
            digest = statement_body_digest_v2(c["object_type_code"], data)
        elif c["function"] == "status_evidence_digest":
            digest = pv2.status_evidence_digest(c["object_type_code"], pv2.decode_revocation_list_v2(data))
        else:
            raise AssertionError(f"unknown function {c['function']}")
    except Exception as exc:  # noqa: BLE001 - classified below
        err = exc
    if c.get("expected_error_class"):
        assert digest is None and error_class_of(err) == c["expected_error_class"], err
        return
    assert err is None, err
    assert "sha384:" + digest.hex() == c["expected_digest"]


def test_statement_body_digest_revocation_bodies():
    """Revocation list and push bodies are the status observations' signed
    intent (SPEC-v2 §4): the digest accepts exactly the signable bytes derived
    from a valid object, and nothing else (Go
    TestStatementBodyDigestV2RevocationBodies)."""
    issuer = "ab" * 32
    lst = pv2.RevocationListV2(version=2, issuer_id=issuer, updated_at=100, next_update=200, sequence=2, revoked=["c1", "c2"])
    push = pv2.RevocationPushV2(version=2, issuer_id=issuer, sequence=3, pushed_at=150, revoked=["c3"])
    list_body = pv2.revocation_list_signable_bytes_v2(lst)
    push_body = pv2.revocation_push_signable_bytes_v2(push)
    for code, body, other in ((0x0003, list_body, push_body), (0x0005, push_body, list_body)):
        independent = sha384(b"ratify-protocol-statement-body-v2\x00" + code.to_bytes(2, "big") + body).digest()
        assert statement_body_digest_v2(code, body) == independent
        fields = json.loads(body)
        variants = {
            "other status object": other,
            "signature field": _v2json.canonical({**fields, "signature": {"ed25519": "", "ml_dsa_65": ""}}),
            "unknown field": _v2json.canonical({**fields, "extra": 1}),
            "noncanonical JSON": body + b" ",
            "null revoked": _v2json.canonical({**fields, "revoked": None}),
        }
        for name, bad in variants.items():
            with pytest.raises(Exception) as excinfo:
                statement_body_digest_v2(code, bad)
            assert error_class_of(excinfo.value) == V2ErrorClass.MALFORMED, (code, name)
    for code in (0x0000, 0x0001, 0x0002, 0x0007, 0x0009, 0x000A, 0xFFFF):
        with pytest.raises(Exception) as excinfo:
            statement_body_digest_v2(code, list_body)
        assert error_class_of(excinfo.value) == V2ErrorClass.UNSUPPORTED_OBJECT_TYPE, code
