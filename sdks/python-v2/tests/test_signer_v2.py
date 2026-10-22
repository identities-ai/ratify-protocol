"""The external signer interface of SPEC-v2 §3.2 (Go signer_v2.go).

Key binding, exact inputs (M and context, or external mu), verification of
every returned component before use, and failure on provider errors,
cancellation, and malformed or invalid output."""
from __future__ import annotations

import pytest

from ratify_protocol_v2 import _native
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2.context_v2 import Cancelled, background, with_cancel
from ratify_protocol_v2.signing_v2 import (
    SignerModeV2,
    V2SigningError,
    external_mu_v2,
    key_id_v2,
    mldsa_context_v2,
    new_local_signer_v2,
    signer_public_key_v2,
)
from signer_fixtures import CountingSigner, ExternalMuSigner, FaultySigner
from test_v2_conformance import OBJECTS, PUB, b64, private_key

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")


def _witness():
    o = next(x for x in OBJECTS["objects"] if x["kind"] == "witness_entry")
    return wv2.decode_witness_entry_v2(b64(o["wire_b64"]))


def _cert():
    o = next(x for x in OBJECTS["objects"] if x["name"] == "delegation_root_to_intermediate")
    return pv2.decode_delegation_cert_v2(b64(o["wire_b64"]))


def test_direct_request_carries_exactly_m_and_the_registry_context():
    signer = CountingSigner(new_local_signer_v2(private_key("root")))
    cert = _cert()
    signed = pv2.sign_delegation_cert_v2_with_signer(background(), cert, signer)
    pv2.verify_delegation_cert_v2_signature(signed)
    (req,) = signer.requests
    assert req.mode == SignerModeV2.DIRECT
    assert len(req.message) == 77 and req.message[25:29] == b"\x00\x02\x00\x01"
    assert req.mldsa_context == mldsa_context_v2(1) == b"ratify-protocol/2/0001"
    assert req.mldsa_mu is None
    assert req.key_id == key_id_v2(PUB["root"]) and req.public_key == PUB["root"]


def test_external_mu_request_carries_only_mu():
    inner = ExternalMuSigner(private_key("witness"), PUB["witness"])
    entry = wv2.sign_witness_entry_v2_with_signer(background(), _witness(), inner)
    assert entry.witness_id == key_id_v2(PUB["witness"])
    (req,) = inner.requests
    assert req.mode == SignerModeV2.EXTERNAL_MU and req.mldsa_context is None
    assert len(req.mldsa_mu) == 64
    assert req.mldsa_mu == external_mu_v2(PUB["witness"].ml_dsa_65, mldsa_context_v2(6), req.message)


def test_signer_bound_to_another_key_is_refused_before_signing():
    signer = CountingSigner(new_local_signer_v2(private_key("attacker")))
    with pytest.raises(V2SigningError, match="does not match"):
        pv2.sign_delegation_cert_v2_with_signer(background(), _cert(), signer)
    assert signer.requests == []


def test_signer_with_incomplete_public_key_is_refused():
    class Broken:
        def public_key_v2(self):
            pub = PUB["root"]
            return type(pub)(pub.ed25519[:31], pub.ml_dsa_65)

    with pytest.raises(V2SigningError, match="public key"):
        signer_public_key_v2(Broken())


@pytest.mark.parametrize("fault", ["flip_ed25519", "flip_ml_dsa", "short", "none", "error", "bad_mode"])
def test_invalid_provider_output_fails_signing(fault):
    with pytest.raises(V2SigningError):
        wv2.sign_witness_entry_v2_with_signer(background(), _witness(), FaultySigner(private_key("witness"), fault))


def test_cancellation_before_signing_returns_no_object():
    ctx = with_cancel(background())
    ctx.cancel()
    signer = CountingSigner(new_local_signer_v2(private_key("witness")))
    with pytest.raises(Cancelled):
        wv2.sign_witness_entry_v2_with_signer(ctx, _witness(), signer)
    assert signer.requests == []


def test_signature_arriving_after_cancellation_is_discarded():
    ctx = with_cancel(background())
    signer = FaultySigner(private_key("witness"), "ok", on_sign=ctx.cancel)
    with pytest.raises(Cancelled):
        wv2.sign_witness_entry_v2_with_signer(ctx, _witness(), signer)


def test_signing_requires_a_context():
    with pytest.raises(V2SigningError):
        wv2.sign_witness_entry_v2_with_signer(None, _witness(), new_local_signer_v2(private_key("witness")))


def test_local_signer_refuses_external_mu_requests():
    from ratify_protocol_v2.signing_v2 import SignRequestV2

    signer = new_local_signer_v2(private_key("root"))
    req = SignRequestV2(SignerModeV2.EXTERNAL_MU, bytes(77), None, bytes(64), PUB["root"], key_id_v2(PUB["root"]))
    with pytest.raises(V2SigningError):
        signer.sign_v2(background(), req)
    assert "Private" not in repr(signer) and "seed" not in repr(signer)
