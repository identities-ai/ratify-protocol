"""Delegation issuer duties from "issuer-duties.json" (SPEC-v2 §3.2, §5.1, §5.2).

A typed delegation signer refuses a certificate that a conforming issuer must
not emit before any signer method (public key, mode, or sign) runs."""
from __future__ import annotations

import pytest

from corpus import b64, load
from ratify_protocol_v2 import _native
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2.context_v2 import background
from ratify_protocol_v2.signing_v2 import V2SigningError, _new_local_signer_v2
from signer_fixtures import CountingSigner, ExternalMuSigner
from test_v2_conformance import PUB, private_key

DUTIES = load("issuer-duties.json")

pytestmark = pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")


@pytest.mark.parametrize("mode", ["direct", "external_mu"])
@pytest.mark.parametrize("v", DUTIES["vectors"], ids=lambda v: v["name"])
def test_issuer_duty(v, mode):
    cert = pv2.decode_delegation_cert_v2(b64(v["unsigned_certificate_b64"]))
    if mode == "direct":
        inner = _new_local_signer_v2(private_key(v["issuer"]))
    else:
        inner = ExternalMuSigner(private_key(v["issuer"]), PUB[v["issuer"]])
    signer = CountingSigner(inner)
    if v["expected"] == "sign":
        signed = pv2.sign_delegation_cert_v2_with_signer(background(), cert, signer)
        pv2.verify_delegation_cert_v2_signature(signed)
        assert signer.calls > 0
    elif v["expected"] == "reject":
        with pytest.raises(V2SigningError):
            pv2.sign_delegation_cert_v2_with_signer(background(), cert, signer)
        assert signer.calls == 0, "a signer method ran before the issuer-duty refusal"
        with pytest.raises(V2SigningError):
            pv2.sign_delegation_cert_v2(cert, private_key(v["issuer"]))
    else:
        pytest.fail(f"unknown expectation {v['expected']!r}")


def test_issuer_duty_vector_count():
    assert len(DUTIES["vectors"]) == 11
