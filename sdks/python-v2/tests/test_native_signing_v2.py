"""Signing goes only through ratify-protocol-native-v2, and fails closed without it.

Pure-Python signing was removed because it is not constant-time. These tests
pin the properties that decision rests on: no signer works without the native
extension, every native signature is checked by the ordinary pure-Python
verifier before it is returned, production signing is hedged, and the native
signer refuses a message/context pair that names different object types.
"""
from __future__ import annotations

import inspect
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import ratify_protocol_v2
from ratify_protocol_v2 import _native, signing_v2
from ratify_protocol_v2 import key_rotation_v2 as kr
from ratify_protocol_v2 import protocol_v2 as pv2
from ratify_protocol_v2 import transaction_receipt_v2 as txv2
from ratify_protocol_v2 import verification_receipt_v2 as vrv2
from ratify_protocol_v2 import witness_v2 as wv2
from ratify_protocol_v2.crypto_v2 import sign_delegation_v2
from ratify_protocol_v2.signing_v2 import (
    _sign_v2_statement,
    keypair_from_seeds_v2,
    mldsa_context_v2,
    public_key_of,
    signing_message_v2,
    verify_v2_statement,
)
from ratify_protocol_v2.types import HybridPrivateKey, HybridSignature

import test_v2_conformance as conf

requires_native = pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")

OBJECTS = {o["name"]: o for o in conf.OBJECTS["objects"]}


def _typed_signers(o: dict):
    """(callable that re-signs the corpus object with a typed signer, verifier
    for the result) for one objects.json entry."""
    wire, v, kind = conf.b64(o["wire_b64"]), o["verify"], o["kind"]
    signer = o["signatures"][0]["signer"]
    key = lambda name: conf.private_key(name)  # noqa: E731
    if kind == "delegation_certificate":
        obj = pv2.decode_delegation_cert_v2(wire)
        return (lambda: pv2.sign_delegation_cert_v2(obj, key(signer)),
                lambda r: pv2.verify_delegation_cert_v2_signature(r))
    if kind == "proof_bundle":
        obj = pv2.decode_proof_bundle_v2(wire)
        return (lambda: pv2.sign_proof_bundle_v2(obj, key(signer)),
                lambda r: pv2.verify_proof_bundle_v2_signatures(r))
    if kind in ("revocation_list", "revocation_push"):
        decode, sign, verify = {
            "revocation_list": (pv2.decode_revocation_list_v2, pv2.sign_revocation_list_v2,
                                pv2.verify_revocation_list_v2_signature),
            "revocation_push": (pv2.decode_revocation_push_v2, pv2.sign_revocation_push_v2,
                                pv2.verify_revocation_push_v2_signature),
        }[kind]
        obj, status_pub = decode(wire), conf.PUB[v["status_key"]]
        return (lambda: sign(obj, v["bound_issuer_id"], status_pub, key(v["status_key"])),
                lambda r: verify(r, v["bound_issuer_id"], status_pub))
    if kind == "key_rotation_statement":
        obj = kr.decode_key_rotation_statement_v2(wire)
        new_signer = o["signatures"][1]["signer"]
        return (lambda: kr.sign_key_rotation_statement_v2(obj, key(signer), key(new_signer)),
                lambda r: kr.verify_key_rotation_statement_v2(r, conf._rotation_state(v["rotation_state"]),
                                                              v["now"], v["future_skew_seconds"]))
    if kind == "witness_entry":
        obj = wv2.decode_witness_entry_v2(wire)
        head = wv2.WitnessV2Head(**conf._head(v["head"]))
        return (lambda: wv2.sign_witness_entry_v2(obj, key(signer)),
                lambda r: wv2.verify_witness_entry_v2(r, head, conf.PUB[v["witness_key"]]))
    if kind == "transaction_receipt":
        obj = txv2.decode_transaction_receipt_v2(wire)

        def sign_all():
            sigs = [txv2.sign_transaction_receipt_party_v2(obj, p.party_id, key(s["signer"]))
                    for p, s in zip(obj.parties, o["signatures"])]
            return replace(obj, party_signatures=sigs)
        return sign_all, lambda r: txv2.verify_transaction_receipt_v2_signatures(r)
    if kind == "verification_receipt":
        obj = vrv2.decode_verification_receipt_v2(wire)
        head = vrv2.ReceiptV2Head(verifier_id=v["head"]["verifier_id"], **conf._head(v["head"]))
        return (lambda: vrv2.sign_verification_receipt_v2(obj, key(signer)),
                lambda r: vrv2.verify_verification_receipt_v2(r, conf.PUB[v["verifier_key"]], head))
    pytest.fail(f"no typed signer mapped for kind {kind!r}")


def test_every_object_code_has_a_typed_signer_case():
    codes = {s["object_type_code"] for o in OBJECTS.values() for s in o["signatures"]}
    assert codes == set(range(1, 10))


# --- fail closed without the extension -------------------------------------


@requires_native
@pytest.mark.parametrize("name", sorted(OBJECTS))
def test_typed_signer_fails_closed_without_native(name, monkeypatch):
    sign, _ = _typed_signers(OBJECTS[name])
    for s in OBJECTS[name]["signatures"]:
        conf.private_key(s["signer"])  # derive keys while the extension is present
    monkeypatch.setattr(_native, "_ext", None)
    with pytest.raises(ImportError, match="ratify-protocol-native-v2"):
        sign()


def test_signing_and_keygen_fail_closed_without_native(monkeypatch):
    monkeypatch.setattr(_native, "_ext", None)
    seed = bytes(32)
    junk = HybridPrivateKey(ed25519=bytes(32), ml_dsa_65=bytes(4032))
    for call in (lambda: keypair_from_seeds_v2(seed, seed),
                 lambda: public_key_of(junk),
                 lambda: sign_delegation_v2(b"x", junk),
                 lambda: _sign_v2_statement(1, b"x", junk)):
        with pytest.raises(ImportError, match="ratify-protocol-native-v2") as info:
            call()
        assert "no pure-Python signing fallback" in str(info.value)


def test_import_without_native_verifies_but_cannot_sign(tmp_path):
    """A process where the extension cannot be imported still verifies the
    shared delegation vector but refuses to sign."""
    package_root = Path(ratify_protocol_v2.__file__).resolve().parents[1]
    script = f"""
import sys
sys.modules["ratify_protocol_native_v2"] = None  # simulate an absent extension
import base64, json
import ratify_protocol_v2 as r
assert r.NATIVE_AVAILABLE is False
v = json.load(open({str(conf.V2_DIR / "delegation-signature.json")!r}))
d = lambda s: base64.b64decode(s)
pub = r.HybridPublicKey(d(v["issuer_public_key"]["ed25519"]), d(v["issuer_public_key"]["ml_dsa_65"]))
sig = r.HybridSignature(d(v["signature"]["ed25519"]), d(v["signature"]["ml_dsa_65"]))
assert r.verify_delegation_signature_v2(d(v["signable_bytes"]), sig, pub)
try:
    r.keypair_from_seeds_v2(bytes(32), bytes(32))
except ImportError as e:
    print("refused:", e)
else:
    raise SystemExit("signed without native")
"""
    env = dict(os.environ, PYTHONPATH=str(package_root))
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "refused:" in result.stdout and "ratify-protocol-native-v2" in result.stdout


# --- no raw signing export, no production deterministic switch -------------


def test_no_raw_sign_export():
    assert not hasattr(signing_v2, "sign_v2_statement")
    assert not hasattr(ratify_protocol_v2, "sign_v2_statement")
    assert not any(n.startswith("sign_v2") for n in ratify_protocol_v2.__all__)


@pytest.mark.parametrize("fn", [
    sign_delegation_v2, pv2.sign_delegation_cert_v2, pv2.sign_proof_bundle_v2, pv2.sign_revocation_list_v2,
    pv2.sign_revocation_push_v2, kr.sign_key_rotation_statement_v2, wv2.sign_witness_entry_v2,
    txv2.sign_transaction_receipt_party_v2, vrv2.sign_verification_receipt_v2,
    vrv2.sign_prepared_verification_receipt_v2,
], ids=lambda f: f.__name__)
def test_typed_signers_have_no_deterministic_parameter(fn):
    assert "deterministic" not in inspect.signature(fn).parameters


# --- native signatures verify under the pure-Python verifier ---------------


@requires_native
@pytest.mark.parametrize("name", sorted(OBJECTS))
def test_typed_signer_hedged_output_verifies(name):
    """Every typed signer, in production (hedged) mode, produces an object the
    pure-Python verifier for that kind accepts."""
    sign, verify = _typed_signers(OBJECTS[name])
    verify(sign())


@requires_native
@pytest.mark.parametrize("code", range(1, 10))
def test_hedged_signatures_differ_and_verify(code):
    priv = conf.private_key("root")
    pub = public_key_of(priv)
    signable = b"hedged signing check"
    a, b = _sign_v2_statement(code, signable, priv), _sign_v2_statement(code, signable, priv)
    assert a.ed25519 == b.ed25519, "Ed25519 is deterministic"
    assert a.ml_dsa_65 != b.ml_dsa_65, "ML-DSA-65 must be hedged by default"
    for s in (a, b):
        verify_v2_statement(code, signable, s, pub)


@requires_native
def test_signature_is_verified_before_it_is_returned(monkeypatch):
    """A native signer that returns a bad signature is caught by the
    pure-Python verifier inside the SDK, not handed to the caller."""
    real = _native.signing_key

    class Corrupting:
        def __init__(self, key):
            self._key = key

        def public_key(self):
            return self._key.public_key()

        def sign(self, message, context, **kw):
            ed, ml = self._key.sign(message, context, **kw)
            return ed, bytes([ml[0] ^ 1]) + ml[1:]

    monkeypatch.setattr(_native, "signing_key", lambda e, m: Corrupting(real(e, m)))
    with pytest.raises(RuntimeError, match="failed verification"):
        sign_delegation_v2(b"x", conf.private_key("root"))


# --- native transcript checks -----------------------------------------------


@requires_native
def test_native_signer_rejects_mismatched_or_malformed_transcripts():
    priv = conf.private_key("root")
    key = _native.signing_key(priv.ed25519, priv.ml_dsa_65)
    message = signing_message_v2(1, b"x")
    assert key.sign(message, mldsa_context_v2(1))
    with pytest.raises(ValueError, match="does not match"):
        key.sign(message, mldsa_context_v2(2))
    with pytest.raises(ValueError, match="77-byte"):
        key.sign(message[:-1], mldsa_context_v2(1))
    with pytest.raises(ValueError, match="77-byte"):
        key.sign(b"X" + message[1:], mldsa_context_v2(1))
    unregistered = message[:27] + (0x000A).to_bytes(2, "big") + message[29:]
    with pytest.raises(ValueError, match="unsupported"):
        key.sign(unregistered, b"ratify-protocol/2/000a")
    with pytest.raises(TypeError):
        key.sign(message, mldsa_context_v2(1), True)  # the test-vector flag is keyword-only


@requires_native
def test_native_key_rejects_bad_private_key_lengths():
    ext = _native.require()
    with pytest.raises(ValueError):
        ext.HybridSigningKey.from_private_bytes(bytes(31), bytes(4032))
    with pytest.raises(ValueError):
        ext.HybridSigningKey.from_private_bytes(bytes(32), bytes(4031))
    assert repr(ext.HybridSigningKey.from_seeds(bytes(32), bytes(32))) == "<HybridSigningKey>"


@requires_native
def test_deterministic_mode_is_scoped_to_the_context_manager():
    from ratify_protocol_v2._testing import deterministic_test_vector_signing

    priv = conf.private_key("root")
    with deterministic_test_vector_signing():
        a = _sign_v2_statement(1, b"y", priv)
        b = _sign_v2_statement(1, b"y", priv)
    assert a == b
    assert _sign_v2_statement(1, b"y", priv) != a
    assert isinstance(a, HybridSignature)
