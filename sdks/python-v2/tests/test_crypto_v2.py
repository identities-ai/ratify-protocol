"""Cross-language Protocol v2 delegation signing vector checks."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ratify_protocol_v2 import (
    HybridPublicKey,
    HybridSignature,
    delegation_signature_message_v2,
    derive_key_id_v2,
    keypair_from_seeds_v2,
    sign_delegation_v2,
    verify_delegation_signature_v2,
)
import ratify_protocol_v2
from ratify_protocol_v2 import _native
from ratify_protocol_v2._version import NATIVE_VERSION, __version__

if os.environ.get("RATIFY_REQUIRE_NATIVE") == "1" and not _native.AVAILABLE:
    raise RuntimeError("RATIFY_REQUIRE_NATIVE=1 but ratify-protocol-native-v2 is not installed")

VECTOR_PATH = (
    Path(os.environ.get("RATIFY_V2_VECTOR_DIR") or Path(__file__).resolve().parents[3] / "testvectors" / "v2")
    / "delegation-signature.json"
)


def vector() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def public_key(v: dict) -> HybridPublicKey:
    return HybridPublicKey(
        ed25519=decode(v["issuer_public_key"]["ed25519"]),
        ml_dsa_65=decode(v["issuer_public_key"]["ml_dsa_65"]),
    )


def signature(v: dict) -> HybridSignature:
    return HybridSignature(
        ed25519=decode(v["signature"]["ed25519"]),
        ml_dsa_65=decode(v["signature"]["ml_dsa_65"]),
    )


def test_v2_message_and_key_id_match_shared_vector():
    v = vector()
    signable = decode(v["signable_bytes"])
    assert v["object_type_code"] == 1
    assert delegation_signature_message_v2(signable) == decode(v["message"])
    assert derive_key_id_v2(public_key(v)) == v["key_id_v2"]


def test_v2_external_mu_matches_shared_signature_vector():
    v = vector()
    pk = public_key(v).ml_dsa_65
    context = decode(v["mldsa_context"])
    message = decode(v["message"])
    assert (len(pk), len(context), len(message)) == (1952, 22, 77)
    tr = hashlib.shake_256(pk).digest(64)
    mu = hashlib.shake_256(tr + b"\x00" + bytes([len(context)]) + context + message).digest(64)
    assert tr == decode(v["mldsa_tr"])
    assert mu == decode(v["mldsa_mu"])


def test_v2_key_id_rejects_wrong_component_sizes():
    key = public_key(vector())
    with pytest.raises(ValueError, match="Ed25519 public key"):
        derive_key_id_v2(HybridPublicKey(ed25519=key.ed25519[:-1], ml_dsa_65=key.ml_dsa_65))
    with pytest.raises(ValueError, match="ML-DSA-65 public key"):
        derive_key_id_v2(HybridPublicKey(ed25519=key.ed25519, ml_dsa_65=key.ml_dsa_65[:-1]))


def test_v2_signature_vector_and_component_mutations():
    v = vector()
    signable = decode(v["signable_bytes"])
    public = public_key(v)
    known_signature = signature(v)
    assert verify_delegation_signature_v2(signable, known_signature, public)

    seeds = v["issuer_seeds"]
    derived_public, private = keypair_from_seeds_v2(
        decode(seeds["ed25519"]), decode(seeds["ml_dsa_65"])
    )
    assert derived_public == public
    generated = sign_delegation_v2(signable, private, deterministic=True)
    assert generated == known_signature
    assert verify_delegation_signature_v2(signable, generated, public)

    changed = bytearray(signable)
    changed[0] ^= 1
    assert not verify_delegation_signature_v2(bytes(changed), known_signature, public)
    for member in ("ed25519", "ml_dsa_65"):
        changed_signature = bytearray(getattr(known_signature, member))
        changed_signature[0] ^= 1
        candidate = HybridSignature(
            ed25519=(bytes(changed_signature) if member == "ed25519" else known_signature.ed25519),
            ml_dsa_65=(bytes(changed_signature) if member == "ml_dsa_65" else known_signature.ml_dsa_65),
        )
        assert not verify_delegation_signature_v2(signable, candidate, public)

        changed_key = bytearray(getattr(public, member))
        changed_key[0] ^= 1
        candidate_key = HybridPublicKey(
            ed25519=(bytes(changed_key) if member == "ed25519" else public.ed25519),
            ml_dsa_65=(bytes(changed_key) if member == "ml_dsa_65" else public.ml_dsa_65),
        )
        assert not verify_delegation_signature_v2(signable, known_signature, candidate_key)


def test_native_version_is_lockstep_with_sdk_version():
    # 2.0.0a1 (PEP 440) <-> 2.0.0-alpha.1 (Cargo): the same release.
    major_minor_patch, _, pre = NATIVE_VERSION.partition("-")
    assert pre.startswith("alpha.")
    assert __version__ == f"{major_minor_patch}a{pre.removeprefix('alpha.')}"


@pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")
def test_native_keygen_matches_pure_python_and_shared_vector(monkeypatch):
    v = vector()
    ed_seed, ml_seed = decode(v["issuer_seeds"]["ed25519"]), decode(v["issuer_seeds"]["ml_dsa_65"])
    native_pub, native_priv = keypair_from_seeds_v2(ed_seed, ml_seed)
    monkeypatch.setattr(_native, "AVAILABLE", False)
    pure_pub, pure_priv = keypair_from_seeds_v2(ed_seed, ml_seed)
    assert native_pub == pure_pub == public_key(v)
    assert native_priv == pure_priv


# Directory holding the ratify_protocol_v2 under test (source tree or site-packages).
_PACKAGE_ROOT = Path(ratify_protocol_v2.__file__).resolve().parents[1]


def _import_with_fake_native(tmp_path, native_source: str) -> subprocess.CompletedProcess:
    (tmp_path / "ratify_protocol_native_v2.py").write_text(native_source)
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(tmp_path), str(_PACKAGE_ROOT), env.get("PYTHONPATH", "")) if p
    )
    return subprocess.run(
        [sys.executable, "-c", "import ratify_protocol_v2; print(ratify_protocol_v2.NATIVE_AVAILABLE)"],
        env=env, capture_output=True, text=True, cwd=tmp_path,
    )


def test_import_rejects_mismatched_native_version(tmp_path):
    result = _import_with_fake_native(tmp_path, "def version(): return '2.0.0-alpha.0'\n")
    assert result.returncode != 0
    assert "ratify-protocol-native-v2 version mismatch" in result.stderr
    assert "found 2.0.0-alpha.0" in result.stderr


def test_import_rejects_v1_native_version_under_v2_module_name(tmp_path):
    result = _import_with_fake_native(tmp_path, "def version(): return '1.0.0-alpha.21'\n")
    assert result.returncode != 0
    assert "version mismatch" in result.stderr


def test_import_accepts_matching_native_version(tmp_path):
    result = _import_with_fake_native(
        tmp_path, f"def version(): return {NATIVE_VERSION!r}\n"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"
