"""Agent key storage of the stdio signer: the OS credential store via
``keyring`` (the ``mcp-signer`` extra), or a 0600 file.

The stored form is the ``ratify-keys`` private key file format
(``ed25519_private_key`` = 64-byte Ed25519 private key, ``mldsa65_private_key``
= ML-DSA-65 secret key, both standard base64). Key generation and the
public-key derivation run in the native v2 extension."""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

from ...canonical import canonical_json
from ..signing_v2 import generate_keypair_v2, key_id_v2, public_key_of
from ..types import HybridPrivateKey, HybridPublicKey
from ._files import read_private_file, write_private_file
from .errors import ConfigError

KEYRING_SERVICE = "ratify-mcp-signer"


def public_key_json(pub: HybridPublicKey) -> bytes:
    """The public key JSON exactly as ``ratify-keys public`` prints it."""
    return canonical_json(pub.to_canonical_dict())


def _encode_private(pub: HybridPublicKey, priv: HybridPrivateKey) -> bytes:
    return json.dumps({
        "ed25519_private_key": base64.b64encode(bytes(priv.ed25519) + bytes(pub.ed25519)).decode(),
        "mldsa65_private_key": base64.b64encode(bytes(priv.ml_dsa_65)).decode(),
    }).encode()


def _decode_private(data: bytes, where: str) -> tuple[HybridPublicKey, HybridPrivateKey]:
    invalid = ConfigError(f"{where} is not a valid ratify-keys private key")
    try:
        obj = json.loads(data)
        if not isinstance(obj, dict) or set(obj) != {"ed25519_private_key", "mldsa65_private_key"}:
            raise invalid
        ed = base64.b64decode(obj["ed25519_private_key"], validate=True)
        ml = base64.b64decode(obj["mldsa65_private_key"], validate=True)
        if len(ed) != 64:
            raise invalid
        priv = HybridPrivateKey(ed25519=ed[:32], ml_dsa_65=ml)
        pub = public_key_of(priv)
        if bytes(pub.ed25519) != ed[32:]:
            raise invalid
    except Exception:
        # Never chain: the cause could quote key bytes.
        raise invalid from None
    return pub, priv


def generate() -> tuple[HybridPublicKey, HybridPrivateKey]:
    return generate_keypair_v2()


def keyring_usable() -> bool:
    try:
        import keyring
        from keyring.backends import fail
        backend = keyring.get_keyring()
        if isinstance(backend, fail.Keyring):
            return False
        try:
            from keyring.backends import chainer
            if isinstance(backend, chainer.ChainerBackend) and not backend.backends:
                return False
        except ImportError:
            pass
        return True
    except Exception:
        return False


def validate_key_ref(key: Any) -> None:
    if not isinstance(key, dict):
        raise ConfigError("key must be an object")
    kind = key.get("kind")
    if kind == "keyring":
        if not isinstance(key.get("service"), str) or not isinstance(key.get("name"), str) or not key["name"]:
            raise ConfigError("keyring key needs service and name")
    elif kind == "file":
        if not isinstance(key.get("path"), str) or not os.path.isabs(key["path"]):
            raise ConfigError("file key needs an absolute path")
    else:
        raise ConfigError("key.kind must be keyring or file")


def store_key(pub: HybridPublicKey, priv: HybridPrivateKey, *, kind: str, directory: str, name: str) -> dict:
    """Store the private key and return the config ``key`` reference."""
    data = _encode_private(pub, priv)
    if kind == "keyring":
        import keyring
        if keyring.get_password(KEYRING_SERVICE, name) is not None:
            raise ConfigError(f"refusing to overwrite keyring item {KEYRING_SERVICE}/{name}")
        try:
            keyring.set_password(KEYRING_SERVICE, name, data.decode())
        except Exception:
            raise ConfigError("could not save the key in the OS credential store") from None
        return {"kind": "keyring", "service": KEYRING_SERVICE, "name": name}
    if kind == "file":
        path = os.path.join(os.path.abspath(directory), name + ".key")
        write_private_file(path, data + b"\n", exclusive=True)
        return {"kind": "file", "path": path}
    raise ConfigError("key store must be keyring or file")


def load_key(ref: dict) -> tuple[HybridPublicKey, HybridPrivateKey]:
    validate_key_ref(ref)
    if ref["kind"] == "keyring":
        import keyring
        try:
            secret: Optional[str] = keyring.get_password(ref["service"], ref["name"])
        except Exception:
            raise ConfigError("could not read the key from the OS credential store") from None
        if secret is None:
            raise ConfigError(f"no key in the OS credential store at {ref['service']}/{ref['name']}")
        return _decode_private(secret.encode(), f"keyring item {ref['service']}/{ref['name']}")
    path = ref["path"]
    return _decode_private(read_private_file(path, "key file", 1 << 16), f"key file {path}")


def key_id(pub: HybridPublicKey) -> str:
    return key_id_v2(pub)
