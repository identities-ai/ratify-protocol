"""Explicit receiver and presenter deployment configuration.

The receiver file holds the receiver's own verifier (receipt-signing) key,
the pinned complete root and agent keys, each issuer's public status key, and
the location of the local status feed. The presenter file holds the worker's
private key and its delegation chains. Both are written with mode ``0600``.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets

from ratify_protocol_v2.protocol_v2 import decode_delegation_cert_v2, encode_delegation_cert_v2
from ratify_protocol_v2.signing_v2 import generate_keypair_v2
from ratify_protocol_v2.types import HybridPrivateKey, HybridPublicKey

from .authority import AuthorityFixture


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def encode_key(key: HybridPublicKey | HybridPrivateKey) -> dict[str, str]:
    return {"ed25519": _b64(key.ed25519), "ml_dsa_65": _b64(key.ml_dsa_65)}


def decode_public_key(data: dict[str, str]) -> HybridPublicKey:
    return HybridPublicKey(ed25519=_unb64(data["ed25519"]), ml_dsa_65=_unb64(data["ml_dsa_65"]))


def decode_private_key(data: dict[str, str]) -> HybridPrivateKey:
    return HybridPrivateKey(ed25519=_unb64(data["ed25519"]), ml_dsa_65=_unb64(data["ml_dsa_65"]))


def write_configs(
    authority: AuthorityFixture,
    receiver_path: Path,
    presenter_path: Path,
    *,
    status_dir: Path | None = None,
) -> None:
    """Write both configs and publish the issuers' signed status lists."""
    if authority.status is None:
        raise ValueError("authority has no status publishers")
    status_dir = status_dir or receiver_path.parent / "status"
    authority.status.write(status_dir)
    transport_token = secrets.token_urlsafe(32)
    _, verifier_private = generate_keypair_v2()
    receiver_config = {
        "trusted_root_id": authority.root_id,
        "root_public_key": encode_key(authority.root_public_key),
        "trusted_agent_id": authority.specialist_id,
        "agent_public_key": encode_key(authority.specialist_public_key),
        "verifier_private_key": encode_key(verifier_private),
        "log_id": secrets.token_hex(16),
        "status_keys": {
            issuer_id: encode_key(key) for issuer_id, key in authority.status.status_keys().items()
        },
        "status_feed_dir": str(status_dir.resolve()),
        "transport_token": transport_token,
        "challenge_ttl_seconds": 300,
        "pending_capacity": 128,
        "federation_routes": [{
            "agent_id": authority.specialist_id,
            "root_id": authority.root_id,
            "subjects_leaf_to_root": list(authority.agent_path),
        }],
    }
    if authority.admission_delegations and authority.admission_root_public_key:
        receiver_config["admission_root_id"] = authority.admission_root_id
        receiver_config["admission_root_public_key"] = encode_key(authority.admission_root_public_key)
        receiver_config["admission_routes"] = [{
            "agent_id": authority.specialist_id,
            "root_id": authority.admission_root_id,
            "subjects_leaf_to_root": [authority.specialist_id],
        }]
    presenter_config = {
        "root_id": authority.root_id,
        "root_public_key": encode_key(authority.root_public_key),
        "specialist_id": authority.specialist_id,
        "specialist_public_key": encode_key(authority.specialist_public_key),
        "specialist_private_key": encode_key(authority.specialist_private_key),
        "delegations": [_b64(encode_delegation_cert_v2(cert)) for cert in authority.delegations],
        "admission_delegations": [
            _b64(encode_delegation_cert_v2(cert)) for cert in (authority.admission_delegations or [])
        ],
        "transport_token": transport_token,
    }
    if authority.admission_root_public_key is not None:
        presenter_config["admission_root_id"] = authority.admission_root_id
        presenter_config["admission_root_public_key"] = encode_key(authority.admission_root_public_key)
    _write_secret(receiver_path, json.dumps(receiver_config))
    _write_secret(presenter_path, json.dumps(presenter_config))


def _write_secret(path: Path, payload: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(payload)


def load_presenter(path: str) -> AuthorityFixture:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    delegations = [decode_delegation_cert_v2(_unb64(cert)) for cert in data["delegations"]]
    admission = [
        decode_delegation_cert_v2(_unb64(cert)) for cert in data.get("admission_delegations", [])
    ]
    return AuthorityFixture(
        root_id=data["root_id"],
        root_public_key=decode_public_key(data["root_public_key"]),
        specialist_id=data["specialist_id"],
        specialist_public_key=decode_public_key(data["specialist_public_key"]),
        specialist_private_key=decode_private_key(data["specialist_private_key"]),
        delegations=delegations,
        agent_path=tuple(cert.subject_id for cert in delegations),
        admission_root_id=data.get("admission_root_id"),
        admission_root_public_key=(
            decode_public_key(data["admission_root_public_key"])
            if data.get("admission_root_public_key")
            else None
        ),
        admission_delegations=admission or None,
    )


def load_transport_token(path: str) -> str:
    return json.loads(Path(path).read_text(encoding="utf-8"))["transport_token"]
