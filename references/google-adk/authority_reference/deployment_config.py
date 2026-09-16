"""Explicit receiver/public and presenter/private deployment configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets

from ratify_protocol import (
    HybridPrivateKey,
    HybridPublicKey,
    base64_standard_decode,
    base64_standard_encode,
    decode_delegation_cert,
    encode_delegation_cert,
    generate_agent,
)

from .authority import AuthorityFixture


def write_configs(authority: AuthorityFixture, receiver_path: Path, presenter_path: Path) -> None:
    transport_token = secrets.token_urlsafe(32)
    receiver_identity, _ = generate_agent("ADK Authority Receiver", "custom")
    receiver_config = {
        "trusted_root_id": authority.root_id,
        "trusted_agent_id": authority.specialist_id,
        "root_ed25519": base64_standard_encode(authority.root_public_key.ed25519),
        "root_ml_dsa_65": base64_standard_encode(authority.root_public_key.ml_dsa_65),
        "receiver_ed25519": base64_standard_encode(receiver_identity.public_key.ed25519),
        "receiver_ml_dsa_65": base64_standard_encode(receiver_identity.public_key.ml_dsa_65),
        "transport_token": transport_token,
        "challenge_ttl_seconds": 300,
        "challenge_capacity": 128,
        "pending_capacity": 128,
    }
    receiver_config["federation_routes"] = [{
        "agent_id": authority.specialist_id,
        "root_id": authority.root_id,
        "subjects_leaf_to_root": list(authority.agent_path),
    }]
    if authority.admission_delegations and authority.admission_root_public_key:
        receiver_config["admission_root_id"] = authority.admission_root_id
        receiver_config["admission_root_ed25519"] = base64_standard_encode(
            authority.admission_root_public_key.ed25519
        )
        receiver_config["admission_root_ml_dsa_65"] = base64_standard_encode(
            authority.admission_root_public_key.ml_dsa_65
        )
        receiver_config["admission_routes"] = [{
            "agent_id": authority.specialist_id,
            "root_id": authority.admission_root_id,
            "subjects_leaf_to_root": [authority.specialist_id],
        }]
    receiver_payload = json.dumps(receiver_config)
    presenter_payload = json.dumps({
        "root_id": authority.root_id,
        "root_ed25519": base64_standard_encode(authority.root_public_key.ed25519),
        "root_ml_dsa_65": base64_standard_encode(authority.root_public_key.ml_dsa_65),
        "specialist_id": authority.specialist_id,
        "private_ed25519": base64_standard_encode(authority.specialist_private_key.ed25519),
        "private_ml_dsa_65": base64_standard_encode(authority.specialist_private_key.ml_dsa_65),
        "delegations": [encode_delegation_cert(cert) for cert in authority.delegations],
        "admission_delegations": [
            encode_delegation_cert(cert) for cert in (authority.admission_delegations or [])
        ],
        "transport_token": transport_token,
    })
    _write_secret(receiver_path, receiver_payload)
    _write_secret(presenter_path, presenter_payload)


def _write_secret(path: Path, payload: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(payload)


def load_presenter(path: str) -> AuthorityFixture:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    delegations = [decode_delegation_cert(cert) for cert in data["delegations"]]
    admission_delegations = [
        decode_delegation_cert(cert) for cert in data.get("admission_delegations", [])
    ]
    return AuthorityFixture(
        root_id=data["root_id"],
        root_public_key=HybridPublicKey(
            ed25519=base64_standard_decode(data["root_ed25519"]),
            ml_dsa_65=base64_standard_decode(data["root_ml_dsa_65"]),
        ),
        specialist_id=data["specialist_id"],
        specialist_private_key=HybridPrivateKey(
            ed25519=base64_standard_decode(data["private_ed25519"]),
            ml_dsa_65=base64_standard_decode(data["private_ml_dsa_65"]),
        ),
        delegations=delegations,
        agent_path=tuple(cert.subject_id for cert in delegations),
        admission_root_id=data.get("admission_root_id"),
        admission_root_public_key=(
            HybridPublicKey(
                ed25519=base64_standard_decode(data["admission_root_ed25519"]),
                ml_dsa_65=base64_standard_decode(data["admission_root_ml_dsa_65"]),
            )
            if data.get("admission_root_id")
            else None
        ),
        admission_delegations=admission_delegations or None,
    )


def load_transport_token(path: str) -> str:
    return json.loads(Path(path).read_text(encoding="utf-8"))["transport_token"]
