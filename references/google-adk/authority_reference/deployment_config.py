"""Explicit receiver/public and presenter/private deployment configuration."""

from __future__ import annotations

import json
from pathlib import Path

from ratify_protocol import (
    HybridPrivateKey,
    HybridPublicKey,
    base64_standard_decode,
    base64_standard_encode,
    decode_delegation_cert,
    encode_delegation_cert,
)

from .authority import AuthorityFixture


def write_configs(authority: AuthorityFixture, receiver_path: Path, presenter_path: Path) -> None:
    receiver_path.write_text(json.dumps({
        "trusted_root_id": authority.root_id,
        "trusted_agent_id": authority.specialist_id,
        "root_ed25519": base64_standard_encode(authority.root_public_key.ed25519),
        "root_ml_dsa_65": base64_standard_encode(authority.root_public_key.ml_dsa_65),
    }), encoding="utf-8")
    presenter_path.write_text(json.dumps({
        "root_id": authority.root_id,
        "root_ed25519": base64_standard_encode(authority.root_public_key.ed25519),
        "root_ml_dsa_65": base64_standard_encode(authority.root_public_key.ml_dsa_65),
        "specialist_id": authority.specialist_id,
        "private_ed25519": base64_standard_encode(authority.specialist_private_key.ed25519),
        "private_ml_dsa_65": base64_standard_encode(authority.specialist_private_key.ml_dsa_65),
        "delegations": [encode_delegation_cert(cert) for cert in authority.delegations],
    }), encoding="utf-8")
    presenter_path.chmod(0o600)


def load_presenter(path: str) -> AuthorityFixture:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
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
        delegations=[decode_delegation_cert(cert) for cert in data["delegations"]],
    )
