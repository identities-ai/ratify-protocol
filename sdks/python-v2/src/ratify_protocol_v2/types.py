"""Hybrid key and signature value types (SPEC-v2 §2.2) and shared limits.

The JSON shape of a public key or signature is
``{"ed25519":"<base64>","ml_dsa_65":"<base64>"}``. Sizes: Ed25519 public key
32 bytes and signature 64 bytes; ML-DSA-65 public key 1952 bytes and
signature 3309 bytes.
"""
from __future__ import annotations

from dataclasses import dataclass

from .limits_v2 import (  # noqa: F401 - re-exported shared limits
    MAX_CONSTRAINTS_PER_CERT,
    MAX_DELEGATION_CHAIN_DEPTH,
    MAX_IDENTIFIER_LENGTH_BYTES,
    MAX_JSON_NESTING_DEPTH,
    MAX_SCOPE_LENGTH_BYTES,
    MAX_SCOPES_PER_CERT,
)

ED25519_PUBLIC_KEY_SIZE: int = 32
ED25519_SIGNATURE_SIZE: int = 64
MLDSA65_PUBLIC_KEY_SIZE: int = 1952
MLDSA65_SIGNATURE_SIZE: int = 3309


@dataclass
class HybridPublicKey:
    """Ed25519 + ML-DSA-65 public key pair."""

    ed25519: bytes  # 32 bytes
    ml_dsa_65: bytes  # 1952 bytes

    def to_canonical_dict(self) -> dict:
        return {"ed25519": bytes(self.ed25519), "ml_dsa_65": bytes(self.ml_dsa_65)}


@dataclass
class HybridSignature:
    """Ed25519 + ML-DSA-65 signatures over the same message; both must verify."""

    ed25519: bytes  # 64 bytes
    ml_dsa_65: bytes  # 3309 bytes

    def to_canonical_dict(self) -> dict:
        return {"ed25519": bytes(self.ed25519), "ml_dsa_65": bytes(self.ml_dsa_65)}


@dataclass
class HybridPrivateKey:
    """Both private components; never serialized to the wire.

    ``ed25519`` is the 32-byte seed and ``ml_dsa_65`` the 4032-byte FIPS 204
    secret key. Signing with it happens only in the native extension."""

    ed25519: bytes
    ml_dsa_65: bytes

    def __repr__(self) -> str:
        return "HybridPrivateKey(<redacted>)"
