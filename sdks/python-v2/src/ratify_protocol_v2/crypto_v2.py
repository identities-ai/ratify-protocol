"""Ratify Protocol v2 delegation-signature helpers.

Verification helpers fixed to the delegation-certificate object code. There
is deliberately no function here that signs caller-selected bytes (SPEC-v2
§3.2); sign certificates with ``protocol_v2.sign_delegation_cert_v2``.
"""
from __future__ import annotations

from .signing_v2 import DELEGATION_CERTIFICATE, key_id_v2, signing_message_v2, verify_v2_statement
from .types import HybridPublicKey, HybridSignature


def delegation_signature_message_v2(signable_bytes: bytes) -> bytes:
    """Build the fixed 77-byte Protocol v2 delegation signing message."""
    if not isinstance(signable_bytes, bytes):
        raise TypeError("signable_bytes must be bytes")
    return signing_message_v2(DELEGATION_CERTIFICATE, signable_bytes)


def derive_key_id_v2(public_key: HybridPublicKey) -> str:
    """Return the 256-bit v2 hybrid key ID after checking component sizes."""
    return key_id_v2(public_key)


def sign_delegation_v2(*_args, **_kwargs):
    """Removed: signing caller-selected bytes is not part of the v2 API.
    Use ``protocol_v2.sign_delegation_cert_v2`` (a typed signer)."""
    raise NotImplementedError(
        "sign_delegation_v2 signed caller-selected bytes and is removed; use protocol_v2.sign_delegation_cert_v2"
    )


def verify_delegation_signature_v2(
    signable_bytes: bytes,
    signature: HybridSignature,
    public_key: HybridPublicKey,
) -> bool:
    """Verify both v2 delegation signature components, failing closed."""
    if not isinstance(signable_bytes, bytes):
        raise TypeError("signable_bytes must be bytes")
    try:
        verify_v2_statement(DELEGATION_CERTIFICATE, signable_bytes, signature, public_key)
    except Exception:  # noqa: BLE001 - any failure is a rejection
        return False
    return True
