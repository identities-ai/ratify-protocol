"""Ratify Protocol v2 Python SDK (distribution ``ratify-protocol-v2``).

A separate distribution and import package from the v1 SDK
(``ratify-protocol`` / ``ratify_protocol``) so both can be installed together.
The object set, verifier and status machinery live in submodules such as
``ratify_protocol_v2.protocol_v2`` and ``ratify_protocol_v2.verify_v2``.

``canonical``, ``types``, ``scope``, ``resource_path`` and ``constraints`` are
copies of the v1 modules of the same name, so this package does not depend on
the v1 distribution.

Key generation and signing run only in the required ``ratify-protocol-native-v2``
extension (constant-time Ed25519 and ML-DSA-65). Verification is pure Python
and works without it; signing without it raises ImportError.
"""
from ._version import __version__
from . import _native  # import-time lockstep check of the native signing extension
from .types import HybridPrivateKey, HybridPublicKey, HybridSignature
from .crypto_v2 import (
    delegation_signature_message_v2,
    derive_key_id_v2,
    sign_delegation_v2,
    verify_delegation_signature_v2,
)
from .operation_context_v2 import (
    decode_payload_digest,
    operation_context_v2_bytes,
    operation_context_v2_hash,
    session_context_v2_bytes,
    session_context_v2_hash,
)
from .challenge_claim_v2 import (
    challenge_claim_digest_v2,
    protocol_claim_id_v2,
    protocol_claim_id_from_digest_v2,
)
from .signing_v2 import keypair_from_seeds_v2

NATIVE_AVAILABLE = _native.AVAILABLE

__all__ = [
    "__version__", "NATIVE_AVAILABLE",
    "HybridPrivateKey", "HybridPublicKey", "HybridSignature",
    "keypair_from_seeds_v2",
    "delegation_signature_message_v2", "derive_key_id_v2",
    "sign_delegation_v2", "verify_delegation_signature_v2",
    "decode_payload_digest", "operation_context_v2_bytes",
    "operation_context_v2_hash", "session_context_v2_bytes",
    "session_context_v2_hash",
    "challenge_claim_digest_v2", "protocol_claim_id_v2",
    "protocol_claim_id_from_digest_v2",
]
