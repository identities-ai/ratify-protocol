"""Protocol v2 challenge replay identifiers; no challenge-store side effects."""
from __future__ import annotations

from hashlib import sha256, sha384

_MAX_SAFE_INTEGER = 2**53 - 1
_CLAIM_DIGEST_TAG = b"ratify-protocol-challenge-claim-v2\x00"
_CLAIM_ID_TAG = b"ratify-protocol-claim-id-v2\x00"


def challenge_claim_digest_v2(challenge: bytes) -> bytes:
    """Hash one decoded 32-byte challenge independently of the proof bundle."""
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise ValueError("v2 challenge claim requires exactly 32 challenge bytes")
    return sha384(_CLAIM_DIGEST_TAG + challenge).digest()


def _namespace_epoch(verifier_namespace: str, replay_epoch: int) -> bytes:
    if not isinstance(verifier_namespace, str) or not verifier_namespace:
        raise ValueError("v2 verifier namespace must be non-empty valid UTF-8")
    try:
        namespace = verifier_namespace.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("v2 verifier namespace must be non-empty valid UTF-8") from exc
    if isinstance(replay_epoch, bool) or not isinstance(replay_epoch, int) or not 0 <= replay_epoch <= _MAX_SAFE_INTEGER:
        raise ValueError("v2 replay epoch is outside the safe integer range")
    return namespace


def protocol_claim_id_v2(verifier_namespace: str, replay_epoch: int, challenge: bytes) -> str:
    """Derive the stable claim ID from namespace, epoch, and challenge bytes."""
    namespace = _namespace_epoch(verifier_namespace, replay_epoch)
    return _claim_id_from_digest(namespace, replay_epoch, challenge_claim_digest_v2(challenge))


def protocol_claim_id_from_digest_v2(verifier_namespace: str, replay_epoch: int, claim_digest: bytes) -> str:
    """Derive the same ID from a precomputed 48-byte challenge claim digest."""
    namespace = _namespace_epoch(verifier_namespace, replay_epoch)
    if not isinstance(claim_digest, bytes) or len(claim_digest) != 48:
        raise ValueError("v2 challenge claim digest must be exactly 48 bytes")
    return _claim_id_from_digest(namespace, replay_epoch, claim_digest)


def _claim_id_from_digest(namespace: bytes, replay_epoch: int, claim_digest: bytes) -> str:
    preimage = (
        _CLAIM_ID_TAG + len(namespace).to_bytes(8, "big") + namespace
        + replay_epoch.to_bytes(8, "big") + claim_digest
    )
    return sha256(preimage).hexdigest()
