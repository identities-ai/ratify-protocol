"""ChallengeStore — single-use tracking for verifier-issued challenges
(SPEC §10).

verify_bundle consumes a challenge through this interface at the locked
point in the algorithm: after the structural, chain, and
challenge-signature checks pass, and before authorization evaluation — so
a forged presentation cannot burn a legitimate challenge, and a
cryptographically valid presentation spends its challenge even when
authorization is subsequently denied.

The bundled implementation is in-memory (MemoryChallengeStore).
Deployments that need issuance state to survive restarts or span verifier
replicas implement the same interface over shared storage; consume MUST
remain atomic (compare-and-set) so two concurrent presentations of one
challenge cannot both succeed.
"""
from __future__ import annotations

import base64
import threading
import time
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple, runtime_checkable

from .crypto import generate_challenge

# The uniform rejection detail for a challenge that cannot be consumed:
# never issued, expired, already consumed, or issued under a different
# session binding. Deliberately identical across those cases so a
# rejection's public detail does not distinguish them. verify_bundle
# normalizes EVERY store failure — custom-store error strings and raised
# exceptions included — to this text in the public result, so
# implementations cannot leak record state even accidentally.
UNKNOWN_CHALLENGE = "challenge was not issued by this verifier or has already been used"


@runtime_checkable
class ChallengeStore(Protocol):
    """Tracks verifier-issued challenges so each is accepted at most once
    within its freshness window (SPEC §10)."""

    def issue(self, session_context: bytes, ttl_seconds: int) -> Tuple[bytes, int]:
        """Generate a fresh challenge bound to ``session_context`` (which
        must be empty or exactly 32 bytes; empty = unbound), valid for
        ``ttl_seconds`` (which must be positive). Returns ``(challenge,
        expires_at_unix)``. Raises when the store cannot issue (e.g. at
        capacity)."""
        ...

    def validate(self, challenge: bytes, session_context: bytes, now: int) -> Optional[str]:
        """Report whether ``challenge`` could be consumed right now —
        issued, unexpired, unconsumed, and bound to ``session_context`` —
        WITHOUT consuming it. Returns None when consumable, else a
        rejection reason. verify_bundle calls this before any signature
        work."""
        ...

    def consume(self, challenge: bytes, session_context: bytes, now: int) -> Optional[str]:
        """Atomically remove the challenge's issuance record. Exactly one
        consume of a given challenge may ever succeed; all later calls
        (and calls with a mismatched ``session_context``, which do NOT
        remove the record) return a rejection reason. Returns None on
        success. Removing the record keeps the store's capacity a count of
        PENDING challenges — a consumed challenge frees its slot
        immediately."""
        ...


@dataclass
class _ChallengeRecord:
    session_context: bytes
    expires_at: int


class MemoryChallengeStore:
    """In-memory ChallengeStore: lock-guarded dict with lazy expiry and a
    capacity cap. Single-process only — state does not survive restarts
    (an unconsumed challenge dies with the process, which fails closed),
    and replicas sharing verification traffic would each accept the same
    challenge once. Deployments spanning processes or hosts need a
    ChallengeStore over shared storage whose consume is atomic (e.g. a
    single-row DELETE ... RETURNING)."""

    def __init__(self, max_size: int = 10_000) -> None:
        if max_size < 1:
            raise ValueError(f"MemoryChallengeStore max_size must be >= 1, got {max_size}")
        self._max_size = max_size
        self._records: dict[str, _ChallengeRecord] = {}
        self._lock = threading.Lock()

    def issue(self, session_context: bytes, ttl_seconds: int) -> Tuple[bytes, int]:
        if session_context and len(session_context) != 32:
            raise ValueError(
                f"session context must be empty or 32 bytes, got {len(session_context)}"
            )
        if ttl_seconds <= 0:
            raise ValueError(f"challenge ttl must be positive, got {ttl_seconds}")
        now = int(time.time())
        expires_at = now + ttl_seconds
        challenge = generate_challenge()
        with self._lock:
            self._expire_locked(now)
            if len(self._records) >= self._max_size:
                raise RuntimeError("challenge store full — too many pending challenges")
            self._records[base64.b64encode(challenge).decode("ascii")] = _ChallengeRecord(
                session_context=bytes(session_context or b""),
                expires_at=expires_at,
            )
        return challenge, expires_at

    def validate(self, challenge: bytes, session_context: bytes, now: int) -> Optional[str]:
        with self._lock:
            record = self._lookup_locked(challenge, session_context, now)
            return None if record is not None else UNKNOWN_CHALLENGE

    def consume(self, challenge: bytes, session_context: bytes, now: int) -> Optional[str]:
        # Check-and-delete under one lock: of two concurrent presentations
        # of the same challenge, exactly one can succeed. Removal frees
        # the record's capacity slot immediately; a session-context
        # mismatch leaves the record in place.
        with self._lock:
            key = self._lookup_locked(challenge, session_context, now)
            if key is None:
                return UNKNOWN_CHALLENGE
            del self._records[key]
            return None

    def _lookup_locked(
        self, challenge: bytes, session_context: bytes, now: int
    ) -> Optional[str]:
        """Resolve a presentable record's key, or None. A session-context
        mismatch fails WITHOUT touching the record, so a presentation
        under the wrong binding cannot burn the legitimate one."""
        self._expire_locked(now)
        key = base64.b64encode(challenge).decode("ascii")
        record = self._records.get(key)
        if record is None:
            return None
        if record.session_context != bytes(session_context or b""):
            return None
        return key

    def _expire_locked(self, now: int) -> None:
        expired = [k for k, r in self._records.items() if r.expires_at < now]
        for k in expired:
            del self._records[k]
