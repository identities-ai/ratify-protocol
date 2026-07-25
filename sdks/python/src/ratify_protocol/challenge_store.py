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
# session binding. Deliberately identical across those cases so a rejection
# does not reveal whether a challenge exists; matches the reference
# verifier's documented error text.
UNKNOWN_CHALLENGE = "challenge was not issued by this verifier or has already been used"


@runtime_checkable
class ChallengeStore(Protocol):
    """Tracks verifier-issued challenges so each is accepted at most once
    within its freshness window (SPEC §10)."""

    def issue(self, session_context: bytes, ttl_seconds: int) -> Tuple[bytes, int]:
        """Generate a fresh challenge bound to ``session_context`` (empty =
        unbound), valid for ``ttl_seconds``. Returns ``(challenge,
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
        """Atomically mark ``challenge`` used. Exactly one consume of a
        given challenge may ever succeed; all later calls (and calls with
        a mismatched ``session_context``, which do NOT consume the record)
        return a rejection reason. Returns None on success."""
        ...


@dataclass
class _ChallengeRecord:
    session_context: bytes
    expires_at: int
    consumed: bool = False


class MemoryChallengeStore:
    """In-memory ChallengeStore: lock-guarded dict with lazy expiry and a
    capacity cap. Suitable for a single verifier process; state does not
    survive restarts (an unconsumed challenge dies with the process, which
    fails closed)."""

    def __init__(self, max_size: int = 10_000) -> None:
        self._max_size = max_size
        self._records: dict[str, _ChallengeRecord] = {}
        self._lock = threading.Lock()

    def issue(self, session_context: bytes, ttl_seconds: int) -> Tuple[bytes, int]:
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
        # Check-and-set under one lock: of two concurrent presentations of
        # the same challenge, exactly one can succeed.
        with self._lock:
            record = self._lookup_locked(challenge, session_context, now)
            if record is None:
                return UNKNOWN_CHALLENGE
            record.consumed = True
            return None

    def _lookup_locked(
        self, challenge: bytes, session_context: bytes, now: int
    ) -> Optional[_ChallengeRecord]:
        """Resolve a presentable record, or None. A session-context
        mismatch fails WITHOUT touching the record, so a presentation
        under the wrong binding cannot burn the legitimate one."""
        self._expire_locked(now)
        record = self._records.get(base64.b64encode(challenge).decode("ascii"))
        if record is None or record.consumed:
            return None
        if record.session_context != bytes(session_context or b""):
            return None
        return record

    def _expire_locked(self, now: int) -> None:
        expired = [k for k, r in self._records.items() if r.expires_at < now]
        for k in expired:
            del self._records[k]
