"""In-memory REFERENCE challenge issuance store (mirrors Go
v2reference/challenges.go). TEST AND CONFORMANCE USE ONLY: not durable."""
from __future__ import annotations

import threading

from .. import context_v2
from ..challenge_claim_v2 import challenge_claim_digest_v2
from ..challenge_issuance_v2 import (
    ChallengeIssuanceConflictErrorV2,
    ChallengeIssuanceNotFoundErrorV2,
    V2ChallengeIssuanceStore,
)
from ..verify_v2_preflight import ExpectedChallengeV2, clone_expected_challenge_v2

PERSIST_OK = 0
# Fails without storing anything.
PERSIST_FAIL_BEFORE_COMMIT = 1
# Stores the record, then reports failure (a crash after the durable write).
PERSIST_FAIL_AFTER_COMMIT = 2


class PersistFailedError(Exception):
    """Go ``ErrPersistFailed``."""

    def __init__(self, message: str = "v2reference: scripted issuance persistence failure"):
        super().__init__(message)


def _issuance_key(namespace: str, epoch: int, digest: bytes) -> str:
    return f"{len(namespace.encode('utf-8'))}:{namespace}|{epoch}|{bytes(digest).hex()}"


class TestOnlyChallengeIssuanceStore(V2ChallengeIssuanceStore):
    """Insert-only, never-overwriting in-memory issuance store."""

    __test__ = False  # not a pytest test class

    def __init__(self):
        self._lock = threading.Lock()
        self._records: dict = {}
        self._fault = PERSIST_OK

    def fail_next_persist(self, fault: int) -> None:
        with self._lock:
            self._fault = fault

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def persist_v2_challenge(self, ctx: context_v2.Context, record: ExpectedChallengeV2) -> None:
        with self._lock:
            fault, self._fault = self._fault, PERSIST_OK
            if fault == PERSIST_FAIL_BEFORE_COMMIT:
                raise PersistFailedError()
            digest = challenge_claim_digest_v2(record.value)
            key = _issuance_key(record.verifier_namespace, record.replay_epoch, digest)
            if key in self._records:
                raise ChallengeIssuanceConflictErrorV2()
            self._records[key] = clone_expected_challenge_v2(record)
            if fault == PERSIST_FAIL_AFTER_COMMIT:
                raise PersistFailedError()

    def load_v2_challenge(self, ctx: context_v2.Context, namespace: str, epoch: int, digest: bytes) -> ExpectedChallengeV2:
        with self._lock:
            record = self._records.get(_issuance_key(namespace, epoch, digest))
            if record is None:
                raise ChallengeIssuanceNotFoundErrorV2()
            return clone_expected_challenge_v2(record)
