"""Challenge issuance helper (mirrors Go challenge_issuance_v2.go, SPEC-v2 §7.3).

The issuer generates 32 unpredictable challenge bytes, reads the
authoritative clock, and durably persists the complete issuance record
BEFORE returning the challenge. A failure at any step returns no challenge;
a record persisted without being returned is never presented and expires.
"""
from __future__ import annotations

import abc
import os
from dataclasses import dataclass
from typing import Callable, Optional

from . import context_v2
from .challenge_claim_v2 import challenge_claim_digest_v2
from .clock_bounds_v2 import checked_add_v2, valid_v2_timestamp
from .errors_v2 import V2Error, V2ErrorClass, classify, classified, V2ValueError
from .limits_v2 import MAX_IDENTIFIER_LENGTH_BYTES
from .release_v2 import _read_v2_authoritative_time
from .signing_v2 import key_id_v2
from .types import HybridPublicKey
from .types_v2 import MAX_SAFE_INTEGER, is_int, valid_v2_id
from .verify_v2_preflight import ExpectedChallengeV2, clone_expected_challenge_v2, clone_hybrid_public_key

V2_MAX_CHALLENGE_AGE_SECONDS = 300

# Bounds retries after a key conflict: a conflict with 32 random bytes
# indicates a broken random source, so the issuer fails rather than looping.
MAX_V2_ISSUANCE_ATTEMPTS = 3


class ChallengeIssuanceConflictErrorV2(Exception):
    """Go ``ErrV2ChallengeIssuanceConflict``: a record already exists for the
    same (namespace, replay_epoch, ChallengeClaimDigestV2)."""

    def __init__(self, message: str = "v2 challenge issuance record already exists"):
        super().__init__(message)


class ChallengeIssuanceNotFoundErrorV2(Exception):
    """Go ``ErrV2ChallengeIssuanceNotFound``."""

    def __init__(self, message: str = "v2 challenge issuance record not found"):
        super().__init__(message)


class V2ChallengeIssuanceStore(abc.ABC):
    """The durable issuance record store, keyed like the claim store. It never
    overwrites an existing record."""

    @abc.abstractmethod
    def persist_v2_challenge(self, ctx: context_v2.Context, record: ExpectedChallengeV2) -> None:
        ...

    @abc.abstractmethod
    def load_v2_challenge(self, ctx: context_v2.Context, namespace: str, replay_epoch: int, claim_digest: bytes) -> ExpectedChallengeV2:
        ...


@dataclass
class V2ChallengeIssueRequest:
    """The authenticated issuance context."""

    verifier_namespace: str = ""
    replay_epoch: int = 0
    verifier_id: str = ""
    # expires_at = issued_at + lifetime_seconds, 1..300.
    lifetime_seconds: int = 0
    expected_agent_id: str = ""
    expected_agent_public_key: Optional[HybridPublicKey] = None
    expected_receiver_id: str = ""
    expected_session_context: Optional[bytes] = None


@dataclass
class V2ChallengeIssuer:
    """Issues challenges. ``clock`` and ``store`` are required; ``random``
    (``n -> bytes``) defaults to ``os.urandom`` and exists only so tests can
    script the bytes."""

    clock: object = None
    store: Optional[V2ChallengeIssuanceStore] = None
    random: Optional[Callable[[int], bytes]] = None

    @classified(V2ErrorClass.CLAIM_STORE_UNAVAILABLE)
    def issue_challenge_v2(self, ctx: context_v2.Context, req: V2ChallengeIssueRequest) -> ExpectedChallengeV2:
        """Go ``IssueChallengeV2``. A clock or issuance-store failure is
        ``claim_store_unavailable``; a failing random source and the third
        consecutive key conflict are ``configuration_invalid`` (SPEC-v2 §7.3)."""
        if not isinstance(ctx, context_v2.Context) or self.clock is None or self.store is None:
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                          "v2 challenge issuer requires a context, authoritative clock and issuance store")
        _validate_v2_challenge_issue_request(req)
        random = self.random or os.urandom
        issued_at = _read_v2_authoritative_time(ctx, self.clock)
        expires_at, ok = checked_add_v2(issued_at, req.lifetime_seconds)
        if not ok or not valid_v2_timestamp(expires_at):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 challenge expiry leaves the timestamp domain")
        for _ in range(MAX_V2_ISSUANCE_ATTEMPTS):
            try:
                value = random(32)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:  # noqa: BLE001 - a failing random source is caller configuration
                raise classify(V2ErrorClass.CONFIGURATION_INVALID,
                               ValueError(f"v2 challenge issuance: random source: {exc}")) from exc
            if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
                raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID,
                                   "v2 challenge issuance: random source returned the wrong length")
            record = ExpectedChallengeV2(
                value=bytes(value), issued_at=issued_at, expires_at=expires_at,
                verifier_namespace=req.verifier_namespace, replay_epoch=req.replay_epoch, verifier_id=req.verifier_id,
                expected_agent_id=req.expected_agent_id, expected_receiver_id=req.expected_receiver_id,
                expected_session_context=None if req.expected_session_context is None else bytes(req.expected_session_context),
                expected_agent_public_key=clone_hybrid_public_key(req.expected_agent_public_key),
            )
            try:
                self.store.persist_v2_challenge(ctx, clone_expected_challenge_v2(record))
            except ChallengeIssuanceConflictErrorV2:
                continue
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:  # noqa: BLE001 - a store failure (Go: a recovered panic)
                raise RuntimeError("v2 challenge issuance: the record was not durably persisted, "
                                   f"so the challenge is not exposed: {exc}") from exc
            return clone_expected_challenge_v2(record)
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                      f"v2 challenge issuance: {MAX_V2_ISSUANCE_ATTEMPTS} consecutive key conflicts; "
                      "the random source is not trustworthy")


@classified(V2ErrorClass.EXPECTED_CHALLENGE_MISSING)
def load_expected_challenge_v2(ctx: context_v2.Context, store: V2ChallengeIssuanceStore, namespace: str,
                               replay_epoch: int, challenge: bytes) -> ExpectedChallengeV2:
    """Go ``LoadExpectedChallengeV2``: a missing record is
    expected_challenge_unavailable."""
    if not isinstance(ctx, context_v2.Context) or store is None:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 challenge lookup requires a context and issuance store")
    try:
        digest = challenge_claim_digest_v2(bytes(challenge))
    except Exception as exc:  # noqa: BLE001
        raise V2Error(V2ErrorClass.EXPECTED_CHALLENGE_MISSING, "v2 presented challenge is not 32 bytes") from exc
    try:
        record = store.load_v2_challenge(ctx, namespace, replay_epoch, bytes(digest))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - a store failure (Go: a recovered panic)
        raise classify(V2ErrorClass.EXPECTED_CHALLENGE_MISSING, exc) from exc
    # The store is keyed by digest; the record must still name these exact
    # bytes and key, or it is not this challenge's record.
    if (not isinstance(record, ExpectedChallengeV2) or bytes(record.value) != bytes(challenge)
            or record.verifier_namespace != namespace or record.replay_epoch != replay_epoch):
        raise V2Error(V2ErrorClass.EXPECTED_CHALLENGE_MISSING, "v2 issuance store returned a record for another challenge")
    return clone_expected_challenge_v2(record)


def _utf8(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _validate_v2_challenge_issue_request(req: V2ChallengeIssueRequest) -> None:
    def invalid(message: str) -> V2Error:
        return V2Error(V2ErrorClass.CONFIGURATION_INVALID, message)

    if not isinstance(req, V2ChallengeIssueRequest):
        raise invalid("v2 challenge issue request has the wrong type")
    if req.verifier_namespace == "" or not _utf8(req.verifier_namespace):
        raise invalid("v2 challenge issuance requires a non-empty UTF-8 verifier namespace")
    if not is_int(req.replay_epoch) or req.replay_epoch < 0 or req.replay_epoch > MAX_SAFE_INTEGER:
        raise invalid(f"v2 challenge replay epoch must be 0..{MAX_SAFE_INTEGER}")
    if not valid_v2_id(req.verifier_id):
        raise invalid("v2 challenge verifier_id must be a v2 key ID")
    if not is_int(req.lifetime_seconds) or req.lifetime_seconds < 1 or req.lifetime_seconds > V2_MAX_CHALLENGE_AGE_SECONDS:
        raise invalid(f"v2 challenge lifetime must be 1..{V2_MAX_CHALLENGE_AGE_SECONDS} seconds")
    if not isinstance(req.expected_agent_id, str) or (req.expected_agent_id == "") != (req.expected_agent_public_key is None):
        raise invalid("v2 expected agent ID and public key must be supplied together")
    if req.expected_agent_public_key is not None:
        try:
            agent_id = key_id_v2(req.expected_agent_public_key)
        except Exception:  # noqa: BLE001
            agent_id = None
        if agent_id is None or agent_id != req.expected_agent_id:
            raise invalid("v2 expected agent ID does not match its complete public key")
    if not isinstance(req.expected_receiver_id, str):
        raise invalid("v2 expected receiver ID must be a string")
    if req.expected_receiver_id != "" and (not _utf8(req.expected_receiver_id)
                                           or len(req.expected_receiver_id.encode("utf-8")) > MAX_IDENTIFIER_LENGTH_BYTES):
        raise invalid(f"v2 expected receiver ID must be valid UTF-8 of at most {MAX_IDENTIFIER_LENGTH_BYTES} bytes")
    if req.expected_session_context is not None and (not isinstance(req.expected_session_context, (bytes, bytearray))
                                                     or len(req.expected_session_context) != 32):
        raise invalid("v2 expected session context must be absent or exactly 32 bytes")
