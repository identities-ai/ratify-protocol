"""Protocol v2 language-neutral failure classes (mirrors Go errors_v2.go).

Messages are diagnostic only; conformance compares classes. An error that was
never classified reports ``unclassified`` so conformance fails loudly instead
of guessing.
"""
from __future__ import annotations

import functools
from typing import Callable, Optional, TypeVar

_F = TypeVar("_F", bound=Callable)


class V2ErrorClass:
    UNCLASSIFIED = "unclassified"

    # Wire and structure.
    MALFORMED = "malformed"
    UNSUPPORTED_OBJECT_TYPE = "unsupported_object_type"
    KEY_ID_MISMATCH = "key_id_mismatch"
    DELEGATION_DIGEST_MISMATCH = "delegation_digest_mismatch"
    CHAIN_LINKAGE_MISMATCH = "chain_linkage_mismatch"
    DUPLICATE_CERTIFICATE_REF = "duplicate_certificate_ref"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_REQUIRED_SCOPE = "invalid_required_scope"

    # Challenge preflight and pure receiver binding.
    CONFIGURATION_INVALID = "configuration_invalid"
    EXPECTED_CHALLENGE_MISSING = "expected_challenge_unavailable"
    NAMESPACE_MISMATCH = "namespace_mismatch"
    STALE_REPLAY_EPOCH = "stale_replay_epoch"
    VERIFIER_ID_MISMATCH = "verifier_id_mismatch"
    CHALLENGE_MISMATCH = "challenge_mismatch"
    CHALLENGE_NOT_FRESH = "challenge_not_fresh"
    EXPECTED_AGENT_MISMATCH = "expected_agent_mismatch"
    SESSION_CONTEXT_MISMATCH = "session_context_mismatch"
    RECEIVER_AUDIENCE_REQUIRED = "receiver_audience_required"
    RECEIVER_AUDIENCE_MISMATCH = "receiver_audience_mismatch"
    RECEIVER_BINDING_REJECTED = "receiver_binding_rejected"
    CLAIM_REPLAY = "claim_replay"
    CLAIM_STORE_UNAVAILABLE = "claim_store_unavailable"
    STATUS_KEY_BINDING_MISMATCH = "status_key_binding_mismatch"
    RECEIPT_BUNDLE_MISMATCH = "receipt_bundle_mismatch"
    BUNDLE_HASH_MISMATCH = "bundle_hash_mismatch"
    TRANSACTION_PARTY_MISMATCH = "transaction_party_mismatch"
    TRANSACTION_CONTEXT_MISMATCH = "transaction_context_mismatch"
    TRANSACTION_SIGNATURE_SET_INVALID = "transaction_signature_set_invalid"
    ROTATION_STATE_MISMATCH = "rotation_state_mismatch"
    ROTATION_KEY_REUSED = "rotation_key_reused"
    ROTATION_FUTURE_DATED = "rotation_future_dated"
    ROTATION_FORK = "rotation_fork"
    ROTATION_FROZEN = "rotation_frozen"
    ROTATION_RECOVERY_INVALID = "rotation_recovery_invalid"
    LOG_STATE_MISMATCH = "log_state_mismatch"
    LOG_GAP = "log_gap"
    LOG_ORPHAN = "log_orphan"
    LOG_FORK = "log_fork"
    LOG_FROZEN = "log_frozen"
    STATUS_OBJECT_REJECTED = "status_object_rejected"

    # Part B stream sequence (SPEC-v2 §7.4): gap, duplicate and reorder all
    # fail before claim with this one class.
    STREAM_SEQUENCE_MISMATCH = "stream_sequence_mismatch"

    # An authoritative clock reading below the store's high-water mark or
    # below T_claim (SPEC-v2 §7.2).
    CLOCK_REGRESSED = "clock_regressed"
    # The caller's context ended. After the claim, nothing was committed and
    # the claim remains recoverable; before the claim, nothing was consumed
    # (SPEC-v2 §6.11).
    EVALUATION_CANCELLED = "evaluation_cancelled"

    # Part B claim lifecycle.
    CLAIM_LEASE_LIVE = "claim_lease_live"
    CLAIM_LEASE_LOST = "claim_lease_lost"
    CLAIM_ALREADY_TERMINAL = "claim_already_terminal"
    CLAIM_NOT_FOUND = "claim_not_found"
    # An exact retry of a claim whose receipt was abandoned (SPEC-v2 §7.7).
    RECEIPT_ABANDONED = "receipt_abandoned"

    # An allow reached finalization at or after its allow horizon or the
    # challenge expiry; nothing was committed (SPEC-v2 §7.2, §7.5).
    ALLOW_HORIZON_PASSED = "allow_horizon_passed"


# The closed list of SPEC-v2 §2.7 (49 classes). ``unclassified`` is not a
# Protocol class: it marks an error this package failed to classify.
ALL_ERROR_CLASSES: frozenset = frozenset(
    value for name, value in vars(V2ErrorClass).items()
    if not name.startswith("_") and isinstance(value, str) and value != V2ErrorClass.UNCLASSIFIED
)


class V2Error(Exception):
    """A diagnostic error carrying a conformance class.

    Plain ``ValueError`` (and any other exception) raised inside v2 code is
    unclassified until a boundary wraps it with :func:`classify`, exactly as
    Go wraps an unclassified error with ``v2Classify``.
    """

    def __init__(self, error_class: str, message: str):
        super().__init__(message)
        self.error_class = error_class


# Sentinel errors that Go classifies through errors.Is.
class WitnessLogForkError(V2Error):
    def __init__(self, message: str = "witness log fork"):
        super().__init__(V2ErrorClass.LOG_FORK, message)


class WitnessLogGapError(V2Error):
    def __init__(self, message: str = "witness log sequence gap"):
        super().__init__(V2ErrorClass.LOG_GAP, message)


class WitnessLogOrphanError(V2Error):
    def __init__(self, message: str = "orphaned witness entry"):
        super().__init__(V2ErrorClass.LOG_ORPHAN, message)


class WitnessLogFrozenError(V2Error):
    def __init__(self, message: str = "witness log is frozen"):
        super().__init__(V2ErrorClass.LOG_FROZEN, message)


class ClaimProofConflictError(V2Error):
    def __init__(self, message: str = "v2 challenge was already claimed by a different proof"):
        super().__init__(V2ErrorClass.CLAIM_REPLAY, message)


class KeyRotationForkError(V2Error):
    def __init__(self, message: str = "key rotation fork"):
        super().__init__(V2ErrorClass.ROTATION_FORK, message)


class KeyRotationFrozenError(V2Error):
    def __init__(self, message: str = "key rotation authority is frozen"):
        super().__init__(V2ErrorClass.ROTATION_FROZEN, message)


def v2_error(error_class: str, message: str) -> V2Error:
    return V2Error(error_class, message)


def classify(error_class: str, exc: Optional[BaseException]) -> Optional[BaseException]:
    """Go ``v2Classify``: keep an existing class, otherwise attach one. A
    :class:`V2Error` that is still unclassified (a typed signing error) is
    classified in place, so its type and message are kept."""
    if exc is None:
        return None
    if isinstance(exc, V2Error):
        if exc.error_class == V2ErrorClass.UNCLASSIFIED:
            exc.error_class = error_class
        return exc
    wrapped = V2Error(error_class, str(exc))
    wrapped.__cause__ = exc
    return wrapped


def error_class_of(exc: Optional[BaseException]) -> str:
    """Go ``V2ErrorClassOf``: "" for no error, unclassified when unknown."""
    if exc is None:
        return ""
    if isinstance(exc, V2Error):
        return exc.error_class
    return V2ErrorClass.UNCLASSIFIED


class V2ValueError(V2Error, ValueError):
    """A classified error raised where the unclassified error was a
    ``ValueError``; it is still caught by ``except ValueError``."""


def classified(error_class: str) -> Callable[[_F], _F]:
    """Decorate a public v2 function so every error it raises carries a
    SPEC-v2 §2.7 class: the error's own class when it has one, otherwise
    ``error_class``, the class of the function's row in the §2.7 table (Go
    ``defer v2Classify(class, err)``). ``ImportError`` from a missing native
    extension is an installation failure, not a Protocol error, and passes
    through unchanged."""

    def decorate(fn: _F) -> _F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except V2Error as exc:
                classify(error_class, exc)
                raise
            except ImportError:
                raise
            except ValueError as exc:
                # Stay a ValueError so callers that caught the unclassified
                # error keep catching it.
                wrapped = V2ValueError(error_class, str(exc))
                raise wrapped from exc
            except Exception as exc:  # noqa: BLE001 - every public v2 error is classified
                raise classify(error_class, exc) from exc

        return wrapper  # type: ignore[return-value]

    return decorate
