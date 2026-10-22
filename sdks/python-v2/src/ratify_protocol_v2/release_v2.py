"""Committed versus released (mirrors Go release_v2.go, SPEC-v2 §6.9, §7.9).

``verify_proof_bundle_v2`` commits a terminal Protocol result and returns an
opaque :class:`CommittedV2Outcome` that exposes no decision.
:func:`release_v2_decision` is the only path to an actionable decision. Its
result :class:`V2ReleasedDecision` has no public constructor: instances are
created only inside this module with a module-private sentinel, every
accessor returns a copy, and only :meth:`V2ReleasedDecision.allowed` may
gate a side effect.
"""
from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass
from typing import Optional

from . import context_v2
from .claim_store_v2 import V2AuthoritativeClock
from .clock_bounds_v2 import valid_v2_timestamp
from .errors_v2 import V2Error, V2ErrorClass, error_class_of
from .types import HybridPublicKey
from .types_v2 import V2CheckpointAcknowledgement, lower_hex_string

__all__ = [
    "CommittedV2Outcome", "V2ReleasedDecision", "V2ReleaseResult", "V2ReleaseRecord", "V2TerminalClaimRecord",
    "V2ReleaseConfig", "V2ReceiptPublisher", "V2ReceiptCheckpoint", "V2ReleaseClaimStore",
    "V2CheckpointAcknowledgement", "AcknowledgementNotFoundErrorV2", "ReleaseStateMismatchErrorV2",
    "receipt_outbox_digest_v2", "release_v2_decision",
    "V2_RELEASE_RELEASED", "V2_RELEASE_PENDING", "V2_RELEASE_WITHHELD", "V2_RELEASE_REJECTED",
]

V2_RELEASE_RELEASED = "released"
V2_RELEASE_PENDING = "pending"
V2_RELEASE_WITHHELD = "withheld"
V2_RELEASE_REJECTED = "rejected"

# Module-private capability: only code in this module holds it, so only this
# module can construct a CommittedV2Outcome or a V2ReleasedDecision.
_SEAL = object()


def receipt_outbox_digest_v2(body: bytes) -> str:
    """Go ``ReceiptOutboxDigestV2``: ``sha384:`` hex of
    SHA-384("ratify-protocol-receipt-outbox-v2" || 0x00 || body)."""
    return "sha384:" + hashlib.sha384(b"ratify-protocol-receipt-outbox-v2\x00" + bytes(body)).hexdigest()


class CommittedV2Outcome:
    """The immutable, non-actionable handoff from a committed verification to
    publication and :func:`release_v2_decision`."""

    __slots__ = ("_claim_id", "_verifier_id", "_receipt_body", "_challenge_expires_at", "_allow_horizon")

    def __init__(self, seal: object = None, *, claim_id: str = "", verifier_id: str = "", receipt_body: bytes = b"",
                 challenge_expires_at: int = 0, allow_horizon: int = 0):
        if seal is not _SEAL:
            raise TypeError("CommittedV2Outcome is created only by the v2 verifier and recovery")
        object.__setattr__(self, "_claim_id", claim_id)
        object.__setattr__(self, "_verifier_id", verifier_id)
        object.__setattr__(self, "_receipt_body", bytes(receipt_body))
        object.__setattr__(self, "_challenge_expires_at", challenge_expires_at)
        object.__setattr__(self, "_allow_horizon", allow_horizon)

    def __setattr__(self, name, value):
        raise AttributeError("CommittedV2Outcome is immutable")

    def __delattr__(self, name):
        raise AttributeError("CommittedV2Outcome is immutable")

    def __reduce__(self):
        raise TypeError("CommittedV2Outcome cannot be serialized")

    def _get(self, name: str, default):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            return default

    def claim_id(self) -> str:
        """The Protocol claim ID of the committed evaluation."""
        return self._get("_claim_id", "")

    def receipt_body(self) -> bytes:
        """A copy of the sealed receipt outbox body, for the receipt publisher
        only. Applications must not parse it to authorize."""
        return bytes(self._get("_receipt_body", b""))

    def receipt_body_digest(self) -> str:
        """ReceiptOutboxDigest of the sealed body (SPEC-v2 §4)."""
        return receipt_outbox_digest_v2(self.receipt_body())

    def challenge_expires_at(self) -> int:
        return self._get("_challenge_expires_at", 0)

    def allow_horizon(self) -> tuple[int, bool]:
        """The exclusive allow deadline; ``ok`` is False unless the committed
        result can become an allow."""
        horizon = self._get("_allow_horizon", 0)
        return horizon, horizon > 0

    def __repr__(self) -> str:
        return f"<CommittedV2Outcome claim_id={self.claim_id()!r}>"


def _new_committed_v2_outcome(claim, body: bytes, allow_horizon: int) -> CommittedV2Outcome:
    return CommittedV2Outcome(_SEAL, claim_id=claim.claim_id, verifier_id=claim.verifier_id, receipt_body=body,
                              challenge_expires_at=claim.expires_at, allow_horizon=allow_horizon)


class AcknowledgementNotFoundErrorV2(Exception):
    """Go ``ErrV2AcknowledgementNotFound``."""

    def __init__(self, message: str = "v2 checkpoint acknowledgement not found"):
        super().__init__(message)


class ReleaseStateMismatchErrorV2(Exception):
    """Go ``ErrV2ReleaseStateMismatch``: a different release record exists."""

    def __init__(self, message: str = "v2 claim already records a different release"):
        super().__init__(message)


class V2ReceiptPublisher(abc.ABC):
    """The Part B receipt outbox drain (§7.7)."""

    @abc.abstractmethod
    def publish_v2_receipt(self, ctx: context_v2.Context, claim_id: str, receipt_body: bytes) -> bytes:
        ...


class V2ReceiptCheckpoint(abc.ABC):
    """The caller-configured independent checkpoint (§7.8)."""

    @abc.abstractmethod
    def acknowledge_v2_receipt(self, ctx: context_v2.Context, log_id: str, sequence: int, previous_entry_hash: bytes,
                               entry_hash: bytes) -> V2CheckpointAcknowledgement:
        ...

    @abc.abstractmethod
    def get_v2_acknowledgement(self, ctx: context_v2.Context, log_id: str, sequence: int) -> V2CheckpointAcknowledgement:
        ...


@dataclass(frozen=True)
class V2ReleaseRecord:
    """The durable release record of §6.9 step 9."""

    claim_id: str
    entry_hash: bytes
    ack_timestamp: int


@dataclass
class V2TerminalClaimRecord:
    """What the claim store returns to release (§7.3)."""

    terminal: bool = False
    receipt_outbox_digest: str = ""
    challenge_expires_at: int = 0
    allow_horizon: int = 0
    finalized_at: int = 0
    receipt_abandoned: bool = False
    release: Optional[V2ReleaseRecord] = None


class V2ReleaseClaimStore(V2AuthoritativeClock):
    """The claim-store view release needs."""

    @abc.abstractmethod
    def load_v2_terminal_claim(self, ctx: context_v2.Context, claim_id: str) -> V2TerminalClaimRecord:
        ...

    @abc.abstractmethod
    def record_v2_release(self, ctx: context_v2.Context, record: V2ReleaseRecord) -> None:
        ...


@dataclass
class V2ReleaseConfig:
    """Caller-authenticated release configuration."""

    verifier_public_key: Optional[HybridPublicKey] = None
    log_id: str = ""
    claim_store: Optional[V2ReleaseClaimStore] = None
    checkpoint: Optional[V2ReceiptCheckpoint] = None


class V2ReleasedDecision:
    """The only actionable value in this package (SPEC-v2 §6.9).

    It has no public constructor or setter, cannot be pickled or copied into
    a new actionable instance, and every accessor returns a copy. An instance
    not created by :func:`release_v2_decision` is never actionable."""

    __slots__ = ("_claim_id", "_decision", "_reason", "_identity_status", "_granted_scope", "_receipt_wire",
                 "_release_time", "_challenge_expires_at", "_allow_horizon", "_sealed")

    def __init__(self, *args, **kwargs):
        raise TypeError("V2ReleasedDecision is created only by release_v2_decision")

    @classmethod
    def _create(cls, seal: object, **values) -> "V2ReleasedDecision":
        if seal is not _SEAL:
            raise TypeError("V2ReleasedDecision is created only by release_v2_decision")
        decision = object.__new__(cls)
        for name in ("claim_id", "decision", "reason", "identity_status", "granted_scope", "receipt_wire",
                     "release_time", "challenge_expires_at", "allow_horizon"):
            object.__setattr__(decision, "_" + name, values[name])
        object.__setattr__(decision, "_sealed", _SEAL)
        return decision

    def __setattr__(self, name, value):
        raise AttributeError("V2ReleasedDecision is immutable")

    def __delattr__(self, name):
        raise AttributeError("V2ReleasedDecision is immutable")

    def __reduce__(self):
        raise TypeError("V2ReleasedDecision cannot be serialized")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def _get(self, name: str, default):
        try:
            if object.__getattribute__(self, "_sealed") is not _SEAL:
                return default
            return object.__getattribute__(self, name)
        except AttributeError:
            return default

    def claim_id(self) -> str:
        return self._get("_claim_id", "")

    def decision(self) -> str:
        """``allow``, ``deny``, or ``indeterminate``. Use :meth:`allowed`, not
        this value, to gate a side effect."""
        return self._get("_decision", "")

    def reason(self) -> str:
        return self._get("_reason", "")

    def identity_status(self) -> str:
        return self._get("_identity_status", "")

    def granted_scope(self) -> list:
        """A copy of the released granted scope."""
        return list(self._get("_granted_scope", []))

    def receipt_wire(self) -> bytes:
        """A copy of the signed receipt wire verified during release."""
        return bytes(self._get("_receipt_wire", b""))

    def receipt(self):
        """A freshly decoded copy of the signed receipt verified during release."""
        from .verification_receipt_v2 import decode_verification_receipt_v2

        wire = self.receipt_wire()
        if not wire:
            raise ValueError("v2 released decision carries no receipt")
        return decode_verification_receipt_v2(wire)

    def release_time(self) -> int:
        """The checkpoint acknowledgement time of the release."""
        return self._get("_release_time", 0)

    def challenge_expires_at(self) -> int:
        return self._get("_challenge_expires_at", 0)

    def allow_horizon(self) -> tuple[int, bool]:
        horizon = self._get("_allow_horizon", 0)
        return horizon, horizon > 0

    def allowed(self, ctx: context_v2.Context, clock: V2AuthoritativeClock) -> bool:
        """Whether this released allow may be acted on now: True only for an
        allow while now < challenge_expires_at and now < allow_horizon (both
        exclusive), read from the receiver's authoritative clock. A clock
        error, exception, or reading outside the timestamp domain is False.
        Call it immediately before the side effect."""
        if (not isinstance(ctx, context_v2.Context) or clock is None or self.decision() != "allow"
                or not self.receipt_wire() or self._get("_allow_horizon", 0) <= 0):
            return False
        try:
            now = _read_v2_authoritative_time(ctx, clock)
        except Exception:  # noqa: BLE001
            return False
        return now < self.challenge_expires_at() and now < self._get("_allow_horizon", 0)

    def __repr__(self) -> str:
        return f"<V2ReleasedDecision claim_id={self.claim_id()!r} decision={self.decision()!r}>"


@dataclass(frozen=True)
class V2ReleaseResult:
    """``decision`` is set only when ``status`` is ``released``; ``reason`` is
    empty only when released. Only ``decision.allowed`` may gate a side effect."""

    status: str
    reason: str = ""
    decision: Optional[V2ReleasedDecision] = None


def _result(status: str, reason: str) -> V2ReleaseResult:
    return V2ReleaseResult(status=status, reason=reason)


def _read_v2_authoritative_time(ctx: context_v2.Context, clock) -> int:
    """Go ``readV2AuthoritativeTime``: a store-reported clock_regressed keeps
    its class; any other failure or an out-of-domain reading is unavailable."""
    now = clock.authoritative_time_v2(ctx)
    if not valid_v2_timestamp(now):
        raise ValueError(f"v2 authoritative clock returned {now!r} outside 0..253402300799")
    return now


def _verify_published_v2_receipt(wire: bytes, config: V2ReleaseConfig):
    from ._v2json import canonical
    from .signing_v2 import VERIFICATION_RECEIPT, verify_v2_statement
    from .verification_receipt_v2 import decode_verification_receipt_v2, receipt_v2_signable

    receipt = decode_verification_receipt_v2(wire)
    if receipt.log_id != config.log_id:
        raise ValueError("v2 published receipt belongs to an unconfigured log")
    body = canonical(receipt_v2_signable(receipt))
    verify_v2_statement(VERIFICATION_RECEIPT, body, receipt.signature, config.verifier_public_key)
    return receipt


def release_v2_decision(ctx: context_v2.Context, committed: CommittedV2Outcome, signed_receipt: Optional[bytes],
                        config: V2ReleaseConfig) -> V2ReleaseResult:
    """Go ``ReleaseV2Decision``: the release steps of SPEC-v2 §6.9 in order,
    stopping at the first that does not pass."""
    from .signing_v2 import key_id_v2
    from .verification_receipt_v2 import verification_receipt_v2_body, verification_receipt_v2_digest

    if (not isinstance(ctx, context_v2.Context) or not isinstance(committed, CommittedV2Outcome)
            or not isinstance(config, V2ReleaseConfig)):
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    claim_id = committed.claim_id()
    committed_body = committed.receipt_body()
    verifier_id_committed = committed._get("_verifier_id", "")
    challenge_expires_at = committed.challenge_expires_at()
    allow_horizon, _ = committed.allow_horizon()
    if claim_id == "" or len(committed_body) == 0 or config.claim_store is None or config.checkpoint is None:
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    if not isinstance(config.log_id, str) or len(config.log_id) != 32 or not lower_hex_string(config.log_id):
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    # 1. Committed state.
    try:
        record = config.claim_store.load_v2_terminal_claim(ctx, claim_id)
        if not isinstance(record, V2TerminalClaimRecord):
            raise ValueError("claim store returned an invalid terminal record")
    except Exception:  # noqa: BLE001
        return _result(V2_RELEASE_PENDING, "claim_store_unavailable")
    if record.receipt_abandoned:
        return _result(V2_RELEASE_WITHHELD, "receipt_abandoned")
    try:
        verifier_id = key_id_v2(config.verifier_public_key)
    except Exception:  # noqa: BLE001
        verifier_id = None
    if (not record.terminal or record.receipt_outbox_digest != receipt_outbox_digest_v2(committed_body)
            or record.challenge_expires_at != challenge_expires_at or record.allow_horizon != allow_horizon
            or verifier_id is None or verifier_id != verifier_id_committed):
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    # 2. Receipt.
    if not signed_receipt:
        return _result(V2_RELEASE_PENDING, "receipt_not_appended")
    signed_receipt = bytes(signed_receipt)
    try:
        receipt = _verify_published_v2_receipt(signed_receipt, config)
    except Exception:  # noqa: BLE001
        receipt = None
    if receipt is None or receipt.verifier_id != verifier_id_committed:
        return _result(V2_RELEASE_REJECTED, "receipt_invalid")
    # 3. Body binding.
    try:
        body = verification_receipt_v2_body(receipt)
    except Exception:  # noqa: BLE001
        body = None
    if body is None or body != committed_body:
        return _result(V2_RELEASE_REJECTED, "receipt_body_mismatch")
    try:
        entry_hash = bytes(verification_receipt_v2_digest(receipt))
    except Exception:  # noqa: BLE001
        return _result(V2_RELEASE_REJECTED, "receipt_invalid")
    # 4. Prior release: the same receipt entry. A recorded release only
    # enforces sameness; it never substitutes for the acknowledgement.
    release = record.release
    if release is not None and (release.claim_id != claim_id or bytes(release.entry_hash) != entry_hash):
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    # 5. Predecessor.
    if receipt.sequence > 1:
        try:
            previous = config.checkpoint.get_v2_acknowledgement(ctx, receipt.log_id, receipt.sequence - 1)
            if not isinstance(previous, V2CheckpointAcknowledgement):
                raise ValueError("invalid acknowledgement")
        except Exception:  # noqa: BLE001
            return _result(V2_RELEASE_PENDING, "acknowledgement_unavailable")
        if (previous.log_id != receipt.log_id or previous.sequence != receipt.sequence - 1
                or bytes(previous.entry_hash) != bytes(receipt.previous_receipt_hash)):
            return _result(V2_RELEASE_REJECTED, "log_predecessor_mismatch")
    # 6. Acknowledgement.
    try:
        ack = config.checkpoint.get_v2_acknowledgement(ctx, receipt.log_id, receipt.sequence)
        if not isinstance(ack, V2CheckpointAcknowledgement):
            raise ValueError("invalid acknowledgement")
    except Exception:  # noqa: BLE001
        return _result(V2_RELEASE_PENDING, "acknowledgement_unavailable")
    if ack.log_id != receipt.log_id or ack.sequence != receipt.sequence or bytes(ack.entry_hash) != entry_hash:
        return _result(V2_RELEASE_REJECTED, "acknowledgement_mismatch")
    if release is not None and release.ack_timestamp != ack.timestamp:
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    # 7. Clock.
    try:
        now = _read_v2_authoritative_time(ctx, config.claim_store)
    except Exception as exc:  # noqa: BLE001
        if error_class_of(exc) == V2ErrorClass.CLOCK_REGRESSED:
            return _result(V2_RELEASE_WITHHELD, "clock_regressed")
        return _result(V2_RELEASE_PENDING, "clock_unavailable")
    if not valid_v2_timestamp(ack.timestamp) or record.finalized_at > ack.timestamp or ack.timestamp > now:
        return _result(V2_RELEASE_WITHHELD, "clock_regressed")
    # 8. Deadlines.
    if ack.timestamp >= challenge_expires_at or now >= challenge_expires_at:
        return _result(V2_RELEASE_WITHHELD, "challenge_expired")
    if receipt.decision == "allow" and (allow_horizon <= 0 or ack.timestamp >= allow_horizon or now >= allow_horizon):
        return _result(V2_RELEASE_WITHHELD, "allow_horizon_passed")
    # 9. Record.
    if release is None:
        try:
            config.claim_store.record_v2_release(ctx, V2ReleaseRecord(claim_id=claim_id, entry_hash=entry_hash,
                                                                      ack_timestamp=ack.timestamp))
        except ReleaseStateMismatchErrorV2:
            return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
        except Exception:  # noqa: BLE001
            return _result(V2_RELEASE_PENDING, "claim_store_unavailable")
    # 10. Return.
    decision = V2ReleasedDecision._create(
        _SEAL, claim_id=claim_id, decision=receipt.decision, reason=receipt.decision_reason,
        identity_status=receipt.identity_status, granted_scope=list(receipt.granted_scope or []),
        receipt_wire=bytes(signed_receipt), release_time=ack.timestamp, challenge_expires_at=challenge_expires_at,
        allow_horizon=allow_horizon if receipt.decision == "allow" else 0,
    )
    return V2ReleaseResult(status=V2_RELEASE_RELEASED, decision=decision)
