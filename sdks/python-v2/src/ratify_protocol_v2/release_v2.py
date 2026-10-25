"""Committed versus released (mirrors Go release_v2.go, SPEC-v2 §6.9, §7.9).

``verify_proof_bundle_v2`` commits a terminal Protocol result and returns an
opaque :class:`CommittedV2Outcome` that exposes no decision.
:func:`release_v2_decision` is the only path to an actionable decision. Its
result :class:`V2ReleasedDecision` has no public constructor and holds no
state of its own: the state of every genuine instance lives in a registry
that only :func:`release_v2_decision` can write, because the registry exists
only in the closure that defines that function. There is no module-level
seal or token. An instance that is not in the registry (one made with
``object.__new__``, ``copy``, ``pickle``, or a subclass) is never actionable.
Every accessor returns a copy, and only :meth:`V2ReleasedDecision.allowed`
may gate a side effect.

Scope of this guarantee (SPEC-v2 §1.3): it prevents API misuse and
accidental construction. It is not a defense against hostile code running in
the same interpreter, which can already read the application's keys and
stores, and which can reach any Python object through ``gc`` or frame
introspection, a function's ``__closure__`` cells, or by monkeypatching this
module.
"""
from __future__ import annotations

import abc
import hashlib
import weakref
from dataclasses import dataclass
from typing import Optional

from . import context_v2
from .claim_store_v2 import V2AuthoritativeClock
from .clock_bounds_v2 import valid_v2_timestamp
from .errors_v2 import V2Error, V2ErrorClass, classified, error_class_of
from .types import HybridPublicKey
from .types_v2 import V2CheckpointAcknowledgement, lower_hex_string

__all__ = [
    "CommittedV2Outcome", "V2ReleasedDecision", "V2ReleaseResult", "V2ReleaseRecord", "V2TerminalClaimRecord",
    "V2ReleaseConfig", "V2ReceiptPublisher", "V2ReceiptCheckpoint", "V2ReleaseClaimStore",
    "V2CheckpointAcknowledgement", "AcknowledgementNotFoundErrorV2", "ReleaseStateMismatchErrorV2",
    "receipt_outbox_digest_v2", "release_v2_decision", "valid_v2_release_record_outcome",
    "V2_RELEASE_RELEASED", "V2_RELEASE_PENDING", "V2_RELEASE_WITHHELD", "V2_RELEASE_REJECTED",
]

V2_RELEASE_RELEASED = "released"
V2_RELEASE_PENDING = "pending"
V2_RELEASE_WITHHELD = "withheld"
V2_RELEASE_REJECTED = "rejected"

def receipt_outbox_digest_v2(body: bytes) -> str:
    """Go ``ReceiptOutboxDigestV2``: ``sha384:`` hex of
    SHA-384("ratify-protocol-receipt-outbox-v2" || 0x00 || body)."""
    return "sha384:" + hashlib.sha384(b"ratify-protocol-receipt-outbox-v2\x00" + bytes(body)).hexdigest()


@dataclass(frozen=True)
class _CommittedState:
    claim_id: str
    verifier_id: str
    receipt_body: bytes
    challenge_expires_at: int
    allow_horizon: int


class CommittedV2Outcome:
    """The immutable, non-actionable handoff from a committed verification to
    publication and :func:`release_v2_decision`. Only the verifier and
    interruption recovery create one; it holds no state of its own, and an
    instance they did not create is rejected by release."""

    __slots__ = ("__weakref__",)

    def __init__(self, *args, **kwargs):
        raise TypeError("CommittedV2Outcome is created only by the v2 verifier and recovery")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("CommittedV2Outcome cannot be subclassed")

    def __setattr__(self, name, value):
        raise AttributeError("CommittedV2Outcome is immutable")

    def __delattr__(self, name):
        raise AttributeError("CommittedV2Outcome is immutable")

    def __reduce__(self):
        raise TypeError("CommittedV2Outcome cannot be serialized")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def claim_id(self) -> str:
        """The Protocol claim ID of the committed evaluation."""
        st = _committed_state(self)
        return st.claim_id if st else ""

    def receipt_body(self) -> bytes:
        """A copy of the sealed receipt outbox body, for the receipt publisher
        only. Applications must not parse it to authorize."""
        st = _committed_state(self)
        return bytes(st.receipt_body) if st else b""

    def receipt_body_digest(self) -> str:
        """ReceiptOutboxDigest of the sealed body (SPEC-v2 §4)."""
        return receipt_outbox_digest_v2(self.receipt_body())

    def challenge_expires_at(self) -> int:
        st = _committed_state(self)
        return st.challenge_expires_at if st else 0

    def allow_horizon(self) -> tuple[int, bool]:
        """The exclusive allow deadline; ``ok`` is False unless the committed
        result can become an allow."""
        st = _committed_state(self)
        horizon = st.allow_horizon if st else 0
        return horizon, horizon > 0

    def __repr__(self) -> str:
        return f"<CommittedV2Outcome claim_id={self.claim_id()!r}>"


def _define_committed_registry():
    # The registry of genuine committed outcomes exists only in this closure.
    registry: "weakref.WeakKeyDictionary[CommittedV2Outcome, _CommittedState]" = weakref.WeakKeyDictionary()

    def committed_state(c) -> Optional[_CommittedState]:
        if type(c) is not CommittedV2Outcome:
            return None
        return registry.get(c)

    def new_committed_v2_outcome(claim, body: bytes, allow_horizon: int) -> CommittedV2Outcome:
        """Internal to the verifier and recovery; not part of the public API."""
        c = object.__new__(CommittedV2Outcome)
        registry[c] = _CommittedState(claim_id=claim.claim_id, verifier_id=claim.verifier_id,
                                      receipt_body=bytes(body), challenge_expires_at=claim.expires_at,
                                      allow_horizon=allow_horizon)
        return c

    return committed_state, new_committed_v2_outcome


_committed_state, _new_committed_v2_outcome = _define_committed_registry()
del _define_committed_registry


class AcknowledgementNotFoundErrorV2(Exception):
    """Go ``ErrV2AcknowledgementNotFound``."""

    def __init__(self, message: str = "v2 checkpoint acknowledgement not found"):
        super().__init__(message)


class ReleaseStateMismatchErrorV2(Exception):
    """Go ``ErrV2ReleaseStateMismatch``: a different release or withheld
    record already exists for the claim."""

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
    """The durable release record of SPEC-v2 §6.9: the release of step 9
    (``outcome`` released, ``reason`` empty) or a withheld result of steps 7
    and 8 (``outcome`` withheld, ``reason`` clock_regressed,
    challenge_expired, or allow_horizon_passed). ``entry_hash`` and
    ``ack_timestamp`` name the verified receipt entry and its
    acknowledgement. The first record for a claim wins; a claim store raises
    :class:`ReleaseStateMismatchErrorV2` for any different later record and
    must persist and return every field unchanged."""

    claim_id: str
    entry_hash: bytes
    ack_timestamp: int
    outcome: str = ""
    reason: str = ""


def valid_v2_release_record_outcome(outcome: str, reason: str) -> bool:
    """Go ``ValidV2ReleaseRecordOutcome``: whether outcome and reason form a
    release record: released with no reason, or withheld with one of the
    reasons release steps 7 and 8 record."""
    if outcome == V2_RELEASE_RELEASED:
        return reason == ""
    if outcome == V2_RELEASE_WITHHELD:
        return reason in ("clock_regressed", "challenge_expired", "allow_horizon_passed")
    return False


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
    """The claim-store view release needs. ``load_v2_terminal_claim`` reports
    a claim the store does not hold with a ``claim_not_found`` error, which
    release answers with rejected / release_state_mismatch; any other error is
    store unavailability (pending / claim_store_unavailable)."""

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


@dataclass(frozen=True)
class _ReleasedState:
    claim_id: str
    decision: str
    reason: str
    identity_status: str
    granted_scope: tuple
    receipt_wire: bytes
    release_time: int
    challenge_expires_at: int
    allow_horizon: int


class V2ReleasedDecision:
    """The only actionable value in this package (SPEC-v2 §6.9).

    It has no public constructor, setter, or state of its own; it cannot be
    subclassed or pickled, and every accessor returns a copy. Only the exact
    object :func:`release_v2_decision` returned is in the release registry;
    any other instance is never actionable. This guards against API misuse,
    not against hostile code in the same interpreter (see the module
    docstring)."""

    __slots__ = ("__weakref__",)

    def __init__(self, *args, **kwargs):
        raise TypeError("V2ReleasedDecision is created only by release_v2_decision")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("V2ReleasedDecision cannot be subclassed")

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

    def claim_id(self) -> str:
        st = _released_state(self)
        return st.claim_id if st else ""

    def decision(self) -> str:
        """``allow``, ``deny``, or ``indeterminate``. Use :meth:`allowed`, not
        this value, to gate a side effect."""
        st = _released_state(self)
        return st.decision if st else ""

    def reason(self) -> str:
        st = _released_state(self)
        return st.reason if st else ""

    def identity_status(self) -> str:
        st = _released_state(self)
        return st.identity_status if st else ""

    def granted_scope(self) -> list:
        """A copy of the released granted scope."""
        st = _released_state(self)
        return list(st.granted_scope) if st else []

    def receipt_wire(self) -> bytes:
        """A copy of the signed receipt wire verified during release."""
        st = _released_state(self)
        return bytes(st.receipt_wire) if st else b""

    @classified(V2ErrorClass.CONFIGURATION_INVALID)
    def receipt(self):
        """A freshly decoded copy of the signed receipt verified during release."""
        from .verification_receipt_v2 import decode_verification_receipt_v2

        wire = self.receipt_wire()
        if not wire:
            raise ValueError("v2 released decision carries no receipt")
        return decode_verification_receipt_v2(wire)

    def release_time(self) -> int:
        """The checkpoint acknowledgement time of the release."""
        st = _released_state(self)
        return st.release_time if st else 0

    def challenge_expires_at(self) -> int:
        st = _released_state(self)
        return st.challenge_expires_at if st else 0

    def allow_horizon(self) -> tuple[int, bool]:
        st = _released_state(self)
        horizon = st.allow_horizon if st else 0
        return horizon, horizon > 0

    def allowed(self, ctx: context_v2.Context, clock: V2AuthoritativeClock) -> bool:
        """Whether this released allow may be acted on now: True only for an
        instance :func:`release_v2_decision` returned, sealed as an allow,
        while now < challenge_expires_at and now < allow_horizon (both
        exclusive), read from the receiver's authoritative clock. A clock
        error, exception, or reading outside the timestamp domain is False.
        Call it immediately before the side effect."""
        st = _released_state(self)
        if (st is None or not isinstance(ctx, context_v2.Context) or clock is None or st.decision != "allow"
                or not st.receipt_wire or st.allow_horizon <= 0):
            return False
        try:
            now = _read_v2_authoritative_time(ctx, clock)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:  # noqa: BLE001 - any clock failure answers False
            return False
        return now < st.challenge_expires_at and now < st.allow_horizon

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
    from .signing_v2 import VERIFICATION_RECEIPT, verify_v2_statement
    from .verification_receipt_v2 import decode_verification_receipt_v2, receipt_v2_signable_bytes

    receipt = decode_verification_receipt_v2(wire)
    if receipt.log_id != config.log_id:
        raise ValueError("v2 published receipt belongs to an unconfigured log")
    body = receipt_v2_signable_bytes(receipt)
    verify_v2_statement(VERIFICATION_RECEIPT, body, receipt.signature, config.verifier_public_key)
    return receipt


def _release_steps(ctx: context_v2.Context, committed: CommittedV2Outcome, signed_receipt: Optional[bytes],
                   config: V2ReleaseConfig):
    """Steps 1 through 9 of SPEC-v2 §6.9. Returns the first non-released
    :class:`V2ReleaseResult`, or the state to seal when every step passed.
    The state is not actionable: only :func:`release_v2_decision` can turn it
    into a registered :class:`V2ReleasedDecision`."""
    from .signing_v2 import key_id_v2
    from .verification_receipt_v2 import verification_receipt_v2_body, verification_receipt_v2_digest

    if (not isinstance(ctx, context_v2.Context) or not isinstance(committed, CommittedV2Outcome)
            or not isinstance(config, V2ReleaseConfig)):
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    c = _committed_state(committed)
    if c is None:
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    claim_id = c.claim_id
    committed_body = bytes(c.receipt_body)
    verifier_id_committed = c.verifier_id
    challenge_expires_at = c.challenge_expires_at
    allow_horizon = c.allow_horizon
    if claim_id == "" or len(committed_body) == 0 or config.claim_store is None or config.checkpoint is None:
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    if not isinstance(config.log_id, str) or len(config.log_id) != 32 or not lower_hex_string(config.log_id):
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    # 1. Committed state.
    try:
        record = config.claim_store.load_v2_terminal_claim(ctx, claim_id)
        if not isinstance(record, V2TerminalClaimRecord):
            raise ValueError("claim store returned an invalid terminal record")
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - a store failure (Go: a recovered panic)
        # Only an unavailable store is retryable. A store that answers that it
        # holds no such claim (claim_not_found) did not produce this handoff.
        if error_class_of(exc) == V2ErrorClass.CLAIM_NOT_FOUND:
            return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
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
    # A recorded withheld result is permanent for the claim and is returned
    # before any other step. A record that is neither a valid withheld nor a
    # valid released record for this claim is a state mismatch.
    release = record.release
    if release is not None:
        if (not isinstance(release, V2ReleaseRecord) or release.claim_id != claim_id
                or not valid_v2_release_record_outcome(release.outcome, release.reason)):
            return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
        if release.outcome == V2_RELEASE_WITHHELD:
            return _result(V2_RELEASE_WITHHELD, release.reason)
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
    if release is not None and bytes(release.entry_hash) != entry_hash:
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
    # 5. Predecessor.
    if receipt.sequence > 1:
        try:
            previous = config.checkpoint.get_v2_acknowledgement(ctx, receipt.log_id, receipt.sequence - 1)
            if not isinstance(previous, V2CheckpointAcknowledgement):
                raise ValueError("invalid acknowledgement")
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:  # noqa: BLE001 - a checkpoint failure (Go: a recovered panic)
            return _result(V2_RELEASE_PENDING, "acknowledgement_unavailable")
        if (previous.log_id != receipt.log_id or previous.sequence != receipt.sequence - 1
                or bytes(previous.entry_hash) != bytes(receipt.previous_receipt_hash)):
            return _result(V2_RELEASE_REJECTED, "log_predecessor_mismatch")
    # 6. Acknowledgement.
    try:
        ack = config.checkpoint.get_v2_acknowledgement(ctx, receipt.log_id, receipt.sequence)
        if not isinstance(ack, V2CheckpointAcknowledgement):
            raise ValueError("invalid acknowledgement")
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:  # noqa: BLE001 - a checkpoint failure (Go: a recovered panic)
        return _result(V2_RELEASE_PENDING, "acknowledgement_unavailable")
    if ack.log_id != receipt.log_id or ack.sequence != receipt.sequence or bytes(ack.entry_hash) != entry_hash:
        return _result(V2_RELEASE_REJECTED, "acknowledgement_mismatch")
    if release is not None and release.ack_timestamp != ack.timestamp:
        return _result(V2_RELEASE_REJECTED, "release_state_mismatch")

    def withhold(reason: str) -> V2ReleaseResult:
        # Release ends at step 7 or 8. With no release recorded it durably
        # records the withheld result first, so it is permanent for the
        # claim; if the store is unavailable this call is still withheld.
        # With a release already recorded, that first record stands and this
        # call alone is withheld.
        if release is None:
            try:
                config.claim_store.record_v2_release(ctx, V2ReleaseRecord(
                    claim_id=claim_id, entry_hash=entry_hash, ack_timestamp=ack.timestamp,
                    outcome=V2_RELEASE_WITHHELD, reason=reason))
            except ReleaseStateMismatchErrorV2:
                return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:  # noqa: BLE001 - a store failure (Go: a recovered panic)
                pass
        return _result(V2_RELEASE_WITHHELD, reason)

    # 7. Clock.
    try:
        now = _read_v2_authoritative_time(ctx, config.claim_store)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - a clock failure (Go: a recovered panic)
        if error_class_of(exc) == V2ErrorClass.CLOCK_REGRESSED:
            return withhold("clock_regressed")
        return _result(V2_RELEASE_PENDING, "clock_unavailable")
    if not valid_v2_timestamp(ack.timestamp) or record.finalized_at > ack.timestamp or ack.timestamp > now:
        return withhold("clock_regressed")
    # 8. Deadlines.
    if ack.timestamp >= challenge_expires_at or now >= challenge_expires_at:
        return withhold("challenge_expired")
    if receipt.decision == "allow" and (allow_horizon <= 0 or ack.timestamp >= allow_horizon or now >= allow_horizon):
        return withhold("allow_horizon_passed")
    # 9. Record.
    if release is None:
        try:
            config.claim_store.record_v2_release(ctx, V2ReleaseRecord(claim_id=claim_id, entry_hash=entry_hash,
                                                                      ack_timestamp=ack.timestamp,
                                                                      outcome=V2_RELEASE_RELEASED))
        except ReleaseStateMismatchErrorV2:
            return _result(V2_RELEASE_REJECTED, "release_state_mismatch")
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:  # noqa: BLE001 - a store failure (Go: a recovered panic)
            return _result(V2_RELEASE_PENDING, "claim_store_unavailable")
    return _ReleasedState(
        claim_id=claim_id, decision=receipt.decision, reason=receipt.decision_reason,
        identity_status=receipt.identity_status, granted_scope=tuple(receipt.granted_scope or ()),
        receipt_wire=bytes(signed_receipt), release_time=ack.timestamp, challenge_expires_at=challenge_expires_at,
        allow_horizon=allow_horizon if receipt.decision == "allow" else 0,
    )


def _define_release_v2_decision():
    # The registry of genuine released decisions exists only in this closure,
    # so only release_v2_decision below can add to it. There is no module
    # attribute through which an importer can register an instance.
    registry: "weakref.WeakKeyDictionary[V2ReleasedDecision, _ReleasedState]" = weakref.WeakKeyDictionary()

    def released_state(d) -> Optional[_ReleasedState]:
        if type(d) is not V2ReleasedDecision:
            return None
        return registry.get(d)

    def release_v2_decision(ctx: context_v2.Context, committed: CommittedV2Outcome, signed_receipt: Optional[bytes],
                            config: V2ReleaseConfig) -> V2ReleaseResult:
        """Go ``ReleaseV2Decision``: the release steps of SPEC-v2 §6.9 in
        order, stopping at the first that does not pass. The only producer
        of an actionable :class:`V2ReleasedDecision`."""
        outcome = _release_steps(ctx, committed, signed_receipt, config)
        if not isinstance(outcome, _ReleasedState):
            return outcome
        # 10. Return.
        decision = object.__new__(V2ReleasedDecision)
        registry[decision] = outcome
        return V2ReleaseResult(status=V2_RELEASE_RELEASED, decision=decision)

    return released_state, release_v2_decision


_released_state, release_v2_decision = _define_release_v2_decision()
del _define_release_v2_decision
