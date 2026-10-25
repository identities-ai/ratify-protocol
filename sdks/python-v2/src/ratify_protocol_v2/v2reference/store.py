"""In-memory REFERENCE implementation of the Part B deployment interfaces
(mirrors Go v2reference/store.go).

FOR TESTS AND CONFORMANCE SCENARIOS ONLY. Nothing here is durable, survives a
restart, spans processes, or provides an independent failure domain. It
exists so every SDK can replay the shared lifecycle-scenarios.json vectors
against identical semantics. Every operation runs under one lock, which
makes the claim and the stream-sequence advance a single atomic step, and
terminal commit and outbox sequence assignment another.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from .. import context_v2
from ..claim_store_v2 import (
    V2_CLAIM_CREATED,
    V2_CLAIM_IN_PROGRESS,
    V2_CLAIM_TERMINAL_REPLAY,
    ClaimProofConflictError,
    ClaimStoreV2,
    V2ChallengeClaim,
    V2ClaimResult,
    V2RateAtFinalizationStore,
    challenge_claim_time_current_v2,
    clone_v2_challenge_claim,
    validate_v2_finalization_payload,
)
from ..errors_v2 import V2Error, V2ErrorClass
from ..evaluation_progress_v2 import (
    V2EvaluationProgress,
    V2InterruptedClaim,
    clone_v2_evaluation_progress,
    initial_v2_evaluation_progress,
    validate_v2_evaluation_progress,
)
from ..release_v2 import (
    V2_RELEASE_RELEASED,
    AcknowledgementNotFoundErrorV2,
    ReleaseStateMismatchErrorV2,
    V2ReceiptCheckpoint,
    V2ReceiptPublisher,
    V2ReleaseClaimStore,
    V2ReleaseRecord,
    V2TerminalClaimRecord,
    receipt_outbox_digest_v2,
    valid_v2_release_record_outcome,
)
from ..signing_v2 import key_id_v2, public_key_of
from ..stream_sequence_v2 import check_v2_stream_sequence
from ..clock_bounds_v2 import V2_MAX_TIMESTAMP_SECONDS
from ..types_v2 import V2CheckpointAcknowledgement
from ..verification_receipt_v2 import decode_verification_receipt_body_v2


class NotAcknowledgedError(Exception):
    """Go ``ErrNotAcknowledged``: not the next correctly linked entry."""

    def __init__(self, message: str = "v2reference: checkpoint refused the acknowledgement"):
        super().__init__(message)


class HeadOfLineBlockedError(Exception):
    """Go ``ErrHeadOfLineBlocked``: an earlier entry is still unpublished."""

    def __init__(self, message: str = "v2reference: an earlier receipt-log entry is still pending"):
        super().__init__(message)


class SignerUnavailableError(Exception):
    """Go ``ErrSignerUnavailable``."""

    def __init__(self, message: str = "v2reference: receipt signer unavailable"):
        super().__init__(message)


class LogFrozenError(Exception):
    """Go ``ErrLogFrozen``."""

    def __init__(self, message: str = "v2reference: the receipt log is frozen after abandonment"):
        super().__init__(message)


_EVALUATING = "evaluating"
_TERMINAL = "terminal"


@dataclass
class _ClaimRecord:
    claim: V2ChallengeClaim
    owner_digest: bytes
    lease_expires_at: int
    state: str
    claimed_at: int
    progress: V2EvaluationProgress
    terminal: bytes = b""
    receipt_body: bytes = b""
    allow_horizon: int = 0
    finalized_at: int = 0
    release: Optional[V2ReleaseRecord] = None
    abandoned: bool = False
    outbox_index: int = -1


@dataclass
class _OutboxEntry:
    claim_id: str
    body: bytes
    wire: Optional[bytes] = None
    digest: bytes = b""
    ack: Optional[V2CheckpointAcknowledgement] = None


def _stream_key(claim: V2ChallengeClaim) -> tuple[str, str, bytes]:
    return (claim.namespace, claim.agent_id, bytes(claim.stream_id or b""))


def _same_immutable_claim(a: V2ChallengeClaim, b: V2ChallengeClaim) -> bool:
    return clone_v2_challenge_claim(a) == clone_v2_challenge_claim(b)


class Store(ClaimStoreV2, V2ReleaseClaimStore, V2ReceiptPublisher, V2ReceiptCheckpoint):
    """The reference Part B store. All methods are safe for concurrent use."""

    def __init__(self, now: int, lease_seconds: int, log_id: str, verifier_key, *, _clone: bool = False):
        self._lock = threading.RLock()
        if _clone:
            return
        verifier_id = key_id_v2(public_key_of(verifier_key))
        if type(lease_seconds) is not int or lease_seconds <= 0 or not isinstance(log_id, str) or len(log_id) != 32:
            raise ValueError("v2reference: lease must be positive and log ID 32 hex characters")
        self._now = now
        self._high_water = now
        self._lease_seconds = lease_seconds
        self._claims: dict = {}
        self._streams: dict = {}
        self._verifier_key = verifier_key
        self._verifier_id = verifier_id
        self._log_id = log_id
        self._outbox: list = []
        self._ack_withheld = False
        self._log_frozen = False
        self._checkpoint_frozen = False
        self._signer_failure = False
        self._rate_at_finalization = False
        self._rate_commits: dict = {}
        self._owner_token_rand: Callable[[int], bytes] = os.urandom
        # anchor, when set by a single-device offline profile primary, anchors
        # every durable security-state change before it takes effect. It is
        # never copied by clone.
        self._anchor = None

    # -- state management --------------------------------------------------

    def clone(self) -> "Store":
        """An independent copy of the complete state (an exact restore)."""
        with self._lock:
            return self._clone_locked()

    def _clone_locked(self) -> "Store":
        out = Store(0, 1, "", None, _clone=True)
        out._now, out._high_water, out._lease_seconds = self._now, self._high_water, self._lease_seconds
        out._claims = {cid: _clone_record(r) for cid, r in self._claims.items()}
        out._streams = dict(self._streams)
        out._verifier_key, out._verifier_id, out._log_id = self._verifier_key, self._verifier_id, self._log_id
        out._outbox = [copy.copy(e) for e in self._outbox]
        out._ack_withheld, out._log_frozen = self._ack_withheld, self._log_frozen
        out._checkpoint_frozen = self._checkpoint_frozen
        out._signer_failure, out._rate_at_finalization = self._signer_failure, self._rate_at_finalization
        out._rate_commits = {k: list(v) for k, v in self._rate_commits.items()}
        out._owner_token_rand = self._owner_token_rand
        out._anchor = None
        return out

    def _change_locked(self, mutate: Callable[[], None]) -> None:
        """Apply ``mutate`` as one durable security-state change, anchored
        first when an anchor is set; on anchoring failure the change is undone
        and claim_store_unavailable is raised."""
        if self._anchor is None:
            mutate()
            return
        before = self._clone_locked()
        try:
            previous = self._state_digests_locked()
            mutate()
            nxt = self._state_digests_locked()
            self._anchor(previous, nxt)
        except Exception as exc:  # noqa: BLE001
            self._claims, self._streams, self._outbox = before._claims, before._streams, before._outbox
            self._rate_commits, self._log_frozen = before._rate_commits, before._log_frozen
            raise V2Error(V2ErrorClass.CLAIM_STORE_UNAVAILABLE,
                          f"v2reference: durable state change was not anchored: {exc}") from exc

    def _state_digests_locked(self):
        from .device_state import _state_digests_locked

        return _state_digests_locked(self)

    def set_time(self, now: int) -> None:
        """Set the authoritative clock; tests may move it backward."""
        with self._lock:
            self._now = now

    def now(self) -> int:
        with self._lock:
            return self._now

    def set_signer_failure(self, failing: bool) -> None:
        with self._lock:
            self._signer_failure = failing

    def set_acknowledgement_withheld(self, withheld: bool) -> None:
        with self._lock:
            self._ack_withheld = withheld
            if not withheld:
                self._acknowledge_pending_locked()

    def _acknowledge_pending_locked(self) -> None:
        """Submit every appended, unacknowledged entry to the reference
        checkpoint in log order. Acknowledgements are timestamped by one
        authoritative reading (SPEC-v2 §7.2), which advances the high-water
        mark; while the clock is regressed nothing is acknowledged."""
        if self._checkpoint_frozen:
            return
        now = None
        for i, entry in enumerate(self._outbox):
            if entry.wire is None:
                return
            if entry.ack is not None:
                continue
            if now is None:
                try:
                    now = self._read_clock_locked()
                except V2Error:
                    return
            entry.ack = V2CheckpointAcknowledgement(log_id=self._log_id, sequence=i + 1, entry_hash=bytes(entry.digest),
                                                    timestamp=now)

    def log_length(self) -> int:
        with self._lock:
            n = 0
            while n < len(self._outbox) and self._outbox[n].wire is not None:
                n += 1
            return n

    def _read_clock_locked(self) -> int:
        if self._now < self._high_water:
            raise V2Error(V2ErrorClass.CLOCK_REGRESSED,
                          f"v2reference: authoritative clock {self._now} is below its high-water mark {self._high_water}")
        self._high_water = self._now
        return self._now

    def authoritative_time_v2(self, ctx: context_v2.Context) -> int:
        with self._lock:
            return self._read_clock_locked()

    # -- claim store -------------------------------------------------------

    def claim_v2(self, ctx: context_v2.Context, claim: V2ChallengeClaim) -> V2ClaimResult:
        with self._lock:
            if not claim.claim_id:
                raise ValueError("v2reference: claim ID is required")
            try:
                now = self._read_clock_locked()
            except V2Error as exc:
                raise V2Error(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, str(exc)) from exc
            existing = self._claims.get(claim.claim_id)
            if existing is not None:
                if not _same_immutable_claim(existing.claim, claim):
                    raise ClaimProofConflictError()
                if existing.abandoned:
                    raise V2Error(V2ErrorClass.RECEIPT_ABANDONED,
                                  "v2reference: the receipt for this claim was abandoned; a fresh challenge is required")
                disposition = V2_CLAIM_TERMINAL_REPLAY if existing.state == _TERMINAL else V2_CLAIM_IN_PROGRESS
                return V2ClaimResult(disposition=disposition, claimed_at=existing.claimed_at)
            if not challenge_claim_time_current_v2(claim, now):
                raise V2Error(V2ErrorClass.CHALLENGE_NOT_FRESH, "v2reference: challenge is not current at the store clock")
            key = None
            if claim.stream_id is not None or claim.stream_seq is not None:
                if claim.stream_id is None or claim.stream_seq is None:
                    raise V2Error(V2ErrorClass.MALFORMED, "v2reference: stream_id and stream_seq must appear together")
                key = _stream_key(claim)
                has_last = key in self._streams
                check_v2_stream_sequence(has_last, self._streams.get(key, 0), claim.stream_seq)
            owner = self._owner_token_rand(32)

            def mutate():
                if key:
                    self._streams[key] = claim.stream_seq
                self._claims[claim.claim_id] = _ClaimRecord(
                    claim=clone_v2_challenge_claim(claim), owner_digest=hashlib.sha256(owner).digest(),
                    lease_expires_at=now + self._lease_seconds, state=_EVALUATING, claimed_at=now,
                    progress=initial_v2_evaluation_progress())

            self._change_locked(mutate)
            return V2ClaimResult(disposition=V2_CLAIM_CREATED, claimed_at=now, owner_token=bytes(owner))

    def _owner_locked(self, claim_id: str, owner_token: bytes):
        record = self._claims.get(claim_id)
        if record is None:
            raise V2Error(V2ErrorClass.CLAIM_NOT_FOUND, "v2reference: unknown claim")
        if not hmac.compare_digest(hashlib.sha256(bytes(owner_token)).digest(), record.owner_digest):
            raise V2Error(V2ErrorClass.CLAIM_LEASE_LOST, "v2reference: evaluator owner mismatch")
        if record.state == _TERMINAL:
            raise _TerminalOwner(record)
        now = self._read_clock_locked()
        if now < record.claimed_at:
            raise V2Error(V2ErrorClass.CLOCK_REGRESSED, f"v2reference: clock {now} is before T_claim {record.claimed_at}")
        if now >= record.lease_expires_at:
            raise V2Error(V2ErrorClass.CLAIM_LEASE_LOST, "v2reference: evaluator lease expired")
        return record, now

    def _commit_terminal_locked(self, record: _ClaimRecord, terminal: bytes, body: bytes, allow_horizon: int, final_at: int) -> None:
        record.state, record.terminal, record.receipt_body = _TERMINAL, bytes(terminal), bytes(body)
        record.allow_horizon, record.finalized_at = allow_horizon, final_at
        record.outbox_index = len(self._outbox)
        self._outbox.append(_OutboxEntry(claim_id=record.claim.claim_id, body=bytes(body)))

    def finalize_v2_claim(self, ctx: context_v2.Context, claim_id: str, owner_token: bytes, terminal_result: bytes,
                          receipt_body: bytes, allow_valid_until: int) -> bool:
        from ..rate_reservation_v2 import V2RateLimitExceededError

        with self._lock:
            try:
                record, final_at = self._owner_locked(claim_id, owner_token)
            except _TerminalOwner as terminal:
                r = terminal.record
                if r.terminal == bytes(terminal_result) and r.receipt_body == bytes(receipt_body):
                    return False
                raise V2Error(V2ErrorClass.CLAIM_ALREADY_TERMINAL, "v2reference: claim already terminal") from None
            validate_v2_finalization_payload(record.claim, terminal_result, receipt_body)
            # SPEC-v2 §6.8: an allow carries a positive allow horizon and every
            # other decision carries none, so the horizon and the rate admission
            # below always apply to exactly the allows.
            decision = decode_verification_receipt_body_v2(bytes(receipt_body)).decision
            if not (0 < allow_valid_until <= V2_MAX_TIMESTAMP_SECONDS if decision == "allow" else allow_valid_until == 0):
                raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2reference: the allow horizon does not match the decision")
            if allow_valid_until > 0 and (final_at >= allow_valid_until or final_at >= record.claim.expires_at):
                raise V2Error(V2ErrorClass.ALLOW_HORIZON_PASSED, "v2reference: allow is at or beyond its horizon")
            admit_rate = allow_valid_until > 0 and self._rate_at_finalization and len(record.claim.rate_batch) != 0
            if admit_rate:
                for item in record.claim.rate_batch:
                    key = (item.issuer_id, item.cert_id, item.window_s)
                    active = sum(1 for at in self._rate_commits.get(key, []) if at > final_at - item.window_s)
                    if active >= item.limit:
                        raise V2RateLimitExceededError()

            def mutate():
                if admit_rate:
                    for item in record.claim.rate_batch:
                        self._rate_commits.setdefault((item.issuer_id, item.cert_id, item.window_s), []).append(final_at)
                self._commit_terminal_locked(record, terminal_result, receipt_body, allow_valid_until, final_at)

            self._change_locked(mutate)
            return True

    def record_v2_evaluation_progress(self, ctx: context_v2.Context, claim_id: str, owner_token: bytes,
                                      progress: V2EvaluationProgress) -> None:
        with self._lock:
            try:
                record, _ = self._owner_locked(claim_id, owner_token)
            except _TerminalOwner:
                raise V2Error(V2ErrorClass.CLAIM_ALREADY_TERMINAL, "v2reference: claim already terminal") from None
            try:
                validate_v2_evaluation_progress(progress)
            except ValueError as exc:
                raise V2Error(V2ErrorClass.MALFORMED, str(exc)) from exc
            snapshot = clone_v2_evaluation_progress(progress)

            def mutate():
                record.progress = snapshot

            self._change_locked(mutate)

    def load_v2_interrupted_claim(self, ctx: context_v2.Context, claim_id: str) -> V2InterruptedClaim:
        with self._lock:
            record = self._claims.get(claim_id)
            if record is None:
                raise V2Error(V2ErrorClass.CLAIM_NOT_FOUND, "v2reference: unknown claim")
            now = self._read_clock_locked()
            if record.state == _EVALUATING and now < record.lease_expires_at:
                raise V2Error(V2ErrorClass.CLAIM_LEASE_LIVE, "v2reference: evaluator lease is still live")
            return V2InterruptedClaim(claim=clone_v2_challenge_claim(record.claim), claimed_at=record.claimed_at,
                                      progress=clone_v2_evaluation_progress(record.progress))

    def recover_interrupted_v2_claim(self, ctx: context_v2.Context, claim_id: str, terminal_result: bytes,
                                     receipt_body: bytes) -> bool:
        with self._lock:
            record = self._claims.get(claim_id)
            if record is None:
                raise V2Error(V2ErrorClass.CLAIM_NOT_FOUND, "v2reference: unknown claim")
            if record.state == _TERMINAL:
                if record.terminal == bytes(terminal_result) and record.receipt_body == bytes(receipt_body):
                    return False
                raise V2Error(V2ErrorClass.CLAIM_ALREADY_TERMINAL, "v2reference: claim already terminal")
            now = self._read_clock_locked()
            if now < record.lease_expires_at:
                raise V2Error(V2ErrorClass.CLAIM_LEASE_LIVE, "v2reference: evaluator lease is still live")
            # Validated exactly as finalization (SPEC-v2 §7.5): malformed or
            # configuration_invalid, committing nothing.
            validate_v2_finalization_payload(record.claim, terminal_result, receipt_body)
            try:
                fields = json.loads(bytes(terminal_result))
            except ValueError:
                fields = None
            if (not isinstance(fields, dict) or fields.get("decision") != "indeterminate"
                    or fields.get("decision_reason") != "evaluation_interrupted"):
                raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                              "v2reference: recovery may commit only indeterminate/evaluation_interrupted")
            self._change_locked(lambda: self._commit_terminal_locked(record, terminal_result, receipt_body, 0, now))
            return True

    # -- release -----------------------------------------------------------

    def load_v2_terminal_claim(self, ctx: context_v2.Context, claim_id: str) -> V2TerminalClaimRecord:
        with self._lock:
            record = self._claims.get(claim_id)
            if record is None:
                raise V2Error(V2ErrorClass.CLAIM_NOT_FOUND, "v2reference: unknown claim")
            out = V2TerminalClaimRecord(terminal=record.state == _TERMINAL, challenge_expires_at=record.claim.expires_at,
                                        allow_horizon=record.allow_horizon, finalized_at=record.finalized_at,
                                        receipt_abandoned=record.abandoned, release=record.release)
            if out.terminal:
                out.receipt_outbox_digest = receipt_outbox_digest_v2(record.receipt_body)
            return out

    def record_v2_release(self, ctx: context_v2.Context, release: V2ReleaseRecord) -> None:
        """Record a release or a withheld result (SPEC-v2 §6.9): the first
        record for a claim wins, an identical repeat is a no-op, and any
        different record is :class:`ReleaseStateMismatchErrorV2`. A new record
        is a durable security-state change, anchored like any other."""
        with self._lock:
            if not valid_v2_release_record_outcome(release.outcome, release.reason):
                raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                              f"v2reference: invalid release record outcome {release.outcome!r} reason {release.reason!r}")
            record = self._claims.get(release.claim_id)
            if record is None or record.state != _TERMINAL:
                raise ReleaseStateMismatchErrorV2()
            if record.release is not None:
                if (bytes(record.release.entry_hash) == bytes(release.entry_hash)
                        and record.release.ack_timestamp == release.ack_timestamp
                        and record.release.outcome == release.outcome and record.release.reason == release.reason):
                    return
                raise ReleaseStateMismatchErrorV2()
            stored = V2ReleaseRecord(claim_id=release.claim_id, entry_hash=bytes(release.entry_hash),
                                     ack_timestamp=release.ack_timestamp, outcome=release.outcome,
                                     reason=release.reason)

            def mutate():
                record.release = stored

            self._change_locked(mutate)

    def plant_release_test_only(self, claim_id: str, ack_timestamp: int) -> None:
        """Write a release record directly into primary storage, bypassing
        release and anchoring (an attacker who can write the primary)."""
        with self._lock:
            record = self._claims.get(claim_id)
            if record is not None and record.outbox_index >= 0 and self._outbox[record.outbox_index].wire is not None:
                record.release = V2ReleaseRecord(claim_id=claim_id, entry_hash=bytes(self._outbox[record.outbox_index].digest),
                                                 ack_timestamp=ack_timestamp, outcome=V2_RELEASE_RELEASED)

    # -- publication and checkpoint ---------------------------------------

    def publish_v2_receipt(self, ctx: context_v2.Context, claim_id: str, receipt_body: bytes) -> bytes:
        from ..verification_receipt_v2 import (
            ReceiptV2Head,
            encode_verification_receipt_v2,
            sign_prepared_verification_receipt_v2,
            verification_receipt_v2_digest,
        )

        with self._lock:
            record = self._claims.get(claim_id)
            if record is None or record.state != _TERMINAL or record.receipt_body != bytes(receipt_body):
                raise ValueError("v2reference: no committed outbox body for this claim matches")
            index = record.outbox_index
            entry = self._outbox[index]
            if entry.wire is not None:
                return bytes(entry.wire)
            if self._log_frozen:
                raise LogFrozenError()
            if index > 0 and self._outbox[index - 1].wire is None:
                raise HeadOfLineBlockedError()
            if self._signer_failure:
                raise SignerUnavailableError()
            accepted = {i + 1: bytes(self._outbox[i].digest) for i in range(index)}
            head_hash = bytes(self._outbox[index - 1].digest) if index > 0 else bytes(48)
            head = ReceiptV2Head(log_id=self._log_id, verifier_id=self._verifier_id, sequence=index, head_hash=head_hash,
                                 accepted_digests=accepted, frozen=False)
            receipt = sign_prepared_verification_receipt_v2(bytes(receipt_body), head, self._verifier_key)
            wire = encode_verification_receipt_v2(receipt)
            digest = bytes(verification_receipt_v2_digest(receipt))

            def mutate():
                entry.wire, entry.digest = wire, digest

            self._change_locked(mutate)
            if not self._ack_withheld:
                self._acknowledge_pending_locked()
            return bytes(wire)

    def acknowledge_v2_receipt(self, ctx: context_v2.Context, log_id: str, sequence: int, previous_entry_hash: bytes,
                               entry_hash: bytes) -> V2CheckpointAcknowledgement:
        """Accept only the next appended entry of the log, linked by
        ``previous_entry_hash``, and return the original acknowledgement for
        an identical retry. A different entry hash at an acknowledged
        sequence is a fork (SPEC-v2 §7.8): it is refused and freezes the log,
        after which the checkpoint acknowledges nothing further for it,
        neither here nor from the publisher's submissions. Identical retries
        of acknowledgements made before the fork still return the original
        acknowledgement."""
        with self._lock:
            if log_id != self._log_id or sequence < 1 or sequence > len(self._outbox):
                raise NotAcknowledgedError()
            acked = self._outbox[sequence - 1].ack
            if acked is not None and bytes(acked.entry_hash) != bytes(entry_hash):
                self._checkpoint_frozen = True
                raise NotAcknowledgedError(f"v2reference: checkpoint refused the acknowledgement: a different entry hash "
                                           f"at acknowledged sequence {sequence} is a fork; the log is frozen")
            if self._checkpoint_frozen and acked is None:
                raise NotAcknowledgedError("v2reference: checkpoint refused the acknowledgement: the log is frozen after a fork")
            if self._outbox[sequence - 1].wire is None or self._outbox[sequence - 1].digest != bytes(entry_hash):
                raise NotAcknowledgedError()
            previous = bytes(48)
            if sequence > 1:
                previous = self._outbox[sequence - 2].digest
                if self._outbox[sequence - 2].ack is None:
                    raise NotAcknowledgedError()
            if previous != bytes(previous_entry_hash):
                raise NotAcknowledgedError()
            entry = self._outbox[sequence - 1]
            if entry.ack is None:
                now = self._read_clock_locked()
                entry.ack = V2CheckpointAcknowledgement(log_id=log_id, sequence=sequence, entry_hash=bytes(entry_hash),
                                                        timestamp=now)
            return entry.ack

    def get_v2_acknowledgement(self, ctx: context_v2.Context, log_id: str, sequence: int) -> V2CheckpointAcknowledgement:
        with self._lock:
            if log_id != self._log_id or sequence < 1 or sequence > len(self._outbox) or self._outbox[sequence - 1].ack is None:
                raise AcknowledgementNotFoundErrorV2()
            return self._outbox[sequence - 1].ack

    def abandon_pending_receipts(self) -> list:
        """Freeze the receipt log and mark every claim whose committed entry was
        not yet appended as receipt_abandoned; return their IDs in log order."""
        with self._lock:
            abandoned: list = []

            def mutate():
                self._log_frozen = True
                for entry in self._outbox:
                    if entry.wire is None:
                        self._claims[entry.claim_id].abandoned = True
                        abandoned.append(entry.claim_id)

            try:
                self._change_locked(mutate)
            except V2Error:
                return []
            return abandoned

    def with_rate_at_finalization(self) -> "RateAtFinalizationStore":
        """Enable rate admission at finalization and return the view that
        advertises it."""
        with self._lock:
            self._rate_at_finalization = True
        return RateAtFinalizationStore(self)


class _TerminalOwner(Exception):
    def __init__(self, record: _ClaimRecord):
        super().__init__("v2reference: claim already terminal")
        self.record = record


def _clone_record(record: _ClaimRecord) -> _ClaimRecord:
    out = copy.copy(record)
    out.claim = clone_v2_challenge_claim(record.claim)
    out.progress = clone_v2_evaluation_progress(record.progress)
    return out


class RateAtFinalizationStore(V2RateAtFinalizationStore, V2ReleaseClaimStore, V2ReceiptPublisher, V2ReceiptCheckpoint):
    """The reference store with max_rate admission moved into the
    finalization compare-and-set. Use it as both claim store and rate store."""

    def __init__(self, store: Store):
        self._store = store

    @property
    def store(self) -> Store:
        return self._store

    def admits_v2_rate_at_finalization(self) -> None:
        return None

    def reserve_v2_rate_batch(self, ctx, claim_id, owner_token, bundle_hash, batch) -> None:
        """Exists only to satisfy the rate reservation interface. The
        verifier never calls it for a store that admits at finalization, and
        it always fails (SPEC-v2 §7.1, §7.6)."""
        raise ValueError("v2reference: provisional rate reservation is not used with admission at finalization")

    def authoritative_time_v2(self, ctx):
        return self._store.authoritative_time_v2(ctx)

    def claim_v2(self, ctx, claim):
        return self._store.claim_v2(ctx, claim)

    def finalize_v2_claim(self, ctx, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until):
        return self._store.finalize_v2_claim(ctx, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until)

    def record_v2_evaluation_progress(self, ctx, claim_id, owner_token, progress):
        return self._store.record_v2_evaluation_progress(ctx, claim_id, owner_token, progress)

    def load_v2_interrupted_claim(self, ctx, claim_id):
        return self._store.load_v2_interrupted_claim(ctx, claim_id)

    def recover_interrupted_v2_claim(self, ctx, claim_id, terminal_result, receipt_body):
        return self._store.recover_interrupted_v2_claim(ctx, claim_id, terminal_result, receipt_body)

    def load_v2_terminal_claim(self, ctx, claim_id):
        return self._store.load_v2_terminal_claim(ctx, claim_id)

    def record_v2_release(self, ctx, record):
        return self._store.record_v2_release(ctx, record)

    def publish_v2_receipt(self, ctx, claim_id, receipt_body):
        return self._store.publish_v2_receipt(ctx, claim_id, receipt_body)

    def acknowledge_v2_receipt(self, ctx, log_id, sequence, previous_entry_hash, entry_hash):
        return self._store.acknowledge_v2_receipt(ctx, log_id, sequence, previous_entry_hash, entry_hash)

    def get_v2_acknowledgement(self, ctx, log_id, sequence):
        return self._store.get_v2_acknowledgement(ctx, log_id, sequence)
