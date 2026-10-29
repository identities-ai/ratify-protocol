"""Single-device offline profile (mirrors Go v2reference/offline_device.go,
SPEC-v2 §7.13), TEST ONLY.

``DeviceComponentTestOnly`` models the independent component the profile
requires (a separately programmed secure element with its own key). It holds
the anchored complete-state digest of the primary, persistently records the
entry hash and state digest of every acknowledged receipt-log entry,
advances monotonically, and signs each acknowledgement. Its test-only
Ed25519 key stands in for the hardware key; nothing here is durable.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..release_v2 import AcknowledgementNotFoundErrorV2, V2ReceiptCheckpoint
from ..types_v2 import V2CheckpointAcknowledgement
from .device_state import DevicePrimaryTestOnly
from .store import NotAcknowledgedError


class DevicePowerLossError(Exception):
    def __init__(self):
        super().__init__("v2reference: power lost during the device checkpoint submission")


class DeviceStorageFullError(Exception):
    def __init__(self):
        super().__init__("v2reference: device checkpoint storage is full")


class DeviceStateMismatchError(Exception):
    def __init__(self):
        super().__init__("v2reference: submission does not extend the device checkpoint head")


class DeviceFrozenError(Exception):
    def __init__(self):
        super().__init__("v2reference: device checkpoint is frozen after a conflicting entry")


DEVICE_POWER_OK = 0
DEVICE_POWER_LOSS_BEFORE_COMMIT = 1
DEVICE_POWER_LOSS_AFTER_COMMIT = 2

DEVICE_READY = "ready"
DEVICE_PRIMARY_BEHIND = "primary_behind"
DEVICE_STATE_DIGEST_MISMATCH = "state_digest_mismatch"
DEVICE_CHECKPOINT_FROZEN = "checkpoint_frozen"


@dataclass(frozen=True)
class DeviceAcknowledgementTestOnly:
    log_id: str
    sequence: int
    entry_hash: bytes
    state_digest: bytes
    timestamp: int
    signature: bytes = b""


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(8, "big") + b


def _device_ack_message(a: DeviceAcknowledgementTestOnly) -> bytes:
    return (b"ratify-test-device-checkpoint-v2\x00" + _lp(a.log_id.encode("utf-8")) + (a.sequence & (2**64 - 1)).to_bytes(8, "big")
            + _lp(a.entry_hash) + _lp(a.state_digest) + (a.timestamp & (2**64 - 1)).to_bytes(8, "big"))


def verify_device_acknowledgement_test_only(pub: bytes, a: DeviceAcknowledgementTestOnly) -> None:
    try:
        if len(pub) != 32:
            raise ValueError("bad key")
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(a.signature, _device_ack_message(a))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("v2reference: device acknowledgement signature does not verify") from exc


class DeviceComponentTestOnly:
    """The independent monotonic authenticated component."""

    def __init__(self, seed: bytes, capacity: int, clock):
        if len(seed) != 32 or capacity < 1 or clock is None:
            raise ValueError("v2reference: device component needs a 32-byte seed, positive capacity, and a clock")
        self._key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        self.clock = clock
        self._capacity = capacity
        self._lock = threading.Lock()
        self._records: list = []
        self._state: Optional[bytes] = None
        self._frozen = False
        self._fault = DEVICE_POWER_OK

    def public_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def set_power_loss(self, fault: int) -> None:
        with self._lock:
            self._fault = fault

    def head(self) -> tuple:
        with self._lock:
            return len(self._records), self._state, self._frozen

    def provision_state(self, digest: bytes) -> None:
        with self._lock:
            if self._state is not None or self._records or len(digest) != 48:
                raise ValueError("v2reference: device component is already provisioned or the digest is not 48 bytes")
            self._state = bytes(digest)

    def anchor_state(self, previous: bytes, nxt: bytes) -> None:
        with self._lock:
            if self._frozen:
                raise DeviceFrozenError()
            if self._state is None or self._state != bytes(previous) or len(nxt) != 48:
                raise DeviceStateMismatchError()
            self._state = bytes(nxt)

    def commit(self, ctx, log_id: str, sequence: int, previous_entry_hash: bytes, entry_hash: bytes, state: bytes):
        # The security clock is read before the component lock.
        try:
            now, clock_err = self.clock.authoritative_time_v2(ctx), None
        except Exception as exc:  # noqa: BLE001
            now, clock_err = 0, exc
        return self._commit_at(now, clock_err, log_id, sequence, previous_entry_hash, entry_hash, state)

    def _commit_at(self, now, clock_err, log_id, sequence, previous_entry_hash, entry_hash, state):
        with self._lock:
            if self._frozen:
                raise DeviceFrozenError()
            if 1 <= sequence <= len(self._records):
                existing = self._records[sequence - 1]
                if existing.log_id == log_id and existing.entry_hash == bytes(entry_hash):
                    return existing
                self._frozen = True
                raise DeviceFrozenError()
            head_entry = bytes(48)
            if self._records:
                head_entry = self._records[-1].entry_hash
                if self._records[-1].log_id != log_id:
                    raise DeviceStateMismatchError()
            if sequence != len(self._records) + 1 or head_entry != bytes(previous_entry_hash) or self._state is None or self._state != bytes(state):
                raise DeviceStateMismatchError()
            if len(self._records) >= self._capacity:
                raise DeviceStorageFullError()
            fault, self._fault = self._fault, DEVICE_POWER_OK
            if fault == DEVICE_POWER_LOSS_BEFORE_COMMIT:
                raise DevicePowerLossError()
            if clock_err is not None:
                raise clock_err
            ack = DeviceAcknowledgementTestOnly(log_id=log_id, sequence=sequence, entry_hash=bytes(entry_hash),
                                                state_digest=bytes(state), timestamp=now)
            ack = replace(ack, signature=self._key.sign(_device_ack_message(ack)))
            self._records.append(ack)
            if fault == DEVICE_POWER_LOSS_AFTER_COMMIT:
                raise DevicePowerLossError()
            return ack

    def get(self, log_id: str, sequence: int) -> DeviceAcknowledgementTestOnly:
        with self._lock:
            if sequence < 1 or sequence > len(self._records) or self._records[sequence - 1].log_id != log_id:
                raise AcknowledgementNotFoundErrorV2()
            return self._records[sequence - 1]


def corrupt_sealed_state_test_only(store, claim_id: str) -> None:
    """Flip one byte of a committed claim's sealed terminal result."""
    with store._lock:
        record = store._claims.get(claim_id)
        if record is not None and record.terminal:
            record.terminal = bytes([record.terminal[0] ^ 1]) + record.terminal[1:]


def _appended_entry(store, sequence: int) -> Optional[bytes]:
    with store._lock:
        if sequence < 1 or sequence > len(store._outbox) or store._outbox[sequence - 1].wire is None:
            return None
        return bytes(store._outbox[sequence - 1].digest)


class DeviceCheckpointTestOnly(V2ReceiptCheckpoint):
    """The primary's view of the component; every acknowledgement it returns
    carries a component signature verified under the pinned key."""

    def __init__(self, primary: DevicePrimaryTestOnly, component: DeviceComponentTestOnly, pinned: bytes):
        if primary is None or component is None:
            raise ValueError("v2reference: device checkpoint needs a primary and a component")
        primary._bind(component)
        self.device, self.primary, self.component, self.pinned = primary, primary.store, component, bytes(pinned)

    def provision(self) -> None:
        self.component.provision_state(self.device.complete_state_digest_test_only())

    def _to_ack(self, a: DeviceAcknowledgementTestOnly) -> V2CheckpointAcknowledgement:
        verify_device_acknowledgement_test_only(self.pinned, a)
        return V2CheckpointAcknowledgement(log_id=a.log_id, sequence=a.sequence, entry_hash=bytes(a.entry_hash), timestamp=a.timestamp)

    def acknowledge_v2_receipt(self, ctx, log_id, sequence, previous_entry_hash, entry_hash):
        appended = _appended_entry(self.primary, sequence)
        if appended is None or appended != bytes(entry_hash):
            raise NotAcknowledgedError()
        try:
            now, clock_err = self.component.clock.authoritative_time_v2(ctx), None
        except Exception as exc:  # noqa: BLE001
            now, clock_err = 0, exc
        with self.device._mu:
            state = self.device._compose_locked(self.device._last_store)
            ack = self.component._commit_at(now, clock_err, log_id, sequence, previous_entry_hash, entry_hash, state)
        return self._to_ack(ack)

    def get_v2_acknowledgement(self, ctx, log_id, sequence):
        return self._to_ack(self.component.get(log_id, sequence))

    def submit_pending(self, ctx) -> tuple:
        """Submit every unacknowledged appended entry in log order; returns
        (acknowledged sequences, error or None), stopping at the first failure."""
        acknowledged: list = []
        nxt = 1
        while True:
            entry = _appended_entry(self.primary, nxt)
            if entry is None:
                return acknowledged, None
            try:
                existing = self.component.get(self.primary._log_id, nxt)
            except AcknowledgementNotFoundErrorV2:
                existing = None
            if existing is None or existing.entry_hash != entry:
                try:
                    self.resubmit(ctx, nxt)
                except Exception as exc:  # noqa: BLE001
                    return acknowledged, exc
                acknowledged.append(nxt)
            nxt += 1

    def resubmit(self, ctx, sequence: int) -> V2CheckpointAcknowledgement:
        entry = _appended_entry(self.primary, sequence)
        if entry is None:
            raise NotAcknowledgedError()
        previous = bytes(48)
        if sequence > 1:
            previous = _appended_entry(self.primary, sequence - 1)
            if previous is None:
                raise NotAcknowledgedError()
        return self.acknowledge_v2_receipt(ctx, self.primary._log_id, sequence, previous, entry)

    def startup(self) -> str:
        head, anchored, frozen = self.component.head()
        if frozen:
            return DEVICE_CHECKPOINT_FROZEN
        if self.primary.log_length() < head:
            return DEVICE_PRIMARY_BEHIND
        try:
            state = self.device.complete_state_digest_test_only()
        except Exception:  # noqa: BLE001
            return DEVICE_STATE_DIGEST_MISMATCH
        if state != anchored:
            return DEVICE_STATE_DIGEST_MISMATCH
        return DEVICE_READY


class DeviceUplinkTestOnly:
    """Uploads signed receipts only from the component-acknowledged prefix,
    in log order, once each. It never releases a decision."""

    def __init__(self, device: DeviceCheckpointTestOnly):
        self.device = device
        self._lock = threading.Lock()
        self._uploaded = 0
        self.collected: list = []

    def upload(self, ctx) -> list:
        with self._lock:
            head, _, _ = self.device.component.head()
            sent = []
            while self._uploaded < head:
                nxt = self._uploaded + 1
                store = self.device.primary
                with store._lock:
                    if nxt > len(store._outbox) or store._outbox[nxt - 1].wire is None:
                        break
                    self.collected.append(bytes(store._outbox[nxt - 1].wire))
                self._uploaded = nxt
                sent.append(nxt)
            return sent
