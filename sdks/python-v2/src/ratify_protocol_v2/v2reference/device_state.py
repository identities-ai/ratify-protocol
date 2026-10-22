"""Complete security state of a single-device offline primary (mirrors Go
v2reference/device_state.go, SPEC-v2 §7.13), TEST ONLY.

``DevicePrimaryTestOnly`` groups every durable security record the primary
holds: the claim store with its release records, stream sequences, rate
counters and receipt log, its anchored SecurityJournalV2 store, its challenge
issuance records, and its replay epoch. Its complete-state digest is a
labelled SHA-384 over a versioned canonical projection of all of them. Once
bound to a device component, every durable change is anchored in the
component before it takes effect; a change the component refuses is undone.

The member digests are this SDK's own deterministic encoding of each
record. They are compared only within one device, never across SDKs.
"""
from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass, fields, is_dataclass

from .._v2json import canonical
from ..errors_v2 import V2Error, V2ErrorClass
from .challenges import TestOnlyChallengeIssuanceStore
from .journal import JournalStore

DEVICE_STATE_LABEL = b"ratify/device-complete-state/v2"
DEVICE_STATE_VERSION = 1


@dataclass(frozen=True)
class StoreStateTestOnly:
    claims: str = ""
    streams: str = ""
    rate_counters: str = ""
    receipt_log: str = ""


def _sha384_hex(b: bytes) -> str:
    return hashlib.sha384(b).hexdigest()


def _plain(value):
    """A deterministic, JSON-safe projection of a record."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    to_dict = getattr(value, "to_canonical_dict", None)
    if to_dict is not None:
        return _plain(to_dict())
    raise TypeError(f"cannot project {type(value).__name__}")


def _record_digest(value) -> str:
    return _sha384_hex(canonical(_plain(value)))


def _member_digest(value) -> str:
    return _sha384_hex(canonical(value))


def _optional_digest(b: bytes) -> str:
    return _sha384_hex(b) if b else ""


def _state_digests_locked(store) -> StoreStateTestOnly:
    """Go ``stateDigestsLocked``: digests of every durable record of the
    store. Checkpoint acknowledgements and clock readings are excluded."""
    claims = []
    for claim_id in sorted(store._claims, key=lambda s: s.encode("utf-8")):
        r = store._claims[claim_id]
        claims.append({
            "abandoned": r.abandoned, "allow_horizon": r.allow_horizon, "claim_id": claim_id,
            "claim_sha384": _record_digest(r.claim), "claimed_at": r.claimed_at, "finalized_at": r.finalized_at,
            "lease_expires_at": r.lease_expires_at, "outbox_index": r.outbox_index, "owner_digest": r.owner_digest.hex(),
            "progress_sha384": _record_digest(r.progress), "receipt_body_sha384": _optional_digest(r.receipt_body),
            "release_sha384": _record_digest(r.release) if r.release is not None else "", "state": r.state,
            "terminal_sha384": _optional_digest(r.terminal),
        })
    streams = sorted(({"last_seq": seq, "stream": key} for key, seq in store._streams.items()),
                     key=lambda s: s["stream"].encode("utf-8"))
    rates = sorted(({"cert_id": key[1], "commits": list(commits), "issuer_id": key[0], "window_s": key[2]}
                    for key, commits in store._rate_commits.items()),
                   key=lambda r: (r["issuer_id"].encode("utf-8"), r["cert_id"].encode("utf-8"), r["window_s"]))
    log = {"entries": [{"body_sha384": _optional_digest(e.body), "claim_id": e.claim_id, "entry_hash": bytes(e.digest).hex(),
                        "sequence": i + 1} for i, e in enumerate(store._outbox)],
           "frozen": store._log_frozen, "log_id": store._log_id}
    return StoreStateTestOnly(claims=_member_digest(claims), streams=_member_digest(streams),
                              rate_counters=_member_digest(rates), receipt_log=_member_digest(log))


class DevicePrimaryTestOnly:
    """The primary of the single-device offline profile. Lock order: a
    sub-store's own lock, then the primary's anchor lock, then the journal or
    issuance store lock and the component lock."""

    def __init__(self, store, replay_epoch: int):
        if store is None or type(replay_epoch) is not int or replay_epoch < 0:
            raise ValueError("v2reference: device primary needs a store and a non-negative replay epoch")
        self.store = store
        self._replay_epoch = replay_epoch
        self._mu = threading.RLock()
        self._component = None
        self._last_store = StoreStateTestOnly()
        self.journal = DeviceJournalTestOnly(self, JournalStore())
        self.issuance = DeviceIssuanceTestOnly(self, TestOnlyChallengeIssuanceStore())

    def clone(self) -> "DevicePrimaryTestOnly":
        """Copy the complete primary state (a backup). Not bound to any component."""
        out = DevicePrimaryTestOnly.__new__(DevicePrimaryTestOnly)
        out.store = self.store.clone()
        out._replay_epoch = self._replay_epoch
        out._mu = threading.RLock()
        out._component = None
        out._last_store = StoreStateTestOnly()
        inner = self.journal.inner
        with inner._lock:
            journal = JournalStore()
            journal._head, journal._snapshot = inner._head, bytes(inner._snapshot)
        issuance = TestOnlyChallengeIssuanceStore()
        with self.issuance.inner._lock:
            issuance._records = {k: copy.deepcopy(v) for k, v in self.issuance.inner._records.items()}
        out.journal = DeviceJournalTestOnly(out, journal)
        out.issuance = DeviceIssuanceTestOnly(out, issuance)
        return out

    def _bind(self, component) -> None:
        with self.store._lock:
            current = _state_digests_locked(self.store)
        with self._mu:
            self._component, self._last_store = component, current
        with self.store._lock:
            self.store._anchor = self._anchor_store

    def _anchor_store(self, previous: StoreStateTestOnly, nxt: StoreStateTestOnly) -> None:
        """The store hook; it runs with the store lock held."""
        with self._mu:
            before = self._compose_locked(previous)
            after = self._compose_locked(nxt)
            self._component.anchor_state(before, after)
            self._last_store = nxt

    def _compose_locked(self, store: StoreStateTestOnly) -> bytes:
        journal = self.journal.inner
        with journal._lock:
            journal_member = {"generation": journal._head.generation, "snapshot_sha384": _sha384_hex(journal._snapshot)}
        issuance = self.issuance.inner
        with issuance._lock:
            records = [{"key": key, "record_sha384": _record_digest(record)} for key, record in issuance._records.items()]
        records.sort(key=lambda r: r["key"].encode("utf-8"))
        body = canonical({
            "claims": store.claims, "issuance_records": _member_digest(records), "log_id": self.store._log_id,
            "rate_counters": store.rate_counters, "receipt_log": store.receipt_log, "replay_epoch": self._replay_epoch,
            "security_journal": journal_member, "streams": store.streams, "version": DEVICE_STATE_VERSION,
        })
        return hashlib.sha384(DEVICE_STATE_LABEL + b"\x00" + body).digest()

    def complete_state_digest_test_only(self) -> bytes:
        with self.store._lock:
            current = _state_digests_locked(self.store)
        with self._mu:
            return self._compose_locked(current)

    def _change_other(self, apply, undo):
        """Apply a journal or issuance change, anchored before it takes effect
        and undone if the component refuses it."""
        with self._mu:
            if self._component is None:
                return apply()
            before = self._compose_locked(self._last_store)
            apply_err = None
            try:
                result = apply()
            except Exception as exc:  # noqa: BLE001
                apply_err, result = exc, None
            try:
                after = self._compose_locked(self._last_store)
                if before != after:
                    self._component.anchor_state(before, after)
            except Exception as exc:  # noqa: BLE001
                undo()
                raise V2Error(V2ErrorClass.CLAIM_STORE_UNAVAILABLE,
                              f"v2reference: durable state change was not anchored: {exc}") from exc
            if apply_err is not None:
                raise apply_err
            return result


class DeviceJournalTestOnly:
    """The primary's anchored SecurityJournalV2 store."""

    def __init__(self, primary: DevicePrimaryTestOnly, inner: JournalStore):
        self.primary, self.inner = primary, inner

    def load(self, ctx):
        return self.inner.load(ctx)

    def compare_and_swap(self, ctx, expected, nxt):
        with self.inner._lock:
            head, snapshot = self.inner._head, self.inner._snapshot

        def undo():
            with self.inner._lock:
                self.inner._head, self.inner._snapshot = head, snapshot

        return self.primary._change_other(lambda: self.inner.compare_and_swap(ctx, expected, nxt), undo)

    def head(self):
        return self.inner.head()


class DeviceIssuanceTestOnly:
    """The primary's challenge issuance store."""

    def __init__(self, primary: DevicePrimaryTestOnly, inner: TestOnlyChallengeIssuanceStore):
        self.primary, self.inner = primary, inner

    def persist_v2_challenge(self, ctx, record):
        with self.inner._lock:
            saved = dict(self.inner._records)

        def undo():
            with self.inner._lock:
                self.inner._records = saved

        return self.primary._change_other(lambda: self.inner.persist_v2_challenge(ctx, record), undo)

    def load_v2_challenge(self, ctx, namespace, epoch, digest):
        return self.inner.load_v2_challenge(ctx, namespace, epoch, digest)
