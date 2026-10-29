"""Complete security state of a single-device offline primary (mirrors Go
v2reference/device_state.go, SPEC-v2 §7.13), TEST ONLY.

``DevicePrimaryTestOnly`` groups every durable security record the primary
holds: the claim store with its release records, stream sequences, rate
counters and receipt log, its anchored SecurityJournalV2 store, its challenge
issuance records, and its replay epoch. Its complete-state digest is a
labelled SHA-384 over a versioned canonical projection of all of them. Once
bound to a device component, every durable change is anchored in the
component before it takes effect; a change the component refuses is undone.

Every record uses the normative encoding of SPEC-v2 §7.13, pinned by the
known answers of testvectors/v2/device-state.json.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import threading
from dataclasses import dataclass

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


# Projection values follow the normative record encodings of SPEC-v2 §7.13.
# Objects are dicts, so RatifyCanonicalJSON orders their members by UTF-8 byte
# order; every collection is sorted explicitly before encoding.


def _b64(b: bytes) -> str:
    return base64.b64encode(bytes(b)).decode("ascii")


def _bytes_or_null(b):
    """Padded base64 of a stored byte string, or null when there is none."""
    return _b64(b) if b else None


def _sha384_or_null(b):
    """Lowercase hex SHA-384 of exact stored bytes, or null when there are none."""
    return _sha384_hex(bytes(b)) if b else None


def _utf8(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


def _sealed_claim_projection(c) -> dict:
    return {
        "agent_id": c.agent_id, "bundle_hash": c.bundle_hash, "challenge_digest": c.challenge_digest,
        "claim_id": c.claim_id, "clock_skew_seconds": c.clock_skew_seconds,
        "constraint_evaluators": [{"profile_digest": e.profile_digest, "type": e.type}
                                  for e in (c.constraint_evaluators or [])],
        "context_policy_digest": c.context_policy_digest or None, "expires_at": c.expires_at,
        "issued_at": c.issued_at, "issuer_ids": list(c.issuer_ids or []), "max_age_seconds": c.max_age_seconds,
        "namespace": c.namespace, "proof_digest": c.proof_digest,
        "rate_batch": [{"cert_id": r.cert_id, "issuer_id": r.issuer_id, "limit": r.limit, "window_s": r.window_s}
                       for r in (c.rate_batch or [])],
        "replay_epoch": c.replay_epoch, "required_scope": c.required_scope, "requires_rate": bool(c.requires_rate),
        "stream_id": _bytes_or_null(c.stream_id), "stream_seq": c.stream_seq, "verifier_id": c.verifier_id,
    }


def _progress_projection(p) -> dict:
    return {
        "context_assessment": p.context_assessment, "context_policy_digest": p.context_policy_digest,
        "status_assessment": p.status_assessment,
        "status_evidence_digests": [
            {"digest": e.digest, "issuer_id": e.issuer_id, "object_type_code": int(e.object_type),
             "sequence": e.sequence, "status_key_id": e.status_key_id}
            for e in (p.status_evidence or [])
        ],
        "trust_assessment": p.trust_assessment,
    }


def _claim_projection(claim_id: str, r) -> dict:
    release = None
    if r.release is not None:
        release = {"ack_timestamp": r.release.ack_timestamp, "claim_id": r.release.claim_id,
                   "entry_hash": _b64(r.release.entry_hash), "outcome": r.release.outcome,
                   "reason": r.release.reason or None}
    return {
        "abandoned": r.abandoned, "allow_horizon": r.allow_horizon, "claim": _sealed_claim_projection(r.claim),
        "claim_id": claim_id, "claimed_at": r.claimed_at, "finalized_at": r.finalized_at,
        "lease_expires_at": r.lease_expires_at, "log_sequence": r.outbox_index + 1 if r.outbox_index >= 0 else None,
        "owner_digest": _b64(r.owner_digest), "progress": _progress_projection(r.progress),
        "receipt_body_sha384": _sha384_or_null(r.receipt_body), "release": release, "state": r.state,
        "terminal_sha384": _sha384_or_null(r.terminal),
    }


def _issuance_projection(e) -> dict:
    agent_key = None
    if e.expected_agent_public_key is not None:
        agent_key = {"ed25519": _b64(e.expected_agent_public_key.ed25519),
                     "ml_dsa_65": _b64(e.expected_agent_public_key.ml_dsa_65)}
    policy = None
    if e.context_policy is not None:
        policy = {"expected_session_context": _bytes_or_null(e.context_policy.expected_session_context),
                  "profile": e.context_policy.profile, "require_bound": e.context_policy.require_bound,
                  "required_fields": e.context_policy.required_fields, "version": 1}
    return {
        "context_policy": policy, "expected_agent_id": e.expected_agent_id, "expected_agent_pub_key": agent_key,
        "expected_receiver_id": e.expected_receiver_id,
        "expected_session_context": _bytes_or_null(e.expected_session_context), "expires_at": e.expires_at,
        "issued_at": e.issued_at, "replay_epoch": e.replay_epoch, "value": _b64(e.value),
        "verifier_id": e.verifier_id, "verifier_namespace": e.verifier_namespace,
    }


def _store_members_locked(store) -> tuple[bytes, bytes, bytes, bytes]:
    """Go ``storeMembersLocked``: the RatifyCanonicalJSON of the claims,
    streams, rate_counters, and receipt_log members: every claim in every
    state with its sealed values and release record, every stream sequence,
    every rate counter, and the receipt log with its outbox. Checkpoint
    acknowledgements and clock readings are excluded."""
    claims = [_claim_projection(claim_id, store._claims[claim_id])
              for claim_id in sorted(store._claims, key=_utf8)]
    streams = [{"agent_id": agent, "last_sequence": store._streams[(namespace, agent, stream)],
                "namespace": namespace, "stream_id": _b64(stream)}
               for namespace, agent, stream in sorted(store._streams, key=lambda k: (_utf8(k[0]), _utf8(k[1]), k[2]))]
    rates = [{"cert_id": cert_id, "commits": list(store._rate_commits[(issuer_id, cert_id, window_s)]),
              "issuer_id": issuer_id, "window_s": window_s}
             for issuer_id, cert_id, window_s in sorted(store._rate_commits,
                                                        key=lambda k: (_utf8(k[0]), _utf8(k[1]), k[2]))]
    entries = [{"body_sha384": _sha384_hex(bytes(e.body)), "claim_id": e.claim_id,
                "entry_hash": _bytes_or_null(e.digest), "sequence": i + 1} for i, e in enumerate(store._outbox)]
    log = {"entries": entries, "frozen": store._log_frozen, "log_id": store._log_id}
    return canonical(claims), canonical(streams), canonical(rates), canonical(log)


def _state_digests_locked(store) -> StoreStateTestOnly:
    """Go ``stateDigestsLocked``: the store member digests of the projection."""
    claims, streams, rates, log = _store_members_locked(store)
    return StoreStateTestOnly(claims=_sha384_hex(claims), streams=_sha384_hex(streams),
                              rate_counters=_sha384_hex(rates), receipt_log=_sha384_hex(log))


def _complete_state_digest(projection: bytes) -> bytes:
    """The labelled SHA-384 of the projection bytes."""
    return hashlib.sha384(DEVICE_STATE_LABEL + b"\x00" + projection).digest()


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
        return _complete_state_digest(self._projection_locked(store, _sha384_hex(self._issuance_member_locked())))

    def _issuance_member_locked(self) -> bytes:
        """Go ``issuanceMemberLocked``: the RatifyCanonicalJSON of the
        issuance_records member, sorted by (verifier_namespace, replay_epoch,
        value)."""
        issuance = self.issuance.inner
        with issuance._lock:
            records = list(issuance._records.values())
        records.sort(key=lambda e: (_utf8(e.verifier_namespace), e.replay_epoch, bytes(e.value)))
        return canonical([_issuance_projection(e) for e in records])

    def _projection_locked(self, store: StoreStateTestOnly, issuance_digest: str) -> bytes:
        """Go ``projectionLocked``: the RatifyCanonicalJSON of the version 1
        projection object."""
        journal = self.journal.inner
        with journal._lock:
            journal_member = {"generation": journal._head.generation, "snapshot_sha384": _sha384_hex(journal._snapshot)}
        return canonical({
            "claims": store.claims, "issuance_records": issuance_digest, "log_id": self.store._log_id,
            "rate_counters": store.rate_counters, "receipt_log": store.receipt_log, "replay_epoch": self._replay_epoch,
            "security_journal": journal_member, "streams": store.streams, "version": DEVICE_STATE_VERSION,
        })

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
