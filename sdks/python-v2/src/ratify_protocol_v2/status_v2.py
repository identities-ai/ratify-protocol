"""Protocol v2 issuer status reducer and status aggregation.

Faithful port of Go status_state_v2.go, status_evaluation_v2.go, and the
status helpers of security_journal_v2.go. The reducer is a pure function: it
returns a new state for the caller to persist atomically and never mutates
its input.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field, replace
from hashlib import sha384
from typing import Callable, Optional

from ._v2json import go_marshal_strings
from .errors_v2 import V2Error, V2ErrorClass, classify
from .protocol_v2 import (
    MAX_SAFE_INTEGER,
    RevocationListV2,
    RevocationPushV2,
    decode_revocation_list_v2,
    encode_revocation_list_v2,
    revocation_list_signable_bytes_v2,
    revocation_push_signable_bytes_v2,
    status_evidence_digest,
    valid_v2_id,
    verify_revocation_list_v2_signature,
    verify_revocation_push_v2_signature,
)
from .signing_v2 import REVOCATION_LIST, REVOCATION_PUSH, key_id_v2
from .types import HybridPublicKey
from .verification_receipt_v2 import (  # shared definitions, re-exported
    StatusEvidenceEntryV2,
    has_accepted_status_history_per_issuer_v2,
)

# ---------------------------------------------------------------------------
# Types


@dataclass
class RevocationStatusPolicyV2:
    max_list_lifetime_seconds: int = 0
    max_status_age_seconds: int = 0
    clock_skew_seconds: int = 0


@dataclass
class RevocationObservationV2:
    object_type: int = 0
    status_key_epoch: int = 0
    status_key_id: str = ""
    sequence: int = 0
    evidence_digest: bytes = b""
    body_digest: bytes = b""
    revoked_set_digest: bytes = b""
    revoked_cert_ids: list = field(default_factory=list)
    future_dated: bool = False
    fork: bool = False
    gap: bool = False
    accepted: bool = False


@dataclass
class RevocationStatusResultV2:
    status: str
    reason: str = ""
    evidence: list = field(default_factory=list)
    fresh_until: int = 0


@dataclass
class RevocationStatusStateV2:
    issuer_id: str = ""
    status_key_epoch: int = 0
    status_key_id: str = ""
    retired_status_key_ids: list = field(default_factory=list)
    has_floor: bool = False
    floor: int = 0
    accepted_snapshot: Optional[RevocationListV2] = None
    accepted_cert_ids: list = field(default_factory=list)
    has_preceding_checkpoint: bool = False
    preceding_floor: int = 0
    preceding_accepted_cert_ids: list = field(default_factory=list)
    deny_union_cert_ids: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    max_observed_sequence: int = 0
    fork_sequence: int = 0
    reconciliation_required: bool = False
    future_dated_object_observed: bool = False


# ---------------------------------------------------------------------------
# Small helpers


def _sorted_unique(values) -> list:
    return sorted(set(values))


def _contains_all(have, want) -> bool:
    have_set = set(have)
    return all(value in have_set for value in want)


def _equal_sets(a, b) -> bool:
    return len(_sorted_unique(a)) == len(_sorted_unique(b)) and _contains_all(a, b)


def _novel(values, accepted) -> bool:
    return not _contains_all(accepted, values)


def _revoked_set_digest(revoked: list) -> bytes:
    return sha384(go_marshal_strings(list(revoked))).digest()


def _beyond_skew(timestamp: int, now: int, skew: int) -> bool:
    return timestamp > now and timestamp - now > skew


def _list_fresh(lst: RevocationListV2, policy: RevocationStatusPolicyV2, now: int) -> bool:
    if (
        policy.max_list_lifetime_seconds == 0 or policy.max_status_age_seconds == 0
        or lst.next_update - lst.updated_at > policy.max_list_lifetime_seconds
        or _beyond_skew(lst.updated_at, now, policy.clock_skew_seconds) or now > lst.next_update
    ):
        return False
    return now <= lst.updated_at or now - lst.updated_at <= policy.max_status_age_seconds


def _validate_policy(policy: RevocationStatusPolicyV2) -> None:
    for value in (policy.max_list_lifetime_seconds, policy.max_status_age_seconds, policy.clock_skew_seconds):
        if value < 0 or value > MAX_SAFE_INTEGER:
            raise ValueError("revocation status policy contains invalid time bounds")


def _validate_binding(state: RevocationStatusStateV2, issuer_id: str, epoch: int) -> None:
    if state.issuer_id != "" and state.issuer_id != issuer_id:
        raise ValueError("revocation status state belongs to a different issuer")
    if state.issuer_id != "" and state.status_key_epoch != epoch:
        raise ValueError("revocation status state belongs to a different status-key epoch")
    if state.floor < 0 or state.max_observed_sequence < 0 or state.fork_sequence < 0:
        raise ValueError("revocation status state has negative sequence state")
    if (
        state.preceding_floor < 0 or state.preceding_floor > MAX_SAFE_INTEGER
        or (state.preceding_floor == 0 and len(state.preceding_accepted_cert_ids) != 0)
        or len(_sorted_unique(state.preceding_accepted_cert_ids)) != len(state.preceding_accepted_cert_ids)
    ):
        raise ValueError("revocation status state has invalid preceding checkpoint")
    if state.has_floor and (
        state.floor == 0 or state.floor > MAX_SAFE_INTEGER or state.accepted_snapshot is None
        or state.accepted_snapshot.sequence <= 0 or state.accepted_snapshot.sequence > state.floor
    ):
        raise ValueError("revocation status state has inconsistent accepted floor")
    if not state.has_floor and (state.floor != 0 or state.accepted_snapshot is not None or len(state.accepted_cert_ids) != 0):
        raise ValueError("revocation status state has accepted data without a floor")
    if state.max_observed_sequence > MAX_SAFE_INTEGER or state.fork_sequence > MAX_SAFE_INTEGER or epoch == 0 or epoch > MAX_SAFE_INTEGER:
        raise ValueError("revocation status state has invalid sequence or epoch")
    if state.issuer_id != "" and not valid_v2_id(state.status_key_id):
        raise ValueError("revocation status state has an invalid status-key ID")
    if len(_sorted_unique(state.retired_status_key_ids)) != len(state.retired_status_key_ids) or _contains_all(
        state.retired_status_key_ids, [state.status_key_id]
    ):
        raise ValueError("revocation status state has invalid retired status-key history")
    for key_id in state.retired_status_key_ids:
        if not valid_v2_id(key_id):
            raise ValueError("revocation status state has an invalid retired status-key ID")


def _initialize(state: RevocationStatusStateV2, issuer_id: str, epoch: int) -> None:
    if state.issuer_id == "":
        state.issuer_id = issuer_id
        state.status_key_epoch = epoch
    state.accepted_cert_ids = _sorted_unique(state.accepted_cert_ids)
    state.deny_union_cert_ids = _sorted_unique(state.deny_union_cert_ids)


def _clone_list(lst: RevocationListV2) -> RevocationListV2:
    return decode_revocation_list_v2(encode_revocation_list_v2(lst))


def _clone_state(state: RevocationStatusStateV2) -> RevocationStatusStateV2:
    snapshot = state.accepted_snapshot
    copy_state = copy.deepcopy(replace(state, accepted_snapshot=None))
    if snapshot is not None:
        copy_state.accepted_snapshot = _clone_list(snapshot)
    return copy_state


def _add_revocations(state: RevocationStatusStateV2, values) -> None:
    state.deny_union_cert_ids = _sorted_unique(list(state.deny_union_cert_ids) + list(values))


def _required_for_snapshot(observations, epoch: int, sequence: int) -> list:
    values = []
    for o in observations:
        if o.status_key_epoch == epoch and o.sequence <= sequence:
            values.extend(o.revoked_cert_ids)
    return _sorted_unique(values)


def _find_observation(observations, epoch, object_type, sequence, digest) -> int:
    for i in range(len(observations) - 1, -1, -1):
        o = observations[i]
        if o.status_key_epoch == epoch and o.object_type == object_type and o.sequence == sequence and o.evidence_digest == digest:
            return i
    return -1


def _snapshot_conflicts_with_push(state, epoch, sequence, snapshot_ids) -> bool:
    for o in state.observations:
        if o.status_key_epoch != epoch or o.object_type != REVOCATION_PUSH or o.sequence != sequence:
            continue
        if state.has_floor and state.floor == sequence - 1:
            if not _equal_sets(snapshot_ids, list(state.accepted_cert_ids) + list(o.revoked_cert_ids)):
                return True
        elif not _contains_all(snapshot_ids, o.revoked_cert_ids):
            return True
    return False


def _find_set_observation(observations, incoming):
    for i in range(len(observations) - 1, -1, -1):
        o = observations[i]
        if (o.status_key_epoch == incoming.status_key_epoch and o.object_type == incoming.object_type
                and o.sequence == incoming.sequence and o.revoked_set_digest == incoming.revoked_set_digest):
            return o
    return None


def _has_forked_sequence(observations, epoch, object_type, sequence) -> bool:
    return any(
        o.status_key_epoch == epoch and (object_type == 0 or o.object_type == object_type)
        and o.sequence == sequence and o.fork
        for o in observations
    )


def _has_push_body(observations, epoch, sequence, body_digest) -> bool:
    return any(
        o.status_key_epoch == epoch and o.object_type == REVOCATION_PUSH and o.sequence == sequence
        and o.body_digest == body_digest
        for o in observations
    )


def _sequence_conflict(observations, incoming) -> bool:
    for o in observations:
        if o.status_key_epoch != incoming.status_key_epoch or o.sequence != incoming.sequence or o.object_type != incoming.object_type:
            continue
        if incoming.object_type == REVOCATION_LIST and o.revoked_set_digest != incoming.revoked_set_digest:
            return True
        if incoming.object_type == REVOCATION_PUSH and o.body_digest != incoming.body_digest:
            return True
    return False


def _snapshot_omission_for_push(state, epoch, push):
    conflicting = 0

    def check(sequence, revoked):
        nonlocal conflicting
        if sequence >= push.sequence and not _contains_all(revoked, push.revoked_cert_ids) and sequence > conflicting:
            conflicting = sequence

    if state.accepted_snapshot is not None and state.status_key_epoch == epoch:
        check(state.accepted_snapshot.sequence, list(state.accepted_snapshot.revoked))
    if state.reconciliation_required:
        for o in state.observations:
            if (o.status_key_epoch == epoch and o.object_type == REVOCATION_LIST and o.sequence > state.floor
                    and o.sequence >= push.sequence and (o.fork or o.gap or o.future_dated)):
                check(o.sequence, o.revoked_cert_ids)
    return conflicting, conflicting != 0


def _mark_fork(state, observation, sequence) -> None:
    observation.fork = True
    state.reconciliation_required = True
    state.fork_sequence = max(0, state.fork_sequence, state.floor, sequence)


def _heartbeat_preferred(incoming: RevocationListV2, incoming_digest: bytes, accepted: RevocationListV2) -> bool:
    if incoming.updated_at != accepted.updated_at:
        return incoming.updated_at > accepted.updated_at
    try:
        accepted_digest = status_evidence_digest(REVOCATION_LIST, accepted)
    except Exception:  # noqa: BLE001 - Go treats an encode error as "not preferred"
        return False
    return incoming_digest < accepted_digest


def _evidence_key(e: StatusEvidenceEntryV2):
    return (e.issuer_id, e.status_key_id, e.sequence, e.object_type, e.digest)


def sort_status_evidence_v2(evidence) -> list:
    if evidence is None:
        return []
    return sorted(evidence, key=_evidence_key)


def _append_evidence(evidence, issuer_id, status_key_id, observation) -> list:
    if observation.status_key_id != "":
        status_key_id = observation.status_key_id
    entry = StatusEvidenceEntryV2(issuer_id, status_key_id, observation.sequence, observation.object_type,
                                  "sha384:" + observation.evidence_digest.hex())
    if entry in evidence:
        return evidence
    return evidence + [entry]


def _include_accepted_base(evidence, state, issuer_id, status_key_id) -> list:
    evidence = list(evidence or [])
    if state.accepted_snapshot is None:
        return sort_status_evidence_v2(evidence)
    try:
        digest = status_evidence_digest(REVOCATION_LIST, state.accepted_snapshot)
    except Exception:  # noqa: BLE001
        digest = None
    if digest is not None:
        evidence.append(StatusEvidenceEntryV2(issuer_id, status_key_id, state.accepted_snapshot.sequence,
                                              REVOCATION_LIST, "sha384:" + digest.hex()))
    return sort_status_evidence_v2(evidence)


def _accepted_evidence(state, issuer_id, status_key_id) -> list:
    evidence = _include_accepted_base(None, state, issuer_id, status_key_id)
    if state.accepted_snapshot is None:
        return evidence
    for o in state.observations:
        if (o.status_key_epoch == state.status_key_epoch and o.object_type == REVOCATION_PUSH and o.accepted
                and o.sequence > state.accepted_snapshot.sequence and o.sequence <= state.floor):
            evidence = _append_evidence(evidence, issuer_id, status_key_id, o)
    return sort_status_evidence_v2(evidence)


def _unavailable_evidence(state, issuer_id, status_key_id) -> list:
    evidence = _accepted_evidence(state, issuer_id, status_key_id)
    for o in state.observations:
        if o.status_key_epoch != state.status_key_epoch:
            continue
        if o.sequence > state.floor or o.fork or o.gap or o.future_dated or (state.reconciliation_required and not o.accepted):
            evidence = _append_evidence(evidence, issuer_id, status_key_id, o)
    return sort_status_evidence_v2(evidence)


def _evidence_for(state, evidence, issuer_id, status_key_id, include: Callable) -> list:
    for o in state.observations:
        if include(o):
            evidence = _append_evidence(evidence, issuer_id, status_key_id, o)
    return sort_status_evidence_v2(evidence)


# ---------------------------------------------------------------------------
# Accepted-state validation and compaction (security_journal_v2.go helpers)


def _has_accepted_observation(observations, epoch, object_type, sequence, digest) -> bool:
    return any(
        o.status_key_epoch == epoch and o.object_type == object_type and o.sequence == sequence
        and o.evidence_digest == digest and o.accepted and not o.fork and not o.future_dated
        for o in observations
    )


def _validate_accepted_state(state: RevocationStatusStateV2) -> None:
    if (len(_sorted_unique(state.deny_union_cert_ids)) != len(state.deny_union_cert_ids)
            or len(_sorted_unique(state.accepted_cert_ids)) != len(state.accepted_cert_ids)):
        raise ValueError("revocation status sets are not canonical")
    observed = []
    fork_recorded = False
    for o in state.observations:
        if (o.sequence <= 0 or o.sequence > MAX_SAFE_INTEGER or not valid_v2_id(o.status_key_id)
                or o.object_type not in (REVOCATION_LIST, REVOCATION_PUSH)
                or len(o.evidence_digest) != 48 or len(o.body_digest) != 48 or len(o.revoked_set_digest) != 48
                or len(_sorted_unique(o.revoked_cert_ids)) != len(o.revoked_cert_ids)):
            raise ValueError("security journal contains a malformed status observation")
        for cert_id in o.revoked_cert_ids:
            if cert_id == "":
                raise ValueError("status observation contains an invalid certificate ID")
        fork_recorded = fork_recorded or (o.status_key_epoch == state.status_key_epoch and o.fork)
        observed.extend(o.revoked_cert_ids)
        if o.status_key_epoch == state.status_key_epoch and o.sequence > state.max_observed_sequence:
            raise ValueError("observed sequence exceeds its high-water mark")
        if not _contains_all(state.deny_union_cert_ids, o.revoked_cert_ids):
            raise ValueError("deny union omits a revocation from authenticated evidence")
    if not _contains_all(observed, state.deny_union_cert_ids):
        raise ValueError("deny union contains a revocation without a retained authenticated witness")
    if state.fork_sequence > 0 and (not state.reconciliation_required or not fork_recorded):
        raise ValueError("unresolved fork state lacks its retained fork marker")
    if state.has_floor and state.floor > state.max_observed_sequence:
        raise ValueError("accepted floor exceeds the observed sequence high-water mark")
    if not state.has_floor:
        return
    snapshot = state.accepted_snapshot
    if snapshot.issuer_id != state.issuer_id or snapshot.sequence > state.floor:
        raise ValueError("accepted snapshot does not match issuer or floor")
    digest = status_evidence_digest(REVOCATION_LIST, snapshot)
    if not _has_accepted_observation(state.observations, state.status_key_epoch, REVOCATION_LIST, snapshot.sequence, digest):
        raise ValueError("accepted snapshot has no matching authenticated observation")
    accepted = list(snapshot.revoked)
    pushes = []
    for o in state.observations:
        if (o.status_key_epoch == state.status_key_epoch and o.object_type == REVOCATION_PUSH and o.accepted
                and o.sequence > snapshot.sequence and o.sequence <= state.floor):
            pushes.append(o)
            accepted.extend(o.revoked_cert_ids)
    pushes.sort(key=lambda o: o.sequence)
    expected = snapshot.sequence
    for push in pushes:
        if expected >= MAX_SAFE_INTEGER or push.sequence != expected + 1:
            raise ValueError("accepted push observations are not contiguous after the accepted snapshot")
        expected = push.sequence
    if expected != state.floor:
        raise ValueError("accepted push history does not reach the recorded floor")
    if not _equal_sets(accepted, state.accepted_cert_ids):
        raise ValueError("accepted certificate set does not follow the accepted snapshot and pushes")


def _must_retain(state, o) -> bool:
    if o.status_key_epoch != state.status_key_epoch:
        return False
    if (state.accepted_snapshot is not None and o.object_type == REVOCATION_PUSH and o.accepted
            and o.sequence > state.accepted_snapshot.sequence and o.sequence <= state.floor):
        return True
    return state.reconciliation_required and (o.sequence > state.floor or o.fork or o.gap or o.future_dated)


def _semantic_key(o) -> tuple:
    digest = o.revoked_set_digest if o.object_type == REVOCATION_LIST else o.body_digest
    return (o.status_key_epoch, o.object_type, o.sequence, bytes(digest), o.future_dated, o.fork)


def _compact(state: RevocationStatusStateV2) -> RevocationStatusStateV2:
    base_digest = b""
    if state.accepted_snapshot is not None:
        try:
            base_digest = status_evidence_digest(REVOCATION_LIST, state.accepted_snapshot)
        except Exception:  # noqa: BLE001 - Go ignores the error here
            base_digest = b""
    observations = sorted(
        state.observations,
        key=lambda o: (o.status_key_epoch, o.sequence, o.object_type, bytes(o.revoked_set_digest), bytes(o.body_digest)),
    )
    retained: list = []
    witnessed: set = set()
    semantic_seen: dict = {}
    for original in observations:
        o = replace(original, revoked_cert_ids=list(original.revoked_cert_ids))
        accepted_base = (
            len(base_digest) != 0 and o.status_key_epoch == state.status_key_epoch
            and o.object_type == REVOCATION_LIST and o.sequence == state.accepted_snapshot.sequence
            and o.evidence_digest == base_digest
        )
        full_record = accepted_base or _must_retain(state, o)
        new_witnesses = []
        for cert_id in o.revoked_cert_ids:
            if cert_id not in witnessed:
                witnessed.add(cert_id)
                new_witnesses.append(cert_id)
        if not full_record:
            o.revoked_cert_ids = new_witnesses
        key = _semantic_key(o)
        if key in semantic_seen:
            index = semantic_seen[key]
            prior = replace(retained[index])
            prior.accepted = prior.accepted or o.accepted
            prior.fork = prior.fork or o.fork
            prior.gap = prior.gap or o.gap
            prior.future_dated = (prior.future_dated or o.future_dated) and not prior.accepted
            prior.revoked_cert_ids = _sorted_unique(list(prior.revoked_cert_ids) + list(o.revoked_cert_ids))
            if accepted_base:
                prior.evidence_digest = o.evidence_digest
                prior.accepted = True
                if not state.reconciliation_required:
                    prior.gap = False
                prior.future_dated = False
            retained[index] = prior
            continue
        semantic_seen[key] = len(retained)
        retained.append(o)
    if not state.reconciliation_required and state.accepted_snapshot is not None:
        for o in retained:
            if (o.status_key_epoch == state.status_key_epoch and o.object_type == REVOCATION_LIST
                    and o.sequence == state.accepted_snapshot.sequence and o.accepted and not o.future_dated
                    and o.evidence_digest == base_digest):
                o.gap = False
                break
    state.observations = retained
    return state


# ---------------------------------------------------------------------------
# Reducer


def _classified(error_class: str, fn: Callable):
    try:
        return fn()
    except V2Error:
        raise
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise classify(error_class, exc) from exc


def transition_revocation_status_epoch_v2(state: RevocationStatusStateV2, issuer_id: str, next_epoch: int,
                                          next_status_key: HybridPublicKey) -> RevocationStatusStateV2:
    def run() -> RevocationStatusStateV2:
        if issuer_id == "" or next_epoch == 0 or next_epoch > MAX_SAFE_INTEGER:
            raise ValueError("status-key epoch transition has invalid issuer or epoch")
        if (state.issuer_id != issuer_id or state.status_key_epoch == 0 or state.status_key_epoch >= MAX_SAFE_INTEGER
                or next_epoch != state.status_key_epoch + 1):
            raise ValueError("status-key epoch transition must advance exactly one configured issuer epoch")
        _validate_binding(state, issuer_id, state.status_key_epoch)
        _validate_accepted_state(state)
        status_key_id = key_id_v2(next_status_key)
        if status_key_id == state.status_key_id or status_key_id in state.retired_status_key_ids:
            raise ValueError("status-key epoch transition cannot reuse a current or retired status key")
        nxt = _clone_state(state)
        nxt.retired_status_key_ids = _sorted_unique(list(nxt.retired_status_key_ids) + [state.status_key_id])
        nxt.status_key_epoch = next_epoch
        nxt.status_key_id = status_key_id
        nxt.has_floor = False
        nxt.floor = 0
        nxt.accepted_snapshot = None
        nxt.accepted_cert_ids = []
        nxt.has_preceding_checkpoint = False
        nxt.preceding_floor = 0
        nxt.preceding_accepted_cert_ids = []
        nxt.max_observed_sequence = 0
        nxt.fork_sequence = 0
        nxt.reconciliation_required = False
        nxt.future_dated_object_observed = False
        return nxt

    return _classified(V2ErrorClass.CONFIGURATION_INVALID, run)


def revocation_status_for_cert_v2(state: RevocationStatusStateV2, issuer_id: str, cert_id: str, status_key_epoch: int,
                                  status_key: HybridPublicKey, policy: RevocationStatusPolicyV2,
                                  now: int) -> RevocationStatusResultV2:
    """Fail-closed status answer plus deterministic authenticated evidence.

    Raises on invalid inputs (Go returns an unavailable result with the error).
    """
    _validate_policy(policy)
    _validate_binding(state, issuer_id, status_key_epoch)
    _validate_accepted_state(state)
    if cert_id == "" or now < 0 or now > MAX_SAFE_INTEGER:
        raise ValueError("status query has invalid certificate ID or time")
    status_key_id = key_id_v2(status_key)
    if state.issuer_id != issuer_id or state.status_key_epoch != status_key_epoch or state.status_key_id != status_key_id:
        raise ValueError("status query does not match the configured issuer status-key binding")
    if state.accepted_snapshot is not None:
        verify_revocation_list_v2_signature(state.accepted_snapshot, issuer_id, status_key)
    if cert_id in state.deny_union_cert_ids:
        evidence = _accepted_evidence(state, issuer_id, status_key_id)
        evidence = _evidence_for(state, evidence, issuer_id, status_key_id, lambda o: cert_id in o.revoked_cert_ids)
        return RevocationStatusResultV2(status="revoked", evidence=evidence)
    if (not state.has_floor or state.accepted_snapshot is None or policy.max_list_lifetime_seconds == 0
            or policy.max_status_age_seconds == 0 or state.future_dated_object_observed or state.reconciliation_required
            or state.floor < state.max_observed_sequence
            or not _contains_all(state.accepted_cert_ids, state.deny_union_cert_ids)):
        return RevocationStatusResultV2(status="indeterminate", reason="unavailable",
                                        evidence=_unavailable_evidence(state, issuer_id, status_key_id))
    if not _list_fresh(state.accepted_snapshot, policy, now):
        return RevocationStatusResultV2(status="indeterminate", reason="stale",
                                        evidence=_accepted_evidence(state, issuer_id, status_key_id))
    snapshot = state.accepted_snapshot
    return RevocationStatusResultV2(
        status="not_revoked",
        evidence=_accepted_evidence(state, issuer_id, status_key_id),
        fresh_until=min(snapshot.next_update, snapshot.updated_at + policy.max_status_age_seconds),
    )


def _finish(result: RevocationStatusStateV2) -> RevocationStatusStateV2:
    if result.issuer_id != "":
        result = _compact(result)
    return result


def apply_revocation_list_v2(state: RevocationStatusStateV2, lst: RevocationListV2, bound_issuer_id: str,
                             status_key_epoch: int, status_key: HybridPublicKey,
                             policy: RevocationStatusPolicyV2, now: int) -> RevocationStatusStateV2:
    """Verify the caller-authenticated binding and apply one full snapshot."""
    return _finish(_classified(V2ErrorClass.STATUS_OBJECT_REJECTED,
                               lambda: _apply_list(state, lst, bound_issuer_id, status_key_epoch, status_key, policy, now)))


def _apply_list(state, lst, bound_issuer_id, status_key_epoch, status_key, policy, now):
    _validate_policy(policy)
    if now < 0 or now > MAX_SAFE_INTEGER or status_key_epoch == 0 or status_key_epoch > MAX_SAFE_INTEGER:
        raise ValueError("revocation list application has invalid time or status-key epoch")
    verify_revocation_list_v2_signature(lst, bound_issuer_id, status_key)
    _validate_binding(state, bound_issuer_id, status_key_epoch)
    digest = status_evidence_digest(REVOCATION_LIST, lst)
    body_digest = sha384(revocation_list_signable_bytes_v2(lst)).digest()
    set_digest = _revoked_set_digest(lst.revoked)

    nxt = _clone_state(state)
    _initialize(nxt, bound_issuer_id, status_key_epoch)
    status_key_id = key_id_v2(status_key)
    if nxt.status_key_id != "" and nxt.status_key_id != status_key_id:
        raise ValueError("revocation list status key does not match configured epoch binding")
    nxt.status_key_id = status_key_id
    duplicate_index = _find_observation(nxt.observations, status_key_epoch, REVOCATION_LIST, lst.sequence, digest)
    duplicate = duplicate_index >= 0

    future = _beyond_skew(lst.updated_at, now, policy.clock_skew_seconds)
    obs = RevocationObservationV2(
        object_type=REVOCATION_LIST, status_key_epoch=status_key_epoch, status_key_id=status_key_id,
        sequence=lst.sequence, evidence_digest=digest, body_digest=body_digest, revoked_set_digest=set_digest,
        revoked_cert_ids=list(lst.revoked), future_dated=future,
    )
    if not duplicate:
        prior = _find_set_observation(nxt.observations, obs)
        if prior is not None:
            if prior.fork:
                return nxt
            if (prior.future_dated or prior.gap) and not future and _list_fresh(lst, policy, now):
                if (nxt.has_floor and lst.sequence < nxt.floor) or _has_forked_sequence(nxt.observations, status_key_epoch, 0, lst.sequence):
                    return nxt
            elif (not prior.accepted and not prior.fork and nxt.has_floor and lst.sequence == nxt.floor
                  and nxt.accepted_snapshot is not None and nxt.accepted_snapshot.sequence < nxt.floor
                  and not future and _list_fresh(lst, policy, now)):
                pass
            elif prior.accepted and nxt.has_floor and lst.sequence == nxt.floor and _heartbeat_preferred(lst, digest, nxt.accepted_snapshot):
                pass
            else:
                return nxt
    if duplicate:
        prior = nxt.observations[duplicate_index]
        if prior.accepted or (not prior.future_dated and not prior.gap) or future or not _list_fresh(lst, policy, now):
            return nxt
        if nxt.has_floor and lst.sequence < nxt.floor:
            return nxt
        if _has_forked_sequence(nxt.observations, status_key_epoch, 0, lst.sequence):
            return nxt
    else:
        _add_revocations(nxt, obs.revoked_cert_ids)
        if lst.sequence > nxt.max_observed_sequence:
            nxt.max_observed_sequence = lst.sequence
    if future:
        nxt.future_dated_object_observed = True
        nxt.reconciliation_required = True

    if _sequence_conflict(nxt.observations, obs):
        _mark_fork(nxt, obs, lst.sequence)
    elif nxt.has_floor and lst.sequence == nxt.floor and not _equal_sets(obs.revoked_cert_ids, nxt.accepted_cert_ids):
        _mark_fork(nxt, obs, lst.sequence)
    elif nxt.has_floor and lst.sequence < nxt.floor and _novel(obs.revoked_cert_ids, nxt.accepted_cert_ids):
        _mark_fork(nxt, obs, lst.sequence)
    applicable = _required_for_snapshot(nxt.observations, status_key_epoch, lst.sequence)
    if not _contains_all(obs.revoked_cert_ids, applicable):
        _mark_fork(nxt, obs, lst.sequence)
    if _snapshot_conflicts_with_push(nxt, status_key_epoch, lst.sequence, obs.revoked_cert_ids):
        _mark_fork(nxt, obs, lst.sequence)

    def record() -> None:
        if not duplicate:
            nxt.observations.append(obs)

    if not _list_fresh(lst, policy, now):
        if nxt.has_floor and lst.sequence <= nxt.floor:
            record()
            return nxt
        nxt.reconciliation_required = True
        obs.gap = True
        record()
        return nxt
    if obs.fork:
        record()
        return nxt
    if not nxt.has_floor and not _contains_all(obs.revoked_cert_ids, nxt.deny_union_cert_ids):
        nxt.reconciliation_required = True
        obs.gap = True
        record()
        return nxt
    if not nxt.has_floor and lst.sequence < nxt.max_observed_sequence:
        nxt.reconciliation_required = True
        obs.gap = True
        record()
        return nxt
    if nxt.has_floor and lst.sequence < nxt.floor:
        record()
        return nxt

    if nxt.has_floor and lst.sequence == nxt.floor:
        if not _equal_sets(obs.revoked_cert_ids, nxt.accepted_cert_ids):
            _mark_fork(nxt, obs, lst.sequence)
            record()
            return nxt
        if (nxt.accepted_snapshot is None or nxt.accepted_snapshot.sequence < lst.sequence
                or _heartbeat_preferred(lst, digest, nxt.accepted_snapshot)):
            nxt.accepted_snapshot = _clone_list(lst)
        obs.accepted = True
    else:
        copy_list = _clone_list(lst)
        if nxt.has_floor and lst.sequence == nxt.floor + 1:
            nxt.has_preceding_checkpoint = True
            nxt.preceding_floor = nxt.floor
            nxt.preceding_accepted_cert_ids = _sorted_unique(nxt.accepted_cert_ids)
        else:
            nxt.has_preceding_checkpoint = False
            nxt.preceding_floor = 0
            nxt.preceding_accepted_cert_ids = []
        nxt.accepted_snapshot = copy_list
        nxt.accepted_cert_ids = _sorted_unique(obs.revoked_cert_ids)
        nxt.has_floor = True
        nxt.floor = lst.sequence
        obs.accepted = True

    if nxt.reconciliation_required:
        recoverable_fork = nxt.fork_sequence == 0 or (lst.sequence > nxt.fork_sequence and lst.sequence >= nxt.max_observed_sequence)
        fully_observed = _contains_all(obs.revoked_cert_ids, nxt.deny_union_cert_ids)
        if recoverable_fork and fully_observed and lst.sequence >= nxt.max_observed_sequence:
            nxt.reconciliation_required = False
            nxt.future_dated_object_observed = False
            nxt.fork_sequence = 0
    elif lst.sequence >= nxt.max_observed_sequence and _contains_all(obs.revoked_cert_ids, nxt.deny_union_cert_ids):
        nxt.reconciliation_required = False
    if not duplicate or (obs.accepted and not nxt.observations[duplicate_index].accepted):
        nxt.observations.append(obs)
    return nxt


def apply_revocation_push_v2(state: RevocationStatusStateV2, push: RevocationPushV2, bound_issuer_id: str,
                             status_key_epoch: int, status_key: HybridPublicKey,
                             policy: RevocationStatusPolicyV2, now: int) -> RevocationStatusStateV2:
    """Verify the caller-authenticated binding and apply one signed push."""
    return _finish(_classified(V2ErrorClass.STATUS_OBJECT_REJECTED,
                               lambda: _apply_push(state, push, bound_issuer_id, status_key_epoch, status_key, policy, now)))


def _apply_push(state, push, bound_issuer_id, status_key_epoch, status_key, policy, now):
    _validate_policy(policy)
    if now < 0 or now > MAX_SAFE_INTEGER or status_key_epoch == 0 or status_key_epoch > MAX_SAFE_INTEGER:
        raise ValueError("revocation push application has invalid time or status-key epoch")
    verify_revocation_push_v2_signature(push, bound_issuer_id, status_key)
    _validate_binding(state, bound_issuer_id, status_key_epoch)
    digest = status_evidence_digest(REVOCATION_PUSH, push)
    body_digest = sha384(revocation_push_signable_bytes_v2(push)).digest()
    set_digest = _revoked_set_digest(push.revoked)

    nxt = _clone_state(state)
    _initialize(nxt, bound_issuer_id, status_key_epoch)
    status_key_id = key_id_v2(status_key)
    if nxt.status_key_id != "" and nxt.status_key_id != status_key_id:
        raise ValueError("revocation push status key does not match configured epoch binding")
    nxt.status_key_id = status_key_id
    if (_find_observation(nxt.observations, status_key_epoch, REVOCATION_PUSH, push.sequence, digest) >= 0
            or _has_push_body(nxt.observations, status_key_epoch, push.sequence, body_digest)):
        return nxt

    future = _beyond_skew(push.pushed_at, now, policy.clock_skew_seconds)
    obs = RevocationObservationV2(
        object_type=REVOCATION_PUSH, status_key_epoch=status_key_epoch, status_key_id=status_key_id,
        sequence=push.sequence, evidence_digest=digest, body_digest=body_digest, revoked_set_digest=set_digest,
        revoked_cert_ids=list(push.revoked), future_dated=future,
    )
    _add_revocations(nxt, obs.revoked_cert_ids)
    if push.sequence > nxt.max_observed_sequence:
        nxt.max_observed_sequence = push.sequence
    if future:
        nxt.future_dated_object_observed = True
        nxt.reconciliation_required = True
    if _sequence_conflict(nxt.observations, obs):
        _mark_fork(nxt, obs, push.sequence)
    conflicting, conflict = _snapshot_omission_for_push(nxt, status_key_epoch, obs)
    if conflict:
        _mark_fork(nxt, obs, conflicting)

    expected = nxt.floor + 1 if nxt.has_floor else 1
    if nxt.has_floor and push.sequence <= nxt.floor:
        if push.sequence == nxt.floor:
            if (nxt.has_preceding_checkpoint and nxt.preceding_floor == push.sequence - 1
                    and not _equal_sets(nxt.accepted_cert_ids, list(nxt.preceding_accepted_cert_ids) + list(obs.revoked_cert_ids))):
                _mark_fork(nxt, obs, push.sequence)
            elif _novel(obs.revoked_cert_ids, nxt.accepted_cert_ids):
                _mark_fork(nxt, obs, push.sequence)
            elif not obs.fork and _contains_all(nxt.accepted_cert_ids, obs.revoked_cert_ids):
                pass
            else:
                obs.gap = True
                nxt.reconciliation_required = True
            nxt.observations.append(obs)
            return nxt
        if _novel(obs.revoked_cert_ids, nxt.accepted_cert_ids):
            _mark_fork(nxt, obs, push.sequence)
        nxt.observations.append(obs)
        return nxt
    if not nxt.has_floor or push.sequence != expected or nxt.reconciliation_required or future:
        obs.gap = not obs.fork
        nxt.reconciliation_required = True
        nxt.observations.append(obs)
        return nxt

    nxt.accepted_cert_ids = _sorted_unique(list(nxt.accepted_cert_ids) + list(obs.revoked_cert_ids))
    nxt.has_preceding_checkpoint = False
    nxt.preceding_floor = 0
    nxt.preceding_accepted_cert_ids = []
    nxt.has_floor = True
    nxt.floor = push.sequence
    obs.accepted = True
    nxt.observations.append(obs)
    return nxt


# ---------------------------------------------------------------------------
# Aggregation over every CertificateRef (status_evaluation_v2.go)


@dataclass
class V2StatusAssessment:
    assessment: str = ""
    reason: str = ""
    evidence: list = field(default_factory=list)
    fresh_until: int = 0


@dataclass
class V2StatusRoleBindings:
    status_key_issuers: Optional[dict] = None
    current_status_key_ids: Optional[dict] = None
    reserved_key_ids: Optional[set] = None


@dataclass(frozen=True)
class V2CertificateStatusCheck:
    delegation_index: int
    issuer_id: str
    subject_id: str
    cert_id: str


_LOWER_HEX_96 = re.compile(r"[0-9a-f]{96}")


def _valid_evidence_digest(value) -> bool:
    return isinstance(value, str) and value.startswith("sha384:") and _LOWER_HEX_96.fullmatch(value[7:]) is not None


def _validate_roles(roles: V2StatusRoleBindings, checks) -> None:
    if roles.status_key_issuers is None or roles.current_status_key_ids is None or roles.reserved_key_ids is None:
        raise ValueError("v2 status aggregation requires authenticated status-key role bindings")
    for key_id, issuer_id in roles.status_key_issuers.items():
        if not valid_v2_id(key_id) or not valid_v2_id(issuer_id):
            raise ValueError("authenticated status-key binding is malformed")
        if key_id in roles.reserved_key_ids:
            raise ValueError("status key collides with a reserved non-status key role")
    for issuer_id in {check.issuer_id for check in checks}:
        key_id = roles.current_status_key_ids.get(issuer_id, "")
        if roles.status_key_issuers.get(key_id, "") != issuer_id:
            raise ValueError("issuer lacks an authenticated current status-key binding")
    for key_id in roles.reserved_key_ids:
        if not valid_v2_id(key_id):
            raise ValueError("reserved non-status key ID is malformed")


def _add_issuer_history(histories: dict, issuer_id: str, evidence) -> bool:
    canonical = sort_status_evidence_v2(list(evidence))
    if issuer_id not in histories:
        histories[issuer_id] = canonical
        return True
    return histories[issuer_id] == canonical


def _valid_current_evidence(evidence, issuer_id: str) -> bool:
    if not evidence:
        return False
    base_count = 0
    base = None
    pushes = []
    for entry in evidence:
        if entry.issuer_id != issuer_id:
            return False
        if entry.object_type == REVOCATION_LIST:
            base_count += 1
            base = entry
        elif entry.object_type == REVOCATION_PUSH:
            pushes.append(entry)
        else:
            return False
    if base_count != 1:
        return False
    pushes.sort(key=lambda e: e.sequence)
    for i, push in enumerate(pushes):
        if push.status_key_id != base.status_key_id or push.sequence != base.sequence + i + 1:
            return False
    return True


def aggregate_certificate_status_v2(checks, results, roles: V2StatusRoleBindings) -> V2StatusAssessment:
    """One result per CertificateRef; revoked > unavailable > stale, independent of order."""
    if len(checks) == 0 or len(checks) != len(results):
        raise ValueError("v2 status aggregation requires one result for every non-empty certificate list")
    _validate_roles(roles, checks)
    assessment = V2StatusAssessment(assessment="current", evidence=[])
    seen: set = set()
    digest_bindings: dict = {}
    invalid_digests: set = set()
    issuer_ids: list = []
    seen_certificates: set = set()
    issuer_set: set = set()
    subject_set: set = set()
    for i, check in enumerate(checks):
        if check.delegation_index != i or not valid_v2_id(check.issuer_id) or not valid_v2_id(check.subject_id) or check.cert_id == "":
            raise ValueError(f"v2 status check {i} has an invalid delegation index or CertificateRef")
        ref = (check.issuer_id, check.cert_id)
        if ref in seen_certificates:
            raise ValueError("v2 status checks contain a duplicate CertificateRef")
        seen_certificates.add(ref)
        subject_set.add(check.subject_id)
        if check.issuer_id not in issuer_set:
            issuer_set.add(check.issuer_id)
            issuer_ids.append(check.issuer_id)
    invalid_result = any_revoked = any_unavailable = any_stale = False
    revoked_candidates = []
    issuer_history: dict = {}
    for i, check in enumerate(checks):
        result = results[i]
        evidence_list = list(result.evidence or [])
        result_valid = True
        for evidence in evidence_list:
            if (evidence.issuer_id != check.issuer_id or not valid_v2_id(evidence.status_key_id)
                    or evidence.sequence <= 0 or evidence.sequence > MAX_SAFE_INTEGER
                    or not _valid_evidence_digest(evidence.digest)
                    or evidence.object_type not in (REVOCATION_LIST, REVOCATION_PUSH)):
                result_valid = False
                continue
            if evidence.status_key_id in issuer_set or evidence.status_key_id in subject_set:
                result_valid = False
                continue
            if (evidence.status_key_id in roles.reserved_key_ids
                    or roles.status_key_issuers.get(evidence.status_key_id, "") != evidence.issuer_id
                    or (result.status != "revoked"
                        and roles.current_status_key_ids.get(evidence.issuer_id, "") != evidence.status_key_id)):
                result_valid = False
                continue
            prior = digest_bindings.get(evidence.digest)
            if prior is not None and prior != evidence:
                invalid_digests.add(evidence.digest)
            digest_bindings[evidence.digest] = evidence
            if evidence not in seen:
                seen.add(evidence)
                assessment.evidence.append(evidence)
        if result.status == "not_revoked":
            result_valid = (result_valid and result.reason == "" and 0 < result.fresh_until <= MAX_SAFE_INTEGER
                            and _valid_current_evidence(evidence_list, check.issuer_id))
            if result_valid:
                if assessment.fresh_until == 0 or result.fresh_until < assessment.fresh_until:
                    assessment.fresh_until = result.fresh_until
                result_valid = _add_issuer_history(issuer_history, check.issuer_id, evidence_list)
        elif result.status == "revoked":
            result_valid = result_valid and result.reason == "" and len(evidence_list) > 0
            if result_valid:
                revoked_candidates.append(i)
        elif result.status == "indeterminate":
            if result.reason == "unavailable":
                any_unavailable = True
            elif result.reason == "stale":
                result_valid = result_valid and _valid_current_evidence(evidence_list, check.issuer_id)
                if result_valid:
                    result_valid = _add_issuer_history(issuer_history, check.issuer_id, evidence_list)
                any_stale = True
            else:
                result_valid = False
        else:
            result_valid = False
        invalid_result = invalid_result or not result_valid
    if invalid_digests:
        assessment.evidence = [e for e in assessment.evidence if e.digest not in invalid_digests]
        invalid_result = True
    for i in revoked_candidates:
        evidence_list = list(results[i].evidence or [])
        valid = len(evidence_list) > 0 and not any(e.digest in invalid_digests for e in evidence_list)
        any_revoked = any_revoked or valid
    assessment.evidence = sort_status_evidence_v2(assessment.evidence)
    if any_revoked:
        assessment.assessment, assessment.reason = "revoked", "delegation_revoked"
    elif invalid_result or any_unavailable:
        assessment.assessment, assessment.reason = "unavailable", "status_unavailable"
    elif any_stale:
        assessment.assessment, assessment.reason = "stale", "status_stale"
    elif not has_accepted_status_history_per_issuer_v2(assessment.evidence, _sorted_unique(issuer_ids)):
        assessment.assessment, assessment.reason = "unavailable", "status_unavailable"
    if assessment.assessment != "current":
        assessment.fresh_until = 0
    return assessment
