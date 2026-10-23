"""Protocol v2 issuer revocation status reducer (Go status_state_v2.go).

The reducer is a pure function of its inputs: every ``apply_*`` call returns a
new :class:`RevocationStatusStateV2` that the caller persists atomically with
its security journal, and never mutates the state it was given. A rejected
input raises a classified :class:`~ratify_protocol_v2.errors_v2.V2Error` and
leaves the caller's state unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha384
from typing import Callable, Optional

from ._v2json import canonical
from .errors_v2 import V2Error, V2ErrorClass, classified, classify
from .types import HybridPublicKey
from .types_v2 import MAX_SAFE_INTEGER, StatusEvidenceEntryV2, is_int, valid_v2_id

__all__ = [
    "RevocationStatusPolicyV2",
    "RevocationObservationV2",
    "RevocationStatusResultV2",
    "RevocationStatusStateV2",
    "StatusEvidenceEntryV2",
    "apply_revocation_list_v2",
    "apply_revocation_push_v2",
    "revocation_status_for_cert_v2",
    "transition_revocation_status_epoch_v2",
]

REVOCATION_LIST_CODE = 0x0003
REVOCATION_PUSH_CODE = 0x0005

# SPEC-v2 §2.5 bounds (Go clock_bounds_v2.go).
V2_MAX_TIMESTAMP_SECONDS = 253402300799
V2_MAX_FUTURE_SKEW_SECONDS = 300
V2_MAX_STATUS_LIFETIME_SECONDS = 86400


def _valid_timestamp(t: object) -> bool:
    return is_int(t) and 0 <= t <= V2_MAX_TIMESTAMP_SECONDS


def _valid_epoch(epoch: object) -> bool:
    return is_int(epoch) and 0 < epoch <= MAX_SAFE_INTEGER


# ---------------------------------------------------------------------------
# Types


@dataclass
class RevocationStatusPolicyV2:
    """Finite freshness bounds for one verifier deployment. A zero maximum
    means the bound is not configured; status can then never be current."""

    max_list_lifetime_seconds: int = 0
    max_status_age_seconds: int = 0
    clock_skew_seconds: int = 0


@dataclass
class RevocationObservationV2:
    """Authenticated status evidence. ``evidence_digest`` includes the
    signature; ``body_digest`` excludes it and detects same-sequence semantic
    conflicts despite randomized signatures."""

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
    status: str = ""
    reason: str = ""
    evidence: list = field(default_factory=list)
    fresh_until: int = 0


@dataclass
class RevocationStatusStateV2:
    """One issuer's rollback-protected reducer state. Callers serialize
    ``apply_*`` calls and atomically persist the returned value with their
    security journal; this value alone is not durable."""

    issuer_id: str = ""
    status_key_epoch: int = 0
    status_key_id: str = ""
    retired_status_key_ids: list = field(default_factory=list)
    has_floor: bool = False
    floor: int = 0
    accepted_snapshot: Optional[object] = None  # RevocationListV2
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


def _unavailable() -> RevocationStatusResultV2:
    return RevocationStatusResultV2(status="indeterminate", reason="unavailable", evidence=[])


# ---------------------------------------------------------------------------
# Wire helpers (the object modules are imported lazily to keep import order
# independent of the wire layer).


def _wire():
    from . import protocol_v2

    return protocol_v2


def _key_id_v2(pub: HybridPublicKey) -> str:
    from .signing_v2 import _key_id_v2 as key_id

    return key_id(pub)


def _cert_ids(refs) -> list:
    """Go ``revokedCertIDsV2``: the cert IDs of a revoked array."""
    out = []
    for ref in refs or []:
        out.append(ref if isinstance(ref, str) else ref.cert_id)
    return out


def _status_evidence_digest(code: int, obj) -> bytes:
    return _wire().status_evidence_digest(code, obj)


def _sha384_hex(b: bytes) -> str:
    return "sha384:" + bytes(b).hex()


# ---------------------------------------------------------------------------
# Set helpers


def sorted_unique_strings_v2(values) -> list:
    return sorted(set(values or []))


def contains_all_string_set_v2(have, want) -> bool:
    s = set(have or [])
    return all(v in s for v in (want or []))


def equal_string_sets_v2(a, b) -> bool:
    return len(sorted_unique_strings_v2(a)) == len(sorted_unique_strings_v2(b)) and contains_all_string_set_v2(a, b)


def _add_revocations(state: RevocationStatusStateV2, values) -> None:
    state.deny_union_cert_ids = sorted_unique_strings_v2(list(state.deny_union_cert_ids) + list(values))


def revoked_set_digest_v2(revoked) -> bytes:
    """RevokedSetDigest (SPEC-v2 §4): SHA-384("ratify-protocol-revoked-set-v2"
    || 0x00 || RatifyCanonicalJSON(sorted, deduplicated cert_ids))."""
    body = canonical(sorted_unique_strings_v2(_cert_ids(revoked)))
    return sha384(b"ratify-protocol-revoked-set-v2\x00" + body).digest()


def _contains_novel(values, accepted) -> bool:
    return not contains_all_string_set_v2(accepted, values)


# ---------------------------------------------------------------------------
# Cloning


def clone_revocation_list_v2(lst):
    w = _wire()
    return w.decode_revocation_list_v2(w.encode_revocation_list_v2(lst))


def clone_revocation_status_state_v2(state: RevocationStatusStateV2) -> RevocationStatusStateV2:
    out = replace(state)
    out.retired_status_key_ids = list(state.retired_status_key_ids or [])
    out.accepted_cert_ids = list(state.accepted_cert_ids or [])
    out.preceding_accepted_cert_ids = list(state.preceding_accepted_cert_ids or [])
    out.deny_union_cert_ids = list(state.deny_union_cert_ids or [])
    out.observations = [replace(o, revoked_cert_ids=list(o.revoked_cert_ids or [])) for o in (state.observations or [])]
    if state.accepted_snapshot is not None:
        out.accepted_snapshot = clone_revocation_list_v2(state.accepted_snapshot)
    return out


# ---------------------------------------------------------------------------
# Validation


def validate_revocation_status_policy_v2(policy: RevocationStatusPolicyV2) -> None:
    if not isinstance(policy, RevocationStatusPolicyV2):
        raise ValueError("revocation status policy is required")
    values = (policy.max_list_lifetime_seconds, policy.max_status_age_seconds, policy.clock_skew_seconds)
    if not all(is_int(v) for v in values):
        raise ValueError("revocation status policy contains invalid time bounds")
    if (
        policy.max_list_lifetime_seconds < 0 or policy.max_status_age_seconds < 0 or policy.clock_skew_seconds < 0
        or policy.max_list_lifetime_seconds > V2_MAX_STATUS_LIFETIME_SECONDS
        or policy.max_status_age_seconds > V2_MAX_STATUS_LIFETIME_SECONDS
        or policy.clock_skew_seconds > V2_MAX_FUTURE_SKEW_SECONDS
    ):
        raise ValueError("revocation status policy contains invalid time bounds")


def validate_status_state_binding_v2(state: RevocationStatusStateV2, issuer_id: str, epoch: int) -> None:
    if not isinstance(state, RevocationStatusStateV2):
        raise ValueError("revocation status state is required")
    for v in (state.status_key_epoch, state.floor, state.max_observed_sequence, state.fork_sequence, state.preceding_floor):
        if not is_int(v):
            raise ValueError("revocation status state has non-integer sequence state")
    if state.issuer_id != "" and state.issuer_id != issuer_id:
        raise ValueError("revocation status state belongs to a different issuer")
    if state.issuer_id != "" and state.status_key_epoch != epoch:
        raise ValueError("revocation status state belongs to a different status-key epoch")
    if state.floor < 0 or state.max_observed_sequence < 0 or state.fork_sequence < 0:
        raise ValueError("revocation status state has negative sequence state")
    preceding = list(state.preceding_accepted_cert_ids or [])
    if (
        state.preceding_floor < 0 or state.preceding_floor > MAX_SAFE_INTEGER
        or (state.preceding_floor == 0 and len(preceding) != 0)
        or len(sorted_unique_strings_v2(preceding)) != len(preceding)
    ):
        raise ValueError("revocation status state has invalid preceding checkpoint")
    snap = state.accepted_snapshot
    if state.has_floor and (
        state.floor == 0 or state.floor > MAX_SAFE_INTEGER or snap is None
        or snap.sequence <= 0 or snap.sequence > state.floor
    ):
        raise ValueError("revocation status state has inconsistent accepted floor")
    if not state.has_floor and (state.floor != 0 or snap is not None or len(state.accepted_cert_ids or []) != 0):
        raise ValueError("revocation status state has accepted data without a floor")
    if (
        state.max_observed_sequence > MAX_SAFE_INTEGER or state.fork_sequence > MAX_SAFE_INTEGER
        or not is_int(epoch) or epoch == 0 or epoch > MAX_SAFE_INTEGER
    ):
        raise ValueError("revocation status state has invalid sequence or epoch")
    if state.issuer_id != "" and not valid_v2_id(state.status_key_id):
        raise ValueError("revocation status state has an invalid status-key ID")
    retired = list(state.retired_status_key_ids or [])
    if len(sorted_unique_strings_v2(retired)) != len(retired) or state.status_key_id in retired:
        raise ValueError("revocation status state has invalid retired status-key history")
    for key_id in retired:
        if not valid_v2_id(key_id):
            raise ValueError("revocation status state has an invalid retired status-key ID")


def _initialize(state: RevocationStatusStateV2, issuer_id: str, epoch: int) -> None:
    if state.issuer_id == "":
        state.issuer_id = issuer_id
        state.status_key_epoch = epoch
    state.accepted_cert_ids = sorted_unique_strings_v2(state.accepted_cert_ids)
    state.deny_union_cert_ids = sorted_unique_strings_v2(state.deny_union_cert_ids)


def timestamp_beyond_skew_v2(timestamp: int, now: int, skew: int) -> bool:
    return timestamp > now and timestamp - now > skew


def revocation_list_fresh_v2(lst, policy: RevocationStatusPolicyV2, now: int) -> bool:
    if (
        policy.max_list_lifetime_seconds == 0 or policy.max_status_age_seconds == 0
        or lst.next_update - lst.updated_at > policy.max_list_lifetime_seconds
        or timestamp_beyond_skew_v2(lst.updated_at, now, policy.clock_skew_seconds)
        or now >= lst.next_update
    ):
        # Exclusive deadline: fresh only while now < next_update.
        return False
    # Exclusive age deadline: fresh only while now < updated_at + max_status_age.
    return now < lst.updated_at or now - lst.updated_at < policy.max_status_age_seconds


# ---------------------------------------------------------------------------
# Observation queries


def _required_for_snapshot(observations, epoch: int, sequence: int) -> list:
    values = []
    for o in observations:
        if o.status_key_epoch == epoch and o.sequence <= sequence:
            values.extend(o.revoked_cert_ids)
    return sorted_unique_strings_v2(values)


def _find_observation(observations, epoch, object_type, sequence, digest) -> int:
    for i in range(len(observations) - 1, -1, -1):
        o = observations[i]
        if o.status_key_epoch == epoch and o.object_type == object_type and o.sequence == sequence and bytes(o.evidence_digest) == bytes(digest):
            return i
    return -1


def _has_observation(observations, epoch, object_type, sequence, digest) -> bool:
    return _find_observation(observations, epoch, object_type, sequence, digest) >= 0


def _snapshot_conflicts_with_observed_push(state, epoch, sequence, snapshot_ids) -> bool:
    for o in state.observations:
        if o.status_key_epoch != epoch or o.object_type != REVOCATION_PUSH_CODE or o.sequence != sequence:
            continue
        if state.has_floor and state.floor == sequence - 1:
            if not equal_string_sets_v2(snapshot_ids, list(state.accepted_cert_ids) + list(o.revoked_cert_ids)):
                return True
        elif not contains_all_string_set_v2(snapshot_ids, o.revoked_cert_ids):
            return True
    return False


def _find_set_observation(observations, incoming):
    for i in range(len(observations) - 1, -1, -1):
        o = observations[i]
        if (
            o.status_key_epoch == incoming.status_key_epoch and o.object_type == incoming.object_type
            and o.sequence == incoming.sequence and bytes(o.revoked_set_digest) == bytes(incoming.revoked_set_digest)
        ):
            return o
    return None


def _has_forked_sequence(observations, epoch, object_type, sequence) -> bool:
    for o in observations:
        if o.status_key_epoch == epoch and (object_type == 0 or o.object_type == object_type) and o.sequence == sequence and o.fork:
            return True
    return False


def _has_push_body(observations, epoch, sequence, body_digest) -> bool:
    for o in observations:
        if o.status_key_epoch == epoch and o.object_type == REVOCATION_PUSH_CODE and o.sequence == sequence and bytes(o.body_digest) == bytes(body_digest):
            return True
    return False


def _find_sequence_conflict(observations, incoming) -> bool:
    for o in observations:
        if o.status_key_epoch != incoming.status_key_epoch or o.sequence != incoming.sequence or o.object_type != incoming.object_type:
            continue
        if incoming.object_type == REVOCATION_LIST_CODE and bytes(o.revoked_set_digest) != bytes(incoming.revoked_set_digest):
            return True
        if incoming.object_type == REVOCATION_PUSH_CODE and bytes(o.body_digest) != bytes(incoming.body_digest):
            return True
    return False


def _snapshot_omission_for_push(state, epoch, push):
    conflicting = 0

    def check(sequence, revoked):
        nonlocal conflicting
        if sequence >= push.sequence and not contains_all_string_set_v2(revoked, push.revoked_cert_ids) and sequence > conflicting:
            conflicting = sequence

    if state.accepted_snapshot is not None and state.status_key_epoch == epoch:
        check(state.accepted_snapshot.sequence, _cert_ids(state.accepted_snapshot.revoked))
    if state.reconciliation_required:
        for o in state.observations:
            if (
                o.status_key_epoch == epoch and o.object_type == REVOCATION_LIST_CODE and o.sequence > state.floor
                and o.sequence >= push.sequence and (o.fork or o.gap or o.future_dated)
            ):
                check(o.sequence, o.revoked_cert_ids)
    return conflicting, conflicting != 0


def _mark_fork(state, observation, sequence) -> None:
    observation.fork = True
    state.reconciliation_required = True
    state.fork_sequence = max(0, state.fork_sequence, state.floor, sequence)


def _heartbeat_preferred(incoming, incoming_digest: bytes, accepted) -> bool:
    if incoming.updated_at != accepted.updated_at:
        return incoming.updated_at > accepted.updated_at
    try:
        accepted_digest = _status_evidence_digest(REVOCATION_LIST_CODE, accepted)
    except Exception:  # noqa: BLE001 - Go: err == nil && ...
        return False
    return bytes(incoming_digest) < bytes(accepted_digest)


# ---------------------------------------------------------------------------
# Evidence selection


def sort_status_evidence_v2(evidence) -> list:
    """Go ``sortStatusEvidenceV2``: issuer, status key, sequence, code, digest."""
    if evidence is None:
        return []
    return sorted(evidence, key=lambda e: (e.issuer_id, e.status_key_id, e.sequence, e.object_type, e.digest))


def _append_evidence(evidence, issuer_id, status_key_id, observation) -> list:
    if observation.status_key_id != "":
        status_key_id = observation.status_key_id
    entry = StatusEvidenceEntryV2(
        issuer_id=issuer_id, status_key_id=status_key_id, sequence=observation.sequence,
        object_type=observation.object_type, digest=_sha384_hex(observation.evidence_digest),
    )
    if entry in evidence:
        return evidence
    return evidence + [entry]


def _include_accepted_base(evidence, state, issuer_id, status_key_id) -> list:
    evidence = list(evidence or [])
    if state.accepted_snapshot is None:
        return sort_status_evidence_v2(evidence)
    try:
        digest = _status_evidence_digest(REVOCATION_LIST_CODE, state.accepted_snapshot)
    except Exception:  # noqa: BLE001 - Go: if err == nil
        digest = None
    if digest is not None:
        evidence.append(StatusEvidenceEntryV2(
            issuer_id=issuer_id, status_key_id=status_key_id, sequence=state.accepted_snapshot.sequence,
            object_type=REVOCATION_LIST_CODE, digest=_sha384_hex(digest),
        ))
    return sort_status_evidence_v2(evidence)


def accepted_status_evidence_v2(state, issuer_id, status_key_id) -> list:
    evidence = _include_accepted_base([], state, issuer_id, status_key_id)
    if state.accepted_snapshot is None:
        return evidence
    for o in state.observations:
        if (
            o.status_key_epoch == state.status_key_epoch and o.object_type == REVOCATION_PUSH_CODE and o.accepted
            and o.sequence > state.accepted_snapshot.sequence and o.sequence <= state.floor
        ):
            evidence = _append_evidence(evidence, issuer_id, status_key_id, o)
    return sort_status_evidence_v2(evidence)


def unavailable_status_evidence_v2(state, issuer_id, status_key_id) -> list:
    evidence = accepted_status_evidence_v2(state, issuer_id, status_key_id)
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
# Public reducer API


def _classified(class_: str, fn):
    try:
        return fn()
    except V2Error:
        raise
    except Exception as exc:  # noqa: BLE001 - Go wraps every unclassified error
        raise classify(class_, exc) from exc


def transition_revocation_status_epoch_v2(
    state: RevocationStatusStateV2, issuer_id: str, next_epoch: int, next_status_key: HybridPublicKey
) -> RevocationStatusStateV2:
    """Apply an already-authenticated trust configuration transition. It
    preserves issuer-wide denials and prior authenticated evidence while
    making old accepted state unusable. Failures are status_object_rejected (SPEC-v2 §2.7)."""
    from .security_journal_v2 import validate_accepted_status_state_v2

    def run():
        if not isinstance(issuer_id, str) or issuer_id == "" or not _valid_epoch(next_epoch):
            raise ValueError("status-key epoch transition has invalid issuer or epoch")
        if (
            state.issuer_id != issuer_id or not is_int(state.status_key_epoch) or state.status_key_epoch == 0
            or state.status_key_epoch >= MAX_SAFE_INTEGER or next_epoch != state.status_key_epoch + 1
        ):
            raise ValueError("status-key epoch transition must advance exactly one configured issuer epoch")
        try:
            validate_status_state_binding_v2(state, issuer_id, state.status_key_epoch)
        except Exception as exc:
            raise ValueError(f"cannot transition malformed status state: {exc}") from exc
        try:
            validate_accepted_status_state_v2(state)
        except Exception as exc:
            raise ValueError(f"cannot transition invalid accepted status state: {exc}") from exc
        status_key_id = _key_id_v2(next_status_key)
        if status_key_id == state.status_key_id or status_key_id in (state.retired_status_key_ids or []):
            raise ValueError("status-key epoch transition cannot reuse a current or retired status key")
        nxt = clone_revocation_status_state_v2(state)
        nxt.retired_status_key_ids = sorted_unique_strings_v2(list(nxt.retired_status_key_ids) + [state.status_key_id])
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

    return _classified(V2ErrorClass.STATUS_OBJECT_REJECTED, run)


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def revocation_status_for_cert_v2(
    state: RevocationStatusStateV2, issuer_id: str, cert_id: str, status_key_epoch: int,
    status_key: HybridPublicKey, policy: RevocationStatusPolicyV2, now: int,
) -> RevocationStatusResultV2:
    """Derive a fail-closed answer and its deterministic authenticated
    evidence from one issuer's rollback-protected reducer state. Raises on
    invalid inputs; the caller treats any failure as unavailable."""
    from .security_journal_v2 import validate_accepted_status_state_v2

    validate_revocation_status_policy_v2(policy)
    validate_status_state_binding_v2(state, issuer_id, status_key_epoch)
    validate_accepted_status_state_v2(state)
    if not isinstance(cert_id, str) or cert_id == "" or not _valid_timestamp(now):
        raise ValueError("status query has invalid certificate ID or time")
    status_key_id = _key_id_v2(status_key)
    if state.issuer_id != issuer_id or state.status_key_epoch != status_key_epoch or state.status_key_id != status_key_id:
        raise ValueError("status query does not match the configured issuer status-key binding")
    if state.accepted_snapshot is not None:
        try:
            _wire().verify_revocation_list_v2_signature(state.accepted_snapshot, issuer_id, status_key)
        except Exception as exc:
            raise ValueError(f"accepted status snapshot signature is invalid: {exc}") from exc
    result = RevocationStatusResultV2(evidence=[])
    if cert_id in state.deny_union_cert_ids:
        result.status = "revoked"
        result.evidence = accepted_status_evidence_v2(state, issuer_id, status_key_id)
        result.evidence = _evidence_for(
            state, result.evidence, issuer_id, status_key_id, lambda o: cert_id in o.revoked_cert_ids
        )
        return result
    if (
        not state.has_floor or state.accepted_snapshot is None or policy.max_list_lifetime_seconds == 0
        or policy.max_status_age_seconds == 0 or state.future_dated_object_observed or state.reconciliation_required
        or state.floor < state.max_observed_sequence
        or not contains_all_string_set_v2(state.accepted_cert_ids, state.deny_union_cert_ids)
    ):
        result.status, result.reason = "indeterminate", "unavailable"
        result.evidence = unavailable_status_evidence_v2(state, issuer_id, status_key_id)
        return result
    if not revocation_list_fresh_v2(state.accepted_snapshot, policy, now):
        result.status, result.reason = "indeterminate", "stale"
        result.evidence = accepted_status_evidence_v2(state, issuer_id, status_key_id)
        return result
    result.status = "not_revoked"
    result.evidence = accepted_status_evidence_v2(state, issuer_id, status_key_id)
    result.fresh_until = min(
        state.accepted_snapshot.next_update, state.accepted_snapshot.updated_at + policy.max_status_age_seconds
    )
    return result


def _apply_prologue(policy, now, status_key_epoch):
    validate_revocation_status_policy_v2(policy)
    if not _valid_timestamp(now) or not _valid_epoch(status_key_epoch):
        raise ValueError("revocation status application has invalid time or status-key epoch")


def _finish(result: RevocationStatusStateV2) -> RevocationStatusStateV2:
    from .security_journal_v2 import compact_revocation_status_observations_v2

    if result.issuer_id != "":
        result = compact_revocation_status_observations_v2(result)
    return result


def apply_revocation_list_v2(
    state: RevocationStatusStateV2, lst, bound_issuer_id: str, status_key_epoch: int,
    status_key: HybridPublicKey, policy: RevocationStatusPolicyV2, now: int,
) -> RevocationStatusStateV2:
    """Verify the caller-authenticated status-key binding and apply one full
    snapshot. Rejections are status_object_rejected unless already classified
    (for example invalid_signature)."""
    return _finish(_classified(
        V2ErrorClass.STATUS_OBJECT_REJECTED,
        lambda: _apply_list(state, lst, bound_issuer_id, status_key_epoch, status_key, policy, now),
    ))


def _apply_list(state, lst, bound_issuer_id, status_key_epoch, status_key, policy, now):
    w = _wire()
    _apply_prologue(policy, now, status_key_epoch)
    w.verify_revocation_list_v2_signature(lst, bound_issuer_id, status_key)
    validate_status_state_binding_v2(state, bound_issuer_id, status_key_epoch)
    digest = _status_evidence_digest(REVOCATION_LIST_CODE, lst)
    body_digest = sha384(w.revocation_list_signable_bytes_v2(lst)).digest()
    set_digest = revoked_set_digest_v2(lst.revoked)

    nxt = clone_revocation_status_state_v2(state)
    _initialize(nxt, bound_issuer_id, status_key_epoch)
    status_key_id = _key_id_v2(status_key)
    if nxt.status_key_id != "" and nxt.status_key_id != status_key_id:
        raise ValueError("revocation list status key does not match configured epoch binding")
    nxt.status_key_id = status_key_id
    duplicate_index = _find_observation(nxt.observations, status_key_epoch, REVOCATION_LIST_CODE, lst.sequence, digest)
    duplicate = duplicate_index >= 0

    future = timestamp_beyond_skew_v2(lst.updated_at, now, policy.clock_skew_seconds)
    obs = RevocationObservationV2(
        object_type=REVOCATION_LIST_CODE, status_key_epoch=status_key_epoch, status_key_id=status_key_id,
        sequence=lst.sequence, evidence_digest=bytes(digest), body_digest=bytes(body_digest),
        revoked_set_digest=set_digest, revoked_cert_ids=_cert_ids(lst.revoked), future_dated=future,
    )
    fresh_now = revocation_list_fresh_v2(lst, policy, now)
    if not duplicate:
        prior = _find_set_observation(nxt.observations, obs)
        if prior is not None:
            if prior.fork:
                return nxt
            if (prior.future_dated or prior.gap) and not future and fresh_now:
                if (nxt.has_floor and lst.sequence < nxt.floor) or _has_forked_sequence(nxt.observations, status_key_epoch, 0, lst.sequence):
                    return nxt
                # A future-dated or stale/gapped snapshot may be re-evaluated once fresh.
            elif (
                not prior.accepted and not prior.fork and nxt.has_floor and lst.sequence == nxt.floor
                and nxt.accepted_snapshot is not None and nxt.accepted_snapshot.sequence < nxt.floor
                and not future and fresh_now
            ):
                pass  # A fresh same-set snapshot at a push-advanced floor becomes the new base.
            elif prior.accepted and nxt.has_floor and lst.sequence == nxt.floor and _heartbeat_preferred(lst, digest, nxt.accepted_snapshot):
                pass  # A newer same-set current-floor heartbeat may refresh freshness.
            else:
                return nxt
    if duplicate:
        prior = nxt.observations[duplicate_index]
        if prior.accepted or (not prior.future_dated and not prior.gap) or future or not fresh_now:
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

    if _find_sequence_conflict(nxt.observations, obs):
        _mark_fork(nxt, obs, lst.sequence)
    elif nxt.has_floor and lst.sequence == nxt.floor and not equal_string_sets_v2(obs.revoked_cert_ids, nxt.accepted_cert_ids):
        _mark_fork(nxt, obs, lst.sequence)
    elif nxt.has_floor and lst.sequence < nxt.floor and _contains_novel(obs.revoked_cert_ids, nxt.accepted_cert_ids):
        _mark_fork(nxt, obs, lst.sequence)
    applicable = _required_for_snapshot(nxt.observations, status_key_epoch, lst.sequence)
    if not contains_all_string_set_v2(obs.revoked_cert_ids, applicable):
        _mark_fork(nxt, obs, lst.sequence)
    if _snapshot_conflicts_with_observed_push(nxt, status_key_epoch, lst.sequence, obs.revoked_cert_ids):
        _mark_fork(nxt, obs, lst.sequence)

    def record():
        if not duplicate:
            nxt.observations.append(obs)
        return nxt

    if not fresh_now:
        if nxt.has_floor and lst.sequence <= nxt.floor:
            return record()
        nxt.reconciliation_required = True
        obs.gap = True
        return record()
    if obs.fork:
        return record()
    if not nxt.has_floor and not contains_all_string_set_v2(obs.revoked_cert_ids, nxt.deny_union_cert_ids):
        nxt.reconciliation_required = True
        obs.gap = True
        return record()
    if not nxt.has_floor and lst.sequence < nxt.max_observed_sequence:
        nxt.reconciliation_required = True
        obs.gap = True
        return record()
    if nxt.has_floor and lst.sequence < nxt.floor:
        return record()

    if nxt.has_floor and lst.sequence == nxt.floor:
        if not equal_string_sets_v2(obs.revoked_cert_ids, nxt.accepted_cert_ids):
            _mark_fork(nxt, obs, lst.sequence)
            return record()
        if (
            nxt.accepted_snapshot is None or nxt.accepted_snapshot.sequence < lst.sequence
            or _heartbeat_preferred(lst, digest, nxt.accepted_snapshot)
        ):
            nxt.accepted_snapshot = clone_revocation_list_v2(lst)
        obs.accepted = True
    else:
        copy_list = clone_revocation_list_v2(lst)
        if nxt.has_floor and lst.sequence == nxt.floor + 1:
            nxt.has_preceding_checkpoint = True
            nxt.preceding_floor = nxt.floor
            nxt.preceding_accepted_cert_ids = sorted_unique_strings_v2(nxt.accepted_cert_ids)
        else:
            nxt.has_preceding_checkpoint = False
            nxt.preceding_floor = 0
            nxt.preceding_accepted_cert_ids = []
        nxt.accepted_snapshot = copy_list
        nxt.accepted_cert_ids = sorted_unique_strings_v2(obs.revoked_cert_ids)
        nxt.has_floor = True
        nxt.floor = lst.sequence
        obs.accepted = True

    if nxt.reconciliation_required:
        recoverable_fork = nxt.fork_sequence == 0 or (lst.sequence > nxt.fork_sequence and lst.sequence >= nxt.max_observed_sequence)
        fully_observed = contains_all_string_set_v2(obs.revoked_cert_ids, nxt.deny_union_cert_ids)
        if recoverable_fork and fully_observed and lst.sequence >= nxt.max_observed_sequence:
            nxt.reconciliation_required = False
            nxt.future_dated_object_observed = False
            nxt.fork_sequence = 0
    elif lst.sequence >= nxt.max_observed_sequence and contains_all_string_set_v2(obs.revoked_cert_ids, nxt.deny_union_cert_ids):
        nxt.reconciliation_required = False
    if not duplicate or (obs.accepted and not nxt.observations[duplicate_index].accepted):
        nxt.observations.append(obs)
    return nxt


def apply_revocation_push_v2(
    state: RevocationStatusStateV2, push, bound_issuer_id: str, status_key_epoch: int,
    status_key: HybridPublicKey, policy: RevocationStatusPolicyV2, now: int,
) -> RevocationStatusStateV2:
    """Verify the caller-authenticated status-key binding and apply one signed
    push. Noncontiguous or future pushes contribute to deny_union but make
    current status unavailable until a full snapshot repairs the gap."""
    return _finish(_classified(
        V2ErrorClass.STATUS_OBJECT_REJECTED,
        lambda: _apply_push(state, push, bound_issuer_id, status_key_epoch, status_key, policy, now),
    ))


def _apply_push(state, push, bound_issuer_id, status_key_epoch, status_key, policy, now):
    w = _wire()
    _apply_prologue(policy, now, status_key_epoch)
    w.verify_revocation_push_v2_signature(push, bound_issuer_id, status_key)
    validate_status_state_binding_v2(state, bound_issuer_id, status_key_epoch)
    digest = _status_evidence_digest(REVOCATION_PUSH_CODE, push)
    body_digest = sha384(w.revocation_push_signable_bytes_v2(push)).digest()
    set_digest = revoked_set_digest_v2(push.revoked)

    nxt = clone_revocation_status_state_v2(state)
    _initialize(nxt, bound_issuer_id, status_key_epoch)
    status_key_id = _key_id_v2(status_key)
    if nxt.status_key_id != "" and nxt.status_key_id != status_key_id:
        raise ValueError("revocation push status key does not match configured epoch binding")
    nxt.status_key_id = status_key_id
    if _has_observation(nxt.observations, status_key_epoch, REVOCATION_PUSH_CODE, push.sequence, digest) or \
            _has_push_body(nxt.observations, status_key_epoch, push.sequence, body_digest):
        return nxt

    future = timestamp_beyond_skew_v2(push.pushed_at, now, policy.clock_skew_seconds)
    obs = RevocationObservationV2(
        object_type=REVOCATION_PUSH_CODE, status_key_epoch=status_key_epoch, status_key_id=status_key_id,
        sequence=push.sequence, evidence_digest=bytes(digest), body_digest=bytes(body_digest),
        revoked_set_digest=set_digest, revoked_cert_ids=_cert_ids(push.revoked), future_dated=future,
    )
    _add_revocations(nxt, obs.revoked_cert_ids)
    if push.sequence > nxt.max_observed_sequence:
        nxt.max_observed_sequence = push.sequence
    if future:
        nxt.future_dated_object_observed = True
        nxt.reconciliation_required = True
    if _find_sequence_conflict(nxt.observations, obs):
        _mark_fork(nxt, obs, push.sequence)
    conflicting, conflict = _snapshot_omission_for_push(nxt, status_key_epoch, obs)
    if conflict:
        _mark_fork(nxt, obs, conflicting)

    expected = nxt.floor + 1 if nxt.has_floor else 1
    if nxt.has_floor and push.sequence <= nxt.floor:
        if push.sequence == nxt.floor:
            if (
                nxt.has_preceding_checkpoint and nxt.preceding_floor == push.sequence - 1
                and not equal_string_sets_v2(nxt.accepted_cert_ids, list(nxt.preceding_accepted_cert_ids) + list(obs.revoked_cert_ids))
            ):
                _mark_fork(nxt, obs, push.sequence)
            elif _contains_novel(obs.revoked_cert_ids, nxt.accepted_cert_ids):
                _mark_fork(nxt, obs, push.sequence)
            elif not obs.fork and contains_all_string_set_v2(nxt.accepted_cert_ids, obs.revoked_cert_ids):
                pass  # The accepted full set already proves these entries.
            else:
                obs.gap = True
                nxt.reconciliation_required = True
            nxt.observations.append(obs)
            return nxt
        if _contains_novel(obs.revoked_cert_ids, nxt.accepted_cert_ids):
            _mark_fork(nxt, obs, push.sequence)
        nxt.observations.append(obs)
        return nxt
    if not nxt.has_floor or push.sequence != expected or nxt.reconciliation_required or future:
        obs.gap = not obs.fork
        nxt.reconciliation_required = True
        nxt.observations.append(obs)
        return nxt

    nxt.accepted_cert_ids = sorted_unique_strings_v2(list(nxt.accepted_cert_ids) + list(obs.revoked_cert_ids))
    nxt.has_preceding_checkpoint = False
    nxt.preceding_floor = 0
    nxt.preceding_accepted_cert_ids = []
    nxt.has_floor = True
    nxt.floor = push.sequence
    obs.accepted = True
    nxt.observations.append(obs)
    return nxt


# Go-mirrored names of helpers other modules use.
revoked_cert_ids_v2 = _cert_ids
initialize_revocation_status_state_v2 = _initialize
