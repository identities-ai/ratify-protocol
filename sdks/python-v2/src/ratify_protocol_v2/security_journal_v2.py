"""Protocol v2 security journal (Go security_journal_v2.go, SPEC-v2 §6.6).

The journal holds the state whose loss or rollback can make verification
unsafe: per-issuer revocation status, permanent key-role history, and every
authenticated status-key epoch. It is a logical record; durability and
anti-rollback guarantees come from a :class:`SecurityJournalStoreV2` whose
head is anchored independently and advanced by compare-and-swap.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, replace
from hashlib import sha384
from typing import Callable, Optional, Protocol

from . import status_state_v2 as ss
from .context_v2 import Context, require_context
from .errors_v2 import V2Error, V2ErrorClass, classify, classified, V2ValueError
from .status_state_v2 import (
    REVOCATION_LIST_CODE,
    REVOCATION_PUSH_CODE,
    RevocationObservationV2,
    RevocationStatusPolicyV2,
    RevocationStatusResultV2,
    RevocationStatusStateV2,
    contains_all_string_set_v2,
    equal_string_sets_v2,
    sorted_unique_strings_v2,
)
from .types import HybridPublicKey
from .types_v2 import MAX_SAFE_INTEGER, is_int, valid_v2_id

# The current record version: canonical snapshot digest. Version 1 records use
# the legacy Go encoding/json digest and must be migrated before use.
SECURITY_JOURNAL_VERSION_V2 = 2
SECURITY_JOURNAL_LEGACY_VERSION = 1


@dataclass(frozen=True)
class SecurityJournalHeadV2:
    """The independently anchored head of a deployment's security journal."""

    generation: int = 0
    digest: str = ""


@dataclass(frozen=True)
class KeyRoleBindingV2:
    """Permanently assigns a key ID and both hybrid key components to one role."""

    key_id: str = ""
    ed25519_digest: str = ""
    ml_dsa_65_digest: str = ""
    role: str = ""


@dataclass(frozen=True)
class StatusKeyBindingV2:
    """One authenticated status-key epoch of one issuer, retained forever."""

    issuer_id: str = ""
    epoch: int = 0
    status_key_id: str = ""
    ed25519_digest: str = ""
    ml_dsa_65_digest: str = ""


@dataclass
class SecurityJournalV2:
    version: int = 0
    generation: int = 0
    previous_digest: str = ""
    digest: str = ""
    status_by_issuer: Optional[dict] = None
    key_role_history: Optional[list] = None
    status_key_history: Optional[list] = None


class SecurityJournalStoreV2(Protocol):
    """An atomic compare-and-swap store backed by an independent,
    rollback-resistant head. ``load`` returns ``(journal, head)`` and must
    return the record matching that head or raise. ``compare_and_swap`` must
    atomically advance both the durable record and its head, and raise
    :class:`SecurityJournalConflictV2` for a stale writer."""

    def load(self, ctx: Context) -> tuple: ...

    def compare_and_swap(self, ctx: Context, expected: SecurityJournalHeadV2, next_journal: SecurityJournalV2) -> None: ...


class SecurityJournalConflictV2(Exception):
    """Go ``ErrSecurityJournalConflictV2``: another writer advanced the
    anchored journal. Reload and re-evaluate; never blindly retry."""

    def __init__(self, message: str = "security journal compare-and-swap conflict"):
        super().__init__(message)


ErrSecurityJournalConflictV2 = SecurityJournalConflictV2


def _snap():
    from . import security_journal_snapshot_v2

    return security_journal_snapshot_v2


def _wrap_v2(message: str, exc: BaseException) -> ValueError:
    """Go ``fmt.Errorf("...: %w", err)``: a new message that keeps the class
    the wrapped error carries."""
    if isinstance(exc, V2Error) and exc.error_class != V2ErrorClass.UNCLASSIFIED:
        return V2ValueError(exc.error_class, message)
    return ValueError(message)


def empty_security_journal_v2() -> SecurityJournalV2:
    """The only valid genesis record."""
    journal = SecurityJournalV2(
        version=SECURITY_JOURNAL_VERSION_V2, status_by_issuer={}, key_role_history=[], status_key_history=[],
    )
    journal.digest = security_journal_digest_v2(journal)
    return journal


def security_journal_digest_v2(journal: SecurityJournalV2) -> str:
    return _snap().security_journal_digest_v2(journal)


def clone_security_journal_v2(journal: SecurityJournalV2) -> SecurityJournalV2:
    """A deep copy (Go clones through encoding/json)."""
    return copy.deepcopy(journal)


# ---------------------------------------------------------------------------
# Store transitions


def update_security_journal_v2(ctx: Context, store, update: Callable[[SecurityJournalV2], None]) -> SecurityJournalV2:
    if store is None or update is None:
        raise ValueError("security journal store and update are required")
    current = load_anchored_security_journal_v2(ctx, store)
    nxt = clone_security_journal_v2(current)
    update(nxt)
    return commit_security_journal_transition_v2(ctx, store, current, nxt)


def commit_security_journal_transition_v2(ctx: Context, store, current: SecurityJournalV2, nxt: SecurityJournalV2) -> SecurityJournalV2:
    """Compact and canonicalize ``nxt``; return ``current`` unchanged for a
    canonical no-op; otherwise chain, validate, and commit by compare-and-swap
    against ``current``'s head. A conflict is raised, never retried."""
    snap = _snap()
    prune_security_journal_observations_v2(nxt)
    snap.canonicalize_security_journal_v2(nxt)
    if snap.same_security_journal_content_v2(nxt, current):
        return current
    nxt.generation = current.generation + 1
    if nxt.generation == 0 or nxt.generation > MAX_SAFE_INTEGER:
        raise ValueError("security journal generation exhausted")
    nxt.version = SECURITY_JOURNAL_VERSION_V2
    nxt.previous_digest = current.digest
    nxt.digest = ""
    nxt.digest = security_journal_digest_v2(nxt)
    try:
        validate_security_journal_transition_v2(current, nxt)
    except Exception as exc:
        raise _wrap_v2(f"invalid security journal transition: {exc}", exc) from exc
    head = SecurityJournalHeadV2(generation=current.generation, digest=current.digest)
    try:
        store.compare_and_swap(ctx, head, nxt)
    except SecurityJournalConflictV2:
        raise
    except Exception as exc:
        raise RuntimeError(f"commit rollback-protected security journal: {exc}") from exc
    return nxt


def load_anchored_security_journal_v2(ctx: Context, store) -> SecurityJournalV2:
    """Load a version 2 record and require it to match the anchored head."""
    try:
        current, head = store.load(ctx)
    except Exception as exc:
        raise RuntimeError(f"load rollback-protected security journal: {exc}") from exc
    if not isinstance(current, SecurityJournalV2) or not isinstance(head, SecurityJournalHeadV2):
        raise ValueError("security journal store returned an invalid record or head")
    if head.generation != current.generation or head.digest == "" or head.digest != current.digest:
        raise ValueError("loaded security journal is not anchored by the store head")
    if current.version != SECURITY_JOURNAL_VERSION_V2:
        raise ValueError(f"security journal version {current.version} requires migration")
    try:
        validate_security_journal_v2(current)
    except Exception as exc:
        raise _wrap_v2(f"validate loaded security journal: {exc}", exc) from exc
    return current


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def record_security_key_role_v2(ctx: Context, store, role: str, pub: HybridPublicKey) -> SecurityJournalV2:
    """Durably add a non-status key role after the caller has authenticated
    the trust-configuration event that admits the key."""
    require_context(ctx)
    if role == "status":
        raise ValueError("status keys must be recorded with their issuer and epoch")
    return update_security_journal_v2(ctx, store, lambda journal: register_key_role_v2(journal, role, pub))


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def configure_status_key_epoch_v2(ctx: Context, store, issuer_id: str, epoch: int, pub: HybridPublicKey) -> SecurityJournalV2:
    """Persist an authenticated status-key binding. A first binding starts at
    epoch 1; later bindings advance exactly one epoch and preserve prior-epoch
    denials and authenticated evidence."""
    require_context(ctx)

    def update(journal: SecurityJournalV2) -> None:
        register_status_key_epoch_v2(journal, issuer_id, epoch, pub)
        prior = journal.status_by_issuer.get(issuer_id)
        if prior is not None:
            if epoch == prior.status_key_epoch:
                require_journal_status_key_v2(journal, issuer_id, epoch, pub)
                return
            journal.status_by_issuer[issuer_id] = ss.transition_revocation_status_epoch_v2(prior, issuer_id, epoch, pub)
            return
        if epoch != 1:
            raise ValueError("first status-key epoch must be 1")
        key_id = ss._key_id_v2(pub)
        journal.status_by_issuer[issuer_id] = RevocationStatusStateV2(
            issuer_id=issuer_id, status_key_epoch=epoch, status_key_id=key_id,
            accepted_cert_ids=[], deny_union_cert_ids=[], observations=[],
        )

    return update_security_journal_v2(ctx, store, update)


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def apply_revocation_list_to_journal_v2(
    ctx: Context, store, lst, issuer_id: str, epoch: int, pub: HybridPublicKey,
    policy: RevocationStatusPolicyV2, now: int,
) -> SecurityJournalV2:
    """Authenticate, reduce, and atomically persist a full status snapshot."""
    require_context(ctx)

    def update(journal: SecurityJournalV2) -> None:
        require_journal_status_key_v2(journal, issuer_id, epoch, pub)
        journal.status_by_issuer[issuer_id] = ss.apply_revocation_list_v2(
            journal.status_by_issuer[issuer_id], lst, issuer_id, epoch, pub, policy, now)

    return update_security_journal_v2(ctx, store, update)


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def apply_revocation_push_to_journal_v2(
    ctx: Context, store, push, issuer_id: str, epoch: int, pub: HybridPublicKey,
    policy: RevocationStatusPolicyV2, now: int,
) -> SecurityJournalV2:
    """Authenticate, reduce, and atomically persist one push."""
    require_context(ctx)

    def update(journal: SecurityJournalV2) -> None:
        require_journal_status_key_v2(journal, issuer_id, epoch, pub)
        journal.status_by_issuer[issuer_id] = ss.apply_revocation_push_v2(
            journal.status_by_issuer[issuer_id], push, issuer_id, epoch, pub, policy, now)

    return update_security_journal_v2(ctx, store, update)


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def revocation_status_from_journal_v2(
    ctx: Context, store, issuer_id: str, cert_id: str, epoch: int, pub: HybridPublicKey,
    policy: RevocationStatusPolicyV2, now: int,
) -> RevocationStatusResultV2:
    """Read an anchored state and return a fail-closed status for one
    issuer-scoped certificate reference. Raises on any failure, where Go
    returns indeterminate/unavailable together with the error; callers treat
    a raised error as unavailable."""
    if store is None:
        raise ValueError("security journal store is required")
    journal = load_anchored_security_journal_v2(ctx, store)
    require_journal_status_key_v2(journal, issuer_id, epoch, pub)
    return ss.revocation_status_for_cert_v2(journal.status_by_issuer[issuer_id], issuer_id, cert_id, epoch, pub, policy, now)


def require_journal_status_key_v2(journal: Optional[SecurityJournalV2], issuer_id: str, epoch: int, pub: HybridPublicKey) -> None:
    if journal is None or not isinstance(issuer_id, str) or issuer_id == "" or not is_int(epoch) or epoch == 0:
        raise ValueError("issuer and status-key epoch are required")
    binding = status_binding_at_epoch_v2(journal.status_key_history, issuer_id, epoch)
    if binding is None:
        raise ValueError("issuer status key is not present in the retained trust history")
    actual = status_key_binding_v2(issuer_id, epoch, pub)
    if binding != actual:
        raise ValueError("status key does not match the retained issuer and epoch binding")
    state = journal.status_by_issuer.get(issuer_id)
    if state is None or state.status_key_epoch != epoch or state.status_key_id != binding.status_key_id:
        raise ValueError("status key is not the current issuer epoch")


# ---------------------------------------------------------------------------
# Validation


@classified(V2ErrorClass.MALFORMED)
def validate_security_journal_v2(journal: SecurityJournalV2) -> None:
    """Validate record integrity and internal indexes."""
    if (
        not isinstance(journal, SecurityJournalV2)
        or journal.version not in (SECURITY_JOURNAL_VERSION_V2, SECURITY_JOURNAL_LEGACY_VERSION)
        or not is_int(journal.version) or not is_int(journal.generation)
        or journal.status_by_issuer is None or journal.key_role_history is None or journal.status_key_history is None
    ):
        raise ValueError("security journal has unsupported or incomplete shape")
    if journal.generation < 0 or journal.generation > 2**64 - 1:
        raise ValueError("security journal generation is out of range")
    if journal.generation == 0 and journal.previous_digest != "":
        raise ValueError("security journal genesis has a predecessor")
    if journal.generation == 0 and (journal.status_by_issuer or journal.key_role_history or journal.status_key_history):
        raise ValueError("security journal genesis must be empty")
    if journal.generation > 0 and (journal.previous_digest == "" or len(journal.previous_digest) != 96):
        raise ValueError("security journal record is missing its predecessor digest")
    if journal.digest != security_journal_digest_v2(journal):
        raise ValueError("security journal digest mismatch")
    for issuer_id, state in journal.status_by_issuer.items():
        if issuer_id == "" or not isinstance(state, RevocationStatusStateV2) or state.issuer_id != issuer_id or state.status_key_epoch == 0:
            raise ValueError("security journal contains a misbound issuer status state")
        try:
            ss.validate_status_state_binding_v2(state, issuer_id, state.status_key_epoch)
        except Exception as exc:
            raise ValueError(f"invalid status state for issuer {issuer_id!r}: {exc}") from exc
        try:
            validate_accepted_status_state_v2(state)
        except Exception as exc:
            raise ValueError(f"invalid accepted status state for issuer {issuer_id!r}: {exc}") from exc
        binding = status_binding_at_epoch_v2(journal.status_key_history, issuer_id, state.status_key_epoch)
        if binding is None or binding.status_key_id != state.status_key_id:
            raise ValueError("current status state has no matching retained key binding")
        max_observed = 0
        retired = [b.status_key_id for b in journal.status_key_history if b.issuer_id == issuer_id and b.epoch < state.status_key_epoch]
        for o in state.observations or []:
            ob = status_binding_at_epoch_v2(journal.status_key_history, issuer_id, o.status_key_epoch)
            if (
                ob is None or o.status_key_id != ob.status_key_id or o.sequence <= 0 or o.sequence > MAX_SAFE_INTEGER
                or len(o.evidence_digest) != 48 or len(o.body_digest) != 48
                or o.object_type not in (REVOCATION_LIST_CODE, REVOCATION_PUSH_CODE)
            ):
                raise ValueError("security journal contains malformed or misbound status evidence")
            if o.status_key_epoch == state.status_key_epoch and o.sequence > max_observed:
                max_observed = o.sequence
        if state.max_observed_sequence != max_observed or not equal_string_sets_v2(state.retired_status_key_ids, retired):
            raise ValueError("status state does not match retained sequence and key history")
    validate_key_role_history_v2(journal.key_role_history)
    validate_status_key_history_v2(journal.status_key_history, journal.key_role_history)
    latest: dict = {}
    for b in journal.status_key_history:
        if b.epoch > latest.get(b.issuer_id, 0):
            latest[b.issuer_id] = b.epoch
    for issuer_id, epoch in latest.items():
        state = journal.status_by_issuer.get(issuer_id)
        if state is None or state.status_key_epoch != epoch:
            raise ValueError("security journal status state is not at the latest retained issuer epoch")


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def validate_security_journal_transition_v2(current: SecurityJournalV2, nxt: SecurityJournalV2) -> None:
    """Generation continuity and append-only key histories."""
    try:
        validate_security_journal_v2(current)
    except Exception as exc:
        raise _wrap_v2(f"invalid current journal: {exc}", exc) from exc
    try:
        validate_security_journal_v2(nxt)
    except Exception as exc:
        raise _wrap_v2(f"invalid next journal: {exc}", exc) from exc
    if nxt.generation != current.generation + 1 or nxt.previous_digest != current.digest:
        raise ValueError("journal generation or predecessor is not contiguous")
    if nxt.version != SECURITY_JOURNAL_VERSION_V2:
        raise ValueError(f"journal transitions must produce a version {SECURITY_JOURNAL_VERSION_V2} record")
    if current.version == SECURITY_JOURNAL_LEGACY_VERSION and not _snap().same_security_journal_content_v2(current, nxt):
        raise ValueError("journal migration must not change logical content")
    if not all(b in nxt.key_role_history for b in current.key_role_history) or \
            not all(b in nxt.status_key_history for b in current.status_key_history):
        raise ValueError("journal key binding history was removed or rewritten")
    for issuer_id, state in current.status_by_issuer.items():
        nstate = nxt.status_by_issuer.get(issuer_id)
        if nstate is None or not contains_all_string_set_v2(nstate.deny_union_cert_ids, state.deny_union_cert_ids):
            raise ValueError("journal transition removed issuer status or a retained revocation")
        nkeys = {security_observation_key_v2(o) for o in nstate.observations}
        nsem = {}
        for o in nstate.observations:
            nsem[security_observation_semantic_key_v2(o)] = o
        for old in state.observations:
            if security_observation_key_v2(old) in nkeys:
                continue
            if not must_retain_status_observation_v2(nstate, old):
                continue
            compacted = nsem.get(security_observation_semantic_key_v2(old))
            if (
                compacted is None or not contains_all_string_set_v2(compacted.revoked_cert_ids, old.revoked_cert_ids)
                or (old.fork and not compacted.fork)
                or (old.gap and nstate.reconciliation_required and not compacted.gap)
                or (old.future_dated and nstate.future_dated_object_observed and not compacted.future_dated)
            ):
                raise ValueError("journal transition removed authenticated status evidence")
        if nstate.status_key_epoch < state.status_key_epoch:
            raise ValueError("journal transition rolled back a status-key epoch")
        if nstate.status_key_epoch > state.status_key_epoch:
            if (
                nstate.status_key_id == state.status_key_id or nstate.status_key_id in state.retired_status_key_ids
                or not equal_string_sets_v2(nstate.retired_status_key_ids, list(state.retired_status_key_ids) + [state.status_key_id])
                or nstate.has_floor or nstate.floor != 0 or nstate.accepted_snapshot is not None or nstate.accepted_cert_ids
                or nstate.has_preceding_checkpoint or nstate.preceding_floor != 0 or nstate.preceding_accepted_cert_ids
                or nstate.max_observed_sequence != 0 or nstate.fork_sequence != 0 or nstate.reconciliation_required
                or nstate.future_dated_object_observed
            ):
                raise ValueError("status-key epoch transition did not perform the required fail-closed reset")
            for o in nstate.observations:
                if o.status_key_epoch >= nstate.status_key_epoch:
                    raise ValueError("status-key epoch transition contains evidence from the new epoch before bootstrap")
        if nstate.status_key_epoch == state.status_key_epoch and state.has_floor and (not nstate.has_floor or nstate.floor < state.floor):
            raise ValueError("journal transition rolled back the accepted status floor")
        if nstate.status_key_epoch == state.status_key_epoch and nstate.max_observed_sequence < state.max_observed_sequence:
            raise ValueError("journal transition rolled back the observed status sequence")
        if nstate.status_key_epoch == state.status_key_epoch and state.reconciliation_required and not nstate.reconciliation_required:
            if not has_accepted_snapshot_after_v2(nstate, state.status_key_epoch, state.max_observed_sequence, state.fork_sequence, state.deny_union_cert_ids) or \
                    not contains_all_string_set_v2(nstate.accepted_cert_ids, state.deny_union_cert_ids):
                raise ValueError("journal transition cleared reconciliation without a caught-up full snapshot")
    for issuer_id, nstate in nxt.status_by_issuer.items():
        if issuer_id not in current.status_by_issuer:
            if status_binding_at_epoch_v2(nxt.status_key_history, issuer_id, nstate.status_key_epoch) is None:
                raise ValueError("new issuer status state lacks authenticated key history")


def validate_accepted_status_state_v2(state: RevocationStatusStateV2) -> None:
    deny = list(state.deny_union_cert_ids or [])
    accepted_ids = list(state.accepted_cert_ids or [])
    if len(sorted_unique_strings_v2(deny)) != len(deny) or len(sorted_unique_strings_v2(accepted_ids)) != len(accepted_ids):
        raise ValueError("revocation status sets are not canonical")
    observed = []
    fork_recorded = False
    for o in state.observations or []:
        if (
            not isinstance(o, RevocationObservationV2) or not is_int(o.sequence) or not is_int(o.status_key_epoch)
            or o.sequence <= 0 or o.sequence > MAX_SAFE_INTEGER or not valid_v2_id(o.status_key_id)
            or o.object_type not in (REVOCATION_LIST_CODE, REVOCATION_PUSH_CODE)
            or len(o.evidence_digest) != 48 or len(o.body_digest) != 48 or len(o.revoked_set_digest) != 48
            or len(sorted_unique_strings_v2(o.revoked_cert_ids)) != len(o.revoked_cert_ids)
        ):
            raise ValueError("security journal contains a malformed status observation")
        for cert_id in o.revoked_cert_ids:
            if not isinstance(cert_id, str) or cert_id == "" or not _valid_utf8(cert_id):
                raise ValueError("status observation contains an invalid certificate ID")
        fork_recorded = fork_recorded or (o.status_key_epoch == state.status_key_epoch and o.fork)
        observed.extend(o.revoked_cert_ids)
        if o.status_key_epoch == state.status_key_epoch and o.sequence > state.max_observed_sequence:
            raise ValueError("observed sequence exceeds its high-water mark")
        if not contains_all_string_set_v2(deny, o.revoked_cert_ids):
            raise ValueError("deny union omits a revocation from authenticated evidence")
    if not contains_all_string_set_v2(observed, deny):
        raise ValueError("deny union contains a revocation without a retained authenticated witness")
    if state.fork_sequence > 0 and (not state.reconciliation_required or not fork_recorded):
        raise ValueError("unresolved fork state lacks its retained fork marker")
    if state.has_floor and state.floor > state.max_observed_sequence:
        raise ValueError("accepted floor exceeds the observed sequence high-water mark")
    if not state.has_floor:
        return
    snap = state.accepted_snapshot
    if snap.issuer_id != state.issuer_id or snap.sequence > state.floor:
        raise ValueError("accepted snapshot does not match issuer or floor")
    digest = ss._status_evidence_digest(REVOCATION_LIST_CODE, snap)
    if not has_accepted_status_observation_v2(state.observations, state.status_key_epoch, REVOCATION_LIST_CODE, snap.sequence, digest):
        raise ValueError("accepted snapshot has no matching authenticated observation")
    accepted = ss._cert_ids(snap.revoked)
    pushes = []
    for o in state.observations:
        if (
            o.status_key_epoch == state.status_key_epoch and o.object_type == REVOCATION_PUSH_CODE and o.accepted
            and o.sequence > snap.sequence and o.sequence <= state.floor
        ):
            pushes.append(o)
            accepted.extend(o.revoked_cert_ids)
    pushes.sort(key=lambda o: o.sequence)
    expected = snap.sequence
    for push in pushes:
        if expected >= MAX_SAFE_INTEGER or push.sequence != expected + 1:
            raise ValueError("accepted push observations are not contiguous after the accepted snapshot")
        expected = push.sequence
    if expected != state.floor:
        raise ValueError("accepted push history does not reach the recorded floor")
    if not equal_string_sets_v2(accepted, accepted_ids):
        raise ValueError("accepted certificate set does not follow the accepted snapshot and pushes")


def _valid_utf8(value: str) -> bool:
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


# ---------------------------------------------------------------------------
# Compaction


def compact_revocation_status_observations_v2(state: RevocationStatusStateV2) -> RevocationStatusStateV2:
    journal = SecurityJournalV2(status_by_issuer={state.issuer_id: state})
    prune_security_journal_observations_v2(journal)
    return journal.status_by_issuer[state.issuer_id]


def _compaction_key(o: RevocationObservationV2):
    return (o.status_key_epoch, o.sequence, o.object_type, bytes(o.revoked_set_digest), bytes(o.body_digest))


def prune_security_journal_observations_v2(journal: SecurityJournalV2) -> None:
    for issuer_id in list(journal.status_by_issuer):
        state = replace(journal.status_by_issuer[issuer_id])
        base_digest = b""
        if state.accepted_snapshot is not None:
            try:
                base_digest = ss._status_evidence_digest(REVOCATION_LIST_CODE, state.accepted_snapshot)
            except Exception:  # noqa: BLE001 - Go ignores the error here
                base_digest = b""
        observations = sorted((replace(o, revoked_cert_ids=list(o.revoked_cert_ids)) for o in state.observations), key=_compaction_key)
        retained: list = []
        witnessed: set = set()
        semantic_seen: dict = {}
        for o in observations:
            accepted_base = (
                len(base_digest) != 0 and o.status_key_epoch == state.status_key_epoch
                and o.object_type == REVOCATION_LIST_CODE and o.sequence == state.accepted_snapshot.sequence
                and bytes(o.evidence_digest) == bytes(base_digest)
            )
            full_record = accepted_base or must_retain_status_observation_v2(state, o)
            new_witnesses = []
            for cert_id in o.revoked_cert_ids:
                if cert_id not in witnessed:
                    witnessed.add(cert_id)
                    new_witnesses.append(cert_id)
            if not full_record:
                o.revoked_cert_ids = new_witnesses
            key = security_observation_semantic_key_v2(o)
            if key in semantic_seen:
                index = semantic_seen[key]
                prior = replace(retained[index])
                prior.accepted = prior.accepted or o.accepted
                prior.fork = prior.fork or o.fork
                prior.gap = prior.gap or o.gap
                prior.future_dated = (prior.future_dated or o.future_dated) and not prior.accepted
                prior.revoked_cert_ids = sorted_unique_strings_v2(list(prior.revoked_cert_ids) + list(o.revoked_cert_ids))
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
                if (
                    o.status_key_epoch == state.status_key_epoch and o.object_type == REVOCATION_LIST_CODE
                    and o.sequence == state.accepted_snapshot.sequence and o.accepted and not o.future_dated
                    and bytes(o.evidence_digest) == bytes(base_digest)
                ):
                    o.gap = False
                    break
        state.observations = retained
        journal.status_by_issuer[issuer_id] = _snap().canonicalize_revocation_status_state_v2(state)


def must_retain_status_observation_v2(state: RevocationStatusStateV2, o: RevocationObservationV2) -> bool:
    if o.status_key_epoch != state.status_key_epoch:
        return False
    if (
        state.accepted_snapshot is not None and o.object_type == REVOCATION_PUSH_CODE and o.accepted
        and o.sequence > state.accepted_snapshot.sequence and o.sequence <= state.floor
    ):
        return True
    return state.reconciliation_required and (o.sequence > state.floor or o.fork or o.gap or o.future_dated)


def security_observation_semantic_key_v2(o: RevocationObservationV2) -> str:
    digest = o.revoked_set_digest if o.object_type == REVOCATION_LIST_CODE else o.body_digest
    return (
        f"{o.status_key_epoch}:{o.object_type}:{o.sequence}:{bytes(digest).hex()}:"
        f"future={'true' if o.future_dated else 'false'}:fork={'true' if o.fork else 'false'}"
    )


def security_observation_key_v2(o: RevocationObservationV2) -> str:
    """Go marshals the whole observation; every member participates."""
    return _go_marshal(_observation_go(o)).decode("utf-8")


def has_accepted_status_observation_v2(observations, epoch, object_type, sequence, digest) -> bool:
    for o in observations:
        if (
            o.status_key_epoch == epoch and o.object_type == object_type and o.sequence == sequence
            and bytes(o.evidence_digest) == bytes(digest) and o.accepted and not o.fork and not o.future_dated
        ):
            return True
    return False


def has_accepted_snapshot_after_v2(state, epoch, min_sequence, fork_sequence, deny_union) -> bool:
    for o in state.observations:
        if (
            o.status_key_epoch == epoch and o.object_type == REVOCATION_LIST_CODE and o.accepted
            and o.sequence >= min_sequence and (fork_sequence == 0 or o.sequence > fork_sequence)
            and contains_all_string_set_v2(o.revoked_cert_ids, deny_union)
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Key roles


_ROLES = ("status", "delegation", "rotation", "verifier", "witness", "receiver", "issuer", "other")


def valid_security_key_role_v2(role: object) -> bool:
    return isinstance(role, str) and role in _ROLES


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def register_key_role_v2(journal: SecurityJournalV2, role: str, pub: HybridPublicKey) -> None:
    """Record a permanent global role assignment. Repeating the identical
    assignment is idempotent; any key-ID or component reuse is denied."""
    if journal is None or not valid_security_key_role_v2(role) or role == "status":
        raise ValueError("security key role is invalid")
    _register_key_role(journal, role, pub)


def _register_key_role(journal: SecurityJournalV2, role: str, pub: HybridPublicKey) -> None:
    binding = key_role_binding_v2(role, pub)
    for existing in journal.key_role_history:
        if existing == binding:
            return
        if (
            existing.key_id == binding.key_id or existing.ed25519_digest == binding.ed25519_digest
            or existing.ml_dsa_65_digest == binding.ml_dsa_65_digest
            or existing.ed25519_digest == binding.ml_dsa_65_digest or existing.ml_dsa_65_digest == binding.ed25519_digest
        ):
            raise ValueError(f"hybrid key ID or component is already permanently assigned to role {existing.role!r}")
    journal.key_role_history.append(binding)
    sort_key_role_history_v2(journal.key_role_history)


@classified(V2ErrorClass.STATUS_OBJECT_REJECTED)
def register_status_key_epoch_v2(journal: SecurityJournalV2, issuer_id: str, epoch: int, pub: HybridPublicKey) -> None:
    """Record caller-authenticated status-key history and the corresponding
    permanent global status role before status objects apply."""
    if (
        journal is None or not isinstance(issuer_id, str) or issuer_id == ""
        or not is_int(epoch) or epoch <= 0 or epoch > MAX_SAFE_INTEGER
    ):
        raise ValueError("status-key binding has invalid issuer or epoch")
    binding = status_key_binding_v2(issuer_id, epoch, pub)
    for existing in journal.status_key_history:
        if existing.issuer_id == issuer_id and existing.epoch == epoch:
            if existing == binding:
                return
            raise ValueError("status-key epoch is permanently bound to a different key")
        if (
            existing.status_key_id == binding.status_key_id or existing.ed25519_digest == binding.ed25519_digest
            or existing.ml_dsa_65_digest == binding.ml_dsa_65_digest
        ):
            raise ValueError("status key was previously bound in this deployment")
    highest = max((e.epoch for e in journal.status_key_history if e.issuer_id == issuer_id), default=0)
    if epoch != highest + 1:
        raise ValueError("status-key epoch must advance by one from retained issuer history")
    _register_key_role(journal, "status", pub)
    journal.status_key_history.append(binding)
    sort_status_key_history_v2(journal.status_key_history)


def key_role_binding_v2(role: str, pub: HybridPublicKey) -> KeyRoleBindingV2:
    key_id = ss._key_id_v2(pub)
    return KeyRoleBindingV2(
        key_id=key_id, ed25519_digest=sha384(bytes(pub.ed25519)).hexdigest(),
        ml_dsa_65_digest=sha384(bytes(pub.ml_dsa_65)).hexdigest(), role=role,
    )


def status_key_binding_v2(issuer_id: str, epoch: int, pub: HybridPublicKey) -> StatusKeyBindingV2:
    role = key_role_binding_v2("status", pub)
    return StatusKeyBindingV2(
        issuer_id=issuer_id, epoch=epoch, status_key_id=role.key_id,
        ed25519_digest=role.ed25519_digest, ml_dsa_65_digest=role.ml_dsa_65_digest,
    )


def validate_key_role_history_v2(history) -> None:
    seen_ids: dict = {}
    seen_components: dict = {}
    for b in history:
        if (
            not isinstance(b, KeyRoleBindingV2) or b.key_id == "" or not valid_security_key_role_v2(b.role)
            or not valid_digest_hex_v2(b.ed25519_digest) or not valid_digest_hex_v2(b.ml_dsa_65_digest)
        ):
            raise ValueError("security journal contains malformed key-role history")
        prior = seen_ids.get(b.key_id)
        if prior is not None and prior != b:
            raise ValueError("security journal reuses a key ID across roles")
        seen_ids[b.key_id] = b
        for component in (b.ed25519_digest, b.ml_dsa_65_digest):
            prior = seen_components.get(component)
            if prior is not None and prior != b:
                raise ValueError("security journal reuses key material across roles")
            seen_components[component] = b


def validate_status_key_history_v2(history, roles) -> None:
    last_epoch: dict = {}
    seen_ids: set = set()
    seen_components: set = set()
    for b in history:
        if (
            not isinstance(b, StatusKeyBindingV2) or b.issuer_id == "" or not is_int(b.epoch) or b.epoch <= 0
            or b.status_key_id == "" or not valid_digest_hex_v2(b.ed25519_digest) or not valid_digest_hex_v2(b.ml_dsa_65_digest)
        ):
            raise ValueError("security journal contains malformed status-key history")
        if b.epoch != last_epoch.get(b.issuer_id, 0) + 1:
            raise ValueError("security journal status-key epochs are missing or out of order")
        last_epoch[b.issuer_id] = b.epoch
        role = role_for_status_binding_v2(roles, b)
        if role is None or role.role != "status":
            raise ValueError("status-key history lacks its global status role assignment")
        if b.status_key_id in seen_ids:
            raise ValueError("security journal reuses a status key ID")
        seen_ids.add(b.status_key_id)
        for component in (b.ed25519_digest, b.ml_dsa_65_digest):
            if component in seen_components:
                raise ValueError("security journal reuses a status-key component")
            seen_components.add(component)


def role_for_status_binding_v2(roles, b: StatusKeyBindingV2) -> Optional[KeyRoleBindingV2]:
    for role in roles:
        if role.key_id == b.status_key_id and role.ed25519_digest == b.ed25519_digest and role.ml_dsa_65_digest == b.ml_dsa_65_digest:
            return role
    return None


def status_binding_at_epoch_v2(history, issuer_id: str, epoch: int) -> Optional[StatusKeyBindingV2]:
    for b in history or []:
        if b.issuer_id == issuer_id and b.epoch == epoch:
            return b
    return None


def valid_digest_hex_v2(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 96:
        return False
    try:
        return bytes.fromhex(value).hex() == value
    except ValueError:
        return False


def sort_key_role_history_v2(history: list) -> None:
    history.sort(key=lambda b: (b.key_id, b.role))


def sort_status_key_history_v2(history: list) -> None:
    history.sort(key=lambda b: (b.issuer_id, b.epoch))


# ---------------------------------------------------------------------------
# Go encoding/json form, used only by the version 1 (legacy) record digest and
# by the observation identity key. Members appear in Go struct order; byte
# slices are padded base64; strings use Go's HTML-safe escaping.


class _GoObject:
    __slots__ = ("items",)

    def __init__(self, items):
        self.items = items  # list of (key, value) in Go declaration order


def _go_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20 or ch in "<>&" or c in (0x2028, 0x2029):
            out.append(f"\\u{c:04x}")
        elif 0xD800 <= c <= 0xDFFF:
            out.append("\\ufffd")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _go_encode(value, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, str):
        out.append(_go_string(value))
    elif isinstance(value, (bytes, bytearray)):
        out.append('"' + base64.b64encode(bytes(value)).decode("ascii") + '"')
    elif isinstance(value, _GoObject):
        out.append("{")
        for i, (k, v) in enumerate(value.items):
            if i:
                out.append(",")
            out.append(_go_string(k))
            out.append(":")
            _go_encode(v, out)
        out.append("}")
    elif isinstance(value, dict):  # Go maps marshal with sorted keys
        out.append("{")
        for i, k in enumerate(sorted(value)):
            if i:
                out.append(",")
            out.append(_go_string(k))
            out.append(":")
            _go_encode(value[k], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, v in enumerate(value):
            if i:
                out.append(",")
            _go_encode(v, out)
        out.append("]")
    else:
        raise TypeError(f"cannot Go-marshal {type(value).__name__}")


def _go_marshal(value) -> bytes:
    out: list = []
    _go_encode(value, out)
    return "".join(out).encode("utf-8")


def _observation_go(o: RevocationObservationV2) -> _GoObject:
    return _GoObject([
        ("object_type", o.object_type), ("status_key_epoch", o.status_key_epoch), ("status_key_id", o.status_key_id),
        ("sequence", o.sequence), ("evidence_digest", o.evidence_digest), ("body_digest", o.body_digest),
        ("revoked_set_digest", o.revoked_set_digest), ("revoked_cert_ids", o.revoked_cert_ids),
        ("future_dated", o.future_dated), ("fork", o.fork), ("gap", o.gap), ("accepted", o.accepted),
    ])


def _revocation_list_go(lst) -> Optional[_GoObject]:
    if lst is None:
        return None
    revoked = None if lst.revoked is None else [_GoObject([("cert_id", c)]) for c in ss._cert_ids(lst.revoked)]
    sig = lst.signature
    return _GoObject([
        ("version", lst.version), ("issuer_id", lst.issuer_id), ("updated_at", lst.updated_at),
        ("next_update", lst.next_update), ("sequence", lst.sequence), ("revoked", revoked),
        ("signature", _GoObject([("ed25519", None if sig.ed25519 is None else bytes(sig.ed25519)),
                                 ("ml_dsa_65", None if sig.ml_dsa_65 is None else bytes(sig.ml_dsa_65))])),
    ])


def _state_go(s: RevocationStatusStateV2) -> _GoObject:
    return _GoObject([
        ("issuer_id", s.issuer_id), ("status_key_epoch", s.status_key_epoch), ("status_key_id", s.status_key_id),
        ("retired_status_key_ids", s.retired_status_key_ids), ("has_floor", s.has_floor), ("floor", s.floor),
        ("accepted_snapshot", _revocation_list_go(s.accepted_snapshot)), ("accepted_cert_ids", s.accepted_cert_ids),
        ("has_preceding_checkpoint", s.has_preceding_checkpoint), ("preceding_floor", s.preceding_floor),
        ("preceding_accepted_cert_ids", s.preceding_accepted_cert_ids), ("deny_union_cert_ids", s.deny_union_cert_ids),
        ("observations", None if s.observations is None else [_observation_go(o) for o in s.observations]),
        ("max_observed_sequence", s.max_observed_sequence), ("fork_sequence", s.fork_sequence),
        ("reconciliation_required", s.reconciliation_required),
        ("future_dated_object_observed", s.future_dated_object_observed),
    ])


def security_journal_v2_go_json(journal: SecurityJournalV2) -> bytes:
    """The Go encoding/json form of a journal record (legacy digest input)."""
    return _go_marshal(_GoObject([
        ("version", journal.version), ("generation", journal.generation),
        ("previous_digest", journal.previous_digest), ("digest", journal.digest),
        ("status_by_issuer", None if journal.status_by_issuer is None else {k: _state_go(v) for k, v in journal.status_by_issuer.items()}),
        ("key_role_history", None if journal.key_role_history is None else [
            _GoObject([("key_id", b.key_id), ("ed25519_digest", b.ed25519_digest), ("ml_dsa_65_digest", b.ml_dsa_65_digest), ("role", b.role)])
            for b in journal.key_role_history]),
        ("status_key_history", None if journal.status_key_history is None else [
            _GoObject([("issuer_id", b.issuer_id), ("epoch", b.epoch), ("status_key_id", b.status_key_id),
                       ("ed25519_digest", b.ed25519_digest), ("ml_dsa_65_digest", b.ml_dsa_65_digest)])
            for b in journal.status_key_history]),
    ]))


def legacy_security_journal_digest_v1(journal: SecurityJournalV2) -> str:
    """The pre-snapshot digest: unlabelled SHA-384 over Go encoding/json of
    the record with an empty digest member. Only validates a record before
    migration."""
    return sha384(security_journal_v2_go_json(replace(journal, digest=""))).hexdigest()


def decode_legacy_security_journal_v1(data: bytes) -> SecurityJournalV2:
    """Decode a stored version 1 (alpha) record in its Go encoding/json form.

    Strict where it matters for migration: one JSON object, no duplicate or
    unknown members, exact member types. Absent members take Go zero values
    and JSON null decodes to ``None`` (a Go nil slice or map). The caller
    validates the result with :func:`validate_security_journal_v2`, which
    checks the legacy digest, before migrating it."""
    from . import _v2json

    try:
        obj = _v2json.parse(data)
        return _journal_from_go(obj)
    except V2Error:
        raise
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc


def _go_fields(obj, allowed: tuple) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    for k in obj:
        if k not in allowed:
            raise ValueError(f"unknown member {k!r}")
    return obj


def _gint(obj, k, lo=-(2**63), hi=2**63 - 1) -> int:
    v = obj.get(k)
    if v is None:
        return 0
    if not is_int(v) or v < lo or v > hi:
        raise ValueError(f"{k} must be an integer in range")
    return v


def _gstr(obj, k) -> str:
    v = obj.get(k)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError(f"{k} must be a string")
    return v


def _gbool(obj, k) -> bool:
    v = obj.get(k)
    if v is None:
        return False
    if not isinstance(v, bool):
        raise ValueError(f"{k} must be a boolean")
    return v


def _gbytes(obj, k):
    v = obj.get(k)
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError(f"{k} must be base64")
    return base64.b64decode(v, validate=True)


def _gstrs(obj, k):
    v = obj.get(k)
    if v is None:
        return None
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{k} must be an array of strings")
    return list(v)


def _journal_from_go(obj) -> SecurityJournalV2:
    from .protocol_v2 import decode_revocation_list_v2
    from ._v2json import canonical

    _go_fields(obj, ("version", "generation", "previous_digest", "digest", "status_by_issuer", "key_role_history", "status_key_history"))
    journal = SecurityJournalV2(
        version=_gint(obj, "version", 0, 65535), generation=_gint(obj, "generation", 0, 2**64 - 1),
        previous_digest=_gstr(obj, "previous_digest"), digest=_gstr(obj, "digest"),
    )
    by_issuer = obj.get("status_by_issuer")
    if by_issuer is not None:
        if not isinstance(by_issuer, dict):
            raise ValueError("status_by_issuer must be an object")
        journal.status_by_issuer = {}
        for issuer_id, raw in by_issuer.items():
            s = _go_fields(raw, (
                "issuer_id", "status_key_epoch", "status_key_id", "retired_status_key_ids", "has_floor", "floor",
                "accepted_snapshot", "accepted_cert_ids", "has_preceding_checkpoint", "preceding_floor",
                "preceding_accepted_cert_ids", "deny_union_cert_ids", "observations", "max_observed_sequence",
                "fork_sequence", "reconciliation_required", "future_dated_object_observed"))
            snapshot = None
            if s.get("accepted_snapshot") is not None:
                snapshot = decode_revocation_list_v2(canonical(s["accepted_snapshot"]))
            observations = None
            if s.get("observations") is not None:
                if not isinstance(s["observations"], list):
                    raise ValueError("observations must be an array")
                observations = []
                for ro in s["observations"]:
                    o = _go_fields(ro, ("object_type", "status_key_epoch", "status_key_id", "sequence", "evidence_digest",
                                        "body_digest", "revoked_set_digest", "revoked_cert_ids", "future_dated", "fork",
                                        "gap", "accepted"))
                    observations.append(RevocationObservationV2(
                        object_type=_gint(o, "object_type", 0, 65535), status_key_epoch=_gint(o, "status_key_epoch", 0, 2**64 - 1),
                        status_key_id=_gstr(o, "status_key_id"), sequence=_gint(o, "sequence"),
                        evidence_digest=_gbytes(o, "evidence_digest") or b"", body_digest=_gbytes(o, "body_digest") or b"",
                        revoked_set_digest=_gbytes(o, "revoked_set_digest") or b"",
                        revoked_cert_ids=_gstrs(o, "revoked_cert_ids") or [], future_dated=_gbool(o, "future_dated"),
                        fork=_gbool(o, "fork"), gap=_gbool(o, "gap"), accepted=_gbool(o, "accepted"),
                    ))
            journal.status_by_issuer[issuer_id] = RevocationStatusStateV2(
                issuer_id=_gstr(s, "issuer_id"), status_key_epoch=_gint(s, "status_key_epoch", 0, 2**64 - 1),
                status_key_id=_gstr(s, "status_key_id"), retired_status_key_ids=_gstrs(s, "retired_status_key_ids"),
                has_floor=_gbool(s, "has_floor"), floor=_gint(s, "floor"), accepted_snapshot=snapshot,
                accepted_cert_ids=_gstrs(s, "accepted_cert_ids"), has_preceding_checkpoint=_gbool(s, "has_preceding_checkpoint"),
                preceding_floor=_gint(s, "preceding_floor"), preceding_accepted_cert_ids=_gstrs(s, "preceding_accepted_cert_ids"),
                deny_union_cert_ids=_gstrs(s, "deny_union_cert_ids"), observations=observations,
                max_observed_sequence=_gint(s, "max_observed_sequence"), fork_sequence=_gint(s, "fork_sequence"),
                reconciliation_required=_gbool(s, "reconciliation_required"),
                future_dated_object_observed=_gbool(s, "future_dated_object_observed"),
            )
    if obj.get("key_role_history") is not None:
        if not isinstance(obj["key_role_history"], list):
            raise ValueError("key_role_history must be an array")
        journal.key_role_history = []
        for rb in obj["key_role_history"]:
            b = _go_fields(rb, ("key_id", "ed25519_digest", "ml_dsa_65_digest", "role"))
            journal.key_role_history.append(KeyRoleBindingV2(
                key_id=_gstr(b, "key_id"), ed25519_digest=_gstr(b, "ed25519_digest"),
                ml_dsa_65_digest=_gstr(b, "ml_dsa_65_digest"), role=_gstr(b, "role")))
    if obj.get("status_key_history") is not None:
        if not isinstance(obj["status_key_history"], list):
            raise ValueError("status_key_history must be an array")
        journal.status_key_history = []
        for rb in obj["status_key_history"]:
            b = _go_fields(rb, ("issuer_id", "epoch", "status_key_id", "ed25519_digest", "ml_dsa_65_digest"))
            journal.status_key_history.append(StatusKeyBindingV2(
                issuer_id=_gstr(b, "issuer_id"), epoch=_gint(b, "epoch", 0, 2**64 - 1),
                status_key_id=_gstr(b, "status_key_id"), ed25519_digest=_gstr(b, "ed25519_digest"),
                ml_dsa_65_digest=_gstr(b, "ml_dsa_65_digest")))
    return journal

