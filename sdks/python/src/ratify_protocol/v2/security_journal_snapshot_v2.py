"""SecurityJournalV2 logical snapshot (Go security_journal_snapshot_v2.go,
SPEC-v2 §6.6).

The snapshot is the portable, canonical projection of a SecurityJournalV2.
Its bytes are RatifyCanonicalJSON of the object below and its digest is

    SecurityJournalDigest = SHA-384("ratify-protocol-security-journal-v2" || 0x00 || snapshot)

rendered as 96 lowercase hex characters. Members are never omitted (absent is
null, an empty set is []); previous_digest is 96 "0" characters at genesis;
histories, issuers and string sets are sorted; observations keep compaction
order; observation digests are base64 of 48 raw bytes; accepted_snapshot is
the complete canonical RevocationList object or null; floor is null before
any accepted state; preceding_checkpoint is null or {accepted_cert_ids, floor}.

A valid digest chain is not rollback protection: the head must be anchored
independently and advanced by atomic compare-and-swap (SPEC-v2 §7.10).
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import replace
from hashlib import sha384

from . import _v2json
from . import security_journal_v2 as sj
from . import status_state_v2 as ss
from .errors_v2 import V2Error, V2ErrorClass, classify, classified
from .security_journal_v2 import (
    SECURITY_JOURNAL_LEGACY_VERSION,
    SECURITY_JOURNAL_VERSION_V2,
    KeyRoleBindingV2,
    SecurityJournalHeadV2,
    SecurityJournalV2,
    StatusKeyBindingV2,
)
from .status_state_v2 import RevocationObservationV2, RevocationStatusStateV2, sorted_unique_strings_v2
from .types_v2 import MAX_SAFE_INTEGER, is_int

SECURITY_JOURNAL_DIGEST_LABEL_V2 = b"ratify-protocol-security-journal-v2"
# Bounds an imported snapshot.
MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES = 64 << 20
GENESIS_PREVIOUS_DIGEST_V2 = "0" * 96


def compare_compaction_order_v2(a: RevocationObservationV2, b: RevocationObservationV2) -> int:
    """The SPEC-v2 §6.6 compaction sort key."""
    ka = (a.status_key_epoch, a.sequence, a.object_type, bytes(a.revoked_set_digest), bytes(a.body_digest))
    kb = (b.status_key_epoch, b.sequence, b.object_type, bytes(b.revoked_set_digest), bytes(b.body_digest))
    return (ka > kb) - (ka < kb)


def canonicalize_security_journal_v2(journal: SecurityJournalV2) -> None:
    """Put every set and history of the in-memory record into snapshot order.
    Observation order is compaction order and is not changed here."""
    if journal.key_role_history is None:
        journal.key_role_history = []
    if journal.status_key_history is None:
        journal.status_key_history = []
    if journal.status_by_issuer is None:
        journal.status_by_issuer = {}
    sj.sort_key_role_history_v2(journal.key_role_history)
    sj.sort_status_key_history_v2(journal.status_key_history)
    for issuer_id in list(journal.status_by_issuer):
        journal.status_by_issuer[issuer_id] = canonicalize_revocation_status_state_v2(journal.status_by_issuer[issuer_id])


def canonicalize_revocation_status_state_v2(state: RevocationStatusStateV2) -> RevocationStatusStateV2:
    state = replace(state)
    state.retired_status_key_ids = sorted_unique_strings_v2(state.retired_status_key_ids)
    state.accepted_cert_ids = sorted_unique_strings_v2(state.accepted_cert_ids)
    state.preceding_accepted_cert_ids = sorted_unique_strings_v2(state.preceding_accepted_cert_ids)
    state.deny_union_cert_ids = sorted_unique_strings_v2(state.deny_union_cert_ids)
    state.observations = [
        replace(o, revoked_cert_ids=sorted_unique_strings_v2(o.revoked_cert_ids)) for o in (state.observations or [])
    ]
    return state


def _snapshot_observation(o: RevocationObservationV2) -> dict:
    return {
        "accepted": o.accepted, "body_digest": bytes(o.body_digest), "evidence_digest": bytes(o.evidence_digest),
        "fork": o.fork, "future_dated": o.future_dated, "gap": o.gap, "object_type_code": o.object_type,
        "revoked_cert_ids": sorted_unique_strings_v2(o.revoked_cert_ids),
        "revoked_set_digest": bytes(o.revoked_set_digest), "sequence": o.sequence,
        "status_key_epoch": o.status_key_epoch, "status_key_id": o.status_key_id,
    }


def security_journal_snapshot_struct_v2(journal: SecurityJournalV2) -> dict:
    # Canonicalize a private copy; the caller's map and lists are not mutated.
    journal = replace(
        journal,
        key_role_history=list(journal.key_role_history or []),
        status_key_history=list(journal.status_key_history or []),
        status_by_issuer=dict(journal.status_by_issuer or {}),
    )
    canonicalize_security_journal_v2(journal)
    if journal.generation == 0 and journal.previous_digest != "":
        raise ValueError("security journal genesis has a predecessor")
    snapshot = {
        "generation": journal.generation,
        "previous_digest": GENESIS_PREVIOUS_DIGEST_V2 if journal.generation == 0 else journal.previous_digest,
        "version": journal.version,
        "key_role_history": [
            {"ed25519_digest": r.ed25519_digest, "key_id": r.key_id, "ml_dsa_65_digest": r.ml_dsa_65_digest, "role": r.role}
            for r in journal.key_role_history
        ],
        "status_key_history": [
            {"ed25519_digest": b.ed25519_digest, "epoch": b.epoch, "issuer_id": b.issuer_id,
             "ml_dsa_65_digest": b.ml_dsa_65_digest, "status_key_id": b.status_key_id}
            for b in journal.status_key_history
        ],
        "issuers": [],
    }
    for issuer_id in sorted(journal.status_by_issuer):
        state = journal.status_by_issuer[issuer_id]
        if state.has_floor != (state.accepted_snapshot is not None):
            raise ValueError(f"security journal issuer {issuer_id!r} has an accepted snapshot inconsistent with its floor")
        projected = {
            "accepted_cert_ids": state.accepted_cert_ids, "accepted_snapshot": None,
            "deny_union_cert_ids": state.deny_union_cert_ids, "floor": None,
            "fork_sequence": state.fork_sequence, "future_dated_object_observed": state.future_dated_object_observed,
            "issuer_id": state.issuer_id, "max_observed_sequence": state.max_observed_sequence,
            "observations": [_snapshot_observation(o) for o in state.observations],
            "preceding_checkpoint": None, "reconciliation_required": state.reconciliation_required,
            "retired_status_key_ids": state.retired_status_key_ids, "status_key_epoch": state.status_key_epoch,
            "status_key_id": state.status_key_id,
        }
        if state.has_floor:
            projected["floor"] = state.floor
            try:
                wire = ss._wire().encode_revocation_list_v2(state.accepted_snapshot)
            except Exception as exc:
                raise ValueError(f"encode accepted snapshot for issuer {issuer_id!r}: {exc}") from exc
            projected["accepted_snapshot"] = _v2json.RawJSON(wire)
        if state.has_preceding_checkpoint:
            projected["preceding_checkpoint"] = {
                "accepted_cert_ids": state.preceding_accepted_cert_ids, "floor": state.preceding_floor,
            }
        snapshot["issuers"].append(projected)
    return snapshot


def security_journal_snapshot_bytes_v2(journal: SecurityJournalV2) -> bytes:
    """Canonical snapshot bytes of a version 2 journal, without validation."""
    return _v2json.canonical(security_journal_snapshot_struct_v2(journal))


def security_journal_snapshot_digest_v2(snapshot: bytes) -> str:
    """The labelled SHA-384 digest of canonical snapshot bytes (96 hex)."""
    return sha384(SECURITY_JOURNAL_DIGEST_LABEL_V2 + b"\x00" + bytes(snapshot)).hexdigest()


def security_journal_digest_v2(journal: SecurityJournalV2) -> str:
    if journal.version == SECURITY_JOURNAL_VERSION_V2 and is_int(journal.version):
        return security_journal_snapshot_digest_v2(security_journal_snapshot_bytes_v2(journal))
    if journal.version == SECURITY_JOURNAL_LEGACY_VERSION and is_int(journal.version):
        return sj.legacy_security_journal_digest_v1(journal)
    raise ValueError(f"security journal version {journal.version} is unsupported")


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def export_security_journal_snapshot_v2(journal: SecurityJournalV2) -> bytes:
    """Validate a version 2 journal and return its canonical snapshot bytes."""
    if not isinstance(journal, SecurityJournalV2) or journal.version != SECURITY_JOURNAL_VERSION_V2:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                      f"only version {SECURITY_JOURNAL_VERSION_V2} security journals can be exported; migrate first")
    try:
        sj.validate_security_journal_v2(journal)
    except V2Error:
        raise
    except Exception as exc:
        raise classify(V2ErrorClass.CONFIGURATION_INVALID, exc) from exc
    return security_journal_snapshot_bytes_v2(journal)


# ---------------------------------------------------------------------------
# Import


def _obj(value, members: tuple, where: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    for key in value:
        if key not in members:
            raise ValueError(f"{where}: unknown member {key!r}")
    return value


def _int(obj: dict, key: str, lo: int, hi: int) -> int:
    v = obj.get(key)
    if v is None:
        return 0
    if not is_int(v) or v < lo or v > hi:
        raise ValueError(f"{key} must be an integer")
    return v


def _str(obj: dict, key: str) -> str:
    v = obj.get(key)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a string")
    return v


def _bool(obj: dict, key: str) -> bool:
    v = obj.get(key)
    if v is None:
        return False
    if not isinstance(v, bool):
        raise ValueError(f"{key} must be a boolean")
    return v


def _strs(obj: dict, key: str) -> list:
    v = obj.get(key)
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{key} must be an array of strings")
    return list(v)


def _list(obj: dict, key: str) -> list:
    v = obj.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError(f"{key} must be an array")
    return v


def _b64(obj: dict, key: str) -> bytes:
    v = obj.get(key)
    if v is None:
        return b""
    if not isinstance(v, str):
        raise ValueError(f"{key} must be base64")
    try:
        return base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{key} is not valid base64") from exc


_U64 = 2**64 - 1
_I64 = (-(2**63), 2**63 - 1)


def import_security_journal_snapshot_v2(snapshot: bytes, head: SecurityJournalHeadV2) -> SecurityJournalV2:
    """Decode canonical snapshot bytes, require exact canonical form, require
    the digest and generation to equal the independently anchored head, and
    validate the record. There is no partial import. Failures are malformed,
    except a head mismatch, which is log_state_mismatch."""
    try:
        return _import(snapshot, head)
    except V2Error:
        raise
    except Exception as exc:  # noqa: BLE001 - every failure is classified
        raise classify(V2ErrorClass.MALFORMED, exc) from exc


def _import(snapshot: bytes, head: SecurityJournalHeadV2) -> SecurityJournalV2:
    if not isinstance(snapshot, (bytes, bytearray)):
        raise ValueError("security journal snapshot must be bytes")
    snapshot = bytes(snapshot)
    if len(snapshot) > MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES:
        raise ValueError(f"security journal snapshot exceeds {MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES} bytes")
    if not isinstance(head, SecurityJournalHeadV2):
        raise ValueError("anchored head is required")
    decoded = _obj(_v2json.parse(snapshot), (
        "generation", "issuers", "key_role_history", "previous_digest", "status_key_history", "version"), "snapshot")
    version = _int(decoded, "version", 0, 65535)
    if version != SECURITY_JOURNAL_VERSION_V2:
        raise ValueError(f"security journal snapshot version {version} is unsupported")
    generation = _int(decoded, "generation", 0, _U64)
    previous = _str(decoded, "previous_digest")
    if generation == 0:
        if previous != GENESIS_PREVIOUS_DIGEST_V2:
            raise ValueError("security journal genesis must have the all-zero predecessor")
        previous = ""
    journal = SecurityJournalV2(
        version=version, generation=generation, previous_digest=previous,
        status_by_issuer={}, key_role_history=[], status_key_history=[],
    )
    for raw in _list(decoded, "key_role_history"):
        r = _obj(raw, ("ed25519_digest", "key_id", "ml_dsa_65_digest", "role"), "key role")
        journal.key_role_history.append(KeyRoleBindingV2(
            key_id=_str(r, "key_id"), ed25519_digest=_str(r, "ed25519_digest"),
            ml_dsa_65_digest=_str(r, "ml_dsa_65_digest"), role=_str(r, "role")))
    for raw in _list(decoded, "status_key_history"):
        b = _obj(raw, ("ed25519_digest", "epoch", "issuer_id", "ml_dsa_65_digest", "status_key_id"), "status key")
        journal.status_key_history.append(StatusKeyBindingV2(
            issuer_id=_str(b, "issuer_id"), epoch=_int(b, "epoch", 0, _U64), status_key_id=_str(b, "status_key_id"),
            ed25519_digest=_str(b, "ed25519_digest"), ml_dsa_65_digest=_str(b, "ml_dsa_65_digest")))
    for raw in _list(decoded, "issuers"):
        p = _obj(raw, (
            "accepted_cert_ids", "accepted_snapshot", "deny_union_cert_ids", "floor", "fork_sequence",
            "future_dated_object_observed", "issuer_id", "max_observed_sequence", "observations",
            "preceding_checkpoint", "reconciliation_required", "retired_status_key_ids", "status_key_epoch",
            "status_key_id"), "issuer state")
        issuer_id = _str(p, "issuer_id")
        if issuer_id in journal.status_by_issuer:
            raise ValueError(f"security journal snapshot repeats issuer {issuer_id!r}")
        state = RevocationStatusStateV2(
            issuer_id=issuer_id, status_key_epoch=_int(p, "status_key_epoch", 0, _U64),
            status_key_id=_str(p, "status_key_id"), retired_status_key_ids=_strs(p, "retired_status_key_ids"),
            accepted_cert_ids=_strs(p, "accepted_cert_ids"), preceding_accepted_cert_ids=[],
            deny_union_cert_ids=_strs(p, "deny_union_cert_ids"),
            max_observed_sequence=_int(p, "max_observed_sequence", *_I64),
            fork_sequence=_int(p, "fork_sequence", *_I64), reconciliation_required=_bool(p, "reconciliation_required"),
            future_dated_object_observed=_bool(p, "future_dated_object_observed"), observations=[],
        )
        if p.get("floor") is not None:
            state.has_floor, state.floor = True, _int(p, "floor", *_I64)
        if p.get("accepted_snapshot") is not None:
            if not isinstance(p["accepted_snapshot"], dict):
                raise ValueError("accepted_snapshot must be an object or null")
            try:
                state.accepted_snapshot = ss._wire().decode_revocation_list_v2(_v2json.canonical(p["accepted_snapshot"]))
            except Exception as exc:
                raise ValueError(f"accepted snapshot for issuer {issuer_id!r}: {exc}") from exc
        if p.get("preceding_checkpoint") is not None:
            c = _obj(p["preceding_checkpoint"], ("accepted_cert_ids", "floor"), "preceding checkpoint")
            state.has_preceding_checkpoint = True
            state.preceding_floor = _int(c, "floor", *_I64)
            state.preceding_accepted_cert_ids = _strs(c, "accepted_cert_ids")
        for raw_o in _list(p, "observations"):
            o = _obj(raw_o, (
                "accepted", "body_digest", "evidence_digest", "fork", "future_dated", "gap", "object_type_code",
                "revoked_cert_ids", "revoked_set_digest", "sequence", "status_key_epoch", "status_key_id"), "observation")
            observation = RevocationObservationV2(
                object_type=_int(o, "object_type_code", 0, 65535), status_key_epoch=_int(o, "status_key_epoch", 0, _U64),
                status_key_id=_str(o, "status_key_id"), sequence=_int(o, "sequence", *_I64),
                evidence_digest=_b64(o, "evidence_digest"), body_digest=_b64(o, "body_digest"),
                revoked_set_digest=_b64(o, "revoked_set_digest"), revoked_cert_ids=_strs(o, "revoked_cert_ids"),
                future_dated=_bool(o, "future_dated"), fork=_bool(o, "fork"), gap=_bool(o, "gap"),
                accepted=_bool(o, "accepted"),
            )
            if len(observation.evidence_digest) != 48 or len(observation.body_digest) != 48 or len(observation.revoked_set_digest) != 48:
                raise ValueError(f"observation digest for issuer {issuer_id!r} is not 48 bytes")
            state.observations.append(observation)
        for i in range(1, len(state.observations)):
            if compare_compaction_order_v2(state.observations[i - 1], state.observations[i]) > 0:
                raise ValueError(f"observations for issuer {issuer_id!r} are not in compaction order")
        journal.status_by_issuer[issuer_id] = state
    if security_journal_snapshot_bytes_v2(journal) != snapshot:
        raise ValueError("security journal snapshot is not in canonical form")
    journal.digest = security_journal_snapshot_digest_v2(snapshot)
    if head.generation != journal.generation or head.digest != journal.digest:
        raise V2Error(V2ErrorClass.LOG_STATE_MISMATCH, "security journal snapshot does not match the anchored head")
    sj.validate_security_journal_v2(journal)
    return journal


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def migrate_security_journal_v2(legacy: SecurityJournalV2) -> SecurityJournalV2:
    """Convert a valid version 1 record into its version 2 successor: the
    same logical content at generation+1, previous_digest set to the legacy
    digest, and the canonical snapshot digest. Commit it with the store's
    anchored compare-and-swap from the legacy head."""
    if not isinstance(legacy, SecurityJournalV2) or legacy.version != SECURITY_JOURNAL_LEGACY_VERSION:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                      f"security journal migration requires a version {SECURITY_JOURNAL_LEGACY_VERSION} record")
    try:
        sj.validate_security_journal_v2(legacy)
    except Exception as exc:
        raise classify(V2ErrorClass.CONFIGURATION_INVALID, exc) from exc
    nxt = sj.clone_security_journal_v2(legacy)
    if legacy.generation >= MAX_SAFE_INTEGER:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "security journal generation exhausted")
    nxt.version = SECURITY_JOURNAL_VERSION_V2
    nxt.generation = legacy.generation + 1
    nxt.previous_digest = legacy.digest
    canonicalize_security_journal_v2(nxt)
    nxt.digest = security_journal_digest_v2(nxt)
    try:
        sj.validate_security_journal_transition_v2(legacy, nxt)
    except Exception as exc:
        raise classify(V2ErrorClass.CONFIGURATION_INVALID, exc) from exc
    return nxt


def same_security_journal_content_v2(a: SecurityJournalV2, b: SecurityJournalV2) -> bool:
    """Compare logical content, ignoring version, generation and digests."""
    a = replace(a, version=SECURITY_JOURNAL_VERSION_V2, generation=1, previous_digest="")
    b = replace(b, version=SECURITY_JOURNAL_VERSION_V2, generation=1, previous_digest="")
    try:
        return security_journal_snapshot_bytes_v2(a) == security_journal_snapshot_bytes_v2(b)
    except Exception:  # noqa: BLE001 - Go: err1 == nil && err2 == nil && equal
        return False
