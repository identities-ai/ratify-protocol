"""Authenticated status at the verifier boundary (Go status_provenance_v2.go,
SPEC-v2 §6.5).

The status provider never supplies a StatusResult. For each distinct issuer
in the verified chain, in ascending order of issuer ID, the verifier:

1. loads the committed SecurityJournalV2 at its anchored head and requires
   the caller-authenticated status key (``status_keys``) to equal the
   journal's current epoch binding for the issuer;
2. checks role separation by complete key ID and both component digests;
3. asks the provider for a bounded batch of signed lists and pushes;
4. decodes every object and verifies it under the selected key (any failure
   rejects the whole batch);
5. applies the batch, sorted by sequence, then code, then
   StatusEvidenceDigest, as one journal transition committed by
   compare-and-swap against the head loaded in step 1; on a conflict it
   reloads, rechecks steps 1 and 2, and reapplies the same batch exactly
   once more;
6. derives each CertificateRef result from the committed journal state.

A missing binding, unanchored or unmigrated journal, role violation, provider
exception/timeout, malformed/oversized/unauthenticated batch, reducer
rejection, store failure or compare-and-swap conflict makes every reference
of that issuer indeterminate/unavailable with no evidence. These are
terminal status outcomes; they do not interrupt the claim. If the caller's
context ends during the stage, nothing is committed and the verifier reports
the evaluating stage with evaluation_cancelled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import security_journal_v2 as sj
from . import status_state_v2 as ss
from .context_v2 import Context
from .status_evaluation_v2 import V2StatusAssessment, V2StatusRoleBindings, aggregate_certificate_status_v2
from .status_state_v2 import REVOCATION_LIST_CODE, REVOCATION_PUSH_CODE, RevocationStatusResultV2
from .types import HybridPublicKey
from .types_v2 import is_int

# SPEC-v2 §2.6 status evidence batch bounds (Go limits_v2.go).
MAX_STATUS_EVIDENCE_BATCH_BYTES_V2 = 8 << 20
MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 = 64


@dataclass(frozen=True)
class V2StatusKeyConfig:
    """The caller-authenticated status-key binding for one issuer. It must
    equal the binding retained in the security journal at that epoch, and the
    epoch must be the issuer's current journal epoch."""

    epoch: int
    key: HybridPublicKey


@dataclass
class V2StatusEvidenceRequest:
    """What the verifier asks a status provider for. It is chosen from
    authenticated configuration, never from the proof. ``refs`` are the
    issuer's CertificateRefs in chain order."""

    issuer_id: str = ""
    status_key_epoch: int = 0
    status_key_id: str = ""
    refs: list = field(default_factory=list)


@dataclass
class V2StatusStageResult:
    """Go ``v2StatusStageResult``: the aggregate, or the context error that
    cancelled the stage, and the number of provider queries."""

    assessment: V2StatusAssessment = field(default_factory=V2StatusAssessment)
    cancelled: Optional[BaseException] = None
    queries: int = 0


@dataclass
class _VerifiedStatusObject:
    code: int
    sequence: int
    digest: bytes
    list: object = None
    push: object = None


def _unavailable_result() -> RevocationStatusResultV2:
    return RevocationStatusResultV2(status="indeterminate", reason="unavailable", evidence=[])


def _certificate_ref(issuer_id: str, cert_id: str):
    from .verify_v2 import CertificateRefV2

    return CertificateRefV2(issuer_id=issuer_id, cert_id=cert_id)


def run_v2_status_stage(ctx: Context, bundle, checks, req, cb, now: int) -> V2StatusStageResult:
    """Execute the status stage for every CertificateRef check. ``req`` and
    ``cb`` are the verifier's request and callbacks; this stage reads
    ``req.status_keys``, ``req.status_policy``, ``cb.status_evidence`` (a
    callable ``(ctx, V2StatusEvidenceRequest) -> V2StatusEvidenceBatch``)
    and ``cb.status_journal`` (a SecurityJournalStoreV2)."""
    issuer_ids: list = []
    refs_by_issuer: dict = {}
    for check in checks:
        if check.issuer_id not in refs_by_issuer:
            issuer_ids.append(check.issuer_id)
            refs_by_issuer[check.issuer_id] = []
        refs_by_issuer[check.issuer_id].append(_certificate_ref(check.issuer_id, check.cert_id))
    issuer_ids.sort()
    results = [_unavailable_result() for _ in checks]
    roles = V2StatusRoleBindings(status_key_issuers={}, current_status_key_ids={}, reserved_key_ids=set())
    queries = 0
    status_keys = getattr(req, "status_keys", None) or {}
    policy = getattr(req, "status_policy", None)
    journal_store = getattr(cb, "status_journal", None)
    provider = getattr(cb, "status_evidence", None)
    for issuer_id in issuer_ids:
        if ctx.err() is not None:
            return V2StatusStageResult(cancelled=ctx.err(), queries=queries)
        config = status_keys.get(issuer_id)
        if config is None or journal_store is None or provider is None:
            continue
        # 1. Anchored journal and current epoch binding.
        try:
            current = sj.load_anchored_security_journal_v2(ctx, journal_store)
        except Exception:  # noqa: BLE001 - any journal failure is unavailable
            if ctx.err() is not None:
                return V2StatusStageResult(cancelled=ctx.err(), queries=queries)
            continue
        # 2. Role separation.
        try:
            check_v2_status_role_separation(current, issuer_id, config, bundle)
            status_key_id = ss._key_id_v2(config.key)
        except Exception:  # noqa: BLE001
            continue
        # 3. Provider.
        queries += 1
        request = V2StatusEvidenceRequest(
            issuer_id=issuer_id, status_key_epoch=config.epoch, status_key_id=status_key_id,
            refs=list(refs_by_issuer[issuer_id]),
        )
        try:
            batch = call_v2_status_provider(ctx, provider, request)
        except Exception:  # noqa: BLE001 - a provider error or exception is unavailable
            if ctx.err() is not None:
                return V2StatusStageResult(cancelled=ctx.err(), queries=queries)
            continue
        # 4. Authenticate.
        try:
            objects = verify_v2_status_evidence_batch(batch, issuer_id, config.key)
        except Exception:  # noqa: BLE001
            continue
        # 5. Apply as one transition against the loaded head; on one
        # compare-and-swap conflict reload, recheck, and reapply the same
        # batch exactly once more (no second provider call).
        committed = None
        applied = False
        for attempt in range(2):
            if applied:
                break
            if attempt > 0:
                try:
                    current = sj.load_anchored_security_journal_v2(ctx, journal_store)
                    check_v2_status_role_separation(current, issuer_id, config, bundle)
                except Exception:  # noqa: BLE001
                    break
            try:
                committed = apply_v2_status_batch_to_journal(
                    ctx, journal_store, current, issuer_id, config, objects, policy, now)
                applied = True
            except sj.SecurityJournalConflictV2:
                continue
            except Exception:  # noqa: BLE001
                break
        if ctx.err() is not None:
            return V2StatusStageResult(cancelled=ctx.err(), queries=queries)
        if not applied:
            continue
        # 6. Derive from committed state.
        for binding in committed.status_key_history:
            if binding.issuer_id == issuer_id:
                roles.status_key_issuers[binding.status_key_id] = issuer_id
        roles.current_status_key_ids[issuer_id] = status_key_id
        for i, check in enumerate(checks):
            if check.issuer_id != issuer_id:
                continue
            try:
                results[i] = ss.revocation_status_for_cert_v2(
                    committed.status_by_issuer.get(issuer_id), issuer_id, check.cert_id, config.epoch, config.key, policy, now)
            except Exception:  # noqa: BLE001
                results[i] = _unavailable_result()
    try:
        assessment = aggregate_certificate_status_v2(checks, results, roles, True)
    except Exception:  # noqa: BLE001
        assessment = V2StatusAssessment(assessment="unavailable", reason="status_unavailable", evidence=[])
    return V2StatusStageResult(assessment=assessment, queries=queries)


# The coordinator's verifier imports the Go-private name.
_run_v2_status_stage = run_v2_status_stage


def call_v2_status_provider(ctx: Context, provider: Callable, request: V2StatusEvidenceRequest):
    """Call the provider. Any exception it raises (the Python counterpart of
    a Go error or panic) propagates to the caller, which treats the issuer as
    unavailable."""
    return provider(ctx, request)


def _batch_objects(batch) -> list:
    objects = getattr(batch, "objects", None)
    if objects is None:
        objects = []
    if not isinstance(objects, (list, tuple)):
        raise ValueError("v2 status batch objects must be a list")
    for obj in objects:
        if not is_int(getattr(obj, "object_type", None)) or not isinstance(getattr(obj, "wire", None), (bytes, bytearray)):
            raise ValueError("v2 status batch entry must carry an integer object_type and wire bytes")
    return list(objects)


def _batch_encoded_length(objects) -> int:
    """Go ``v2StatusEvidenceBatchEncodedLength``: the batch wire form with each
    object's exact received bytes."""
    total = 2
    for i, obj in enumerate(objects):
        if i > 0:
            total += 1
        total += len('{"object":') + len(obj.wire) + len(',"object_type_code":') + len(str(obj.object_type)) + 1
    return total


def verify_v2_status_evidence_batch(batch, issuer_id: str, key: HybridPublicKey) -> list:
    """Decode and authenticate every object before any is applied; return
    them in application order: ascending sequence, then object type code,
    then evidence digest bytes."""
    w = ss._wire()
    objects = _batch_objects(batch)
    if len(objects) > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2:
        raise ValueError(f"v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects")
    if _batch_encoded_length(objects) > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2:
        raise ValueError(f"v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_BYTES_V2} bytes")
    out = []
    for obj in objects:
        if obj.object_type == REVOCATION_LIST_CODE:
            lst = w.decode_revocation_list_v2(bytes(obj.wire))
            w.verify_revocation_list_v2_signature(lst, issuer_id, key)
            digest = ss._status_evidence_digest(obj.object_type, lst)
            out.append(_VerifiedStatusObject(code=obj.object_type, sequence=lst.sequence, digest=digest, list=lst))
        elif obj.object_type == REVOCATION_PUSH_CODE:
            push = w.decode_revocation_push_v2(bytes(obj.wire))
            w.verify_revocation_push_v2_signature(push, issuer_id, key)
            digest = ss._status_evidence_digest(obj.object_type, push)
            out.append(_VerifiedStatusObject(code=obj.object_type, sequence=push.sequence, digest=digest, push=push))
        else:
            raise ValueError(f"v2 status batch contains unsupported object type 0x{obj.object_type:04x}")
    out.sort(key=lambda o: (o.sequence, o.code, bytes(o.digest)))
    return out


def apply_v2_status_batch_to_journal(
    ctx: Context, store, current, issuer_id: str, config: V2StatusKeyConfig, objects: list, policy, now: int,
):
    """Apply one issuer's authenticated batch to the loaded journal and
    commit it by compare-and-swap against the loaded head. A no-op batch
    returns the loaded journal unchanged."""
    nxt = sj.clone_security_journal_v2(current)
    state = nxt.status_by_issuer.get(issuer_id, ss.RevocationStatusStateV2())
    for obj in objects:
        if obj.list is not None:
            state = ss.apply_revocation_list_v2(state, obj.list, issuer_id, config.epoch, config.key, policy, now)
        else:
            state = ss.apply_revocation_push_v2(state, obj.push, issuer_id, config.epoch, config.key, policy, now)
    nxt.status_by_issuer[issuer_id] = state
    return sj.commit_security_journal_transition_v2(ctx, store, current, nxt)


def check_v2_status_role_separation(journal, issuer_id: str, config: V2StatusKeyConfig, bundle) -> None:
    """SPEC-v2 §5.4 and §6.5 permanent role separation: the configured status
    key must be the issuer's current journal epoch binding; its role history
    entry must be exactly the status role; and neither its key ID nor either
    component may equal the key ID or a component of any other journal role,
    of any key in the proof (issuers, subjects, agent), or the verifier ID."""
    if not isinstance(config, V2StatusKeyConfig):
        raise ValueError("v2 status-key configuration is required")
    sj.require_journal_status_key_v2(journal, issuer_id, config.epoch, config.key)
    status = sj.key_role_binding_v2("status", config.key)
    components = (status.ed25519_digest, status.ml_dsa_65_digest)
    recorded = False
    for binding in journal.key_role_history:
        if binding == status:
            recorded = True
            continue
        if binding.key_id == status.key_id or binding.ed25519_digest in components or binding.ml_dsa_65_digest in components:
            raise ValueError(f"status key shares a key ID or component with journal role {binding.role!r}")
    if not recorded:
        raise ValueError("status key lacks its permanent status role in the journal")
    keys = [bundle.agent_pub_key]
    for cert in bundle.delegations or []:
        keys.extend((cert.issuer_pub_key, cert.subject_pub_key))
    for key in keys:
        chain_key = sj.key_role_binding_v2("other", key)
        # No chain key may share an ID or component with any current or
        # retired status binding of any issuer (§6.5 step 2).
        for binding in journal.key_role_history:
            if binding.role != "status":
                continue
            bc = (binding.ed25519_digest, binding.ml_dsa_65_digest)
            if chain_key.key_id == binding.key_id or chain_key.ed25519_digest in bc or chain_key.ml_dsa_65_digest in bc:
                raise ValueError("a proof key shares a key ID or component with a status key")
    if status.key_id == bundle.verifier_id:
        raise ValueError("status key equals the verifier identity")

