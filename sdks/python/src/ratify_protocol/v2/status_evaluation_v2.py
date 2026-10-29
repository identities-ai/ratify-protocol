"""Aggregation of per-certificate status results (Go status_evaluation_v2.go,
SPEC-v2 §6.5).

The aggregate is not a terminal decision: callers stop on non-current status
and never reserve rate capacity until the assessment is current.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .status_state_v2 import REVOCATION_LIST_CODE, REVOCATION_PUSH_CODE, sort_status_evidence_v2, sorted_unique_strings_v2
from .types_v2 import MAX_SAFE_INTEGER, StatusEvidenceEntryV2, is_int, valid_prefixed_digest_v2, valid_v2_id


@dataclass
class V2StatusAssessment:
    """Deterministic aggregate of one result for every issuer-scoped
    certificate in a verified chain."""

    assessment: str = ""
    reason: str = ""
    evidence: list = field(default_factory=list)
    fresh_until: int = 0


@dataclass
class V2StatusRoleBindings:
    """Built from caller-authenticated trust state. ``reserved_key_ids`` must
    include every non-status role admitted by deployment trust history that
    is not in the evaluated chain. Historical keys may authenticate revoked
    evidence; only current keys authenticate current or stale state."""

    status_key_issuers: Optional[dict] = None  # status key ID -> issuer ID
    current_status_key_ids: Optional[dict] = None  # issuer ID -> status key ID
    reserved_key_ids: Optional[set] = None


def _has_accepted_status_history_per_issuer(evidence, issuer_ids) -> bool:
    from .verification_receipt_v2 import has_accepted_status_history_per_issuer_v2

    return has_accepted_status_history_per_issuer_v2(evidence, issuer_ids)


def aggregate_certificate_status_results_v2(checks, results, roles: V2StatusRoleBindings) -> V2StatusAssessment:
    """Exactly one reducer result per requested CertificateRef, in order.
    Revocation takes precedence over unavailable, which takes precedence
    over stale, independent of chain order."""
    return aggregate_certificate_status_v2(checks, results, roles, False)


def aggregate_certificate_status_v2(checks, results, roles: V2StatusRoleBindings, allow_unbound_issuers: bool) -> V2StatusAssessment:
    """The shared aggregator. ``allow_unbound_issuers`` is used only by the
    live verifier, which reports an issuer without authenticated status
    configuration as unavailable instead of aborting."""
    if not checks or len(checks) != len(results):
        raise ValueError("v2 status aggregation requires one result for every non-empty certificate list")
    validate_v2_status_role_bindings(roles, checks, allow_unbound_issuers)
    assessment = V2StatusAssessment(assessment="current", evidence=[])
    seen: set = set()
    digest_bindings: dict = {}
    invalid_digests: set = set()
    issuer_ids: list = []
    seen_certificates: set = set()
    issuer_set: set = set()
    subject_set: set = set()
    for i, check in enumerate(checks):
        if (
            not is_int(check.delegation_index) or check.delegation_index != i or not valid_v2_id(check.issuer_id)
            or not valid_v2_id(check.subject_id) or not isinstance(check.cert_id, str) or check.cert_id == ""
        ):
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
    revoked_candidates: list = []
    issuer_history: dict = {}
    for i, check in enumerate(checks):
        result = results[i]
        result_valid = True
        for evidence in result.evidence or []:
            if (
                not isinstance(evidence, StatusEvidenceEntryV2) or evidence.issuer_id != check.issuer_id
                or not valid_v2_id(evidence.status_key_id) or not is_int(evidence.sequence)
                or evidence.sequence <= 0 or evidence.sequence > MAX_SAFE_INTEGER
                or not valid_v2_status_evidence_digest(evidence.digest)
                or evidence.object_type not in (REVOCATION_LIST_CODE, REVOCATION_PUSH_CODE)
            ):
                result_valid = False
                continue
            if evidence.status_key_id in issuer_set or evidence.status_key_id in subject_set:
                result_valid = False
                continue
            if (
                evidence.status_key_id in roles.reserved_key_ids
                or roles.status_key_issuers.get(evidence.status_key_id, "") != evidence.issuer_id
                or (result.status != "revoked" and roles.current_status_key_ids.get(evidence.issuer_id, "") != evidence.status_key_id)
            ):
                result_valid = False
                continue
            prior = digest_bindings.get(evidence.digest)
            if prior is not None and prior != evidence:
                invalid_digests.add(evidence.digest)
            digest_bindings[evidence.digest] = evidence
            if evidence not in seen:
                seen.add(evidence)
                assessment.evidence.append(evidence)
        status = result.status
        if status == "not_revoked":
            result_valid = (
                result_valid and result.reason == "" and is_int(result.fresh_until) and 0 < result.fresh_until <= MAX_SAFE_INTEGER
                and valid_current_status_evidence_v2(result.evidence, check.issuer_id)
            )
            if result_valid:
                if assessment.fresh_until == 0 or result.fresh_until < assessment.fresh_until:
                    assessment.fresh_until = result.fresh_until
                result_valid = _add_issuer_history(issuer_history, check.issuer_id, result.evidence)
        elif status == "revoked":
            result_valid = result_valid and result.reason == "" and len(result.evidence or []) > 0
            if result_valid:
                revoked_candidates.append(i)
        elif status == "indeterminate":
            if result.reason == "unavailable":
                any_unavailable = True
            elif result.reason == "stale":
                result_valid = result_valid and valid_current_status_evidence_v2(result.evidence, check.issuer_id)
                if result_valid:
                    result_valid = _add_issuer_history(issuer_history, check.issuer_id, result.evidence)
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
        valid = len(results[i].evidence or []) > 0
        for evidence in results[i].evidence:
            if evidence.digest in invalid_digests:
                valid = False
                break
        any_revoked = any_revoked or valid
    assessment.evidence = sort_status_evidence_v2(assessment.evidence)
    if any_revoked:
        assessment.assessment, assessment.reason = "revoked", "delegation_revoked"
    elif invalid_result or any_unavailable:
        assessment.assessment, assessment.reason = "unavailable", "status_unavailable"
    elif any_stale:
        assessment.assessment, assessment.reason = "stale", "status_stale"
    elif not _has_accepted_status_history_per_issuer(assessment.evidence, sorted_unique_strings_v2(issuer_ids)):
        assessment.assessment, assessment.reason = "unavailable", "status_unavailable"
    if assessment.assessment != "current":
        assessment.fresh_until = 0
    return assessment


def validate_v2_status_role_bindings(roles: V2StatusRoleBindings, checks, allow_unbound_issuers: bool) -> None:
    if (
        not isinstance(roles, V2StatusRoleBindings) or roles.status_key_issuers is None
        or roles.current_status_key_ids is None or roles.reserved_key_ids is None
    ):
        raise ValueError("v2 status aggregation requires authenticated status-key role bindings")
    issuers = {check.issuer_id for check in checks}
    for key_id, issuer_id in roles.status_key_issuers.items():
        if not valid_v2_id(key_id) or not valid_v2_id(issuer_id):
            raise ValueError("authenticated status-key binding is malformed")
        if key_id in roles.reserved_key_ids:
            raise ValueError("status key collides with a reserved non-status key role")
    for issuer_id in issuers:
        if issuer_id not in roles.current_status_key_ids and allow_unbound_issuers:
            continue
        key_id = roles.current_status_key_ids.get(issuer_id, "")
        if roles.status_key_issuers.get(key_id, "") != issuer_id:
            raise ValueError("issuer lacks an authenticated current status-key binding")
    for key_id in roles.reserved_key_ids:
        if not valid_v2_id(key_id):
            raise ValueError("reserved non-status key ID is malformed")


def _add_issuer_history(histories: dict, issuer_id: str, evidence) -> bool:
    canonical = sort_status_evidence_v2(list(evidence or []))
    prior = histories.get(issuer_id)
    if prior is None:
        histories[issuer_id] = canonical
        return True
    return prior == canonical


def valid_current_status_evidence_v2(evidence, issuer_id: str) -> bool:
    if not evidence:
        return False
    base_count = 0
    base = None
    pushes = []
    for entry in evidence:
        if entry.issuer_id != issuer_id:
            return False
        if entry.object_type == REVOCATION_LIST_CODE:
            base_count += 1
            base = entry
        elif entry.object_type == REVOCATION_PUSH_CODE:
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


def valid_v2_status_evidence_digest(value: object) -> bool:
    """``sha384:`` and 96 lowercase hexadecimal characters."""
    return valid_prefixed_digest_v2(value)
