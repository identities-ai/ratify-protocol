"""Protocol v2 verification receipts, prepared outbox bodies, and receipt-log
verification (mirrors Go verification_receipt_v2.go and
verification_receipt_body_v2.go)."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Optional

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .errors_v2 import V2Error, V2ErrorClass
from .protocol_v2 import (
    ProofBundleV2,
    _run,
    bundle_hash_v2,
    check_keys,
    decode_signature,
    encode_proof_bundle_v2,
    get_bytes,
    get_int,
    get_str,
    get_str_list,
    key_dict,
    lower_hex_string,
    require_fields,
    valid_prefixed_digest_v2,
    valid_v2_id,
    validate_hybrid_signature_v2,
    validate_required_scope_v2,
    validate_scopes_v2,
)
from .scope import scope_wildcards
from .signing_v2 import VERIFICATION_RECEIPT, key_id_v2, public_key_of, _sign_v2_statement, verify_v2_statement
from .types import MAX_PROOF_BUNDLE_BYTES, HybridPrivateKey, HybridPublicKey, HybridSignature
from .witness_v2 import ZERO_HASH, WitnessEntryV2Result, _validate_log_head, log_position_result, statement_body_digest_v2


@dataclass(frozen=True, order=False)
class StatusEvidenceEntryV2:
    issuer_id: str
    status_key_id: str
    sequence: int
    object_type: int
    digest: str


def _evidence_sort_key(e: StatusEvidenceEntryV2):
    return (e.issuer_id, e.status_key_id, e.sequence, e.object_type, e.digest)


@dataclass
class VerificationReceiptV2:
    version: int = 2
    log_id: str = ""
    sequence: int = 0
    verifier_id: str = ""
    agent_id: str = ""
    human_id: str = ""
    bundle_hash: str = ""
    issuer_ids: Optional[list[str]] = None
    decision: str = ""
    decision_reason: str = ""
    identity_status: str = ""
    trust_assessment: str = ""
    status_assessment: str = ""
    challenge_assessment: str = ""
    context_assessment: str = ""
    context_policy_digest: Optional[str] = None
    verified_at: int = 0
    required_scope: str = ""
    granted_scope: Optional[list[str]] = None
    status_evidence: Optional[list[StatusEvidenceEntryV2]] = None
    previous_receipt_hash: bytes = b""
    signature: HybridSignature = field(default_factory=lambda: HybridSignature(b"", b""))


@dataclass
class ReceiptV2Head:
    log_id: str
    verifier_id: str
    sequence: int = 0
    head_hash: bytes = ZERO_HASH
    accepted_digests: dict[int, bytes] = field(default_factory=dict)
    frozen: bool = False


VERIFICATION_RECEIPT_V2_FIELDS = (
    "version", "log_id", "sequence", "verifier_id", "bundle_hash", "issuer_ids",
    "decision", "decision_reason", "identity_status", "trust_assessment",
    "status_assessment", "challenge_assessment", "context_assessment",
    "context_policy_digest", "verified_at", "required_scope", "granted_scope",
    "status_evidence_digests", "previous_receipt_hash", "signature",
)
_WIRE_KEYS = VERIFICATION_RECEIPT_V2_FIELDS + ("agent_id", "human_id")
_BODY_REQUIRED = (
    "version", "verifier_id", "bundle_hash", "issuer_ids", "decision", "decision_reason",
    "identity_status", "trust_assessment", "status_assessment", "challenge_assessment",
    "context_assessment", "context_policy_digest", "verified_at", "required_scope",
    "granted_scope", "status_evidence_digests",
)
_BODY_KEYS = _BODY_REQUIRED + ("agent_id", "human_id")


def _evidence_dict(e: StatusEvidenceEntryV2) -> dict:
    return {"digest": e.digest, "issuer_id": e.issuer_id, "object_type_code": e.object_type,
            "sequence": e.sequence, "status_key_id": e.status_key_id}


def _body_dict(r: VerificationReceiptV2) -> dict:
    out = {
        "bundle_hash": r.bundle_hash, "challenge_assessment": r.challenge_assessment,
        "context_assessment": r.context_assessment, "context_policy_digest": r.context_policy_digest,
        "decision": r.decision, "decision_reason": r.decision_reason, "granted_scope": r.granted_scope,
        "identity_status": r.identity_status, "issuer_ids": r.issuer_ids, "required_scope": r.required_scope,
        "status_assessment": r.status_assessment,
        "status_evidence_digests": None if r.status_evidence is None else [_evidence_dict(e) for e in r.status_evidence],
        "trust_assessment": r.trust_assessment, "verified_at": r.verified_at, "verifier_id": r.verifier_id,
        "version": r.version,
    }
    if r.agent_id:
        out["agent_id"] = r.agent_id
    if r.human_id:
        out["human_id"] = r.human_id
    return out


def _signable_dict(r: VerificationReceiptV2) -> dict:
    out = _body_dict(r)
    out.update(log_id=r.log_id, previous_receipt_hash=bytes(r.previous_receipt_hash), sequence=r.sequence)
    return out


def receipt_v2_signable_bytes(r: VerificationReceiptV2) -> bytes:
    return canonical(_signable_dict(r))


def _decode_evidence(value) -> Optional[list[StatusEvidenceEntryV2]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("wire v2: status_evidence_digests must be an array")
    out = []
    for item in value:
        item = {} if item is None else item
        if not isinstance(item, dict):
            raise ValueError("wire v2: status evidence entries must be objects")
        check_keys(item, ("digest", "issuer_id", "object_type_code", "sequence", "status_key_id"), "status evidence")
        out.append(StatusEvidenceEntryV2(
            issuer_id=get_str(item, "issuer_id"), status_key_id=get_str(item, "status_key_id"),
            sequence=get_int(item, "sequence"), object_type=get_int(item, "object_type_code", 0, 0xFFFF),
            digest=get_str(item, "digest"),
        ))
    return out


def _receipt_from_obj(obj: dict, allowed) -> VerificationReceiptV2:
    check_keys(obj, allowed, "verification receipt")
    cpd = obj.get("context_policy_digest")
    if cpd is not None and not isinstance(cpd, str):
        raise ValueError("wire v2: context_policy_digest must be a string or null")
    return VerificationReceiptV2(
        version=get_int(obj, "version"), log_id=get_str(obj, "log_id"), sequence=get_int(obj, "sequence"),
        verifier_id=get_str(obj, "verifier_id"), agent_id=get_str(obj, "agent_id"), human_id=get_str(obj, "human_id"),
        bundle_hash=get_str(obj, "bundle_hash"), issuer_ids=get_str_list(obj, "issuer_ids"),
        decision=get_str(obj, "decision"), decision_reason=get_str(obj, "decision_reason"),
        identity_status=get_str(obj, "identity_status"), trust_assessment=get_str(obj, "trust_assessment"),
        status_assessment=get_str(obj, "status_assessment"), challenge_assessment=get_str(obj, "challenge_assessment"),
        context_assessment=get_str(obj, "context_assessment"), context_policy_digest=cpd,
        verified_at=get_int(obj, "verified_at"), required_scope=get_str(obj, "required_scope"),
        granted_scope=get_str_list(obj, "granted_scope"),
        status_evidence=_decode_evidence(obj.get("status_evidence_digests")),
        previous_receipt_hash=get_bytes(obj, "previous_receipt_hash") or b"",
        signature=decode_signature(obj.get("signature")),
    )


# ---------------------------------------------------------------------------
# Validation


def _sorted_unique_ids(values: list[str]) -> bool:
    for i, value in enumerate(values):
        if not valid_v2_id(value) or (i > 0 and values[i - 1] >= value):
            return False
    return True


def _sorted_granted_scopes(values: list[str]) -> bool:
    if not values:
        return True
    try:
        validate_scopes_v2(values)
    except ValueError:
        return False
    wildcards = scope_wildcards()
    for i, value in enumerate(values):
        if value in wildcards or (i > 0 and values[i - 1] >= value):
            return False
    return True


def has_accepted_status_history_per_issuer_v2(evidence: list[StatusEvidenceEntryV2], issuer_ids: list[str]) -> bool:
    for issuer_id in issuer_ids:
        base_sequence = 0
        status_key_id = ""
        pushes: set[int] = set()
        for entry in evidence:
            if entry.issuer_id != issuer_id:
                continue
            if status_key_id == "":
                status_key_id = entry.status_key_id
            elif status_key_id != entry.status_key_id:
                return False
            if entry.object_type == 3:
                if base_sequence != 0:
                    return False
                base_sequence = entry.sequence
            else:
                if entry.sequence in pushes:
                    return False
                pushes.add(entry.sequence)
        if base_sequence == 0:
            return False
        if any(seq <= base_sequence for seq in pushes):
            return False
        for seq in range(base_sequence + 1, base_sequence + len(pushes) + 1):
            if seq not in pushes:
                return False
    return len(issuer_ids) > 0


def _sorted_evidence(values, issuer_ids, verifier_id: str, agent_id: str) -> bool:
    issuer_set = set(issuer_ids)
    status_key_issuers: dict[str, str] = {}
    for i, value in enumerate(values):
        prior = status_key_issuers.get(value.status_key_id)
        if prior is not None and prior != value.issuer_id:
            return False
        status_key_issuers[value.status_key_id] = value.issuer_id
        if (
            value.issuer_id not in issuer_set or not valid_v2_id(value.status_key_id)
            or value.status_key_id in issuer_set or value.status_key_id == verifier_id
            or (agent_id != "" and value.status_key_id == agent_id)
            or value.sequence <= 0 or value.sequence > MAX_SAFE_INTEGER
            or value.object_type not in (3, 5) or not valid_prefixed_digest_v2(value.digest)
        ):
            return False
        if i > 0 and _evidence_sort_key(values[i - 1]) >= _evidence_sort_key(value):
            return False
    return True


_DECISION_REASONS = frozenset({
    "authorized", "not_delegated", "delegation_not_authorized", "delegation_expired",
    "delegation_revoked", "scope_denied", "constraint_denied", "constraint_unverifiable",
    "constraint_unknown", "invalid_scope", "proof_invalid", "unauthorized", "status_stale",
    "status_unavailable", "action_context_unverified", "trust_unavailable", "evaluation_interrupted",
})
_DENY_PAIRS = {
    "not_delegated": "delegation_not_authorized", "delegation_not_authorized": "delegation_not_authorized",
    "delegation_expired": "expired", "delegation_revoked": "revoked", "scope_denied": "scope_denied",
    "invalid_scope": "invalid_scope", "constraint_denied": "constraint_denied",
    "constraint_unverifiable": "constraint_unverifiable", "constraint_unknown": "constraint_unknown",
    "proof_invalid": "invalid", "unauthorized": "unauthorized",
}
_CONSTRAINT_REASONS = ("constraint_denied", "constraint_unverifiable", "constraint_unknown")


def _validate_receipt_decision(r: VerificationReceiptV2) -> None:
    reason, trust, status, ctx = r.decision_reason, r.trust_assessment, r.status_assessment, r.context_assessment
    evidence, granted = r.status_evidence, r.granted_scope
    if reason not in _DECISION_REASONS:
        raise ValueError("wire v2: receipt decision_reason is invalid")
    if trust not in ("trusted", "untrusted", "unavailable", "not_evaluated"):
        raise ValueError("wire v2: receipt trust_assessment is invalid")
    if status not in ("current", "revoked", "stale", "unavailable", "not_evaluated"):
        raise ValueError("wire v2: receipt status_assessment is invalid")
    if ctx not in ("bound", "not_required", "unbound", "unverified", "mismatch", "not_evaluated"):
        raise ValueError("wire v2: receipt context_assessment is invalid")
    if r.decision == "allow":
        if (
            reason != "authorized" or r.identity_status != "authorized_agent" or trust != "trusted"
            or status != "current" or not evidence or not granted or r.required_scope not in granted
            or (ctx != "bound" and ctx != "not_required") or r.context_policy_digest is None
        ):
            raise ValueError("wire v2: allow receipt violates authorization, status, context, or scope requirements")
        return
    if r.decision == "deny":
        if granted or _DENY_PAIRS.get(reason) != r.identity_status:
            raise ValueError("wire v2: deny receipt has an invalid reason/status pair or granted scope")
        if reason == "not_delegated" and r.issuer_ids:
            raise ValueError("wire v2: not_delegated receipt cannot contain certificate issuers")
        if (reason == "scope_denied" or reason in _CONSTRAINT_REASONS) and status != "current":
            raise ValueError("wire v2: post-status local policy denial requires current status")
        if (
            (reason == "unauthorized" and trust != "untrusted")
            or (reason == "not_delegated" and trust != "not_evaluated")
            or (reason not in ("unauthorized", "not_delegated") and trust != "trusted")
        ):
            raise ValueError("wire v2: deny receipt trust assessment is inconsistent")
        if (
            (reason == "delegation_revoked" and status != "revoked")
            or (reason == "not_delegated" and status != "not_evaluated")
            or (reason not in ("delegation_revoked", "not_delegated") and status != "not_evaluated"
                and not (status == "current" and (reason == "scope_denied" or reason in _CONSTRAINT_REASONS)))
        ):
            raise ValueError("wire v2: deny receipt status assessment is inconsistent")
        if (reason == "not_delegated" and ctx != "not_evaluated") or (reason == "unauthorized" and ctx != "not_evaluated"):
            raise ValueError("wire v2: deny receipt context assessment is inconsistent")
        if reason == "delegation_revoked" and ctx == "not_evaluated":
            raise ValueError("wire v2: delegation_revoked receipt must retain its completed context assessment")
        if reason not in ("delegation_revoked", "scope_denied", *_CONSTRAINT_REASONS, "not_delegated", "unauthorized") and ctx != "not_evaluated":
            raise ValueError("wire v2: context assessment must be not_evaluated for this deny result")
        if (reason == "scope_denied" and ctx == "not_evaluated") or (
            reason in _CONSTRAINT_REASONS and ctx not in ("bound", "not_required")
            and not (reason == "constraint_denied" and ctx == "mismatch")
        ):
            raise ValueError("wire v2: constraint denial must retain its completed context assessment")
        if reason in ("not_delegated", "unauthorized") and evidence:
            raise ValueError("wire v2: status evidence is not evaluated for this deny result")
        if reason == "constraint_denied" and ctx == "mismatch" and r.identity_status != "constraint_denied":
            raise ValueError("wire v2: context mismatch must be a constraint denial")
        return
    if r.decision != "indeterminate" or granted or r.identity_status != "authorization_unverified":
        raise ValueError("wire v2: receipt decision or indeterminate identity/scope is invalid")
    if reason == "status_stale":
        if trust != "trusted" or status != "stale" or ctx == "not_evaluated":
            raise ValueError("wire v2: status_stale assessment tuple is invalid")
    elif reason == "status_unavailable":
        if trust != "trusted" or status != "unavailable" or ctx == "not_evaluated":
            raise ValueError("wire v2: status_unavailable assessment tuple is invalid")
    elif reason == "trust_unavailable":
        if trust != "unavailable" or status != "not_evaluated" or ctx != "not_evaluated" or evidence:
            raise ValueError("wire v2: trust_unavailable assessment tuple is invalid")
    elif reason == "action_context_unverified":
        if trust != "trusted" or status != "current" or ctx not in ("unbound", "unverified"):
            raise ValueError("wire v2: action_context_unverified assessment tuple is invalid")
    elif reason == "evaluation_interrupted":
        if (
            trust == "untrusted" or status in ("revoked", "stale") or ctx in ("unbound", "unverified", "mismatch")
            or (trust == "not_evaluated" and (status != "not_evaluated" or ctx != "not_evaluated"))
            or (trust == "unavailable" and (status != "not_evaluated" or ctx != "not_evaluated"))
            or (trust == "trusted" and status not in ("not_evaluated", "unavailable", "current"))
            or (ctx == "not_evaluated" and status != "not_evaluated")
            or (status in ("unavailable", "current") and (trust != "trusted" or ctx not in ("bound", "not_required")))
        ):
            raise ValueError("wire v2: evaluation_interrupted assessment tuple is invalid")
    else:
        raise ValueError("wire v2: indeterminate reason is invalid")


def validate_verification_receipt_v2(r: VerificationReceiptV2, signature: bool) -> None:
    if (
        r is None or r.version != 2 or len(r.log_id) != 32 or not lower_hex_string(r.log_id)
        or r.sequence <= 0 or r.sequence > MAX_SAFE_INTEGER
        or not -MAX_SAFE_INTEGER <= r.verified_at <= MAX_SAFE_INTEGER
    ):
        raise ValueError("wire v2: receipt version, log ID, sequence, or verified_at is invalid")
    if not valid_v2_id(r.verifier_id) or (r.agent_id != "" and not valid_v2_id(r.agent_id)):
        raise ValueError("wire v2: receipt verifier_id and optional agent_id must be v2 key IDs")
    if not valid_prefixed_digest_v2(r.bundle_hash) or len(r.previous_receipt_hash) != 48:
        raise ValueError("wire v2: receipt bundle hash or previous receipt hash is invalid")
    if r.issuer_ids is None or not _sorted_unique_ids(r.issuer_ids) or r.granted_scope is None or r.status_evidence is None:
        raise ValueError("wire v2: receipt arrays must be present and canonical")
    if r.decision_reason not in ("not_delegated", "evaluation_interrupted") and not r.issuer_ids:
        raise ValueError("wire v2: a receipt for a delegated decision must identify its certificate issuers")
    if r.decision_reason == "evaluation_interrupted" and not r.issuer_ids and (
        r.trust_assessment != "not_evaluated" or r.status_assessment != "not_evaluated"
        or r.context_assessment != "not_evaluated" or r.status_evidence
    ):
        raise ValueError("wire v2: interrupted empty-chain receipt cannot claim completed trust, status, or context checks")
    validate_required_scope_v2(r.required_scope)
    zero = bytes(r.previous_receipt_hash) == ZERO_HASH
    if (r.sequence == 1 and not zero) or (r.sequence > 1 and zero):
        raise ValueError("wire v2: previous_receipt_hash is inconsistent with receipt sequence")
    if not _sorted_granted_scopes(r.granted_scope):
        raise ValueError("wire v2: granted_scope must be sorted, unique canonical scopes")
    if not _sorted_evidence(r.status_evidence, r.issuer_ids, r.verifier_id, r.agent_id):
        raise ValueError("wire v2: status evidence is invalid, duplicated, or not canonically sorted")
    if r.status_assessment in ("current", "revoked", "stale") and not r.status_evidence:
        raise ValueError("wire v2: evaluated status requires authenticated evidence")
    if r.context_policy_digest is not None and not valid_prefixed_digest_v2(r.context_policy_digest):
        raise ValueError("wire v2: context_policy_digest is invalid")
    if (r.context_assessment in ("not_evaluated", "unbound") and r.context_policy_digest is not None) or (
        r.context_assessment in ("bound", "not_required", "mismatch") and r.context_policy_digest is None
    ):
        raise ValueError("wire v2: context_policy_digest does not match context_assessment")
    if r.status_assessment == "not_evaluated" and r.status_evidence:
        raise ValueError("wire v2: status evidence cannot be present when status was not evaluated")
    if r.status_assessment in ("current", "stale") and not has_accepted_status_history_per_issuer_v2(r.status_evidence, r.issuer_ids):
        raise ValueError("wire v2: current or stale status requires one accepted full-list base and contiguous pushes for every issuer")
    if r.challenge_assessment != "current":
        raise ValueError("wire v2: terminal receipt challenge_assessment must be current")
    _validate_receipt_decision(r)
    if signature:
        validate_hybrid_signature_v2(r.signature)


# ---------------------------------------------------------------------------
# Codec


def verification_receipt_v2_digest(r: VerificationReceiptV2) -> bytes:
    validate_verification_receipt_v2(r, False)
    return statement_body_digest_v2(VERIFICATION_RECEIPT, receipt_v2_signable_bytes(r))


def encode_verification_receipt_v2(r: VerificationReceiptV2) -> bytes:
    validate_verification_receipt_v2(r, True)
    data = canonical({**_signable_dict(r), "signature": key_dict(r.signature)})
    if len(data) > MAX_PROOF_BUNDLE_BYTES:
        raise ValueError("wire v2: verification receipt exceeds the wire size limit")
    return data


def decode_verification_receipt_v2(data: bytes) -> VerificationReceiptV2:
    def run() -> VerificationReceiptV2:
        if len(data) > MAX_PROOF_BUNDLE_BYTES:
            raise ValueError("wire v2: verification receipt exceeds the wire size limit")
        obj = _v2json.check_wire_json(data, ("previous_receipt_hash",), ("bundle_hash",))
        require_fields(obj, VERIFICATION_RECEIPT_V2_FIELDS, ("context_policy_digest",))
        receipt = _receipt_from_obj(obj, _WIRE_KEYS)
        validate_verification_receipt_v2(receipt, True)
        try:
            canonical_bytes = encode_verification_receipt_v2(receipt)
        except ValueError:
            canonical_bytes = None
        if canonical_bytes != data:
            raise ValueError("wire v2: verification receipt is not canonical Ratify JSON")
        return receipt

    return _run(V2ErrorClass.MALFORMED, run)


def validate_verification_receipt_signable_v2(data: bytes) -> None:
    obj = _v2json.check_wire_json(data, ("previous_receipt_hash",), ("bundle_hash",))
    require_fields(obj, VERIFICATION_RECEIPT_V2_FIELDS[:-1], ("context_policy_digest",))
    if "signature" in obj:
        raise ValueError("signable body must exclude signature")
    receipt = _receipt_from_obj(obj, _WIRE_KEYS)
    validate_verification_receipt_v2(receipt, False)
    if receipt_v2_signable_bytes(receipt) != data:
        raise ValueError("signable body must use RatifyCanonicalJSON")


def sign_verification_receipt_v2(r: VerificationReceiptV2, verifier_private: HybridPrivateKey) -> VerificationReceiptV2:
    validate_verification_receipt_v2(r, False)
    if key_id_v2(public_key_of(verifier_private)) != r.verifier_id:
        raise ValueError("receipt verifier_id does not match signing key")
    body = receipt_v2_signable_bytes(r)
    result = replace(r, signature=_sign_v2_statement(VERIFICATION_RECEIPT, body, verifier_private))
    encode_verification_receipt_v2(result)
    return result


def validate_receipt_v2_head(head: ReceiptV2Head) -> None:
    if not valid_v2_id(head.verifier_id):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "caller receipt head is invalid")
    _validate_log_head(head.log_id, head.sequence, head.head_hash, head.accepted_digests, "receipt")


def verify_verification_receipt_v2(r: VerificationReceiptV2, verifier_public: HybridPublicKey,
                                   head: ReceiptV2Head) -> WitnessEntryV2Result:
    _run(V2ErrorClass.MALFORMED, lambda: validate_verification_receipt_v2(r, True))
    _run(V2ErrorClass.MALFORMED, lambda: encode_verification_receipt_v2(r))
    validate_receipt_v2_head(head)
    if r.log_id != head.log_id or r.verifier_id != head.verifier_id:
        raise V2Error(V2ErrorClass.LOG_STATE_MISMATCH,
                      "receipt log ID or verifier identity does not match caller-authenticated state")
    verifier_id = _run(V2ErrorClass.UNCLASSIFIED, lambda: key_id_v2(verifier_public))
    if r.verifier_id != verifier_id:
        raise V2Error(V2ErrorClass.LOG_STATE_MISMATCH, "receipt verifier_id does not match caller-authenticated key")
    verify_v2_statement(VERIFICATION_RECEIPT, receipt_v2_signable_bytes(r), r.signature, verifier_public)
    digest = verification_receipt_v2_digest(r)
    return log_position_result(r.sequence, r.previous_receipt_hash, digest, head.sequence, head.head_hash,
                               head.accepted_digests, head.frozen, head.log_id)


def check_verification_receipt_v2_bundle_binding(r: VerificationReceiptV2, bundle: ProofBundleV2) -> None:
    _run(V2ErrorClass.MALFORMED, lambda: validate_verification_receipt_v2(r, False))
    _run(V2ErrorClass.MALFORMED, lambda: encode_proof_bundle_v2(bundle))
    mismatch = V2ErrorClass.RECEIPT_BUNDLE_MISMATCH
    if r.verifier_id != bundle.verifier_id or (r.agent_id != "" and r.agent_id != bundle.agent_id):
        raise V2Error(mismatch, "receipt verifier or agent ID does not match the proof bundle")
    roles = {bundle.verifier_id, bundle.agent_id}
    for cert in bundle.delegations:
        roles.add(cert.issuer_id)
        roles.add(cert.subject_id)
    for evidence in r.status_evidence:
        if evidence.status_key_id in roles:
            raise V2Error(mismatch, "receipt status key ID overlaps a proof or verifier key role")
    if r.bundle_hash != bundle_hash_v2(bundle):
        raise V2Error(mismatch, "receipt bundle_hash does not match the proof bundle")
    if sorted({cert.issuer_id for cert in bundle.delegations}) != list(r.issuer_ids):
        raise V2Error(mismatch, "receipt issuer_ids do not match the proof bundle chain")


# ---------------------------------------------------------------------------
# Prepared outbox bodies


def verification_receipt_v2_body(r: VerificationReceiptV2) -> bytes:
    """The canonical content prepared before terminal commit (no log position,
    previous hash, or signature)."""
    if r is None:
        raise ValueError("wire v2: receipt body is nil")
    candidate = copy.copy(r)
    candidate.log_id = "0123456789abcdef0123456789abcdef"
    candidate.sequence = 1
    candidate.previous_receipt_hash = bytes(48)
    candidate.signature = HybridSignature(b"", b"")
    validate_verification_receipt_v2(candidate, False)
    candidate.sequence = MAX_SAFE_INTEGER
    candidate.previous_receipt_hash = b"\x01" + bytes(47)
    candidate.signature = HybridSignature(bytes(64), bytes(3309))
    encode_verification_receipt_v2(candidate)
    return canonical(_body_dict(r))


def decode_verification_receipt_body_v2(data: bytes) -> VerificationReceiptV2:
    def run() -> VerificationReceiptV2:
        if len(data) > MAX_PROOF_BUNDLE_BYTES:
            raise ValueError("wire v2: verification receipt body exceeds the wire size limit")
        obj = _v2json.check_wire_json(data, (), ("bundle_hash",))
        require_fields(obj, _BODY_REQUIRED, ("context_policy_digest",))
        receipt = _receipt_from_obj(obj, _BODY_KEYS)
        try:
            canonical_bytes = verification_receipt_v2_body(receipt)
        except ValueError as exc:
            raise ValueError(f"wire v2: verification receipt body is invalid or noncanonical: {exc}") from exc
        if canonical_bytes != data:
            raise ValueError("wire v2: verification receipt body is noncanonical")
        return receipt

    return _run(V2ErrorClass.MALFORMED, run)


def bind_verification_receipt_body_v2(data: bytes, head: ReceiptV2Head) -> VerificationReceiptV2:
    validate_receipt_v2_head(head)
    if head.frozen or head.sequence == MAX_SAFE_INTEGER:
        raise ValueError("wire v2: receipt log cannot accept another entry")
    receipt = decode_verification_receipt_body_v2(data)
    if receipt.verifier_id != head.verifier_id:
        raise ValueError("wire v2: prepared receipt verifier differs from authenticated log")
    receipt.log_id = head.log_id
    receipt.sequence = head.sequence + 1
    receipt.previous_receipt_hash = bytes(head.head_hash)
    validate_verification_receipt_v2(receipt, False)
    return receipt


def sign_prepared_verification_receipt_v2(data: bytes, head: ReceiptV2Head, private: HybridPrivateKey) -> VerificationReceiptV2:
    bound = bind_verification_receipt_body_v2(data, head)
    signed = sign_verification_receipt_v2(bound, private)
    if verification_receipt_v2_body(signed) != data:
        raise ValueError("wire v2: signed receipt differs from prepared body")
    return signed

