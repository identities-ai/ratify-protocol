"""Archival verification of stored v2 objects (SPEC-v2 §6.10).

Mirrors Go archival_v2.go. An archival result reports that one stored object
decoded strictly and that its signatures verify. It is NOT an authorization
decision and must never be used to allow an action: no challenge was
consumed, and no trust root, issuer status, revocation, expiry at the current
time, receipt-log position or rotation state was evaluated. Every result is
labelled ``freshness_unverified`` and is never actionable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import _v2json
from . import key_rotation_v2 as _kr
from . import protocol_v2 as _pv2
from . import signing_v2 as _sig
from . import transaction_receipt_v2 as _tx
from . import verification_receipt_v2 as _vr
from . import witness_v2 as _wv
from .errors_v2 import V2Error, V2ErrorClass, classify, error_class_of
from .types import HybridPublicKey

FRESHNESS_UNVERIFIED_V2 = "freshness_unverified"

_DELEGATION_CERTIFICATE = 0x0001
_REVOCATION_LIST = 0x0003
_KEY_ROTATION_AUTHORIZATION = 0x0004
_REVOCATION_PUSH = 0x0005
_WITNESS_ENTRY = 0x0006
_TRANSACTION_PARTY_STATEMENT = 0x0007
_VERIFICATION_RECEIPT = 0x0008
_KEY_ROTATION_PROOF_OF_POSSESSION = 0x0009


@dataclass(frozen=True)
class ArchivalVerificationV2:
    """One stored object verified for archive purposes. ``digest`` is
    ``sha384:`` + hex (bundle hash, StatementBodyDigest, or status evidence
    digest), or empty for certificates and transaction receipts.
    ``signer_key_ids`` lists the v2 key IDs whose signatures verified, in
    object order. ``freshness`` is always ``freshness_unverified`` and
    ``actionable`` is always False."""

    object_type: int
    freshness: str
    actionable: bool
    digest: str
    signer_key_ids: tuple

    def to_canonical_dict(self) -> dict:
        return {
            "actionable": False,
            "digest": self.digest,
            "freshness": self.freshness,
            "object_type_code": self.object_type,
            "signer_key_ids": list(self.signer_key_ids),
        }


def _archival_result_v2(code: int, digest: Optional[bytes], *signers: str) -> ArchivalVerificationV2:
    return ArchivalVerificationV2(
        object_type=code, freshness=FRESHNESS_UNVERIFIED_V2, actionable=False,
        digest="" if digest is None else "sha384:" + bytes(digest).hex(), signer_key_ids=tuple(signers),
    )


@dataclass
class ArchivalProofBundleResultV2:
    """The SPEC-v2 §6.10 archival result for a proof bundle. It has no
    decision field and is never actionable. ``error_class`` is empty when
    every check passed; ``err`` carries the diagnostic and is not part of the
    language-neutral result."""

    assessment: str = FRESHNESS_UNVERIFIED_V2
    actionable: bool = False
    bundle_hash: str = ""
    agent_id: str = ""
    issuer_ids: list = field(default_factory=list)
    error_class: str = ""
    err: Optional[BaseException] = None

    def to_json(self) -> bytes:
        """The language-neutral members, with ``error_class`` null on success."""
        return _v2json.canonical({
            "actionable": bool(self.actionable),
            "agent_id": self.agent_id,
            "assessment": self.assessment,
            "bundle_hash": self.bundle_hash,
            "error_class": self.error_class or None,
            "issuer_ids": list(self.issuer_ids or []),
        })


def verify_archival_proof_bundle_v2(data: bytes) -> ArchivalProofBundleResultV2:
    """Run only the signature-and-structure pre-claim steps on a stored proof
    bundle: bounded strict decode, key IDs, delegation digest, duplicate
    CertificateRef and linkage, and every certificate and challenge
    signature. Required-scope validation, expected-challenge checks and
    every provider are omitted."""
    result = ArchivalProofBundleResultV2()

    def fail(exc: BaseException) -> ArchivalProofBundleResultV2:
        result.error_class = error_class_of(exc)
        result.err = exc
        return result

    try:
        bundle = _pv2.decode_proof_bundle_v2(data)
    except Exception as exc:  # noqa: BLE001 - every failure carries its class
        return fail(classify(V2ErrorClass.MALFORMED, exc) if not isinstance(exc, V2Error) else exc)
    result.agent_id = bundle.agent_id
    try:
        result.bundle_hash = _pv2.bundle_hash_v2(bundle)
    except Exception as exc:  # noqa: BLE001
        return fail(classify(V2ErrorClass.MALFORMED, exc))
    result.issuer_ids = sorted({cert.issuer_id for cert in bundle.delegations or ()})
    try:
        _pv2.verify_proof_bundle_v2_signatures(bundle)
    except Exception as exc:  # noqa: BLE001
        return fail(exc)
    return result


def verify_archival_delegation_cert_v2(data: bytes) -> ArchivalVerificationV2:
    """Check one stored certificate and its issuer signature under the issuer
    key it carries."""
    cert = _pv2.decode_delegation_cert_v2(data)
    _pv2.verify_delegation_cert_v2_signature(cert)
    return _archival_result_v2(_DELEGATION_CERTIFICATE, None, cert.issuer_id)


def _status_key_id(status_key: HybridPublicKey) -> str:
    try:
        return _sig.key_id_v2(status_key)
    except Exception:  # noqa: BLE001 - Go ignores this error after verification
        return ""


def verify_archival_revocation_list_v2(data: bytes, issuer_id: str, status_key: HybridPublicKey) -> ArchivalVerificationV2:
    """Check a stored revocation list under a caller-authenticated issuer
    status key."""
    lst = _pv2.decode_revocation_list_v2(data)
    _pv2.verify_revocation_list_v2_signature(lst, issuer_id, status_key)
    try:
        digest = _pv2.status_evidence_digest(_REVOCATION_LIST, lst)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    return _archival_result_v2(_REVOCATION_LIST, digest, _status_key_id(status_key))


def verify_archival_revocation_push_v2(data: bytes, issuer_id: str, status_key: HybridPublicKey) -> ArchivalVerificationV2:
    """Check a stored revocation push under a caller-authenticated issuer
    status key."""
    push = _pv2.decode_revocation_push_v2(data)
    _pv2.verify_revocation_push_v2_signature(push, issuer_id, status_key)
    try:
        digest = _pv2.status_evidence_digest(_REVOCATION_PUSH, push)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    return _archival_result_v2(_REVOCATION_PUSH, digest, _status_key_id(status_key))


def verify_archival_key_rotation_statement_v2(data: bytes) -> ArchivalVerificationV2:
    """Check a stored rotation statement's old-key authorization and new-key
    proof of possession under the keys it names. It does not establish that
    ``old_key`` was the authority's current key."""
    stmt = _kr.decode_key_rotation_statement_v2(data)
    try:
        signable = _kr.key_rotation_signable_bytes_v2(stmt)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    try:
        _sig.verify_v2_statement(_KEY_ROTATION_AUTHORIZATION, signable, stmt.old_signature, stmt.old_key)
    except V2Error as exc:
        raise V2Error(exc.error_class, f"old-key rotation authorization: {exc}") from exc
    try:
        _sig.verify_v2_statement(_KEY_ROTATION_PROOF_OF_POSSESSION, signable, stmt.new_signature, stmt.new_key)
    except V2Error as exc:
        raise V2Error(exc.error_class, f"new-key proof of possession: {exc}") from exc
    try:
        digest = _kr.key_rotation_statement_v2_digest(stmt)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    return _archival_result_v2(_KEY_ROTATION_AUTHORIZATION, digest, stmt.old_key_id, stmt.new_key_id)


def verify_archival_witness_entry_v2(data: bytes, witness_public: HybridPublicKey) -> ArchivalVerificationV2:
    """Check a stored witness entry under a caller-authenticated witness key,
    without log position or fork checks."""
    entry = _wv.decode_witness_entry_v2(data)
    try:
        witness_id = _sig.key_id_v2(witness_public)
    except Exception:  # noqa: BLE001
        witness_id = None
    if witness_id is None or witness_id != entry.witness_id:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "witness key does not match witness_id")
    try:
        body = _wv.witness_entry_signable_bytes_v2(entry)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    _sig.verify_v2_statement(_WITNESS_ENTRY, body, entry.signature, witness_public)
    try:
        digest = _wv.witness_entry_v2_digest(entry)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    return _archival_result_v2(_WITNESS_ENTRY, digest, witness_id)


def verify_archival_verification_receipt_v2(data: bytes, verifier_public: HybridPublicKey) -> ArchivalVerificationV2:
    """Check a stored verification receipt under a caller-authenticated
    verifier key, without log position, fork or bundle-binding checks."""
    receipt = _vr.decode_verification_receipt_v2(data)
    try:
        verifier_id = _sig.key_id_v2(verifier_public)
    except Exception:  # noqa: BLE001
        verifier_id = None
    if verifier_id is None or verifier_id != receipt.verifier_id:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "verifier key does not match verifier_id")
    try:
        body = _vr.receipt_v2_signable_bytes(receipt)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    _sig.verify_v2_statement(_VERIFICATION_RECEIPT, body, receipt.signature, verifier_public)
    try:
        digest = _vr.verification_receipt_v2_digest(receipt)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    return _archival_result_v2(_VERIFICATION_RECEIPT, digest, verifier_id)


def verify_archival_transaction_receipt_v2(data: bytes) -> ArchivalVerificationV2:
    """Check a stored transaction receipt: canonical form, every party
    signature, and every embedded proof bundle's signatures, hash and
    transaction context (all enforced by the strict decoder). Use
    ``verify_transaction_receipt_v2`` for per-party trust and status."""
    receipt = _tx.decode_transaction_receipt_v2(data)
    return _archival_result_v2(
        _TRANSACTION_PARTY_STATEMENT, None, *[party.agent_id for party in receipt.parties]
    )
