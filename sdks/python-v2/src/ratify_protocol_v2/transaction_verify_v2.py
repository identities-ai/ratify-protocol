"""Composed transaction-receipt verification (mirrors Go
transaction_verify_v2.go, SPEC-v2 §5.7).

The result is evidence about signed authority, never an authorization
decision: ``actionable`` is always False. No live challenge is consumed and
request-context constraints are never evaluated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import context_v2
from .authorization_v2 import SCOPE_IDENTITY_DELEGATE, V2CertificateStatusCheck
from .clock_bounds_v2 import checked_add_v2, valid_v2_timestamp
from .errors_v2 import V2Error, V2ErrorClass, classified
from .scope import intersect_scopes, validate_scopes_v2
from .signing_v2 import key_id_v2
from .types_v2 import is_int
from .verify_v2 import (
    V2_TRUST_TRUSTED,
    V2_TRUST_UNTRUSTED,
    V2VerifyCallbacks,
    V2VerifyRequest,
    _call_v2_trust_safely,
    _validate_v2_status_configuration,
)
from .verify_v2_preflight import equal_hybrid_public_keys

FRESHNESS_UNVERIFIED_V2 = "freshness_unverified"
V2_MAX_FUTURE_SKEW_SECONDS = 300
V2_MAX_DELEGATION_LIFETIME_SECONDS = 315360000


@dataclass
class TransactionVerifySourcesV2:
    """Caller-authenticated trust and status sources, shaped like the live
    verifier's callbacks and configuration. A missing trust source means
    trust is unavailable; a missing status source, journal, or status key
    makes that issuer's status unavailable."""

    trust: Optional[Callable] = None
    status_evidence: Optional[Callable] = None
    status_journal: object = None
    status_keys: dict = field(default_factory=dict)
    status_policy: object = None


@dataclass
class TransactionVerifyRequestV2:
    """``now`` is the caller-supplied authoritative evaluation time."""

    receipt: bytes = b""
    now: int = 0
    future_skew_seconds: int = 0


@dataclass
class TransactionPartyVerificationV2:
    party_id: str = ""
    agent_id: str = ""
    required_scope: str = ""
    trust_assessment: str = "unavailable"
    delegation_assessment: str = "not_evaluated"
    delegation_expires_at: Optional[int] = None
    status_assessment: str = "not_evaluated"
    scope_assessment: str = "not_evaluated"
    freshness: str = FRESHNESS_UNVERIFIED_V2
    status_evidence: list = field(default_factory=list)

    def to_json_dict(self) -> dict:
        return {
            "party_id": self.party_id, "agent_id": self.agent_id, "required_scope": self.required_scope,
            "trust_assessment": self.trust_assessment, "delegation_assessment": self.delegation_assessment,
            "delegation_expires_at": self.delegation_expires_at, "status_assessment": self.status_assessment,
            "scope_assessment": self.scope_assessment, "freshness": self.freshness,
            "status_evidence_digests": [e.to_canonical_dict() for e in self.status_evidence],
        }


@dataclass
class TransactionReceiptVerificationV2:
    """Never an authorization decision: ``actionable`` is always False."""

    transaction_id: str = ""
    parties: list = field(default_factory=list)

    @property
    def actionable(self) -> bool:
        return False

    def to_json_dict(self) -> dict:
        return {"transaction_id": self.transaction_id, "actionable": False,
                "parties": [p.to_json_dict() for p in self.parties]}


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def verify_transaction_receipt_v2(ctx: context_v2.Context, req: TransactionVerifyRequestV2,
                                  sources: TransactionVerifySourcesV2) -> TransactionReceiptVerificationV2:
    """Go ``VerifyTransactionReceiptV2``. Any receipt failure raises its error
    class and invokes no provider; a cancelled context raises its error."""
    from .transaction_receipt_v2 import decode_transaction_receipt_v2

    if not isinstance(ctx, context_v2.Context):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "transaction verification requires a context")
    if not isinstance(req, TransactionVerifyRequestV2) or not isinstance(sources, TransactionVerifySourcesV2):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "transaction verification request or sources have the wrong type")
    _validate_v2_transaction_verify_configuration(req, sources)
    if not isinstance(req.receipt, (bytes, bytearray)):
        raise V2Error(V2ErrorClass.MALFORMED, "transaction receipt must be bytes")
    receipt = decode_transaction_receipt_v2(bytes(req.receipt))
    result = TransactionReceiptVerificationV2(transaction_id=receipt.transaction_id, parties=[])
    for party in receipt.parties:
        err = ctx.err()
        if err is not None:
            raise err
        result.parties.append(_verify_transaction_party_v2(ctx, party, req, sources))
    return result


def _validate_v2_transaction_verify_configuration(req: TransactionVerifyRequestV2, sources: TransactionVerifySourcesV2) -> None:
    if not valid_v2_timestamp(req.now):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "transaction verification time is outside 0..253402300799")
    if not is_int(req.future_skew_seconds) or req.future_skew_seconds < 0 or req.future_skew_seconds > V2_MAX_FUTURE_SKEW_SECONDS:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "transaction verification future skew must be 0..300 seconds")
    _validate_v2_status_configuration(sources.status_keys, sources.status_policy)


def _verify_transaction_party_v2(ctx, party, req: TransactionVerifyRequestV2, sources: TransactionVerifySourcesV2) -> TransactionPartyVerificationV2:
    from .status_provenance_v2 import _run_v2_status_stage

    out = TransactionPartyVerificationV2(party_id=party.party_id, agent_id=party.agent_id, required_scope=party.required_scope,
                                         status_evidence=[])
    bundle = party.proof_bundle
    chain = list(bundle.delegations)
    root = chain[-1]  # decoding rejects an empty chain
    resolution, err = _call_v2_trust_safely(ctx, sources.trust, list(chain))
    if err is not None and ctx.err() is not None:
        raise ctx.err()
    if err is None and sources.trust is not None:
        if resolution.outcome == V2_TRUST_TRUSTED:
            try:
                root_id = key_id_v2(resolution.root_key)
            except Exception:  # noqa: BLE001
                root_id = None
            if root_id is not None and root_id == root.issuer_id and equal_hybrid_public_keys(resolution.root_key, root.issuer_pub_key):
                out.trust_assessment = "trusted"
        elif resolution.outcome == V2_TRUST_UNTRUSTED:
            out.trust_assessment = "untrusted"
    if out.trust_assessment != "trusted":
        return out

    # Delegation validity uses the §6.7 rules at the evaluation time.
    out.delegation_assessment = "current"
    earliest = chain[0].expires_at
    for cert in chain:
        earliest = min(earliest, cert.expires_at)
        latest_issue, ok = checked_add_v2(req.now, req.future_skew_seconds)
        if (not ok or cert.issued_at >= cert.expires_at or cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS
                or cert.issued_at > latest_issue):
            out.delegation_assessment = "invalid"
        elif req.now >= cert.expires_at and out.delegation_assessment == "current":
            out.delegation_assessment = "expired"
    out.delegation_expires_at = earliest

    checks = [V2CertificateStatusCheck(delegation_index=i, issuer_id=c.issuer_id, subject_id=c.subject_id, cert_id=c.cert_id)
              for i, c in enumerate(chain)]
    stage = _run_v2_status_stage(ctx, bundle, checks,
                                 V2VerifyRequest(status_keys=sources.status_keys, status_policy=sources.status_policy),
                                 V2VerifyCallbacks(status_evidence=sources.status_evidence, status_journal=sources.status_journal),
                                 req.now)
    if stage.cancelled is not None:
        raise stage.cancelled
    out.status_assessment = stage.assessment.assessment
    out.status_evidence = list(stage.assessment.evidence or [])

    out.scope_assessment = "covered"
    for cert in chain:
        try:
            validate_scopes_v2(cert.scope)
        except Exception:  # noqa: BLE001
            out.scope_assessment = "invalid_scope"
            return out
    for i in range(len(chain) - 1):
        if SCOPE_IDENTITY_DELEGATE not in chain[i + 1].scope:
            out.scope_assessment = "delegation_not_authorized"
            return out
    if party.required_scope not in intersect_scopes(*[list(c.scope) for c in chain]):
        out.scope_assessment = "not_covered"
    return out
