"""Protocol v2 verifier context policy, receiver audience, and signed rate
reservation batches (mirrors Go context_policy_v2.go, audience_v2.go, and
rate_reservation_v2.go)."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from hashlib import sha384
from typing import Optional

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .protocol_v2 import (
    RECEIVER_AUDIENCE,
    ProofBundleV2,
    _go_unmarshal_constraint,
    constraint_canonical_json,
    valid_prefixed_digest_v2,
    valid_v2_id,
    validate_v2_constraint_fields,
)
from .types import MAX_IDENTIFIER_LENGTH_BYTES

VERIFY_SESSION_CONTEXT_PROFILE_V2 = "ratify.verify.session-context/v1"
VERIFY_SESSION_CONTEXT_FIELDS_V2 = ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"]
MAX_RATE = "max_rate"


class V2ContextPolicy:
    """Validated verifier-owned context policy. Its digest is derived from the
    canonical policy fields; the per-invocation expected context is excluded."""

    __slots__ = ("profile", "require_bound", "required_fields", "expected_session_context", "digest", "valid")

    def __init__(self, profile, require_bound, required_fields, expected_session_context, digest, valid=True):
        self.profile = profile
        self.require_bound = require_bound
        self.required_fields = list(required_fields)
        self.expected_session_context = None if expected_session_context is None else bytes(expected_session_context)
        self.digest = digest
        self.valid = valid


def new_v2_context_policy(profile: str, require_bound: bool, required_fields: list[str],
                          expected_session_context: Optional[bytes]) -> V2ContextPolicy:
    if not isinstance(profile, str) or profile == "":
        raise ValueError("v2 context policy profile must be non-empty valid UTF-8")
    seen = set()
    fields = []
    for i, name in enumerate(required_fields or []):
        if not isinstance(name, str) or name == "":
            raise ValueError(f"v2 context policy field {i} is empty or invalid UTF-8")
        if name in seen:
            raise ValueError(f"v2 context policy has duplicate field {name!r}")
        seen.add(name)
        fields.append(name)
    expected_len = len(expected_session_context or b"")
    if require_bound and (not fields or expected_len != 32):
        raise ValueError("bound v2 context policy requires fields and a 32-byte authenticated context")
    if not require_bound and expected_len != 0:
        raise ValueError("unbound v2 context policy cannot carry an expected context")
    if profile == VERIFY_SESSION_CONTEXT_PROFILE_V2 and (not require_bound or fields != VERIFY_SESSION_CONTEXT_FIELDS_V2):
        raise ValueError("Ratify Verify session-context policy must require the canonical field set")
    encoded = canonical({"profile": profile, "require_bound": bool(require_bound), "required_fields": fields, "version": 1})
    digest = "sha384:" + sha384(encoded).hexdigest()
    return V2ContextPolicy(profile, bool(require_bound), fields, expected_session_context, digest)


@dataclass
class V2ContextPolicyAssessment:
    assessment: str
    policy_digest: Optional[str] = None
    status: str = ""
    reason: str = ""
    detail: str = ""


def same_v2_context_policy(a: Optional[V2ContextPolicy], b: Optional[V2ContextPolicy]) -> bool:
    return (
        a is not None and b is not None and a.valid and b.valid and a.profile == b.profile
        and a.require_bound == b.require_bound and a.digest == b.digest
        and a.required_fields == b.required_fields
        and (a.expected_session_context or b"") == (b.expected_session_context or b"")
    )


def clone_v2_context_policy(policy: Optional[V2ContextPolicy]) -> Optional[V2ContextPolicy]:
    return None if policy is None else copy.copy(policy)


def evaluate_proof_bundle_v2_context_policy(bundle: Optional[ProofBundleV2],
                                            policy: Optional[V2ContextPolicy]) -> V2ContextPolicyAssessment:
    def failure(assessment: str, detail: str) -> V2ContextPolicyAssessment:
        return V2ContextPolicyAssessment(assessment, None, "authorization_unverified", "action_context_unverified", detail)

    if bundle is None:
        return failure("unverified", "proof bundle is unavailable")
    bound = "unverified" if bundle.session_context is not None else "unbound"
    if policy is None:
        return failure(bound, "no caller-authenticated context policy is configured")
    if not policy.valid or not policy.digest or not valid_prefixed_digest_v2(policy.digest):
        return failure(bound, "no valid caller-authenticated context policy is configured")
    if not policy.require_bound:
        return V2ContextPolicyAssessment("not_required", policy.digest, "passed")
    if bundle.session_context is None:
        return V2ContextPolicyAssessment("unverified", policy.digest, "authorization_unverified",
                                         "action_context_unverified", "required session context is absent")
    if bytes(bundle.session_context) != (policy.expected_session_context or b""):
        return V2ContextPolicyAssessment("mismatch", policy.digest, "constraint_denied", "constraint_denied",
                                         "proof session context does not match the verifier's authenticated context")
    return V2ContextPolicyAssessment("bound", policy.digest, "passed")


# ---------------------------------------------------------------------------
# Deferred constraints, receiver audience, and rate reservation


@dataclass
class V2DeferredConstraint:
    delegation_index: int
    constraint_index: int
    issuer_id: str
    cert_id: str
    type: str
    canonical_json: bytes


@dataclass
class V2AudienceMembership:
    """Caller-authenticated, complete membership result for one constrained
    link. Protocol does not authenticate this input."""
    delegation_index: int
    constraint_index: int
    receiver_id: str
    trust_domain_ids: list[str]
    issued_at: int
    expires_at: int
    evidence_digest: str


@dataclass
class V2AudienceAssessment:
    status: str
    evidence_digests: list[str] = field(default_factory=list)
    fresh_until: int = 0


def _sealed_constraint(item: V2DeferredConstraint):
    raw = _v2json.parse(item.canonical_json)
    validate_v2_constraint_fields(raw)
    constraint = _go_unmarshal_constraint(raw)
    if constraint_canonical_json(constraint) != bytes(item.canonical_json):
        raise ValueError("v2 deferred constraint is not canonical")
    return constraint, raw


def evaluate_receiver_audience_v2(deferred: list[V2DeferredConstraint], receiver_id: str,
                                  memberships: list[V2AudienceMembership], now: int,
                                  future_skew: int) -> V2AudienceAssessment:
    if not receiver_id or not -MAX_SAFE_INTEGER <= now <= MAX_SAFE_INTEGER or future_skew < 0 or future_skew > MAX_SAFE_INTEGER:
        raise ValueError("v2 audience requires a sealed receiver and valid security time")
    links = []
    seen_links = set()
    max_age = MAX_SAFE_INTEGER
    fresh_until = MAX_SAFE_INTEGER
    for item in deferred:
        if item.type != RECEIVER_AUDIENCE:
            continue
        key = (item.delegation_index, item.constraint_index)
        constraint, raw = _sealed_constraint(item)
        if item.delegation_index < 0 or item.constraint_index < 0 or key in seen_links:
            raise ValueError("v2 audience constraint has duplicate or invalid position")
        seen_links.add(key)
        if constraint.type != RECEIVER_AUDIENCE:
            raise ValueError("v2 sealed audience constraint has wrong type")
        params = raw.get("params") or {}
        exact = list(params.get("exact_receiver_ids") or [])
        domains = list(params.get("trust_domain_ids") or [])
        age = params.get("max_membership_age_seconds") or 0
        if domains and age <= 0:
            raise ValueError("v2 audience membership age must be positive")
        if domains and age < max_age:
            max_age = age
        links.append((exact, domains, item.delegation_index, item.constraint_index))
    if not links:
        raise ValueError("v2 audience stage has no audience constraints")
    denied = unavailable = False
    evidence: list[str] = []
    for exact, domains, delegation_index, constraint_index in links:
        if receiver_id in exact:
            continue
        if not domains:
            raise ValueError("v2 exact-only audience mismatch passed preflight")
        membership = None
        for candidate in memberships:
            if candidate.delegation_index == delegation_index and candidate.constraint_index == constraint_index:
                if membership is not None:
                    unavailable = True
                    membership = None
                    break
                membership = candidate
        if membership is None:
            unavailable = True
            continue
        m = membership
        if (
            m.receiver_id != receiver_id or not valid_prefixed_digest_v2(m.evidence_digest)
            or not -MAX_SAFE_INTEGER <= m.issued_at <= MAX_SAFE_INTEGER
            or not -MAX_SAFE_INTEGER <= m.expires_at <= MAX_SAFE_INTEGER
            or m.issued_at >= m.expires_at or now >= m.expires_at
            or (m.issued_at > now and m.issued_at - now > future_skew)
            or (now > m.issued_at and now - m.issued_at > max_age)
        ):
            unavailable = True
            continue
        seen = set()
        match = malformed = False
        for domain_id in m.trust_domain_ids or []:
            if domain_id == "" or domain_id in seen:
                malformed = True
                break
            seen.add(domain_id)
            match = match or domain_id in domains
        if malformed:
            unavailable = True
            continue
        evidence.append(m.evidence_digest)
        if not match:
            denied = True
        else:
            fresh_until = min(fresh_until, m.expires_at, m.issued_at + max_age)
    evidence = sorted(set(evidence))
    if denied:
        return V2AudienceAssessment("constraint_denied", evidence)
    if unavailable:
        return V2AudienceAssessment("constraint_unverifiable", evidence)
    return V2AudienceAssessment("passed", evidence, fresh_until)


@dataclass(frozen=True)
class V2RateReservation:
    """One issuer-scoped rolling-window counter; the effective limit is the
    smallest signed limit for this certificate and window."""
    issuer_id: str
    cert_id: str
    window_s: int
    limit: int


def build_v2_rate_reservation_batch(deferred: list[V2DeferredConstraint]) -> list[V2RateReservation]:
    counters: dict[tuple, int] = {}
    seen = set()
    for item in deferred:
        position = (item.delegation_index, item.constraint_index)
        if (
            item.delegation_index < 0 or item.constraint_index < 0 or position in seen
            or not valid_v2_id(item.issuer_id) or item.cert_id == ""
            or len(item.cert_id.encode("utf-8")) > MAX_IDENTIFIER_LENGTH_BYTES
        ):
            raise ValueError("v2 rate constraint has invalid identity or duplicate position")
        seen.add(position)
        constraint, _ = _sealed_constraint(item)
        if constraint.type != item.type:
            raise ValueError("v2 rate constraint has wrong type")
        if item.type not in (MAX_RATE, RECEIVER_AUDIENCE):
            raise ValueError("v2 rate batch contains an unexpected deferred constraint type")
        if item.type == RECEIVER_AUDIENCE:
            continue
        if constraint.count <= 0 or constraint.count > MAX_SAFE_INTEGER or constraint.window_s <= 0 or constraint.window_s > MAX_SAFE_INTEGER:
            raise ValueError("v2 rate constraint has noncanonical or invalid limits")
        key = (item.issuer_id, item.cert_id, constraint.window_s)
        if key not in counters or constraint.count < counters[key]:
            counters[key] = constraint.count
    return [V2RateReservation(i, c, w, limit) for (i, c, w), limit in sorted(counters.items())]


def signed_v2_rate_reservation_batch(bundle: ProofBundleV2) -> list[V2RateReservation]:
    deferred = []
    for i, cert in enumerate(bundle.delegations):
        for j, constraint in enumerate(cert.constraints):
            if constraint.type != MAX_RATE:
                continue
            deferred.append(V2DeferredConstraint(i, j, cert.issuer_id, cert.cert_id, MAX_RATE,
                                                 constraint_canonical_json(constraint)))
    return build_v2_rate_reservation_batch(deferred)
