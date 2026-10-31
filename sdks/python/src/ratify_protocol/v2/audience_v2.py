"""Protocol v2 ``ratify.receiver_audience`` evaluation (mirrors Go audience_v2.go).

The audience stage runs after the claim and after status. It uses only the
verifier's authenticated expected receiver and caller-authenticated
membership results; it never copies membership from a proof.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .clock_bounds_v2 import V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS, V2_MAX_FUTURE_SKEW_SECONDS, valid_v2_timestamp
from .context_policy_v2 import V2DeferredConstraint
from .errors_v2 import V2ErrorClass, classified
from .rate_reservation_v2 import RECEIVER_AUDIENCE, decode_sealed_constraint_v2
from .types_v2 import MAX_SAFE_INTEGER, is_int, valid_prefixed_digest_v2


@dataclass(frozen=True)
class V2AudienceMembership:
    """A caller-authenticated, complete membership result for one constrained
    certificate link. Protocol does not authenticate this input: a live
    adapter must verify the statement, signer, version floor, receiver
    ownership, source, and completeness first. Absence is unavailable, not
    proof of nonmembership."""

    delegation_index: int = 0
    constraint_index: int = 0
    receiver_id: str = ""
    trust_domain_ids: tuple = ()
    issued_at: int = 0
    expires_at: int = 0
    evidence_digest: str = ""


@dataclass(frozen=True)
class V2AudienceAssessment:
    """A post-claim, post-status constraint outcome: ``passed``,
    ``constraint_denied``, or ``constraint_unverifiable``."""

    status: str
    evidence_digests: list = field(default_factory=list)
    fresh_until: int = 0


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def evaluate_receiver_audience_v2(deferred, receiver_id: str, memberships, now: int, future_skew: int) -> V2AudienceAssessment:
    """Evaluate every deferred audience link. A valid nonmatching membership
    takes precedence over unavailable membership in another link. Raises
    ValueError when the sealed input is invalid (a broken verifier
    invariant, never a decision)."""
    if (
        not isinstance(receiver_id, str) or receiver_id == "" or not valid_v2_timestamp(now)
        or not is_int(future_skew) or future_skew < 0 or future_skew > V2_MAX_FUTURE_SKEW_SECONDS
    ):
        raise ValueError("v2 audience requires a sealed receiver and valid security time")
    links = []
    seen_links: set = set()
    max_age = MAX_SAFE_INTEGER
    fresh_until = MAX_SAFE_INTEGER
    for item in deferred or ():
        if not isinstance(item, V2DeferredConstraint):
            raise ValueError("v2 audience input must be V2DeferredConstraint values")
        if item.type != RECEIVER_AUDIENCE:
            continue
        try:
            constraint = decode_sealed_constraint_v2(item.canonical_json)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"v2 sealed audience constraint is invalid: {exc}") from exc
        key = (item.delegation_index, item.constraint_index)
        if not is_int(item.delegation_index) or not is_int(item.constraint_index) or item.delegation_index < 0 or item.constraint_index < 0 or key in seen_links:
            raise ValueError("v2 audience constraint has duplicate or invalid position")
        seen_links.add(key)
        if constraint.type != RECEIVER_AUDIENCE:
            raise ValueError("v2 sealed audience constraint has wrong type")
        params = constraint.params or {}
        exact = list(params.get("exact_receiver_ids") or [])
        domains = list(params.get("trust_domain_ids") or [])
        age = params.get("max_membership_age_seconds", 0)
        if domains and (not is_int(age) or age <= 0 or age > V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS):
            raise ValueError(f"v2 audience membership age must be 1..{V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS} seconds")
        if domains and age < max_age:
            max_age = age
        links.append((exact, domains, item.delegation_index, item.constraint_index))
    if not links:
        raise ValueError("v2 audience stage has no audience constraints")
    denied = unavailable = False
    evidence: list = []
    for exact, domains, delegation_index, constraint_index in links:
        if receiver_id in exact:
            continue
        if not domains:
            raise ValueError("v2 exact-only audience mismatch passed preflight")
        membership = None
        for candidate in memberships or ():
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
            or not valid_v2_timestamp(m.issued_at) or not valid_v2_timestamp(m.expires_at)
            or m.issued_at >= m.expires_at or now >= m.expires_at
            or (m.issued_at > now and m.issued_at - now > future_skew)
            # Exclusive age deadline: current only while now < issued_at + max_age.
            or (now >= m.issued_at and now - m.issued_at >= max_age)
        ):
            unavailable = True
            continue
        seen: set = set()
        match = malformed = False
        for domain_id in m.trust_domain_ids or ():
            if not isinstance(domain_id, str) or domain_id == "" or domain_id in seen:
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
        return V2AudienceAssessment(status="constraint_denied", evidence_digests=evidence)
    if unavailable:
        return V2AudienceAssessment(status="constraint_unverifiable", evidence_digests=evidence)
    return V2AudienceAssessment(status="passed", evidence_digests=evidence, fresh_until=fresh_until)
