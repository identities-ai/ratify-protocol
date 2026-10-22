"""Protocol v2 post-claim local authorization (mirrors Go authorization_v2.go).

After a successful atomic challenge claim, the single-use evaluator
capability runs the deterministic checks of SPEC-v2 §6.3 and §6.4 (trust-root
binding, delegation times, effective scope, context policy, and locally
decidable constraints), then the ordered status, audience, and rate stages.
No stage output here is actionable; only ``release_v2_decision`` is.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from . import context_v2
from .claim_store_v2 import (
    V2EvaluationToken,
    V2RateReservationStore,
    _token_state,
    is_v2_rate_at_finalization_store,
)
from .challenge_claim_v2 import protocol_claim_id_v2
from .clock_bounds_v2 import checked_add_v2, valid_v2_timestamp
from .context_policy_v2 import (
    V2ContextPolicy,
    V2DeferredConstraint,
    evaluate_proof_bundle_v2_context_policy,
    same_v2_context_policy,
)
from .errors_v2 import V2Error, V2ErrorClass, classified
from .limits_v2 import MAX_DELEGATION_CHAIN_DEPTH  # noqa: F401 - re-exported bound
from .protocol_v2 import ProofBundleV2, bundle_hash_v2, verify_proof_bundle_v2_signatures
from .scope import intersect_scopes, validate_required_scope_v2, validate_scopes_v2
from .types import HybridPublicKey
from .types_v2 import StatusEvidenceEntryV2
from .verify_v2_preflight import ExpectedChallengeV2, _matches_expected_challenge_v2, equal_hybrid_public_keys

V2_MAX_TIMESTAMP_SECONDS = 253402300799
V2_MAX_DELEGATION_LIFETIME_SECONDS = 315360000
SCOPE_IDENTITY_DELEGATE = "identity:delegate"
CONSTRAINT_MAX_RATE = "max_rate"
CONSTRAINT_RECEIVER_AUDIENCE = "ratify.receiver_audience"
CONSTRAINT_TIME_WINDOW = "time_window"


@dataclass
class V2LocalAuthorizationOptions:
    """Verifier-owned inputs for the post-claim deterministic checks. There is
    no caller-supplied evaluation time: every time-sensitive check uses the
    authoritative claim time sealed in ``claim_token``."""

    future_skew_seconds: int = 0
    required_scope: str = ""
    trusted_root_id: str = ""
    trusted_root_key: Optional[HybridPublicKey] = None
    trust_configured: bool = False
    context: object = None  # constraints_v2.ConstraintContextV2
    tzdb_version: str = ""
    context_policy: Optional[V2ContextPolicy] = None
    expected_challenge: Optional[ExpectedChallengeV2] = None
    claim_token: Optional[V2EvaluationToken] = None


@dataclass
class V2LocalPolicyFailure:
    status: str = ""
    reason: str = ""
    detail: str = ""


@dataclass
class V2CertificateStatusCheck:
    delegation_index: int = 0
    issuer_id: str = ""
    subject_id: str = ""
    cert_id: str = ""


@dataclass
class V2LocalAuthorizationAssessment:
    """An intermediate result, not a terminal authorization decision."""

    bundle_hash: str = ""
    issuer_ids: list = field(default_factory=list)
    agent_id: str = ""
    root_id: str = ""
    required_scope: str = ""
    delegation_digest: bytes = b""
    effective_scope: Optional[list] = None
    context_assessment: str = ""
    context_policy_digest: Optional[str] = None
    status_assessment: str = ""
    delegation_valid_until: int = 0
    local_time_valid_until: int = 0
    extension_valid_until: int = 0
    status_fresh_until: int = 0
    audience_fresh_until: int = 0
    status_evidence: list = field(default_factory=list)
    audience_evidence_digests: list = field(default_factory=list)
    rate_store_unavailable: bool = False
    rate_admission_deferred: bool = False
    status_checks: list = field(default_factory=list)
    deferred: list = field(default_factory=list)
    local_policy_failure: Optional[V2LocalPolicyFailure] = None
    status: str = ""
    reason: str = ""
    detail: str = ""


def _clone_v2_local_authorization_assessment(src: V2LocalAuthorizationAssessment) -> V2LocalAuthorizationAssessment:
    dst = copy.copy(src)
    dst.issuer_ids = list(src.issuer_ids or [])
    dst.delegation_digest = bytes(src.delegation_digest or b"")
    dst.effective_scope = None if src.effective_scope is None else list(src.effective_scope)
    dst.status_checks = [copy.copy(c) for c in (src.status_checks or [])]
    dst.status_evidence = list(src.status_evidence or [])
    dst.audience_evidence_digests = list(src.audience_evidence_digests or [])
    dst.deferred = [replace(d, canonical_json=bytes(d.canonical_json or b"")) for d in (src.deferred or [])]
    dst.local_policy_failure = None if src.local_policy_failure is None else copy.copy(src.local_policy_failure)
    return dst


def _v2_local_assessment(bundle, status: str, reason: str, scope: Optional[list], detail: str) -> V2LocalAuthorizationAssessment:
    return V2LocalAuthorizationAssessment(effective_scope=scope, context_assessment="not_evaluated", status=status,
                                          reason=reason, detail=detail)


def v2_interrupted_assessment(bundle, detail: str) -> V2LocalAuthorizationAssessment:
    """Go ``v2InterruptedAssessment``."""
    return _v2_local_assessment(bundle, "authorization_unverified", "evaluation_interrupted", None, detail)


def evaluate_proof_bundle_v2_local_authorization(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions) -> V2LocalAuthorizationAssessment:
    """Go ``EvaluateProofBundleV2LocalAuthorization``."""
    state = _token_state(opts.claim_token) if isinstance(opts, V2LocalAuthorizationOptions) else None
    started = [False]

    def finish(assessment: V2LocalAuthorizationAssessment) -> V2LocalAuthorizationAssessment:
        if state is not None and state.expected is not None:
            assessment.bundle_hash = state.expected.bundle_hash
            assessment.issuer_ids = list(state.expected.issuer_ids)
        if started[0] and assessment.status != "":
            with state.finalization_mu:
                state.evaluation_status = assessment.status
                state.evaluation_reason = assessment.reason
                if assessment.status == "pending_external_checks":
                    state.pending_assessment = _clone_v2_local_authorization_assessment(assessment)
                state.evaluation_complete = True
        return assessment

    if state is None or state.expected is None:
        return finish(_v2_local_assessment(bundle, "preflight_binding_mismatch", "claim_required", None,
                                           "local authorization requires a successful atomic challenge claim"))
    try:
        claim_id = protocol_claim_id_v2(state.expected.verifier_namespace, state.expected.replay_epoch, state.expected.value)
    except Exception:  # noqa: BLE001
        claim_id = None
    if claim_id is None or state.claim_id != claim_id or state.proof_digest != state.expected.bundle_hash or len(state.owner_token) != 32:
        return finish(v2_interrupted_assessment(bundle, "local authorization state differs from successful preflight or atomic claim"))
    if not state.try_use():
        return finish(_v2_local_assessment(bundle, "evaluation_in_progress", "claim_in_progress", None,
                                           "the claim's single evaluation token has already been used"))
    started[0] = True
    try:
        return finish(_evaluate_local(bundle, opts, state))
    except Exception as exc:  # noqa: BLE001 - an unexpected failure after claim interrupts the evaluation
        return finish(v2_interrupted_assessment(bundle, f"local authorization failed: {exc}"))


def _evaluate_local(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions, state) -> V2LocalAuthorizationAssessment:
    if not state.claim_time_valid:
        return v2_interrupted_assessment(bundle, "claim store returned an authoritative claim time outside the authenticated freshness bounds")
    if opts.expected_challenge is not None and not _matches_expected_challenge_v2(opts.expected_challenge, state.expected):
        return v2_interrupted_assessment(bundle, "local authorization challenge state differs from successful preflight or atomic claim")
    now_unix = state.claimed_at
    with state.finalization_mu:
        state.evaluated_at = now_unix
    if opts.required_scope != state.required_scope or opts.future_skew_seconds != state.future_skew:
        return v2_interrupted_assessment(bundle, "local authorization state differs from successful preflight or atomic claim")
    if opts.required_scope != state.expected.required_scope:
        return v2_interrupted_assessment(bundle, "required scope differs from the scope validated during preflight")
    try:
        bundle_hash = bundle_hash_v2(bundle)
    except Exception:  # noqa: BLE001
        bundle_hash = None
    if bundle_hash is None or bundle_hash != state.proof_digest:
        return v2_interrupted_assessment(bundle, "proof bundle differs from the bundle validated during preflight")
    if (bundle is None or bytes(bundle.challenge) != state.expected.value or bundle.challenge_at != state.expected.issued_at
            or bundle.verifier_id != state.expected.verifier_id):
        return v2_interrupted_assessment(bundle, "proof challenge differs from the challenge validated during preflight")
    try:
        validate_required_scope_v2(opts.required_scope)
    except Exception as exc:  # noqa: BLE001
        return v2_interrupted_assessment(bundle, "required scope changed after successful preflight: " + str(exc))
    try:
        verify_proof_bundle_v2_signatures(bundle)
    except Exception:  # noqa: BLE001
        return v2_interrupted_assessment(bundle, "proof signature changed after successful preflight")
    delegations = bundle.delegations
    if len(delegations) == 0:
        return _v2_local_assessment(bundle, "delegation_not_authorized", "not_delegated", None, "proof has no delegation certificates")
    if not opts.trust_configured:
        return _v2_local_assessment(bundle, "authorization_unverified", "trust_unavailable", None,
                                    "caller-authenticated trust configuration is unavailable")
    root = delegations[-1]
    if opts.trusted_root_id != root.issuer_id or not equal_hybrid_public_keys(opts.trusted_root_key, root.issuer_pub_key):
        return _v2_local_assessment(bundle, "unauthorized", "unauthorized", None,
                                    "delegation chain does not terminate at the configured trust root")
    for i, cert in enumerate(delegations):
        latest_issue, ok = checked_add_v2(now_unix, state.future_skew)
        if (not valid_v2_timestamp(cert.issued_at) or not valid_v2_timestamp(cert.expires_at) or cert.issued_at >= cert.expires_at
                or cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS or not ok or cert.issued_at > latest_issue):
            return _v2_local_assessment(bundle, "invalid", "proof_invalid", None, f"delegation {i} has invalid time bounds")
    for i, cert in enumerate(delegations):
        if now_unix >= cert.expires_at:
            return _v2_local_assessment(bundle, "expired", "delegation_expired", None, f"delegation {i} has expired")
    for i, cert in enumerate(delegations):
        try:
            validate_scopes_v2(cert.scope)
        except Exception as exc:  # noqa: BLE001
            return _v2_local_assessment(bundle, "invalid_scope", "invalid_scope", None, f"delegation {i}: {exc}")
    for i in range(len(delegations)):
        if i + 1 < len(delegations) and SCOPE_IDENTITY_DELEGATE not in delegations[i + 1].scope:
            return _v2_local_assessment(bundle, "delegation_not_authorized", "delegation_not_authorized", None,
                                        f"parent delegation {i + 1} does not grant {SCOPE_IDENTITY_DELEGATE!r}")
    effective = intersect_scopes(*[list(cert.scope) for cert in delegations])
    local_policy_failure: Optional[V2LocalPolicyFailure] = None
    if opts.required_scope not in effective:
        local_policy_failure = V2LocalPolicyFailure("scope_denied", "scope_denied",
                                                    f"required scope {opts.required_scope!r} is not in the effective delegation scope")
    if opts.context_policy is not None and not same_v2_context_policy(opts.context_policy, state.expected.context_policy):
        return v2_interrupted_assessment(bundle, "context policy differs from the policy sealed during successful preflight")
    context_assessment = evaluate_proof_bundle_v2_context_policy(bundle, state.expected.context_policy)
    if context_assessment.status != "passed" and local_policy_failure is None:
        local_policy_failure = V2LocalPolicyFailure(context_assessment.status, context_assessment.reason, context_assessment.detail)
    deferred, constraint_status, constraint_failures, extension_valid_until = _evaluate_v2_local_constraints(
        bundle, opts, state.expected, now_unix)
    if constraint_status != "":
        constraint_failures.sort(key=lambda s: s.encode("utf-8"))
        if local_policy_failure is None:
            local_policy_failure = V2LocalPolicyFailure(constraint_status, constraint_status, "; ".join(constraint_failures))
    assessment = _pending_v2_local_assessment(bundle, opts, effective, deferred, local_policy_failure)
    assessment.extension_valid_until = extension_valid_until
    assessment.delegation_valid_until = min(cert.expires_at for cert in delegations)
    if local_policy_failure is None:
        try:
            assessment.local_time_valid_until = _local_time_window_valid_until_v2(bundle, opts.tzdb_version, now_unix)
        except Exception as exc:  # noqa: BLE001
            assessment.local_policy_failure = V2LocalPolicyFailure("constraint_unverifiable", "constraint_unverifiable", str(exc))
    assessment.context_assessment = context_assessment.assessment
    assessment.context_policy_digest = context_assessment.policy_digest
    return assessment


def _pending_v2_local_assessment(bundle, opts, effective, deferred, failure) -> V2LocalAuthorizationAssessment:
    assessment = _v2_local_assessment(bundle, "pending_external_checks", "external_checks_required", effective,
                                      "local checks recorded; status and deferred authorization checks remain")
    assessment.agent_id = bundle.agent_id
    assessment.root_id = opts.trusted_root_id
    assessment.required_scope = opts.required_scope
    assessment.delegation_digest = bytes(bundle.delegation_digest)
    assessment.local_policy_failure = failure
    assessment.status_checks = [
        V2CertificateStatusCheck(delegation_index=i, issuer_id=cert.issuer_id, subject_id=cert.subject_id, cert_id=cert.cert_id)
        for i, cert in enumerate(bundle.delegations)
    ]
    assessment.deferred = deferred
    return assessment


def constraint_precedence_v2(status: str) -> int:
    """Go ``constraintPrecedenceV2``: denied > unknown > unverifiable."""
    return {"constraint_denied": 3, "constraint_unknown": 2, "constraint_unverifiable": 1}.get(status, 0)


def _evaluate_v2_local_constraints(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions, sealed, now_unix: int):
    """Go ``evaluateV2LocalConstraints``."""
    from ._v2json import canonical
    from .constraint_evaluator_v2 import (
        ConstraintEvaluationInputV2,
        clone_constraint_context_v2,
        extension_params_json_v2,
        run_constraint_evaluator_v2,
    )
    from .constraints_v2 import (
        ConstraintUnverifiableError,
        UnknownConstraintError,
        evaluate_constraint_v2,
        is_registered_constraint_type_v2,
    )

    deferred: list = []
    constraint_status = ""
    failures: list = []
    extension_horizon = 0
    evaluators = sealed.evaluators or {}
    for i, cert in enumerate(bundle.delegations):
        for j, constraint in enumerate(cert.constraints):
            if constraint.type in (CONSTRAINT_MAX_RATE, CONSTRAINT_RECEIVER_AUDIENCE):
                try:
                    encoded = canonical(constraint)
                except Exception as exc:  # noqa: BLE001
                    if constraint_precedence_v2("constraint_unverifiable") > constraint_precedence_v2(constraint_status):
                        constraint_status = "constraint_unverifiable"
                    failures.append(f"delegation {i} constraint {j} cannot be encoded: {exc}")
                    continue
                deferred.append(V2DeferredConstraint(delegation_index=i, constraint_index=j, issuer_id=cert.issuer_id,
                                                     cert_id=cert.cert_id, type=constraint.type, canonical_json=encoded))
                continue
            err: Optional[BaseException] = None
            entry = evaluators.get(constraint.type)
            if entry is not None and not is_registered_constraint_type_v2(constraint.type):
                horizon = 0
                try:
                    params = extension_params_json_v2(constraint)
                except Exception as exc:  # noqa: BLE001
                    err = ConstraintUnverifiableError(f"{constraint.type} params cannot be encoded: {exc}")
                else:
                    try:
                        horizon = run_constraint_evaluator_v2(entry, sealed.evaluator_timeout, ConstraintEvaluationInputV2(
                            type=constraint.type, params_json=params, delegation_index=i, constraint_index=j,
                            issuer_id=cert.issuer_id, cert_id=cert.cert_id, context=clone_constraint_context_v2(opts.context),
                            evaluation_time=now_unix))
                    except Exception as exc:  # noqa: BLE001
                        err = exc
                if err is None and horizon != 0 and (extension_horizon == 0 or horizon < extension_horizon):
                    extension_horizon = horizon
            else:
                try:
                    evaluate_constraint_v2(constraint, opts.context, opts.tzdb_version, now_unix)
                except Exception as exc:  # noqa: BLE001
                    err = exc
            if err is not None:
                status = "constraint_denied"
                if isinstance(err, ConstraintUnverifiableError):
                    status = "constraint_unverifiable"
                elif isinstance(err, UnknownConstraintError):
                    status = "constraint_unknown"
                if constraint_status == "" or constraint_precedence_v2(status) > constraint_precedence_v2(constraint_status):
                    constraint_status = status
                failures.append(f"delegation {i} constraint {j}: {err}")
    return deferred, constraint_status, failures, extension_horizon


def allow_horizon_v2(assessment: V2LocalAuthorizationAssessment) -> int:
    """Go ``allowHorizonV2``."""
    horizon = min(assessment.delegation_valid_until, assessment.status_fresh_until)
    if assessment.audience_fresh_until > 0:
        horizon = min(horizon, assessment.audience_fresh_until)
    if assessment.local_time_valid_until > 0:
        horizon = min(horizon, assessment.local_time_valid_until)
    if assessment.extension_valid_until > 0:
        horizon = min(horizon, assessment.extension_valid_until)
    return min(horizon, V2_MAX_TIMESTAMP_SECONDS)


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 of a proleptic Gregorian date (any year)."""
    year -= month <= 2
    era = (year if year >= 0 else year - 399) // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _local_time_window_valid_until_v2(bundle: ProofBundleV2, tzdb_version: str, now_unix: int) -> int:
    """Go ``localTimeWindowValidUntilV2``: bound an allow at the end of each
    currently accepted local minute or the next UTC offset change."""
    from . import _tzdb_v2
    from .constraints_v2 import load_v2_time_zone, parse_hhmm_v2, local_time_v2 as v2_local_time_v2

    horizon = 0
    for cert in bundle.delegations:
        for constraint in cert.constraints:
            if constraint.type != CONSTRAINT_TIME_WINDOW:
                continue
            local = v2_local_time_v2(tzdb_version, constraint.tz, now_unix)
            zone = load_v2_time_zone(tzdb_version, constraint.tz)
            start = parse_hhmm_v2(constraint.start)
            end = parse_hhmm_v2(constraint.end)
            minute = local.hour * 60 + local.minute
            if (start <= end and (minute < start or minute > end)) or (start > end and minute < start and minute > end):
                raise ValueError("time window is no longer current")
            day_offset = 1 if start > end and minute >= start else 0
            until = (_days_from_civil(local.year, local.month, local.day) + day_offset) * 86400 + (end + 1) * 60 - local.utc_offset_seconds
            change = _tzdb_v2.next_utc_offset_change(zone, now_unix, V2_MAX_TIMESTAMP_SECONDS)
            if change is not None and change < until:
                until = change
            if not until > now_unix:
                raise ValueError("time window has no valid terminal horizon")
            # A horizon past the timestamp domain is clamped to its upper bound.
            contribution = min(until, V2_MAX_TIMESTAMP_SECONDS)
            if horizon == 0 or contribution < horizon:
                horizon = contribution
    return horizon


def _combinable_with_audience_v2(failure: Optional[V2LocalPolicyFailure], deferred: list) -> bool:
    if failure is None or failure.status not in ("constraint_unknown", "constraint_unverifiable"):
        return False
    return any(item.type == CONSTRAINT_RECEIVER_AUDIENCE for item in deferred)


def _resolve_claim_proof_bundle_v2_after_status(token: V2EvaluationToken, aggregate: Callable) -> V2LocalAuthorizationAssessment:
    """Go ``resolveClaimProofBundleV2AfterStatus``. ``aggregate`` maps the
    status checks to a ``V2StatusAssessment`` (assessment, fresh_until,
    evidence)."""
    state = _token_state(token)
    if state is None:
        raise ValueError("v2 claim evaluator capability is required")
    with state.finalization_mu:
        if (state.expected is None or not state.evaluation_complete or state.evaluation_status != "pending_external_checks"
                or state.pending_assessment is None):
            raise ValueError("v2 claim does not have a pending status assessment")
        assessment = _clone_v2_local_authorization_assessment(state.pending_assessment)
        if assessment.bundle_hash != state.expected.bundle_hash or assessment.required_scope != state.expected.required_scope:
            raise ValueError("pending status assessment differs from its claimed proof")
        aggregated = aggregate(assessment.status_checks)
        assessment.status_assessment = aggregated.assessment
        assessment.status_fresh_until = aggregated.fresh_until
        assessment.status_evidence = list(aggregated.evidence or [])
        if aggregated.assessment == "revoked":
            assessment.status, assessment.reason = "revoked", "delegation_revoked"
            assessment.detail = "at least one delegation certificate is revoked"
        elif aggregated.assessment == "unavailable":
            assessment.status, assessment.reason = "authorization_unverified", "status_unavailable"
            assessment.detail = "one or more delegation certificate statuses are unavailable"
        elif aggregated.assessment == "stale":
            assessment.status, assessment.reason = "authorization_unverified", "status_stale"
            assessment.detail = "one or more delegation certificate statuses are stale"
        elif aggregated.assessment == "current":
            if assessment.local_policy_failure is not None and _combinable_with_audience_v2(assessment.local_policy_failure, assessment.deferred):
                # A proven audience violation on another link outranks a local
                # unknown or unverifiable constraint; rate never follows.
                assessment.deferred = [d for d in assessment.deferred if d.type == CONSTRAINT_RECEIVER_AUDIENCE]
                assessment.status, assessment.reason = "pending_external_checks", "deferred_policy_checks_required"
                assessment.detail = "status is current; audience must be aggregated with a pending local constraint result"
                state.pending_assessment = _clone_v2_local_authorization_assessment(assessment)
                state.evaluation_status, state.evaluation_reason = assessment.status, assessment.reason
                return assessment
            if assessment.local_policy_failure is not None:
                failure = assessment.local_policy_failure
                assessment.status, assessment.reason, assessment.detail = failure.status, failure.reason, failure.detail
            elif len(assessment.deferred) != 0:
                assessment.status, assessment.reason = "pending_external_checks", "deferred_policy_checks_required"
                assessment.detail = "status is current; deferred audience or rate checks remain"
                state.pending_assessment = _clone_v2_local_authorization_assessment(assessment)
                state.evaluation_status, state.evaluation_reason = assessment.status, assessment.reason
                return assessment
            else:
                assessment.status, assessment.reason = "authorized_agent", "authorized"
                assessment.detail = "proof, status, and local authorization checks passed"
                state.allow_valid_until = allow_horizon_v2(assessment)
        else:
            raise ValueError("v2 status aggregator returned an unknown assessment")
        state.evaluation_status, state.evaluation_reason = assessment.status, assessment.reason
        state.pending_assessment = None
        return assessment


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def resolve_claim_proof_bundle_v2_after_audience(token: V2EvaluationToken, memberships: Optional[list]) -> V2LocalAuthorizationAssessment:
    """Go ``ResolveClaimProofBundleV2AfterAudience``: membership freshness is
    evaluated at the authoritative claim time sealed in the token."""
    from .audience_v2 import evaluate_receiver_audience_v2

    state = _token_state(token)
    if state is None:
        raise ValueError("v2 claim evaluator capability is required")
    with state.finalization_mu:
        pending = state.pending_assessment
        if (state.expected is None or not state.evaluation_complete or state.evaluation_status != "pending_external_checks"
                or pending is None or pending.status_assessment != "current"
                or (pending.local_policy_failure is not None and not _combinable_with_audience_v2(pending.local_policy_failure, pending.deferred))):
            raise ValueError("v2 claim does not have current status and pending audience checks")
        assessment = _clone_v2_local_authorization_assessment(pending)
        if assessment.bundle_hash != state.expected.bundle_hash or assessment.required_scope != state.expected.required_scope:
            state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
            state.pending_assessment = None
            raise ValueError("pending audience assessment differs from its claimed proof")
        try:
            result = evaluate_receiver_audience_v2(assessment.deferred, state.expected.expected_receiver_id, memberships,
                                                   state.evaluated_at, state.future_skew)
        except Exception:
            state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
            state.pending_assessment = None
            raise
        assessment.audience_evidence_digests = list(result.evidence_digests or [])
        assessment.audience_fresh_until = result.fresh_until
        local = assessment.local_policy_failure
        if local is not None:
            # Aggregate independently of link order: denied, unknown, unverifiable.
            if result.status == "passed" or constraint_precedence_v2(local.status) > constraint_precedence_v2(result.status):
                assessment.status, assessment.reason, assessment.detail = local.status, local.reason, local.detail
            else:
                assessment.status, assessment.reason = result.status, result.status
                assessment.detail = "receiver audience did not authorize this receiver"
            assessment.deferred = []
            state.pending_assessment = None
        elif result.status != "passed":
            assessment.status, assessment.reason = result.status, result.status
            assessment.detail = "receiver audience did not authorize this receiver"
            state.pending_assessment = None
        else:
            assessment.deferred = [d for d in assessment.deferred if d.type != CONSTRAINT_RECEIVER_AUDIENCE]
            if len(assessment.deferred) == 0:
                assessment.status, assessment.reason = "authorized_agent", "authorized"
                assessment.detail = "proof, status, audience, and local authorization checks passed"
                state.allow_valid_until = allow_horizon_v2(assessment)
                state.pending_assessment = None
            else:
                assessment.status, assessment.reason = "pending_external_checks", "rate_reservation_required"
                assessment.detail = "audience passed; rate reservation remains"
                state.pending_assessment = _clone_v2_local_authorization_assessment(assessment)
        state.evaluation_status, state.evaluation_reason = assessment.status, assessment.reason
        return assessment


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def resolve_claim_proof_bundle_v2_after_rate(ctx: context_v2.Context, store: Optional[V2RateReservationStore],
                                             token: V2EvaluationToken) -> V2LocalAuthorizationAssessment:
    """Go ``ResolveClaimProofBundleV2AfterRate``: the final external stage."""
    from .rate_reservation_v2 import V2RateLimitExceededError, build_v2_rate_reservation_batch

    state = _token_state(token)
    if not isinstance(ctx, context_v2.Context) or state is None:
        raise ValueError("v2 rate evaluation requires context and claim capability")
    err = ctx.err()
    if err is not None:
        raise err
    with state.finalization_mu:
        pending = state.pending_assessment
        if (state.expected is None or not state.evaluation_complete or state.evaluation_status != "pending_external_checks"
                or pending is None or pending.status_assessment != "current" or pending.local_policy_failure is not None):
            raise ValueError("v2 claim does not have current status and pending rate checks")
        assessment = _clone_v2_local_authorization_assessment(pending)
        if (assessment.bundle_hash != state.expected.bundle_hash or assessment.required_scope != state.expected.required_scope
                or len(state.rate_batch) == 0):
            state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
            state.pending_assessment = None
            raise ValueError("pending rate assessment differs from its claimed proof")
        for item in assessment.deferred:
            if item.type != CONSTRAINT_MAX_RATE:
                raise ValueError("audience or unknown checks remain before rate reservation")
        try:
            batch = list(build_v2_rate_reservation_batch(assessment.deferred))
        except Exception:  # noqa: BLE001
            batch = None
        if batch is None or batch != list(state.rate_batch):
            state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
            state.pending_assessment = None
            raise ValueError("pending rate checks differ from sealed signed batch")
        rate_err: Optional[BaseException] = None
        if store is None:
            rate_err = ValueError("v2 rate reservation store is unavailable")
        elif is_v2_rate_at_finalization_store(store):
            state.rate_at_finalization = True
            assessment.rate_admission_deferred = True
        else:
            try:
                store.reserve_v2_rate_batch(ctx, state.claim_id, bytes(state.owner_token), assessment.bundle_hash, list(batch))
            except Exception as exc:  # noqa: BLE001 - a store failure or panic is unverifiable
                rate_err = exc
        if rate_err is None:
            assessment.status, assessment.reason = "authorized_agent", "authorized"
            if state.rate_at_finalization:
                assessment.detail = "proof, status, and audience passed; rate admission is deferred to durable finalization"
            else:
                assessment.detail = "proof, status, audience, and rate checks passed"
            state.allow_valid_until = allow_horizon_v2(assessment)
        elif isinstance(rate_err, V2RateLimitExceededError):
            assessment.status, assessment.reason = "constraint_denied", "constraint_denied"
            assessment.detail = "signed rate limit has no remaining capacity"
        else:
            assessment.status, assessment.reason = "constraint_unverifiable", "constraint_unverifiable"
            assessment.detail = "rate reservation could not be verified"
            assessment.rate_store_unavailable = True
        assessment.deferred = []
        state.pending_assessment = None
        state.evaluation_status, state.evaluation_reason = assessment.status, assessment.reason
        return assessment


def _interrupt_v2_evaluation(token: V2EvaluationToken) -> None:
    """Go ``interruptV2Evaluation``."""
    state = _token_state(token)
    if state is None:
        return
    with state.finalization_mu:
        state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
        state.allow_valid_until = 0
        state.rate_at_finalization = False
        state.pending_assessment = None
        state.evaluation_complete = True


__all__ = [
    "V2LocalAuthorizationOptions", "V2LocalAuthorizationAssessment", "V2LocalPolicyFailure",
    "V2CertificateStatusCheck", "V2DeferredConstraint", "V2RateReservationStore",
    "evaluate_proof_bundle_v2_local_authorization", "resolve_claim_proof_bundle_v2_after_audience",
    "resolve_claim_proof_bundle_v2_after_rate", "allow_horizon_v2", "constraint_precedence_v2",
]
