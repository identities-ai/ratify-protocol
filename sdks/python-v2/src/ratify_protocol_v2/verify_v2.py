"""The live Protocol v2 verifier (mirrors Go verify_v2.go, SPEC-v2 §6).

:func:`verify_proof_bundle_v2` runs configuration bounds, bounded strict
decode, required-scope validation, structural and signature checks, the
authenticated challenge binding, the pure receiver-binding hook, and the
atomic claim; only then trust, local authorization, authenticated status for
every CertificateRef, receiver audience, ``max_rate``, and terminal
finalization at a fresh authoritative time. A committed outcome is never an
authorization: pass it to :func:`release_v2.release_v2_decision`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import context_v2
from ._v2json import canonical
from .authorization_v2 import (
    CONSTRAINT_RECEIVER_AUDIENCE,
    V2LocalAuthorizationAssessment,
    V2LocalAuthorizationOptions,
    _interrupt_v2_evaluation,
    _resolve_claim_proof_bundle_v2_after_status,
    evaluate_proof_bundle_v2_local_authorization,
    resolve_claim_proof_bundle_v2_after_audience,
    resolve_claim_proof_bundle_v2_after_rate,
    v2_interrupted_assessment,
)
from .claim_store_v2 import (
    V2_CLAIM_CREATED,
    ClaimStoreV2,
    V2ChallengeClaim,
    _token_state,
    claim_proof_bundle_v2,
    finalize_claim_proof_bundle_v2,
    is_v2_rate_at_finalization_store,
    terminal_decision_for_v2_evaluation,
)
from .clock_bounds_v2 import validate_v2_freshness_configuration
from .errors_v2 import V2Error, V2ErrorClass, classify, error_class_of
from .evaluation_progress_v2 import (
    V2EvaluationProgress,
    _record_v2_progress_safely,
    clone_v2_evaluation_progress,
    initial_v2_evaluation_progress,
)
from .limits_v2 import MAX_IDENTIFIER_LENGTH_BYTES
from .protocol_v2 import DelegationCertV2, decode_proof_bundle_v2
from .release_v2 import CommittedV2Outcome, _new_committed_v2_outcome
from .signing_v2 import key_id_v2
from .types import HybridPublicKey
from .types_v2 import MAX_SAFE_INTEGER, is_int, valid_v2_id
from .verify_v2_preflight import (
    ExpectedChallengeV2,
    _preflight_proof_bundle_v2,
    _validate_v2_verifier_identity_configuration,
    equal_hybrid_public_keys,
)

V2_TRUST_TRUSTED = "trusted"
V2_TRUST_UNTRUSTED = "untrusted"
V2_TRUST_UNAVAILABLE = "unavailable"
V2_TRUST_AMBIGUOUS = "ambiguous"

V2_STAGE_PREFLIGHT = "preflight"
V2_STAGE_REPLAY = "replay"
V2_STAGE_EVALUATING = "evaluating"
V2_STAGE_COMMITTED = "committed"

V2_MAX_STATUS_LIFETIME_SECONDS = 86400
V2_MAX_FUTURE_SKEW_SECONDS = 300


@dataclass(frozen=True)
class CertificateRefV2:
    """The issuer-scoped certificate reference used for status."""

    issuer_id: str
    cert_id: str


@dataclass
class V2TrustResolution:
    """The caller-authenticated trust provider result. ``root_key`` is the
    complete root key for ``trusted``; the verifier requires it and its key ID
    to equal the chain's terminal issuer."""

    outcome: str = ""
    root_key: Optional[HybridPublicKey] = None


@dataclass
class V2VerifyCallbacks:
    """The verifier-owned dependencies of the live decision path.
    ``claim_store`` is required. Every callback failure is fail-closed:
    trust -> trust_unavailable, status -> unavailable for that issuer,
    audience -> constraint_unverifiable, rate -> constraint_unverifiable.
    If the caller's context has ended when a callback fails, nothing is
    committed (evaluation_cancelled)."""

    receiver_binding: Optional[Callable] = None  # (bundle, expected) -> None; raise to reject
    claim_store: Optional[ClaimStoreV2] = None
    trust: Optional[Callable] = None  # (ctx, chain) -> V2TrustResolution
    status_evidence: Optional[Callable] = None  # (ctx, V2StatusEvidenceRequest) -> V2StatusEvidenceBatch
    status_journal: object = None  # SecurityJournalStoreV2
    audience: Optional[Callable] = None  # (ctx, deferred, receiver_id) -> list[V2AudienceMembership]
    rate: object = None  # V2RateReservationStore


@dataclass
class V2VerifyRequest:
    """One live verification. ``context_policy`` None means the verifier
    explicitly configured no context policy; the result can then never be
    allow. ``now`` is used only for the pre-claim freshness check."""

    bundle: bytes = b""
    expected: Optional[ExpectedChallengeV2] = None
    context_policy: object = None
    required_scope: str = ""
    verifier_namespace: str = ""
    replay_epoch: int = 0
    # The caller-authenticated verifier key ID (SPEC-v2 §2.4, §6.1). Required:
    # an empty or non-canonical value is configuration_invalid before the
    # ExpectedChallenge is examined, and both the ExpectedChallenge and the
    # proof bundle must name it (verifier_id_mismatch otherwise).
    verifier_id: str = ""
    now: int = 0
    max_challenge_age_seconds: int = 0
    future_skew_seconds: int = 0
    context: object = None  # constraints_v2.ConstraintContextV2
    tzdb_version: str = ""
    status_keys: dict = field(default_factory=dict)  # issuer ID -> V2StatusKeyConfig
    status_policy: object = None  # RevocationStatusPolicyV2
    constraint_evaluators: object = None  # ConstraintEvaluatorRegistryV2


@dataclass
class V2VerifyOutcome:
    """The result of :func:`verify_proof_bundle_v2`. It deliberately has no
    decision field: for ``committed``, ``committed`` is the opaque handoff to
    release."""

    stage: str = ""
    error: Optional[BaseException] = None
    error_class: str = ""
    disposition: str = ""
    claim: V2ChallengeClaim = field(default_factory=V2ChallengeClaim)
    committed: Optional[CommittedV2Outcome] = None


@dataclass
class _V2EvaluationProgress:
    persisted: V2EvaluationProgress
    trust_completed: bool = False


def verify_proof_bundle_v2(ctx: context_v2.Context, req: V2VerifyRequest, cb: V2VerifyCallbacks) -> V2VerifyOutcome:
    """Go ``VerifyProofBundleV2``. A pre-claim failure returns stage
    ``preflight`` with a classified error and invokes no claim, trust,
    status, audience, or rate callback. ``outcome.error`` is set for
    ``preflight`` and ``evaluating``; only ``evaluating`` corresponds to Go's
    non-nil returned error."""

    def preflight_failure(err: BaseException) -> V2VerifyOutcome:
        err = classify(V2ErrorClass.CONFIGURATION_INVALID, err)
        return V2VerifyOutcome(stage=V2_STAGE_PREFLIGHT, error=err, error_class=error_class_of(err))

    from .constraints_v2 import ConstraintContextV2

    if not isinstance(req, V2VerifyRequest):
        return preflight_failure(V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 verification request has the wrong type"))
    # SPEC-v2 §6.2 step 1 (bounded strict decode), then step 2 (configuration,
    # including the context and claim store). No callback runs before both pass.
    if not isinstance(req.bundle, (bytes, bytearray)):
        return preflight_failure(V2Error(V2ErrorClass.MALFORMED, "v2 proof bundle must be bytes"))
    try:
        bundle = decode_proof_bundle_v2(bytes(req.bundle))
    except Exception as exc:  # noqa: BLE001
        return preflight_failure(classify(V2ErrorClass.MALFORMED, exc))
    if not isinstance(ctx, context_v2.Context) or not isinstance(cb, V2VerifyCallbacks) or cb.claim_store is None:
        return preflight_failure(V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 verification requires a context and claim store"))
    request_context = req.context if req.context is not None else ConstraintContextV2()
    try:
        _validate_v2_verify_configuration(req, request_context)
        preflight = _preflight_proof_bundle_v2(
            bundle, req.expected, req.context_policy, True, _safe_v2_receiver_binding(cb.receiver_binding),
            req.constraint_evaluators, req.required_scope, req.verifier_namespace, req.replay_epoch, req.verifier_id, req.now,
            req.max_challenge_age_seconds, req.future_skew_seconds)
    except Exception as exc:  # noqa: BLE001
        return preflight_failure(exc if isinstance(exc, V2Error) else V2Error(V2ErrorClass.UNCLASSIFIED, str(exc)))
    try:
        claim, disposition, token = claim_proof_bundle_v2(ctx, cb.claim_store, bundle, preflight, req.verifier_namespace,
                                                          req.replay_epoch, req.now)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - a store failure (Go: a recovered panic) before claim
        if error_class_of(exc) == V2ErrorClass.UNCLASSIFIED:
            exc = classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, exc)
        return preflight_failure(exc)
    if disposition != V2_CLAIM_CREATED:
        return V2VerifyOutcome(stage=V2_STAGE_REPLAY, disposition=disposition, claim=claim)

    # Every evaluating error reaching here is a claim-store, progress-write,
    # or finalization failure unless it already carries a class.
    def evaluating(err: BaseException) -> V2VerifyOutcome:
        err = classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, err)
        return V2VerifyOutcome(stage=V2_STAGE_EVALUATING, claim=claim, disposition=disposition, error=err,
                               error_class=error_class_of(err))

    def cancelled(err: BaseException) -> V2VerifyOutcome:
        wrapped = V2Error(V2ErrorClass.EVALUATION_CANCELLED, f"v2 evaluation cancelled before commit: {err}")
        wrapped.__cause__ = err
        return evaluating(wrapped)

    state = _token_state(token)
    progress = _V2EvaluationProgress(persisted=initial_v2_evaluation_progress())

    def record() -> Optional[BaseException]:
        try:
            _record_v2_progress_safely(ctx, cb.claim_store, token, progress.persisted)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:  # noqa: BLE001
            if ctx.err() is not None:
                wrapped = V2Error(V2ErrorClass.EVALUATION_CANCELLED, f"v2 evaluation cancelled before commit: {ctx.err()}")
                wrapped.__cause__ = exc
                return wrapped
            return exc
        return None

    opts = V2LocalAuthorizationOptions(
        future_skew_seconds=req.future_skew_seconds, required_scope=req.required_scope, context=request_context,
        tzdb_version=req.tzdb_version, context_policy=req.context_policy, expected_challenge=req.expected,
        claim_token=token,
    )
    if state.claim_time_valid and len(bundle.delegations) > 0:
        progress.persisted.trust_assessment = "unavailable"  # resolution started
        err = record()
        if err is not None:
            return evaluating(err)
        chain = list(bundle.delegations)
        resolution, trust_err = _call_v2_trust_safely(ctx, cb.trust, chain)
        if trust_err is not None and ctx.err() is not None:
            return cancelled(ctx.err())
        root = bundle.delegations[-1]
        trust = "unavailable"
        if trust_err is None and isinstance(resolution, V2TrustResolution):
            if resolution.outcome == V2_TRUST_TRUSTED:
                try:
                    root_id = key_id_v2(resolution.root_key)
                except Exception:  # noqa: BLE001
                    root_id = None
                if root_id is not None and root_id == root.issuer_id and equal_hybrid_public_keys(resolution.root_key, root.issuer_pub_key):
                    trust = "trusted"
                    opts.trusted_root_id, opts.trusted_root_key = root_id, resolution.root_key
            elif resolution.outcome == V2_TRUST_UNTRUSTED:
                # Configured trust that excludes this chain: the local
                # evaluation compares against an empty root and denies.
                trust = "untrusted"
        opts.trust_configured = trust != "unavailable"
        progress.trust_completed = True
        progress.persisted.trust_assessment = trust
    assessment = evaluate_proof_bundle_v2_local_authorization(bundle, opts)
    claimed_at = state.claimed_at
    if progress.trust_completed:
        if (progress.persisted.trust_assessment == "trusted" and assessment.context_assessment in ("bound", "not_required")
                and assessment.context_policy_digest is not None):
            progress.persisted.context_assessment = assessment.context_assessment
            progress.persisted.context_policy_digest = assessment.context_policy_digest
        if assessment.status == "pending_external_checks":
            progress.persisted.status_assessment = "unavailable"  # status started
        err = record()
        if err is not None:
            return evaluating(err)

    if assessment.status == "pending_external_checks":
        from .status_provenance_v2 import _run_v2_status_stage

        stage = _run_v2_status_stage(ctx, bundle, assessment.status_checks, req, cb, claimed_at)
        if stage.cancelled is not None:
            return cancelled(stage.cancelled)
        progress.persisted.status_assessment = stage.assessment.assessment
        progress.persisted.status_evidence = list(stage.assessment.evidence or [])
        err = record()
        if err is not None:
            return evaluating(err)
        try:
            assessment = _resolve_claim_proof_bundle_v2_after_status(token, lambda _checks: stage.assessment)
        except Exception:  # noqa: BLE001
            _interrupt_v2_evaluation(token)
            assessment = v2_interrupted_assessment(bundle, "evaluation interrupted after status")
    if assessment.status == "pending_external_checks" and any(d.type == CONSTRAINT_RECEIVER_AUDIENCE for d in assessment.deferred):
        audience_deferred = [d for d in assessment.deferred if d.type == CONSTRAINT_RECEIVER_AUDIENCE]
        memberships, audience_err = _call_v2_audience_safely(ctx, cb.audience, audience_deferred,
                                                             req.expected.expected_receiver_id)
        if audience_err is not None:
            if ctx.err() is not None:
                return cancelled(ctx.err())
            memberships = None
        try:
            assessment = resolve_claim_proof_bundle_v2_after_audience(token, memberships)
        except Exception:  # noqa: BLE001
            _interrupt_v2_evaluation(token)
            assessment = v2_interrupted_assessment(bundle, "evaluation interrupted after audience")
    if assessment.status == "pending_external_checks":
        if ctx.err() is not None:
            return cancelled(ctx.err())
        try:
            assessment = resolve_claim_proof_bundle_v2_after_rate(ctx, cb.rate, token)
        except Exception:  # noqa: BLE001
            if ctx.err() is not None:
                return cancelled(ctx.err())
            _interrupt_v2_evaluation(token)
            assessment = v2_interrupted_assessment(bundle, "evaluation interrupted after rate")

    # The claim store reads T_final inside the finalization compare-and-set
    # and rejects a regressed clock or an allow at or beyond its horizon or
    # the challenge expiry; nothing is then committed (SPEC-v2 §7.2, §7.5).
    from .rate_reservation_v2 import V2RateLimitExceededError

    for attempt in range(2):
        try:
            decision, terminal, body = _build_v2_terminal_result(bundle, assessment, progress, claim, claimed_at)
        except Exception as exc:  # noqa: BLE001
            return evaluating(exc)
        try:
            finalize_claim_proof_bundle_v2(ctx, cb.claim_store, token, terminal, body)
            finalize_err = None
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:  # noqa: BLE001 - a store failure (Go: a recovered panic)
            finalize_err = exc
        if finalize_err is None:
            horizon = state.allow_horizon() if decision == "allow" else 0
            return V2VerifyOutcome(stage=V2_STAGE_COMMITTED, claim=claim, disposition=disposition,
                                   committed=_new_committed_v2_outcome(claim, body, horizon))
        if ctx.err() is not None:
            return cancelled(ctx.err())
        if not isinstance(finalize_err, V2RateLimitExceededError) or attempt > 0:
            if error_class_of(finalize_err) == V2ErrorClass.UNCLASSIFIED:
                finalize_err = classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, finalize_err)
            return evaluating(finalize_err)
        # A barrier store proved definitive capacity exhaustion and rolled
        # back; the same claim finalizes once as constraint_denied.
        assessment.status, assessment.reason = "constraint_denied", "constraint_denied"
        assessment.detail = "signed rate limit has no remaining capacity"
    return evaluating(classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, ValueError("v2 terminal finalization did not complete")))


def _validate_v2_verify_configuration(req: V2VerifyRequest, request_context) -> None:
    """Go ``validateV2VerifyConfiguration``."""
    from .constraint_evaluator_v2 import ConstraintEvaluatorRegistryV2

    for name in ("replay_epoch", "now", "max_challenge_age_seconds", "future_skew_seconds"):
        if not is_int(getattr(req, name)):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, f"v2 request {name} must be an integer")
    for name in ("required_scope", "verifier_namespace", "verifier_id", "tzdb_version"):
        if not isinstance(getattr(req, name), str):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, f"v2 request {name} must be a string")
    validate_v2_freshness_configuration(req.now, req.max_challenge_age_seconds, req.future_skew_seconds)
    _validate_v2_verifier_identity_configuration(req.verifier_namespace, req.replay_epoch, req.verifier_id)
    # The live verifier has one future skew (SPEC-v2 §6.1): status freshness
    # uses future_skew_seconds, so a status policy carrying another skew is a
    # configuration error rather than a second, silently different bound.
    status_skew = getattr(req.status_policy, "clock_skew_seconds", None)
    if not is_int(status_skew) or status_skew != req.future_skew_seconds:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 status policy skew must equal future_skew_seconds")
    _validate_v2_request_context(request_context)
    registry = req.constraint_evaluators
    if registry is not None and (not isinstance(registry, ConstraintEvaluatorRegistryV2) or getattr(registry, "_valid", False) is not True):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID,
                      "v2 constraint evaluator registry was not built by new_constraint_evaluator_registry_v2")
    _validate_v2_status_configuration(req.status_keys, req.status_policy)


def _utf8_ok(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _validate_v2_request_context(c) -> None:
    """Go ``validateV2RequestContext``."""
    from .constraint_evaluator_v2 import validate_v2_extension_context
    from .constraints_v2 import ConstraintContextV2, valid_iso4217_alpha_v2

    invalid = V2ErrorClass.CONFIGURATION_INVALID
    if not isinstance(c, ConstraintContextV2):
        raise V2Error(invalid, "v2 request context has the wrong type")
    if not isinstance(c.has_amount, bool) or not isinstance(c.has_resource, bool) or not is_int(c.requested_amount_micros):
        raise V2Error(invalid, "v2 request context has a field of the wrong type")
    if not isinstance(c.requested_currency, str) or not isinstance(c.requested_resource_id, str) or not isinstance(c.requested_path, str):
        raise V2Error(invalid, "v2 request context has a field of the wrong type")
    if c.has_amount:
        if c.requested_amount_micros < 0 or c.requested_amount_micros > MAX_SAFE_INTEGER or not valid_iso4217_alpha_v2(c.requested_currency):
            raise V2Error(invalid, f"v2 request amount must be 0..{MAX_SAFE_INTEGER} micro-units with a three-letter A-Z currency")
    elif c.requested_amount_micros != 0 or c.requested_currency != "":
        raise V2Error(invalid, "v2 request amount and currency must be supplied together with has_amount")
    if c.has_resource:
        if (not _utf8_ok(c.requested_resource_id) or not _utf8_ok(c.requested_path)
                or len(c.requested_resource_id.encode("utf-8")) > MAX_IDENTIFIER_LENGTH_BYTES):
            raise V2Error(invalid, f"v2 requested resource ID and path must be valid UTF-8 and the resource ID at most {MAX_IDENTIFIER_LENGTH_BYTES} bytes")
    elif c.requested_resource_id != "" or c.requested_path != "":
        raise V2Error(invalid, "v2 requested resource ID and path must be supplied with has_resource")
    validate_v2_extension_context(c)


def _validate_v2_status_configuration(keys, policy) -> None:
    """Go ``validateV2StatusConfiguration``."""
    from .status_provenance_v2 import V2StatusKeyConfig
    from .status_state_v2 import RevocationStatusPolicyV2

    invalid = V2ErrorClass.CONFIGURATION_INVALID
    if not isinstance(policy, RevocationStatusPolicyV2):
        raise V2Error(invalid, "v2 status policy is required")
    for value in (policy.max_list_lifetime_seconds, policy.max_status_age_seconds, policy.clock_skew_seconds):
        if not is_int(value):
            raise V2Error(invalid, "v2 status policy bounds must be integers")
    if (policy.max_list_lifetime_seconds < 1 or policy.max_list_lifetime_seconds > V2_MAX_STATUS_LIFETIME_SECONDS
            or policy.max_status_age_seconds < 1 or policy.max_status_age_seconds > V2_MAX_STATUS_LIFETIME_SECONDS
            or policy.clock_skew_seconds < 0 or policy.clock_skew_seconds > V2_MAX_FUTURE_SKEW_SECONDS):
        raise V2Error(invalid, f"v2 status policy must bound list lifetime and status age to 1..{V2_MAX_STATUS_LIFETIME_SECONDS} seconds and skew to 0..{V2_MAX_FUTURE_SKEW_SECONDS}")
    if keys is None:
        return
    if not isinstance(keys, dict):
        raise V2Error(invalid, "v2 status-key configuration must be a mapping")
    for issuer_id, config in keys.items():
        if (not valid_v2_id(issuer_id) or not isinstance(config, V2StatusKeyConfig) or not is_int(config.epoch)
                or config.epoch <= 0 or config.epoch > MAX_SAFE_INTEGER):
            raise V2Error(invalid, "v2 status-key configuration has an invalid issuer or epoch")
        try:
            key_id_v2(config.key)
        except Exception as exc:  # noqa: BLE001
            raise V2Error(invalid, f"v2 status-key configuration has an invalid key: {exc}") from exc


def _build_v2_terminal_result(bundle, assessment: V2LocalAuthorizationAssessment, progress: _V2EvaluationProgress,
                              claim: V2ChallengeClaim, verified_at: int) -> tuple[str, bytes, bytes]:
    """Go ``buildV2TerminalResult``: map a terminal assessment to the receipt
    tuple of SPEC-v2 §5.8 and §6.7 and prepare the exact outbox body."""
    from .types_v2 import clone_constraint_evaluator_refs_v2
    from .verification_receipt_v2 import VerificationReceiptV2, verification_receipt_v2_body

    decision, ok = terminal_decision_for_v2_evaluation(assessment.status, assessment.reason)
    if not ok:
        raise ValueError(f"v2 evaluation did not reach a terminal result: {assessment.status}/{assessment.reason}")
    trust = progress.persisted.trust_assessment
    status_assessment = assessment.status_assessment or "not_evaluated"
    context_assessment = assessment.context_assessment or "not_evaluated"
    evidence = list(assessment.status_evidence or [])
    if assessment.reason == "not_delegated":
        trust = "not_evaluated"
    if status_assessment == "not_evaluated":
        evidence = []
    policy_digest = None
    if context_assessment not in ("not_evaluated", "unbound") and assessment.context_policy_digest is not None:
        policy_digest = assessment.context_policy_digest
    if assessment.reason == "evaluation_interrupted":
        p = clone_v2_evaluation_progress(progress.persisted)
        trust, status_assessment, context_assessment = p.trust_assessment, p.status_assessment, p.context_assessment
        policy_digest, evidence = p.context_policy_digest, p.status_evidence
    granted: list = []
    if decision == "allow":
        granted = sorted(set(assessment.effective_scope or []), key=lambda s: s.encode("utf-8"))
    receipt = VerificationReceiptV2(
        version=2, verifier_id=bundle.verifier_id, agent_id=bundle.agent_id, bundle_hash=claim.bundle_hash,
        issuer_ids=list(claim.issuer_ids), decision=decision, decision_reason=assessment.reason,
        identity_status=assessment.status, trust_assessment=trust, status_assessment=status_assessment,
        challenge_assessment="current", context_assessment=context_assessment, context_policy_digest=policy_digest,
        verified_at=verified_at, required_scope=claim.required_scope, granted_scope=granted, status_evidence=evidence,
        constraint_evaluators=clone_constraint_evaluator_refs_v2(claim.constraint_evaluators),
    )
    try:
        body = verification_receipt_v2_body(receipt)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"v2 terminal receipt body is inconsistent with the evaluated result: {exc}") from exc
    terminal = canonical({"decision": decision, "decision_reason": assessment.reason, "identity_status": assessment.status})
    return decision, terminal, body


# ---------------------------------------------------------------------------
# Fail-closed callback adapters. An exception is treated exactly like an error.


def _safe_v2_receiver_binding(hook: Optional[Callable]) -> Optional[Callable]:
    if hook is None:
        return None

    def safe(bundle, expected):
        hook(bundle, expected)

    return safe


def _call_v2_trust_safely(ctx, trust: Optional[Callable], chain: list):
    if trust is None:
        return V2TrustResolution(), None
    try:
        return trust(ctx, chain), None
    except (KeyboardInterrupt, SystemExit):
        # The caller's own cancellation propagates.
        raise
    except BaseException as exc:  # noqa: BLE001 - any provider failure (Go: a recovered panic) fails closed
        return None, exc


def _call_v2_audience_safely(ctx, audience: Optional[Callable], deferred: list, receiver_id: str):
    if audience is None:
        return None, None
    try:
        return audience(ctx, deferred, receiver_id), None
    except (KeyboardInterrupt, SystemExit):
        # The caller's own cancellation propagates.
        raise
    except BaseException as exc:  # noqa: BLE001 - any provider failure (Go: a recovered panic) fails closed
        return None, exc
