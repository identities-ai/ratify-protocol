"""Protocol v2 live verification (mirrors Go verify_v2_preflight.go,
claim_store_v2.go, authorization_v2.go, and verify_v2.go).

``verify_proof_bundle_v2`` runs the SPEC-v2 §6 order: bounded strict decode
and structure, required scope, key-ID/digest/linkage/duplicate checks, every
signature, authenticated ExpectedChallenge validation and freshness, the pure
receiver-binding hook, the atomic challenge claim, and only then trust, local
authorization, status for every CertificateRef, receiver audience, and
max_rate reservation, followed by terminal finalization through the claim
store. No claim, trust, status, audience, or rate callback runs on a
pre-claim failure.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Callable, Optional, Protocol
from zoneinfo import ZoneInfo

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .challenge_claim_v2 import challenge_claim_digest_v2, protocol_claim_id_v2
from .constraints import _evaluate_constraint, _parse_hhmm
from .context_policy_v2 import (
    MAX_RATE,
    V2AudienceMembership,
    V2ContextPolicy,
    V2DeferredConstraint,
    V2RateReservation,
    build_v2_rate_reservation_batch,
    clone_v2_context_policy,
    evaluate_proof_bundle_v2_context_policy,
    evaluate_receiver_audience_v2,
    same_v2_context_policy,
    signed_v2_rate_reservation_batch,
)
from .errors_v2 import RateLimitExceededError, V2Error, V2ErrorClass, classify, error_class_of
from .protocol_v2 import (
    RECEIVER_AUDIENCE,
    SCOPE_IDENTITY_DELEGATE,
    DelegationCertV2,
    ProofBundleV2,
    bundle_hash_v2,
    constraint_canonical_json,
    decode_proof_bundle_v2,
    valid_prefixed_digest_v2,
    valid_v2_id,
    validate_required_scope_v2,
    validate_scopes_v2,
    verify_proof_bundle_v2_signatures,
)
from .scope import intersect_scopes
from .signing_v2 import equal_public_keys, key_id_v2
from .status_v2 import (
    RevocationStatusResultV2,
    V2CertificateStatusCheck,
    V2StatusRoleBindings,
    aggregate_certificate_status_v2,
)
from .types import HybridPublicKey, VerifierContext
from .verification_receipt_v2 import StatusEvidenceEntryV2, VerificationReceiptV2, verification_receipt_v2_body

# ---------------------------------------------------------------------------
# Expected challenge and preflight


@dataclass
class ExpectedChallengeV2:
    """Verifier-authenticated issuance state."""
    value: bytes
    issued_at: int
    expires_at: int
    verifier_namespace: str
    replay_epoch: int
    verifier_id: str
    expected_agent_id: str = ""
    expected_agent_public_key: Optional[HybridPublicKey] = None
    expected_receiver_id: str = ""
    expected_session_context: Optional[bytes] = None
    context_policy: Optional[V2ContextPolicy] = None


@dataclass
class _SealedState:
    value: bytes
    issued_at: int
    expires_at: int
    verifier_namespace: str
    replay_epoch: int
    verifier_id: str
    expected_agent_id: str
    expected_agent_public_key: Optional[HybridPublicKey]
    expected_receiver_id: str
    expected_session_context: Optional[bytes]
    required_scope: str
    bundle_hash: str
    issuer_ids: list[str]
    future_skew: int
    max_age: int
    context_policy_digest: str
    context_policy: Optional[V2ContextPolicy]
    no_context_policy: bool


class V2PreflightResult:
    """Seals the authenticated issuance, policy, and proof identity."""

    __slots__ = ("_state",)

    def __init__(self, state: _SealedState):
        self._state = state


def _bytes_eq(a: Optional[bytes], b: Optional[bytes]) -> bool:
    return (a or b"") == (b or b"")


def _matches_expected(expected: Optional[ExpectedChallengeV2], state: Optional[_SealedState]) -> bool:
    if (
        expected is None or state is None or not _bytes_eq(expected.value, state.value)
        or expected.issued_at != state.issued_at or expected.expires_at != state.expires_at
        or expected.verifier_namespace != state.verifier_namespace or expected.replay_epoch != state.replay_epoch
        or expected.verifier_id != state.verifier_id or expected.expected_agent_id != state.expected_agent_id
        or expected.expected_receiver_id != state.expected_receiver_id
        or not _bytes_eq(expected.expected_session_context, state.expected_session_context)
        or (expected.context_policy is not None and not same_v2_context_policy(expected.context_policy, state.context_policy))
    ):
        return False
    if (expected.expected_agent_public_key is None) != (state.expected_agent_public_key is None):
        return False
    return expected.expected_agent_public_key is None or equal_public_keys(
        expected.expected_agent_public_key, state.expected_agent_public_key)


def _policy_valid(policy: V2ContextPolicy) -> bool:
    return policy.valid and bool(policy.digest) and valid_prefixed_digest_v2(policy.digest)


def validate_proof_bundle_v2_preflight(bundle: ProofBundleV2, expected: ExpectedChallengeV2, required_scope: str,
                                       configured_namespace: str, configured_replay_epoch: int, now_unix: int,
                                       max_age_seconds: int, future_skew_seconds: int) -> None:
    """Pure pre-claim checks; no external calls and no authorization decision."""
    cfg = V2ErrorClass.CONFIGURATION_INVALID
    policy = expected.context_policy
    if policy is not None:
        if not _policy_valid(policy):
            raise V2Error(cfg, "v2 expected context policy is invalid")
        if policy.require_bound and (not _bytes_eq(expected.expected_session_context, policy.expected_session_context)
                                     or len(expected.expected_session_context or b"") != 32):
            raise V2Error(cfg, "v2 expected context does not match its policy")
        if not policy.require_bound and expected.expected_session_context is not None:
            raise V2Error(cfg, "unbound v2 context policy cannot have an expected session context")
    try:
        validate_required_scope_v2(required_scope)
    except ValueError as exc:
        raise V2Error(V2ErrorClass.INVALID_REQUIRED_SCOPE, f"v2 request scope: {exc}") from exc
    verify_proof_bundle_v2_signatures(bundle)
    if not configured_namespace or expected.verifier_namespace != configured_namespace:
        raise V2Error(V2ErrorClass.NAMESPACE_MISMATCH, "v2 challenge verifier namespace mismatch")
    if (
        not 0 <= configured_replay_epoch <= MAX_SAFE_INTEGER or not 0 <= expected.replay_epoch <= MAX_SAFE_INTEGER
        or expected.replay_epoch != configured_replay_epoch
    ):
        raise V2Error(V2ErrorClass.STALE_REPLAY_EPOCH, "v2 challenge replay epoch is stale")
    if not expected.verifier_id or expected.verifier_id != bundle.verifier_id or not valid_v2_id(expected.verifier_id):
        raise V2Error(V2ErrorClass.VERIFIER_ID_MISMATCH, "v2 challenge verifier ID mismatch")
    if len(expected.value or b"") != 32 or bytes(bundle.challenge) != bytes(expected.value) or bundle.challenge_at != expected.issued_at:
        raise V2Error(V2ErrorClass.CHALLENGE_MISMATCH, "v2 proof does not match authenticated challenge issuance")
    if (
        not -MAX_SAFE_INTEGER <= expected.issued_at <= MAX_SAFE_INTEGER
        or not -MAX_SAFE_INTEGER <= expected.expires_at <= MAX_SAFE_INTEGER or expected.expires_at <= expected.issued_at
    ):
        raise V2Error(cfg, "v2 authenticated challenge time bounds are invalid")
    if (
        not -MAX_SAFE_INTEGER <= now_unix <= MAX_SAFE_INTEGER or max_age_seconds <= 0 or max_age_seconds > MAX_SAFE_INTEGER
        or future_skew_seconds < 0 or future_skew_seconds > MAX_SAFE_INTEGER
    ):
        raise V2Error(cfg, "v2 freshness policy is invalid")
    not_fresh = V2ErrorClass.CHALLENGE_NOT_FRESH
    if expected.issued_at > now_unix and expected.issued_at - now_unix > future_skew_seconds:
        raise V2Error(not_fresh, "v2 challenge issuance is too far in the future")
    if now_unix >= expected.expires_at:
        raise V2Error(not_fresh, "v2 challenge is expired")
    if now_unix - expected.issued_at > max_age_seconds:
        raise V2Error(not_fresh, "v2 challenge exceeds maximum age")
    if (expected.expected_agent_id == "") != (expected.expected_agent_public_key is None):
        raise V2Error(cfg, "v2 expected agent ID and public key must be configured together")
    if expected.expected_agent_public_key is not None:
        try:
            agent_id = key_id_v2(expected.expected_agent_public_key)
        except ValueError as exc:
            raise V2Error(cfg, f"v2 expected agent key: {exc}") from exc
        if (
            agent_id != expected.expected_agent_id or bundle.agent_id != agent_id
            or not equal_public_keys(bundle.agent_pub_key, expected.expected_agent_public_key)
        ):
            raise V2Error(V2ErrorClass.EXPECTED_AGENT_MISMATCH, "v2 presentation does not match authenticated expected agent")
    if expected.expected_session_context is not None:
        if (
            len(expected.expected_session_context) != 32 or bundle.session_context is None
            or bytes(bundle.session_context) != bytes(expected.expected_session_context)
        ):
            raise V2Error(V2ErrorClass.SESSION_CONTEXT_MISMATCH, "v2 presentation does not match expected session context")
    _check_exact_receiver_audience(bundle, expected.expected_receiver_id)


def _check_exact_receiver_audience(bundle: ProofBundleV2, receiver_id: str) -> None:
    for i, cert in enumerate(bundle.delegations):
        for constraint in cert.constraints:
            if constraint.type != RECEIVER_AUDIENCE:
                continue
            if receiver_id == "":
                raise V2Error(V2ErrorClass.RECEIVER_AUDIENCE_REQUIRED,
                              "v2 receiver audience requires an authenticated expected receiver ID")
            params = constraint.params or {}
            exact = params.get("exact_receiver_ids") if isinstance(params.get("exact_receiver_ids"), list) else []
            domains = params.get("trust_domain_ids") if isinstance(params.get("trust_domain_ids"), list) else []
            matches = any(isinstance(v, str) and v == receiver_id for v in exact)
            if not domains and not matches:
                raise V2Error(V2ErrorClass.RECEIVER_AUDIENCE_MISMATCH,
                              f"v2 receiver does not match exact-only audience at delegation {i}")


def _preflight(bundle: ProofBundleV2, expected: Optional[ExpectedChallengeV2], policy: Optional[V2ContextPolicy],
               allow_no_policy: bool, hook, required_scope: str, configured_namespace: str,
               configured_replay_epoch: int, now_unix: int, max_age_seconds: int,
               future_skew_seconds: int) -> V2PreflightResult:
    cfg = V2ErrorClass.CONFIGURATION_INVALID
    if expected is None:
        raise V2Error(V2ErrorClass.EXPECTED_CHALLENGE_MISSING, "v2 expected challenge is unavailable")
    if (policy is None and not allow_no_policy) or (policy is not None and not _policy_valid(policy)):
        raise V2Error(cfg, "v2 context policy is missing or invalid")
    if policy is None and expected.context_policy is not None:
        raise V2Error(cfg, "v2 challenge context policy does not match the issued policy")
    if policy is not None:
        if expected.context_policy is not None and not same_v2_context_policy(expected.context_policy, policy):
            raise V2Error(cfg, "v2 challenge context policy does not match the issued policy")
        if policy.require_bound:
            if not _bytes_eq(expected.expected_session_context, policy.expected_session_context) or len(expected.expected_session_context or b"") != 32:
                raise V2Error(cfg, "v2 challenge context does not match the configured context policy")
        elif expected.expected_session_context is not None:
            raise V2Error(cfg, "unbound v2 context policy cannot have an expected session context")
    checked = copy.copy(expected)
    checked.context_policy = policy
    validate_proof_bundle_v2_preflight(bundle, checked, required_scope, configured_namespace, configured_replay_epoch,
                                       now_unix, max_age_seconds, future_skew_seconds)
    if hook is not None:
        try:
            hook(bundle, checked)
        except Exception as exc:  # noqa: BLE001 - any rejection by the application hook
            raise V2Error(V2ErrorClass.RECEIVER_BINDING_REJECTED,
                          f"v2 receiver-binding hook rejected the presentation: {exc}") from exc
    try:
        bundle_hash = bundle_hash_v2(bundle)
    except (ValueError, V2Error) as exc:
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    issuer_ids = sorted({cert.issuer_id for cert in bundle.delegations})
    return V2PreflightResult(_SealedState(
        value=bytes(expected.value), issued_at=expected.issued_at, expires_at=expected.expires_at,
        verifier_namespace=expected.verifier_namespace, replay_epoch=expected.replay_epoch,
        verifier_id=expected.verifier_id, expected_agent_id=expected.expected_agent_id,
        expected_agent_public_key=copy.deepcopy(expected.expected_agent_public_key),
        expected_receiver_id=expected.expected_receiver_id,
        expected_session_context=None if expected.expected_session_context is None else bytes(expected.expected_session_context),
        required_scope=required_scope, bundle_hash=bundle_hash, issuer_ids=issuer_ids,
        future_skew=future_skew_seconds, max_age=max_age_seconds,
        context_policy_digest=policy.digest if policy is not None else "",
        context_policy=clone_v2_context_policy(policy), no_context_policy=policy is None,
    ))


def preflight_proof_bundle_v2(bundle: ProofBundleV2, expected: Optional[ExpectedChallengeV2],
                              policy: Optional[V2ContextPolicy], required_scope: str, configured_namespace: str,
                              configured_replay_epoch: int, now_unix: int, max_age_seconds: int,
                              future_skew_seconds: int) -> V2PreflightResult:
    """Public preflight; requires a context policy."""
    return _preflight(bundle, expected, policy, False, None, required_scope, configured_namespace,
                      configured_replay_epoch, now_unix, max_age_seconds, future_skew_seconds)


# ---------------------------------------------------------------------------
# Claim store


V2_CLAIM_CREATED = "created"
V2_CLAIM_IN_PROGRESS = "in_progress"
V2_CLAIM_TERMINAL_REPLAY = "terminal_replay"


@dataclass
class V2ChallengeClaim:
    claim_id: str = ""
    namespace: str = ""
    replay_epoch: int = 0
    challenge_digest: str = ""
    proof_digest: str = ""
    bundle_hash: str = ""
    issuer_ids: list[str] = field(default_factory=list)
    required_scope: str = ""
    context_policy_digest: str = ""
    verifier_id: str = ""
    agent_id: str = ""
    requires_rate: bool = False
    rate_batch: list[V2RateReservation] = field(default_factory=list)
    issued_at: int = 0
    expires_at: int = 0
    max_age_seconds: int = 0
    clock_skew_seconds: int = 0
    stream_id: Optional[bytes] = None
    stream_seq: Optional[int] = None


@dataclass
class V2ClaimResult:
    disposition: str
    claimed_at: int
    owner_token: bytes = b""


class ClaimStoreV2(Protocol):
    """Atomic, durable challenge-claim storage (see Go ClaimStoreV2 for the
    full implementer contract). Raise ClaimProofConflictError for a different
    proof on the same replay key; any other exception is unavailable."""

    def claim_v2(self, claim: V2ChallengeClaim) -> V2ClaimResult: ...

    def finalize_v2_claim(self, claim_id: str, owner_token: bytes, terminal_result: bytes,
                          receipt_body: bytes, allow_valid_until: int) -> bool: ...

    def recover_interrupted_v2_claim(self, claim_id: str, terminal_result: bytes, receipt_body: bytes) -> bool: ...


class V2RateReservationStore(Protocol):
    """Atomically reserve the complete claim-sealed batch; raise
    RateLimitExceededError for definitive exhaustion."""

    def reserve_v2_rate_batch(self, claim_id: str, owner_token: bytes, bundle_hash: str,
                              batch: list[V2RateReservation]) -> None: ...


def _is_rate_at_finalization_store(store: Any) -> bool:
    return bool(getattr(store, "admits_v2_rate_at_finalization", False)) and hasattr(store, "finalize_v2_claim") and hasattr(store, "reserve_v2_rate_batch")


class _TokenState:
    def __init__(self, claim_id, proof_digest, required_scope, future_skew, expected, owner_token, claimed_at,
                 claim_time_valid, rate_batch):
        self.claim_id = claim_id
        self.proof_digest = proof_digest
        self.required_scope = required_scope
        self.future_skew = future_skew
        self.expected: _SealedState = expected
        self.used = False
        self.evaluation_complete = False
        self.finalization_digest = b""
        self.finalization_started = False
        self.claim_time_valid = claim_time_valid
        self.claimed_at = claimed_at
        self.evaluated_at = 0
        self.rate_batch = list(rate_batch)
        self.rate_at_finalization = False
        self.allow_valid_until = 0
        self.owner_token = bytes(owner_token)
        self.evaluation_status = ""
        self.evaluation_reason = ""
        self.pending_assessment: Optional[V2LocalAuthorizationAssessment] = None


class V2EvaluationToken:
    """Single-use capability for one evaluation of a newly created claim."""

    __slots__ = ("_state",)

    def __init__(self, state: _TokenState):
        self._state = state


def claim_proof_bundle_v2(store, bundle: ProofBundleV2, preflight: Optional[V2PreflightResult], configured_namespace: str,
                          configured_replay_epoch: int, now_unix: int):
    """Repeat the freshness and binding checks, then claim atomically.
    Returns (claim, disposition, token-or-None)."""
    if store is None:
        raise ValueError("v2 claim store is required")
    if preflight is None or preflight._state is None or (preflight._state.context_policy is None and not preflight._state.no_context_policy):
        raise ValueError("v2 successful preflight state is required before claim")
    sealed = copy.deepcopy(preflight._state)
    try:
        bundle_hash = bundle_hash_v2(bundle)
    except (ValueError, V2Error):
        bundle_hash = None
    if bundle_hash != sealed.bundle_hash:
        raise ValueError("v2 proof bundle differs from successful preflight")
    expected = ExpectedChallengeV2(
        value=sealed.value, issued_at=sealed.issued_at, expires_at=sealed.expires_at,
        verifier_namespace=sealed.verifier_namespace, replay_epoch=sealed.replay_epoch, verifier_id=sealed.verifier_id,
        expected_agent_id=sealed.expected_agent_id, expected_agent_public_key=sealed.expected_agent_public_key,
        expected_receiver_id=sealed.expected_receiver_id, expected_session_context=sealed.expected_session_context,
        context_policy=sealed.context_policy,
    )
    validate_proof_bundle_v2_preflight(bundle, expected, sealed.required_scope, configured_namespace,
                                       configured_replay_epoch, now_unix, sealed.max_age, sealed.future_skew)
    challenge_digest = challenge_claim_digest_v2(sealed.value)
    claim_id = protocol_claim_id_v2(sealed.verifier_namespace, sealed.replay_epoch, sealed.value)
    claim = V2ChallengeClaim(
        claim_id=claim_id, namespace=sealed.verifier_namespace, replay_epoch=sealed.replay_epoch,
        challenge_digest="sha384:" + challenge_digest.hex(), proof_digest=bundle_hash, bundle_hash=sealed.bundle_hash,
        issuer_ids=list(sealed.issuer_ids), required_scope=sealed.required_scope,
        context_policy_digest=sealed.context_policy_digest, verifier_id=sealed.verifier_id, agent_id=bundle.agent_id,
        issued_at=sealed.issued_at, expires_at=sealed.expires_at, max_age_seconds=sealed.max_age,
        clock_skew_seconds=sealed.future_skew,
        stream_id=None if bundle.stream_id is None else bytes(bundle.stream_id), stream_seq=bundle.stream_seq,
    )
    try:
        claim.rate_batch = signed_v2_rate_reservation_batch(bundle)
    except ValueError as exc:
        raise ValueError(f"v2 signed rate batch: {exc}") from exc
    claim.requires_rate = len(claim.rate_batch) != 0
    result = store.claim_v2(copy.deepcopy(claim))
    if result.disposition == V2_CLAIM_CREATED:
        if len(result.owner_token or b"") != 32:
            raise ValueError("v2 claim store returned an invalid evaluator owner token")
        at = result.claimed_at
        claim_time_valid = (
            -MAX_SAFE_INTEGER <= at <= MAX_SAFE_INTEGER
            and not (at < sealed.issued_at and sealed.issued_at - at > sealed.future_skew)
            and at < sealed.expires_at
            and not (at > sealed.issued_at and at - sealed.issued_at > sealed.max_age)
        )
        return claim, result.disposition, V2EvaluationToken(_TokenState(
            claim.claim_id, claim.proof_digest, sealed.required_scope, sealed.future_skew, sealed,
            result.owner_token, at, claim_time_valid, claim.rate_batch,
        ))
    if result.disposition in (V2_CLAIM_IN_PROGRESS, V2_CLAIM_TERMINAL_REPLAY):
        if result.owner_token:
            raise ValueError("v2 exact retry must not receive evaluator ownership")
        return claim, result.disposition, None
    raise ValueError("v2 claim store returned an invalid disposition")


def terminal_decision_for_v2_evaluation(status: str, reason: str) -> tuple[str, bool]:
    if reason == "evaluation_interrupted":
        return "indeterminate", status == "authorization_unverified"
    if status == "authorization_unverified":
        return "indeterminate", reason in ("trust_unavailable", "action_context_unverified", "status_unavailable", "status_stale")
    if status == "authorized_agent":
        return "allow", reason == "authorized"
    if status in ("constraint_denied", "constraint_unverifiable", "constraint_unknown", "unauthorized", "invalid_scope", "scope_denied"):
        return "deny", reason == status
    if status == "revoked":
        return "deny", reason == "delegation_revoked"
    if status == "invalid":
        return "deny", reason == "proof_invalid"
    if status == "delegation_not_authorized":
        return "deny", reason in ("not_delegated", "delegation_not_authorized")
    if status == "expired":
        return "deny", reason == "delegation_expired"
    return "", False


def _read_decision(value: bytes) -> Optional[tuple[str, str]]:
    try:
        obj = _v2json.parse(value)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    decision, reason = obj.get("decision"), obj.get("decision_reason")
    decision = "" if decision is None else decision
    reason = "" if reason is None else reason
    if not isinstance(decision, str) or not isinstance(reason, str):
        return None
    return decision, reason


def _finalization_digest(terminal_result: bytes, receipt_body: bytes) -> bytes:
    return sha256(len(terminal_result).to_bytes(8, "big") + terminal_result
                  + len(receipt_body).to_bytes(8, "big") + receipt_body).digest()


def finalize_claim_proof_bundle_v2(store, token: Optional[V2EvaluationToken], terminal_result: bytes,
                                   receipt_body: bytes) -> bool:
    """Commit a terminal evaluation through the capability that won the claim."""
    if store is None or token is None or token._state is None or len(token._state.owner_token) != 32 or not token._state.claim_id:
        raise ValueError("v2 claim store and valid evaluator capability are required")
    state = token._state
    terminal_result, receipt_body = bytes(terminal_result), bytes(receipt_body)
    if not state.evaluation_complete:
        raise ValueError("v2 proof evaluation has not completed")
    decision, ok = terminal_decision_for_v2_evaluation(state.evaluation_status, state.evaluation_reason)
    if not ok:
        raise ValueError("v2 proof evaluation has not reached a terminal local result")
    result_pair, body_pair = _read_decision(terminal_result), _read_decision(receipt_body)
    want = (decision, state.evaluation_reason)
    if result_pair != want or body_pair != want:
        raise ValueError("v2 terminal result does not match the completed local evaluation")
    if (decision == "allow" and state.allow_valid_until <= 0) or (decision != "allow" and state.allow_valid_until != 0):
        raise ValueError("v2 terminal result lacks a valid allow freshness horizon")
    if state.rate_at_finalization and not _is_rate_at_finalization_store(store):
        raise ValueError("v2 rate-at-finalization requires an atomic rate store")
    digest = _finalization_digest(terminal_result, receipt_body)
    if state.finalization_started and state.finalization_digest != digest:
        raise ValueError("v2 evaluator capability cannot change its terminal result or receipt body")
    state.finalization_started = True
    state.finalization_digest = digest
    try:
        return bool(store.finalize_v2_claim(state.claim_id, bytes(state.owner_token), terminal_result, receipt_body,
                                            state.allow_valid_until))
    except RateLimitExceededError:
        if state.rate_at_finalization and decision == "allow" and _is_rate_at_finalization_store(store):
            state.evaluation_status, state.evaluation_reason = "constraint_denied", "constraint_denied"
            state.allow_valid_until = 0
            state.rate_at_finalization = False
            state.finalization_started = False
            state.finalization_digest = b""
        raise


# ---------------------------------------------------------------------------
# Local authorization


@dataclass
class V2LocalPolicyFailure:
    status: str
    reason: str
    detail: str


@dataclass
class V2LocalAuthorizationAssessment:
    bundle_hash: str = ""
    issuer_ids: list[str] = field(default_factory=list)
    agent_id: str = ""
    root_id: str = ""
    required_scope: str = ""
    delegation_digest: bytes = b""
    effective_scope: Optional[list[str]] = None
    context_assessment: str = ""
    context_policy_digest: Optional[str] = None
    status_assessment: str = ""
    delegation_valid_until: int = 0
    local_time_valid_until: int = 0
    status_fresh_until: int = 0
    audience_fresh_until: int = 0
    status_evidence: list[StatusEvidenceEntryV2] = field(default_factory=list)
    audience_evidence_digests: list[str] = field(default_factory=list)
    rate_store_unavailable: bool = False
    rate_admission_deferred: bool = False
    status_checks: list[V2CertificateStatusCheck] = field(default_factory=list)
    deferred: list[V2DeferredConstraint] = field(default_factory=list)
    local_policy_failure: Optional[V2LocalPolicyFailure] = None
    status: str = ""
    reason: str = ""
    detail: str = ""


@dataclass
class V2LocalAuthorizationOptions:
    now: int
    future_skew: int
    required_scope: str
    trusted_root_id: str = ""
    trusted_root_key: Optional[HybridPublicKey] = None
    trust_configured: bool = False
    context: Optional[VerifierContext] = None
    context_policy: Optional[V2ContextPolicy] = None
    expected_challenge: Optional[ExpectedChallengeV2] = None
    claim_token: Optional[V2EvaluationToken] = None


def _local(status: str, reason: str, scope, detail: str) -> V2LocalAuthorizationAssessment:
    return V2LocalAuthorizationAssessment(effective_scope=scope, context_assessment="not_evaluated",
                                          status=status, reason=reason, detail=detail)


def _interrupted(detail: str) -> V2LocalAuthorizationAssessment:
    return _local("authorization_unverified", "evaluation_interrupted", None, detail)


_PRECEDENCE = {"constraint_denied": 3, "constraint_unknown": 2, "constraint_unverifiable": 1}


def _precedence(status: str) -> int:
    return _PRECEDENCE.get(status, 0)


def _evaluate_local_constraints(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions, now: int):
    deferred: list[V2DeferredConstraint] = []
    constraint_status = ""
    failures: list[str] = []
    ctx = opts.context if opts.context is not None else VerifierContext()
    for i, cert in enumerate(bundle.delegations):
        for j, constraint in enumerate(cert.constraints):
            if constraint.type in (MAX_RATE, RECEIVER_AUDIENCE):
                try:
                    encoded = constraint_canonical_json(constraint)
                except ValueError as exc:
                    if _precedence("constraint_unverifiable") > _precedence(constraint_status):
                        constraint_status = "constraint_unverifiable"
                    failures.append(f"delegation {i} constraint {j} cannot be encoded: {exc}")
                    continue
                deferred.append(V2DeferredConstraint(i, j, cert.issuer_id, cert.cert_id, constraint.type, encoded))
                continue
            err = _evaluate_constraint(constraint, cert.cert_id, ctx, now)
            if err is not None:
                if err.startswith("constraint_unverifiable"):
                    status = "constraint_unverifiable"
                elif err.startswith("constraint_unknown:"):
                    status = "constraint_unknown"
                else:
                    status = "constraint_denied"
                if constraint_status == "" or _precedence(status) > _precedence(constraint_status):
                    constraint_status = status
                failures.append(f"delegation {i} constraint {j}: {err}")
    return deferred, constraint_status, failures


def _zone_key(local: datetime) -> tuple:
    return (local.utcoffset(), local.tzname(), local.dst())


def _local_time_window_valid_until(bundle: ProofBundleV2, now: int) -> int:
    horizon = 0
    for cert in bundle.delegations:
        for constraint in cert.constraints:
            if constraint.type != "time_window":
                continue
            zone = ZoneInfo(constraint.tz) if constraint.tz not in ("", "UTC") else timezone.utc
            start, end = _parse_hhmm(constraint.start), _parse_hhmm(constraint.end)
            if start is None or end is None:
                raise ValueError("bad time window bounds")
            local = datetime.fromtimestamp(now, tz=timezone.utc).astimezone(zone)
            minute = local.hour * 60 + local.minute
            if (start <= end and (minute < start or minute > end)) or (start > end and start > minute > end):
                raise ValueError("time window is no longer current")
            offset = int(local.utcoffset().total_seconds())
            day_offset = 1 if start > end and minute >= start else 0
            base = datetime(local.year, local.month, local.day, tzinfo=timezone.utc)
            until = int((base + timedelta(days=day_offset, minutes=end + 1)).timestamp()) - offset
            # Go caps the horizon at the end of the current zone period.
            current = _zone_key(local)
            if _zone_key(datetime.fromtimestamp(until, tz=timezone.utc).astimezone(zone)) != current:
                lo, hi = now, until
                while hi - lo > 1:
                    mid = (lo + hi) // 2
                    if _zone_key(datetime.fromtimestamp(mid, tz=timezone.utc).astimezone(zone)) == current:
                        lo = mid
                    else:
                        hi = mid
                until = hi
            if until <= now or until <= 0 or until > MAX_SAFE_INTEGER:
                raise ValueError("time window has no valid terminal horizon")
            if horizon == 0 or until < horizon:
                horizon = until
    return horizon


def evaluate_proof_bundle_v2_local_authorization(bundle: ProofBundleV2,
                                                 opts: V2LocalAuthorizationOptions) -> V2LocalAuthorizationAssessment:
    """Trust-root binding, delegation times, effective scope, context policy, and
    deterministic constraints. Only after preflight and a created claim."""
    token = opts.claim_token
    state = token._state if token is not None else None
    started = False
    assessment: V2LocalAuthorizationAssessment

    def finish(result: V2LocalAuthorizationAssessment) -> V2LocalAuthorizationAssessment:
        if state is not None and state.expected is not None:
            result.bundle_hash = state.expected.bundle_hash
            result.issuer_ids = list(state.expected.issuer_ids)
        if started and result.status:
            state.evaluation_status = result.status
            state.evaluation_reason = result.reason
            if result.status == "pending_external_checks":
                state.pending_assessment = copy.deepcopy(result)
            state.evaluation_complete = True
        return result

    if state is None or state.expected is None:
        return finish(_local("preflight_binding_mismatch", "claim_required", None,
                             "local authorization requires a successful atomic challenge claim"))
    try:
        claim_id = protocol_claim_id_v2(state.expected.verifier_namespace, state.expected.replay_epoch, state.expected.value)
    except ValueError:
        claim_id = None
    if claim_id != state.claim_id or state.proof_digest != state.expected.bundle_hash or len(state.owner_token) != 32:
        return finish(_interrupted("local authorization state differs from successful preflight or atomic claim"))
    if state.used:
        return finish(_local("evaluation_in_progress", "claim_in_progress", None,
                             "the claim's single evaluation token has already been used"))
    state.used = True
    started = True
    if not state.claim_time_valid:
        return finish(_interrupted("claim store returned an authoritative claim time outside the authenticated freshness bounds"))
    if opts.expected_challenge is not None and not _matches_expected(opts.expected_challenge, state.expected):
        return finish(_interrupted("local authorization challenge state differs from successful preflight or atomic claim"))
    now = opts.now
    if now < state.claimed_at:
        now = state.claimed_at
    state.evaluated_at = now
    if opts.required_scope != state.required_scope or opts.future_skew < 0 or opts.future_skew != state.future_skew:
        return finish(_interrupted("local authorization state differs from successful preflight or atomic claim"))
    if opts.required_scope != state.expected.required_scope:
        return finish(_interrupted("required scope differs from the scope validated during preflight"))
    try:
        bundle_hash = bundle_hash_v2(bundle)
    except (ValueError, V2Error):
        bundle_hash = None
    if bundle_hash != state.proof_digest:
        return finish(_interrupted("proof bundle differs from the bundle validated during preflight"))
    if (
        bytes(bundle.challenge) != bytes(state.expected.value) or bundle.challenge_at != state.expected.issued_at
        or bundle.verifier_id != state.expected.verifier_id
    ):
        return finish(_interrupted("proof challenge differs from the challenge validated during preflight"))
    try:
        validate_required_scope_v2(opts.required_scope)
    except ValueError as exc:
        return finish(_interrupted(f"required scope changed after successful preflight: {exc}"))
    try:
        verify_proof_bundle_v2_signatures(bundle)
    except Exception:  # noqa: BLE001
        return finish(_interrupted("proof signature changed after successful preflight"))
    if not bundle.delegations:
        return finish(_local("delegation_not_authorized", "not_delegated", None, "proof has no delegation certificates"))
    if not opts.trust_configured:
        return finish(_local("authorization_unverified", "trust_unavailable", None,
                             "caller-authenticated trust configuration is unavailable"))
    root = bundle.delegations[-1]
    if opts.trusted_root_id != root.issuer_id or opts.trusted_root_key is None or not equal_public_keys(opts.trusted_root_key, root.issuer_pub_key):
        return finish(_local("unauthorized", "unauthorized", None,
                             "delegation chain does not terminate at the configured trust root"))
    for i, cert in enumerate(bundle.delegations):
        if cert.issued_at >= cert.expires_at or cert.issued_at > now + opts.future_skew:
            return finish(_local("invalid", "proof_invalid", None, f"delegation {i} has invalid time bounds"))
    for i, cert in enumerate(bundle.delegations):
        if now >= cert.expires_at:
            return finish(_local("expired", "delegation_expired", None, f"delegation {i} has expired"))
    for i, cert in enumerate(bundle.delegations):
        try:
            validate_scopes_v2(cert.scope)
        except ValueError as exc:
            return finish(_local("invalid_scope", "invalid_scope", None, f"delegation {i}: {exc}"))
    for i in range(len(bundle.delegations) - 1):
        if SCOPE_IDENTITY_DELEGATE not in bundle.delegations[i + 1].scope:
            return finish(_local("delegation_not_authorized", "delegation_not_authorized", None,
                                 f"parent delegation {i + 1} does not grant {SCOPE_IDENTITY_DELEGATE!r}"))
    effective = intersect_scopes(*[cert.scope for cert in bundle.delegations])
    failure = None
    if opts.required_scope not in effective:
        failure = V2LocalPolicyFailure("scope_denied", "scope_denied",
                                       f"required scope {opts.required_scope!r} is not in the effective delegation scope")
    if opts.context_policy is not None and not same_v2_context_policy(opts.context_policy, state.expected.context_policy):
        return finish(_interrupted("context policy differs from the policy sealed during successful preflight"))
    context = evaluate_proof_bundle_v2_context_policy(bundle, state.expected.context_policy)
    if context.status != "passed" and failure is None:
        failure = V2LocalPolicyFailure(context.status, context.reason, context.detail)
    deferred, constraint_status, failures = _evaluate_local_constraints(bundle, opts, now)
    if constraint_status and failure is None:
        failure = V2LocalPolicyFailure(constraint_status, constraint_status, "; ".join(sorted(failures)))
    assessment = _local("pending_external_checks", "external_checks_required", effective,
                        "local checks recorded; status and deferred authorization checks remain")
    assessment.agent_id = bundle.agent_id
    assessment.root_id = opts.trusted_root_id
    assessment.required_scope = opts.required_scope
    assessment.delegation_digest = bytes(bundle.delegation_digest)
    assessment.local_policy_failure = failure
    assessment.status_checks = [V2CertificateStatusCheck(i, c.issuer_id, c.subject_id, c.cert_id)
                                for i, c in enumerate(bundle.delegations)]
    assessment.deferred = deferred
    assessment.delegation_valid_until = min(cert.expires_at for cert in bundle.delegations)
    if failure is None:
        try:
            assessment.local_time_valid_until = _local_time_window_valid_until(bundle, now)
        except Exception as exc:  # noqa: BLE001 - unknown zone, bad bounds, no horizon
            assessment.local_policy_failure = V2LocalPolicyFailure("constraint_unverifiable", "constraint_unverifiable", str(exc))
    assessment.context_assessment = context.assessment
    assessment.context_policy_digest = context.policy_digest
    return finish(assessment)


def _allow_horizon(a: V2LocalAuthorizationAssessment) -> int:
    horizon = min(a.delegation_valid_until, a.status_fresh_until)
    if a.audience_fresh_until > 0:
        horizon = min(horizon, a.audience_fresh_until)
    if a.local_time_valid_until > 0:
        horizon = min(horizon, a.local_time_valid_until)
    return horizon


def _combinable_with_audience(failure: Optional[V2LocalPolicyFailure], deferred) -> bool:
    if failure is None or failure.status not in ("constraint_unknown", "constraint_unverifiable"):
        return False
    return any(item.type == RECEIVER_AUDIENCE for item in deferred)


def resolve_claim_proof_bundle_v2_after_status(token: Optional[V2EvaluationToken], results: list[RevocationStatusResultV2],
                                               roles: V2StatusRoleBindings) -> V2LocalAuthorizationAssessment:
    if token is None or token._state is None:
        raise ValueError("v2 claim evaluator capability is required")
    state = token._state
    if state.expected is None or not state.evaluation_complete or state.evaluation_status != "pending_external_checks" or state.pending_assessment is None:
        raise ValueError("v2 claim does not have a pending status assessment")
    a = copy.deepcopy(state.pending_assessment)
    if a.bundle_hash != state.expected.bundle_hash or a.required_scope != state.expected.required_scope:
        raise ValueError("pending status assessment differs from its claimed proof")
    aggregated = aggregate_certificate_status_v2(a.status_checks, results, roles)
    a.status_assessment = aggregated.assessment
    a.status_fresh_until = aggregated.fresh_until
    a.status_evidence = list(aggregated.evidence)
    if aggregated.assessment == "revoked":
        a.status, a.reason, a.detail = "revoked", "delegation_revoked", "at least one delegation certificate is revoked"
    elif aggregated.assessment == "unavailable":
        a.status, a.reason, a.detail = "authorization_unverified", "status_unavailable", "one or more delegation certificate statuses are unavailable"
    elif aggregated.assessment == "stale":
        a.status, a.reason, a.detail = "authorization_unverified", "status_stale", "one or more delegation certificate statuses are stale"
    elif aggregated.assessment == "current":
        if a.local_policy_failure is not None and _combinable_with_audience(a.local_policy_failure, a.deferred):
            a.deferred = [d for d in a.deferred if d.type == RECEIVER_AUDIENCE]
            a.status, a.reason = "pending_external_checks", "deferred_policy_checks_required"
            a.detail = "status is current; audience must be aggregated with a pending local constraint result"
            state.pending_assessment = copy.deepcopy(a)
            state.evaluation_status, state.evaluation_reason = a.status, a.reason
            return a
        elif a.local_policy_failure is not None:
            a.status, a.reason, a.detail = a.local_policy_failure.status, a.local_policy_failure.reason, a.local_policy_failure.detail
        elif a.deferred:
            a.status, a.reason = "pending_external_checks", "deferred_policy_checks_required"
            a.detail = "status is current; deferred audience or rate checks remain"
            state.pending_assessment = copy.deepcopy(a)
            state.evaluation_status, state.evaluation_reason = a.status, a.reason
            return a
        else:
            a.status, a.reason, a.detail = "authorized_agent", "authorized", "proof, status, and local authorization checks passed"
            state.allow_valid_until = _allow_horizon(a)
    else:
        raise ValueError("v2 status aggregator returned an unknown assessment")
    state.evaluation_status, state.evaluation_reason = a.status, a.reason
    state.pending_assessment = None
    return a


def resolve_claim_proof_bundle_v2_after_audience(token: Optional[V2EvaluationToken],
                                                 memberships: list[V2AudienceMembership],
                                                 now: int) -> V2LocalAuthorizationAssessment:
    if token is None or token._state is None:
        raise ValueError("v2 claim evaluator capability is required")
    state = token._state
    pending = state.pending_assessment
    if (
        state.expected is None or not state.evaluation_complete or state.evaluation_status != "pending_external_checks"
        or pending is None or pending.status_assessment != "current"
        or (pending.local_policy_failure is not None and not _combinable_with_audience(pending.local_policy_failure, pending.deferred))
    ):
        raise ValueError("v2 claim does not have current status and pending audience checks")
    a = copy.deepcopy(pending)
    if a.bundle_hash != state.expected.bundle_hash or a.required_scope != state.expected.required_scope:
        state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
        state.pending_assessment = None
        raise ValueError("pending audience assessment differs from its claimed proof")
    if now < state.evaluated_at:
        now = state.evaluated_at
    try:
        result = evaluate_receiver_audience_v2(a.deferred, state.expected.expected_receiver_id, memberships, now, state.future_skew)
    except Exception:
        state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
        state.pending_assessment = None
        raise
    a.audience_evidence_digests = list(result.evidence_digests)
    a.audience_fresh_until = result.fresh_until
    local = a.local_policy_failure
    if local is not None:
        if result.status == "passed" or _precedence(local.status) > _precedence(result.status):
            a.status, a.reason, a.detail = local.status, local.reason, local.detail
        else:
            a.status, a.reason, a.detail = result.status, result.status, "receiver audience did not authorize this receiver"
        a.deferred = []
        state.pending_assessment = None
    elif result.status != "passed":
        a.status, a.reason, a.detail = result.status, result.status, "receiver audience did not authorize this receiver"
        state.pending_assessment = None
    else:
        a.deferred = [d for d in a.deferred if d.type != RECEIVER_AUDIENCE]
        if not a.deferred:
            a.status, a.reason = "authorized_agent", "authorized"
            a.detail = "proof, status, audience, and local authorization checks passed"
            state.allow_valid_until = _allow_horizon(a)
            state.pending_assessment = None
        else:
            a.status, a.reason, a.detail = "pending_external_checks", "rate_reservation_required", "audience passed; rate reservation remains"
            state.pending_assessment = copy.deepcopy(a)
    state.evaluation_status, state.evaluation_reason = a.status, a.reason
    return a


def resolve_claim_proof_bundle_v2_after_rate(store, token: Optional[V2EvaluationToken]) -> V2LocalAuthorizationAssessment:
    if token is None or token._state is None:
        raise ValueError("v2 rate evaluation requires claim capability")
    state = token._state
    pending = state.pending_assessment
    if (
        state.expected is None or not state.evaluation_complete or state.evaluation_status != "pending_external_checks"
        or pending is None or pending.status_assessment != "current" or pending.local_policy_failure is not None
    ):
        raise ValueError("v2 claim does not have current status and pending rate checks")
    a = copy.deepcopy(pending)
    if a.bundle_hash != state.expected.bundle_hash or a.required_scope != state.expected.required_scope or not state.rate_batch:
        state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
        state.pending_assessment = None
        raise ValueError("pending rate assessment differs from its claimed proof")
    if any(item.type != MAX_RATE for item in a.deferred):
        raise ValueError("audience or unknown checks remain before rate reservation")
    try:
        batch = build_v2_rate_reservation_batch(a.deferred)
    except ValueError:
        batch = None
    if batch != state.rate_batch:
        state.evaluation_status, state.evaluation_reason = "authorization_unverified", "evaluation_interrupted"
        state.pending_assessment = None
        raise ValueError("pending rate checks differ from sealed signed batch")
    error: Optional[BaseException] = None
    if store is None:
        error = ValueError("v2 rate reservation store is unavailable")
    elif _is_rate_at_finalization_store(store):
        state.rate_at_finalization = True
        a.rate_admission_deferred = True
    else:
        try:
            store.reserve_v2_rate_batch(state.claim_id, bytes(state.owner_token), a.bundle_hash, list(batch))
        except Exception as exc:  # noqa: BLE001 - every store failure is classified below
            error = exc
    if error is None:
        a.status, a.reason = "authorized_agent", "authorized"
        a.detail = ("proof, status, and audience passed; rate admission is deferred to durable finalization"
                    if state.rate_at_finalization else "proof, status, audience, and rate checks passed")
        state.allow_valid_until = _allow_horizon(a)
    elif isinstance(error, RateLimitExceededError):
        a.status, a.reason, a.detail = "constraint_denied", "constraint_denied", "signed rate limit has no remaining capacity"
    else:
        a.status, a.reason, a.detail = "constraint_unverifiable", "constraint_unverifiable", "rate reservation could not be verified"
        a.rate_store_unavailable = True
    a.deferred = []
    state.pending_assessment = None
    state.evaluation_status, state.evaluation_reason = a.status, a.reason
    return a


# ---------------------------------------------------------------------------
# End-to-end verifier


@dataclass
class V2TrustResolution:
    available: bool = False
    root_id: str = ""
    root_key: Optional[HybridPublicKey] = None


@dataclass
class V2VerifyCallbacks:
    """Verifier-owned dependencies. ``claim_store`` is required.

    receiver_binding(bundle, expected) is the application's pure
    pre-consumption hook (raise to reject). trust(chain) -> V2TrustResolution;
    status(issuer_id, cert_id) -> RevocationStatusResultV2;
    audience(deferred, receiver_id) -> list[V2AudienceMembership];
    rate implements reserve_v2_rate_batch. An exception from trust or
    audience is treated as unavailable, as in Go.
    """
    claim_store: Any = None
    receiver_binding: Optional[Callable[[ProofBundleV2, ExpectedChallengeV2], None]] = None
    trust: Optional[Callable[[list[DelegationCertV2]], V2TrustResolution]] = None
    status: Optional[Callable[[str, str], RevocationStatusResultV2]] = None
    audience: Optional[Callable[[list[V2DeferredConstraint], str], list[V2AudienceMembership]]] = None
    rate: Any = None


@dataclass
class V2VerifyRequest:
    bundle: bytes
    required_scope: str
    verifier_namespace: str
    replay_epoch: int
    now: int
    max_challenge_age_seconds: int
    future_skew_seconds: int
    expected: Optional[ExpectedChallengeV2] = None
    context_policy: Optional[V2ContextPolicy] = None
    context: Optional[VerifierContext] = None
    status_roles: V2StatusRoleBindings = field(default_factory=lambda: V2StatusRoleBindings({}, {}, set()))


V2_STAGE_PREFLIGHT = "preflight"
V2_STAGE_REPLAY = "replay"
V2_STAGE_EVALUATING = "evaluating"
V2_STAGE_TERMINAL = "terminal"


@dataclass
class V2VerifyOutcome:
    stage: str
    error: Optional[BaseException] = None
    error_class: str = ""
    disposition: str = ""
    claim: Optional[V2ChallengeClaim] = None
    decision: str = ""
    reason: str = ""
    identity_status: str = ""
    receipt: Optional[VerificationReceiptV2] = None
    receipt_body: bytes = b""
    allow_valid_until: int = 0


class V2EvaluationNotTerminalError(Exception):
    """A claimed evaluation could not reach a terminal commit (Go's non-nil
    error return). ``outcome`` is the evaluating-stage outcome; the claim
    stays in progress for lease-expiry recovery."""

    def __init__(self, outcome: V2VerifyOutcome, cause: BaseException):
        super().__init__(str(cause))
        self.outcome = outcome
        self.cause = cause
        self.error_class = error_class_of(cause)


def _terminal_outcome(bundle: ProofBundleV2, a: V2LocalAuthorizationAssessment, trust: str, req: V2VerifyRequest,
                      claim: V2ChallengeClaim) -> V2VerifyOutcome:
    decision, ok = terminal_decision_for_v2_evaluation(a.status, a.reason)
    if not ok:
        raise ValueError(f"v2 evaluation did not reach a terminal result: {a.status}/{a.reason}")
    status_assessment = a.status_assessment or "not_evaluated"
    context_assessment = a.context_assessment or "not_evaluated"
    if a.reason == "not_delegated":
        trust = "not_evaluated"
    elif a.reason == "evaluation_interrupted":
        if trust != "trusted":
            trust, status_assessment = "not_evaluated", "not_evaluated"
        if context_assessment not in ("bound", "not_required"):
            context_assessment = "not_evaluated"
        if context_assessment == "not_evaluated":
            status_assessment = "not_evaluated"
    policy_digest = None
    if context_assessment not in ("not_evaluated", "unbound") and a.context_policy_digest is not None:
        policy_digest = a.context_policy_digest
    evidence = [] if status_assessment == "not_evaluated" else list(a.status_evidence)
    granted = sorted(set(a.effective_scope or [])) if decision == "allow" else []
    receipt = VerificationReceiptV2(
        version=2, verifier_id=bundle.verifier_id, agent_id=bundle.agent_id, bundle_hash=claim.bundle_hash,
        issuer_ids=list(claim.issuer_ids), decision=decision, decision_reason=a.reason, identity_status=a.status,
        trust_assessment=trust, status_assessment=status_assessment, challenge_assessment="current",
        context_assessment=context_assessment, context_policy_digest=policy_digest, verified_at=req.now,
        required_scope=claim.required_scope, granted_scope=granted, status_evidence=evidence,
    )
    try:
        body = verification_receipt_v2_body(receipt)
    except ValueError as exc:
        raise ValueError(f"v2 terminal receipt body is inconsistent with the evaluated result: {exc}") from exc
    return V2VerifyOutcome(stage=V2_STAGE_TERMINAL, claim=claim, decision=decision, reason=a.reason,
                           identity_status=a.status, receipt=receipt, receipt_body=body)


def verify_proof_bundle_v2(req: V2VerifyRequest, cb: V2VerifyCallbacks) -> V2VerifyOutcome:
    """Run the complete live Protocol v2 decision path (Go VerifyProofBundleV2).

    A pre-claim failure returns stage ``preflight`` with a classified error and
    invokes no claim, trust, status, audience, or rate callback. Raises
    V2EvaluationNotTerminalError only when a claimed evaluation could not
    reach a terminal commit.
    """
    def preflight_failure(err: BaseException) -> V2VerifyOutcome:
        return V2VerifyOutcome(stage=V2_STAGE_PREFLIGHT, error=err, error_class=error_class_of(err))

    if cb is None or cb.claim_store is None:
        return preflight_failure(V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 verification requires a claim store"))
    try:
        bundle = decode_proof_bundle_v2(req.bundle)
        preflight = _preflight(bundle, req.expected, req.context_policy, True, cb.receiver_binding, req.required_scope,
                               req.verifier_namespace, req.replay_epoch, req.now, req.max_challenge_age_seconds,
                               req.future_skew_seconds)
    except Exception as exc:  # noqa: BLE001 - every pre-claim failure is reported, classified
        return preflight_failure(exc)
    try:
        claim, disposition, token = claim_proof_bundle_v2(cb.claim_store, bundle, preflight, req.verifier_namespace,
                                                          req.replay_epoch, req.now)
    except Exception as exc:  # noqa: BLE001
        if error_class_of(exc) == V2ErrorClass.UNCLASSIFIED:
            exc = classify(V2ErrorClass.CLAIM_STORE_UNAVAILABLE, exc)
        return preflight_failure(exc)
    if disposition != V2_CLAIM_CREATED:
        return V2VerifyOutcome(stage=V2_STAGE_REPLAY, disposition=disposition, claim=claim)

    def not_terminal(err: BaseException, class_: Optional[str] = V2ErrorClass.CONFIGURATION_INVALID):
        cause = classify(class_, err) if class_ else err
        return V2EvaluationNotTerminalError(
            V2VerifyOutcome(stage=V2_STAGE_EVALUATING, claim=claim, disposition=disposition), cause)

    trust = "not_evaluated"
    opts = V2LocalAuthorizationOptions(
        now=req.now, future_skew=req.future_skew_seconds, required_scope=req.required_scope, context=req.context,
        context_policy=req.context_policy, expected_challenge=req.expected, claim_token=token,
    )
    if bundle.delegations:
        resolution = V2TrustResolution()
        if cb.trust is not None:
            try:
                resolved = cb.trust(list(bundle.delegations))
                if resolved is not None:
                    resolution = resolved
            except Exception:  # noqa: BLE001 - trust source failure is unavailable trust
                pass
        opts.trust_configured = resolution.available
        opts.trusted_root_id = resolution.root_id
        opts.trusted_root_key = resolution.root_key
        root = bundle.delegations[-1]
        if not resolution.available:
            trust = "unavailable"
        elif resolution.root_id != root.issuer_id or resolution.root_key is None or not equal_public_keys(resolution.root_key, root.issuer_pub_key):
            trust = "untrusted"
        else:
            trust = "trusted"
    assessment = evaluate_proof_bundle_v2_local_authorization(bundle, opts)

    if assessment.status == "pending_external_checks":
        results = []
        for check in assessment.status_checks:
            if cb.status is None:
                results.append(RevocationStatusResultV2(status="indeterminate", reason="unavailable", evidence=[]))
            else:
                results.append(cb.status(check.issuer_id, check.cert_id))
        try:
            assessment = resolve_claim_proof_bundle_v2_after_status(token, results, req.status_roles)
        except Exception as exc:  # noqa: BLE001
            raise not_terminal(exc) from exc
    if assessment.status == "pending_external_checks" and any(d.type == RECEIVER_AUDIENCE for d in assessment.deferred):
        memberships: list[V2AudienceMembership] = []
        if cb.audience is not None:
            try:
                result = cb.audience([d for d in assessment.deferred if d.type == RECEIVER_AUDIENCE],
                                     req.expected.expected_receiver_id)
                memberships = list(result or [])
            except Exception:  # noqa: BLE001 - a failed adapter is unavailable membership
                memberships = []
        try:
            assessment = resolve_claim_proof_bundle_v2_after_audience(token, memberships, req.now)
        except Exception as exc:  # noqa: BLE001
            raise not_terminal(exc) from exc
    if assessment.status == "pending_external_checks":
        try:
            assessment = resolve_claim_proof_bundle_v2_after_rate(cb.rate, token)
        except Exception as exc:  # noqa: BLE001
            raise not_terminal(exc) from exc

    for attempt in range(2):
        try:
            outcome = _terminal_outcome(bundle, assessment, trust, req, claim)
        except Exception as exc:  # noqa: BLE001
            raise not_terminal(exc, None) from exc
        terminal = canonical({"decision": outcome.decision, "decision_reason": outcome.reason,
                              "identity_status": outcome.identity_status})
        try:
            finalize_claim_proof_bundle_v2(cb.claim_store, token, terminal, outcome.receipt_body)
        except RateLimitExceededError as exc:
            if attempt > 0:
                raise not_terminal(exc, None) from exc
            # A barrier store proved capacity exhaustion and rolled back; the
            # same claim finalizes once as constraint_denied (SPEC-v2 §6.2).
            assessment.status, assessment.reason = "constraint_denied", "constraint_denied"
            assessment.detail = "signed rate limit has no remaining capacity"
            continue
        except Exception as exc:  # noqa: BLE001
            raise not_terminal(exc, None) from exc
        outcome.disposition = disposition
        outcome.allow_valid_until = token._state.allow_valid_until
        return outcome
    raise ValueError("v2 terminal finalization did not complete")

