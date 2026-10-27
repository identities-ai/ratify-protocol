"""Protocol v2 challenge claim and finalization (mirrors Go claim_store_v2.go).

``ClaimStoreV2`` is the Part B storage boundary for challenge consumption
(SPEC-v2 §7.3, §7.5). ``claim_proof_bundle_v2`` repeats the pre-claim checks
and atomically claims the challenge; ``finalize_claim_proof_bundle_v2``
commits a terminal local evaluation through the single-use evaluator
capability that won the claim.
"""
from __future__ import annotations

import abc
import hashlib
import json
import threading
from dataclasses import dataclass, field, replace
from typing import Optional

from . import context_v2
from ._v2json import canonical
from .challenge_claim_v2 import challenge_claim_digest_v2, protocol_claim_id_v2
from .clock_bounds_v2 import v2_challenge_time_current
from .errors_v2 import ClaimProofConflictError, V2Error, V2ErrorClass, classify, classified, V2ValueError
from .protocol_v2 import ProofBundleV2, bundle_hash_v2
from .types_v2 import clone_constraint_evaluator_refs_v2
from .verify_v2_preflight import (
    ExpectedChallengeV2,
    V2PreflightResult,
    _clone_expected_challenge_state_v2,
    _ExpectedChallengeStateV2,
    _preflight_state,
    validate_proof_bundle_v2_preflight,
)

# Go ErrV2ClaimProofConflict: a different proof for an already claimed challenge.
ErrV2ClaimProofConflict = ClaimProofConflictError


@dataclass
class V2ChallengeClaim:
    """The immutable identity a verifier persists when it consumes a fresh
    challenge. Every field is an immutable claim value; a changed scope or
    context policy is not an exact retry."""

    claim_id: str = ""
    namespace: str = ""
    replay_epoch: int = 0
    challenge_digest: str = ""
    proof_digest: str = ""
    bundle_hash: str = ""
    issuer_ids: list = field(default_factory=list)
    required_scope: str = ""
    context_policy_digest: str = ""
    verifier_id: str = ""
    agent_id: str = ""
    requires_rate: bool = False
    rate_batch: list = field(default_factory=list)
    issued_at: int = 0
    expires_at: int = 0
    max_age_seconds: int = 0
    clock_skew_seconds: int = 0
    stream_id: Optional[bytes] = None
    stream_seq: Optional[int] = None
    # The sealed extension evaluator snapshot (SPEC-v2 §5.2, §6.3), sorted by type.
    constraint_evaluators: Optional[list] = None


def clone_v2_challenge_claim(claim: V2ChallengeClaim) -> V2ChallengeClaim:
    """Go ``cloneV2ChallengeClaim``."""
    return replace(
        claim,
        issuer_ids=list(claim.issuer_ids or []),
        rate_batch=list(claim.rate_batch or []),
        stream_id=None if claim.stream_id is None else bytes(claim.stream_id),
        constraint_evaluators=clone_constraint_evaluator_refs_v2(claim.constraint_evaluators),
    )


V2_CLAIM_CREATED = "created"
V2_CLAIM_IN_PROGRESS = "in_progress"
V2_CLAIM_TERMINAL_REPLAY = "terminal_replay"


@dataclass
class V2ClaimResult:
    """The claim transaction's result. ``claimed_at`` is the store's
    authoritative claim time; ``owner_token`` is returned only to the
    process that atomically created the claim."""

    disposition: str = ""
    claimed_at: int = 0
    owner_token: bytes = b""


class V2AuthoritativeClock(abc.ABC):
    """A Part B authoritative security clock in integer seconds."""

    @abc.abstractmethod
    def authoritative_time_v2(self, ctx: context_v2.Context) -> int:
        """Return the store's security clock reading; raise on failure."""


class V2RateReservationStore(abc.ABC):
    """Atomically reserves the complete claim-sealed rate batch. An exact live
    retry is idempotent. Returning normally means every counter remains
    provisionally held; ``V2RateLimitExceededError`` means no capacity."""

    @abc.abstractmethod
    def reserve_v2_rate_batch(self, ctx: context_v2.Context, claim_id: str, owner_token: bytes,
                              bundle_hash: str, batch: list) -> None:
        ...


class ClaimStoreV2(V2AuthoritativeClock):
    """The storage boundary for challenge consumption (Go ``ClaimStoreV2``).

    ``claim_v2`` must be atomic across processes and durable, advance any
    stream sequence in the same transaction, and recheck freshness at its
    authoritative clock. ``finalize_v2_claim`` reads T_final inside its
    compare-and-set: a regressed reading fails with ``clock_regressed``; a
    non-zero ``allow_valid_until`` commits only while T_final <
    allow_valid_until and T_final < the sealed challenge expiry, else
    ``allow_horizon_passed``. It returns True when it commits, False for an
    identical repeat. See SPEC-v2 §7.2 to §7.5 for the full contract.
    """

    @abc.abstractmethod
    def claim_v2(self, ctx: context_v2.Context, claim: V2ChallengeClaim) -> V2ClaimResult:
        ...

    @abc.abstractmethod
    def finalize_v2_claim(self, ctx: context_v2.Context, claim_id: str, owner_token: bytes, terminal_result: bytes,
                          receipt_body: bytes, allow_valid_until: int) -> bool:
        ...

    @abc.abstractmethod
    def record_v2_evaluation_progress(self, ctx: context_v2.Context, claim_id: str, owner_token: bytes, progress) -> None:
        ...

    @abc.abstractmethod
    def load_v2_interrupted_claim(self, ctx: context_v2.Context, claim_id: str):
        ...

    @abc.abstractmethod
    def recover_interrupted_v2_claim(self, ctx: context_v2.Context, claim_id: str, terminal_result: bytes,
                                     receipt_body: bytes) -> bool:
        ...


class V2RateAtFinalizationStore(ClaimStoreV2, V2RateReservationStore):
    """A claim store that admits the sealed rate batch atomically inside its
    finalization compare-and-set (Go ``V2RateAtFinalizationStore``).

    The capability is explicit: a store has it only by subclassing this
    class, never by having a method of the right name. Its
    ``finalize_v2_claim`` may raise exactly ``V2RateLimitExceededError`` only
    after definitive rollback."""

    @abc.abstractmethod
    def admits_v2_rate_at_finalization(self) -> None:
        ...


def is_v2_rate_at_finalization_store(store: object) -> bool:
    """True only for a store that explicitly subclasses
    :class:`V2RateAtFinalizationStore` (no structural typing)."""
    return isinstance(store, V2RateAtFinalizationStore) and V2RateAtFinalizationStore in type(store).__mro__


def challenge_claim_time_current_v2(claim: V2ChallengeClaim, now: int) -> bool:
    """Go ``ChallengeClaimTimeCurrentV2``: exclusive challenge deadlines."""
    return v2_challenge_time_current(now, claim.issued_at, claim.expires_at, claim.max_age_seconds, claim.clock_skew_seconds)


class _V2EvaluationTokenState:
    __slots__ = (
        "claim_id", "claim", "proof_digest", "required_scope", "future_skew", "expected", "_used_lock", "used",
        "evaluation_complete", "finalization_mu", "finalization_digest", "finalization_started",
        "claim_time_valid", "claimed_at", "evaluated_at", "rate_batch", "rate_at_finalization",
        "allow_valid_until", "owner_token", "evaluation_status", "evaluation_reason", "pending_assessment",
    )

    def __init__(self, *, claim_id: str, claim: V2ChallengeClaim, proof_digest: str, rate_batch: list, required_scope: str, future_skew: int,
                 owner_token: bytes, claimed_at: int, claim_time_valid: bool, expected: _ExpectedChallengeStateV2):
        self.claim_id = claim_id
        self.claim = clone_v2_challenge_claim(claim)
        self.proof_digest = proof_digest
        self.required_scope = required_scope
        self.future_skew = future_skew
        self.expected = expected
        self._used_lock = threading.Lock()
        self.used = False
        self.evaluation_complete = False
        # RLock: Go guards these fields with one mutex; Python callers may
        # nest the clone helpers that also read under it.
        self.finalization_mu = threading.RLock()
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
        self.pending_assessment = None

    def try_use(self) -> bool:
        """Go ``used.CompareAndSwap(false, true)``."""
        with self._used_lock:
            if self.used:
                return False
            self.used = True
            return True

    def allow_horizon(self) -> int:
        with self.finalization_mu:
            return self.allow_valid_until


class V2EvaluationToken:
    """Grants one local evaluation attempt for a newly created claim. It is
    single-use, opaque, and never returned for an exact retry; only
    ``claim_proof_bundle_v2`` creates one."""

    __slots__ = ("_state",)

    def __init__(self, *args, **kwargs):
        raise TypeError("V2EvaluationToken is created only by claim_proof_bundle_v2")

    @classmethod
    def _create(cls, state: _V2EvaluationTokenState) -> "V2EvaluationToken":
        token = object.__new__(cls)
        object.__setattr__(token, "_state", state)
        return token

    def __repr__(self) -> str:
        return "<V2EvaluationToken>"


def _token_state(token: object) -> Optional[_V2EvaluationTokenState]:
    if not isinstance(token, V2EvaluationToken):
        return None
    try:
        state = object.__getattribute__(token, "_state")
    except AttributeError:
        return None
    return state if isinstance(state, _V2EvaluationTokenState) else None


@classified(V2ErrorClass.CLAIM_STORE_UNAVAILABLE)
def claim_proof_bundle_v2(ctx: context_v2.Context, store: ClaimStoreV2, bundle: ProofBundleV2, preflight: V2PreflightResult,
                          configured_namespace: str, configured_replay_epoch: int, now_unix: int):
    """Go ``ClaimProofBundleV2``. Returns ``(claim, disposition, token)``;
    ``token`` is None unless the disposition is ``created``."""
    from .rate_reservation_v2 import signed_v2_rate_reservation_batch

    if store is None or not isinstance(ctx, context_v2.Context):
        raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 claim store and context are required")
    state = _preflight_state(preflight)
    if state is None or (state.context_policy is None and not state.no_context_policy):
        raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 successful preflight state is required before claim")
    sealed = _clone_expected_challenge_state_v2(state)
    try:
        bundle_hash = bundle_hash_v2(bundle)
    except Exception:  # noqa: BLE001
        bundle_hash = None
    if bundle_hash is None or bundle_hash != sealed.bundle_hash:
        raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 proof bundle differs from successful preflight")
    expected = ExpectedChallengeV2(
        value=sealed.value, issued_at=sealed.issued_at, expires_at=sealed.expires_at,
        verifier_namespace=sealed.verifier_namespace, replay_epoch=sealed.replay_epoch, verifier_id=sealed.verifier_id,
        expected_agent_id=sealed.expected_agent_id, expected_agent_public_key=sealed.expected_agent_public_key,
        expected_receiver_id=sealed.expected_receiver_id, expected_session_context=sealed.expected_session_context,
        context_policy=sealed.context_policy,
    )
    try:
        validate_proof_bundle_v2_preflight(bundle, expected, sealed.required_scope, configured_namespace,
                                           configured_replay_epoch, sealed.verifier_id, now_unix, sealed.max_age,
                                           sealed.future_skew)
    except V2Error as exc:
        raise V2Error(exc.error_class, f"v2 claim-time preflight: {exc}") from exc
    required_scope, max_age_seconds, future_skew_seconds = sealed.required_scope, sealed.max_age, sealed.future_skew
    challenge_digest = challenge_claim_digest_v2(sealed.value)
    claim_id = protocol_claim_id_v2(sealed.verifier_namespace, sealed.replay_epoch, sealed.value)
    claim = V2ChallengeClaim(
        claim_id=claim_id, namespace=sealed.verifier_namespace, replay_epoch=sealed.replay_epoch,
        challenge_digest="sha384:" + bytes(challenge_digest).hex(), proof_digest=bundle_hash,
        bundle_hash=sealed.bundle_hash, issuer_ids=list(sealed.issuer_ids), required_scope=required_scope,
        context_policy_digest=sealed.context_policy_digest, verifier_id=sealed.verifier_id, agent_id=bundle.agent_id,
        issued_at=sealed.issued_at, expires_at=sealed.expires_at, max_age_seconds=max_age_seconds,
        clock_skew_seconds=future_skew_seconds,
        stream_id=None if bundle.stream_id is None else bytes(bundle.stream_id),
        stream_seq=bundle.stream_seq,
        constraint_evaluators=clone_constraint_evaluator_refs_v2(sealed.evaluator_refs),
    )
    try:
        claim.rate_batch = list(signed_v2_rate_reservation_batch(bundle))
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, ValueError(f"v2 signed rate batch: {exc}")) from exc
    claim.requires_rate = len(claim.rate_batch) != 0
    # SPEC-v2 §6.11: cancellation before the claim consumes nothing, so a
    # caller that has already cancelled never reaches the store.
    err = ctx.err()
    if err is not None:
        raise V2Error(V2ErrorClass.EVALUATION_CANCELLED, f"v2 claim cancelled before the store was called: {err}") from err
    result = store.claim_v2(ctx, clone_v2_challenge_claim(claim))
    if not isinstance(result, V2ClaimResult):
        raise ValueError("v2 claim store returned an invalid result")
    if result.disposition == V2_CLAIM_CREATED:
        if not isinstance(result.owner_token, (bytes, bytearray)) or len(result.owner_token) != 32:
            raise ValueError("v2 claim store returned an invalid evaluator owner token")
        if type(result.claimed_at) is not int:
            raise ValueError("v2 claim store returned an invalid claim time")
        # The store's authoritative claim time must itself satisfy the
        # exclusive challenge deadlines; otherwise evaluation is interrupted.
        claim_time_valid = v2_challenge_time_current(result.claimed_at, sealed.issued_at, sealed.expires_at,
                                                     max_age_seconds, future_skew_seconds)
        token = V2EvaluationToken._create(_V2EvaluationTokenState(
            claim_id=claim.claim_id, claim=claim, proof_digest=claim.proof_digest, rate_batch=claim.rate_batch,
            required_scope=required_scope, future_skew=future_skew_seconds, owner_token=bytes(result.owner_token),
            claimed_at=result.claimed_at, claim_time_valid=claim_time_valid, expected=sealed,
        ))
        return claim, result.disposition, token
    if result.disposition in (V2_CLAIM_IN_PROGRESS, V2_CLAIM_TERMINAL_REPLAY):
        if result.owner_token:
            raise ValueError("v2 exact retry must not receive evaluator ownership")
        return claim, result.disposition, None
    raise ValueError("v2 claim store returned an invalid disposition")


@classified(V2ErrorClass.CLAIM_STORE_UNAVAILABLE)
def finalize_claim_proof_bundle_v2(ctx: context_v2.Context, store: ClaimStoreV2, token: V2EvaluationToken,
                                   terminal_result: bytes, receipt_body: bytes) -> bool:
    """Go ``FinalizeClaimProofBundleV2``: commit a terminal local evaluation
    through the opaque capability that won the atomic claim."""
    from .rate_reservation_v2 import V2RateLimitExceededError

    state = _token_state(token)
    if (not isinstance(ctx, context_v2.Context) or store is None or state is None or len(state.owner_token) != 32
            or state.claim_id == ""):
        raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 claim store and valid evaluator capability are required")
    terminal_result = bytes(terminal_result)
    receipt_body = bytes(receipt_body)
    err = ctx.err()
    if err is not None:
        raise err
    with state.finalization_mu:
        if not state.evaluation_complete:
            raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 proof evaluation has not completed")
        decision, ok = terminal_decision_for_v2_evaluation(state.evaluation_status, state.evaluation_reason)
        if not ok:
            raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 proof evaluation has not reached a terminal local result")
        validate_v2_finalization_payload(state.claim, terminal_result, receipt_body)
        if not terminal_payload_matches_v2(terminal_result, receipt_body, decision, state.evaluation_reason):
            raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 terminal result does not match the completed local evaluation")
        if (decision == "allow" and state.allow_valid_until <= 0) or (decision != "allow" and state.allow_valid_until != 0):
            raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 terminal result lacks a valid allow freshness horizon")
        if state.rate_at_finalization and not is_v2_rate_at_finalization_store(store):
            raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 rate-at-finalization requires an atomic rate store")
        payload_digest = v2_finalization_payload_digest(terminal_result, receipt_body)
        if state.finalization_started and state.finalization_digest != payload_digest:
            raise V2ValueError(V2ErrorClass.CONFIGURATION_INVALID, "v2 evaluator capability cannot change its terminal result or receipt body")
        state.finalization_started = True
        state.finalization_digest = payload_digest
        try:
            return bool(store.finalize_v2_claim(ctx, state.claim_id, bytes(state.owner_token), terminal_result,
                                                receipt_body, state.allow_valid_until))
        except V2RateLimitExceededError:
            if state.rate_at_finalization and decision == "allow" and is_v2_rate_at_finalization_store(store):
                state.evaluation_status, state.evaluation_reason = "constraint_denied", "constraint_denied"
                state.allow_valid_until = 0
                state.rate_at_finalization = False
                state.finalization_started = False
                state.finalization_digest = b""
            raise


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def validate_v2_finalization_payload(claim: V2ChallengeClaim, terminal_result: bytes, receipt_body: bytes) -> None:
    """Go ``ValidateV2FinalizationPayload``: check that a terminal result and
    its unsigned receipt outbox body belong to the sealed claim (SPEC-v2
    §7.5). The body must decode strictly as a canonical receipt body
    (malformed otherwise). Its verifier_id, agent_id, bundle_hash, issuer_ids
    (the sorted, distinct sealed issuer IDs), required_scope, and
    constraint_evaluators must equal the sealed claim's values; its
    context_policy_digest must equal the sealed claim's (None for a
    policy-less claim) unless context_assessment is not_evaluated, when it
    must be None. The terminal result must be a JSON object whose
    decision and decision_reason equal the body's; any difference is
    configuration_invalid. ``finalize_claim_proof_bundle_v2`` applies it
    before the store is called, and a claim store applies it inside its
    finalization compare-and-set so that no caller can commit a body for
    another proof."""
    from .verification_receipt_v2 import decode_verification_receipt_body_v2

    if not isinstance(claim, V2ChallengeClaim):
        raise ValueError("v2 sealed claim is required")
    body = decode_verification_receipt_body_v2(bytes(receipt_body))
    issuers = sorted(set(claim.issuer_ids or []))
    if body.verifier_id != claim.verifier_id:
        raise ValueError("v2 receipt body verifier_id differs from the sealed claim")
    if body.agent_id != claim.agent_id:
        raise ValueError("v2 receipt body agent_id differs from the sealed claim")
    if body.bundle_hash != claim.bundle_hash:
        raise ValueError("v2 receipt body bundle_hash differs from the sealed claim")
    if list(body.issuer_ids or []) != issuers:
        raise ValueError("v2 receipt body issuer_ids differ from the sealed claim")
    if body.required_scope != claim.required_scope:
        raise ValueError("v2 receipt body required_scope differs from the sealed claim")
    want_policy_digest = None
    if body.context_assessment != "not_evaluated" and claim.context_policy_digest:
        want_policy_digest = claim.context_policy_digest
    if body.context_policy_digest != want_policy_digest:
        raise ValueError("v2 receipt body context_policy_digest differs from the sealed claim")
    if list(body.constraint_evaluators or []) != list(claim.constraint_evaluators or []):
        raise ValueError("v2 receipt body constraint_evaluators differ from the sealed evaluator snapshot")
    if not terminal_payload_matches_v2(terminal_result, receipt_body, body.decision, body.decision_reason):
        raise ValueError("v2 terminal result is not the canonical decision, reason and identity status of the receipt body")


def terminal_decision_for_v2_evaluation(status: str, reason: str) -> tuple[str, bool]:
    """Go ``terminalDecisionForV2Evaluation``."""
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


def _unique_pairs(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON object key")
        out[key] = value
    return out


def _reject_constant(name: str):
    raise ValueError(f"invalid JSON literal {name}")


def _read_decision(value: bytes) -> Optional[tuple[str, str, str]]:
    try:
        text = bytes(value).decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    if "identity_status" not in parsed:
        return None
    decision = parsed.get("decision", "")
    reason = parsed.get("decision_reason", "")
    identity = parsed["identity_status"]
    # Go json.Unmarshal into a string accepts a string or null (zero value).
    if decision is None:
        decision = ""
    if reason is None:
        reason = ""
    if identity is None:
        identity = ""
    if not isinstance(decision, str) or not isinstance(reason, str) or not isinstance(identity, str):
        return None
    return decision, reason, identity


def terminal_payload_matches_v2(terminal_result: bytes, receipt_body: bytes, want_decision: str, want_reason: str) -> bool:
    """Go ``terminalPayloadMatchesV2``: the body is a well formed,
    duplicate-free JSON object naming the expected decision and reason, and
    the terminal result is exactly the RatifyCanonicalJSON of its decision,
    decision_reason and identity_status (SPEC-v2 §7.13)."""
    body = _read_decision(receipt_body)
    if body is None or body[0] != want_decision or body[1] != want_reason:
        return False
    want = canonical({"decision": body[0], "decision_reason": body[1], "identity_status": body[2]})
    return bytes(terminal_result) == want


def v2_finalization_payload_digest(terminal_result: bytes, receipt_body: bytes) -> bytes:
    """Go ``v2FinalizationPayloadDigest``."""
    h = hashlib.sha256()
    h.update(len(terminal_result).to_bytes(8, "big"))
    h.update(terminal_result)
    h.update(len(receipt_body).to_bytes(8, "big"))
    h.update(receipt_body)
    return h.digest()
