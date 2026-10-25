"""Protocol v2 pre-claim checks (mirrors Go verify_v2_preflight.go).

The ordered pre-claim pipeline of SPEC-v2 §6.2: authenticated
``ExpectedChallengeV2`` and context-policy consistency, the required scope,
every key ID, digest, linkage and signature, the challenge binding and
freshness, expected agent and session context, and the exact receiver
audience. It performs no trust, status, policy or other external call.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Callable, Optional

from .clock_bounds_v2 import v2_challenge_time_current, validate_v2_freshness_configuration
from .context_policy_v2 import V2ContextPolicy, clone_v2_context_policy, same_v2_context_policy
from .errors_v2 import V2Error, V2ErrorClass, classify, classified
from .protocol_v2 import ProofBundleV2, bundle_hash_v2, verify_proof_bundle_v2_signatures
from .scope import validate_required_scope_v2
from .signing_v2 import key_id_v2
from .types import HybridPublicKey
from .types_v2 import MAX_SAFE_INTEGER, is_int, valid_prefixed_digest_v2, valid_v2_id

RECEIVER_AUDIENCE = "ratify.receiver_audience"


def equal_hybrid_public_keys(a: Optional[HybridPublicKey], b: Optional[HybridPublicKey]) -> bool:
    """Go ``equalHybridPublicKeys``."""
    if a is None or b is None:
        return False
    return bytes(a.ed25519) == bytes(b.ed25519) and bytes(a.ml_dsa_65) == bytes(b.ml_dsa_65)


def clone_hybrid_public_key(key: Optional[HybridPublicKey]) -> Optional[HybridPublicKey]:
    if key is None:
        return None
    return HybridPublicKey(ed25519=bytes(key.ed25519), ml_dsa_65=bytes(key.ml_dsa_65))


@dataclass
class ExpectedChallengeV2:
    """Verifier-authenticated issuance state. Values must come from the local
    issuer or an independently authenticated issuer. Empty strings and
    ``None`` mean "not configured", as Go's zero values do."""

    value: bytes = b""
    issued_at: int = 0
    expires_at: int = 0
    verifier_namespace: str = ""
    replay_epoch: int = 0
    verifier_id: str = ""
    expected_agent_id: str = ""
    expected_agent_public_key: Optional[HybridPublicKey] = None
    expected_receiver_id: str = ""
    expected_session_context: Optional[bytes] = None
    context_policy: Optional[V2ContextPolicy] = None


def clone_expected_challenge_v2(e: ExpectedChallengeV2) -> ExpectedChallengeV2:
    """Go ``cloneExpectedChallengeV2``."""
    return ExpectedChallengeV2(
        value=bytes(e.value) if e.value is not None else b"",
        issued_at=e.issued_at,
        expires_at=e.expires_at,
        verifier_namespace=e.verifier_namespace,
        replay_epoch=e.replay_epoch,
        verifier_id=e.verifier_id,
        expected_agent_id=e.expected_agent_id,
        expected_agent_public_key=clone_hybrid_public_key(e.expected_agent_public_key),
        expected_receiver_id=e.expected_receiver_id,
        expected_session_context=None if e.expected_session_context is None else bytes(e.expected_session_context),
        context_policy=clone_v2_context_policy(e.context_policy),
    )


@dataclass
class _ExpectedChallengeStateV2:
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
    issuer_ids: list
    future_skew: int
    max_age: int
    context_policy_digest: str = ""
    context_policy: Optional[V2ContextPolicy] = None
    no_context_policy: bool = False
    evaluator_refs: Optional[list] = None
    evaluators: Optional[dict] = None
    evaluator_timeout: float = 0.0


class V2PreflightResult:
    """Seals the authenticated issuance, policy, and proof identity for one
    request. Its state is never exposed or mutated after construction, and
    only this module's preflight creates one."""

    __slots__ = ("_state",)

    def __init__(self, *args, **kwargs):
        raise TypeError("V2PreflightResult is created only by preflight_proof_bundle_v2")

    @classmethod
    def _seal(cls, state: _ExpectedChallengeStateV2) -> "V2PreflightResult":
        result = object.__new__(cls)
        object.__setattr__(result, "_state", state)
        return result

    def __repr__(self) -> str:
        return "<V2PreflightResult>"


def _preflight_state(preflight: object) -> Optional[_ExpectedChallengeStateV2]:
    if not isinstance(preflight, V2PreflightResult):
        return None
    try:
        state = object.__getattribute__(preflight, "_state")
    except AttributeError:
        return None
    return state if isinstance(state, _ExpectedChallengeStateV2) else None


def _snapshot_expected_challenge_v2(expected: ExpectedChallengeV2, policy: Optional[V2ContextPolicy], required_scope: str,
                                    bundle_hash: str, issuer_ids: list, max_age: int,
                                    future_skew: int) -> _ExpectedChallengeStateV2:
    state = _ExpectedChallengeStateV2(
        value=bytes(expected.value), issued_at=expected.issued_at, expires_at=expected.expires_at,
        verifier_namespace=expected.verifier_namespace, replay_epoch=expected.replay_epoch,
        verifier_id=expected.verifier_id, expected_agent_id=expected.expected_agent_id,
        expected_agent_public_key=clone_hybrid_public_key(expected.expected_agent_public_key),
        expected_receiver_id=expected.expected_receiver_id,
        expected_session_context=None if expected.expected_session_context is None else bytes(expected.expected_session_context),
        required_scope=required_scope, bundle_hash=bundle_hash, issuer_ids=list(issuer_ids),
        max_age=max_age, future_skew=future_skew,
    )
    state.context_policy = clone_v2_context_policy(policy)
    if policy is not None:
        state.context_policy_digest = policy._digest
    else:
        state.no_context_policy = True
    return state


def _clone_expected_challenge_state_v2(state: Optional[_ExpectedChallengeStateV2]) -> Optional[_ExpectedChallengeStateV2]:
    if state is None:
        return None
    clone = copy.copy(state)
    clone.value = bytes(state.value)
    clone.expected_session_context = None if state.expected_session_context is None else bytes(state.expected_session_context)
    clone.issuer_ids = list(state.issuer_ids)
    clone.context_policy = clone_v2_context_policy(state.context_policy)
    clone.evaluator_refs = None if not state.evaluator_refs else list(state.evaluator_refs)
    clone.evaluators = None if state.evaluators is None else dict(state.evaluators)
    clone.expected_agent_public_key = clone_hybrid_public_key(state.expected_agent_public_key)
    return clone


def _matches_expected_challenge_v2(expected: Optional[ExpectedChallengeV2], state: Optional[_ExpectedChallengeStateV2]) -> bool:
    if expected is None or state is None:
        return False
    if (bytes(expected.value or b"") != state.value or expected.issued_at != state.issued_at
            or expected.expires_at != state.expires_at or expected.verifier_namespace != state.verifier_namespace
            or expected.replay_epoch != state.replay_epoch or expected.verifier_id != state.verifier_id
            or expected.expected_agent_id != state.expected_agent_id
            or expected.expected_receiver_id != state.expected_receiver_id
            or (expected.expected_session_context or b"") != (state.expected_session_context or b"")
            or (expected.context_policy is not None and not same_v2_context_policy(expected.context_policy, state.context_policy))):
        return False
    if (expected.expected_agent_public_key is None) != (state.expected_agent_public_key is None):
        return False
    return expected.expected_agent_public_key is None or equal_hybrid_public_keys(
        expected.expected_agent_public_key, state.expected_agent_public_key)


def _policy_valid(policy: V2ContextPolicy) -> bool:
    return (isinstance(policy, V2ContextPolicy) and getattr(policy, "_valid", False) is True
            and bool(getattr(policy, "_digest", "")) and valid_prefixed_digest_v2(policy._digest))


def _check_expected_types(expected: ExpectedChallengeV2) -> None:
    """Type-check the caller-supplied ExpectedChallengeV2 (Go's static types)."""
    ok = (
        isinstance(expected.value, (bytes, bytearray))
        and is_int(expected.issued_at) and is_int(expected.expires_at)
        and isinstance(expected.verifier_namespace, str) and is_int(expected.replay_epoch)
        and isinstance(expected.verifier_id, str) and isinstance(expected.expected_agent_id, str)
        and (expected.expected_agent_public_key is None or isinstance(expected.expected_agent_public_key, HybridPublicKey))
        and isinstance(expected.expected_receiver_id, str)
        and (expected.expected_session_context is None or isinstance(expected.expected_session_context, (bytes, bytearray)))
        and (expected.context_policy is None or isinstance(expected.context_policy, V2ContextPolicy))
    )
    if not ok:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected challenge has a field of the wrong type")


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def preflight_proof_bundle_v2(bundle: ProofBundleV2, expected: Optional[ExpectedChallengeV2], policy: Optional[V2ContextPolicy],
                              required_scope: str, configured_namespace: str, configured_replay_epoch: int,
                              configured_verifier_id: str, now_unix: int, max_age_seconds: int,
                              future_skew_seconds: int) -> V2PreflightResult:
    """Go ``PreflightProofBundleV2``: binds the challenge's expected context to
    the same immutable policy used by terminal evaluation. It seals no
    extension evaluator profile."""
    return _preflight_proof_bundle_v2(bundle, expected, policy, False, None, None, required_scope, configured_namespace,
                                      configured_replay_epoch, configured_verifier_id, now_unix, max_age_seconds,
                                      future_skew_seconds)


def _preflight_proof_bundle_v2(bundle: ProofBundleV2, expected: Optional[ExpectedChallengeV2], policy: Optional[V2ContextPolicy],
                               allow_no_policy: bool, hook: Optional[Callable], evaluators,
                               required_scope: str, configured_namespace: str, configured_replay_epoch: int,
                               configured_verifier_id: str, now_unix: int, max_age_seconds: int,
                               future_skew_seconds: int) -> V2PreflightResult:
    from .constraint_evaluator_v2 import snapshot_constraint_evaluators_v2

    if expected is None:
        raise V2Error(V2ErrorClass.EXPECTED_CHALLENGE_MISSING, "v2 expected challenge is unavailable")
    if not isinstance(expected, ExpectedChallengeV2):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected challenge has the wrong type")
    _check_expected_types(expected)
    if (policy is None and not allow_no_policy) or (policy is not None and not _policy_valid(policy)):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 context policy is missing or invalid")
    if policy is None and expected.context_policy is not None:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 challenge context policy does not match the issued policy")
    if policy is not None:
        if expected.context_policy is not None and not same_v2_context_policy(expected.context_policy, policy):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 challenge context policy does not match the issued policy")
        if policy._require_bound:
            # SPEC-v2 §6.7: an ExpectedChallenge without an expected session
            # context is accepted; the policy's own expected context is then
            # compared after claim and a mismatch is a post-claim deny.
            if expected.expected_session_context is not None and bytes(expected.expected_session_context) != (policy._expected_session_context or b""):
                raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 challenge context does not match the configured context policy")
        elif expected.expected_session_context is not None:
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "unbound v2 context policy cannot have an expected session context")
    checked = copy.copy(expected)
    checked.context_policy = policy
    validate_proof_bundle_v2_preflight(bundle, checked, required_scope, configured_namespace, configured_replay_epoch,
                                       configured_verifier_id, now_unix, max_age_seconds, future_skew_seconds)
    if hook is not None:
        try:
            hook(bundle, checked)
        except (KeyboardInterrupt, SystemExit):
            # The caller's own cancellation propagates.
            raise
        except BaseException as exc:  # noqa: BLE001 - any hook failure (Go: a recovered panic) rejects
            raise V2Error(V2ErrorClass.RECEIVER_BINDING_REJECTED,
                          f"v2 receiver-binding hook rejected the presentation: {exc}") from exc
    try:
        bundle_hash = bundle_hash_v2(bundle)
    except Exception as exc:  # noqa: BLE001
        raise classify(V2ErrorClass.MALFORMED, ValueError(f"v2 validated bundle hash: {exc}")) from exc
    issuer_ids = sorted({cert.issuer_id for cert in bundle.delegations}, key=lambda s: s.encode("utf-8"))
    state = _snapshot_expected_challenge_v2(expected, policy, required_scope, bundle_hash, issuer_ids,
                                            max_age_seconds, future_skew_seconds)
    state.evaluators, state.evaluator_refs, state.evaluator_timeout = snapshot_constraint_evaluators_v2(evaluators, bundle)
    return V2PreflightResult._seal(state)


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def validate_proof_bundle_v2_preflight(bundle: ProofBundleV2, expected: ExpectedChallengeV2, required_scope: str,
                                       configured_namespace: str, configured_replay_epoch: int,
                                       configured_verifier_id: str, now_unix: int,
                                       max_age_seconds: int, future_skew_seconds: int) -> None:
    """Go ``ValidateProofBundleV2Preflight``: the pure pre-claim checks."""
    if not isinstance(expected, ExpectedChallengeV2):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected challenge has the wrong type")
    _check_expected_types(expected)
    if not isinstance(bundle, ProofBundleV2):
        raise V2Error(V2ErrorClass.MALFORMED, "v2 proof bundle has the wrong type")
    for value in (configured_replay_epoch, now_unix, max_age_seconds, future_skew_seconds):
        if not is_int(value):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 preflight configuration must be integers")
    _validate_v2_verifier_identity_configuration(configured_namespace, configured_replay_epoch, configured_verifier_id)
    if expected.expected_session_context is not None and len(expected.expected_session_context) != 32:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected session context must be absent or exactly 32 bytes")
    policy = expected.context_policy
    if policy is not None:
        if not _policy_valid(policy):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected context policy is invalid")
        if policy._require_bound and expected.expected_session_context is not None and bytes(expected.expected_session_context) != (policy._expected_session_context or b""):
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected context does not match its policy")
        if not policy._require_bound and expected.expected_session_context is not None:
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "unbound v2 context policy cannot have an expected session context")
    if not isinstance(required_scope, str):
        raise V2Error(V2ErrorClass.INVALID_REQUIRED_SCOPE, "v2 request scope must be a string")
    try:
        validate_required_scope_v2(required_scope)
    except V2Error as exc:
        raise V2Error(V2ErrorClass.INVALID_REQUIRED_SCOPE, f"v2 request scope: {exc}") from exc
    except ValueError as exc:
        raise V2Error(V2ErrorClass.INVALID_REQUIRED_SCOPE, f"v2 request scope: {exc}") from exc
    verify_proof_bundle_v2_signatures(bundle)
    if expected.verifier_namespace != configured_namespace:
        raise V2Error(V2ErrorClass.NAMESPACE_MISMATCH, "v2 challenge verifier namespace mismatch")
    if (configured_replay_epoch < 0 or configured_replay_epoch > MAX_SAFE_INTEGER or expected.replay_epoch < 0
            or expected.replay_epoch > MAX_SAFE_INTEGER or expected.replay_epoch != configured_replay_epoch):
        raise V2Error(V2ErrorClass.STALE_REPLAY_EPOCH, "v2 challenge replay epoch is stale")
    if expected.verifier_id != configured_verifier_id or bundle.verifier_id != configured_verifier_id:
        raise V2Error(V2ErrorClass.VERIFIER_ID_MISMATCH,
                      "v2 challenge or proof verifier ID differs from the configured verifier key ID")
    if len(expected.value) != 32 or bytes(bundle.challenge) != bytes(expected.value) or bundle.challenge_at != expected.issued_at:
        raise V2Error(V2ErrorClass.CHALLENGE_MISMATCH, "v2 proof does not match authenticated challenge issuance")
    from .clock_bounds_v2 import valid_v2_timestamp
    if not valid_v2_timestamp(expected.issued_at) or not valid_v2_timestamp(expected.expires_at) or expected.expires_at <= expected.issued_at:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 authenticated challenge time bounds are invalid")
    validate_v2_freshness_configuration(now_unix, max_age_seconds, future_skew_seconds)
    if not v2_challenge_time_current(now_unix, expected.issued_at, expected.expires_at, max_age_seconds, future_skew_seconds):
        raise V2Error(V2ErrorClass.CHALLENGE_NOT_FRESH, "v2 challenge is not fresh (future-dated, expired, or beyond maximum age)")
    if (expected.expected_agent_id == "") != (expected.expected_agent_public_key is None):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 expected agent ID and public key must be configured together")
    if expected.expected_agent_public_key is not None:
        try:
            agent_id = key_id_v2(expected.expected_agent_public_key)
        except Exception as exc:  # noqa: BLE001
            raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, f"v2 expected agent key: {exc}") from exc
        if (agent_id != expected.expected_agent_id or bundle.agent_id != agent_id
                or not equal_hybrid_public_keys(bundle.agent_pub_key, expected.expected_agent_public_key)):
            raise V2Error(V2ErrorClass.EXPECTED_AGENT_MISMATCH, "v2 presentation does not match authenticated expected agent")
    if expected.expected_session_context is not None:
        if bundle.session_context is None or bytes(bundle.session_context) != bytes(expected.expected_session_context):
            raise V2Error(V2ErrorClass.SESSION_CONTEXT_MISMATCH, "v2 presentation does not match expected session context")
    _check_exact_receiver_audience_v2(bundle, expected.expected_receiver_id)


def _validate_v2_verifier_identity_configuration(namespace: object, replay_epoch: object, verifier_id: object) -> None:
    """Go ``validateV2VerifierIdentityConfiguration``: the caller-authenticated
    verifier identity of SPEC-v2 §6.1 at §6.2 step 2. A non-empty namespace, a
    replay epoch of 0 through 2^53-1, and the verifier key ID as a canonical
    v2 key ID; any violation is configuration_invalid."""
    if not isinstance(namespace, str) or namespace == "":
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 configured verifier namespace must be a non-empty string")
    if not is_int(replay_epoch) or replay_epoch < 0 or replay_epoch > MAX_SAFE_INTEGER:
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, f"v2 configured replay epoch must be 0..{MAX_SAFE_INTEGER}")
    if not isinstance(verifier_id, str) or not valid_v2_id(verifier_id):
        raise V2Error(V2ErrorClass.CONFIGURATION_INVALID, "v2 configured verifier key ID must be a canonical v2 key ID")


def _check_exact_receiver_audience_v2(bundle: ProofBundleV2, receiver_id: str) -> None:
    for i, cert in enumerate(bundle.delegations):
        for constraint in cert.constraints:
            if constraint.type != RECEIVER_AUDIENCE:
                continue
            if receiver_id == "":
                raise V2Error(V2ErrorClass.RECEIVER_AUDIENCE_REQUIRED,
                              "v2 receiver audience requires an authenticated expected receiver ID")
            params = constraint.params or {}
            exact = params.get("exact_receiver_ids")
            domains = params.get("trust_domain_ids")
            exact = exact if isinstance(exact, list) else []
            domains = domains if isinstance(domains, list) else []
            matches = any(isinstance(value, str) and value == receiver_id for value in exact)
            # A domain audience is evaluated only after claim from authenticated
            # trust configuration. An exact mismatch cannot pre-reject that case.
            if len(domains) == 0 and not matches:
                raise V2Error(V2ErrorClass.RECEIVER_AUDIENCE_MISMATCH,
                              f"v2 receiver does not match exact-only audience at delegation {i}")
