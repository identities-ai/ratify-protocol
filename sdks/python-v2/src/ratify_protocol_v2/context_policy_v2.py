"""Protocol v2 verifier context policy (mirrors Go context_policy_v2.go).

Also declares :class:`V2DeferredConstraint`, which Go declares in
authorization_v2.go: a signed constraint retained from the claimed proof for a
post-status stage (``max_rate`` or ``ratify.receiver_audience``).
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha384
from typing import Optional

from . import _v2json
from .types_v2 import valid_prefixed_digest_v2

VERIFY_SESSION_CONTEXT_PROFILE_V2 = "ratify.verify.session-context/v1"
VERIFY_SESSION_CONTEXT_FIELDS_V2 = (
    "verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash",
)


@dataclass(frozen=True)
class V2DeferredConstraint:
    """A signed constraint sealed with the claim for a post-status stage."""

    delegation_index: int
    constraint_index: int
    issuer_id: str
    cert_id: str
    type: str
    canonical_json: bytes


def _valid_text(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


_POLICY_TOKEN = object()


class V2ContextPolicy:
    """Validated verifier-owned context policy. Its receipt digest is derived
    from the canonical policy fields, never supplied by callers. Only
    :func:`new_v2_context_policy` builds a valid policy; any other instance
    is invalid and can never pass."""

    __slots__ = ("_profile", "_require_bound", "_required_fields", "_expected_session_context", "_digest", "_valid")

    def __init__(self, *_args, **kwargs):
        token = kwargs.pop("_token", None)
        self._valid = token is _POLICY_TOKEN
        self._profile: str = kwargs.get("profile", "") if self._valid else ""
        self._require_bound: bool = bool(kwargs.get("require_bound", False)) if self._valid else False
        self._required_fields: list = list(kwargs.get("required_fields", ())) if self._valid else []
        self._expected_session_context: Optional[bytes] = (
            kwargs.get("expected_session_context") if self._valid else None
        )
        self._digest: str = kwargs.get("digest", "") if self._valid else ""

    @property
    def profile(self) -> str:
        return self._profile

    @property
    def require_bound(self) -> bool:
        return self._require_bound

    @property
    def required_fields(self) -> list:
        return list(self._required_fields)

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def expected_session_context(self) -> Optional[bytes]:
        return self._expected_session_context

    def __repr__(self) -> str:
        return f"V2ContextPolicy(profile={self._profile!r}, require_bound={self._require_bound}, digest={self._digest!r})"


@dataclass(frozen=True)
class V2ContextPolicyAssessment:
    """An intermediate ordered-stage result. A caller stops on any status
    other than ``passed`` before constraints or status."""

    assessment: str
    policy_digest: Optional[str]
    status: str
    reason: str = ""
    detail: str = ""


def new_v2_context_policy(
    profile: str, require_bound: bool, required_fields, expected_session_context: Optional[bytes]
) -> V2ContextPolicy:
    """Validate and fingerprint a policy. ``expected_session_context`` is
    per-invocation authenticated state and is excluded from the digest.
    Raises ValueError (unclassified, as in Go) on an invalid policy."""
    if not _valid_text(profile) or profile == "":
        raise ValueError("v2 context policy profile must be non-empty valid UTF-8")
    if not isinstance(require_bound, bool):
        raise TypeError("require_bound must be a bool")
    if required_fields is None:
        required_fields = []
    if isinstance(required_fields, (str, bytes)):
        raise TypeError("required_fields must be a list of strings")
    fields: list = []
    seen: set = set()
    for i, field in enumerate(required_fields):
        if not _valid_text(field) or field == "":
            raise ValueError(f"v2 context policy field {i} is empty or invalid UTF-8")
        if field in seen:
            raise ValueError(f"v2 context policy has duplicate field {field!r}")
        seen.add(field)
        fields.append(field)
    if expected_session_context is not None and not isinstance(expected_session_context, (bytes, bytearray)):
        raise TypeError("expected_session_context must be bytes or None")
    expected = None if expected_session_context is None else bytes(expected_session_context)
    if require_bound and (len(fields) == 0 or expected is None or len(expected) != 32):
        raise ValueError("bound v2 context policy requires fields and a 32-byte authenticated context")
    if not require_bound and expected:
        raise ValueError("unbound v2 context policy cannot carry an expected context")
    if profile == VERIFY_SESSION_CONTEXT_PROFILE_V2 and (
        not require_bound or tuple(fields) != VERIFY_SESSION_CONTEXT_FIELDS_V2
    ):
        raise ValueError("Ratify Verify session-context policy must require the canonical field set")
    encoded = _v2json.canonical(
        {"profile": profile, "require_bound": require_bound, "required_fields": fields, "version": 1}
    )
    digest = "sha384:" + sha384(encoded).hexdigest()
    # Go bytes.Clone(nil) and of an empty slice: no expected context.
    return V2ContextPolicy(
        _token=_POLICY_TOKEN, profile=profile, require_bound=require_bound, required_fields=fields,
        expected_session_context=expected if expected else None, digest=digest,
    )


def _context_policy_failure(assessment: str, status: str, reason: str, detail: str) -> V2ContextPolicyAssessment:
    return V2ContextPolicyAssessment(assessment=assessment, policy_digest=None, status=status, reason=reason, detail=detail)


def evaluate_proof_bundle_v2_context_policy(bundle, policy: Optional[V2ContextPolicy]) -> V2ContextPolicyAssessment:
    """Apply a validated verifier context policy after preflight and claim."""
    if bundle is None:
        return _context_policy_failure(
            "unverified", "authorization_unverified", "action_context_unverified", "proof bundle is unavailable"
        )
    has_context = getattr(bundle, "session_context", None) is not None
    if policy is None:
        return _context_policy_failure(
            "unverified" if has_context else "unbound", "authorization_unverified", "action_context_unverified",
            "no caller-authenticated context policy is configured",
        )
    if not isinstance(policy, V2ContextPolicy) or not policy._valid or not policy._digest or not valid_prefixed_digest_v2(policy._digest):
        return _context_policy_failure(
            "unverified" if has_context else "unbound", "authorization_unverified", "action_context_unverified",
            "no valid caller-authenticated context policy is configured",
        )
    digest = policy._digest
    if not policy._require_bound:
        return V2ContextPolicyAssessment(assessment="not_required", policy_digest=digest, status="passed")
    if not has_context:
        return V2ContextPolicyAssessment(
            assessment="unverified", policy_digest=digest, status="authorization_unverified",
            reason="action_context_unverified", detail="required session context is absent",
        )
    if bytes(bundle.session_context) != (policy._expected_session_context or b""):
        return V2ContextPolicyAssessment(
            assessment="mismatch", policy_digest=digest, status="constraint_denied", reason="constraint_denied",
            detail="proof session context does not match the verifier's authenticated context",
        )
    return V2ContextPolicyAssessment(assessment="bound", policy_digest=digest, status="passed")


def same_v2_context_policy(a: Optional[V2ContextPolicy], b: Optional[V2ContextPolicy]) -> bool:
    return (
        isinstance(a, V2ContextPolicy) and isinstance(b, V2ContextPolicy) and a._valid and b._valid
        and a._profile == b._profile and a._require_bound == b._require_bound and a._digest == b._digest
        and list(a._required_fields) == list(b._required_fields)
        and (a._expected_session_context or b"") == (b._expected_session_context or b"")
    )


def clone_v2_context_policy(policy: Optional[V2ContextPolicy]) -> Optional[V2ContextPolicy]:
    if policy is None:
        return None
    out = V2ContextPolicy()
    out._valid = policy._valid
    out._profile = policy._profile
    out._require_bound = policy._require_bound
    out._required_fields = list(policy._required_fields)
    out._expected_session_context = (
        None if policy._expected_session_context is None else bytes(policy._expected_session_context)
    )
    out._digest = policy._digest
    return out
