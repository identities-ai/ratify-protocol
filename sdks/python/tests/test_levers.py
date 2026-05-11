"""Tests for the SPEC §17.5–§17.8 levers introduced in alpha.7."""
from __future__ import annotations

import time

import pytest

from ratify_protocol import (
    PROTOCOL_VERSION,
    SCOPE_MEETING_ATTEND,
    Anchor,
    Constraint,
    DelegationCert,
    ProofBundle,
    VerifierContext,
    VerifyOptions,
    bundle_hash,
    generate_agent,
    generate_challenge,
    generate_human_root,
    issue_delegation,
    issue_policy_verdict,
    issue_verification_receipt,
    receipt_hash,
    sign_challenge,
    verifier_context_hash,
    verify_bundle,
    verify_policy_verdict_e,
    verify_verification_receipt,
)


def _good_bundle():
    root, root_priv = generate_human_root()
    agent, agent_priv = generate_agent("L Bot", "custom")
    now = int(time.time())
    cert = DelegationCert(
        cert_id="lever-cert",
        version=PROTOCOL_VERSION,
        issuer_id=root.id,
        issuer_pub_key=root.public_key,
        subject_id=agent.id,
        subject_pub_key=agent.public_key,
        scope=[SCOPE_MEETING_ATTEND],
        issued_at=now,
        expires_at=now + 86400,
        signature=None,
    )
    issue_delegation(cert, root_priv)
    challenge = generate_challenge()
    sig = sign_challenge(challenge, now, agent_priv)
    return (
        ProofBundle(
            agent_id=agent.id,
            agent_pub_key=agent.public_key,
            delegations=[cert],
            challenge=challenge,
            challenge_at=now,
            challenge_sig=sig,
        ),
        cert.cert_id,
        root.id,
    )


# ---------------------------------------------------------------------------
# Lever 1: VerificationReceipt
# ---------------------------------------------------------------------------

def test_verification_receipt_roundtrip():
    bundle, _, _ = _good_bundle()
    v, v_priv = generate_agent("v", "verifier")
    result = verify_bundle(bundle, VerifyOptions())
    r = issue_verification_receipt(
        bundle, result, v.id, v.public_key, v_priv, None, int(time.time())
    )
    assert verify_verification_receipt(r) is None
    assert r.decision == "authorized_agent"


def test_verification_receipt_detects_tampering():
    bundle, _, _ = _good_bundle()
    v, v_priv = generate_agent("v", "verifier")
    result = verify_bundle(bundle, VerifyOptions())
    r = issue_verification_receipt(
        bundle, result, v.id, v.public_key, v_priv, None, int(time.time())
    )
    r.decision = "revoked"
    assert verify_verification_receipt(r) is not None


def test_verification_receipt_detects_bundle_substitution():
    b1, _, _ = _good_bundle()
    b2, _, _ = _good_bundle()
    v, v_priv = generate_agent("v", "verifier")
    result = verify_bundle(b1, VerifyOptions())
    r = issue_verification_receipt(
        b1, result, v.id, v.public_key, v_priv, None, int(time.time())
    )
    r.bundle_hash = bundle_hash(b2)
    assert verify_verification_receipt(r) is not None


def test_verification_receipt_chain_linkage():
    bundle, _, _ = _good_bundle()
    v, v_priv = generate_agent("v", "verifier")
    result = verify_bundle(bundle, VerifyOptions())
    r1 = issue_verification_receipt(
        bundle, result, v.id, v.public_key, v_priv, None, int(time.time())
    )
    prev = receipt_hash(r1)
    r2 = issue_verification_receipt(
        bundle, result, v.id, v.public_key, v_priv, prev, int(time.time())
    )
    assert r2.prev_hash == prev
    r1.decision = "tampered"
    assert receipt_hash(r1) != prev


def test_bundle_hash_deterministic():
    bundle, _, _ = _good_bundle()
    assert bundle_hash(bundle) == bundle_hash(bundle)
    assert len(bundle_hash(bundle)) == 32


# ---------------------------------------------------------------------------
# Lever 2: PolicyVerdict
# ---------------------------------------------------------------------------

SECRET = b"\x33" * 32


def test_policy_verdict_roundtrip():
    now = int(time.time())
    ctx = verifier_context_hash(VerifierContext())
    v = issue_policy_verdict("vid", "agent-A", "meeting:attend", True, ctx, now, now + 3600, SECRET)
    assert verify_policy_verdict_e(v, SECRET, "agent-A", "meeting:attend", ctx, now) is None


def test_policy_verdict_deny():
    now = int(time.time())
    ctx = verifier_context_hash(VerifierContext())
    v = issue_policy_verdict("v", "a", "s", False, ctx, now, now + 3600, SECRET)
    err = verify_policy_verdict_e(v, SECRET, "a", "s", ctx, now)
    assert err is not None and "policy_verdict_denied" in err


def test_policy_verdict_wrong_secret():
    now = int(time.time())
    ctx = verifier_context_hash(VerifierContext())
    v = issue_policy_verdict("v", "a", "s", True, ctx, now, now + 3600, SECRET)
    assert verify_policy_verdict_e(v, b"\x44" * 32, "a", "s", ctx, now) is not None


def test_policy_verdict_context_hash_mismatch():
    now = int(time.time())
    ctxA = verifier_context_hash(VerifierContext(current_lat=37.0, current_lon=-122.0))
    ctxB = verifier_context_hash(VerifierContext(current_lat=51.5, current_lon=-0.1))
    v = issue_policy_verdict("v", "a", "s", True, ctxA, now, now + 3600, SECRET)
    assert verify_policy_verdict_e(v, SECRET, "a", "s", ctxB, now) is not None


def test_policy_verdict_expired():
    now = int(time.time())
    ctx = verifier_context_hash(VerifierContext())
    v = issue_policy_verdict("v", "a", "s", True, ctx, now - 7200, now - 3600, SECRET)
    assert verify_policy_verdict_e(v, SECRET, "a", "s", ctx, now) is not None


class _LivePolicy:
    def __init__(self, allow):
        self.allow = allow
        self.calls = 0
    def evaluate_policy(self, bundle, ctx):
        self.calls += 1
        return self.allow, None


def test_policy_verdict_fast_path_skips_live_policy():
    bundle, _, _ = _good_bundle()
    now = int(time.time())
    ctx_hash = verifier_context_hash(VerifierContext())
    v = issue_policy_verdict(
        "vid", bundle.agent_id, "meeting:attend", True, ctx_hash,
        now - 60, now + 3600, SECRET,
    )
    live = _LivePolicy(allow=False)  # would deny if consulted

    res = verify_bundle(bundle, VerifyOptions(
        required_scope="meeting:attend",
        policy=live,
        policy_verdict=v,
        policy_secret=SECRET,
    ))
    assert res.valid, res.error_reason
    assert live.calls == 0


def test_policy_verdict_cached_deny():
    bundle, _, _ = _good_bundle()
    now = int(time.time())
    ctx_hash = verifier_context_hash(VerifierContext())
    v = issue_policy_verdict(
        "vid", bundle.agent_id, "meeting:attend", False, ctx_hash,
        now - 60, now + 3600, SECRET,
    )
    live = _LivePolicy(allow=True)

    res = verify_bundle(bundle, VerifyOptions(
        required_scope="meeting:attend",
        policy=live,
        policy_verdict=v,
        policy_secret=SECRET,
    ))
    assert not res.valid
    assert res.identity_status == "scope_denied"
    assert live.calls == 0


def test_policy_verdict_falls_back_when_stale():
    bundle, _, _ = _good_bundle()
    now = int(time.time())
    ctx_hash = verifier_context_hash(VerifierContext())
    expired = issue_policy_verdict(
        "vid", bundle.agent_id, "meeting:attend", True, ctx_hash,
        now - 7200, now - 3600, SECRET,
    )
    live = _LivePolicy(allow=True)

    res = verify_bundle(bundle, VerifyOptions(
        required_scope="meeting:attend",
        policy=live,
        policy_verdict=expired,
        policy_secret=SECRET,
    ))
    assert res.valid, res.error_reason
    assert live.calls == 1


# ---------------------------------------------------------------------------
# Lever 3: ConstraintEvaluator
# ---------------------------------------------------------------------------

def _bundle_with_custom_constraint(constraint_type):
    root, root_priv = generate_human_root()
    agent, agent_priv = generate_agent("C", "custom")
    now = int(time.time())
    cert = DelegationCert(
        cert_id="cc",
        version=PROTOCOL_VERSION,
        issuer_id=root.id, issuer_pub_key=root.public_key,
        subject_id=agent.id, subject_pub_key=agent.public_key,
        scope=[SCOPE_MEETING_ATTEND],
        constraints=[Constraint(type=constraint_type)],
        issued_at=now, expires_at=now + 3600,
        signature=None,
    )
    issue_delegation(cert, root_priv)
    challenge = generate_challenge()
    sig = sign_challenge(challenge, now, agent_priv)
    return ProofBundle(
        agent_id=agent.id, agent_pub_key=agent.public_key,
        delegations=[cert],
        challenge=challenge, challenge_at=now, challenge_sig=sig,
    )


def test_constraint_evaluator_unknown_fails_closed():
    bundle = _bundle_with_custom_constraint("verify.max_concurrent_sessions")
    res = verify_bundle(bundle, VerifyOptions())
    assert not res.valid
    assert res.identity_status == "constraint_unknown"


class _AllowEvaluator:
    def evaluate(self, c, cert_id, ctx, now): return (True, None)


class _DenyEvaluator:
    def evaluate(self, c, cert_id, ctx, now): return (False, "too many sessions")


class _UnverifiableEvaluator:
    def evaluate(self, c, cert_id, ctx, now):
        return (False, "constraint_unverifiable: missing input")


def test_constraint_evaluator_registry_allow():
    bundle = _bundle_with_custom_constraint("verify.max_concurrent_sessions")
    res = verify_bundle(bundle, VerifyOptions(
        constraint_evaluators={"verify.max_concurrent_sessions": _AllowEvaluator()},
    ))
    assert res.valid, res.error_reason


def test_constraint_evaluator_registry_deny():
    bundle = _bundle_with_custom_constraint("verify.max_concurrent_sessions")
    res = verify_bundle(bundle, VerifyOptions(
        constraint_evaluators={"verify.max_concurrent_sessions": _DenyEvaluator()},
    ))
    assert not res.valid
    assert res.identity_status == "constraint_denied"


def test_constraint_evaluator_unverifiable_routes():
    bundle = _bundle_with_custom_constraint("verify.needs_context")
    res = verify_bundle(bundle, VerifyOptions(
        constraint_evaluators={"verify.needs_context": _UnverifiableEvaluator()},
    ))
    assert not res.valid
    assert res.identity_status == "constraint_unverifiable"


# ---------------------------------------------------------------------------
# Lever 4: AnchorResolver
# ---------------------------------------------------------------------------

class _StaticAnchorResolver:
    def __init__(self, anchors=None, raises=None):
        self.anchors = anchors or {}
        self.raises = raises
    def resolve_anchor(self, human_id):
        if self.raises is not None:
            raise self.raises
        return self.anchors.get(human_id)


def test_anchor_resolver_populates_result():
    bundle, _, human_id = _good_bundle()
    anchor = Anchor(type="enterprise_sso", provider="okta",
                    reference="opaque", verified_at=1000)
    res = verify_bundle(bundle, VerifyOptions(
        anchor_resolver=_StaticAnchorResolver({human_id: anchor}),
    ))
    assert res.valid, res.error_reason
    assert res.anchor is not None
    assert res.anchor.provider == "okta"


def test_anchor_resolver_error_is_non_fatal():
    bundle, _, _ = _good_bundle()
    res = verify_bundle(bundle, VerifyOptions(
        anchor_resolver=_StaticAnchorResolver(raises=RuntimeError("dir down")),
    ))
    assert res.valid, res.error_reason
    assert res.anchor is None


def test_audit_observes_anchor():
    bundle, _, human_id = _good_bundle()
    anchor = Anchor(type="email", provider="google",
                    reference="h:abc", verified_at=100)
    logged = []
    class _Audit:
        def log_verification(self, r, b): logged.append(r)
    res = verify_bundle(bundle, VerifyOptions(
        anchor_resolver=_StaticAnchorResolver({human_id: anchor}),
        audit=_Audit(),
    ))
    assert res.valid
    assert len(logged) == 1
    assert logged[0].anchor is not None
    assert logged[0].anchor.provider == "google"
