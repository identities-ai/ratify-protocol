"""Tests for the Provider interfaces defined in SPEC §17.

Each test builds a known-good single-cert ProofBundle as the fixture, then
configures one provider hook at a time to confirm:
  - RevocationProvider (§17.1) revoke / not-revoke / error-fails-closed /
    precedence over legacy is_revoked closure.
  - PolicyProvider (§17.2) allow / deny → scope_denied / error → policy_error /
    runs only after cryptographic checks pass.
  - AuditProvider (§17.3) is called on success AND failure; provider exceptions
    do NOT alter the verdict.
"""
from __future__ import annotations

import time

import pytest

from ratify_protocol import (
    PROTOCOL_VERSION,
    SCOPE_MEETING_ATTEND,
    DelegationCert,
    ProofBundle,
    VerifyOptions,
    generate_agent,
    generate_challenge,
    generate_human_root,
    issue_delegation,
    sign_challenge,
    verify_bundle,
)


def _good_bundle():
    """Return a (bundle, cert_id) pair that verifies cleanly with no opts."""
    root, root_priv = generate_human_root()
    agent, agent_priv = generate_agent("Provider Bot", "custom")
    now = int(time.time())
    cert = DelegationCert(
        cert_id="provider-cert-001",
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
    bundle = ProofBundle(
        agent_id=agent.id,
        agent_pub_key=agent.public_key,
        delegations=[cert],
        challenge=challenge,
        challenge_at=now,
        challenge_sig=sig,
    )
    return bundle, cert.cert_id


# ---------------------------------------------------------------------------
# RevocationProvider — SPEC §17.1
# ---------------------------------------------------------------------------

class FakeRevocation:
    def __init__(self, revoked=None, err=None):
        self.revoked = revoked or {}
        self.err = err
        self.calls = 0

    def is_revoked(self, cert_id):
        self.calls += 1
        if self.err is not None:
            return False, self.err
        return self.revoked.get(cert_id, False), None


def test_revocation_provider_revoked():
    bundle, cert_id = _good_bundle()
    provider = FakeRevocation(revoked={cert_id: True})
    res = verify_bundle(bundle, VerifyOptions(revocation=provider))
    assert not res.valid
    assert res.identity_status == "revoked"
    assert provider.calls == 1


def test_revocation_provider_not_revoked():
    bundle, _ = _good_bundle()
    provider = FakeRevocation()
    res = verify_bundle(bundle, VerifyOptions(revocation=provider))
    assert res.valid, res.error_reason


def test_revocation_provider_error_fails_closed():
    bundle, _ = _good_bundle()
    provider = FakeRevocation(err="upstream timeout")
    res = verify_bundle(bundle, VerifyOptions(revocation=provider))
    assert not res.valid
    assert "revocation_error" in res.error_reason


def test_revocation_provider_takes_precedence_over_closure():
    bundle, cert_id = _good_bundle()
    provider = FakeRevocation(revoked={cert_id: True})
    closure_calls = {"count": 0}

    def legacy_closure(_):
        closure_calls["count"] += 1
        return False

    res = verify_bundle(
        bundle,
        VerifyOptions(revocation=provider, is_revoked=legacy_closure),
    )
    assert not res.valid
    assert closure_calls["count"] == 0, "legacy closure must not be invoked"


def test_force_revocation_check_accepts_provider():
    bundle, _ = _good_bundle()
    provider = FakeRevocation()
    res = verify_bundle(
        bundle,
        VerifyOptions(revocation=provider, force_revocation_check=True),
    )
    assert res.valid, res.error_reason


# ---------------------------------------------------------------------------
# PolicyProvider — SPEC §17.2
# ---------------------------------------------------------------------------

class FakePolicy:
    def __init__(self, allow=True, err=None, raises=None):
        self.allow = allow
        self.err = err
        self.raises = raises
        self.calls = 0

    def evaluate_policy(self, bundle, context):
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return self.allow, self.err


def test_policy_provider_allow():
    bundle, _ = _good_bundle()
    policy = FakePolicy(allow=True)
    res = verify_bundle(bundle, VerifyOptions(policy=policy))
    assert res.valid, res.error_reason
    assert policy.calls == 1


def test_policy_provider_deny():
    bundle, _ = _good_bundle()
    policy = FakePolicy(allow=False)
    res = verify_bundle(bundle, VerifyOptions(policy=policy))
    assert not res.valid
    assert res.identity_status == "scope_denied"


def test_policy_provider_error_returned():
    bundle, _ = _good_bundle()
    policy = FakePolicy(err="opa eval crashed")
    res = verify_bundle(bundle, VerifyOptions(policy=policy))
    assert not res.valid
    assert "policy_error" in res.error_reason


def test_policy_provider_exception_fails_closed():
    bundle, _ = _good_bundle()
    policy = FakePolicy(raises=RuntimeError("boom"))
    res = verify_bundle(bundle, VerifyOptions(policy=policy))
    assert not res.valid
    assert "policy_error" in res.error_reason


def test_policy_provider_only_runs_after_crypto_checks():
    bundle, _ = _good_bundle()
    bundle.challenge = b"tampered"
    policy = FakePolicy(allow=True)
    res = verify_bundle(bundle, VerifyOptions(policy=policy))
    assert not res.valid
    assert policy.calls == 0, "policy must not run when crypto fails"


# ---------------------------------------------------------------------------
# AuditProvider — SPEC §17.3
# ---------------------------------------------------------------------------

class FakeAudit:
    def __init__(self, raises=None):
        self.results = []
        self.raises = raises

    def log_verification(self, result, bundle):
        self.results.append(result)
        if self.raises is not None:
            raise self.raises


def test_audit_provider_logs_success():
    bundle, _ = _good_bundle()
    audit = FakeAudit()
    res = verify_bundle(bundle, VerifyOptions(audit=audit))
    assert res.valid, res.error_reason
    assert len(audit.results) == 1
    assert audit.results[0].valid


def test_audit_provider_logs_failure():
    bundle, _ = _good_bundle()
    bundle.challenge = b"tampered"
    audit = FakeAudit()
    res = verify_bundle(bundle, VerifyOptions(audit=audit))
    assert not res.valid
    assert len(audit.results) == 1
    assert not audit.results[0].valid


def test_audit_provider_exception_does_not_alter_verdict():
    bundle, _ = _good_bundle()
    audit = FakeAudit(raises=RuntimeError("audit store offline"))
    res = verify_bundle(bundle, VerifyOptions(audit=audit))
    assert res.valid, "audit exception must not flip verdict"
