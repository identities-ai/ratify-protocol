"""v1 max_rate (SPEC §5.6): the invocation counter is the only input that can
deny an otherwise valid bundle on rate grounds. A counter that cannot answer
(a negative count, for example a database error mapped to -1) must fail
closed, never read as "no invocations yet". Mirrors the Rust
tests/v1_rate_counter.rs."""
from __future__ import annotations

from ratify_protocol import (
    PROTOCOL_VERSION,
    SCOPE_MEETING_ATTEND,
    Constraint,
    DelegationCert,
    ProofBundle,
    VerifierContext,
    VerifyOptions,
    generate_agent,
    generate_human_root,
    issue_delegation,
    sign_challenge,
    verify_bundle,
)

NOW = 1_800_000_000


def _rate_limited_bundle() -> ProofBundle:
    root, root_priv = generate_human_root()
    agent, agent_priv = generate_agent("rate-agent", "custom")
    cert = DelegationCert(
        cert_id="rate-cert",
        version=PROTOCOL_VERSION,
        issuer_id=root.id, issuer_pub_key=root.public_key,
        subject_id=agent.id, subject_pub_key=agent.public_key,
        scope=[SCOPE_MEETING_ATTEND],
        constraints=[Constraint(type="max_rate", count=1, window_s=60)],
        issued_at=NOW - 10, expires_at=NOW + 3600,
        signature=None,
    )
    issue_delegation(cert, root_priv)
    challenge = bytes([7]) * 32
    return ProofBundle(
        agent_id=agent.id, agent_pub_key=agent.public_key, delegations=[cert],
        challenge=challenge, challenge_at=NOW, challenge_sig=sign_challenge(challenge, NOW, agent_priv),
    )


def _verify_with_count(count: int):
    return verify_bundle(_rate_limited_bundle(), VerifyOptions(
        required_scope=SCOPE_MEETING_ATTEND, now=NOW,
        context=VerifierContext(invocations_in_window=lambda cert_id, window_s: count),
    ))


def test_rate_counter_below_limit_allows():
    r = _verify_with_count(0)
    assert r.valid, r.error_reason


def test_rate_counter_at_limit_denies():
    r = _verify_with_count(1)
    assert not r.valid
    assert r.identity_status == "constraint_denied"


def test_negative_rate_count_fails_closed_as_unverifiable():
    for count in (-1, -(2**63)):
        r = _verify_with_count(count)
        assert not r.valid, f"count {count} must not allow"
        assert r.identity_status == "constraint_unverifiable", (count, r.error_reason)
