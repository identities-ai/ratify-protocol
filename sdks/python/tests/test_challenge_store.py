"""ChallengeStore tests — store semantics plus the locked consumption
order in verify_bundle (SPEC §10): a challenge is consumed after the
structural, chain, and challenge-signature checks pass and before
authorization evaluation, so a forged presentation never spends a
challenge and a cryptographically valid presentation spends it even when
denied."""
from __future__ import annotations

import threading
import time

import pytest

from ratify_protocol import (
    PROTOCOL_VERSION,
    SCOPE_FILES_WRITE,
    SCOPE_MEETING_ATTEND,
    SCOPE_TRANSACT_PURCHASE,
    UNKNOWN_CHALLENGE,
    Constraint,
    DelegationCert,
    HybridSignature,
    MemoryChallengeStore,
    ProofBundle,
    VerifierContext,
    VerifyOptions,
    generate_agent,
    generate_human_root,
    issue_delegation,
    sign_challenge,
    verify_bundle,
)

UNKNOWN_REASON = f"unknown_challenge: {UNKNOWN_CHALLENGE}"


def _now() -> int:
    return int(time.time())


# ----- Store semantics -----

def test_issue_then_consume():
    store = MemoryChallengeStore(max_size=16)
    challenge, expires_at = store.issue(b"", 300)
    assert len(challenge) == 32
    assert 290 <= expires_at - _now() <= 310
    assert store.validate(challenge, b"", _now()) is None
    assert store.consume(challenge, b"", _now()) is None


def test_double_consume_fails():
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    assert store.consume(challenge, b"", _now()) is None
    assert store.consume(challenge, b"", _now()) == UNKNOWN_CHALLENGE
    assert store.validate(challenge, b"", _now()) == UNKNOWN_CHALLENGE


def test_expiry():
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    later = _now() + 360
    assert store.validate(challenge, b"", later) == UNKNOWN_CHALLENGE
    assert store.consume(challenge, b"", later) == UNKNOWN_CHALLENGE


def test_never_issued_challenge():
    store = MemoryChallengeStore(max_size=16)
    assert store.consume(b"\x00" * 32, b"", _now()) == UNKNOWN_CHALLENGE


def test_wrong_session_context_does_not_consume():
    store = MemoryChallengeStore(max_size=16)
    ctx = b"\x01" + b"\x00" * 31
    challenge, _ = store.issue(ctx, 300)

    other = b"\x02" + b"\x00" * 31
    assert store.consume(challenge, other, _now()) == UNKNOWN_CHALLENGE
    assert store.consume(challenge, b"", _now()) == UNKNOWN_CHALLENGE
    # The legitimate record survived both wrong-context presentations.
    assert store.consume(challenge, ctx, _now()) is None


def test_capacity_cap():
    store = MemoryChallengeStore(max_size=2)
    store.issue(b"", 60)
    store.issue(b"", 60)
    with pytest.raises(RuntimeError, match="challenge store full"):
        store.issue(b"", 60)


def test_concurrent_consume_is_atomic():
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    now = _now()
    successes = []
    barrier = threading.Barrier(16)

    def attempt():
        barrier.wait()
        if store.consume(challenge, b"", now) is None:
            successes.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(successes) == 1


# ----- verify_bundle integration: the locked consumption order -----

def _store_bundle(scope, constraints=None):
    root, root_priv = generate_human_root()
    agent, agent_priv = generate_agent("Store Bot", "custom")
    now = _now()
    cert = DelegationCert(
        cert_id="store-cert-001",
        version=PROTOCOL_VERSION,
        issuer_id=root.id,
        issuer_pub_key=root.public_key,
        subject_id=agent.id,
        subject_pub_key=agent.public_key,
        scope=scope,
        constraints=constraints or [],
        issued_at=now,
        expires_at=now + 86400,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    issue_delegation(cert, root_priv)
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    sig = sign_challenge(challenge, now, agent_priv)
    bundle = ProofBundle(
        agent_id=agent.id,
        agent_pub_key=agent.public_key,
        delegations=[cert],
        challenge=challenge,
        challenge_at=now,
        challenge_sig=sig,
    )
    return bundle, store


def test_verify_with_store_replay_is_rejected():
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    opts = VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store)

    first = verify_bundle(bundle, opts)
    assert first.valid, first.error_reason

    replay = verify_bundle(bundle, opts)
    assert not replay.valid
    assert replay.identity_status == "invalid"
    assert replay.error_reason == UNKNOWN_REASON


def test_verify_with_store_bad_signature_does_not_consume():
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    opts = VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store)

    forged_ed = bytearray(bundle.challenge_sig.ed25519)
    forged_ed[0] ^= 0xFF
    forged = ProofBundle(
        agent_id=bundle.agent_id,
        agent_pub_key=bundle.agent_pub_key,
        delegations=bundle.delegations,
        challenge=bundle.challenge,
        challenge_at=bundle.challenge_at,
        challenge_sig=HybridSignature(
            ed25519=bytes(forged_ed), ml_dsa_65=bundle.challenge_sig.ml_dsa_65
        ),
    )
    res = verify_bundle(forged, opts)
    assert not res.valid
    assert res.error_reason.startswith("bad_challenge_sig")

    # The legitimate presentation still succeeds afterwards.
    legit = verify_bundle(bundle, opts)
    assert legit.valid, legit.error_reason


def test_verify_with_store_scope_denied_still_consumes():
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    denied = verify_bundle(
        bundle, VerifyOptions(required_scope=SCOPE_FILES_WRITE, challenge_store=store)
    )
    assert not denied.valid
    assert denied.identity_status == "scope_denied"

    # Retrying with the correct scope fails: the challenge is spent.
    retry = verify_bundle(
        bundle, VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store)
    )
    assert retry.error_reason == UNKNOWN_REASON


def test_verify_with_store_constraint_denied_still_consumes():
    bundle, store = _store_bundle(
        [SCOPE_TRANSACT_PURCHASE],
        [Constraint(type="max_amount", max_amount=100, currency="USD")],
    )
    denied = verify_bundle(
        bundle,
        VerifyOptions(
            required_scope=SCOPE_TRANSACT_PURCHASE,
            challenge_store=store,
            context=VerifierContext(requested_amount=500, requested_currency="USD"),
        ),
    )
    assert not denied.valid
    assert denied.identity_status == "constraint_denied"

    # Constraint denial happened AFTER consumption: the challenge is spent.
    retry = verify_bundle(
        bundle,
        VerifyOptions(
            required_scope=SCOPE_TRANSACT_PURCHASE,
            challenge_store=store,
            context=VerifierContext(requested_amount=50, requested_currency="USD"),
        ),
    )
    assert retry.error_reason == UNKNOWN_REASON


def test_verify_with_store_unknown_challenge_rejected_before_crypto():
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    other_store = MemoryChallengeStore(max_size=16)
    res = verify_bundle(bundle, VerifyOptions(challenge_store=other_store))
    assert res.error_reason == UNKNOWN_REASON
    # The bundle's own store still holds the unconsumed record.
    assert store.validate(bundle.challenge, b"", _now()) is None
