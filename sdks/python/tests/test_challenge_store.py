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


def test_consume_frees_capacity_immediately():
    # Capacity counts PENDING challenges: consuming one frees its slot, so
    # legitimate traffic cannot wedge issuance until records expire.
    store = MemoryChallengeStore(max_size=2)
    challenge, _ = store.issue(b"", 300)
    store.issue(b"", 300)
    with pytest.raises(RuntimeError, match="challenge store full"):
        store.issue(b"", 300)
    assert store.consume(challenge, b"", _now()) is None
    store.issue(b"", 300)  # must succeed immediately


def test_wrong_session_context_does_not_free_capacity():
    store = MemoryChallengeStore(max_size=1)
    ctx = b"\x01" + b"\x00" * 31
    challenge, _ = store.issue(ctx, 300)
    assert store.consume(challenge, b"", _now()) == UNKNOWN_CHALLENGE
    with pytest.raises(RuntimeError, match="challenge store full"):
        store.issue(b"", 300)


def test_issue_validates_inputs():
    store = MemoryChallengeStore(max_size=16)
    with pytest.raises(ValueError, match="session context"):
        store.issue(b"\x00" * 5, 300)
    with pytest.raises(ValueError, match="ttl"):
        store.issue(b"", 0)
    with pytest.raises(ValueError, match="ttl"):
        store.issue(b"", -60)
    # 0 and 32 bytes are the two valid session-context lengths.
    store.issue(b"", 60)
    store.issue(b"\x00" * 32, 60)


def test_constructor_rejects_non_positive_capacity():
    with pytest.raises(ValueError, match="max_size"):
        MemoryChallengeStore(max_size=0)
    with pytest.raises(ValueError, match="max_size"):
        MemoryChallengeStore(max_size=-1)


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


# ----- Store-failure normalization: no custom-store text or exception leaks -----

class _LeakyStore:
    """Adversarial custom ChallengeStore whose failures carry backend
    detail that would distinguish record states. verify_bundle must
    normalize every one — returned strings AND raised exceptions — to the
    canonical unknown_challenge result."""

    def __init__(self, inner, validate_result=None, consume_result=None):
        self._inner = inner
        self._validate_result = validate_result
        self._consume_result = consume_result

    def issue(self, session_context, ttl_seconds):
        return self._inner.issue(session_context, ttl_seconds)

    def validate(self, challenge, session_context, now):
        if self._validate_result is not None:
            if isinstance(self._validate_result, Exception):
                raise self._validate_result
            return self._validate_result
        return self._inner.validate(challenge, session_context, now)

    def consume(self, challenge, session_context, now):
        if self._consume_result is not None:
            if isinstance(self._consume_result, Exception):
                raise self._consume_result
            return self._consume_result
        return self._inner.consume(challenge, session_context, now)


@pytest.mark.parametrize(
    "leak",
    [
        'pg: relation "challenges" does not exist',
        "record expired 42s ago",
        "challenge already consumed by request 7f3a",
        "session binding mismatch: bound to sess-991",
    ],
)
def test_verify_normalizes_custom_store_error_strings(leak):
    # Failure surfaced at the pre-signature validate step.
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    res = verify_bundle(
        bundle, VerifyOptions(challenge_store=_LeakyStore(store, validate_result=leak))
    )
    assert not res.valid
    assert res.error_reason == UNKNOWN_REASON

    # Failure surfaced at the post-signature consume step.
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    res = verify_bundle(
        bundle, VerifyOptions(challenge_store=_LeakyStore(store, consume_result=leak))
    )
    assert not res.valid
    assert res.error_reason == UNKNOWN_REASON


def test_verify_store_exceptions_fail_closed_with_uniform_result():
    # validate raises.
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    res = verify_bundle(
        bundle,
        VerifyOptions(
            challenge_store=_LeakyStore(
                store, validate_result=ConnectionError("ECONNREFUSED 10.0.0.7:5432")
            )
        ),
    )
    assert not res.valid
    assert res.error_reason == UNKNOWN_REASON

    # consume raises — after signatures verified.
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    res = verify_bundle(
        bundle,
        VerifyOptions(
            challenge_store=_LeakyStore(
                store, consume_result=RuntimeError("deadlock detected on challenges_pkey")
            )
        ),
    )
    assert not res.valid
    assert res.error_reason == UNKNOWN_REASON


# ----- Policy evaluation happens after consumption -----

class _StubPolicy:
    def __init__(self, allow=False, err=None, exc=None):
        self._allow = allow
        self._err = err
        self._exc = exc

    def evaluate_policy(self, bundle, context):
        if self._exc is not None:
            raise self._exc
        return self._allow, self._err


def test_verify_with_store_policy_denied_still_consumes():
    bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
    denied = verify_bundle(
        bundle,
        VerifyOptions(
            required_scope=SCOPE_MEETING_ATTEND,
            challenge_store=store,
            policy=_StubPolicy(allow=False),
        ),
    )
    assert not denied.valid
    assert denied.identity_status == "scope_denied"

    # Policy denial happened AFTER consumption: retrying without the
    # policy gate still fails — the challenge is spent.
    retry = verify_bundle(
        bundle, VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store)
    )
    assert retry.error_reason == UNKNOWN_REASON


def test_verify_with_store_policy_error_still_consumes():
    for policy in (
        _StubPolicy(err="policy backend unreachable"),
        _StubPolicy(exc=ConnectionError("policy backend unreachable")),
    ):
        bundle, store = _store_bundle([SCOPE_MEETING_ATTEND])
        res = verify_bundle(
            bundle,
            VerifyOptions(
                required_scope=SCOPE_MEETING_ATTEND,
                challenge_store=store,
                policy=policy,
            ),
        )
        assert not res.valid
        assert res.error_reason.startswith("policy_error")

        # The provider error surfaced after the challenge was spent: replay
        # of the same presentation is still rejected.
        retry = verify_bundle(
            bundle,
            VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store),
        )
        assert retry.error_reason == UNKNOWN_REASON
