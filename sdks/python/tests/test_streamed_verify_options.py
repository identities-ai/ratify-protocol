"""verify_streamed_turn_with_options tests — the options-object streamed
fast path (SPEC §5.13): required_scope against token.granted_scope,
single-use challenges with the §10 consumption order, and verifier-side
session and stream binding checks."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ratify_protocol import (
    PROTOCOL_VERSION,
    SCOPE_FILES_READ,
    SCOPE_FILES_WRITE,
    SCOPE_MEETING_ATTEND,
    UNKNOWN_CHALLENGE,
    DelegationCert,
    HybridPrivateKey,
    HybridSignature,
    MemoryChallengeStore,
    ProofBundle,
    SessionToken,
    StreamContext,
    StreamedTurn,
    VerifyOptions,
    generate_agent,
    generate_challenge,
    generate_human_root,
    issue_delegation,
    issue_session_token,
    sign_challenge,
    verify_bundle,
    verify_streamed_turn_with_options,
)

UNKNOWN_REASON = f"unknown_challenge: {UNKNOWN_CHALLENGE}"


@dataclass
class _Fixture:
    token: SessionToken
    secret: bytes
    agent_priv: HybridPrivateKey
    now: int


def _fixture(scope) -> _Fixture:
    root, root_priv = generate_human_root()
    agent, agent_priv = generate_agent("Turn Bot", "custom")
    now = int(time.time())
    cert = DelegationCert(
        cert_id="turn-cert-001",
        version=PROTOCOL_VERSION,
        issuer_id=root.id,
        issuer_pub_key=root.public_key,
        subject_id=agent.id,
        subject_pub_key=agent.public_key,
        scope=scope,
        constraints=[],
        issued_at=now,
        expires_at=now + 86400,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
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
    res = verify_bundle(bundle, VerifyOptions(now=now))
    assert res.valid, res.error_reason
    secret = b"\x42" * 32
    token = issue_session_token(bundle, res, "session-turn", now, now + 1800, secret)
    return _Fixture(token=token, secret=secret, agent_priv=agent_priv, now=now)


def _turn(f: _Fixture, challenge: bytes, session_context: bytes = b"",
          stream_id: bytes = b"", stream_seq: int = 0) -> StreamedTurn:
    sig = sign_challenge(challenge, f.now, f.agent_priv, session_context, stream_id, stream_seq)
    return StreamedTurn(
        challenge=challenge,
        challenge_at=f.now,
        challenge_sig=sig,
        session_context=session_context,
        stream_id=stream_id,
        stream_seq=stream_seq,
    )


def test_required_scope_allowed_and_denied():
    f = _fixture([SCOPE_MEETING_ATTEND, SCOPE_FILES_READ])
    turn = _turn(f, generate_challenge())

    ok = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, now=f.now)
    )
    assert ok.valid, ok.error_reason

    denied = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(required_scope=SCOPE_FILES_WRITE, now=f.now)
    )
    assert not denied.valid
    assert denied.identity_status == "scope_denied"


def test_single_use_replay_is_rejected():
    f = _fixture([SCOPE_MEETING_ATTEND])
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    turn = _turn(f, challenge)
    opts = VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store, now=f.now)

    first = verify_streamed_turn_with_options(f.token, f.secret, turn, opts)
    assert first.valid, first.error_reason

    replay = verify_streamed_turn_with_options(f.token, f.secret, turn, opts)
    assert not replay.valid
    assert replay.error_reason == UNKNOWN_REASON


def test_forged_signature_does_not_consume():
    f = _fixture([SCOPE_MEETING_ATTEND])
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    turn = _turn(f, challenge)
    opts = VerifyOptions(challenge_store=store, now=f.now)

    forged_ed = bytearray(turn.challenge_sig.ed25519)
    forged_ed[0] ^= 0xFF
    forged = StreamedTurn(
        challenge=turn.challenge,
        challenge_at=turn.challenge_at,
        challenge_sig=HybridSignature(
            ed25519=bytes(forged_ed), ml_dsa_65=turn.challenge_sig.ml_dsa_65
        ),
    )
    res = verify_streamed_turn_with_options(f.token, f.secret, forged, opts)
    assert not res.valid
    assert res.error_reason.startswith("bad_challenge_sig")

    legit = verify_streamed_turn_with_options(f.token, f.secret, turn, opts)
    assert legit.valid, legit.error_reason


def test_scope_denial_still_consumes():
    f = _fixture([SCOPE_MEETING_ATTEND])
    store = MemoryChallengeStore(max_size=16)
    challenge, _ = store.issue(b"", 300)
    turn = _turn(f, challenge)

    denied = verify_streamed_turn_with_options(
        f.token, f.secret, turn,
        VerifyOptions(required_scope=SCOPE_FILES_WRITE, challenge_store=store, now=f.now),
    )
    assert denied.identity_status == "scope_denied"

    # The denial happened AFTER consumption: the challenge is spent.
    retry = verify_streamed_turn_with_options(
        f.token, f.secret, turn,
        VerifyOptions(required_scope=SCOPE_MEETING_ATTEND, challenge_store=store, now=f.now),
    )
    assert retry.error_reason == UNKNOWN_REASON


def test_unknown_challenge_rejected_before_crypto():
    f = _fixture([SCOPE_MEETING_ATTEND])
    store = MemoryChallengeStore(max_size=16)
    turn = _turn(f, generate_challenge())
    res = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(challenge_store=store, now=f.now)
    )
    assert res.error_reason == UNKNOWN_REASON


def test_session_binding_checks():
    f = _fixture([SCOPE_MEETING_ATTEND])
    ctx = b"\x07" + b"\x00" * 31
    turn = _turn(f, generate_challenge(), session_context=ctx)

    ok = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(session_context=ctx, now=f.now)
    )
    assert ok.valid, ok.error_reason

    other = b"\x08" + b"\x00" * 31
    mismatch = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(session_context=other, now=f.now)
    )
    assert mismatch.error_reason.startswith("session_context_mismatch")

    unverifiable = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(now=f.now)
    )
    assert unverifiable.error_reason.startswith("session_context_unverifiable")

    unbound = _turn(f, generate_challenge())
    missing = verify_streamed_turn_with_options(
        f.token, f.secret, unbound, VerifyOptions(session_context=ctx, now=f.now)
    )
    assert missing.error_reason.startswith("missing_session_context")


def test_stream_tracking_replay_and_skip():
    f = _fixture([SCOPE_MEETING_ATTEND])
    stream_id = b"\x03" + b"\x00" * 31
    turn = _turn(f, generate_challenge(), stream_id=stream_id, stream_seq=4)

    ok = verify_streamed_turn_with_options(
        f.token, f.secret, turn,
        VerifyOptions(stream=StreamContext(stream_id=stream_id, last_seen_seq=3), now=f.now),
    )
    assert ok.valid, ok.error_reason

    replay = verify_streamed_turn_with_options(
        f.token, f.secret, turn,
        VerifyOptions(stream=StreamContext(stream_id=stream_id, last_seen_seq=4), now=f.now),
    )
    assert replay.error_reason.startswith("stream_seq_replay")

    skip = verify_streamed_turn_with_options(
        f.token, f.secret, turn,
        VerifyOptions(stream=StreamContext(stream_id=stream_id, last_seen_seq=1), now=f.now),
    )
    assert skip.error_reason.startswith("stream_seq_skip")

    unverifiable = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(now=f.now)
    )
    assert unverifiable.error_reason.startswith("stream_context_unverifiable")


def test_token_checks_still_apply():
    f = _fixture([SCOPE_MEETING_ATTEND])
    turn = _turn(f, generate_challenge())

    bad_secret = verify_streamed_turn_with_options(
        f.token, b"\x99" * 32, turn, VerifyOptions(now=f.now)
    )
    assert bad_secret.error_reason.startswith("session_token_invalid")

    expired = verify_streamed_turn_with_options(
        f.token, f.secret, turn, VerifyOptions(now=f.now + 31 * 60)
    )
    assert expired.error_reason.startswith("session_token_invalid")
