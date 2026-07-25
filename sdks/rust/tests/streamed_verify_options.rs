// verify_streamed_turn_with_options tests — the options-object streamed
// fast path (SPEC §5.13): required_scope against token.granted_scope,
// single-use challenges with the §10 consumption order, and verifier-side
// session and stream binding checks.

use std::time::{SystemTime, UNIX_EPOCH};

use ratify_protocol::{
    generate_agent, generate_challenge, generate_human_root, issue_delegation,
    issue_session_token, sign_challenge, sign_challenge_with_session_context,
    sign_challenge_with_stream, verify_bundle, verify_streamed_turn_with_options, ChallengeStore,
    DelegationCert, HybridPrivateKey, HybridSignature, IdentityStatus, MemoryChallengeStore,
    ProofBundle, SessionToken, StreamContext, StreamedTurn, VerifyOptions, PROTOCOL_VERSION,
    SCOPE_FILES_READ, SCOPE_FILES_WRITE, SCOPE_MEETING_ATTEND, UNKNOWN_CHALLENGE,
};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn unknown_reason() -> String {
    format!("unknown_challenge: {UNKNOWN_CHALLENGE}")
}

struct Fixture {
    token: SessionToken,
    secret: Vec<u8>,
    agent_priv: HybridPrivateKey,
    now: i64,
}

fn fixture(scope: Vec<String>) -> Fixture {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("Turn Bot", "custom");
    let n = now_unix();
    let mut cert = DelegationCert {
        cert_id: "turn-cert-001".to_string(),
        version: PROTOCOL_VERSION,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope,
        constraints: vec![],
        issued_at: n,
        expires_at: n + 86_400,
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    issue_delegation(&mut cert, &root_priv);
    let challenge = generate_challenge();
    let sig = sign_challenge(&challenge, n, &agent_priv);
    let bundle = ProofBundle {
        agent_id: agent.id.clone(),
        agent_pub_key: agent.public_key.clone(),
        delegations: vec![cert],
        challenge,
        challenge_at: n,
        challenge_sig: sig,
        session_context: Vec::new(),
        stream_id: Vec::new(),
        stream_seq: 0,
    };
    let res = verify_bundle(
        &bundle,
        &VerifyOptions {
            now: Some(n),
            ..VerifyOptions::default()
        },
    );
    assert!(res.valid, "{}", res.error_reason);
    let secret = vec![0x42u8; 32];
    let token = issue_session_token(&bundle, &res, "session-turn", n, n + 1800, &secret)
        .expect("issue_session_token");
    Fixture {
        token,
        secret,
        agent_priv,
        now: n,
    }
}

fn turn_for(
    f: &Fixture,
    challenge: Vec<u8>,
    session_context: Vec<u8>,
    stream_id: Vec<u8>,
    stream_seq: i64,
) -> StreamedTurn {
    let sig = if !stream_id.is_empty() {
        sign_challenge_with_stream(
            &challenge,
            f.now,
            &session_context,
            &stream_id,
            stream_seq,
            &f.agent_priv,
        )
    } else if !session_context.is_empty() {
        sign_challenge_with_session_context(&challenge, f.now, &session_context, &f.agent_priv)
    } else {
        sign_challenge(&challenge, f.now, &f.agent_priv)
    };
    StreamedTurn {
        challenge,
        challenge_at: f.now,
        challenge_sig: sig,
        session_context,
        stream_id,
        stream_seq,
    }
}

fn opts_now(f: &Fixture) -> VerifyOptions<'static> {
    VerifyOptions {
        now: Some(f.now),
        ..VerifyOptions::default()
    }
}

#[test]
fn required_scope_allowed_and_denied() {
    let f = fixture(vec![
        SCOPE_MEETING_ATTEND.to_string(),
        SCOPE_FILES_READ.to_string(),
    ]);
    let turn = turn_for(&f, generate_challenge(), vec![], vec![], 0);

    let mut opts = opts_now(&f);
    opts.required_scope = SCOPE_MEETING_ATTEND.to_string();
    let ok = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(ok.valid, "{}", ok.error_reason);

    opts.required_scope = SCOPE_FILES_WRITE.to_string();
    let denied = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(!denied.valid);
    assert!(matches!(denied.identity_status, IdentityStatus::ScopeDenied));
}

#[test]
fn single_use_replay_is_rejected() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let store = MemoryChallengeStore::new(16);
    let (challenge, _) = store.issue(&[], 300).unwrap();
    let turn = turn_for(&f, challenge, vec![], vec![], 0);

    let mut opts = opts_now(&f);
    opts.required_scope = SCOPE_MEETING_ATTEND.to_string();
    opts.challenge_store = Some(Box::new(&store));
    let first = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(first.valid, "{}", first.error_reason);

    let replay = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(!replay.valid);
    assert_eq!(replay.error_reason, unknown_reason());
}

#[test]
fn forged_signature_does_not_consume() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let store = MemoryChallengeStore::new(16);
    let (challenge, _) = store.issue(&[], 300).unwrap();
    let turn = turn_for(&f, challenge, vec![], vec![], 0);

    let mut forged = turn.clone();
    forged.challenge_sig.ed25519[0] ^= 0xFF;
    let mut opts = opts_now(&f);
    opts.challenge_store = Some(Box::new(&store));
    let res = verify_streamed_turn_with_options(&f.token, &f.secret, &forged, &opts);
    assert!(!res.valid);
    assert!(
        res.error_reason.starts_with("bad_challenge_sig"),
        "{}",
        res.error_reason
    );

    let legit = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(legit.valid, "{}", legit.error_reason);
}

#[test]
fn scope_denial_still_consumes() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let store = MemoryChallengeStore::new(16);
    let (challenge, _) = store.issue(&[], 300).unwrap();
    let turn = turn_for(&f, challenge, vec![], vec![], 0);

    let mut opts = opts_now(&f);
    opts.required_scope = SCOPE_FILES_WRITE.to_string();
    opts.challenge_store = Some(Box::new(&store));
    let denied = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(matches!(denied.identity_status, IdentityStatus::ScopeDenied));

    // The denial happened AFTER consumption: the challenge is spent.
    let mut retry_opts = opts_now(&f);
    retry_opts.required_scope = SCOPE_MEETING_ATTEND.to_string();
    retry_opts.challenge_store = Some(Box::new(&store));
    let retry = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &retry_opts);
    assert_eq!(retry.error_reason, unknown_reason());
}

#[test]
fn unknown_challenge_rejected_before_crypto() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let store = MemoryChallengeStore::new(16);
    let turn = turn_for(&f, generate_challenge(), vec![], vec![], 0);
    let mut opts = opts_now(&f);
    opts.challenge_store = Some(Box::new(&store));
    let res = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert_eq!(res.error_reason, unknown_reason());
}

#[test]
fn session_binding_checks() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let mut ctx = vec![0u8; 32];
    ctx[0] = 7;
    let turn = turn_for(&f, generate_challenge(), ctx.clone(), vec![], 0);

    let mut opts = opts_now(&f);
    opts.session_context = ctx.clone();
    let ok = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(ok.valid, "{}", ok.error_reason);

    let mut other = vec![0u8; 32];
    other[0] = 8;
    opts.session_context = other;
    let mismatch = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(
        mismatch.error_reason.starts_with("session_context_mismatch"),
        "{}",
        mismatch.error_reason
    );

    let unverifiable =
        verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts_now(&f));
    assert!(
        unverifiable
            .error_reason
            .starts_with("session_context_unverifiable"),
        "{}",
        unverifiable.error_reason
    );

    let unbound = turn_for(&f, generate_challenge(), vec![], vec![], 0);
    let mut expect_ctx = opts_now(&f);
    expect_ctx.session_context = ctx;
    let missing = verify_streamed_turn_with_options(&f.token, &f.secret, &unbound, &expect_ctx);
    assert!(
        missing.error_reason.starts_with("missing_session_context"),
        "{}",
        missing.error_reason
    );
}

#[test]
fn stream_tracking_replay_and_skip() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let mut stream_id = vec![0u8; 32];
    stream_id[0] = 3;
    let turn = turn_for(&f, generate_challenge(), vec![], stream_id.clone(), 4);

    let mut opts = opts_now(&f);
    opts.stream = Some(StreamContext {
        stream_id: stream_id.clone(),
        last_seen_seq: 3,
    });
    let ok = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(ok.valid, "{}", ok.error_reason);

    opts.stream = Some(StreamContext {
        stream_id: stream_id.clone(),
        last_seen_seq: 4,
    });
    let replay = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(
        replay.error_reason.starts_with("stream_seq_replay"),
        "{}",
        replay.error_reason
    );

    opts.stream = Some(StreamContext {
        stream_id,
        last_seen_seq: 1,
    });
    let skip = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts);
    assert!(
        skip.error_reason.starts_with("stream_seq_skip"),
        "{}",
        skip.error_reason
    );

    let unverifiable =
        verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &opts_now(&f));
    assert!(
        unverifiable
            .error_reason
            .starts_with("stream_context_unverifiable"),
        "{}",
        unverifiable.error_reason
    );
}

#[test]
fn token_checks_still_apply() {
    let f = fixture(vec![SCOPE_MEETING_ATTEND.to_string()]);
    let turn = turn_for(&f, generate_challenge(), vec![], vec![], 0);

    let bad_secret =
        verify_streamed_turn_with_options(&f.token, &[0x99u8; 32], &turn, &opts_now(&f));
    assert!(
        bad_secret.error_reason.starts_with("session_token_invalid"),
        "{}",
        bad_secret.error_reason
    );

    let mut expired_opts = opts_now(&f);
    expired_opts.now = Some(f.now + 31 * 60);
    let expired = verify_streamed_turn_with_options(&f.token, &f.secret, &turn, &expired_opts);
    assert!(
        expired.error_reason.starts_with("session_token_invalid"),
        "{}",
        expired.error_reason
    );
}
