// ChallengeStore tests — store semantics plus the locked consumption order
// in verify_bundle (SPEC §10): a challenge is consumed after the
// structural, chain, and challenge-signature checks pass and before
// authorization evaluation, so a forged presentation never spends a
// challenge and a cryptographically valid presentation spends it even when
// denied.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ratify_protocol::{
    generate_agent, generate_human_root, issue_delegation, sign_challenge, verify_bundle,
    ChallengeStore, Constraint, DelegationCert, HybridSignature, IdentityStatus,
    MemoryChallengeStore, ProofBundle, VerifierContext, VerifyOptions, PROTOCOL_VERSION,
    SCOPE_FILES_WRITE, SCOPE_MEETING_ATTEND, SCOPE_TRANSACT_PURCHASE, UNKNOWN_CHALLENGE,
};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn unknown_reason() -> String {
    format!("unknown_challenge: {UNKNOWN_CHALLENGE}")
}

// ----- Store semantics -----

#[test]
fn issue_then_consume() {
    let store = MemoryChallengeStore::new(16);
    let (challenge, expires_at) = store.issue(&[], 300).unwrap();
    assert_eq!(challenge.len(), 32);
    let until = expires_at - now();
    assert!((290..=310).contains(&until), "expiry {until}s out, want ~300");
    assert!(store.validate(&challenge, &[], now()).is_ok());
    assert!(store.consume(&challenge, &[], now()).is_ok());
}

#[test]
fn double_consume_fails() {
    let store = MemoryChallengeStore::new(16);
    let (challenge, _) = store.issue(&[], 300).unwrap();
    assert!(store.consume(&challenge, &[], now()).is_ok());
    assert_eq!(
        store.consume(&challenge, &[], now()).unwrap_err(),
        UNKNOWN_CHALLENGE
    );
    assert!(store.validate(&challenge, &[], now()).is_err());
}

#[test]
fn expiry() {
    let store = MemoryChallengeStore::new(16);
    let (challenge, _) = store.issue(&[], 300).unwrap();
    let later = now() + 360;
    assert!(store.validate(&challenge, &[], later).is_err());
    assert_eq!(
        store.consume(&challenge, &[], later).unwrap_err(),
        UNKNOWN_CHALLENGE
    );
}

#[test]
fn never_issued_challenge() {
    let store = MemoryChallengeStore::new(16);
    assert_eq!(
        store.consume(&[0u8; 32], &[], now()).unwrap_err(),
        UNKNOWN_CHALLENGE
    );
}

#[test]
fn wrong_session_context_does_not_consume() {
    let store = MemoryChallengeStore::new(16);
    let mut ctx = vec![0u8; 32];
    ctx[0] = 1;
    let (challenge, _) = store.issue(&ctx, 300).unwrap();

    let mut other = vec![0u8; 32];
    other[0] = 2;
    assert!(store.consume(&challenge, &other, now()).is_err());
    assert!(store.consume(&challenge, &[], now()).is_err());
    // The legitimate record survived both wrong-context presentations.
    assert!(store.consume(&challenge, &ctx, now()).is_ok());
}

#[test]
fn capacity_cap() {
    let store = MemoryChallengeStore::new(2);
    store.issue(&[], 60).unwrap();
    store.issue(&[], 60).unwrap();
    let err = store.issue(&[], 60).unwrap_err();
    assert!(err.contains("challenge store full"), "{err}");
}

#[test]
fn consume_frees_capacity_immediately() {
    // Capacity counts PENDING challenges: consuming one frees its slot, so
    // legitimate traffic cannot wedge issuance until records expire.
    let store = MemoryChallengeStore::new(2);
    let (challenge, _) = store.issue(&[], 300).unwrap();
    store.issue(&[], 300).unwrap();
    assert!(store.issue(&[], 300).is_err());
    store.consume(&challenge, &[], now()).unwrap();
    store.issue(&[], 300).unwrap(); // must succeed immediately
}

#[test]
fn wrong_session_context_does_not_free_capacity() {
    let store = MemoryChallengeStore::new(1);
    let mut ctx = vec![0u8; 32];
    ctx[0] = 1;
    let (challenge, _) = store.issue(&ctx, 300).unwrap();
    assert!(store.consume(&challenge, &[], now()).is_err());
    let err = store.issue(&[], 300).unwrap_err();
    assert!(err.contains("challenge store full"), "{err}");
}

#[test]
fn issue_validates_inputs() {
    let store = MemoryChallengeStore::new(16);
    let err = store.issue(&[0u8; 5], 300).unwrap_err();
    assert!(err.contains("session context"), "{err}");
    let err = store.issue(&[], 0).unwrap_err();
    assert!(err.contains("ttl"), "{err}");
    let err = store.issue(&[], -60).unwrap_err();
    assert!(err.contains("ttl"), "{err}");
    // 0 and 32 bytes are the two valid session-context lengths.
    store.issue(&[], 60).unwrap();
    store.issue(&[0u8; 32], 60).unwrap();
}

#[test]
#[should_panic(expected = "max_size must be >= 1")]
fn constructor_rejects_zero_capacity() {
    let _ = MemoryChallengeStore::new(0);
}

#[test]
fn concurrent_consume_is_atomic() {
    let store = Arc::new(MemoryChallengeStore::new(16));
    let (challenge, _) = store.issue(&[], 300).unwrap();
    let n = now();

    let mut handles = Vec::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        let challenge = challenge.clone();
        handles.push(std::thread::spawn(move || {
            store.consume(&challenge, &[], n).is_ok()
        }));
    }
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(successes, 1, "exactly one concurrent consume may succeed");
}

// ----- verify_bundle integration: the locked consumption order -----

fn store_bundle(
    scope: Vec<String>,
    constraints: Vec<Constraint>,
) -> (ProofBundle, MemoryChallengeStore) {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("Store Bot", "custom").unwrap();
    let n = now();
    let mut cert = DelegationCert {
        cert_id: "store-cert-001".to_string(),
        version: PROTOCOL_VERSION,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope,
        constraints,
        issued_at: n,
        expires_at: n + 86_400,
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    issue_delegation(&mut cert, &root_priv).unwrap();

    let store = MemoryChallengeStore::new(16);
    let (challenge, _) = store.issue(&[], 300).unwrap();
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
    (bundle, store)
}

fn opts_with_store<'a>(store: &'a MemoryChallengeStore, scope: &str) -> VerifyOptions<'a> {
    VerifyOptions {
        required_scope: scope.to_string(),
        challenge_store: Some(Box::new(store)),
        ..VerifyOptions::default()
    }
}

#[test]
fn verify_with_store_replay_is_rejected() {
    let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);

    let first = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert!(first.valid, "{}", first.error_reason);

    let replay = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert!(!replay.valid);
    assert_eq!(replay.error_reason, unknown_reason());
}

#[test]
fn verify_with_store_bad_signature_does_not_consume() {
    let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);

    let mut forged = bundle.clone();
    forged.challenge_sig.ed25519[0] ^= 0xFF;
    let res = verify_bundle(&forged, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert!(!res.valid);
    assert!(
        res.error_reason.starts_with("bad_challenge_sig"),
        "{}",
        res.error_reason
    );

    // The legitimate presentation still succeeds afterwards.
    let legit = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert!(legit.valid, "{}", legit.error_reason);
}

#[test]
fn verify_with_store_scope_denied_still_consumes() {
    let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);

    let denied = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_FILES_WRITE));
    assert!(!denied.valid);
    assert!(matches!(denied.identity_status, IdentityStatus::ScopeDenied));

    // Retrying with the correct scope fails: the challenge is spent.
    let retry = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert_eq!(retry.error_reason, unknown_reason());
}

#[test]
fn verify_with_store_constraint_denied_still_consumes() {
    let (bundle, store) = store_bundle(
        vec![SCOPE_TRANSACT_PURCHASE.to_string()],
        vec![Constraint {
            kind: "max_amount".to_string(),
            max_amount: 100.0,
            currency: "USD".to_string(),
            ..Constraint::default()
        }],
    );

    let denied_opts = VerifyOptions {
        required_scope: SCOPE_TRANSACT_PURCHASE.to_string(),
        challenge_store: Some(Box::new(&store)),
        context: VerifierContext {
            requested_amount: Some(500.0),
            requested_currency: Some("USD".to_string()),
            ..VerifierContext::default()
        },
        ..VerifyOptions::default()
    };
    let denied = verify_bundle(&bundle, &denied_opts);
    assert!(!denied.valid);
    assert!(matches!(denied.identity_status, IdentityStatus::ConstraintDenied));

    // Constraint denial happened AFTER consumption: the challenge is spent.
    let retry_opts = VerifyOptions {
        required_scope: SCOPE_TRANSACT_PURCHASE.to_string(),
        challenge_store: Some(Box::new(&store)),
        context: VerifierContext {
            requested_amount: Some(50.0),
            requested_currency: Some("USD".to_string()),
            ..VerifierContext::default()
        },
        ..VerifyOptions::default()
    };
    let retry = verify_bundle(&bundle, &retry_opts);
    assert_eq!(retry.error_reason, unknown_reason());
}

#[test]
fn verify_with_store_unknown_challenge_rejected_before_crypto() {
    let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);
    let other_store = MemoryChallengeStore::new(16);
    let res = verify_bundle(&bundle, &opts_with_store(&other_store, ""));
    assert_eq!(res.error_reason, unknown_reason());
    // The bundle's own store still holds the unconsumed record.
    assert!(store.validate(&bundle.challenge, &[], now()).is_ok());
}

// ----- Store-failure normalization: no custom-store text leaks -----

/// Adversarial custom ChallengeStore whose failures carry backend detail
/// that would distinguish record states. verify_bundle must normalize
/// every failure to the canonical unknown_challenge result.
struct LeakyStore<'a> {
    inner: &'a MemoryChallengeStore,
    validate_err: Option<String>,
    consume_err: Option<String>,
}

impl ChallengeStore for LeakyStore<'_> {
    fn issue(&self, session_context: &[u8], ttl_seconds: i64) -> Result<(Vec<u8>, i64), String> {
        self.inner.issue(session_context, ttl_seconds)
    }
    fn validate(&self, challenge: &[u8], session_context: &[u8], now: i64) -> Result<(), String> {
        match &self.validate_err {
            Some(err) => Err(err.clone()),
            None => self.inner.validate(challenge, session_context, now),
        }
    }
    fn consume(&self, challenge: &[u8], session_context: &[u8], now: i64) -> Result<(), String> {
        match &self.consume_err {
            Some(err) => Err(err.clone()),
            None => self.inner.consume(challenge, session_context, now),
        }
    }
}

#[test]
fn verify_normalizes_custom_store_errors() {
    let leaks = [
        "pg: relation \"challenges\" does not exist",
        "record expired 42s ago",
        "challenge already consumed by request 7f3a",
        "session binding mismatch: bound to sess-991",
    ];
    for leak in leaks {
        // Failure surfaced at the pre-signature validate step.
        let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);
        let leaky = LeakyStore {
            inner: &store,
            validate_err: Some(leak.to_string()),
            consume_err: None,
        };
        let opts = VerifyOptions {
            challenge_store: Some(Box::new(&leaky as &dyn ChallengeStore)),
            ..VerifyOptions::default()
        };
        let res = verify_bundle(&bundle, &opts);
        assert!(!res.valid);
        assert_eq!(res.error_reason, unknown_reason());

        // Failure surfaced at the post-signature consume step.
        let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);
        let leaky = LeakyStore {
            inner: &store,
            validate_err: None,
            consume_err: Some(leak.to_string()),
        };
        let opts = VerifyOptions {
            challenge_store: Some(Box::new(&leaky as &dyn ChallengeStore)),
            ..VerifyOptions::default()
        };
        let res = verify_bundle(&bundle, &opts);
        assert!(!res.valid);
        assert_eq!(res.error_reason, unknown_reason());
    }
}

// ----- Policy evaluation happens after consumption -----

struct StubPolicy {
    result: Result<bool, String>,
}

impl ratify_protocol::PolicyProvider for StubPolicy {
    fn evaluate_policy(
        &self,
        _bundle: &ProofBundle,
        _context: &VerifierContext,
    ) -> Result<bool, String> {
        self.result.clone()
    }
}

#[test]
fn verify_with_store_policy_denied_still_consumes() {
    let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);
    let opts = VerifyOptions {
        required_scope: SCOPE_MEETING_ATTEND.to_string(),
        challenge_store: Some(Box::new(&store)),
        policy: Some(Box::new(StubPolicy { result: Ok(false) })),
        ..VerifyOptions::default()
    };
    let denied = verify_bundle(&bundle, &opts);
    assert!(!denied.valid);
    assert!(matches!(denied.identity_status, IdentityStatus::ScopeDenied));

    // Policy denial happened AFTER consumption: retrying without the
    // policy gate still fails — the challenge is spent.
    let retry = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert_eq!(retry.error_reason, unknown_reason());
}

#[test]
fn verify_with_store_policy_error_still_consumes() {
    let (bundle, store) = store_bundle(vec![SCOPE_MEETING_ATTEND.to_string()], vec![]);
    let opts = VerifyOptions {
        required_scope: SCOPE_MEETING_ATTEND.to_string(),
        challenge_store: Some(Box::new(&store)),
        policy: Some(Box::new(StubPolicy {
            result: Err("policy backend unreachable".to_string()),
        })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert!(
        res.error_reason.starts_with("policy_error"),
        "{}",
        res.error_reason
    );

    // The provider error surfaced after the challenge was spent: replay of
    // the same presentation is still rejected.
    let retry = verify_bundle(&bundle, &opts_with_store(&store, SCOPE_MEETING_ATTEND));
    assert_eq!(retry.error_reason, unknown_reason());
}
