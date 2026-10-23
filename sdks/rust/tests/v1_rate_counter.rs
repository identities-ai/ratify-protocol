//! v1 `max_rate` (SPEC §5.6): the invocation counter is the only input that
//! can deny an otherwise valid bundle on rate grounds. A counter that cannot
//! answer (a negative count, for example a database error mapped to -1) must
//! fail closed, never read as "no invocations yet".

use ratify_protocol::*;

const NOW: i64 = 1_800_000_000;

fn rate_limited_bundle() -> ProofBundle {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("rate-agent", "custom").unwrap();
    let mut cert = DelegationCert {
        cert_id: "rate-cert".into(),
        version: 1,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope: vec!["meeting:attend".into()],
        constraints: vec![Constraint {
            kind: "max_rate".into(),
            count: 1,
            window_s: 60,
            ..Default::default()
        }],
        issued_at: NOW - 10,
        expires_at: NOW + 3600,
        signature: HybridSignature {
            ed25519: vec![],
            ml_dsa_65: vec![],
        },
    };
    issue_delegation(&mut cert, &root_priv).unwrap();
    let challenge = vec![7u8; 32];
    let challenge_sig = sign_challenge(&challenge, NOW, &agent_priv);
    ProofBundle {
        agent_id: agent.id,
        agent_pub_key: agent.public_key,
        delegations: vec![cert],
        challenge,
        challenge_at: NOW,
        challenge_sig,
        session_context: vec![],
        stream_id: vec![],
        stream_seq: 0,
    }
}

fn verify_with_count(count: i64) -> VerifyResult {
    let bundle = rate_limited_bundle();
    let opts = VerifyOptions {
        required_scope: "meeting:attend".into(),
        now: Some(NOW),
        context: VerifierContext {
            invocations_in_window: Some(Box::new(move |_: &str, _: i64| count)),
            ..Default::default()
        },
        ..Default::default()
    };
    verify_bundle(&bundle, &opts)
}

#[test]
fn rate_counter_below_limit_allows() {
    let r = verify_with_count(0);
    assert!(r.valid, "{}", r.error_reason);
}

#[test]
fn rate_counter_at_limit_denies() {
    let r = verify_with_count(1);
    assert!(!r.valid);
    assert_eq!(r.identity_status.as_str(), "constraint_denied");
}

#[test]
fn negative_rate_count_fails_closed_as_unverifiable() {
    for count in [-1, i64::MIN] {
        let r = verify_with_count(count);
        assert!(!r.valid, "count {count} must not allow");
        assert_eq!(
            r.identity_status.as_str(),
            "constraint_unverifiable",
            "count {count}: {}",
            r.error_reason
        );
    }
}
