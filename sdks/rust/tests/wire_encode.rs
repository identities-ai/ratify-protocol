// Encoder side of the wire integer domain (SPEC §6.2): serialization of
// wire structures must never emit an integer that strict wire decoders
// reject. Positive cases sit exactly on the safe-integer bounds.

use ratify_protocol::{
    Constraint, DelegationCert, HybridPublicKey, HybridSignature, ProofBundle, SessionToken,
};

const MAX_SAFE: i64 = (1 << 53) - 1;

fn pubkey() -> HybridPublicKey {
    HybridPublicKey {
        ed25519: vec![0; 32],
        ml_dsa_65: vec![0; 1952],
    }
}

fn sig() -> HybridSignature {
    HybridSignature {
        ed25519: vec![0; 64],
        ml_dsa_65: vec![0; 3309],
    }
}

fn token(issued_at: i64, valid_until: i64) -> SessionToken {
    SessionToken {
        version: 1,
        session_id: "s".into(),
        agent_id: "a".into(),
        agent_pub_key: pubkey(),
        human_id: "h".into(),
        granted_scope: vec![],
        issued_at,
        valid_until,
        chain_hash: vec![0; 32],
        mac: vec![0; 32],
    }
}

fn cert(issued_at: i64, expires_at: i64, constraints: Vec<Constraint>) -> DelegationCert {
    DelegationCert {
        cert_id: "c".into(),
        version: 1,
        issuer_id: "i".into(),
        issuer_pub_key: pubkey(),
        subject_id: "s".into(),
        subject_pub_key: pubkey(),
        scope: vec!["meeting:attend".into()],
        constraints,
        issued_at,
        expires_at,
        signature: sig(),
    }
}

#[test]
fn session_token_serialization_bounds_timestamps() {
    assert!(serde_json::to_string(&token(MAX_SAFE, MAX_SAFE)).is_ok());
    assert!(serde_json::to_string(&token(-MAX_SAFE, 0)).is_ok());
    assert!(serde_json::to_string(&token(MAX_SAFE + 1, 0)).is_err());
    assert!(serde_json::to_string(&token(0, -(MAX_SAFE + 1))).is_err());
}

#[test]
fn delegation_cert_serialization_bounds_timestamps() {
    assert!(serde_json::to_string(&cert(-MAX_SAFE, MAX_SAFE, vec![])).is_ok());
    assert!(serde_json::to_string(&cert(0, MAX_SAFE + 1, vec![])).is_err());
    assert!(serde_json::to_string(&cert(-(MAX_SAFE + 1), 0, vec![])).is_err());
}

#[test]
fn max_rate_constraint_serialization_bounds_count_and_window() {
    let ok = Constraint {
        kind: "max_rate".into(),
        count: 5,
        window_s: MAX_SAFE,
        ..Default::default()
    };
    assert!(serde_json::to_string(&cert(0, 1, vec![ok])).is_ok());

    let bad_window = Constraint {
        kind: "max_rate".into(),
        count: 5,
        window_s: MAX_SAFE + 1,
        ..Default::default()
    };
    assert!(serde_json::to_string(&cert(0, 1, vec![bad_window])).is_err());

    let bad_count = Constraint {
        kind: "max_rate".into(),
        count: MAX_SAFE + 1,
        window_s: 300,
        ..Default::default()
    };
    assert!(serde_json::to_string(&cert(0, 1, vec![bad_count])).is_err());
}

#[test]
fn proof_bundle_serialization_bounds_challenge_at_and_stream_seq() {
    let mut bundle = ProofBundle {
        agent_id: "a".into(),
        agent_pub_key: pubkey(),
        delegations: vec![cert(0, 1, vec![])],
        challenge: vec![0; 32],
        challenge_at: MAX_SAFE,
        challenge_sig: sig(),
        session_context: vec![],
        stream_id: vec![0; 32],
        stream_seq: MAX_SAFE,
    };
    assert!(serde_json::to_string(&bundle).is_ok());
    bundle.challenge_at = MAX_SAFE + 1;
    assert!(serde_json::to_string(&bundle).is_err());
    bundle.challenge_at = 0;
    bundle.stream_seq = MAX_SAFE + 1;
    assert!(serde_json::to_string(&bundle).is_err());
}
