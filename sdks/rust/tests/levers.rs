//! Tests for the SPEC §17.5–§17.8 levers introduced in alpha.7.
//! Requires the `std` feature (uses generate_human_root / generate_agent).
#![cfg(feature = "std")]

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use ratify_protocol::{
    bundle_hash, generate_agent, generate_challenge, generate_human_root, issue_delegation,
    issue_policy_verdict, issue_verification_receipt, receipt_hash, sign_challenge,
    verifier_context_hash, verify_bundle, verify_policy_verdict, verify_verification_receipt,
    Anchor, AnchorResolver, Constraint, ConstraintEvaluator, DelegationCert, HybridSignature,
    IdentityStatus, PolicyProvider, ProofBundle, RevocationProvider, VerifierContext,
    VerifyOptions, VerifyResult, PROTOCOL_VERSION, SCOPE_MEETING_ATTEND,
};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn good_bundle() -> (ProofBundle, String, String) {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("L Bot", "custom");
    let n = now();
    let mut cert = DelegationCert {
        cert_id: "lever-cert".into(),
        version: PROTOCOL_VERSION,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope: vec![SCOPE_MEETING_ATTEND.to_string()],
        constraints: Vec::new(),
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
        delegations: vec![cert.clone()],
        challenge,
        challenge_at: n,
        challenge_sig: sig,
        session_context: Vec::new(),
        stream_id: Vec::new(),
        stream_seq: 0,
    };
    (bundle, cert.cert_id, root.id)
}

// ---------------------------------------------------------------------------
// Lever 1: VerificationReceipt
// ---------------------------------------------------------------------------

#[test]
fn verification_receipt_roundtrip() {
    let (bundle, _, _) = good_bundle();
    let (v, v_priv) = generate_agent("v", "verifier");
    let result = verify_bundle(&bundle, &VerifyOptions::default());
    let r = issue_verification_receipt(
        &bundle, &result, &v.id, &v.public_key, &v_priv, None, now(),
    )
    .expect("issue");
    assert!(verify_verification_receipt(&r).is_ok());
    assert_eq!(r.decision, "authorized_agent");
}

#[test]
fn verification_receipt_detects_tampering() {
    let (bundle, _, _) = good_bundle();
    let (v, v_priv) = generate_agent("v", "verifier");
    let result = verify_bundle(&bundle, &VerifyOptions::default());
    let mut r = issue_verification_receipt(
        &bundle, &result, &v.id, &v.public_key, &v_priv, None, now(),
    )
    .unwrap();
    r.decision = "revoked".into();
    assert!(verify_verification_receipt(&r).is_err());
}

#[test]
fn verification_receipt_detects_bundle_substitution() {
    let (b1, _, _) = good_bundle();
    let (b2, _, _) = good_bundle();
    let (v, v_priv) = generate_agent("v", "verifier");
    let result = verify_bundle(&b1, &VerifyOptions::default());
    let mut r = issue_verification_receipt(
        &b1, &result, &v.id, &v.public_key, &v_priv, None, now(),
    )
    .unwrap();
    r.bundle_hash = bundle_hash(&b2).unwrap();
    assert!(verify_verification_receipt(&r).is_err());
}

#[test]
fn verification_receipt_chain_linkage() {
    let (bundle, _, _) = good_bundle();
    let (v, v_priv) = generate_agent("v", "verifier");
    let result = verify_bundle(&bundle, &VerifyOptions::default());
    let r1 = issue_verification_receipt(
        &bundle, &result, &v.id, &v.public_key, &v_priv, None, now(),
    )
    .unwrap();
    let prev = receipt_hash(&r1).unwrap();
    let r2 = issue_verification_receipt(
        &bundle, &result, &v.id, &v.public_key, &v_priv, Some(&prev), now(),
    )
    .unwrap();
    assert_eq!(r2.prev_hash, prev);
    // Tampering r1 changes its hash → chain pointer breaks.
    let mut r1_t = r1.clone();
    r1_t.decision = "tampered".into();
    let prev_after = receipt_hash(&r1_t).unwrap();
    assert_ne!(prev, prev_after);
}

#[test]
fn bundle_hash_deterministic() {
    let (bundle, _, _) = good_bundle();
    let a = bundle_hash(&bundle).unwrap();
    let b = bundle_hash(&bundle).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);
}

// ---------------------------------------------------------------------------
// Lever 2: PolicyVerdict
// ---------------------------------------------------------------------------

const SECRET: [u8; 32] = [0x33; 32];

#[test]
fn policy_verdict_roundtrip() {
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let v = issue_policy_verdict("vid", "a", "meeting:attend", true, &ctx, n, n + 3600, &SECRET)
        .unwrap();
    assert!(verify_policy_verdict(&v, &SECRET, "a", "meeting:attend", &ctx, n).is_ok());
}

#[test]
fn policy_verdict_deny_returns_policy_verdict_denied() {
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let v = issue_policy_verdict("v", "a", "s", false, &ctx, n, n + 3600, &SECRET).unwrap();
    let err = verify_policy_verdict(&v, &SECRET, "a", "s", &ctx, n).unwrap_err();
    assert!(err.starts_with("policy_verdict_denied"));
}

#[test]
fn policy_verdict_wrong_secret_rejected() {
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let v = issue_policy_verdict("v", "a", "s", true, &ctx, n, n + 3600, &SECRET).unwrap();
    let wrong = [0x44u8; 32];
    assert!(verify_policy_verdict(&v, &wrong, "a", "s", &ctx, n).is_err());
}

#[test]
fn policy_verdict_context_hash_mismatch() {
    let n = now();
    let mut ctx_a = VerifierContext::default();
    ctx_a.current_lat = Some(37.0);
    ctx_a.current_lon = Some(-122.0);
    let mut ctx_b = VerifierContext::default();
    ctx_b.current_lat = Some(51.5);
    ctx_b.current_lon = Some(-0.1);
    let hash_a = verifier_context_hash(&ctx_a).unwrap();
    let hash_b = verifier_context_hash(&ctx_b).unwrap();
    let v = issue_policy_verdict("v", "a", "s", true, &hash_a, n, n + 3600, &SECRET).unwrap();
    assert!(verify_policy_verdict(&v, &SECRET, "a", "s", &hash_b, n).is_err());
}

#[test]
fn policy_verdict_expired() {
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let v = issue_policy_verdict("v", "a", "s", true, &ctx, n - 7200, n - 3600, &SECRET).unwrap();
    assert!(verify_policy_verdict(&v, &SECRET, "a", "s", &ctx, n).is_err());
}

struct CountingPolicy {
    allow: bool,
    calls: Arc<Mutex<usize>>,
}
impl PolicyProvider for CountingPolicy {
    fn evaluate_policy(&self, _: &ProofBundle, _: &VerifierContext) -> Result<bool, String> {
        *self.calls.lock().unwrap() += 1;
        Ok(self.allow)
    }
}

#[test]
fn policy_verdict_fast_path_skips_live_policy() {
    let (bundle, _, _) = good_bundle();
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let v = issue_policy_verdict(
        "vid",
        &bundle.agent_id,
        "meeting:attend",
        true,
        &ctx,
        n - 60,
        n + 3600,
        &SECRET,
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(0));
    let opts = VerifyOptions {
        required_scope: "meeting:attend".into(),
        policy: Some(Box::new(CountingPolicy {
            allow: false,
            calls: calls.clone(),
        })),
        policy_verdict: Some(v),
        policy_secret: Some(SECRET.to_vec()),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[test]
fn policy_verdict_cached_deny() {
    let (bundle, _, _) = good_bundle();
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let v = issue_policy_verdict(
        "vid",
        &bundle.agent_id,
        "meeting:attend",
        false,
        &ctx,
        n - 60,
        n + 3600,
        &SECRET,
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(0));
    let opts = VerifyOptions {
        required_scope: "meeting:attend".into(),
        policy: Some(Box::new(CountingPolicy {
            allow: true,
            calls: calls.clone(),
        })),
        policy_verdict: Some(v),
        policy_secret: Some(SECRET.to_vec()),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert_eq!(res.identity_status, IdentityStatus::ScopeDenied);
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[test]
fn policy_verdict_falls_back_when_stale() {
    let (bundle, _, _) = good_bundle();
    let n = now();
    let ctx = verifier_context_hash(&VerifierContext::default()).unwrap();
    let expired = issue_policy_verdict(
        "vid",
        &bundle.agent_id,
        "meeting:attend",
        true,
        &ctx,
        n - 7200,
        n - 3600,
        &SECRET,
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(0));
    let opts = VerifyOptions {
        required_scope: "meeting:attend".into(),
        policy: Some(Box::new(CountingPolicy {
            allow: true,
            calls: calls.clone(),
        })),
        policy_verdict: Some(expired),
        policy_secret: Some(SECRET.to_vec()),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
    assert_eq!(*calls.lock().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// Lever 3: ConstraintEvaluator
// ---------------------------------------------------------------------------

fn bundle_with_custom_constraint(kind: &str) -> ProofBundle {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("C", "custom");
    let n = now();
    let mut cert = DelegationCert {
        cert_id: "cc".into(),
        version: PROTOCOL_VERSION,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope: vec![SCOPE_MEETING_ATTEND.to_string()],
        constraints: vec![Constraint {
            kind: kind.into(),
            ..Default::default()
        }],
        issued_at: n,
        expires_at: n + 3600,
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    issue_delegation(&mut cert, &root_priv);
    let challenge = generate_challenge();
    let sig = sign_challenge(&challenge, n, &agent_priv);
    ProofBundle {
        agent_id: agent.id,
        agent_pub_key: agent.public_key,
        delegations: vec![cert],
        challenge,
        challenge_at: n,
        challenge_sig: sig,
        session_context: Vec::new(),
        stream_id: Vec::new(),
        stream_seq: 0,
    }
}

struct AllowEval;
impl ConstraintEvaluator for AllowEval {
    fn evaluate(&self, _: &Constraint, _: &str, _: &VerifierContext, _: i64) -> Result<(), String> {
        Ok(())
    }
}

struct DenyEval;
impl ConstraintEvaluator for DenyEval {
    fn evaluate(&self, _: &Constraint, _: &str, _: &VerifierContext, _: i64) -> Result<(), String> {
        Err("too many".into())
    }
}

struct UnverifiableEval;
impl ConstraintEvaluator for UnverifiableEval {
    fn evaluate(&self, _: &Constraint, _: &str, _: &VerifierContext, _: i64) -> Result<(), String> {
        Err("constraint_unverifiable: missing".into())
    }
}

#[test]
fn constraint_evaluator_unknown_fails_closed() {
    let bundle = bundle_with_custom_constraint("verify.max_concurrent_sessions");
    let res = verify_bundle(&bundle, &VerifyOptions::default());
    assert!(!res.valid);
    assert_eq!(res.identity_status, IdentityStatus::ConstraintUnknown);
}

#[test]
fn constraint_evaluator_registry_allow() {
    let bundle = bundle_with_custom_constraint("verify.max_concurrent_sessions");
    let mut evs: BTreeMap<String, Box<dyn ConstraintEvaluator>> = BTreeMap::new();
    evs.insert("verify.max_concurrent_sessions".into(), Box::new(AllowEval));
    let opts = VerifyOptions {
        constraint_evaluators: Some(evs),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
}

#[test]
fn constraint_evaluator_registry_deny() {
    let bundle = bundle_with_custom_constraint("verify.max_concurrent_sessions");
    let mut evs: BTreeMap<String, Box<dyn ConstraintEvaluator>> = BTreeMap::new();
    evs.insert("verify.max_concurrent_sessions".into(), Box::new(DenyEval));
    let opts = VerifyOptions {
        constraint_evaluators: Some(evs),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert_eq!(res.identity_status, IdentityStatus::ConstraintDenied);
}

#[test]
fn constraint_evaluator_unverifiable_routes() {
    let bundle = bundle_with_custom_constraint("verify.needs_context");
    let mut evs: BTreeMap<String, Box<dyn ConstraintEvaluator>> = BTreeMap::new();
    evs.insert("verify.needs_context".into(), Box::new(UnverifiableEval));
    let opts = VerifyOptions {
        constraint_evaluators: Some(evs),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert_eq!(res.identity_status, IdentityStatus::ConstraintUnverifiable);
}

// ---------------------------------------------------------------------------
// Lever 4: AnchorResolver
// ---------------------------------------------------------------------------

struct StaticAnchor {
    map: HashMap<String, Anchor>,
    err: Option<String>,
}
impl AnchorResolver for StaticAnchor {
    fn resolve_anchor(&self, human_id: &str) -> Result<Option<Anchor>, String> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        Ok(self.map.get(human_id).cloned())
    }
}

#[test]
fn anchor_resolver_populates_result() {
    let (bundle, _, human_id) = good_bundle();
    let mut map = HashMap::new();
    map.insert(
        human_id.clone(),
        Anchor {
            anchor_type: "enterprise_sso".into(),
            provider: "okta".into(),
            reference: "opaque".into(),
            verified_at: 1000,
        },
    );
    let opts = VerifyOptions {
        anchor_resolver: Some(Box::new(StaticAnchor { map, err: None })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
    let anchor = res.anchor.expect("anchor populated");
    assert_eq!(anchor.provider, "okta");
}

#[test]
fn anchor_resolver_error_is_non_fatal() {
    let (bundle, _, _) = good_bundle();
    let opts = VerifyOptions {
        anchor_resolver: Some(Box::new(StaticAnchor {
            map: HashMap::new(),
            err: Some("dir down".into()),
        })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
    assert!(res.anchor.is_none());
}

struct CaptureAudit {
    logs: Arc<Mutex<Vec<VerifyResult>>>,
}
impl ratify_protocol::AuditProvider for CaptureAudit {
    fn log_verification(&self, r: &VerifyResult, _: &ProofBundle) {
        self.logs.lock().unwrap().push(r.clone());
    }
}

#[test]
fn audit_observes_anchor() {
    let (bundle, _, human_id) = good_bundle();
    let mut map = HashMap::new();
    map.insert(
        human_id.clone(),
        Anchor {
            anchor_type: "email".into(),
            provider: "google".into(),
            reference: "h:abc".into(),
            verified_at: 100,
        },
    );
    let logs = Arc::new(Mutex::new(Vec::new()));
    let opts = VerifyOptions {
        anchor_resolver: Some(Box::new(StaticAnchor { map, err: None })),
        audit: Some(Box::new(CaptureAudit { logs: logs.clone() })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid);
    let logs = logs.lock().unwrap();
    assert_eq!(logs.len(), 1);
    let a = logs[0].anchor.as_ref().expect("anchor captured");
    assert_eq!(a.provider, "google");
}

// Cross-SDK byte equivalence is covered by tests/cross_sdk.rs which loads
// the canonical fixture file testvectors/v1/cross_sdk_vectors.json.

// Silence unused-import warnings.
#[allow(dead_code)]
fn _silence() {
    let _ = Cell::new(0u8);
    let _: Option<Box<dyn RevocationProvider>> = None;
}
