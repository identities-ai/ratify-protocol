//! Tests for the Provider interfaces defined in SPEC §17.
//!
//! Each test builds a known-good single-cert ProofBundle as the fixture, then
//! configures one provider hook at a time and asserts the verifier's behaviour
//! matches the spec. The fixture is a freshly minted bundle — running
//! `verify_bundle` against it with default options MUST return `valid=true`.

use std::cell::Cell;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ratify_protocol::{
    generate_agent, generate_challenge, generate_human_root, issue_delegation, sign_challenge,
    verify_bundle, AuditProvider, DelegationCert, HybridSignature, IdentityStatus, PolicyProvider,
    ProofBundle, RevocationProvider, VerifierContext, VerifyOptions, VerifyResult,
    PROTOCOL_VERSION, SCOPE_MEETING_ATTEND,
};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Build a known-good (bundle, cert_id) fixture.
fn good_bundle() -> (ProofBundle, String) {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("Provider Bot", "custom");
    let n = now();
    let mut cert = DelegationCert {
        cert_id: "provider-cert-001".to_string(),
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
    (bundle, cert.cert_id)
}

// ---------------------------------------------------------------------------
// RevocationProvider — SPEC §17.1
// ---------------------------------------------------------------------------

struct FakeRevocation {
    revoked: Vec<String>,
    err: Option<String>,
    calls: Cell<usize>,
}

impl FakeRevocation {
    fn new() -> Self {
        Self {
            revoked: Vec::new(),
            err: None,
            calls: Cell::new(0),
        }
    }
    fn with_revoked(mut self, id: &str) -> Self {
        self.revoked.push(id.to_string());
        self
    }
    fn with_error(mut self, msg: &str) -> Self {
        self.err = Some(msg.to_string());
        self
    }
}

impl RevocationProvider for FakeRevocation {
    fn is_revoked(&self, cert_id: &str) -> Result<bool, String> {
        self.calls.set(self.calls.get() + 1);
        if let Some(err) = &self.err {
            return Err(err.clone());
        }
        Ok(self.revoked.iter().any(|c| c == cert_id))
    }
}

#[test]
fn revocation_provider_revoked() {
    let (bundle, cert_id) = good_bundle();
    let provider = FakeRevocation::new().with_revoked(&cert_id);
    let opts = VerifyOptions {
        revocation: Some(Box::new(provider)),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert_eq!(res.identity_status, IdentityStatus::Revoked);
}

#[test]
fn revocation_provider_not_revoked() {
    let (bundle, _) = good_bundle();
    let provider = FakeRevocation::new();
    let opts = VerifyOptions {
        revocation: Some(Box::new(provider)),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "got {:?}: {}", res.identity_status, res.error_reason);
}

#[test]
fn revocation_provider_error_fails_closed() {
    let (bundle, _) = good_bundle();
    let provider = FakeRevocation::new().with_error("upstream timeout");
    let opts = VerifyOptions {
        revocation: Some(Box::new(provider)),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert!(
        res.error_reason.contains("revocation_error"),
        "error_reason={}",
        res.error_reason
    );
}

#[test]
fn revocation_provider_takes_precedence_over_closure() {
    let (bundle, cert_id) = good_bundle();
    let provider = FakeRevocation::new().with_revoked(&cert_id);
    // Closure would return "not revoked" — provider must still revoke and the
    // closure must never run.
    let closure_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = closure_calls.clone();
    let opts = VerifyOptions {
        revocation: Some(Box::new(provider)),
        is_revoked: Some(Box::new(move |_| {
            cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            false
        })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid, "provider should still revoke");
    assert_eq!(
        closure_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "legacy closure must not be invoked"
    );
}

#[test]
fn force_revocation_check_accepts_provider() {
    let (bundle, _) = good_bundle();
    let provider = FakeRevocation::new();
    let opts = VerifyOptions {
        revocation: Some(Box::new(provider)),
        force_revocation_check: true,
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "got {:?}: {}", res.identity_status, res.error_reason);
}

// ---------------------------------------------------------------------------
// PolicyProvider — SPEC §17.2
// ---------------------------------------------------------------------------

struct FakePolicy {
    allow: bool,
    err: Option<String>,
    calls: Cell<usize>,
}

impl FakePolicy {
    fn allow() -> Self {
        Self { allow: true, err: None, calls: Cell::new(0) }
    }
    fn deny() -> Self {
        Self { allow: false, err: None, calls: Cell::new(0) }
    }
    fn err(msg: &str) -> Self {
        Self {
            allow: true,
            err: Some(msg.to_string()),
            calls: Cell::new(0),
        }
    }
}

impl PolicyProvider for FakePolicy {
    fn evaluate_policy(
        &self,
        _: &ProofBundle,
        _: &VerifierContext,
    ) -> Result<bool, String> {
        self.calls.set(self.calls.get() + 1);
        if let Some(err) = &self.err {
            return Err(err.clone());
        }
        Ok(self.allow)
    }
}

#[test]
fn policy_provider_allow() {
    let (bundle, _) = good_bundle();
    let opts = VerifyOptions {
        policy: Some(Box::new(FakePolicy::allow())),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
}

#[test]
fn policy_provider_deny_maps_to_scope_denied() {
    let (bundle, _) = good_bundle();
    let opts = VerifyOptions {
        policy: Some(Box::new(FakePolicy::deny())),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert_eq!(res.identity_status, IdentityStatus::ScopeDenied);
}

#[test]
fn policy_provider_error_fails_closed() {
    let (bundle, _) = good_bundle();
    let opts = VerifyOptions {
        policy: Some(Box::new(FakePolicy::err("opa eval crashed"))),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert!(
        res.error_reason.contains("policy_error"),
        "error_reason={}",
        res.error_reason
    );
}

// Sentinel-recording fake to verify policy is skipped when crypto fails.
struct CountingPolicy {
    calls: Cell<usize>,
}

impl PolicyProvider for CountingPolicy {
    fn evaluate_policy(
        &self,
        _: &ProofBundle,
        _: &VerifierContext,
    ) -> Result<bool, String> {
        self.calls.set(self.calls.get() + 1);
        Ok(true)
    }
}

#[test]
fn policy_provider_only_runs_after_crypto_checks() {
    let (mut bundle, _) = good_bundle();
    bundle.challenge = b"tampered".to_vec();
    let policy = CountingPolicy { calls: Cell::new(0) };
    // We need to read calls after the verifier returns — but Box<dyn ...>
    // erases the type, so use a shared Mutex<usize>.
    let count = std::sync::Arc::new(Mutex::new(0usize));
    struct SharedPolicy(std::sync::Arc<Mutex<usize>>);
    impl PolicyProvider for SharedPolicy {
        fn evaluate_policy(&self, _: &ProofBundle, _: &VerifierContext) -> Result<bool, String> {
            *self.0.lock().unwrap() += 1;
            Ok(true)
        }
    }
    let _ = policy; // discard unused
    let opts = VerifyOptions {
        policy: Some(Box::new(SharedPolicy(count.clone()))),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    assert_eq!(
        *count.lock().unwrap(),
        0,
        "policy must not run when crypto fails"
    );
}

// ---------------------------------------------------------------------------
// AuditProvider — SPEC §17.3
// ---------------------------------------------------------------------------

struct RecordingAudit {
    log: std::sync::Arc<Mutex<Vec<VerifyResult>>>,
}

impl AuditProvider for RecordingAudit {
    fn log_verification(&self, result: &VerifyResult, _: &ProofBundle) {
        self.log.lock().unwrap().push(result.clone());
    }
}

#[test]
fn audit_provider_logs_success() {
    let (bundle, _) = good_bundle();
    let log = std::sync::Arc::new(Mutex::new(Vec::new()));
    let opts = VerifyOptions {
        audit: Some(Box::new(RecordingAudit { log: log.clone() })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(res.valid, "{}", res.error_reason);
    let entries = log.lock().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].valid);
}

#[test]
fn audit_provider_logs_failure() {
    let (mut bundle, _) = good_bundle();
    bundle.challenge = b"tampered".to_vec();
    let log = std::sync::Arc::new(Mutex::new(Vec::new()));
    let opts = VerifyOptions {
        audit: Some(Box::new(RecordingAudit { log: log.clone() })),
        ..VerifyOptions::default()
    };
    let res = verify_bundle(&bundle, &opts);
    assert!(!res.valid);
    let entries = log.lock().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].valid);
}
