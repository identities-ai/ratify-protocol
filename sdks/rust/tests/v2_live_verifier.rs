//! Live verifier, release, recovery and claim-capability tests, porting
//! the relevant Go unit tests (release_v2_api_test.go,
//! verify_v2_interrupted_test.go, claim_store_v2_test.go highlights) onto
//! the reference Part B store and verifier-ordering corpus inputs.

mod v2_status_common;
mod v2_verify_common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ratify_protocol::v2::reference::Store;
use ratify_protocol::v2::*;
use ratify_protocol::HybridPublicKey;
use serde_json::Value;
use v2_verify_common::*;

const LOG_ID: &str = "0123456789abcdef0123456789abcdef";

fn corpus() -> &'static Value {
    static CORPUS: OnceLock<Value> = OnceLock::new();
    CORPUS.get_or_init(|| load_v2_vector("verifier-ordering.json"))
}

/// The inputs and presented bundle of one verifier-ordering vector.
fn case(name: &str) -> (Value, Vec<u8>) {
    let f = corpus();
    let v = arr(&f["vectors"])
        .into_iter()
        .find(|v| s(&v["name"]) == name)
        .unwrap_or_else(|| panic!("no vector {name}"));
    let bundle = unb64(&f["bundles_b64"][s(&v["bundle"])]);
    (v, bundle)
}

fn verifier_keys() -> (HybridPublicKey, ratify_protocol::HybridPrivateKey) {
    let fx = v2_status_common::load_v2_keys();
    (fx.public("verifier"), fx.private.get("verifier").expect("verifier").clone())
}

fn new_store(now: i64) -> Arc<Store> {
    let (_, private) = verifier_keys();
    Arc::new(Store::new(now, 30, LOG_ID, &private).expect("store"))
}

/// Verify one corpus vector against the reference store.
fn verify_case(name: &str, store: &Arc<Store>, adjust: impl FnOnce(&mut V2VerifyCallbacks)) -> (V2VerifyOutcome, Value) {
    let (v, bundle) = case(name);
    let counts = Arc::new(Counts::default());
    let (req, mut cb, _) = build_verify_request(&v, bundle, &counts);
    cb.claim_store = Some(store.clone());
    adjust(&mut cb);
    (verify_proof_bundle_v2(&V2Context::background(), &req, &cb), v)
}

struct TestClock {
    now: i64,
    fail: bool,
    panic: bool,
}

impl V2AuthoritativeClock for TestClock {
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        if self.panic {
            panic!("clock");
        }
        if self.fail {
            return Err(V2StoreError::Unavailable("clock unavailable".into()));
        }
        Ok(self.now)
    }
}

fn clock(now: i64) -> TestClock {
    TestClock {
        now,
        fail: false,
        panic: false,
    }
}

fn release(store: &Arc<Store>, committed: &CommittedV2Outcome, wire: Option<&[u8]>) -> V2ReleaseResult {
    let (public, _) = verifier_keys();
    release_v2_decision(
        &V2Context::background(),
        committed,
        wire,
        V2ReleaseConfig {
            verifier_public_key: &public,
            log_id: LOG_ID,
            claim_store: store.as_ref(),
            checkpoint: store.as_ref(),
        },
    )
}

fn publish(store: &Arc<Store>, committed: &CommittedV2Outcome) -> Vec<u8> {
    store
        .publish_v2_receipt(&V2Context::background(), &committed.claim_id(), &committed.receipt_body())
        .expect("publish")
}

// ---------------------------------------------------------------------------
// Release (SPEC-v2 §6.9)

#[test]
fn committed_allow_releases_once_with_exclusive_deadlines() {
    let store = new_store(1_800_000_000);
    let (outcome, v) = verify_case("allow_bound_context", &store, |_| {});
    assert_eq!(outcome.stage, V2VerifyStage::Committed, "{:?}", outcome.error);
    let committed = outcome.committed.expect("committed");
    let expires = i(&v["expected_challenge"]["expires_at"]);
    assert_eq!(committed.challenge_expires_at(), expires);
    assert_eq!(committed.allow_horizon(), Some(1_800_003_600));
    // Not appended yet: pending, never released.
    let pending = release(&store, &committed, None);
    assert_eq!((pending.status, pending.reason.as_str()), (V2ReleaseStatus::Pending, "receipt_not_appended"));
    assert!(pending.decision().is_none());
    let wire = publish(&store, &committed);
    assert_eq!(publish(&store, &committed), wire, "an appended receipt is returned again");
    let released = release(&store, &committed, Some(&wire));
    assert_eq!(released.status, V2ReleaseStatus::Released, "{}", released.reason);
    assert!(released.reason.is_empty());
    let decision = released.into_decision().expect("released decision");
    assert_eq!(decision.decision(), "allow");
    assert_eq!(decision.reason(), "authorized");
    assert_eq!(decision.identity_status(), "authorized_agent");
    assert_eq!(decision.claim_id(), committed.claim_id());
    assert_eq!(decision.allow_horizon(), Some(1_800_003_600));
    assert_eq!(decision.release_time(), 1_800_000_000);
    assert_eq!(decision.receipt().expect("receipt").decision, "allow");
    // Accessors return copies.
    let mut scope = decision.granted_scope();
    scope.push("admin:all".into());
    assert_ne!(decision.granted_scope(), scope);
    let mut wire_copy = decision.receipt_wire();
    wire_copy.clear();
    assert_eq!(decision.receipt_wire(), wire);
    // Exclusive deadlines: the challenge expiry binds (it precedes the
    // allow horizon).
    let ctx = V2Context::background();
    assert!(decision.allowed(&ctx, &clock(expires - 1)));
    assert!(!decision.allowed(&ctx, &clock(expires)));
    assert!(!decision.allowed(&ctx, &clock(1_800_003_600)));
    assert!(!decision.allowed(&ctx, &clock(-1)));
    assert!(!decision.allowed(&ctx, &clock(V2_MAX_TIMESTAMP_SECONDS + 1)));
    assert!(!decision.allowed(&ctx, &TestClock { now: 1_800_000_000, fail: true, panic: false }));
    assert!(!decision.allowed(&ctx, &TestClock { now: 1_800_000_000, fail: false, panic: true }));
    // A repeat release is idempotent and records nothing new.
    let again = release(&store, &committed, Some(&wire));
    assert_eq!(again.status, V2ReleaseStatus::Released);
    // A tampered receipt is rejected.
    let mut tampered = wire.clone();
    if let Some(byte) = tampered.iter_mut().rev().find(|b| b.is_ascii_digit()) {
        *byte = if *byte == b'1' { b'2' } else { b'1' };
    }
    let rejected = release(&store, &committed, Some(&tampered));
    assert_eq!(rejected.status, V2ReleaseStatus::Rejected);
}

#[test]
fn allow_horizon_from_an_extension_evaluator_bounds_allowed() {
    let store = new_store(1_800_000_000);
    let (outcome, _) = verify_case("extension_pass_horizon_bounds_allow", &store, |_| {});
    let committed = outcome.committed.expect("committed");
    assert_eq!(committed.allow_horizon(), Some(1_800_000_120));
    let wire = publish(&store, &committed);
    let decision = release(&store, &committed, Some(&wire)).into_decision().expect("released");
    let ctx = V2Context::background();
    assert!(decision.allowed(&ctx, &clock(1_800_000_119)));
    assert!(!decision.allowed(&ctx, &clock(1_800_000_120)), "the allow horizon is exclusive");
}

#[test]
fn released_deny_is_never_allowed() {
    let store = new_store(1_800_000_000);
    let (outcome, _) = verify_case("untrusted_root_consumes_challenge", &store, |_| {});
    let committed = outcome.committed.expect("committed");
    assert_eq!(committed.allow_horizon(), None);
    let wire = publish(&store, &committed);
    let decision = release(&store, &committed, Some(&wire)).into_decision().expect("released");
    assert_ne!(decision.decision(), "allow");
    assert_eq!(decision.allow_horizon(), None);
    assert!(!decision.allowed(&V2Context::background(), &clock(1_800_000_001)));
}

#[test]
fn release_is_withheld_after_expiry_or_abandonment() {
    let store = new_store(1_800_000_000);
    let (outcome, v) = verify_case("allow_bound_context", &store, |_| {});
    let committed = outcome.committed.expect("committed");
    let wire = publish(&store, &committed);
    store.set_time(i(&v["expected_challenge"]["expires_at"]));
    let withheld = release(&store, &committed, Some(&wire));
    assert_eq!((withheld.status, withheld.reason.as_str()), (V2ReleaseStatus::Withheld, "challenge_expired"));

    let store = new_store(1_800_000_000);
    let (outcome, _) = verify_case("allow_bound_context", &store, |_| {});
    let committed = outcome.committed.expect("committed");
    store.set_signer_failure(true);
    assert!(store
        .publish_v2_receipt(&V2Context::background(), &committed.claim_id(), &committed.receipt_body())
        .is_err());
    assert_eq!(store.abandon_pending_receipts(), vec![committed.claim_id()]);
    let withheld = release(&store, &committed, None);
    assert_eq!((withheld.status, withheld.reason.as_str()), (V2ReleaseStatus::Withheld, "receipt_abandoned"));
    // An exact retry of an abandoned claim fails before claim.
    let (retry, _) = verify_case("allow_bound_context", &store, |_| {});
    assert_eq!(retry.stage, V2VerifyStage::Preflight);
    assert_eq!(retry.error_class, Some(V2ErrorClass::ReceiptAbandoned));
}

#[test]
fn a_regressed_store_clock_withholds_release() {
    let store = new_store(1_800_000_000);
    let (outcome, _) = verify_case("allow_bound_context", &store, |_| {});
    let committed = outcome.committed.expect("committed");
    let wire = publish(&store, &committed);
    store.set_time(1_800_000_010);
    assert_eq!(store.authoritative_time_v2(&V2Context::background()), Ok(1_800_000_010));
    store.set_time(1_800_000_005);
    let withheld = release(&store, &committed, Some(&wire));
    assert_eq!((withheld.status, withheld.reason.as_str()), (V2ReleaseStatus::Withheld, "clock_regressed"));
}

/// Go TestV2ReleasedDecisionHasOneConstructor and
/// TestV2ReleasedDecisionAndCommittedOutcomeAreOpaque: the released decision
/// is built only by `release_v2_decision`, has no derive or trait impl that
/// could forge or copy one, and both handoff types expose exactly the
/// expected accessors.
#[test]
fn released_decision_is_sealed_in_source() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut dirs = vec![src];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    let mut literals = 0;
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.contains("V2ReleasedDecision {") && !t.starts_with("pub struct V2ReleasedDecision") && !t.starts_with("impl ") && !t.starts_with("//") {
                literals += 1;
                assert!(path.ends_with("v2/release.rs"), "{}:{} builds a V2ReleasedDecision", path.display(), n + 1);
            }
            for forbidden in [
                "impl Default for V2ReleasedDecision",
                "impl Clone for V2ReleasedDecision",
                "Deserialize<'de> for V2ReleasedDecision",
                "impl Default for CommittedV2Outcome",
            ] {
                assert!(!t.contains(forbidden), "{}:{}: {forbidden}", path.display(), n + 1);
            }
        }
    }
    assert_eq!(literals, 1, "exactly one construction site");
    let release = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/v2/release.rs")).unwrap();
    for ty in ["pub struct V2ReleasedDecision {", "pub struct CommittedV2Outcome {", "pub struct V2ReleaseResult {"] {
        let at = release.find(ty).expect(ty);
        let before = &release[..at];
        let previous_line = before.trim_end().lines().last().unwrap_or_default();
        for derived in ["Clone", "Default", "Deserialize"] {
            assert!(
                !(previous_line.contains("#[derive") && previous_line.contains(derived)),
                "{ty} must not derive {derived}"
            );
        }
        let body = &release[at..at + release[at..].find("\n}").unwrap()];
        for line in body.lines().skip(1) {
            let t = line.trim();
            assert!(
                !t.starts_with("pub ") || ty.contains("V2ReleaseResult") && (t.starts_with("pub status") || t.starts_with("pub reason")),
                "{ty} exposes field {t}"
            );
        }
    }
    let methods = |ty: &str| -> Vec<String> {
        let at = release.find(&format!("impl {ty} {{")).expect(ty);
        let block = &release[at..at + release[at..].find("\n}\n").unwrap()];
        let mut names: Vec<String> = block
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub fn "))
            .map(|l| l[..l.find('(').unwrap()].to_string())
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        methods("V2ReleasedDecision"),
        [
            "allow_horizon",
            "allowed",
            "challenge_expires_at",
            "claim_id",
            "decision",
            "granted_scope",
            "identity_status",
            "reason",
            "receipt",
            "receipt_wire",
            "release_time"
        ]
    );
    assert_eq!(
        methods("CommittedV2Outcome"),
        ["allow_horizon", "challenge_expires_at", "claim_id", "receipt_body", "receipt_body_digest"]
    );
}

// ---------------------------------------------------------------------------
// Cancellation and lease-expiry recovery (SPEC-v2 §6.11, §7.5)

#[test]
fn cancellation_after_claim_commits_nothing_and_recovery_reports_progress() {
    let store = new_store(1_800_000_000);
    let (v, bundle) = case("allow_bound_context");
    let counts = Arc::new(Counts::default());
    let (req, mut cb, _) = build_verify_request(&v, bundle, &counts);
    cb.claim_store = Some(store.clone());
    let (ctx, cancel) = V2Context::background().with_cancel();
    cb.trust = Some(Arc::new(move |_: &V2Context, _: &[DelegationCertV2]| {
        cancel.cancel();
        Err(V2ProviderError::new("trust lookup interrupted"))
    }));
    let outcome = verify_proof_bundle_v2(&ctx, &req, &cb);
    assert_eq!(outcome.stage, V2VerifyStage::Evaluating);
    assert_eq!(outcome.error_class, Some(V2ErrorClass::EvaluationCancelled));
    assert!(outcome.committed.is_none());
    let claim_id = outcome.claim.claim_id.clone();
    let bg = V2Context::background();
    // The lease is live: recovery refuses.
    let live = recover_interrupted_claim_v2(&bg, store.as_ref(), &claim_id).expect_err("lease live");
    assert_eq!(live.class, V2ErrorClass::ClaimLeaseLive);
    store.set_time(1_800_000_031);
    let committed = recover_interrupted_claim_v2(&bg, store.as_ref(), &claim_id).expect("recover");
    let receipt = decode_verification_receipt_body_v2(&committed.receipt_body()).expect("body");
    assert_eq!(
        (
            receipt.decision.as_str(),
            receipt.decision_reason.as_str(),
            receipt.trust_assessment.as_str(),
            receipt.status_assessment.as_str(),
            receipt.verified_at
        ),
        ("indeterminate", "evaluation_interrupted", "unavailable", "not_evaluated", 1_800_000_000),
        "the interrupted trust lookup is unavailable and T_claim is verified_at"
    );
    assert_eq!(committed.allow_horizon(), None);
    // Identical repeat recovery returns the same outcome.
    let again = recover_interrupted_claim_v2(&bg, store.as_ref(), &claim_id).expect("repeat");
    assert_eq!(again.receipt_body(), committed.receipt_body());
    // Recovery of an unknown claim is classified.
    let unknown = recover_interrupted_claim_v2(&bg, store.as_ref(), "nope").expect_err("unknown");
    assert_eq!(unknown.class, V2ErrorClass::ClaimNotFound);
    // The recovered outcome is released as a non-actionable decision.
    let wire = publish(&store, &committed);
    let decision = release(&store, &committed, Some(&wire)).into_decision().expect("released");
    assert_eq!(decision.decision(), "indeterminate");
    assert!(!decision.allowed(&bg, &clock(1_800_000_032)));
}

#[test]
fn a_lost_lease_stops_evaluation_before_the_next_provider() {
    let store = new_store(1_800_000_000);
    let status_calls = Arc::new(AtomicUsize::new(0));
    let calls = status_calls.clone();
    let lease_store = store.clone();
    let (outcome, _) = verify_case("allow_bound_context", &store, move |cb| {
        let trust = cb.trust.clone().expect("trust");
        cb.trust = Some(Arc::new(move |ctx: &V2Context, chain: &[DelegationCertV2]| {
            lease_store.set_time(1_800_000_031); // the lease expires during trust
            trust(ctx, chain)
        }));
        let status = cb.status_evidence.clone().expect("status");
        cb.status_evidence = Some(Arc::new(move |ctx: &V2Context, r: &V2StatusEvidenceRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            status(ctx, r)
        }));
    });
    assert_eq!(outcome.stage, V2VerifyStage::Evaluating);
    assert_eq!(outcome.error_class, Some(V2ErrorClass::ClaimLeaseLost));
    assert_eq!(status_calls.load(Ordering::SeqCst), 0, "no provider runs after a failed progress write");
    let committed = recover_interrupted_claim_v2(&V2Context::background(), store.as_ref(), &outcome.claim.claim_id)
        .expect("recover");
    let receipt = decode_verification_receipt_body_v2(&committed.receipt_body()).expect("body");
    assert_eq!(receipt.trust_assessment, "unavailable", "the last recorded progress is used");
}

/// Go TestInterruptedV2ReceiptFollowsPersistedProgress.
#[test]
fn interrupted_receipt_follows_persisted_progress() {
    let digest = format!("sha384:{}", "d".repeat(96));
    let claim = V2ChallengeClaim {
        claim_id: "c".into(),
        verifier_id: "a".repeat(64),
        bundle_hash: format!("sha384:{}", "b".repeat(96)),
        issuer_ids: vec!["c".repeat(64)],
        required_scope: "data:read".into(),
        ..Default::default()
    };
    for (name, trust, status, context, valid) in [
        ("before trust", "not_evaluated", "not_evaluated", "not_evaluated", true),
        ("trust resolution interrupted", "unavailable", "not_evaluated", "not_evaluated", true),
        ("untrusted is retained", "untrusted", "not_evaluated", "not_evaluated", true),
        ("trusted, local stage interrupted", "trusted", "not_evaluated", "not_evaluated", true),
        ("status lookup interrupted", "trusted", "unavailable", "bound", true),
        ("status kept while context was pending", "trusted", "unavailable", "not_evaluated", true),
        ("context kept before status started", "trusted", "not_evaluated", "not_required", true),
        ("status without a trusted root", "unavailable", "unavailable", "not_evaluated", false),
        ("context without a trusted root", "untrusted", "not_evaluated", "bound", false),
        ("pending unbound context is never recorded", "trusted", "unavailable", "unbound", false),
    ] {
        let progress = V2EvaluationProgress {
            trust_assessment: trust.into(),
            status_assessment: status.into(),
            context_assessment: context.into(),
            context_policy_digest: (context != "not_evaluated").then(|| digest.clone()),
            status_evidence: Vec::new(),
        };
        let result = v2_evaluation_interrupted_result(&claim, 15, &progress);
        if !valid {
            let e = result.expect_err(name);
            assert_eq!(e.class, V2ErrorClass::Malformed, "{name}");
            continue;
        }
        let (terminal, body) = result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            terminal,
            br#"{"decision":"indeterminate","decision_reason":"evaluation_interrupted","identity_status":"authorization_unverified"}"#
        );
        let receipt = decode_verification_receipt_body_v2(&body).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            (
                receipt.trust_assessment.as_str(),
                receipt.status_assessment.as_str(),
                receipt.context_assessment.as_str(),
                receipt.context_policy_digest.clone(),
                receipt.verified_at
            ),
            (trust, status, context, progress.context_policy_digest.clone(), 15),
            "{name}"
        );
    }
    let bad_time = v2_evaluation_interrupted_result(&claim, -1, &initial_v2_evaluation_progress()).expect_err("time");
    assert_eq!(bad_time.class, V2ErrorClass::ConfigurationInvalid);
}

// ---------------------------------------------------------------------------
// Claim capability (Go claim_store_v2_test.go highlights)

type ClaimOutcome = V2Result<(V2ChallengeClaim, V2ClaimDisposition, Option<V2EvaluationToken>)>;

/// A preflight and atomic claim of one corpus vector against `store`.
fn preflight_and_claim(
    name: &str,
    store: &dyn ClaimStoreV2,
    now: i64,
) -> (ProofBundleV2, V2VerifyRequest, ClaimOutcome) {
    let (v, wire) = case(name);
    let counts = Arc::new(Counts::default());
    let (req, _, _) = build_verify_request(&v, wire.clone(), &counts);
    let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
    let preflight = preflight_proof_bundle_v2(
        &bundle,
        req.expected.as_ref(),
        req.context_policy.as_ref(),
        &req.required_scope,
        &req.verifier_namespace,
        req.replay_epoch,
        &req.verifier_id,
        req.now,
        req.max_challenge_age_seconds,
        req.future_skew_seconds,
    )
    .expect("preflight");
    let claimed = claim_proof_bundle_v2(
        &V2Context::background(),
        store,
        &bundle,
        &preflight,
        &req.verifier_namespace,
        req.replay_epoch,
        now,
    );
    (bundle, req, claimed)
}

/// The receipt outbox body the live verifier commits for vector `name` with
/// no trust provider configured (`indeterminate / trust_unavailable`). It is
/// bound to the same sealed claim values a direct claim of that vector
/// seals (SPEC-v2 §7.5), so helper and store finalization accept it.
fn untrusted_receipt_body(name: &str) -> (Vec<u8>, VerificationReceiptV2) {
    let (outcome, _) = verify_case(name, &new_store(1_800_000_000), |cb| cb.trust = None);
    let body = outcome.committed.expect("committed").receipt_body();
    let decoded = decode_verification_receipt_body_v2(&body).expect("receipt body");
    assert_eq!((decoded.decision.as_str(), decoded.decision_reason.as_str()), ("indeterminate", "trust_unavailable"));
    (body, decoded)
}

fn local_options(req: &V2VerifyRequest, token: &V2EvaluationToken, trusted: bool) -> V2LocalAuthorizationOptions {
    V2LocalAuthorizationOptions {
        future_skew_seconds: req.future_skew_seconds,
        required_scope: req.required_scope.clone(),
        trust_configured: trusted,
        context: req.context.clone(),
        tzdb_version: req.tzdb_version.clone(),
        context_policy: req.context_policy.clone(),
        expected_challenge: req.expected.clone(),
        claim_token: Some(token.clone()),
        ..Default::default()
    }
}

#[test]
fn one_concurrent_evaluator_per_claim() {
    let store = new_store(1_800_000_000);
    let (bundle, req, claimed) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000);
    let (_, disposition, token) = claimed.expect("claim");
    assert_eq!(disposition, V2ClaimDisposition::Created);
    let token = token.expect("token");
    let opts = local_options(&req, &token, false);
    let statuses: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| scope.spawn(|| evaluate_proof_bundle_v2_local_authorization(&bundle, &opts).status))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let evaluated = statuses.iter().filter(|s| *s != "evaluation_in_progress").count();
    assert_eq!(evaluated, 1, "{statuses:?}");
}

#[test]
fn an_exact_retry_never_receives_the_evaluator_capability() {
    let store = new_store(1_800_000_000);
    let (_, _, first) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000);
    assert!(first.expect("first").2.is_some());
    let (_, _, retry) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000);
    let (claim, disposition, token) = retry.expect("retry");
    assert_eq!(disposition, V2ClaimDisposition::InProgress);
    assert!(token.is_none() && !claim.claim_id.is_empty());
}

/// Go TestClaimProofBundleV2AmbiguousCreateErrorRecoversWithoutOwnership: a
/// store whose create response is lost returns an error; the exact retry is
/// in progress and never restores the lost capability.
#[test]
fn an_ambiguous_create_recovers_without_ownership() {
    struct LostResponse {
        inner: Arc<Store>,
        lose_next: Mutex<bool>,
    }
    impl V2AuthoritativeClock for LostResponse {
        fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
            self.inner.authoritative_time_v2(ctx)
        }
    }
    impl ClaimStoreV2 for LostResponse {
        fn claim_v2(&self, ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError> {
            let result = self.inner.claim_v2(ctx, claim);
            if std::mem::take(&mut *self.lose_next.lock().unwrap()) {
                return Err(V2StoreError::Unavailable("simulated ambiguous response after claim commit".into()));
            }
            result
        }
        fn finalize_v2_claim(&self, ctx: &V2Context, id: &str, o: &[u8], t: &[u8], b: &[u8], a: i64) -> Result<bool, V2StoreError> {
            self.inner.finalize_v2_claim(ctx, id, o, t, b, a)
        }
        fn record_v2_evaluation_progress(&self, ctx: &V2Context, id: &str, o: &[u8], p: V2EvaluationProgress) -> Result<(), V2StoreError> {
            self.inner.record_v2_evaluation_progress(ctx, id, o, p)
        }
        fn load_v2_interrupted_claim(&self, ctx: &V2Context, id: &str) -> Result<V2InterruptedClaim, V2StoreError> {
            self.inner.load_v2_interrupted_claim(ctx, id)
        }
        fn recover_interrupted_v2_claim(&self, ctx: &V2Context, id: &str, t: &[u8], b: &[u8]) -> Result<bool, V2StoreError> {
            self.inner.recover_interrupted_v2_claim(ctx, id, t, b)
        }
    }
    let store = LostResponse {
        inner: new_store(1_800_000_000),
        lose_next: Mutex::new(true),
    };
    let (_, _, first) = preflight_and_claim("allow_context_not_required", &store, 1_800_000_000);
    let e = first.expect_err("lost response");
    assert_eq!(e.class, V2ErrorClass::ClaimStoreUnavailable);
    let (_, _, retry) = preflight_and_claim("allow_context_not_required", &store, 1_800_000_000);
    let (_, disposition, token) = retry.expect("retry");
    assert_eq!(disposition, V2ClaimDisposition::InProgress);
    assert!(token.is_none());
}

#[test]
fn claim_time_preflight_rejects_before_the_store() {
    let store = new_store(1_800_000_000);
    // The sealed challenge expires at 1_800_000_290 (exclusive).
    let (_, _, claimed) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_290);
    let e = claimed.expect_err("expired at claim time");
    assert_eq!(e.class, V2ErrorClass::ChallengeNotFresh);
    let replay = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000).2.expect("claim");
    assert_eq!(replay.1, V2ClaimDisposition::Created, "the rejected attempt consumed nothing");
}

/// Go TestFinalizeClaimProofBundleV2RejectsDuplicateJSONKeys and the
/// terminal-payload binding.
#[test]
fn finalization_binds_the_completed_local_result() {
    let store = new_store(1_800_000_000);
    let (bundle, req, claimed) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000);
    let token = claimed.expect("claim").2.expect("token");
    let ctx = V2Context::background();
    let early = finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, b"{}", b"{}").expect_err("not evaluated");
    assert_eq!(early.class(), Some(V2ErrorClass::ConfigurationInvalid));
    let assessment = evaluate_proof_bundle_v2_local_authorization(&bundle, &local_options(&req, &token, false));
    assert_eq!((assessment.status.as_str(), assessment.reason.as_str()), ("authorization_unverified", "trust_unavailable"));
    let terminal = br#"{"decision":"indeterminate","decision_reason":"trust_unavailable","identity_status":"authorization_unverified"}"#;
    let duplicate = br#"{"decision":"indeterminate","decision":"indeterminate","decision_reason":"trust_unavailable"}"#;
    let (body, _) = untrusted_receipt_body("allow_context_not_required");
    let body = body.as_slice();
    let e = finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, duplicate, body).expect_err("duplicate keys");
    assert_eq!(e.class(), Some(V2ErrorClass::ConfigurationInvalid));
    let wrong = br#"{"decision":"deny","decision_reason":"trust_unavailable"}"#;
    assert!(finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, wrong, body).is_err());
    assert_eq!(finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, terminal, body), Ok(true));
    // An identical retry is accepted without a second commit; a changed body
    // is refused by the capability.
    assert_eq!(finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, terminal, body), Ok(false));
    let changed = br#"{"decision":"indeterminate","decision_reason":"trust_unavailable","x":1}"#;
    assert!(finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, terminal, changed).is_err());
}

/// Go TestFinalizeClaimProofBundleV2BindsReceiptBodyToSealedClaim (SPEC-v2
/// §7.5): a capability holder that changes any bound member of the receipt
/// body could otherwise get a signed, log-appended receipt naming another
/// proof, agent, or scope. Each mismatch is refused before the store
/// commits, and the genuine body still finalizes afterwards.
#[test]
fn finalization_binds_the_receipt_body_to_the_sealed_claim() {
    let store = new_store(1_800_000_000);
    let (bundle, req, claimed) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000);
    let (claim, _, token) = claimed.expect("claim");
    let token = token.expect("token");
    let ctx = V2Context::background();
    evaluate_proof_bundle_v2_local_authorization(&bundle, &local_options(&req, &token, false));
    let terminal = br#"{"decision":"indeterminate","decision_reason":"trust_unavailable","identity_status":"authorization_unverified"}"#;
    let (genuine, decoded) = untrusted_receipt_body("allow_context_not_required");
    let other_id = bundle.delegations.last().expect("root").issuer_id.clone();
    assert!(other_id != claim.verifier_id && other_id != claim.agent_id, "fixture root ID collides with a sealed ID");
    let other_digest = format!("sha384:{}", "2".repeat(96));
    type Edit<'a> = Box<dyn Fn(&mut VerificationReceiptV2) + 'a>;
    let edits: Vec<(&str, Edit)> = vec![
        ("verifier_id", Box::new(|r| r.verifier_id = other_id.clone())),
        ("agent_id", Box::new(|r| r.agent_id = other_id.clone())),
        ("bundle_hash", Box::new(|r| r.bundle_hash = format!("sha384:{}", "0".repeat(96)))),
        ("issuer_ids", Box::new(|r| {
            r.issuer_ids.pop();
        })),
        ("required_scope", Box::new(|r| r.required_scope = "data:write".into())),
        // A trust_unavailable body carries no context digest, so this case
        // uses the interrupted tuple that can.
        ("context_policy_digest", Box::new(|r| {
            r.decision_reason = "evaluation_interrupted".into();
            r.trust_assessment = "trusted".into();
            r.context_assessment = "bound".into();
            r.context_policy_digest = Some(other_digest.clone());
        })),
        ("constraint_evaluators", Box::new(|r| {
            r.constraint_evaluators = vec![ConstraintEvaluatorRefV2 {
                kind: "com.ratifyprotocol.max_count".into(),
                profile_digest: format!("sha384:{}", "1".repeat(96)),
            }]
        })),
    ];
    for (name, edit) in edits {
        let mut r = decoded.clone();
        edit(&mut r);
        let body = verification_receipt_v2_body(&r).unwrap_or_else(|e| panic!("{name}: {e}"));
        let e = finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, terminal, &body).expect_err(name);
        assert_eq!(e.class(), Some(V2ErrorClass::ConfigurationInvalid), "{name}: {e:?}");
        let direct_terminal = format!(
            r#"{{"decision":"indeterminate","decision_reason":"{}"}}"#,
            r.decision_reason
        );
        let direct = validate_v2_finalization_payload(&claim, direct_terminal.as_bytes(), &body);
        assert_eq!(v2_error_class_of(&direct), Some(V2ErrorClass::ConfigurationInvalid), "{name}: {direct:?}");
    }
    // A body that does not decode is malformed, and a terminal result naming
    // another decision is configuration_invalid.
    let malformed = validate_v2_finalization_payload(&claim, terminal, b"{}");
    assert_eq!(v2_error_class_of(&malformed), Some(V2ErrorClass::Malformed));
    let other_decision = validate_v2_finalization_payload(&claim, br#"{"decision":"deny","decision_reason":"trust_unavailable"}"#, &genuine);
    assert_eq!(v2_error_class_of(&other_decision), Some(V2ErrorClass::ConfigurationInvalid));
    validate_v2_finalization_payload(&claim, terminal, &genuine).expect("genuine payload");
    // Every refusal came before the store committed: the genuine body still
    // finalizes once.
    assert_eq!(finalize_claim_proof_bundle_v2(&ctx, store.as_ref(), &token, terminal, &genuine), Ok(true));
}

/// Go FinalizeClaimProofBundleV2 classifies a store's rate exhaustion as
/// claim_store_unavailable while errors.Is still finds the sentinel. Rust
/// keeps the matchable variant and reports the same class, so a caller sees
/// one SPEC-v2 §2.7 class for this refusal in every SDK.
#[test]
fn finalization_rate_exhaustion_keeps_the_variant_and_the_reference_class() {
    struct Exhausted(Arc<Store>);
    impl V2AuthoritativeClock for Exhausted {
        fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
            self.0.authoritative_time_v2(ctx)
        }
    }
    impl ClaimStoreV2 for Exhausted {
        fn claim_v2(&self, ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError> {
            self.0.claim_v2(ctx, claim)
        }
        fn finalize_v2_claim(&self, _: &V2Context, _: &str, _: &[u8], _: &[u8], _: &[u8], _: i64) -> Result<bool, V2StoreError> {
            Err(V2StoreError::RateLimitExceeded)
        }
        fn record_v2_evaluation_progress(&self, ctx: &V2Context, id: &str, o: &[u8], p: V2EvaluationProgress) -> Result<(), V2StoreError> {
            self.0.record_v2_evaluation_progress(ctx, id, o, p)
        }
        fn load_v2_interrupted_claim(&self, ctx: &V2Context, id: &str) -> Result<V2InterruptedClaim, V2StoreError> {
            self.0.load_v2_interrupted_claim(ctx, id)
        }
        fn recover_interrupted_v2_claim(&self, ctx: &V2Context, id: &str, t: &[u8], b: &[u8]) -> Result<bool, V2StoreError> {
            self.0.recover_interrupted_v2_claim(ctx, id, t, b)
        }
    }
    let store = Exhausted(new_store(1_800_000_000));
    let (bundle, req, claimed) = preflight_and_claim("allow_context_not_required", &store, 1_800_000_000);
    let token = claimed.expect("claim").2.expect("token");
    evaluate_proof_bundle_v2_local_authorization(&bundle, &local_options(&req, &token, false));
    let terminal = br#"{"decision":"indeterminate","decision_reason":"trust_unavailable","identity_status":"authorization_unverified"}"#;
    let (body, _) = untrusted_receipt_body("allow_context_not_required");
    let e = finalize_claim_proof_bundle_v2(&V2Context::background(), &store, &token, terminal, &body).expect_err("exhausted");
    assert_eq!(e, V2StoreError::RateLimitExceeded);
    assert_eq!(e.class(), Some(V2ErrorClass::ClaimStoreUnavailable));
}

#[test]
fn local_authorization_is_interrupted_when_sealed_state_differs() {
    let store = new_store(1_800_000_000);
    let (bundle, req, claimed) = preflight_and_claim("allow_context_not_required", store.as_ref(), 1_800_000_000);
    let token = claimed.expect("claim").2.expect("token");
    let mut opts = local_options(&req, &token, false);
    opts.required_scope = "data:write".into();
    let a = evaluate_proof_bundle_v2_local_authorization(&bundle, &opts);
    assert_eq!((a.status.as_str(), a.reason.as_str()), ("authorization_unverified", "evaluation_interrupted"));
    assert!(!a.bundle_hash.is_empty(), "the sealed bundle hash is carried for the receipt");
    let no_token = evaluate_proof_bundle_v2_local_authorization(&bundle, &V2LocalAuthorizationOptions::default());
    assert_eq!(no_token.reason, "claim_required");
}

#[test]
fn rate_admission_at_finalization_through_the_reference_store() {
    let store = new_store(1_800_000_000);
    let view = store.with_rate_at_finalization();
    let (v, bundle) = case("rate_reserved");
    let counts = Arc::new(Counts::default());
    let (req, mut cb, _) = build_verify_request(&v, bundle, &counts);
    cb.claim_store = Some(view.clone());
    cb.rate = Some(view.clone());
    let outcome = verify_proof_bundle_v2(&V2Context::background(), &req, &cb);
    assert_eq!(outcome.stage, V2VerifyStage::Committed, "{:?}", outcome.error);
    let committed = outcome.committed.expect("committed");
    assert!(committed.allow_horizon().is_some());
    assert_eq!(counts.rate.load(Ordering::SeqCst), 0, "no provisional reservation");
    assert_eq!(outcome.claim.rate_batch.len(), 1);
}

/// A barrier store's exact capacity exhaustion at finalization rolls back
/// and the same claim finalizes once as constraint_denied (SPEC-v2 §6.2).
#[test]
fn rate_exhaustion_at_finalization_commits_constraint_denied() {
    let store = new_store(1_800_000_000);
    let view = store.with_rate_at_finalization();
    let ctx = V2Context::background();
    let item = V2RateReservation {
        issuer_id: "89b5205a1e7e7906c38902a823c544fcd4ce0c22058a239d6da7d0c106c3d22c".into(),
        cert_id: "cert-leaf".into(),
        window_s: 60,
        limit: 5,
    };
    // Five prior allows fill the counter. Each prior claim seals the values of
    // a genuine allow receipt body, which the reference store's finalization
    // requires (SPEC-v2 §7.5), and carries an allow horizon (§6.8); only an
    // allow is counted.
    for n in 0..5 {
        let id = format!("prior-{n}");
        let mut claim = keyed(V2ChallengeClaim {
            namespace: "ns".into(),
            proof_digest: id.clone(),
            issued_at: 1_799_999_990,
            expires_at: 1_800_000_290,
            max_age_seconds: 300,
            rate_batch: vec![item.clone()],
            requires_rate: true,
            ..Default::default()
        }, &id);
        let id = claim.claim_id.clone();
        let (terminal, body) = bind_claim_to_receipt_body(&mut claim, 1_800_000_000);
        let created = view.claim_v2(&ctx, claim).expect("claim");
        let finalized = view.finalize_v2_claim(&ctx, &id, &created.owner_token, &terminal, &body, 1_800_000_100);
        assert_eq!(finalized, Ok(true));
    }
    let (v, bundle) = case("rate_reserved");
    let counts = Arc::new(Counts::default());
    let (req, mut cb, _) = build_verify_request(&v, bundle, &counts);
    cb.claim_store = Some(view.clone());
    cb.rate = Some(view.clone());
    let outcome = verify_proof_bundle_v2(&ctx, &req, &cb);
    assert_eq!(outcome.stage, V2VerifyStage::Committed, "{:?}", outcome.error);
    let committed = outcome.committed.expect("committed");
    assert_eq!(committed.allow_horizon(), None);
    let receipt = decode_verification_receipt_body_v2(&committed.receipt_body()).unwrap();
    assert_eq!(
        (receipt.decision.as_str(), receipt.decision_reason.as_str(), receipt.granted_scope.len()),
        ("deny", "constraint_denied", 0)
    );
}

// SPEC-v2 §2.5, §6.1 and §6.2 step 2: configuration that is out of bounds or
// internally inconsistent is configuration_invalid before any later
// pre-claim step and before the claim store is consulted. Without the fault
// each request stops later (expected challenge missing, or an invalid
// required scope), so the class proves where the check runs.
#[test]
fn configuration_rejected_at_step_two() {
    let (_, bundle) = case("pre_agent_key_without_id");
    let base = || V2VerifyRequest {
        bundle: bundle.clone(),
        verifier_namespace: "ns".into(),
        verifier_id: "a".repeat(64),
        now: 1_800_000_000,
        max_challenge_age_seconds: 60,
        future_skew_seconds: 5,
        status_policy: RevocationStatusPolicyV2 {
            max_list_lifetime_seconds: 3600,
            max_status_age_seconds: 3600,
            clock_skew_seconds: 5,
        },
        ..Default::default()
    };
    let session_context = |len: usize| ExpectedChallengeV2 {
        expected_session_context: Some(vec![0; len]),
        ..Default::default()
    };
    type Edit = Box<dyn Fn(&mut V2VerifyRequest)>;
    let cases: Vec<(&str, Edit)> = vec![
        ("status skew below future skew", Box::new(|r| r.status_policy.clock_skew_seconds = 0)),
        ("status skew above future skew", Box::new(|r| r.future_skew_seconds = 0)),
        ("replay epoch above 2^53-1", Box::new(|r| r.replay_epoch = 1 << 53)),
        ("replay epoch negative", Box::new(|r| r.replay_epoch = -1)),
        ("31-byte expected session context without a policy", Box::new(move |r| r.expected = Some(session_context(31)))),
        ("empty expected session context without a policy", Box::new(move |r| r.expected = Some(session_context(0)))),
    ];
    for (name, edit) in cases {
        let mut req = base();
        edit(&mut req);
        let store = new_store(1_800_000_000);
        let cb = V2VerifyCallbacks {
            claim_store: Some(store.clone()),
            ..Default::default()
        };
        let outcome = verify_proof_bundle_v2(&V2Context::background(), &req, &cb);
        assert_eq!(
            (outcome.stage, outcome.error_class),
            (V2VerifyStage::Preflight, Some(V2ErrorClass::ConfigurationInvalid)),
            "{name}: {:?}",
            outcome.error
        );
    }
}

// The standalone preflight entry point applies the same §6.2 step 2 bound on
// the configured replay epoch as verify_proof_bundle_v2, so a caller that
// runs preflight itself sees configuration_invalid, not stale_replay_epoch.
#[test]
fn standalone_preflight_replay_epoch_bound() {
    let (_, wire) = case("pre_agent_key_without_id");
    let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
    for epoch in [-1, 1 << 53] {
        let expected = ExpectedChallengeV2 {
            replay_epoch: epoch,
            ..Default::default()
        };
        let got = validate_proof_bundle_v2_preflight(
            &bundle,
            &expected,
            "data:read",
            "ns",
            epoch,
            &bundle.verifier_id,
            1_800_000_000,
            60,
            5,
        );
        assert_eq!(v2_error_class_of(&got), Some(V2ErrorClass::ConfigurationInvalid), "epoch {epoch}: {got:?}");
    }
}
