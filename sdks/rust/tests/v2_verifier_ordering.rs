//! testvectors/v2/verifier-ordering.json against `verify_proof_bundle_v2`,
//! mirroring Go `TestV2ConformanceVerifierOrdering`
//! (v2_conformance_ordering_test.go).

mod v2_verify_common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ratify_protocol::v2::*;
use serde_json::Value;
use v2_verify_common::*;

/// Go `v2ScriptedClaimStore`: a single-claim, in-memory test double.
struct ScriptedClaimStore {
    mode: String,
    claimed_at: i64,
    finalization_at: i64,
    counts: Arc<Counts>,
    final_body: Mutex<Vec<u8>>,
    expires_at: Mutex<i64>,
}

impl V2AuthoritativeClock for ScriptedClaimStore {
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        Ok(self.finalization_at)
    }
}

impl ClaimStoreV2 for ScriptedClaimStore {
    fn claim_v2(&self, _ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError> {
        self.counts.claim.fetch_add(1, Ordering::SeqCst);
        *self.expires_at.lock().unwrap() = claim.expires_at;
        match self.mode.as_str() {
            "create" => Ok(V2ClaimResult {
                disposition: V2ClaimDisposition::Created,
                claimed_at: self.claimed_at,
                owner_token: vec![7; 32],
            }),
            "proof_conflict" => Err(V2StoreError::ClaimProofConflict),
            "in_progress" => Ok(V2ClaimResult {
                disposition: V2ClaimDisposition::InProgress,
                claimed_at: self.claimed_at,
                owner_token: Vec::new(),
            }),
            "terminal_replay" => Ok(V2ClaimResult {
                disposition: V2ClaimDisposition::TerminalReplay,
                claimed_at: self.claimed_at,
                owner_token: Vec::new(),
            }),
            _ => Err(V2StoreError::Unavailable("scripted claim store unavailable".into())),
        }
    }

    /// SPEC-v2 §7.2: T_final is the scripted finalization reading, a reading
    /// below T_claim is clock_regressed, and an allow commits only while
    /// T_final is before both its horizon and the challenge expiry.
    fn finalize_v2_claim(
        &self,
        _ctx: &V2Context,
        _claim_id: &str,
        _owner_token: &[u8],
        _terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError> {
        self.counts.finalize.fetch_add(1, Ordering::SeqCst);
        if self.finalization_at < self.claimed_at {
            return Err(V2StoreError::Classified(V2Error::new(
                V2ErrorClass::ClockRegressed,
                "scripted finalization clock regressed",
            )));
        }
        let expires_at = *self.expires_at.lock().unwrap();
        if allow_valid_until > 0 && (self.finalization_at >= allow_valid_until || self.finalization_at >= expires_at) {
            return Err(V2StoreError::Classified(V2Error::new(
                V2ErrorClass::AllowHorizonPassed,
                "scripted allow at or beyond its deadline",
            )));
        }
        *self.final_body.lock().unwrap() = receipt_body.to_vec();
        Ok(true)
    }

    fn record_v2_evaluation_progress(
        &self,
        _ctx: &V2Context,
        _claim_id: &str,
        _owner_token: &[u8],
        _progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError> {
        self.counts.progress.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn load_v2_interrupted_claim(&self, _ctx: &V2Context, _claim_id: &str) -> Result<V2InterruptedClaim, V2StoreError> {
        Err(V2StoreError::Unavailable("not used by ordering vectors".into()))
    }

    fn recover_interrupted_v2_claim(
        &self,
        _ctx: &V2Context,
        _claim_id: &str,
        _terminal_result: &[u8],
        _receipt_body: &[u8],
    ) -> Result<bool, V2StoreError> {
        Err(V2StoreError::Unavailable("not used by ordering vectors".into()))
    }
}

/// Runs one vector; returns a list of mismatches (empty = pass).
fn run_vector(v: &Value, bundle: Vec<u8>) -> Vec<String> {
    let mut failures = Vec::new();
    let counts = Arc::new(Counts::default());
    let (req, mut cb, rate) = build_verify_request(v, bundle, &counts);
    let claimed_at = i(&v["now"]) + i(&v["claim_time_offset"]);
    let store = Arc::new(ScriptedClaimStore {
        mode: s(&v["claim_store"]),
        claimed_at,
        finalization_at: claimed_at + i(&v["finalize_time_offset"]),
        counts: Arc::clone(&counts),
        final_body: Mutex::new(Vec::new()),
        expires_at: Mutex::new(0),
    });
    // claim_store "absent": no claim store is configured.
    cb.claim_store = (s(&v["claim_store"]) != "absent").then(|| store.clone() as _);

    let outcome = verify_proof_bundle_v2(&V2Context::background(), &req, &cb);
    let want = &v["expected"];
    let want_stage = s(&want["stage"]);
    if outcome.stage.as_str() != want_stage {
        failures.push(format!(
            "stage {} (class {:?}, err {:?}), want {want_stage}",
            outcome.stage.as_str(),
            outcome.error_class,
            outcome.error
        ));
        return failures;
    }
    // Go returns the error only for the evaluating stage; here every
    // preflight and evaluating outcome carries it.
    let has_error = outcome.error.is_some();
    if has_error != (want_stage == "evaluating" || want_stage == "preflight") {
        failures.push(format!("error presence {has_error} does not match stage {want_stage}"));
    }
    let got_class = outcome.error_class.map(|c| c.as_str().to_string()).unwrap_or_default();
    if got_class != s(&want["error_class"]) {
        failures.push(format!(
            "error class {got_class:?} ({:?}), want {:?}",
            outcome.error,
            s(&want["error_class"])
        ));
    }
    let want_disposition = s(&want["disposition"]);
    if !want_disposition.is_empty() && outcome.disposition.map(|d| d.as_str()) != Some(want_disposition.as_str()) {
        failures.push(format!("disposition {:?}, want {want_disposition}", outcome.disposition));
    }
    let got_counts = counts.snapshot();
    let want_counts = Counts::expected(&want["callback_counts"]);
    if got_counts != want_counts {
        failures.push(format!("callback counts {got_counts:?}, want {want_counts:?}"));
    }
    if want_stage != "committed" {
        if outcome.committed.is_some() {
            failures.push("a non-committed stage carried a committed outcome".into());
        }
        return failures;
    }
    let Some(committed) = outcome.committed else {
        failures.push("committed stage without a committed outcome".into());
        return failures;
    };
    let body = committed.receipt_body();
    let r = match decode_verification_receipt_body_v2(&body) {
        Ok(r) => r,
        Err(e) => {
            failures.push(format!("committed receipt body does not decode: {e}"));
            return failures;
        }
    };
    let got = [
        &r.decision,
        &r.decision_reason,
        &r.identity_status,
        &r.trust_assessment,
        &r.status_assessment,
        &r.context_assessment,
    ]
    .map(|x| x.to_string());
    let exp = [
        "decision",
        "decision_reason",
        "identity_status",
        "trust_assessment",
        "status_assessment",
        "context_assessment",
    ]
    .map(|k| s(&want[k]));
    if got != exp {
        failures.push(format!("committed tuple {got:?}, want {exp:?}"));
    }
    if r.verified_at != i(&want["verified_at"]) {
        failures.push(format!("verified_at {}, want {}", r.verified_at, i(&want["verified_at"])));
    }
    if want.get("context_policy_digest").is_some() {
        let want_digest = want["context_policy_digest"].as_str().map(str::to_string);
        if r.context_policy_digest != want_digest {
            failures.push(format!(
                "context_policy_digest {:?}, want {want_digest:?}",
                r.context_policy_digest
            ));
        }
    }
    if want.get("granted_scope").is_some() {
        let want_scope: Vec<String> = arr(&want["granted_scope"]).iter().map(s).collect();
        if r.granted_scope != want_scope {
            failures.push(format!("granted_scope {:?}, want {want_scope:?}", r.granted_scope));
        }
    }
    if want.get("status_evidence").is_some() {
        let want_evidence: Vec<StatusEvidenceEntryV2> = arr(&want["status_evidence"]).iter().map(evidence_json).collect();
        if r.status_evidence != want_evidence {
            failures.push(format!("status evidence {:?}, want {want_evidence:?}", r.status_evidence));
        }
    }
    let want_body = unb64(&want["receipt_body_b64"]);
    if body != want_body || *store.final_body.lock().unwrap() != body {
        failures.push(format!(
            "receipt body differs:\n got {}\nwant {}",
            String::from_utf8_lossy(&body),
            String::from_utf8_lossy(&want_body)
        ));
    }
    if committed.receipt_body_digest() != receipt_outbox_digest_v2(&want_body) || committed.claim_id().is_empty() {
        failures.push("committed handoff digest or claim ID is wrong".into());
    }
    let horizon = committed.allow_horizon();
    let want_allow = s(&want["decision"]) == "allow";
    if horizon.is_some() != want_allow || horizon.unwrap_or(0) != i(&want["allow_valid_until"]) {
        failures.push(format!("allow horizon {horizon:?}, want {}", i(&want["allow_valid_until"])));
    }
    let want_batch = arr(&want["rate_batch"]);
    if !want_batch.is_empty() {
        let got_batch = rate.as_ref().map(|r| r.batch.lock().unwrap().clone()).unwrap_or_default();
        let want_batch: Vec<V2RateReservation> = want_batch
            .iter()
            .map(|w| V2RateReservation {
                issuer_id: s(&w["issuer_id"]),
                cert_id: s(&w["cert_id"]),
                window_s: i(&w["window_s"]),
                limit: i(&w["limit"]),
            })
            .collect();
        if got_batch != want_batch {
            failures.push(format!("rate batch {got_batch:?}, want {want_batch:?}"));
        }
    }
    failures
}

#[test]
fn v2_conformance_verifier_ordering() {
    let f = load_v2_vector("verifier-ordering.json");
    let bundles = f["bundles_b64"].as_object().expect("bundles_b64");
    let vectors = arr(&f["vectors"]);
    assert!(!vectors.is_empty(), "no ordering vectors");
    let mut stages: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    let consumed = AtomicUsize::new(0);
    for v in &vectors {
        let name = s(&v["name"]);
        let bundle = bundles
            .get(&s(&v["bundle"]))
            .unwrap_or_else(|| panic!("{name}: unknown bundle {}", v["bundle"]));
        let result = run_vector(v, unb64(bundle));
        consumed.fetch_add(1, Ordering::SeqCst);
        *stages.entry(s(&v["expected"]["stage"])).or_default() += 1;
        if !result.is_empty() {
            failures.push(format!("{name}:\n  {}", result.join("\n  ")));
        }
    }
    assert!(failures.is_empty(), "{} of {} vectors failed:\n{}", failures.len(), vectors.len(), failures.join("\n"));
    // Exact counts from the corpus and its README row.
    assert_eq!(consumed.load(Ordering::SeqCst), 342);
    assert_eq!(vectors.len(), 342);
    let want_stages = BTreeMap::from([
        ("committed".to_string(), 240),
        ("evaluating".to_string(), 2),
        ("preflight".to_string(), 98),
        ("replay".to_string(), 2),
    ]);
    assert_eq!(stages, want_stages);
    let readme = readme_line("verifier-ordering.json");
    assert!(
        readme.contains("342 end-to-end live-verifier cases (98 pre-claim, 2 replay, 240 committed, 2 evaluating"),
        "README row: {readme}"
    );
    let custody = vectors.iter().filter(|v| s(&v["name"]).starts_with("custody_profile_")).count();
    assert_eq!(custody, 10, "Middleware Custody Profile cases");
    let registry = vectors.iter().filter(|v| s(&v["name"]).starts_with("trust_registry_")).count();
    assert_eq!(registry, 5, "reference trust registry cases");
}

/// Every vector that registers extension evaluators gives the same outcome
/// when the registry invokes them on the calling thread, including the
/// error, panic, timeout, and invalid-output faults.
#[test]
fn v2_conformance_verifier_ordering_calling_thread_evaluators() {
    EVALUATOR_INVOCATION.with(|m| m.set(ConstraintEvaluatorInvocationV2::CallingThread));
    let f = load_v2_vector("verifier-ordering.json");
    let bundles = f["bundles_b64"].as_object().expect("bundles_b64");
    let mut ran = 0usize;
    let mut failures = Vec::new();
    for v in arr(&f["vectors"]) {
        if arr(&v["constraint_evaluators"]).is_empty() {
            continue;
        }
        ran += 1;
        let name = s(&v["name"]);
        let result = run_vector(&v, unb64(&bundles[&s(&v["bundle"])]));
        if !result.is_empty() {
            failures.push(format!("{name}:\n  {}", result.join("\n  ")));
        }
    }
    assert!(ran > 0, "no vector registers an evaluator");
    assert!(failures.is_empty(), "{} of {ran} vectors failed:\n{}", failures.len(), failures.join("\n"));
}
