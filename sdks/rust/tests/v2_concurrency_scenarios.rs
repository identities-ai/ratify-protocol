//! Shared concurrency scenarios (testvectors/v2/concurrency-scenarios.json):
//! Go `TestV2ConformanceConcurrencyScenarios`.
//!
//! Every participant is a `std::thread` (scoped); all of them wait on one
//! `std::sync::Barrier` and start together, so the reference store's locks
//! see real contention. Each participant's verify request is built before
//! the barrier. Set RATIFY_RACE_ITERATIONS to change the per-scenario
//! iteration count; run with `--nocapture` to see the distinct outcomes each
//! group reached across iterations.

mod v2_status_common;
mod v2_verify_common;

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ratify_protocol::v2::reference::store::ERR_HEAD_OF_LINE_BLOCKED;
use ratify_protocol::v2::reference::*;
use ratify_protocol::v2::*;
use serde_json::Value;
use v2_verify_common::*;

fn file() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| load_v2_vector("concurrency-scenarios.json"))
}

/// The lifecycle file the scenarios draw their inputs from.
fn inputs() -> &'static Value {
    static INPUTS: OnceLock<Value> = OnceLock::new();
    INPUTS.get_or_init(|| load_v2_vector(&s(&file()["inputs"])))
}

fn keys() -> &'static v2_status_common::Fixture {
    static KEYS: OnceLock<v2_status_common::Fixture> = OnceLock::new();
    KEYS.get_or_init(v2_status_common::load_v2_keys)
}

fn new_store(now: i64) -> Arc<Store> {
    let f = inputs();
    let private = keys().private.get(&s(&f["verifier_key"])).expect("verifier key");
    Arc::new(Store::new(now, i(&f["lease_seconds"]), &s(&f["log_id"]), private).expect("store"))
}

fn bundle_of(name: &str) -> Vec<u8> {
    let f = inputs();
    unb64(&f["bundles_b64"][s(&f["requests"][name]["bundle"])])
}

/// The protocol claim ID of `name`'s expected challenge, claimed or not
/// (as the lifecycle recover step).
fn claim_id_of(name: &str) -> String {
    let e = &inputs()["requests"][name]["expected_challenge"];
    protocol_claim_id_v2(&s(&e["verifier_namespace"]), i(&e["replay_epoch"]), &unb64(&e["value_b64"])).expect("claim id")
}

fn class_str(class: Option<V2ErrorClass>) -> &'static str {
    class.map_or("", |c| c.as_str())
}

fn error_label(class: Option<V2ErrorClass>) -> String {
    format!("error/{}", class_str(class))
}

fn strings(v: &Value) -> Vec<String> {
    arr(v).iter().map(s).collect()
}

/// As `v2_lifecycle.rs`: Go `checkV2CommittedDecision`.
fn check_committed_decision(at: &str, c: &CommittedV2Outcome, want: &Value) {
    let body = decode_verification_receipt_body_v2(&c.receipt_body()).expect("committed body");
    assert_eq!(
        (body.decision.as_str(), body.decision_reason.as_str()),
        (s(&want["decision"]).as_str(), s(&want["decision_reason"]).as_str()),
        "{at} committed decision"
    );
    for (field, got) in [
        ("trust_assessment", &body.trust_assessment),
        ("status_assessment", &body.status_assessment),
        ("context_assessment", &body.context_assessment),
    ] {
        let expected = s(&want[field]);
        assert!(expected.is_empty() || *got == expected, "{at} committed {field} {got}, want {expected}");
    }
    assert_eq!(c.allow_horizon().unwrap_or(0), i(&want["allow_horizon"]), "{at} allow horizon");
}

/// As `v2_lifecycle.rs`: Go `v2OwnerCapturingClaimStore`, recording the
/// evaluator owner token the claim store returns to the creator.
struct OwnerCapturingClaimStore {
    inner: Arc<dyn ClaimStoreV2>,
    owner: Mutex<Vec<u8>>,
}

impl V2AuthoritativeClock for OwnerCapturingClaimStore {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.inner.authoritative_time_v2(ctx)
    }
}

impl ClaimStoreV2 for OwnerCapturingClaimStore {
    fn claim_v2(&self, ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError> {
        let result = self.inner.claim_v2(ctx, claim);
        *self.owner.lock().unwrap() = result.as_ref().map(|r| r.owner_token.clone()).unwrap_or_default();
        result
    }
    fn finalize_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError> {
        self.inner
            .finalize_v2_claim(ctx, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until)
    }
    fn record_v2_evaluation_progress(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError> {
        self.inner.record_v2_evaluation_progress(ctx, claim_id, owner_token, progress)
    }
    fn load_v2_interrupted_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2InterruptedClaim, V2StoreError> {
        self.inner.load_v2_interrupted_claim(ctx, claim_id)
    }
    fn recover_interrupted_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, V2StoreError> {
        self.inner.recover_interrupted_v2_claim(ctx, claim_id, terminal_result, receipt_body)
    }
    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        self.inner.rate_at_finalization_view()
    }
}

/// The state an iteration's participants share, under one lock (Go
/// `v2RaceIteration.mu`).
#[derive(Default)]
struct Shared {
    committed: BTreeMap<String, Arc<CommittedV2Outcome>>,
    receipts: BTreeMap<String, Vec<u8>>,
    owners: BTreeMap<String, Vec<u8>>,
    /// Claim ID to committed receipt body, and claim IDs in first-recorded
    /// order.
    recorded: BTreeMap<String, Vec<u8>>,
    recorded_at: Vec<String>,
}

/// One iteration of one scenario (Go `v2RaceIteration`).
struct Iteration {
    store: Arc<Store>,
    rate_at_finalization: bool,
    shared: Mutex<Shared>,
}

impl Iteration {
    fn new(start: i64, rate_at_finalization: bool) -> Iteration {
        Iteration {
            store: new_store(start),
            rate_at_finalization,
            shared: Mutex::new(Shared::default()),
        }
    }

    fn claim_store(&self) -> Arc<dyn ClaimStoreV2> {
        if self.rate_at_finalization {
            self.store.with_rate_at_finalization()
        } else {
            self.store.clone()
        }
    }

    fn record(&self, claim_id: &str, body: &[u8]) {
        let mut sh = self.shared.lock().unwrap();
        if !sh.recorded.contains_key(claim_id) {
            sh.recorded.insert(claim_id.to_string(), body.to_vec());
            sh.recorded_at.push(claim_id.to_string());
        }
    }

    fn record_outcome(&self, request: &str, c: CommittedV2Outcome) {
        let (claim_id, body) = (c.claim_id(), c.receipt_body());
        self.shared.lock().unwrap().committed.insert(request.to_string(), Arc::new(c));
        self.record(&claim_id, &body);
    }

    /// Go `prepareVerify`: one verification of `name` at the current store
    /// clock, built before any participant starts.
    fn prepare_verify(&self, name: &str) -> (V2VerifyRequest, V2VerifyCallbacks) {
        let mut request = inputs()["requests"][name].clone();
        request["now"] = self.store.now().into();
        let (req, mut cb, _) = build_verify_request(&request, bundle_of(name), &Arc::new(Counts::default()));
        if self.rate_at_finalization {
            let view = self.store.with_rate_at_finalization();
            cb.claim_store = Some(view.clone());
            cb.rate = Some(view);
        } else {
            cb.claim_store = Some(self.store.clone());
        }
        (req, cb)
    }

    /// Go `verifyLabel`: the label of a verify outcome, recording a
    /// committed result.
    fn verify_label(&self, name: &str, outcome: V2VerifyOutcome) -> String {
        match outcome.stage {
            V2VerifyStage::Committed => {
                let c = outcome.committed.expect("committed outcome");
                let label = match decode_verification_receipt_body_v2(&c.receipt_body()) {
                    Ok(body) => format!("committed/{}/{}", body.decision, body.decision_reason),
                    Err(_) => "undecodable committed body".into(),
                };
                self.record_outcome(name, c);
                label
            }
            V2VerifyStage::Replay => format!("replay/{}", outcome.disposition.map_or("", |d| d.as_str())),
            stage => format!("{}/{}", stage.as_str(), class_str(outcome.error_class)),
        }
    }

    /// Go `recordResumed`: records a resumed handoff as a committed result
    /// of its claim, and reports whether its body equals the one recorded.
    fn record_resumed(&self, c: &CommittedV2Outcome) -> bool {
        let (claim_id, body) = (c.claim_id(), c.receipt_body());
        let mut sh = self.shared.lock().unwrap();
        if let Some(prior) = sh.recorded.get(&claim_id) {
            return *prior == body;
        }
        sh.recorded.insert(claim_id.clone(), body);
        sh.recorded_at.push(claim_id);
        true
    }

    /// Go `releaseLabel`.
    fn release_label(&self, ctx: &V2Context, request: &str) -> String {
        let c = {
            let sh = self.shared.lock().unwrap();
            sh.committed.get(request).cloned().unwrap_or_else(|| panic!("{request} was never committed"))
        };
        self.release_handoff_label(ctx, request, &c)
    }

    /// Go `releaseHandoffLabel`: releases handoff `c` with `request`'s last
    /// published receipt.
    fn release_handoff_label(&self, ctx: &V2Context, request: &str, c: &CommittedV2Outcome) -> String {
        let receipt = self.shared.lock().unwrap().receipts.get(request).cloned();
        let verifier_public = keys().public(&s(&inputs()["verifier_key"]));
        let log_id = s(&inputs()["log_id"]);
        let result = release_v2_decision(
            ctx,
            c,
            receipt.as_deref(),
            V2ReleaseConfig {
                verifier_public_key: &verifier_public,
                log_id: &log_id,
                claim_store: self.store.as_ref(),
                checkpoint: self.store.as_ref(),
            },
        );
        let Some(d) = result.decision() else {
            return format!("{}/{}", result.status.as_str(), result.reason);
        };
        match d.receipt() {
            Ok(r) => format!("released/{}/{}/{}", d.decision(), d.release_time(), r.sequence),
            Err(_) => "released with an undecodable receipt".into(),
        }
    }

    /// Preflight and claim `name` without evaluating (lifecycle claim_only):
    /// the claim result and the owner token the store returned.
    fn claim_only(&self, ctx: &V2Context, name: &str) -> Result<(String, V2ClaimDisposition, Vec<u8>), String> {
        let bundle = decode_proof_bundle_v2(&bundle_of(name)).expect("bundle");
        let now = self.store.now();
        let (req, _, _) = build_verify_request(&inputs()["requests"][name], Vec::new(), &Arc::new(Counts::default()));
        let pre = preflight_proof_bundle_v2(
            &bundle,
            req.expected.as_ref(),
            req.context_policy.as_ref(),
            &req.required_scope,
            &req.verifier_namespace,
            req.replay_epoch,
            &req.verifier_id,
            now,
            req.max_challenge_age_seconds,
            req.future_skew_seconds,
        );
        let pre = pre.map_err(|e| format!("preflight/{}", e.class.as_str()))?;
        let capturing = OwnerCapturingClaimStore {
            inner: self.claim_store(),
            owner: Mutex::new(Vec::new()),
        };
        let result = claim_proof_bundle_v2(ctx, &capturing, &bundle, &pre, &req.verifier_namespace, req.replay_epoch, now);
        let (claim, disposition, _) = result.map_err(|e| error_label(Some(e.class)))?;
        Ok((claim.claim_id, disposition, capturing.owner.into_inner().unwrap()))
    }

    /// Go `step`: one setup or after step; `want` overrides the step's
    /// expect.
    fn step(&self, at: &str, st: &Value, want: &Value) {
        let ctx = V2Context::background();
        let request = s(&st["request"]);
        match s(&st["op"]).as_str() {
            "set_time" => self.store.set_time(i(&st["time"])),
            "set_ack_withheld" => self.store.set_acknowledgement_withheld(b(&st["withheld"])),
            "verify" => {
                let (req, cb) = self.prepare_verify(&request);
                let outcome = verify_proof_bundle_v2(&ctx, &req, &cb);
                let disposition = s(&want["disposition"]);
                assert!(
                    outcome.stage.as_str() == s(&want["stage"])
                        && class_str(outcome.error_class) == s(&want["error_class"])
                        && (disposition.is_empty() || outcome.disposition.map(|d| d.as_str()) == Some(disposition.as_str())),
                    "{at} verify {request}: stage {} class {:?} disposition {:?} ({:?}), want {want}",
                    outcome.stage.as_str(),
                    outcome.error_class,
                    outcome.disposition,
                    outcome.error
                );
                if let Some(c) = &outcome.committed {
                    check_committed_decision(at, c, want);
                }
                self.verify_label(&request, outcome);
            }
            "claim_only" => {
                let (claim_id, disposition, owner) = match self.claim_only(&ctx, &request) {
                    Ok(claimed) => claimed,
                    Err(label) => panic!("{at} claim_only: {label}, want {want}"),
                };
                assert!(
                    want["error_class"].is_null() && disposition.as_str() == s(&want["disposition"]),
                    "{at} claim_only: disposition {}, want {want}",
                    disposition.as_str()
                );
                assert_eq!(claim_id, claim_id_of(&request), "{at} claim_only: not the request's protocol claim ID");
                self.shared.lock().unwrap().owners.insert(request, owner);
            }
            "recover" => {
                let result = recover_interrupted_claim_v2(&ctx, self.store.as_ref(), &claim_id_of(&request));
                let class = s(&want["error_class"]);
                if !class.is_empty() {
                    assert_eq!(class_str(v2_error_class_of(&result)), class, "{at} recover: {result:?}");
                    return;
                }
                let outcome = result.unwrap_or_else(|e| panic!("{at} recover: {e}"));
                check_committed_decision(at, &outcome, want);
                self.record_outcome(&request, outcome);
            }
            "resume" => {
                let result = resume_committed_claim_v2(&ctx, self.store.as_ref(), &claim_id_of(&request));
                let class = s(&want["error_class"]);
                if !class.is_empty() {
                    assert_eq!(class_str(v2_error_class_of(&result)), class, "{at} resume: {result:?}");
                    return;
                }
                let outcome = result.unwrap_or_else(|e| panic!("{at} resume: {e}"));
                check_committed_decision(at, &outcome, want);
                assert!(self.record_resumed(&outcome), "{at} resume: the resumed body differs from the committed one");
                self.shared.lock().unwrap().committed.insert(request, Arc::new(outcome));
            }
            "publish" => {
                let c = self.shared.lock().unwrap().committed[&request].clone();
                let wire = self
                    .store
                    .publish_v2_receipt(&ctx, &c.claim_id(), &c.receipt_body())
                    .unwrap_or_else(|e| panic!("{at} publish: {e:?}"));
                let receipt = decode_verification_receipt_v2(&wire).expect("published receipt");
                assert_eq!(receipt.sequence, i(&want["receipt_sequence"]), "{at} publish sequence");
                self.shared.lock().unwrap().receipts.insert(request, wire);
            }
            "release" => {
                let got = self.release_label(&ctx, &request);
                let expected = if s(&want["release_status"]) == V2ReleaseStatus::Released.as_str() {
                    format!(
                        "released/{}/{}/{}",
                        s(&want["decision"]),
                        i(&want["release_time"]),
                        i(&want["receipt_sequence"])
                    )
                } else {
                    format!("{}/{}", s(&want["release_status"]), s(&want["release_reason"]))
                };
                assert_eq!(got, expected, "{at} release");
            }
            other => panic!("{at}: op {other} is not a concurrency setup or after step"),
        }
    }

    /// Go `participant`: one participant's operation (other than verify and
    /// cancel, which the runner prepares) and its label.
    fn participant(&self, p: &Value) -> String {
        let ctx = V2Context::background();
        let request = s(&p["request"]);
        match s(&p["op"]).as_str() {
            "claim_only" => match self.claim_only(&ctx, &request) {
                Ok((_, disposition, _)) => disposition.as_str().to_string(),
                Err(label) => label,
            },
            op @ ("finalize" | "recover_direct") => {
                let claim_id = claim_id_of(&request);
                let owner = self.shared.lock().unwrap().owners.get(&request).cloned().unwrap_or_default();
                let (terminal, body) = (unb64(&p["terminal_b64"]), unb64(&p["body_b64"]));
                let store = self.claim_store();
                let result = if op == "finalize" {
                    store.finalize_v2_claim(&ctx, &claim_id, &owner, &terminal, &body, i(&p["allow_valid_until"]))
                } else {
                    store.recover_interrupted_v2_claim(&ctx, &claim_id, &terminal, &body)
                };
                match result {
                    Err(e) => error_label(e.class()),
                    Ok(true) => {
                        self.record(&claim_id, &body);
                        "committed".into()
                    }
                    Ok(false) => "identical".into(),
                }
            }
            "recover" => {
                match recover_interrupted_claim_v2(&ctx, self.store.as_ref(), &claim_id_of(&request)) {
                    Err(e) => error_label(Some(e.class)),
                    Ok(outcome) => {
                        let label = match decode_verification_receipt_body_v2(&outcome.receipt_body()) {
                            Ok(body) => format!("committed/{}/{}", body.decision, body.decision_reason),
                            Err(_) => "undecodable recovered body".into(),
                        };
                        self.record_outcome(&request, outcome);
                        label
                    }
                }
            }
            "resume" => match resume_committed_claim_v2(&ctx, self.store.as_ref(), &claim_id_of(&request)) {
                Err(e) => error_label(Some(e.class)),
                Ok(outcome) if !self.record_resumed(&outcome) => "resumed a body other than the committed one".into(),
                Ok(outcome) if s(&p["mode"]) == "release" => self.release_handoff_label(&ctx, &request, &outcome),
                Ok(outcome) => match decode_verification_receipt_body_v2(&outcome.receipt_body()) {
                    Ok(body) => format!("committed/{}/{}", body.decision, body.decision_reason),
                    Err(_) => "undecodable resumed body".into(),
                },
            },
            "release" => self.release_label(&ctx, &request),
            "acknowledge" => {
                let wire = self.shared.lock().unwrap().receipts.get(&request).cloned().unwrap_or_default();
                let Ok(receipt) = decode_verification_receipt_v2(&wire) else {
                    return "undecodable receipt".into();
                };
                let Ok(entry) = verification_receipt_v2_digest(&receipt) else {
                    return "undigestable receipt".into();
                };
                match self.store.acknowledge_v2_receipt(
                    &ctx,
                    &receipt.log_id,
                    receipt.sequence,
                    &receipt.previous_receipt_hash,
                    &entry,
                ) {
                    Ok(ack) => format!("acknowledged/{}", ack.timestamp),
                    Err(_) => "refused".into(),
                }
            }
            "set_time" => {
                self.store.set_time(i(&p["time"]));
                "done".into()
            }
            other => format!("unknown op {other}"),
        }
    }

    /// Go `receiptLogContiguous`: publish every recorded result, retrying
    /// entries blocked behind an earlier one, and require sequences 1..k.
    fn receipt_log_contiguous(&self) -> Result<(), String> {
        let ctx = V2Context::background();
        let (recorded, recorded_at) = {
            let sh = self.shared.lock().unwrap();
            (sh.recorded.clone(), sh.recorded_at.clone())
        };
        let mut published: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
        let mut progress = true;
        while progress {
            progress = false;
            for claim_id in &recorded_at {
                if published.contains_key(claim_id.as_str()) {
                    continue;
                }
                match self.store.publish_v2_receipt(&ctx, claim_id, &recorded[claim_id]) {
                    Err(V2StoreError::Unavailable(m)) if m == ERR_HEAD_OF_LINE_BLOCKED => continue,
                    Err(e) => return Err(format!("publish {claim_id}: {e:?}")),
                    Ok(wire) => {
                        published.insert(claim_id, wire);
                        progress = true;
                    }
                }
            }
        }
        let mut sequences = Vec::new();
        for claim_id in &recorded_at {
            let wire = published
                .get(claim_id.as_str())
                .ok_or_else(|| format!("claim {claim_id} never published (head of line blocked)"))?;
            let receipt = decode_verification_receipt_v2(wire).map_err(|e| e.to_string())?;
            let again = self.store.publish_v2_receipt(&ctx, claim_id, &recorded[claim_id]);
            if again.as_ref().ok() != Some(wire) {
                return Err(format!("claim {claim_id} republished differently ({:?})", again.err()));
            }
            sequences.push(receipt.sequence);
        }
        sequences.sort();
        if sequences.iter().enumerate().any(|(k, seq)| *seq != k as i64 + 1) {
            return Err(format!("receipt sequences {sequences:?}, want 1..{}", sequences.len()));
        }
        Ok(())
    }
}

/// Go `v2CheckConcurrencyInvariant` (every kind but receipt_log_contiguous).
fn check_invariant(inv: &Value, labels: &BTreeMap<String, Vec<String>>, all: &[String]) -> Result<(), String> {
    let groups = strings(&inv["groups"]);
    let of = || -> Vec<String> {
        if groups.is_empty() {
            return all.to_vec();
        }
        groups.iter().flat_map(|g| labels.get(g).cloned().unwrap_or_default()).collect()
    };
    let outcomes = strings(&inv["outcomes"]);
    match s(&inv["kind"]).as_str() {
        "allowed" => {
            if let Some(l) = of().into_iter().find(|l| !outcomes.contains(l)) {
                return Err(format!("outcome {l:?} of {groups:?} is not one of {outcomes:?}"));
            }
        }
        "count" => {
            let n = of().iter().filter(|l| outcomes.contains(l)).count() as i64;
            let (equals, at_most) = (inv["equals"].as_i64(), inv["at_most"].as_i64());
            let bound = |b: Option<i64>| b.map_or("-".to_string(), |n| n.to_string());
            if equals.is_some_and(|e| n != e) || at_most.is_some_and(|m| n > m) {
                return Err(format!(
                    "{n} outcomes of {groups:?} are in {outcomes:?}, want equals {}, at most {}",
                    bound(equals),
                    bound(at_most)
                ));
            }
        }
        "all_equal" => {
            let got = of();
            if got.iter().any(|l| *l != got[0]) {
                return Err(format!("outcomes of {groups:?} differ: {got:?}"));
            }
        }
        "one_winner" => {
            let winning = strings(&inv["winning"]);
            let by_group = inv["by_group"].as_object().expect("by_group");
            let group_labels = |g: &str| labels.get(g).cloned().unwrap_or_default();
            let winners: Vec<&String> =
                by_group.keys().filter(|g| group_labels(g).iter().any(|l| winning.contains(l))).collect();
            if winners.len() > 1 {
                return Err(format!("winning groups {winners:?}, want at most one"));
            }
            for (g, rule) in by_group {
                let want = strings(&rule[if winners.contains(&g) { "if_winner" } else { "if_loser" }]);
                if let Some(l) = group_labels(g).into_iter().find(|l| !want.contains(l)) {
                    return Err(format!("group {g} (winners {winners:?}) has outcome {l:?}, not one of {want:?}"));
                }
            }
        }
        other => return Err(format!("unknown invariant kind {other}")),
    }
    Ok(())
}

/// Go `v2MeasureVerification`: the duration of one uncancelled verification
/// of the request group `target` verifies, on a scratch store.
fn measure_verification(start: i64, rate_at_finalization: bool, participants: &[Value], target: &str) -> Duration {
    let p = participants
        .iter()
        .find(|p| s(&p["group"]) == target && s(&p["op"]) == "verify")
        .unwrap_or_else(|| panic!("cancel target {target} has no verify participant"));
    let it = Iteration::new(start, rate_at_finalization);
    let (req, cb) = it.prepare_verify(&s(&p["request"]));
    let began = Instant::now();
    verify_proof_bundle_v2(&V2Context::background(), &req, &cb);
    began.elapsed()
}

/// The iteration count of an unoptimized build when RATIFY_RACE_ITERATIONS
/// is unset. Hybrid signing and verification are slow without
/// optimization, so the file's default_iterations (20) would add minutes to
/// `cargo test`; an optimized build (`cargo test --release`) runs the file's
/// count. Set RATIFY_RACE_ITERATIONS=20 to run the full count in any build.
const DEBUG_DEFAULT_ITERATIONS: u64 = 3;

/// Go `v2RaceIterations`: RATIFY_RACE_ITERATIONS, else the file's
/// default_iterations (DEBUG_DEFAULT_ITERATIONS in an unoptimized build).
fn race_iterations() -> u64 {
    match std::env::var("RATIFY_RACE_ITERATIONS") {
        Ok(v) => v
            .parse()
            .ok()
            .filter(|n| *n >= 1)
            .unwrap_or_else(|| panic!("RATIFY_RACE_ITERATIONS={v:?} is not a positive integer")),
        Err(_) if cfg!(debug_assertions) => DEBUG_DEFAULT_ITERATIONS,
        Err(_) => u(&file()["default_iterations"]),
    }
}

/// The cancel delay of iteration `iter` of `iterations`, in tenths of a
/// measured verification: 0 to 12.
fn tenth(iter: u64, iterations: u64) -> u32 {
    let k = if iterations >= 13 { iter % 13 } else { iter * 12 / (iterations - 1).max(1) };
    k as u32
}

/// What one participant runs once the barrier releases it.
enum Run {
    Verify {
        name: String,
        req: Box<V2VerifyRequest>,
        cb: V2VerifyCallbacks,
        ctx: V2Context,
    },
    Cancel {
        delay: Duration,
        target: String,
    },
    Op(Value),
}

#[test]
fn concurrency_scenarios() {
    let f = file();
    let scenarios = arr(&f["scenarios"]);
    assert!(
        i(&f["version"]) == 1 && !scenarios.is_empty(),
        "concurrency-scenarios.json version {} with {} scenarios",
        i(&f["version"]),
        scenarios.len()
    );
    let iterations = race_iterations();
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let start = i(&sc["start_time"]);
        let rate_at_finalization = b(&sc["rate_at_finalization"]);
        let participants = arr(&sc["participants"]);
        // Each distinct outcome per group across iterations, printed so a
        // --nocapture run shows which interleavings occurred.
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        // The duration of one uncancelled verification of a cancel target,
        // measured once per scenario.
        let mut span: Option<Duration> = None;
        let began = Instant::now();
        for iter in 0..iterations {
            let it = Iteration::new(start, rate_at_finalization);
            for (k, st) in arr(&sc["setup"]).iter().enumerate() {
                it.step(&format!("{name} iteration {iter} setup step {k}"), st, &st["expect"]);
            }
            // Prepare every participant on this thread, then release them
            // together.
            let mut slots: Vec<(String, Run)> = Vec::new();
            let mut cancels: BTreeMap<String, Vec<V2CancelHandle>> = BTreeMap::new();
            for p in &participants {
                let group = s(&p["group"]);
                for _ in 0..u(&p["count"]) {
                    let run = match s(&p["op"]).as_str() {
                        "verify" => {
                            let request = s(&p["request"]);
                            let (req, cb) = it.prepare_verify(&request);
                            let (ctx, cancel) = V2Context::background().with_cancel();
                            cancels.entry(group.clone()).or_default().push(cancel);
                            Run::Verify {
                                name: request,
                                req: Box::new(req),
                                cb,
                                ctx,
                            }
                        }
                        "cancel" => {
                            let target = s(&p["target"]);
                            // Spread the signal over the target's verification
                            // across iterations: 0 to 1.2 times its duration in
                            // tenths (Go: iteration mod 13), stretched over the
                            // whole range when there are fewer than 13
                            // iterations.
                            let span = *span.get_or_insert_with(|| {
                                measure_verification(start, rate_at_finalization, &participants, &target)
                            });
                            Run::Cancel {
                                delay: span * tenth(iter, iterations) / 10,
                                target,
                            }
                        }
                        _ => Run::Op(p.clone()),
                    };
                    slots.push((group.clone(), run));
                }
            }
            let barrier = Barrier::new(slots.len());
            let results: Vec<String> = std::thread::scope(|scope| {
                let handles: Vec<_> = slots
                    .iter()
                    .map(|(_, run)| {
                        let (it, barrier, cancels) = (&it, &barrier, &cancels);
                        scope.spawn(move || {
                            barrier.wait();
                            match run {
                                Run::Verify { name, req, cb, ctx } => {
                                    it.verify_label(name, verify_proof_bundle_v2(ctx, req, cb))
                                }
                                Run::Cancel { delay, target } => {
                                    std::thread::sleep(*delay);
                                    cancels.get(target).into_iter().flatten().for_each(V2CancelHandle::cancel);
                                    "done".into()
                                }
                                Run::Op(p) => it.participant(p),
                            }
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().expect("participant thread")).collect()
            });
            cancels.values().flatten().for_each(V2CancelHandle::cancel);
            let mut labels: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for ((group, _), label) in slots.iter().zip(&results) {
                labels.entry(group.clone()).or_default().push(label.clone());
                *seen.entry(format!("{group}:{label}")).or_default() += 1;
            }
            for inv in arr(&sc["invariants"]) {
                let kind = s(&inv["kind"]);
                let checked = if kind == "receipt_log_contiguous" {
                    it.receipt_log_contiguous()
                } else {
                    check_invariant(&inv, &labels, &results)
                };
                if let Err(e) = checked {
                    panic!("{name} iteration {iter}: invariant {kind}: {e} (outcomes {labels:?})");
                }
            }
            for (k, st) in arr(&sc["after"]).iter().enumerate() {
                let at = format!("{name} iteration {iter} after step {k}");
                let by_outcome = &st["expect_by_outcome"];
                let want = if by_outcome.is_null() {
                    &st["expect"]
                } else {
                    let group = s(&by_outcome["group"]);
                    let got = labels.get(&group).cloned().unwrap_or_default();
                    assert_eq!(got.len(), 1, "{at}: expect_by_outcome group {group} has {} participants", got.len());
                    let case = &by_outcome["cases"][&got[0]];
                    assert!(!case.is_null(), "{at}: no case for outcome {}", got[0]);
                    case
                };
                it.step(&at, st, want);
            }
        }
        println!("{name}: {iterations} iterations in {:.1?}, outcomes {seen:?}", began.elapsed());
    }
}
