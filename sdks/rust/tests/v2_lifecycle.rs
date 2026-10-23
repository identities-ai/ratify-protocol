//! Part B lifecycle and profile scenarios (testvectors/v2/
//! lifecycle-scenarios.json): Go `TestV2ConformanceLifecycleScenarios`,
//! `TestV2ConformanceProfileScenarios` (single-device offline profile,
//! SPEC-v2 §7.13, and dual-root composition profile, §7.14), and
//! `TestV2CancellationAfterClaimLeavesClaimRecoverable`.

mod v2_status_common;
mod v2_verify_common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ratify_protocol::v2::reference::*;
use ratify_protocol::v2::*;
use serde_json::Value;
use v2_verify_common::*;

fn file() -> &'static Value {
    static FILE: OnceLock<Value> = OnceLock::new();
    FILE.get_or_init(|| load_v2_vector("lifecycle-scenarios.json"))
}

fn keys() -> &'static v2_status_common::Fixture {
    static KEYS: OnceLock<v2_status_common::Fixture> = OnceLock::new();
    KEYS.get_or_init(v2_status_common::load_v2_keys)
}

fn new_store(now: i64, log_id: &str) -> Arc<Store> {
    let f = file();
    let private = keys().private.get(&s(&f["verifier_key"])).expect("verifier key");
    Arc::new(Store::new(now, i(&f["lease_seconds"]), log_id, private).expect("store"))
}

/// The request's ordering inputs with `now` (and optionally the configured
/// replay epoch) replaced.
fn request_inputs(name: &str, now: i64, epoch_override: i64) -> Value {
    let mut inputs = file()["requests"][name].clone();
    inputs["now"] = now.into();
    if epoch_override != 0 {
        inputs["configured_replay_epoch"] = epoch_override.into();
    }
    inputs
}

fn bundle_of(name: &str) -> Vec<u8> {
    let f = file();
    unb64(&f["bundles_b64"][s(&f["requests"][name]["bundle"])])
}

fn class_str(class: Option<V2ErrorClass>) -> &'static str {
    class.map_or("", |c| c.as_str())
}

struct FixedClock(i64);

impl V2AuthoritativeClock for FixedClock {
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        Ok(self.0)
    }
}

/// Go `checkV2CommittedDecision`: reads the committed receipt body for the
/// test only; applications must never authorize from it.
fn check_committed_decision(step: usize, c: &CommittedV2Outcome, want: &Value) {
    let body = decode_verification_receipt_body_v2(&c.receipt_body()).expect("committed body");
    assert_eq!(
        (body.decision.as_str(), body.decision_reason.as_str()),
        (s(&want["decision"]).as_str(), s(&want["decision_reason"]).as_str()),
        "step {step} committed decision"
    );
    for (field, got) in [
        ("trust_assessment", &body.trust_assessment),
        ("status_assessment", &body.status_assessment),
        ("context_assessment", &body.context_assessment),
    ] {
        let expected = s(&want[field]);
        assert!(expected.is_empty() || *got == expected, "step {step} committed {field} {got}, want {expected}");
    }
    assert_eq!(c.allow_horizon().unwrap_or(0), i(&want["allow_horizon"]), "step {step} allow horizon");
}

/// Go `checkV2ReleasedDecisionAllowed`: `allowed` compares the receiver's
/// authoritative time only with the sealed exclusive deadlines, and changing
/// values returned by the accessors does not change the decision.
fn check_released_decision_allowed(step: usize, d: &V2ReleasedDecision) {
    let ctx = V2Context::background();
    let at = |now: i64| d.allowed(&ctx, &FixedClock(now));
    let horizon = d.allow_horizon();
    assert_eq!(horizon.is_some(), d.decision() == "allow", "step {step}: allow horizon presence");
    let Some(horizon) = horizon else {
        assert!(!at(d.release_time()), "step {step}: a released {} is allowed", d.decision());
        return;
    };
    let deadline = horizon.min(d.challenge_expires_at());
    assert!(
        at(d.release_time()) && at(deadline - 1) && !at(deadline) && !at(deadline + 1),
        "step {step}: allowed does not end exactly at the exclusive deadline {deadline}"
    );
    let mut scope = d.granted_scope();
    scope.iter_mut().for_each(|x| *x = "mutated".into());
    let mut wire = d.receipt_wire();
    wire.iter_mut().for_each(|x| *x = 0);
    let mut receipt = d.receipt().expect("receipt");
    receipt.decision = "deny".into();
    receipt.sequence += 1;
    let again = d.receipt().expect("receipt");
    assert!(
        again.decision == "allow"
            && again.sequence == receipt.sequence - 1
            && !d.granted_scope().iter().any(|x| x == "mutated")
            && at(d.release_time()),
        "step {step}: a returned copy changed the released decision"
    );
}

/// Check a release result against the step expectation; returns the
/// released decision.
fn check_release(step: usize, result: V2ReleaseResult, want: &Value) -> Option<V2ReleasedDecision> {
    assert_eq!(
        (result.status.as_str(), result.reason.as_str()),
        (s(&want["release_status"]).as_str(), s(&want["release_reason"]).as_str()),
        "step {step} release"
    );
    assert_eq!(
        result.decision().is_some(),
        result.status == V2ReleaseStatus::Released,
        "decision presence does not match release status"
    );
    let d = result.into_decision()?;
    let receipt = d.receipt().expect("released receipt");
    assert_eq!(
        (d.decision(), d.release_time(), receipt.sequence),
        (s(&want["decision"]), i(&want["release_time"]), i(&want["receipt_sequence"])),
        "step {step} released decision"
    );
    check_released_decision_allowed(step, &d);
    Some(d)
}

/// Go `v2WrongEntryCheckpoint`: acknowledgements report a different entry
/// hash.
struct WrongEntryCheckpoint(Arc<Store>);

impl V2ReceiptCheckpoint for WrongEntryCheckpoint {
    fn acknowledge_v2_receipt(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous: &[u8],
        entry: &[u8],
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        self.0.acknowledge_v2_receipt(ctx, log_id, sequence, previous, entry)
    }

    fn get_v2_acknowledgement(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        let mut ack = self.0.get_v2_acknowledgement(ctx, log_id, sequence)?;
        ack.entry_hash[0] ^= 1;
        Ok(ack)
    }
}

/// Go `v2OwnerCapturingClaimStore`: records the evaluator owner token a
/// claim store returns to the creator, so a finalize step can call the store
/// directly.
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

/// The claim store of a scenario: the reference store, or its
/// rate-at-finalization view used as both claim and rate store.
fn claim_store_of(store: &Arc<Store>, rate_at_finalization: bool) -> (Arc<dyn ClaimStoreV2>, Option<Arc<dyn V2RateReservationStore>>) {
    if rate_at_finalization {
        let view = store.with_rate_at_finalization();
        (view.clone(), Some(view))
    } else {
        (store.clone(), None)
    }
}

fn publish_error_message(name: &str) -> &'static str {
    match name {
        "head_of_line_blocked" => ratify_protocol::v2::reference::store::ERR_HEAD_OF_LINE_BLOCKED,
        "signer_unavailable" => ratify_protocol::v2::reference::store::ERR_SIGNER_UNAVAILABLE,
        "log_frozen" => ratify_protocol::v2::reference::store::ERR_LOG_FROZEN,
        other => panic!("unknown publish error {other}"),
    }
}

/// Go `recoverStep`'s check of one recovery result.
fn check_recover(step: usize, result: V2Result<CommittedV2Outcome>, want: &Value) -> Option<CommittedV2Outcome> {
    let class = s(&want["error_class"]);
    if !class.is_empty() {
        assert_eq!(class_str(v2_error_class_of(&result)), class, "step {step} recover: {result:?}");
        return None;
    }
    let outcome = result.unwrap_or_else(|e| panic!("step {step} recover: {e}"));
    check_committed_decision(step, &outcome, want);
    Some(outcome)
}

type ClaimIds = (BTreeMap<String, String>, BTreeMap<String, String>);

/// Go `runVerify`: one verify step against the scenario store at its current
/// clock. Safe for concurrent use with mode "" (`verify_concurrent`). Returns
/// the outcome and, for `recover_during_status`, the recovery run inside the
/// status lookup.
fn run_verify(
    store: &Arc<Store>,
    rate_at_finalization: bool,
    request: &str,
    mode: &str,
    time: i64,
    epoch_override: i64,
    ids: &Mutex<ClaimIds>,
) -> (V2VerifyOutcome, Option<V2Result<CommittedV2Outcome>>) {
    let counts = Arc::new(Counts::default());
    let inputs = request_inputs(request, store.now(), epoch_override);
    let (req, mut cb, _) = build_verify_request(&inputs, bundle_of(request), &counts);
    let (claim_store, rate) = claim_store_of(store, rate_at_finalization);
    cb.claim_store = Some(claim_store);
    if rate.is_some() {
        cb.rate = rate;
    }
    let claim_id = protocol_claim_id_v2(
        &req.verifier_namespace,
        req.replay_epoch,
        &req.expected.as_ref().expect("expected challenge").value,
    )
    .expect("claim id");
    {
        let mut ids = ids.lock().unwrap();
        ids.0.insert(request.to_string(), claim_id.clone());
        ids.1.insert(claim_id.clone(), request.to_string());
    }
    let (vctx, cancel) = V2Context::background().with_cancel();
    let recovered: Arc<Mutex<Option<V2Result<CommittedV2Outcome>>>> = Arc::new(Mutex::new(None));
    match mode {
        "" => {}
        "cancel_before_claim" => cancel.cancel(),
        _ => {
            let provider = cb.status_evidence.clone().expect("status provider");
            let fired = Arc::new(AtomicUsize::new(0));
            let (store, recovered, mode, cancel) = (store.clone(), recovered.clone(), mode.to_string(), cancel.clone());
            cb.status_evidence = Some(Arc::new(move |c: &V2Context, r: &V2StatusEvidenceRequest| {
                if fired.fetch_add(1, Ordering::SeqCst) == 0 {
                    match mode.as_str() {
                        "cancel_during_status" => {
                            // The provider reports the caller's cancellation.
                            cancel.cancel();
                            return Err(V2StatusProviderError::new("context canceled"));
                        }
                        "recover_during_status" => {
                            store.set_time(time);
                            let result = recover_interrupted_claim_v2(c, store.as_ref(), &claim_id);
                            *recovered.lock().unwrap() = Some(result);
                        }
                        "expire_lease_during_status" | "regress_clock_during_status" => store.set_time(time),
                        other => panic!("unknown verify mode {other}"),
                    }
                }
                provider(c, r)
            }));
        }
    }
    let outcome = verify_proof_bundle_v2(&vctx, &req, &cb);
    let recovered = recovered.lock().unwrap().take();
    (outcome, recovered)
}

#[test]
fn lifecycle_scenarios() {
    let f = file();
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no lifecycle scenarios");
    let mut steps = 0usize;
    let verifier_public = keys().public(&s(&f["verifier_key"]));
    let ctx = V2Context::background();
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let rate_at_finalization = b(&sc["rate_at_finalization"]);
        let mut store = new_store(i(&sc["start_time"]), &s(&f["log_id"]));
        let mut log_id = s(&f["log_id"]);
        let mut owners: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut committed: BTreeMap<String, CommittedV2Outcome> = BTreeMap::new();
        let mut receipts: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        // (claim IDs by request name, request name by claim ID), written by
        // concurrent verify steps.
        let ids: Mutex<ClaimIds> = Mutex::new((BTreeMap::new(), BTreeMap::new()));
        let mut epoch_override = 0;
        steps += arr(&sc["steps"]).len();
        for (step_index, step) in arr(&sc["steps"]).iter().enumerate() {
            let want = &step["expect"];
            let now = store.now();
            let request = s(&step["request"]);
            let mode = s(&step["mode"]);
            let at = format!("{name} step {step_index}");
            match s(&step["op"]).as_str() {
                "set_time" => store.set_time(i(&step["time"])),
                "set_ack_withheld" => store.set_acknowledgement_withheld(b(&step["withheld"])),
                "verify" => {
                    let (outcome, recovered) = run_verify(
                        &store,
                        rate_at_finalization,
                        &request,
                        &mode,
                        i(&step["time"]),
                        epoch_override,
                        &ids,
                    );
                    if let Some(result) = recovered {
                        if let Some(c) = check_recover(step_index, result, &want["recovered"]) {
                            committed.insert(request.clone(), c);
                        }
                    }
                    let disposition = s(&want["disposition"]);
                    assert!(
                        outcome.stage.as_str() == s(&want["stage"])
                            && class_str(outcome.error_class) == s(&want["error_class"])
                            && (disposition.is_empty()
                                || outcome.disposition.map(|d| d.as_str()) == Some(disposition.as_str())),
                        "{at} verify {request}: stage {} class {:?} disposition {:?} ({:?}), want {want}",
                        outcome.stage.as_str(),
                        outcome.error_class,
                        outcome.disposition,
                        outcome.error
                    );
                    if let Some(c) = outcome.committed {
                        check_committed_decision(step_index, &c, want);
                        committed.insert(request.clone(), c);
                    }
                }
                "verify_concurrent" => {
                    let names: Vec<String> = arr(&step["requests"]).iter().map(s).collect();
                    let start = std::sync::Barrier::new(names.len());
                    let results: Vec<V2VerifyOutcome> = std::thread::scope(|scope| {
                        let handles: Vec<_> = names
                            .iter()
                            .map(|name| {
                                let (store, start, ids) = (&store, &start, &ids);
                                scope.spawn(move || {
                                    start.wait();
                                    run_verify(store, rate_at_finalization, name, "", 0, epoch_override, ids).0
                                })
                            })
                            .collect();
                        handles.into_iter().map(|h| h.join().expect("verify thread")).collect()
                    });
                    let mut got = Vec::new();
                    for (name, outcome) in names.iter().zip(results) {
                        let mut label = outcome.stage.as_str().to_string();
                        if matches!(outcome.stage, V2VerifyStage::Preflight | V2VerifyStage::Evaluating) {
                            label = format!("{label}/{}", class_str(outcome.error_class));
                        }
                        got.push(label);
                        if let Some(c) = outcome.committed {
                            committed.insert(name.clone(), c);
                        }
                    }
                    got.sort();
                    let expected: Vec<String> = arr(&want["outcomes"]).iter().map(s).collect();
                    assert_eq!(got, expected, "{at} verify_concurrent {names:?}");
                }
                "claim_only" => {
                    let bundle = decode_proof_bundle_v2(&bundle_of(&request)).expect("bundle");
                    let inputs = file()["requests"][&request].clone();
                    let (req, _, _) = build_verify_request(&inputs, Vec::new(), &Arc::new(Counts::default()));
                    let pre = preflight_proof_bundle_v2(
                        &bundle,
                        req.expected.as_ref(),
                        req.context_policy.as_ref(),
                        &req.required_scope,
                        &req.verifier_namespace,
                        req.replay_epoch,
                        now,
                        req.max_challenge_age_seconds,
                        req.future_skew_seconds,
                    )
                    .expect("preflight");
                    let (claim_store, _) = claim_store_of(&store, rate_at_finalization);
                    let capturing = OwnerCapturingClaimStore {
                        inner: claim_store,
                        owner: Mutex::new(Vec::new()),
                    };
                    let result = claim_proof_bundle_v2(
                        &ctx,
                        &capturing,
                        &bundle,
                        &pre,
                        &req.verifier_namespace,
                        req.replay_epoch,
                        now,
                    );
                    let class = class_str(v2_error_class_of(&result));
                    let (claim_id, disposition) = match &result {
                        Ok((claim, disposition, _)) => (claim.claim_id.clone(), disposition.as_str()),
                        Err(_) => (String::new(), ""),
                    };
                    assert_eq!(
                        (class, disposition),
                        (s(&want["error_class"]).as_str(), s(&want["disposition"]).as_str()),
                        "{at} claim_only"
                    );
                    let mut ids = ids.lock().unwrap();
                    ids.0.insert(request.clone(), claim_id.clone());
                    ids.1.insert(claim_id, request.clone());
                    owners.insert(request.clone(), capturing.owner.into_inner().unwrap());
                }
                "acknowledge" => {
                    let receipt = decode_verification_receipt_v2(&receipts[&request]).expect("receipt");
                    let mut entry = verification_receipt_v2_digest(&receipt).expect("entry hash");
                    match mode.as_str() {
                        "exact" => {}
                        "fork" => entry[0] ^= 1,
                        other => panic!("unknown acknowledge mode {other}"),
                    }
                    let ack = store.acknowledge_v2_receipt(
                        &ctx,
                        &receipt.log_id,
                        receipt.sequence,
                        &receipt.previous_receipt_hash,
                        &entry,
                    );
                    if b(&want["failed"]) {
                        assert!(ack.is_err(), "{at} acknowledge {mode}: {ack:?}, want refusal");
                        continue;
                    }
                    let ack = ack.unwrap_or_else(|e| panic!("{at} acknowledge: {e:?}"));
                    assert!(
                        ack.timestamp == i(&want["ack_timestamp"]) && ack.sequence == receipt.sequence && ack.entry_hash == entry,
                        "{at} acknowledge: {ack:?}, want timestamp {}",
                        i(&want["ack_timestamp"])
                    );
                }
                "finalize" => {
                    let (claim_store, _) = claim_store_of(&store, rate_at_finalization);
                    let claim_id = ids.lock().unwrap().0.get(&request).cloned().unwrap_or_default();
                    let owner = owners.get(&request).cloned().unwrap_or_default();
                    let finalized = claim_store.finalize_v2_claim(
                        &ctx,
                        &claim_id,
                        &owner,
                        &unb64(&step["terminal_b64"]),
                        &unb64(&step["body_b64"]),
                        i(&step["allow_valid_until"]),
                    );
                    let class = s(&want["error_class"]);
                    if !class.is_empty() {
                        let got = finalized.as_ref().err().and_then(V2StoreError::class);
                        assert!(
                            !matches!(finalized, Ok(true)) && class_str(got) == class,
                            "{at} finalize: {finalized:?}, want class {class}"
                        );
                        continue;
                    }
                    let got = match finalized {
                        Ok(true) => "committed",
                        Ok(false) => "identical",
                        Err(e) => panic!("{at} finalize: {e:?}"),
                    };
                    assert_eq!(got, s(&want["finalize_result"]), "{at} finalize");
                }
                "recover" => {
                    let claim_id = ids.lock().unwrap().0.get(&request).cloned().unwrap_or_else(|| {
                        // Never claimed: the request's own claim ID (claim_not_found).
                        let e = &file()["requests"][&request]["expected_challenge"];
                        protocol_claim_id_v2(&s(&e["verifier_namespace"]), i(&e["replay_epoch"]), &unb64(&e["value_b64"]))
                            .expect("claim id")
                    });
                    let result = recover_interrupted_claim_v2(&ctx, store.as_ref(), &claim_id);
                    if let Some(c) = check_recover(step_index, result, want) {
                        committed.insert(request.clone(), c);
                    }
                }
                "publish" => {
                    let c = &committed[&request];
                    if mode == "signer_failure" {
                        store.set_signer_failure(true);
                    }
                    let published = store.publish_v2_receipt(&ctx, &c.claim_id(), &c.receipt_body());
                    store.set_signer_failure(false);
                    if b(&want["failed"]) {
                        let expected = publish_error_message(&s(&want["publish_error"]));
                        assert!(
                            matches!(&published, Err(V2StoreError::Unavailable(m)) if m == expected),
                            "{at} publish: {published:?}, want failure {expected}"
                        );
                        continue;
                    }
                    let mut wire = published.unwrap_or_else(|e| panic!("{at} publish: {e:?}"));
                    let mut receipt = decode_verification_receipt_v2(&wire).expect("published receipt");
                    assert_eq!(receipt.sequence, i(&want["receipt_sequence"]), "{at} publish sequence");
                    if mode == "corrupt_signature" {
                        receipt.signature.ed25519[0] ^= 1;
                        wire = encode_verification_receipt_v2(&receipt).expect("encode");
                    }
                    receipts.insert(request.clone(), wire);
                }
                "abandon" => {
                    let got: Vec<String> = store
                        .abandon_pending_receipts()
                        .iter()
                        .map(|id| ids.lock().unwrap().1.get(id).cloned().unwrap_or_default())
                        .collect();
                    let expected: Vec<String> = arr(&want["abandoned"]).iter().map(s).collect();
                    assert_eq!(got, expected, "{at} abandon");
                }
                "restore" => match mode.as_str() {
                    "exact" => store = Arc::new(store.clone_store()),
                    "lost_state_epoch_bump" => {
                        log_id = s(&step["log_id"]);
                        store = new_store(now, &log_id);
                        epoch_override = i(&step["replay_epoch"]);
                    }
                    other => panic!("unknown restore mode {other}"),
                },
                "plant_release" => store.plant_release_test_only(&committed[&request].claim_id(), i(&step["time"])),
                "release" => {
                    let c = committed.get(&request).unwrap_or_else(|| panic!("{at}: {request} was never committed"));
                    let receipt_of = s(&step["receipt_of"]);
                    let mut receipt = receipts.get(if receipt_of.is_empty() { &request } else { &receipt_of });
                    if mode == "no_receipt" {
                        receipt = None;
                    }
                    let wrong = WrongEntryCheckpoint(store.clone());
                    let checkpoint: &dyn V2ReceiptCheckpoint = if s(&step["checkpoint"]) == "wrong_entry" {
                        &wrong
                    } else {
                        store.as_ref()
                    };
                    let result = release_v2_decision(
                        &ctx,
                        c,
                        receipt.map(Vec::as_slice),
                        V2ReleaseConfig {
                            verifier_public_key: &verifier_public,
                            log_id: &log_id,
                            claim_store: store.as_ref(),
                            checkpoint,
                        },
                    );
                    check_release(step_index, result, want);
                }
                "release_forged" => {
                    // Go releases a zero-value CommittedV2Outcome. In Rust the
                    // type is sealed (private fields, no Default), so a forged
                    // outcome cannot be constructed outside the crate; the
                    // crate's own unit test releases one and checks this
                    // expectation.
                    assert_eq!(
                        (s(&want["release_status"]).as_str(), s(&want["release_reason"]).as_str()),
                        ("rejected", "release_state_mismatch"),
                        "{at} release_forged"
                    );
                }
                other => panic!("unknown op {other}"),
            }
        }
    }
    assert_eq!((scenarios.len(), steps), (48, 271), "Part B scripts");
    let readme = readme_line("lifecycle-scenarios.json");
    assert!(readme.contains("48 Part B scripts (271 steps)"), "README row: {readme}");
}

// ---------------------------------------------------------------------------
// Profile scenarios (SPEC-v2 §7.13, §7.14)

/// Go `v2DeviceClock`: the device's one security clock is whichever primary
/// store is current (a rollback replaces the store, not the clock).
struct DeviceClock(Arc<Mutex<Arc<Store>>>);

impl V2AuthoritativeClock for DeviceClock {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        let store = self.0.lock().unwrap().clone();
        store.authoritative_time_v2(ctx)
    }
}

fn device_error_class(err: Option<&DeviceErrorTestOnly>) -> String {
    match err {
        None => String::new(),
        Some(DeviceErrorTestOnly::PowerLoss) => "power_loss".into(),
        Some(DeviceErrorTestOnly::StorageFull) => "storage_full".into(),
        Some(DeviceErrorTestOnly::StateMismatch) => "state_mismatch".into(),
        Some(DeviceErrorTestOnly::Frozen) => "frozen".into(),
        Some(DeviceErrorTestOnly::Store(e)) if e.class() == Some(V2ErrorClass::ClockRegressed) => {
            "clock_regressed".into()
        }
        Some(other) => format!("unexpected: {other}"),
    }
}

fn ledger_error_class(result: Result<(), ApprovalErrorTestOnly>) -> String {
    match result {
        Ok(()) => String::new(),
        Err(
            e @ (ApprovalErrorTestOnly::SetInvalid
            | ApprovalErrorTestOnly::NotReleased
            | ApprovalErrorTestOnly::ActionMismatch
            | ApprovalErrorTestOnly::RootMismatch
            | ApprovalErrorTestOnly::SlotFilled
            | ApprovalErrorTestOnly::Reused
            | ApprovalErrorTestOnly::Incomplete
            | ApprovalErrorTestOnly::Expired
            | ApprovalErrorTestOnly::AlreadyExecuted),
        ) => e.as_str().into(),
        Err(other) => format!("unexpected: {other}"),
    }
}

fn int_list(v: &Value) -> Vec<i64> {
    arr(v).iter().map(i).collect()
}

/// The single-device offline profile's components.
struct Device {
    component: Arc<DeviceComponentTestOnly>,
    primary: DevicePrimaryTestOnly,
    checkpoint: Arc<DeviceCheckpointTestOnly>,
    uplink: DeviceUplinkTestOnly,
}

fn bind_device(primary: DevicePrimaryTestOnly, component: Arc<DeviceComponentTestOnly>) -> Device {
    let checkpoint =
        Arc::new(DeviceCheckpointTestOnly::new(&primary, component.clone(), &component.public_key()).expect("checkpoint"));
    let uplink = DeviceUplinkTestOnly::new(checkpoint.clone());
    Device {
        component,
        primary,
        checkpoint,
        uplink,
    }
}

#[test]
fn profile_scenarios() {
    let f = file();
    let fx = keys();
    let scenarios = arr(&f["profile_scenarios"]);
    let mut profiles: BTreeMap<String, usize> = BTreeMap::new();
    for sc in &scenarios {
        *profiles.entry(s(&sc["profile"])).or_default() += 1;
    }
    assert!(
        profiles.get("single_device_offline").copied().unwrap_or(0) >= 16
            && profiles.get("dual_root").copied().unwrap_or(0) >= 13
            && profiles.len() == 2,
        "profile scenarios {profiles:?}"
    );
    let verifier_public = fx.public(&s(&f["verifier_key"]));
    let log_id = s(&f["log_id"]);
    let ctx = V2Context::background();
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let rate_at_finalization = b(&sc["rate_at_finalization"]);
        let mut store = new_store(i(&sc["start_time"]), &log_id);
        let slot = Arc::new(Mutex::new(store.clone()));
        let mut device = None;
        if s(&sc["profile"]) == "single_device_offline" {
            store.set_acknowledgement_withheld(true);
            let d = &sc["device"];
            let component = Arc::new(
                DeviceComponentTestOnly::new(
                    &unb64(&d["component_seed_b64"]),
                    u(&d["capacity"]) as usize,
                    Arc::new(DeviceClock(slot.clone())),
                )
                .expect("component"),
            );
            let primary = DevicePrimaryTestOnly::new(store.clone(), i(&d["replay_epoch"])).expect("primary");
            let bound = bind_device(primary, component);
            bound.checkpoint.provision().expect("provision");
            device = Some(bound);
        }
        let ledger = ApprovalLedgerTestOnly::new();
        let mut set_id = String::new();
        let mut committed: BTreeMap<String, CommittedV2Outcome> = BTreeMap::new();
        let mut receipts: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut decisions: BTreeMap<String, Option<Arc<V2ReleasedDecision>>> = BTreeMap::new();
        let mut snapshots: BTreeMap<String, DevicePrimaryTestOnly> = BTreeMap::new();
        for (step_index, step) in arr(&sc["steps"]).iter().enumerate() {
            let want = &step["expect"];
            let request = s(&step["request"]);
            let at = format!("{name} step {step_index}");
            let target = if s(&step["set"]).is_empty() { set_id.clone() } else { s(&step["set"]) };
            match s(&step["op"]).as_str() {
                "set_time" => store.set_time(i(&step["time"])),
                "set_ack_withheld" => store.set_acknowledgement_withheld(b(&step["withheld"])),
                "verify" => {
                    let inputs = request_inputs(&request, store.now(), 0);
                    let (req, mut cb, _) = build_verify_request(&inputs, bundle_of(&request), &Arc::new(Counts::default()));
                    let (claim_store, rate) = claim_store_of(&store, rate_at_finalization);
                    cb.claim_store = Some(claim_store);
                    if rate.is_some() {
                        cb.rate = rate;
                    }
                    let outcome = verify_proof_bundle_v2(&ctx, &req, &cb);
                    assert!(
                        outcome.stage.as_str() == s(&want["stage"]) && class_str(outcome.error_class) == s(&want["error_class"]),
                        "{at} verify {request}: stage {} class {:?} ({:?}), want {want}",
                        outcome.stage.as_str(),
                        outcome.error_class,
                        outcome.error
                    );
                    if let Some(c) = outcome.committed {
                        check_committed_decision(step_index, &c, want);
                        committed.insert(request.clone(), c);
                    }
                }
                "publish" => {
                    let c = &committed[&request];
                    let wire = store
                        .publish_v2_receipt(&ctx, &c.claim_id(), &c.receipt_body())
                        .unwrap_or_else(|e| panic!("{at} publish: {e:?}"));
                    let receipt = decode_verification_receipt_v2(&wire).expect("published receipt");
                    assert_eq!(receipt.sequence, i(&want["receipt_sequence"]), "{at} publish sequence");
                    receipts.insert(request.clone(), wire);
                }
                "release" => {
                    let checkpoint: &dyn V2ReceiptCheckpoint = if s(&step["checkpoint"]) == "device" {
                        device.as_ref().expect("device").checkpoint.as_ref()
                    } else {
                        store.as_ref()
                    };
                    let c = committed.get(&request).unwrap_or_else(|| panic!("{at}: {request} was never committed"));
                    let result = release_v2_decision(
                        &ctx,
                        c,
                        receipts.get(&request).map(Vec::as_slice),
                        V2ReleaseConfig {
                            verifier_public_key: &verifier_public,
                            log_id: &log_id,
                            claim_store: store.as_ref(),
                            checkpoint,
                        },
                    );
                    let decision = check_release(step_index, result, want);
                    decisions.insert(request.clone(), decision.map(Arc::new));
                }
                "device_power_loss" => {
                    let fault = match s(&step["mode"]).as_str() {
                        "before_commit" => DevicePowerLoss::BeforeCommit,
                        "after_commit" => DevicePowerLoss::AfterCommit,
                        other => panic!("unknown power loss mode {other}"),
                    };
                    device.as_ref().expect("device").component.set_power_loss(fault);
                }
                "device_submit" => {
                    let (acknowledged, err) = device.as_ref().expect("device").checkpoint.submit_pending(&ctx);
                    assert_eq!(
                        (acknowledged, device_error_class(err.as_ref())),
                        (int_list(&want["acknowledged"]), s(&want["device_error"])),
                        "{at} device_submit"
                    );
                }
                "device_resubmit" => {
                    let result = device.as_ref().expect("device").checkpoint.resubmit(&ctx, i(&step["sequence"]));
                    assert_eq!(device_error_class(result.as_ref().err()), s(&want["device_error"]), "{at} device_resubmit");
                    if let Ok(ack) = result {
                        assert_eq!(ack.timestamp, i(&want["ack_time"]), "{at} device_resubmit ack time");
                    }
                }
                "device_startup" => {
                    let got = device.as_ref().expect("device").checkpoint.startup();
                    assert_eq!(got.as_str(), s(&want["device_status"]), "{at} device_startup");
                }
                "snapshot" => {
                    let copy = device.as_ref().expect("device").primary.clone_primary();
                    snapshots.insert(s(&step["snapshot"]), copy);
                }
                "restore" => {
                    let now = store.now();
                    let primary = snapshots[&s(&step["snapshot"])].clone_primary();
                    store = primary.store.clone();
                    *slot.lock().unwrap() = store.clone();
                    store.set_time(now);
                    let component = device.take().expect("device").component;
                    device = Some(bind_device(primary, component));
                }
                "stage_status" => {
                    let journal = &device.as_ref().expect("device").primary.journal;
                    populate_status_journal(journal, &file()["requests"][&request]);
                }
                "plant_release" => store.plant_release_test_only(&committed[&request].claim_id(), i(&step["time"])),
                "corrupt_state" => store.corrupt_sealed_state_test_only(&committed[&request].claim_id()),
                "upload" => {
                    let got = device.as_ref().expect("device").uplink.upload(&ctx);
                    assert_eq!(got, int_list(&want["uploaded"]), "{at} upload");
                }
                "ledger_open" => {
                    let a = &step["approval_set"];
                    let roots = arr(&a["root_keys"]);
                    let request_hash = unb64(&a["request_hash_b64"]);
                    // The known-answer context must equal an independent §2.4
                    // derivation; the ledger derives its own and never reads it.
                    let derived = build_session_context_v2(&SessionContextV2Inputs {
                        verifier_id: s(&a["verifier_id"]),
                        workspace_id: s(&a["workspace_id"]),
                        agent_id: fx.id.get(&s(&a["agent_key"])).cloned().unwrap_or_default(),
                        session_id: s(&a["session_id"]),
                        invocation_id: s(&a["id"]),
                        request_hash: request_hash.clone(),
                    });
                    assert_eq!(
                        derived.ok(),
                        Some(unb64(&a["session_context_b64"])),
                        "{at} ledger_open: known-answer session context differs from the §2.4 derivation"
                    );
                    let result = ledger.open(ApprovalSetTestOnly {
                        approval_set_id: s(&a["id"]),
                        verifier_id: s(&a["verifier_id"]),
                        workspace_id: s(&a["workspace_id"]),
                        session_id: s(&a["session_id"]),
                        agent_public_key: fx.public(&s(&a["agent_key"])),
                        required_scope: s(&a["required_scope"]),
                        request_hash,
                        roots: [fx.public(&s(&roots[0])), fx.public(&s(&roots[1]))],
                    });
                    let ok = result.is_ok();
                    assert_eq!(ledger_error_class(result), s(&want["ledger_error"]), "{at} ledger_open");
                    if ok {
                        set_id = s(&a["id"]);
                    }
                }
                "ledger_record" => {
                    let decision = decisions.get(&request).and_then(Option::as_ref);
                    let result = ledger.record_approval(&target, u(&step["slot"]) as usize, decision, &bundle_of(&request));
                    let complete = *result.as_ref().unwrap_or(&false);
                    assert_eq!(
                        (complete, ledger_error_class(result.map(|_| ()))),
                        (b(&want["ledger_complete"]), s(&want["ledger_error"])),
                        "{at} ledger_record {request}"
                    );
                }
                "ledger_record_concurrent" => {
                    let names: Vec<String> = arr(&step["requests"]).iter().map(s).collect();
                    std::thread::scope(|scope| {
                        let handles: Vec<_> = names
                            .iter()
                            .enumerate()
                            .map(|(slot_index, name)| {
                                let (ledger, decisions, set_id) = (&ledger, &decisions, &set_id);
                                scope.spawn(move || {
                                    let decision = decisions.get(name).and_then(Option::as_ref);
                                    ledger.record_approval(set_id, slot_index, decision, &bundle_of(name))
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().expect("record thread").unwrap_or_else(|e| panic!("{at} ledger_record_concurrent: {e}"));
                        }
                    });
                    // An identical re-record reports the final state.
                    let decision = decisions.get(&names[0]).and_then(Option::as_ref);
                    let complete = ledger
                        .record_approval(&set_id, 0, decision, &bundle_of(&names[0]))
                        .unwrap_or_else(|e| panic!("{at} ledger_record_concurrent: {e}"));
                    assert_eq!(complete, b(&want["ledger_complete"]), "{at} ledger_record_concurrent");
                }
                "ledger_execute" => {
                    let got = ledger_error_class(ledger.execute(&ctx, &target, store.as_ref()));
                    assert_eq!(got, s(&want["ledger_error"]), "{at} ledger_execute");
                }
                "ledger_execute_concurrent" => {
                    let executed = AtomicUsize::new(0);
                    std::thread::scope(|scope| {
                        for _ in 0..u(&step["count"]) {
                            scope.spawn(|| match ledger.execute(&ctx, &set_id, store.as_ref()) {
                                Ok(()) => {
                                    executed.fetch_add(1, Ordering::SeqCst);
                                }
                                Err(ApprovalErrorTestOnly::AlreadyExecuted) => {}
                                Err(e) => panic!("concurrent execute: {e}"),
                            });
                        }
                    });
                    assert_eq!(executed.into_inner() as u64, u(&want["executed"]), "{at} ledger_execute_concurrent");
                }
                other => panic!("unknown profile op {other}"),
            }
        }
    }
}

/// Go `TestV2CancellationAfterClaimLeavesClaimRecoverable`: cancelling the
/// verification after the claim commits nothing; an exact retry sees the
/// claim in progress, and lease-expiry recovery terminalizes it (SPEC-v2
/// §6.11).
#[test]
fn cancellation_after_claim_leaves_claim_recoverable() {
    let f = file();
    const START: i64 = 1_800_000_000;
    let store = new_store(START, &s(&f["log_id"]));
    let inputs = request_inputs("A", START, 0);
    let (parent, cancel) = V2Context::background().with_cancel();
    let (req, mut cb, _) = build_verify_request(&inputs, bundle_of("A"), &Arc::new(Counts::default()));
    cb.claim_store = Some(store.clone());
    let provider = cb.status_evidence.clone().expect("status provider");
    cb.status_evidence = Some(Arc::new(move |c: &V2Context, r: &V2StatusEvidenceRequest| {
        cancel.cancel();
        provider(c, r)?;
        Err(V2StatusProviderError::new("context canceled"))
    }));
    let outcome = verify_proof_bundle_v2(&parent, &req, &cb);
    assert!(
        outcome.error.is_some()
            && outcome.stage == V2VerifyStage::Evaluating
            && outcome.error_class == Some(V2ErrorClass::EvaluationCancelled)
            && outcome.committed.is_none(),
        "cancelled evaluation: stage {} class {:?} err {:?}",
        outcome.stage.as_str(),
        outcome.error_class,
        outcome.error
    );
    let (retry_req, mut retry_cb, _) = build_verify_request(&inputs, bundle_of("A"), &Arc::new(Counts::default()));
    retry_cb.claim_store = Some(store.clone());
    let retry = verify_proof_bundle_v2(&V2Context::background(), &retry_req, &retry_cb);
    assert_eq!(
        (retry.stage, retry.disposition),
        (V2VerifyStage::Replay, Some(V2ClaimDisposition::InProgress)),
        "retry after cancellation"
    );
    let bg = V2Context::background();
    let live = recover_interrupted_claim_v2(&bg, store.as_ref(), &outcome.claim.claim_id);
    assert_eq!(v2_error_class_of(&live), Some(V2ErrorClass::ClaimLeaseLive), "recovery during a live lease");
    store.set_time(START + i(&f["lease_seconds"]));
    let committed = recover_interrupted_claim_v2(&bg, store.as_ref(), &outcome.claim.claim_id).expect("recover");
    let body = decode_verification_receipt_body_v2(&committed.receipt_body()).expect("body");
    assert_eq!(body.decision_reason, "evaluation_interrupted");
}

