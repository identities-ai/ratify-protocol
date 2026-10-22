//! testvectors/v2/verifier-ordering.json and transaction-verification.json
//! through the C ABI: `ratify_v2_verify_proof_bundle` and
//! `ratify_v2_verify_transaction_receipt` with every provider and store
//! implemented as C callbacks (the scripted claim store below, scripted
//! trust/status/audience/rate/binding providers, and the reference journal
//! behind a modal journal callback).

mod v2c_common;

use std::collections::BTreeMap;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::{Arc, Mutex};

use ratify_c::*;
use serde_json::Value;
use v2c_common::*;

/// Go `v2ScriptedClaimStore` as C callbacks: a single-claim test double.
struct ScriptedClaimStore {
    mode: String,
    claimed_at: i64,
    finalization_at: i64,
    counts: Arc<Counts>,
    final_body: Mutex<Vec<u8>>,
    expires_at: Mutex<i64>,
    token: Vec<u8>,
}

unsafe fn store<'a>(user: *mut c_void) -> &'a ScriptedClaimStore {
    &*(user as *const ScriptedClaimStore)
}

unsafe extern "C" fn sc_now(user: *mut c_void, out: *mut i64) -> i32 {
    *out = store(user).finalization_at;
    0
}

unsafe extern "C" fn sc_claim(user: *mut c_void, view: *const RatifyV2ClaimView, out: *mut RatifyV2ClaimResult) -> i32 {
    let st = store(user);
    st.counts.bump("claim");
    *st.expires_at.lock().unwrap() = (*view).expires_at;
    let result = |disposition: i32, token: bool| RatifyV2ClaimResult {
        disposition,
        claimed_at: st.claimed_at,
        owner_token: if token { slice(&st.token) } else { null_slice() },
    };
    match st.mode.as_str() {
        "create" => *out = result(1, true),
        "in_progress" => *out = result(2, false),
        "terminal_replay" => *out = result(3, false),
        "proof_conflict" => return RatifyV2Code::RatifyV2StoreClaimProofConflict as i32,
        _ => return RatifyV2Code::RatifyV2StoreUnavailable as i32,
    }
    0
}

unsafe extern "C" fn sc_finalize(
    user: *mut c_void,
    _claim_id: *const c_char,
    _token: RatifyV2Slice,
    _terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    allow_valid_until: i64,
    committed: *mut i32,
) -> i32 {
    let st = store(user);
    st.counts.bump("finalize");
    if st.finalization_at < st.claimed_at {
        return RatifyV2Code::RatifyV2ClockRegressed as i32;
    }
    let expires_at = *st.expires_at.lock().unwrap();
    if allow_valid_until > 0 && (st.finalization_at >= allow_valid_until || st.finalization_at >= expires_at) {
        return RatifyV2Code::RatifyV2AllowHorizonPassed as i32;
    }
    *st.final_body.lock().unwrap() = slice_in(body);
    *committed = 1;
    0
}

unsafe extern "C" fn sc_progress(user: *mut c_void, _id: *const c_char, _token: RatifyV2Slice, _p: RatifyV2Slice) -> i32 {
    store(user).counts.bump("progress");
    0
}

unsafe extern "C" fn sc_unused_load(_u: *mut c_void, _id: *const c_char, _o: *mut RatifyV2InterruptedClaim) -> i32 {
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}

unsafe extern "C" fn sc_unused_recover(_u: *mut c_void, _id: *const c_char, _t: RatifyV2Slice, _b: RatifyV2Slice, _c: *mut i32) -> i32 {
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}

impl ScriptedClaimStore {
    fn callbacks(&self) -> RatifyV2ClaimStoreCallbacks {
        RatifyV2ClaimStoreCallbacks {
            user: self as *const ScriptedClaimStore as *mut c_void,
            rate_at_finalization: 0,
            now: Some(sc_now),
            claim: Some(sc_claim),
            finalize: Some(sc_finalize),
            record_progress: Some(sc_progress),
            load_interrupted: Some(sc_unused_load),
            recover: Some(sc_unused_recover),
        }
    }
}

/// Run one ordering vector; returns mismatches (empty = pass).
fn run_vector(v: &Value, bundle: &[u8], builtin_standard: bool) -> Vec<String> {
    let mut failures = Vec::new();
    let counts = Arc::new(Counts::default());
    let mut setup = Setup::build(v, &counts, builtin_standard);
    let claimed_at = i(&v["now"]) + i(&v["claim_time_offset"]);
    let st = ScriptedClaimStore {
        mode: s(&v["claim_store"]),
        claimed_at,
        finalization_at: claimed_at + i(&v["finalize_time_offset"]),
        counts: Arc::clone(&counts),
        final_body: Mutex::new(Vec::new()),
        expires_at: Mutex::new(0),
        token: vec![7; 32],
    };
    setup.claim_cb = Some(st.callbacks());
    let outcome = match verify(&setup, bundle) {
        Ok(o) => o,
        Err(e) => return vec![format!("ABI call failed: {e:?}")],
    };
    let want = &v["expected"];
    let want_stage = s(&want["stage"]);
    if outcome.stage != want_stage {
        failures.push(format!("stage {} (class {:?}: {}), want {want_stage}", outcome.stage, outcome.class, outcome.message));
        return failures;
    }
    if outcome.class != s(&want["error_class"]) {
        failures.push(format!("error class {:?} ({}), want {:?}", outcome.class, outcome.message, s(&want["error_class"])));
    }
    let has_error = !outcome.class.is_empty();
    if has_error != (want_stage == "evaluating" || want_stage == "preflight") {
        failures.push(format!("error presence {has_error} does not match stage {want_stage}"));
    }
    let want_disposition = s(&want["disposition"]);
    if !want_disposition.is_empty() && outcome.disposition != want_disposition {
        failures.push(format!("disposition {}, want {want_disposition}", outcome.disposition));
    }
    let mut got_counts = counts.snapshot();
    let mut want_counts = Counts::expected(&want["callback_counts"]);
    if builtin_standard {
        // Built-in standard evaluators are not observable from C.
        got_counts.remove("evaluator");
        want_counts.remove("evaluator");
    }
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
    let body = committed.body();
    let r = body_json(&body);
    for k in ["decision", "decision_reason", "identity_status", "trust_assessment", "status_assessment", "context_assessment"] {
        if s(&r[k]) != s(&want[k]) {
            failures.push(format!("{k} {:?}, want {:?}", r[k], want[k]));
        }
    }
    if i(&r["verified_at"]) != i(&want["verified_at"]) {
        failures.push(format!("verified_at {}, want {}", r["verified_at"], want["verified_at"]));
    }
    if want.get("context_policy_digest").is_some() && r["context_policy_digest"] != want["context_policy_digest"] {
        failures.push(format!("context_policy_digest {}, want {}", r["context_policy_digest"], want["context_policy_digest"]));
    }
    if want.get("granted_scope").is_some() && r["granted_scope"] != want["granted_scope"] {
        failures.push(format!("granted_scope {}, want {}", r["granted_scope"], want["granted_scope"]));
    }
    if want.get("status_evidence").is_some() {
        let want_ev: Vec<Value> = arr(&want["status_evidence"]).iter().map(evidence_json).collect();
        let got_ev: Vec<Value> = arr(&r["status_evidence_digests"]).iter().map(evidence_json).collect();
        if got_ev != want_ev {
            failures.push(format!("status evidence {got_ev:?}, want {want_ev:?}"));
        }
    }
    let want_body = b64(&want["receipt_body_b64"]);
    if body != want_body || *st.final_body.lock().unwrap() != body {
        failures.push(format!(
            "receipt body differs:\n got {}\nwant {}",
            String::from_utf8_lossy(&body),
            String::from_utf8_lossy(&want_body)
        ));
    }
    let want_digest = string(|o| unsafe { ratify_v2_receipt_outbox_digest(want_body.as_ptr(), want_body.len(), o) }).unwrap();
    if committed.body_digest() != want_digest || committed.claim_id().is_empty() {
        failures.push("committed handoff digest or claim ID is wrong".into());
    }
    let horizon = committed.allow_horizon();
    let want_allow = s(&want["decision"]) == "allow";
    if horizon.is_some() != want_allow || horizon.unwrap_or(0) != i(&want["allow_valid_until"]) {
        failures.push(format!("allow horizon {horizon:?}, want {}", i(&want["allow_valid_until"])));
    }
    let want_batch = arr(&want["rate_batch"]);
    if !want_batch.is_empty() {
        let got = setup.rate_batch.lock().unwrap().clone();
        let want_batch: Vec<Rate> = want_batch
            .iter()
            .map(|w| Rate {
                issuer_id: s(&w["issuer_id"]),
                cert_id: s(&w["cert_id"]),
                window_s: i(&w["window_s"]),
                limit: i(&w["limit"]),
            })
            .collect();
        if got != want_batch {
            failures.push(format!("rate batch {got:?}, want {want_batch:?}"));
        }
    }
    failures
}

fn run_ordering(builtin_standard: bool) {
    let f = load("verifier-ordering.json");
    let bundles = f["bundles_b64"].as_object().expect("bundles_b64");
    let vectors = arr(&f["vectors"]);
    assert!(!vectors.is_empty(), "no ordering vectors");
    let mut stages: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for v in &vectors {
        let name = s(&v["name"]);
        let bundle = b64(bundles.get(&s(&v["bundle"])).unwrap_or_else(|| panic!("{name}: unknown bundle")));
        let result = run_vector(v, &bundle, builtin_standard);
        *stages.entry(s(&v["expected"]["stage"])).or_default() += 1;
        if !result.is_empty() {
            failures.push(format!("{name}:\n  {}", result.join("\n  ")));
        }
    }
    println!("C-ABI COVERAGE verifier-ordering.json (builtin_standard={builtin_standard}): {} vectors {stages:?}", vectors.len());
    assert!(failures.is_empty(), "{} of {} vectors failed:\n{}", failures.len(), vectors.len(), failures.join("\n"));
    // The README states the vector count and stage split.
    let readme = readme_line("verifier-ordering.json");
    let total = vectors.len().to_string();
    assert!(readme.contains(&format!("{total} end-to-end live-verifier cases")), "README row: {readme}");
}

/// Every ordering vector through the C callback interface, with the
/// standard evaluator profiles run as counted C evaluators.
#[test]
fn v2c_verifier_ordering() {
    run_ordering(false);
}

/// The same vectors with the library's built-in standard evaluators.
#[test]
fn v2c_verifier_ordering_builtin_standard_profiles() {
    run_ordering(true);
}

fn party_json(p: &Value) -> Value {
    serde_json::json!({
        "party_id": s(&p["party_id"]),
        "agent_id": s(&p["agent_id"]),
        "required_scope": s(&p["required_scope"]),
        "trust_assessment": s(&p["trust_assessment"]),
        "delegation_assessment": s(&p["delegation_assessment"]),
        "delegation_expires_at": p["delegation_expires_at"],
        "status_assessment": s(&p["status_assessment"]),
        "scope_assessment": s(&p["scope_assessment"]),
        "freshness": s(&p["freshness"]),
        "status_evidence_digests": arr(&p["status_evidence_digests"]).iter().map(evidence_json).collect::<Vec<_>>(),
    })
}

#[test]
fn v2c_transaction_verification() {
    let f = load("transaction-verification.json");
    let vectors = arr(&f["vectors"]);
    assert!(!vectors.is_empty(), "no transaction verification vectors");
    let (mut results, mut errors) = (0usize, 0usize);
    for v in &vectors {
        let name = s(&v["name"]);
        let counts = Arc::new(Counts::default());
        let setup = Setup::build(v, &counts, true);
        let config = serde_json::to_vec(&serde_json::json!({
            "status_keys": status_keys_json(&v["status_keys"]),
            "status_policy": v["status_policy"],
        }))
        .unwrap();
        let receipt = b64(&v["receipt_b64"]);
        let got = buf(|o| unsafe {
            ratify_v2_verify_transaction_receipt(
                ptr_of(&receipt),
                receipt.len(),
                i(&v["now"]),
                i(&v["future_skew_seconds"]),
                config.as_ptr(),
                config.len(),
                if v["trust"].is_null() { ptr::null() } else { setup.trust_ptr() },
                setup.status_ptr(),
                setup.journal_ptr(),
                o,
            )
        });
        let want_class = s(&v["expected"]["error_class"]);
        if !want_class.is_empty() {
            assert_eq!(class_of(&got), want_class, "{name}: {got:?}");
            errors += 1;
            continue;
        }
        let got = parse(&got.unwrap_or_else(|e| panic!("{name}: {e:?}")));
        let result = &v["expected"]["result"];
        let want = serde_json::json!({
            "transaction_id": s(&result["transaction_id"]),
            "actionable": b(&result["actionable"]),
            "parties": arr(&result["parties"]).iter().map(party_json).collect::<Vec<_>>(),
        });
        assert_eq!(got, want, "{name}");
        assert_eq!(got["actionable"], false, "{name}: never actionable");
        results += 1;
    }
    println!("C-ABI COVERAGE transaction-verification.json: {results} results, {errors} errors");
    assert_eq!(results + errors, vectors.len());
    assert!(results > 0 && errors > 0);
}
