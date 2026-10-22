//! testvectors/v2/"challenge-issuance.json" through the C ABI only:
//! `ratify_v2_issue_challenge` and `ratify_v2_load_expected_challenge` with
//! the reference issuance store and the reference Part B store's clock
//! behind their C callbacks and a C random source, and presentation through
//! `ratify_v2_claim_proof_bundle`. Mirrors
//! sdks/rust/tests/v2_challenge_issuance.rs.

mod v2c_common;

use std::os::raw::c_void;
use std::ptr;
use std::sync::Mutex;

use ratify_c::*;
use serde_json::{json, Value};
use v2c_common::*;

// Fixture namespace and replay epoch shared with the other corpus files.
const NAMESPACE: &str = "verify-test";
const EPOCH: i64 = 3;

/// The scenario's random bytes, consumed in order; running out fails.
struct Random(Mutex<(Vec<u8>, usize)>);

unsafe extern "C" fn random_fill(user: *mut c_void, out: *mut u8, len: usize) -> i32 {
    let r = &*(user as *const Random);
    let mut st = r.0.lock().unwrap();
    let (data, pos) = &mut *st;
    if *pos + len > data.len() {
        return RatifyV2Code::RatifyV2StoreUnavailable as i32;
    }
    std::ptr::copy_nonoverlapping(data[*pos..].as_ptr(), out, len);
    *pos += len;
    0
}

/// Callback structs that may cross threads (their users are live handles).
#[derive(Clone, Copy)]
struct Stores {
    issuance: RatifyV2IssuanceStoreCallbacks,
    claims: RatifyV2ClaimStoreCallbacks,
}
unsafe impl Send for Stores {}
unsafe impl Sync for Stores {}

fn load_expected(
    issuance: &RatifyV2IssuanceStoreCallbacks,
    ns: &str,
    epoch: i64,
    challenge: &[u8],
) -> R<Value> {
    let ns = cs(ns);
    buf(|o| unsafe {
        ratify_v2_load_expected_challenge(
            issuance,
            ns.as_ptr(),
            epoch,
            ptr_of(challenge),
            challenge.len(),
            o,
        )
    })
    .map(|b| parse(&b))
}

/// Go `v2PresentIssued`: retrieval, pre-claim checks and the atomic claim
/// for one presented bundle, naming the outcome. The claim stage reports a
/// pre-claim failure and a claim failure with their classes alike; a
/// `claim_replay` is the proof conflict.
fn present_issued(stores: &Stores, wire: &[u8], now: i64) -> String {
    let bundle = match canonicalize(2, wire) {
        Ok(_) => parse(wire),
        Err(e) => return format!("preflight:{}", e.class),
    };
    let expected = match load_expected(
        &stores.issuance,
        NAMESPACE,
        EPOCH,
        &b64(&bundle["challenge"]),
    ) {
        Ok(e) => e,
        Err(e) => return format!("preflight:{}", e.class),
    };
    let policy = match expected.get("expected_session_context_b64") {
        Some(ctx) => json!({
            "profile": "ratify.verify.session-context/v1",
            "require_bound": true,
            "required_fields": ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"],
            "expected_session_context_b64": ctx,
        }),
        None => {
            json!({"profile": "ratify.conformance.context-not-required/v1", "require_bound": false, "required_fields": []})
        }
    };
    let req = json_bytes(&json!({
        "required_scope": "data:read",
        "verifier_namespace": NAMESPACE,
        "replay_epoch": EPOCH,
        "now": now,
        "max_challenge_age_seconds": 300,
        "future_skew_seconds": 5,
        "expected_challenge": expected,
        "context_policy": policy,
    }));
    let mut disposition = 0i32;
    match string(|o| unsafe {
        ratify_v2_claim_proof_bundle(
            ptr_of(wire),
            wire.len(),
            req.as_ptr(),
            req.len(),
            &stores.claims,
            &mut disposition,
            o,
        )
    }) {
        Ok(_) => disposition_name(disposition).into(),
        Err(e) if e.class == "claim_replay" => "proof_conflict".into(),
        Err(e) => format!("preflight:{}", e.class),
    }
}

fn run_scenario(sc: &Value, fx: &Fixture) -> usize {
    let name = s(&sc["name"]);
    let mut random = Vec::new();
    for r in arr(&sc["random_b64"]) {
        random.extend(b64(&r));
    }
    let random = Random(Mutex::new((random, 0)));
    let steps = arr(&sc["steps"]);
    let claims = RefStore::new(
        i(&steps[0]["at"]),
        60,
        "0123456789abcdef0123456789abcdef",
        fx.kp("verifier"),
    );
    let issuance = {
        let mut out = ptr::null_mut();
        check(unsafe { ratify_v2_ref_issuance_new(&mut out) }).unwrap();
        out
    };
    let control = |fault: i32| -> (RatifyV2IssuanceStoreCallbacks, i64) {
        let mut cb = unsafe { std::mem::zeroed::<RatifyV2IssuanceStoreCallbacks>() };
        let mut n = 0i64;
        check(unsafe { ratify_v2_ref_issuance_control(issuance, fault, &mut cb, &mut n) }).unwrap();
        (cb, n)
    };
    let stores = Stores {
        issuance: control(-1).0,
        claims: claims.claim(false),
    };
    let clock = claims.clock();
    let random_cb = RatifyV2RandomCallbacks {
        user: &random as *const Random as *mut c_void,
        fill: Some(random_fill),
    };
    for (n, step) in steps.iter().enumerate() {
        let at = i(&step["at"]);
        if at != 0 {
            claims.set_time(at);
        }
        let exp = &step["expect"];
        match s(&step["op"]).as_str() {
            "issue" => {
                let r = &step["request"];
                let mut req = json!({
                    "verifier_namespace": r["verifier_namespace"],
                    "replay_epoch": r["replay_epoch"],
                    "verifier_id": r["verifier_id"],
                    "lifetime_seconds": r["lifetime_seconds"],
                });
                if !r["expected_agent"].is_null() {
                    let agent = s(&r["expected_agent"]);
                    req["expected_agent_id"] =
                        fx.id.get(&agent).cloned().unwrap_or_default().into();
                    let key = fx.key_json(&agent);
                    req["expected_agent_public_key"] = if key.is_null() {
                        json!({"ed25519": "", "ml_dsa_65": ""})
                    } else {
                        key
                    };
                }
                if !r["expected_receiver_id"].is_null() {
                    req["expected_receiver_id"] = r["expected_receiver_id"].clone();
                }
                if !r["expected_session_context_b64"].is_null() {
                    req["expected_session_context_b64"] = r["expected_session_context_b64"].clone();
                }
                match s(&step["persist_fault"]).as_str() {
                    "fail_before_commit" => {
                        control(1);
                    }
                    "fail_after_commit" => {
                        control(2);
                    }
                    _ => {}
                }
                let req_bytes = json_bytes(&req);
                let got = buf(|o| unsafe {
                    ratify_v2_issue_challenge(
                        req_bytes.as_ptr(),
                        req_bytes.len(),
                        &clock,
                        &stores.issuance,
                        &random_cb,
                        o,
                    )
                })
                .map(|b| parse(&b));
                match s(&exp["result"]).as_str() {
                    "issued" => {
                        let got = got
                            .unwrap_or_else(|e| panic!("{name} step {n}: issuance failed: {e:?}"));
                        assert!(
                            b64(&got["value_b64"]) == b64(&exp["challenge_b64"])
                                && i(&got["issued_at"]) == i(&exp["issued_at"])
                                && i(&got["expires_at"]) == i(&exp["expires_at"]),
                            "{name} step {n}: issued {got}"
                        );
                        let stored = load_expected(&stores.issuance, &s(&req["verifier_namespace"]), i(&req["replay_epoch"]), &b64(&got["value_b64"]))
                            .unwrap_or_else(|e| panic!("{name} step {n}: a returned challenge must already be durably retrievable: {e:?}"));
                        assert_eq!(
                            s(&stored["expected_agent_id"]),
                            s(&req["expected_agent_id"]),
                            "{name} step {n}"
                        );
                        assert_eq!(
                            stored.get("expected_session_context_b64"),
                            req.get("expected_session_context_b64"),
                            "{name} step {n}"
                        );
                    }
                    "error" => {
                        let e = got
                            .expect_err(&format!("{name} step {n}: issuance returned a challenge"));
                        let want = s(&exp["error_class"]);
                        if !want.is_empty() {
                            assert_eq!(e.class, want, "{name} step {n}: {}", e.message);
                        }
                    }
                    other => panic!("{name} step {n}: unknown issue result {other:?}"),
                }
                if !exp["records_after"].is_null() {
                    assert_eq!(
                        control(-1).1,
                        i(&exp["records_after"]),
                        "{name} step {n}: stored records"
                    );
                }
            }
            "load" => {
                let got = load_expected(
                    &stores.issuance,
                    NAMESPACE,
                    EPOCH,
                    &b64(&step["challenge_b64"]),
                );
                if s(&exp["result"]) == "found" {
                    let got = got.unwrap_or_else(|e| panic!("{name} step {n}: load: {e:?}"));
                    assert_eq!(
                        (i(&got["issued_at"]), i(&got["expires_at"])),
                        (i(&exp["issued_at"]), i(&exp["expires_at"])),
                        "{name} step {n}"
                    );
                } else {
                    let class = got.err().map(|e| e.class).unwrap_or_default();
                    assert_eq!(class, s(&exp["result"]), "{name} step {n}: load class");
                }
            }
            "present" | "present_concurrent" => {
                let wires: Vec<Vec<u8>> = arr(&step["bundles_b64"]).iter().map(b64).collect();
                let mut outcomes: Vec<String> = std::thread::scope(|scope| {
                    let handles: Vec<_> = wires
                        .iter()
                        .map(|wire| scope.spawn(move || present_issued(&stores, wire, at)))
                        .collect();
                    handles.into_iter().map(|h| h.join().unwrap()).collect()
                });
                outcomes.sort();
                let mut want: Vec<String> = match s(&exp["result"]).as_str() {
                    "preflight" => vec![format!("preflight:{}", s(&exp["error_class"]))],
                    "claimed" => arr(&exp["dispositions"]).iter().map(s).collect(),
                    other => panic!("{name} step {n}: unknown present result {other:?}"),
                };
                want.sort();
                assert_eq!(outcomes, want, "{name} step {n}: outcomes");
            }
            other => panic!("{name} step {n}: unknown op {other:?}"),
        }
    }
    unsafe { ratify_v2_ref_issuance_free(issuance) };
    steps.len()
}

#[test]
fn v2c_challenge_issuance() {
    let f = load("challenge-issuance.json");
    let fx = Fixture::load();
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no challenge issuance scenarios");
    let steps: usize = scenarios.iter().map(|sc| run_scenario(sc, &fx)).sum();
    let want: usize = scenarios.iter().map(|sc| arr(&sc["steps"]).len()).sum();
    assert_eq!(steps, want, "every issuance step must run");
    assert_eq!(
        (scenarios.len(), steps),
        (10, 36),
        "challenge-issuance.json"
    );
    println!(
        "C-ABI COVERAGE challenge-issuance.json: {} scenarios, {steps} steps",
        scenarios.len()
    );
    let readme = readme_line("challenge-issuance.json");
    assert!(
        readme.contains(&format!(
            "{} challenge issuance helper scenarios ({steps} steps",
            scenarios.len()
        )),
        "README row: {readme}"
    );
}
