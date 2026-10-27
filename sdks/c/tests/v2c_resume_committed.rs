//! Resumption of committed work from the claim store (SPEC-v2 §7.11)
//! through the C ABI only: `ratify_v2_resume_committed_claim` against the
//! reference store's `load_committed` callback, and against callbacks that
//! answer with a damaged record. Mirrors Go `resume_committed_v2_test.go`
//! and sdks/rust/tests/v2_resume_committed.rs.

mod v2c_common;

use std::cell::RefCell;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::{Arc, OnceLock};

use ratify_c::*;
use serde_json::{json, Value};
use v2c_common::*;

fn file() -> &'static Value {
    static F: OnceLock<Value> = OnceLock::new();
    F.get_or_init(|| load("lifecycle-scenarios.json"))
}

fn keys() -> &'static Fixture {
    static K: OnceLock<Fixture> = OnceLock::new();
    K.get_or_init(Fixture::load)
}

fn new_store(log_id: &str) -> RefStore {
    let f = file();
    RefStore::new(
        1_800_000_000,
        i(&f["lease_seconds"]),
        log_id,
        keys().kp(&s(&f["verifier_key"])),
    )
}

/// Request "A" of the lifecycle corpus (an allow) against `store`.
fn setup_a(store: &RefStore) -> (Box<Setup>, Vec<u8>) {
    let f = file();
    let mut inputs = f["requests"]["A"].clone();
    inputs["now"] = store.now().into();
    let mut setup = Setup::build(&inputs, &Arc::new(Counts::default()), true);
    setup.claim_cb = Some(store.claim(false));
    (setup, b64(&f["bundles_b64"][s(&inputs["bundle"])]))
}

/// A committed allow on the reference store (Go `v2ReleaseFixture`).
fn committed_allow() -> (RefStore, Committed) {
    let store = new_store(&s(&file()["log_id"]));
    let (setup, bundle) = setup_a(&store);
    let outcome = verify(&setup, &bundle).expect("verify");
    assert_eq!(outcome.stage, "committed", "{}", outcome.message);
    (store, outcome.committed.expect("committed"))
}

fn resume(store: &RatifyV2CommittedStoreCallbacks, claim_id: &str) -> R<Committed> {
    let id = cs(claim_id);
    let mut out: *mut RatifyV2Committed = ptr::null_mut();
    let code = unsafe { ratify_v2_resume_committed_claim(store, id.as_ptr(), &mut out) };
    let r = check(code);
    let c = (!out.is_null()).then_some(Committed(out));
    assert_eq!(
        r.is_ok(),
        c.is_some(),
        "an output is written exactly on success"
    );
    r.map(|_| c.expect("committed outcome"))
}

/// Release `c` with the published `receipt`; returns the status name and,
/// when released, the decision.
fn release(store: &RefStore, c: &Committed, receipt: &[u8]) -> (String, String) {
    let key = keys().key(&s(&file()["verifier_key"]));
    let log = cs(&s(&file()["log_id"]));
    let (release_cb, checkpoint) = (store.release(), store.checkpoint());
    let (mut status, mut reason, mut released) = (0i32, ptr::null_mut(), ptr::null_mut());
    let code = unsafe {
        ratify_v2_release_decision(
            c.0,
            slice(receipt),
            &key,
            log.as_ptr(),
            &release_cb,
            &checkpoint,
            &mut status,
            &mut reason,
            &mut released,
        )
    };
    check(code).expect("release");
    take_str(reason);
    let decision = if released.is_null() {
        String::new()
    } else {
        let d = string(|o| unsafe {
            ratify_v2_released_string(
                released,
                RatifyV2ReleasedField::RatifyV2ReleasedDecision as i32,
                o,
            )
        })
        .unwrap();
        unsafe { ratify_v2_released_free(released) };
        d
    };
    let name = unsafe { cstr_in(ratify_v2_release_status_str(status)) };
    (name, decision)
}

// SPEC-v2 §7.11: a service whose handoff died after the terminal commit
// resumes it from the store, and the resumed handoff is the committed one:
// publication and release answer it exactly as the original.
#[test]
fn v2c_resume_returns_the_committed_handoff() {
    let (store, committed) = committed_allow();
    let resumed = resume(&store.committed(), &committed.claim_id()).expect("resume");
    assert_eq!(resumed.claim_id(), committed.claim_id());
    assert_eq!(resumed.body(), committed.body());
    assert_eq!(resumed.expires_at(), committed.expires_at());
    assert!(committed.allow_horizon().is_some());
    assert_eq!(resumed.allow_horizon(), committed.allow_horizon());
    // The original handoff is dropped, as by a crash before it returned.
    let claim_id = committed.claim_id();
    drop(committed);
    let wire = store.publish(&claim_id, &resumed.body()).expect("publish");
    assert_eq!(
        release(&store, &resumed, &wire),
        ("released".into(), "allow".into())
    );
    assert_eq!(
        release(&store, &resumed, &wire),
        ("released".into(), "allow".into()),
        "a repeated release is idempotent"
    );
}

// The store's answers for a claim with no committed record pass through with
// their class; resumption commits nothing.
#[test]
fn v2c_resume_refuses_a_claim_with_no_committed_record() {
    let (store, committed) = committed_allow();
    assert_eq!(
        class_of(&resume(&store.committed(), "unknown-claim")),
        "claim_not_found"
    );
    let evaluating = new_store(&"ab".repeat(16));
    let (setup, bundle) = setup_a(&evaluating);
    let claim_cb = evaluating.claim(false);
    let mut disposition = 0;
    let claim_id = string(|o| unsafe {
        ratify_v2_claim_proof_bundle(
            bundle.as_ptr(),
            bundle.len(),
            setup.request.as_ptr(),
            setup.request.len(),
            &claim_cb,
            &mut disposition,
            o,
        )
    })
    .expect("claim");
    assert_eq!(claim_id, committed.claim_id());
    assert_eq!(
        class_of(&resume(&evaluating.committed(), &claim_id)),
        "claim_lease_live"
    );
    evaluating.set_time(evaluating.now() + i(&file()["lease_seconds"]));
    assert_eq!(
        class_of(&resume(&evaluating.committed(), &claim_id)),
        "claim_lease_lost"
    );
    let release_cb = evaluating.release();
    let mut terminal = unsafe { std::mem::zeroed::<RatifyV2TerminalClaim>() };
    let id = cs(&claim_id);
    let code =
        unsafe { (release_cb.load_terminal.unwrap())(release_cb.user, id.as_ptr(), &mut terminal) };
    assert!(
        code == 0 && terminal.terminal == 0,
        "resumption committed a result"
    );

    // No store, no callback, or no claim ID.
    let id = cs(&claim_id);
    let mut out = ptr::null_mut();
    let code = unsafe { ratify_v2_resume_committed_claim(ptr::null(), id.as_ptr(), &mut out) };
    assert!(out.is_null() && code == RatifyV2Code::RatifyV2ErrNullPointer as i32);
    let unset = RatifyV2CommittedStoreCallbacks {
        user: ptr::null_mut(),
        load_committed: None,
    };
    assert_eq!(
        class_of(&resume(&unset, &claim_id)),
        "claim_store_unavailable"
    );
    assert_eq!(
        class_of(&resume(&store.committed(), "")),
        "configuration_invalid"
    );
}

/// The record a damaged-store callback answers with. `null` sends the
/// matching slice as NULL with a non-zero length; `forged` sends it with a
/// length over `isize::MAX`.
struct Answer {
    record: Vec<u8>,
    terminal: Vec<u8>,
    body: Vec<u8>,
    horizon: i64,
    null: [bool; 3],
    forged: [bool; 3],
}

type EditFn = dyn Fn(&mut Answer) -> i32;

/// Go `v2CommittedRecordStore`: the reference store's answer, passed through
/// `edit` (a non-zero return is the callback's status).
struct Edited {
    inner: RatifyV2CommittedStoreCallbacks,
    edit: Box<EditFn>,
    keep: RefCell<Option<Answer>>,
}

impl Edited {
    fn callbacks(&self) -> RatifyV2CommittedStoreCallbacks {
        RatifyV2CommittedStoreCallbacks {
            user: self as *const Edited as *mut c_void,
            load_committed: Some(edited_load),
        }
    }
}

static ONE: [u8; 1] = [b'{'];

fn answer_slice(b: &[u8], null: bool, forged: bool) -> RatifyV2Slice {
    if null {
        RatifyV2Slice {
            ptr: ptr::null(),
            len: b.len().max(1),
        }
    } else if forged {
        RatifyV2Slice {
            ptr: ONE.as_ptr(),
            len: usize::MAX,
        }
    } else {
        slice(b)
    }
}

unsafe extern "C" fn edited_load(
    user: *mut c_void,
    claim_id: *const c_char,
    out: *mut RatifyV2CommittedClaim,
) -> i32 {
    let e = &*(user as *const Edited);
    let code = (e.inner.load_committed.unwrap())(e.inner.user, claim_id, out);
    if code != 0 {
        return code;
    }
    let mut a = Answer {
        record: slice_in((*out).record),
        terminal: slice_in((*out).terminal_result),
        body: slice_in((*out).receipt_body),
        horizon: (*out).allow_horizon,
        null: [false; 3],
        forged: [false; 3],
    };
    let code = (e.edit)(&mut a);
    if code != 0 {
        return code;
    }
    let mut keep = e.keep.borrow_mut();
    let a = keep.insert(a);
    *out = RatifyV2CommittedClaim {
        record: answer_slice(&a.record, a.null[0], a.forged[0]),
        terminal_result: answer_slice(&a.terminal, a.null[1], a.forged[1]),
        receipt_body: answer_slice(&a.body, a.null[2], a.forged[2]),
        allow_horizon: a.horizon,
    };
    0
}

/// Rewrite the canonical claim record through `f`.
fn edit_record(a: &mut Answer, f: impl FnOnce(&mut Value)) {
    let mut v = parse(&a.record);
    f(&mut v);
    a.record = canon(&v);
}

fn derived_claim_id(record: &Value) -> String {
    let ns = s(&record["namespace"]);
    let digest =
        hex::decode(s(&record["challenge_digest"]).trim_start_matches("sha384:")).expect("digest");
    string(|o| unsafe {
        ratify_v2_claim_id_from_digest(
            ptr_of(ns.as_bytes()),
            ns.len(),
            i(&record["replay_epoch"]),
            ptr_of(&digest),
            digest.len(),
            o,
        )
    })
    .expect("claim id")
}

/// The committed allow rewritten as the canonical interrupted result
/// (SPEC-v2 §7.5) built from the initial progress.
fn interrupted(a: &mut Answer) -> i32 {
    let mut body = parse(&a.body);
    for (field, value) in [
        ("decision", json!("indeterminate")),
        ("decision_reason", json!("evaluation_interrupted")),
        ("identity_status", json!("authorization_unverified")),
        ("trust_assessment", json!("not_evaluated")),
        ("status_assessment", json!("not_evaluated")),
        ("context_assessment", json!("not_evaluated")),
        ("context_policy_digest", Value::Null),
        ("granted_scope", json!([])),
    ] {
        body[field] = value;
    }
    if let Some(evidence) = body.as_object_mut().and_then(|o| {
        o.iter_mut()
            .find(|(k, _)| k.starts_with("status_evidence"))
            .map(|(_, v)| v)
    }) {
        *evidence = json!([]);
    }
    a.body = canon(&body);
    a.terminal = canon(&json!({
        "decision": "indeterminate",
        "decision_reason": "evaluation_interrupted",
        "identity_status": "authorization_unverified",
    }));
    0
}

// Resumption applies the terminal compare-and-set's checks to the record the
// store returns (§7.3, §7.5, §6.8), and the C layer refuses a record that
// is not the canonical sealed claim or a slice no answer can have. Each is
// the store's failure, never a handoff.
#[test]
fn v2c_resume_refuses_a_record_that_fails_its_checks() {
    let (base, committed) = committed_allow();
    let claim_id = committed.claim_id();
    let unclassified = RatifyV2Code::RatifyV2StoreUnavailable as i32;
    let cases: Vec<(&str, Box<EditFn>)> = vec![
        (
            "record for another claim",
            Box::new(|a| {
                edit_record(a, |v| {
                    v["claim_id"] = json!("0".repeat(s(&v["claim_id"]).len()));
                });
                0
            }),
        ),
        (
            "well-formed record of a different claim",
            Box::new(|a| {
                edit_record(a, |v| {
                    v["replay_epoch"] = json!(i(&v["replay_epoch"]) + 1);
                    v["claim_id"] = json!(derived_claim_id(v));
                });
                0
            }),
        ),
        (
            "claim ID not derived from the replay key",
            Box::new(|a| {
                edit_record(a, |v| v["replay_epoch"] = json!(i(&v["replay_epoch"]) + 1));
                0
            }),
        ),
        (
            "challenge digest altered (still lowercase hex)",
            Box::new(|a| {
                edit_record(a, |v| {
                    let d = s(&v["challenge_digest"]);
                    let last = if d.ends_with('0') { "1" } else { "0" };
                    v["challenge_digest"] = json!(format!("{}{last}", &d[..d.len() - 1]));
                });
                0
            }),
        ),
        (
            "challenge digest not a sha384 digest",
            Box::new(|a| {
                edit_record(a, |v| {
                    v["challenge_digest"] = json!(s(&v["challenge_digest"]).to_uppercase());
                });
                0
            }),
        ),
        (
            "body for another agent",
            Box::new(|a| {
                edit_record(a, |v| {
                    v["agent_id"] = json!(format!("{}x", s(&v["agent_id"])))
                });
                0
            }),
        ),
        (
            "record not canonical",
            Box::new(|a| {
                a.record.push(b' ');
                0
            }),
        ),
        (
            "terminal result differs from the body",
            Box::new(|a| {
                let text = String::from_utf8(a.terminal.clone()).expect("utf-8");
                a.terminal = text.replacen("\"allow\"", "\"deny\"", 1).into_bytes();
                0
            }),
        ),
        (
            "allow with no horizon",
            Box::new(|a| {
                a.horizon = 0;
                0
            }),
        ),
        (
            "allow horizon outside the timestamp domain",
            Box::new(|a| {
                a.horizon = 253_402_300_800;
                0
            }),
        ),
        (
            "interrupted result with an allow horizon",
            Box::new(interrupted),
        ),
        (
            "NULL record with a length",
            Box::new(|a| {
                a.null[0] = true;
                0
            }),
        ),
        (
            "NULL terminal result with a length",
            Box::new(|a| {
                a.null[1] = true;
                0
            }),
        ),
        (
            "NULL receipt body with a length",
            Box::new(|a| {
                a.null[2] = true;
                0
            }),
        ),
        (
            "forged record length",
            Box::new(|a| {
                a.forged[0] = true;
                0
            }),
        ),
        (
            "forged terminal result length",
            Box::new(|a| {
                a.forged[1] = true;
                0
            }),
        ),
        (
            "forged receipt body length",
            Box::new(|a| {
                a.forged[2] = true;
                0
            }),
        ),
        (
            "empty answer",
            Box::new(|a| {
                a.record.clear();
                a.terminal.clear();
                a.body.clear();
                0
            }),
        ),
        (
            "store failure without a class",
            Box::new(move |_| unclassified),
        ),
        (
            "store internal failure",
            Box::new(|_| RatifyV2Code::RatifyV2ErrInternal as i32),
        ),
    ];
    let mut failures = Vec::new();
    for (name, edit) in cases {
        let store = Edited {
            inner: base.committed(),
            edit,
            keep: RefCell::new(None),
        };
        match resume(&store.callbacks(), &claim_id) {
            Err(e) if e.class == "claim_store_unavailable" => {}
            Err(e) => failures.push(format!(
                "{name}: {} ({}), want claim_store_unavailable",
                e.class, e.message
            )),
            Ok(_) => failures.push(format!("{name}: a handoff was returned")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The interrupted result itself, with no horizon, is a valid record.
    let store = Edited {
        inner: base.committed(),
        edit: Box::new(|a| {
            a.horizon = 0;
            interrupted(a)
        }),
        keep: RefCell::new(None),
    };
    let resumed = resume(&store.callbacks(), &claim_id).expect("a valid interrupted record");
    assert_eq!(
        s(&body_json(&resumed.body())["decision_reason"]),
        "evaluation_interrupted"
    );
    assert_eq!(resumed.allow_horizon(), None);
}

/// A failed resume or recovery sets `*committed_out` to NULL, as verify and
/// release clear their outputs, so a caller that reuses the variable and
/// frees it on every path never frees a stale handle.
#[test]
fn v2c_failed_resume_and_recovery_clear_the_output() {
    type OutputCall<'a> = Box<dyn Fn(*mut *mut RatifyV2Committed) -> i32 + 'a>;
    let store = new_store(&s(&file()["log_id"]));
    let committed = store.committed();
    let claim = store.claim(false);
    let id = cs("unknown-claim");
    let empty = cs("");
    let stale = ptr::NonNull::<RatifyV2Committed>::dangling().as_ptr();
    let cases: Vec<(&str, OutputCall<'_>)> = vec![
        ("resume unknown claim", Box::new(|out| unsafe { ratify_v2_resume_committed_claim(&committed, id.as_ptr(), out) })),
        ("resume empty claim ID", Box::new(|out| unsafe { ratify_v2_resume_committed_claim(&committed, empty.as_ptr(), out) })),
        ("resume NULL store", Box::new(|out| unsafe { ratify_v2_resume_committed_claim(ptr::null(), id.as_ptr(), out) })),
        ("recover unknown claim", Box::new(|out| unsafe { ratify_v2_recover_interrupted_claim(&claim, id.as_ptr(), out) })),
        ("recover NULL store", Box::new(|out| unsafe { ratify_v2_recover_interrupted_claim(ptr::null(), id.as_ptr(), out) })),
    ];
    for (name, call) in cases {
        let mut out = stale;
        let code = call(&mut out);
        assert_ne!(code, 0, "{name} succeeded");
        assert!(out.is_null(), "{name} left a stale handle in the output");
    }
}
