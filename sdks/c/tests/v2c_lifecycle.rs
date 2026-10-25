//! Part B lifecycle and profile scenarios (testvectors/v2/
//! "lifecycle-scenarios.json") through the C ABI only: the reference store,
//! journal, device, and ledger are reached through `ratify_v2_ref_*` and
//! their C callback structs; verification, recovery, claim, and release go
//! through `ratify_v2_verify_proof_bundle`, `ratify_v2_recover_interrupted_claim`,
//! `ratify_v2_claim_proof_bundle`, and `ratify_v2_release_decision`. Mirrors
//! sdks/rust/tests/v2_lifecycle.rs.

mod v2c_common;

use std::collections::BTreeMap;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ratify_c::*;
use serde_json::{json, Value};
use v2c_common::*;

const FILE: &str = "lifecycle-scenarios.json";

fn file() -> &'static Value {
    static F: OnceLock<Value> = OnceLock::new();
    F.get_or_init(|| load(FILE))
}

fn keys() -> &'static Fixture {
    static K: OnceLock<Fixture> = OnceLock::new();
    K.get_or_init(Fixture::load)
}

fn new_store(now: i64, log_id: &str) -> RefStore {
    let f = file();
    RefStore::new(
        now,
        i(&f["lease_seconds"]),
        log_id,
        keys().kp(&s(&f["verifier_key"])),
    )
}

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
    b64(&f["bundles_b64"][s(&f["requests"][name]["bundle"])])
}

/// A fixture public key as wire JSON; an unknown name is the empty key (the
/// Rust harness's zero key).
fn pub_json(name: &str) -> Value {
    let k = keys().key_json(name);
    if k.is_null() {
        json!({"ed25519": "", "ml_dsa_65": ""})
    } else {
        k
    }
}

fn claim_id_of(inputs: &Value) -> String {
    let ns = s(&inputs["configured_namespace"]);
    let challenge = b64(&inputs["expected_challenge"]["value_b64"]);
    string(|o| unsafe {
        ratify_v2_claim_id(
            ptr_of(ns.as_bytes()),
            ns.len(),
            i(&inputs["configured_replay_epoch"]),
            ptr_of(&challenge),
            challenge.len(),
            o,
        )
    })
    .expect("claim id")
}

fn recover(claim_cb: &RatifyV2ClaimStoreCallbacks, claim_id: &str) -> R<Committed> {
    let id = cs(claim_id);
    let mut out: *mut RatifyV2Committed = ptr::null_mut();
    let code = unsafe { ratify_v2_recover_interrupted_claim(claim_cb, id.as_ptr(), &mut out) };
    let r = check(code);
    let c = (!out.is_null()).then_some(Committed(out));
    r.map(|_| c.expect("committed outcome"))
}

/// Go `checkV2CommittedDecision`: reads the committed body for the test
/// only; applications never authorize from it.
fn check_committed(at: &str, c: &Committed, want: &Value) {
    let body = body_json(&c.body());
    assert_eq!(
        (s(&body["decision"]), s(&body["decision_reason"])),
        (s(&want["decision"]), s(&want["decision_reason"])),
        "{at} committed decision"
    );
    for field in [
        "trust_assessment",
        "status_assessment",
        "context_assessment",
    ] {
        let expected = s(&want[field]);
        assert!(
            expected.is_empty() || s(&body[field]) == expected,
            "{at} committed {field} {}, want {expected}",
            body[field]
        );
    }
    assert_eq!(
        c.allow_horizon().unwrap_or(0),
        i(&want["allow_horizon"]),
        "{at} allow horizon"
    );
}

fn check_recover(at: &str, result: R<Committed>, want: &Value) -> Option<Committed> {
    let class = s(&want["error_class"]);
    if !class.is_empty() {
        assert_eq!(
            class_of(&result),
            class,
            "{at} recover: {:?}",
            result.as_ref().err()
        );
        return None;
    }
    let c = result.unwrap_or_else(|e| panic!("{at} recover: {e:?}"));
    check_committed(at, &c, want);
    Some(c)
}

// ---------------------------------------------------------------------------
// Released decisions

/// A released decision handle.
struct Released(*mut RatifyV2Released);

unsafe impl Send for Released {}
unsafe impl Sync for Released {}

impl Drop for Released {
    fn drop(&mut self) {
        unsafe { ratify_v2_released_free(self.0) };
    }
}

impl Released {
    fn field(&self, f: i32) -> String {
        string(|o| unsafe { ratify_v2_released_string(self.0, f, o) }).unwrap()
    }
    fn decision(&self) -> String {
        self.field(RatifyV2ReleasedField::RatifyV2ReleasedDecision as i32)
    }
    fn receipt(&self) -> Vec<u8> {
        buf(|o| unsafe { ratify_v2_released_receipt(self.0, o) }).unwrap()
    }
    fn scope(&self) -> Vec<u8> {
        buf(|o| unsafe { ratify_v2_released_granted_scope(self.0, o) }).unwrap()
    }
    /// (release_time, challenge_expires_at, allow_horizon)
    fn times(&self) -> (i64, i64, Option<i64>) {
        let (mut rt, mut exp, mut has, mut h) = (0, 0, 0, 0);
        check(unsafe { ratify_v2_released_times(self.0, &mut rt, &mut exp, &mut has, &mut h) })
            .unwrap();
        (rt, exp, (has != 0).then_some(h))
    }
    fn allowed_at(&self, now: i64) -> bool {
        let clock = Clock::fixed(now);
        let cb = clock.callbacks();
        unsafe { ratify_v2_released_allowed(self.0, &cb) == 1 }
    }
}

/// Go `checkV2ReleasedDecisionAllowed`: `allowed` compares only with the
/// sealed exclusive deadlines; accessors return copies.
fn check_released_allowed(at: &str, d: &Released) {
    let (release_time, expires, horizon) = d.times();
    assert_eq!(
        horizon.is_some(),
        d.decision() == "allow",
        "{at}: allow horizon presence"
    );
    let Some(horizon) = horizon else {
        assert!(
            !d.allowed_at(release_time),
            "{at}: a released {} is allowed",
            d.decision()
        );
        return;
    };
    let deadline = horizon.min(expires);
    assert!(
        d.allowed_at(release_time)
            && d.allowed_at(deadline - 1)
            && !d.allowed_at(deadline)
            && !d.allowed_at(deadline + 1),
        "{at}: allowed does not end exactly at the exclusive deadline {deadline}"
    );
    // Mutating returned copies never changes the decision.
    let (receipt, scope) = (d.receipt(), d.scope());
    let (mut r2, mut s2) = (receipt.clone(), scope.clone());
    r2.iter_mut().for_each(|x| *x = 0);
    s2.iter_mut().for_each(|x| *x = b'x');
    let again = parse(&d.receipt());
    assert!(
        d.receipt() == receipt
            && d.scope() == scope
            && s(&again["decision"]) == "allow"
            && d.allowed_at(release_time),
        "{at}: a returned copy changed the released decision"
    );
}

fn release_status_name(code: i32) -> String {
    unsafe { cstr_in(ratify_v2_release_status_str(code)) }
}

/// Release a committed outcome and check the step expectation.
fn release(
    at: &str,
    c: &Committed,
    receipt: Option<&Vec<u8>>,
    log_id: &str,
    store: &RefStore,
    checkpoint: &RatifyV2CheckpointCallbacks,
    want: &Value,
) -> Option<Released> {
    let key = keys().key(&s(&file()["verifier_key"]));
    let log = cs(log_id);
    let release_cb = store.release();
    // Seed the output with a stale non-NULL value, as a caller reusing a
    // variable would: the library must overwrite it on every call.
    let (mut status, mut reason, mut released) = (
        0i32,
        ptr::null_mut(),
        ptr::NonNull::<RatifyV2Released>::dangling().as_ptr(),
    );
    let code = unsafe {
        ratify_v2_release_decision(
            c.0,
            receipt.map_or(null_slice(), |r| slice(r)),
            &key,
            log.as_ptr(),
            &release_cb,
            checkpoint,
            &mut status,
            &mut reason,
            &mut released,
        )
    };
    check(code).unwrap_or_else(|e| panic!("{at} release: {e:?}"));
    if status != RatifyV2ReleaseStatus::RatifyV2ReleaseReleased as i32 {
        assert!(
            released.is_null(),
            "{at}: released_out must be NULL unless released"
        );
    }
    let reason = take_str(reason);
    let d = (!released.is_null()).then_some(Released(released));
    assert_eq!(
        (release_status_name(status), reason),
        (s(&want["release_status"]), s(&want["release_reason"])),
        "{at} release"
    );
    assert_eq!(
        d.is_some(),
        status == RatifyV2ReleaseStatus::RatifyV2ReleaseReleased as i32,
        "{at}: decision presence"
    );
    let d = d?;
    let receipt = parse(&canonicalize(8, &d.receipt()).expect("released receipt decodes"));
    assert_eq!(
        (d.decision(), d.times().0, i(&receipt["sequence"])),
        (
            s(&want["decision"]),
            i(&want["release_time"]),
            i(&want["receipt_sequence"])
        ),
        "{at} released decision"
    );
    check_released_allowed(at, &d);
    Some(d)
}

// ---------------------------------------------------------------------------
// Checkpoint wrapper that reports a different entry hash

struct WrongEntry {
    inner: RatifyV2CheckpointCallbacks,
    hash: Mutex<Vec<u8>>,
}

unsafe extern "C" fn wrong_ack(
    user: *mut c_void,
    log_id: *const c_char,
    sequence: i64,
    previous: RatifyV2Slice,
    entry: RatifyV2Slice,
    out: *mut RatifyV2Acknowledgement,
) -> i32 {
    let w = &*(user as *const WrongEntry);
    (w.inner.acknowledge.unwrap())(w.inner.user, log_id, sequence, previous, entry, out)
}

unsafe extern "C" fn wrong_get(
    user: *mut c_void,
    log_id: *const c_char,
    sequence: i64,
    out: *mut RatifyV2Acknowledgement,
) -> i32 {
    let w = &*(user as *const WrongEntry);
    let code = (w.inner.get.unwrap())(w.inner.user, log_id, sequence, out);
    if code == 0 {
        let mut h = w.hash.lock().unwrap();
        *h = slice_in((*out).entry_hash);
        if let Some(b) = h.first_mut() {
            *b ^= 1;
        }
        (*out).entry_hash = slice(&h);
    }
    code
}

impl WrongEntry {
    fn callbacks(&self) -> RatifyV2CheckpointCallbacks {
        RatifyV2CheckpointCallbacks {
            user: self as *const WrongEntry as *mut c_void,
            acknowledge: Some(wrong_ack),
            get: Some(wrong_get),
        }
    }
}

// ---------------------------------------------------------------------------
// Claim store wrapper that records the owner token handed to the creator

/// Go `v2OwnerCapturingClaimStore`: forwards every callback to the store and
/// records the evaluator owner token its `claim` returns, so a `finalize`
/// step can call the store's finalize directly.
struct OwnerCapture {
    inner: RatifyV2ClaimStoreCallbacks,
    owner: Mutex<Vec<u8>>,
}

fn capture(user: *mut c_void) -> &'static OwnerCapture {
    // SAFETY: `user` is the OwnerCapture of `callbacks`, alive for the call.
    unsafe { &*(user as *const OwnerCapture) }
}

unsafe extern "C" fn cap_now(user: *mut c_void, out: *mut i64) -> i32 {
    let w = capture(user);
    (w.inner.now.unwrap())(w.inner.user, out)
}

unsafe extern "C" fn cap_claim(
    user: *mut c_void,
    view: *const RatifyV2ClaimView,
    out: *mut RatifyV2ClaimResult,
) -> i32 {
    let w = capture(user);
    let code = (w.inner.claim.unwrap())(w.inner.user, view, out);
    *w.owner.lock().unwrap() = if code == 0 {
        slice_in((*out).owner_token)
    } else {
        Vec::new()
    };
    code
}

unsafe extern "C" fn cap_finalize(
    user: *mut c_void,
    id: *const c_char,
    owner: RatifyV2Slice,
    terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    allow_valid_until: i64,
    committed: *mut i32,
) -> i32 {
    let w = capture(user);
    (w.inner.finalize.unwrap())(w.inner.user, id, owner, terminal, body, allow_valid_until, committed)
}

unsafe extern "C" fn cap_progress(
    user: *mut c_void,
    id: *const c_char,
    owner: RatifyV2Slice,
    progress: RatifyV2Slice,
) -> i32 {
    let w = capture(user);
    (w.inner.record_progress.unwrap())(w.inner.user, id, owner, progress)
}

unsafe extern "C" fn cap_load(
    user: *mut c_void,
    id: *const c_char,
    out: *mut RatifyV2InterruptedClaim,
) -> i32 {
    let w = capture(user);
    (w.inner.load_interrupted.unwrap())(w.inner.user, id, out)
}

unsafe extern "C" fn cap_recover(
    user: *mut c_void,
    id: *const c_char,
    terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    committed: *mut i32,
) -> i32 {
    let w = capture(user);
    (w.inner.recover.unwrap())(w.inner.user, id, terminal, body, committed)
}

impl OwnerCapture {
    fn callbacks(&self) -> RatifyV2ClaimStoreCallbacks {
        RatifyV2ClaimStoreCallbacks {
            user: self as *const OwnerCapture as *mut c_void,
            rate_at_finalization: self.inner.rate_at_finalization,
            now: Some(cap_now),
            claim: Some(cap_claim),
            finalize: Some(cap_finalize),
            record_progress: Some(cap_progress),
            load_interrupted: Some(cap_load),
            recover: Some(cap_recover),
        }
    }
}

// ---------------------------------------------------------------------------
// Status provider wrapper running one step mid-lookup

struct ModeStatus {
    inner: RatifyV2StatusEvidenceCallbacks,
    store: *const RatifyV2RefStore,
    claim_cb: RatifyV2ClaimStoreCallbacks,
    claim_id: String,
    mode: String,
    time: i64,
    fired: AtomicUsize,
    recovered: Mutex<Option<R<Committed>>>,
    cancel_after: bool,
}

unsafe extern "C" fn mode_fetch(
    user: *mut c_void,
    req: *const RatifyV2StatusRequest,
    out: *mut RatifyV2StatusBatch,
) -> i32 {
    let m = &*(user as *const ModeStatus);
    if m.cancel_after {
        // Delegate, then cancel the operation (SPEC-v2 §6.11).
        (m.inner.fetch.unwrap())(m.inner.user, req, out);
        return RatifyV2Code::RatifyV2ErrCancelled as i32;
    }
    if m.fired.fetch_add(1, Ordering::SeqCst) == 0 {
        match m.mode.as_str() {
            // The caller cancels during the lookup and the provider
            // reports that cancellation (SPEC-v2 §6.11).
            "cancel_during_status" => return RatifyV2Code::RatifyV2ErrCancelled as i32,
            "recover_during_status" => {
                check(ratify_v2_ref_store_control(m.store, 1, m.time)).unwrap();
                *m.recovered.lock().unwrap() = Some(recover(&m.claim_cb, &m.claim_id));
            }
            "expire_lease_during_status" | "regress_clock_during_status" => {
                check(ratify_v2_ref_store_control(m.store, 1, m.time)).unwrap();
            }
            other => panic!("unknown verify mode {other}"),
        }
    }
    (m.inner.fetch.unwrap())(m.inner.user, req, out)
}

impl ModeStatus {
    fn callbacks(&self) -> RatifyV2StatusEvidenceCallbacks {
        RatifyV2StatusEvidenceCallbacks {
            user: self as *const ModeStatus as *mut c_void,
            fetch: Some(mode_fetch),
        }
    }
}

fn claim_callbacks(store: &RefStore, rate_at_finalization: bool) -> RatifyV2ClaimStoreCallbacks {
    store.claim(rate_at_finalization)
}

fn setup_for(inputs: &Value, store: &RefStore, rate_at_finalization: bool) -> Box<Setup> {
    let mut setup = Setup::build(inputs, &Arc::new(Counts::default()), true);
    setup.claim_cb = Some(claim_callbacks(store, rate_at_finalization));
    if rate_at_finalization {
        setup.set_rate(store.rate());
    }
    setup
}

fn receipt_sequence(wire: &[u8]) -> i64 {
    i(&parse(&canonicalize(8, wire).expect("published receipt decodes"))["sequence"])
}

type ClaimIds = (BTreeMap<String, String>, BTreeMap<String, String>);

/// Go `runVerify`: one verify step against the scenario store at its clock.
/// Safe for concurrent use with mode "" (`verify_concurrent`). Returns the
/// outcome and, for `recover_during_status`, the recovery run mid-lookup.
/// `cancel_before_claim` is the C caller's cancellation before the claim:
/// the receiver-binding hook, the only callback before the claim, returns
/// `RatifyV2ErrCancelled`.
fn run_verify(
    store: &RefStore,
    rate_at_finalization: bool,
    request: &str,
    mode: &str,
    time: i64,
    epoch_override: i64,
    ids: &Mutex<ClaimIds>,
) -> (Outcome, Option<R<Committed>>) {
    let inputs = request_inputs(request, store.now(), epoch_override);
    let mut setup = setup_for(&inputs, store, rate_at_finalization);
    let claim_id = claim_id_of(&inputs);
    {
        let mut ids = ids.lock().unwrap();
        ids.0.insert(request.to_string(), claim_id.clone());
        ids.1.insert(claim_id.clone(), request.to_string());
    }
    let wrapper = (!mode.is_empty() && mode != "cancel_before_claim").then(|| {
        Box::new(ModeStatus {
            inner: setup.status_callbacks(),
            store: store.0,
            claim_cb: store.claim(false),
            claim_id: claim_id.clone(),
            mode: mode.to_string(),
            time,
            fired: AtomicUsize::new(0),
            recovered: Mutex::new(None),
            cancel_after: false,
        })
    });
    if let Some(w) = &wrapper {
        setup.set_status(w.callbacks());
    }
    if mode == "cancel_before_claim" {
        setup.set_binding(Binding(Box::new(|| {
            RatifyV2Code::RatifyV2ErrCancelled as i32
        })));
    }
    let outcome =
        verify(&setup, &bundle_of(request)).unwrap_or_else(|e| panic!("verify {request}: {e:?}"));
    let recovered = wrapper.and_then(|w| w.recovered.lock().unwrap().take());
    (outcome, recovered)
}

#[test]
fn v2c_lifecycle_scenarios() {
    let f = file();
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no lifecycle scenarios");
    let (mut ran, mut want_steps) = (0usize, 0usize);
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let rate_at_finalization = b(&sc["rate_at_finalization"]);
        let mut store = new_store(i(&sc["start_time"]), &s(&f["log_id"]));
        let mut log_id = s(&f["log_id"]);
        let mut committed: BTreeMap<String, Committed> = BTreeMap::new();
        let mut receipts: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut owners: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        // (claim IDs by request, request by claim ID), written by
        // concurrent verify steps.
        let ids: Mutex<ClaimIds> = Mutex::new((BTreeMap::new(), BTreeMap::new()));
        let mut epoch_override = 0;
        let steps = arr(&sc["steps"]);
        want_steps += steps.len();
        for (n, step) in steps.iter().enumerate() {
            ran += 1;
            let want = &step["expect"];
            let now = store.now();
            let request = s(&step["request"]);
            let mode = s(&step["mode"]);
            let at = format!("{name} step {n}");
            match s(&step["op"]).as_str() {
                "set_time" => store.set_time(i(&step["time"])),
                "set_ack_withheld" => store.set_ack_withheld(b(&step["withheld"])),
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
                        if let Some(c) = check_recover(&at, result, &want["recovered"]) {
                            committed.insert(request.clone(), c);
                        }
                    }
                    let disposition = s(&want["disposition"]);
                    assert!(
                        outcome.stage == s(&want["stage"])
                            && outcome.class == s(&want["error_class"])
                            && (disposition.is_empty() || outcome.disposition == disposition),
                        "{at} verify {request}: stage {} class {:?} disposition {:?} ({}), want {want}",
                        outcome.stage,
                        outcome.class,
                        outcome.disposition,
                        outcome.message
                    );
                    if let Some(c) = outcome.committed {
                        check_committed(&at, &c, want);
                        committed.insert(request.clone(), c);
                    }
                }
                "verify_concurrent" => {
                    let names: Vec<String> = arr(&step["requests"]).iter().map(s).collect();
                    let start = std::sync::Barrier::new(names.len());
                    let results: Vec<Outcome> = std::thread::scope(|scope| {
                        let handles: Vec<_> = names
                            .iter()
                            .map(|name| {
                                let (store, start, ids) = (&store, &start, &ids);
                                scope.spawn(move || {
                                    start.wait();
                                    run_verify(
                                        store,
                                        rate_at_finalization,
                                        name,
                                        "",
                                        0,
                                        epoch_override,
                                        ids,
                                    )
                                    .0
                                })
                            })
                            .collect();
                        handles
                            .into_iter()
                            .map(|h| h.join().expect("verify thread"))
                            .collect()
                    });
                    let mut got = Vec::new();
                    for (name, outcome) in names.iter().zip(results) {
                        let mut label = outcome.stage.clone();
                        if label == "preflight" || label == "evaluating" {
                            label = format!("{label}/{}", outcome.class);
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
                    let mut req = request_json(&file()["requests"][&request]);
                    req["now"] = now.into();
                    let req = json_bytes(&req);
                    let bundle = bundle_of(&request);
                    let capturing = OwnerCapture {
                        inner: claim_callbacks(&store, rate_at_finalization),
                        owner: Mutex::new(Vec::new()),
                    };
                    let claim_cb = capturing.callbacks();
                    let mut disposition = 0i32;
                    let result = string(|o| unsafe {
                        ratify_v2_claim_proof_bundle(
                            ptr_of(&bundle),
                            bundle.len(),
                            req.as_ptr(),
                            req.len(),
                            &claim_cb,
                            &mut disposition,
                            o,
                        )
                    });
                    let class = match &result {
                        Ok(_) => String::new(),
                        Err(e) => e.class.clone(),
                    };
                    let (claim_id, disp) = match &result {
                        Ok(id) => (id.clone(), disposition_name(disposition)),
                        Err(_) => (String::new(), ""),
                    };
                    assert_eq!(
                        (class.as_str(), disp),
                        (
                            s(&want["error_class"]).as_str(),
                            s(&want["disposition"]).as_str()
                        ),
                        "{at} claim_only"
                    );
                    let mut ids = ids.lock().unwrap();
                    ids.0.insert(request.clone(), claim_id.clone());
                    ids.1.insert(claim_id, request.clone());
                    owners.insert(request.clone(), capturing.owner.into_inner().unwrap());
                }
                "acknowledge" => {
                    // The reference checkpoint through its C callbacks; the
                    // entry hash is `ratify_v2_object_body_digest` of the
                    // published receipt.
                    let wire = &receipts[&request];
                    let receipt = parse(&canonicalize(8, wire).expect("receipt decodes"));
                    let mut entry = buf(|o| unsafe {
                        ratify_v2_object_body_digest(8, ptr_of(wire), wire.len(), o)
                    })
                    .expect("entry hash");
                    match mode.as_str() {
                        "exact" => {}
                        "fork" => entry[0] ^= 1,
                        other => panic!("unknown acknowledge mode {other}"),
                    }
                    let previous = b64(&receipt["previous_receipt_hash"]);
                    let log = cs(&s(&receipt["log_id"]));
                    let sequence = i(&receipt["sequence"]);
                    let cp = store.checkpoint();
                    let mut ack = RatifyV2Acknowledgement {
                        log_id: ptr::null(),
                        sequence: 0,
                        entry_hash: null_slice(),
                        timestamp: 0,
                    };
                    let code = unsafe {
                        (cp.acknowledge.unwrap())(
                            cp.user,
                            log.as_ptr(),
                            sequence,
                            slice(&previous),
                            slice(&entry),
                            &mut ack,
                        )
                    };
                    if b(&want["failed"]) {
                        assert_ne!(code, 0, "{at} acknowledge {mode}: acknowledged at {}, want refusal", ack.timestamp);
                        continue;
                    }
                    assert_eq!(code, 0, "{at} acknowledge: {}", class(code));
                    assert_eq!(
                        (ack.timestamp, ack.sequence, unsafe { slice_in(ack.entry_hash) }),
                        (i(&want["ack_timestamp"]), sequence, entry),
                        "{at} acknowledge"
                    );
                }
                "finalize" => {
                    // The store's finalize through its C callbacks, with the
                    // owner token claim_only recorded.
                    let cb = claim_callbacks(&store, rate_at_finalization);
                    let claim_id = cs(&ids.lock().unwrap().0.get(&request).cloned().unwrap_or_default());
                    let owner = owners.get(&request).cloned().unwrap_or_default();
                    let (terminal, body) = (b64(&step["terminal_b64"]), b64(&step["body_b64"]));
                    let mut committed_flag = 0i32;
                    let code = unsafe {
                        (cb.finalize.unwrap())(
                            cb.user,
                            claim_id.as_ptr(),
                            slice(&owner),
                            slice(&terminal),
                            slice(&body),
                            i(&step["allow_valid_until"]),
                            &mut committed_flag,
                        )
                    };
                    let want_class = s(&want["error_class"]);
                    if !want_class.is_empty() {
                        assert_eq!(class(code), want_class, "{at} finalize");
                        continue;
                    }
                    assert_eq!(code, 0, "{at} finalize: {}", class(code));
                    let got = if committed_flag == 1 { "committed" } else { "identical" };
                    assert_eq!(got, s(&want["finalize_result"]), "{at} finalize");
                }
                "recover_direct" => {
                    // The store's recovery operation through its C callbacks.
                    let cb = claim_callbacks(&store, rate_at_finalization);
                    let claim_id = cs(&ids.lock().unwrap().0.get(&request).cloned().unwrap_or_default());
                    let (terminal, body) = (b64(&step["terminal_b64"]), b64(&step["body_b64"]));
                    let mut committed_flag = 0i32;
                    let code = unsafe {
                        (cb.recover.unwrap())(
                            cb.user,
                            claim_id.as_ptr(),
                            slice(&terminal),
                            slice(&body),
                            &mut committed_flag,
                        )
                    };
                    let want_class = s(&want["error_class"]);
                    if !want_class.is_empty() {
                        assert_eq!((class(code), committed_flag), (want_class, 0), "{at} recover_direct");
                        continue;
                    }
                    assert_eq!(code, 0, "{at} recover_direct: {}", class(code));
                    let got = if committed_flag == 1 { "committed" } else { "identical" };
                    assert_eq!(got, s(&want["finalize_result"]), "{at} recover_direct");
                }
                "recover" => {
                    // A request never claimed recovers its own claim ID
                    // (claim_not_found).
                    let claim_id = ids
                        .lock()
                        .unwrap()
                        .0
                        .get(&request)
                        .cloned()
                        .unwrap_or_else(|| claim_id_of(&file()["requests"][&request]));
                    let result = recover(&store.claim(false), &claim_id);
                    if let Some(c) = check_recover(&at, result, want) {
                        committed.insert(request.clone(), c);
                    }
                }
                "publish" => {
                    let c = &committed[&request];
                    if mode == "signer_failure" {
                        store.set_signer_failure(true);
                    }
                    let published = store.publish(&c.claim_id(), &c.body());
                    store.set_signer_failure(false);
                    if b(&want["failed"]) {
                        assert_eq!(
                            published.as_ref().err().map(String::as_str),
                            Some(s(&want["publish_error"]).as_str()),
                            "{at} publish"
                        );
                        continue;
                    }
                    let mut wire = published.unwrap_or_else(|e| panic!("{at} publish: {e}"));
                    assert_eq!(
                        receipt_sequence(&wire),
                        i(&want["receipt_sequence"]),
                        "{at} publish sequence"
                    );
                    if mode == "corrupt_signature" {
                        let mut v = parse(&wire);
                        let mut ed = b64(&v["signature"]["ed25519"]);
                        ed[0] ^= 1;
                        v["signature"]["ed25519"] = enc(&ed).into();
                        wire = canon(&v);
                    }
                    receipts.insert(request.clone(), wire);
                }
                "abandon" => {
                    let got: Vec<String> = store
                        .abandon()
                        .iter()
                        .map(|id| ids.lock().unwrap().1.get(id).cloned().unwrap_or_default())
                        .collect();
                    let expected: Vec<String> = arr(&want["abandoned"]).iter().map(s).collect();
                    assert_eq!(got, expected, "{at} abandon");
                }
                "restore" => match mode.as_str() {
                    "exact" => store = store.clone_store(),
                    "lost_state_epoch_bump" => {
                        log_id = s(&step["log_id"]);
                        store = new_store(now, &log_id);
                        epoch_override = i(&step["replay_epoch"]);
                    }
                    other => panic!("unknown restore mode {other}"),
                },
                "plant_release" => {
                    store.plant_release(&committed[&request].claim_id(), i(&step["time"]))
                }
                "release" => {
                    let c = committed
                        .get(&request)
                        .unwrap_or_else(|| panic!("{at}: {request} was never committed"));
                    let receipt_of = s(&step["receipt_of"]);
                    let receipt = receipts
                        .get(if receipt_of.is_empty() {
                            &request
                        } else {
                            &receipt_of
                        })
                        .filter(|_| mode != "no_receipt");
                    let wrong = WrongEntry {
                        inner: store.checkpoint(),
                        hash: Mutex::new(Vec::new()),
                    };
                    let checkpoint = if s(&step["checkpoint"]) == "wrong_entry" {
                        wrong.callbacks()
                    } else {
                        store.checkpoint()
                    };
                    release(&at, c, receipt, &log_id, &store, &checkpoint, want);
                }
                "release_forged" => {
                    // The committed outcome is an opaque library handle that
                    // only the verifier creates, so a C caller cannot forge
                    // one; the closest forgery, an absent handle, is refused.
                    assert_eq!(
                        (s(&want["release_status"]), s(&want["release_reason"])),
                        ("rejected".to_string(), "release_state_mismatch".to_string()),
                        "{at} release_forged"
                    );
                    let key = keys().key(&s(&f["verifier_key"]));
                    let log = cs(&log_id);
                    let (release_cb, checkpoint) = (store.release(), store.checkpoint());
                    let (mut status, mut reason, mut released) =
                        (0i32, ptr::null_mut(), ptr::null_mut());
                    let code = unsafe {
                        ratify_v2_release_decision(
                            ptr::null(),
                            null_slice(),
                            &key,
                            log.as_ptr(),
                            &release_cb,
                            &checkpoint,
                            &mut status,
                            &mut reason,
                            &mut released,
                        )
                    };
                    assert_eq!(class(code), "null_pointer", "{at} release_forged");
                    assert!(
                        released.is_null() && reason.is_null(),
                        "{at}: no decision from a forged release"
                    );
                }
                other => panic!("unknown op {other}"),
            }
        }
    }
    assert_eq!(ran, want_steps, "every lifecycle step must run");
    assert_eq!((scenarios.len(), ran), (62, 338), "Part B scripts");
    let readme = readme_line(FILE);
    assert!(
        readme.contains("62 Part B scripts (338 steps)"),
        "README row: {readme}"
    );
    println!(
        "C-ABI COVERAGE {FILE} scenarios: {} scenarios, {ran} steps",
        scenarios.len()
    );
}

// ---------------------------------------------------------------------------
// Profile scenarios (SPEC-v2 §7.13, §7.14)

struct Device(*mut RatifyV2RefDevice);

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { ratify_v2_ref_device_free(self.0) };
    }
}

struct Primary(*mut RatifyV2RefPrimary);

impl Drop for Primary {
    fn drop(&mut self) {
        unsafe { ratify_v2_ref_primary_free(self.0) };
    }
}

impl Device {
    /// (json output, value output, name output)
    fn op(&self, op: i32, sequence: i64) -> (Value, i64, String) {
        let mut out = empty_buf();
        let mut value = 0i64;
        let mut name: *const c_char = ptr::null();
        let code = unsafe {
            ratify_v2_ref_device_op(self.0, op, sequence, &mut out, &mut value, &mut name)
        };
        let data = take(out);
        check(code).unwrap_or_else(|e| panic!("device op {op}: {e:?}"));
        (
            if data.is_empty() {
                Value::Null
            } else {
                parse(&data)
            },
            value,
            unsafe { cstr_in(name) },
        )
    }

    fn callbacks(&self) -> (RatifyV2CheckpointCallbacks, RatifyV2JournalStoreCallbacks) {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2CheckpointCallbacks>() };
        let mut j = unsafe { std::mem::zeroed::<RatifyV2JournalStoreCallbacks>() };
        check(unsafe { ratify_v2_ref_device_callbacks(self.0, &mut c, &mut j) }).unwrap();
        (c, j)
    }
}

struct Ledger(*mut RatifyV2RefLedger);

unsafe impl Send for Ledger {}
unsafe impl Sync for Ledger {}

impl Drop for Ledger {
    fn drop(&mut self) {
        unsafe { ratify_v2_ref_ledger_free(self.0) };
    }
}

impl Ledger {
    fn record(
        &self,
        set_id: &str,
        slot: u64,
        decision: Option<&Released>,
        bundle: &[u8],
    ) -> (bool, String) {
        let id = cs(set_id);
        let (mut complete, mut err): (i32, *const c_char) = (0, ptr::null());
        let code = unsafe {
            ratify_v2_ref_ledger_record(
                self.0,
                id.as_ptr(),
                slot,
                decision.map_or(ptr::null(), |d| d.0),
                ptr_of(bundle),
                bundle.len(),
                &mut complete,
                &mut err,
            )
        };
        check(code).expect("ledger record");
        (complete != 0, unsafe { cstr_in(err) })
    }

    fn execute(&self, set_id: &str, clock: &RatifyV2ClockCallbacks) -> String {
        let id = cs(set_id);
        let mut err: *const c_char = ptr::null();
        check(unsafe { ratify_v2_ref_ledger_execute(self.0, id.as_ptr(), clock, &mut err) })
            .expect("ledger execute");
        unsafe { cstr_in(err) }
    }
}

/// A clock callback struct that may cross threads (its user is a live store).
#[derive(Clone, Copy)]
struct SendClock(RatifyV2ClockCallbacks);
unsafe impl Send for SendClock {}
unsafe impl Sync for SendClock {}

impl SendClock {
    fn get(&self) -> &RatifyV2ClockCallbacks {
        &self.0
    }
}

fn int_list(v: &Value) -> Vec<i64> {
    arr(v).iter().map(i).collect()
}

#[test]
fn v2c_profile_scenarios() {
    let f = file();
    let fx = keys();
    let scenarios = arr(&f["profile_scenarios"]);
    let mut profiles: BTreeMap<String, usize> = BTreeMap::new();
    for sc in &scenarios {
        *profiles.entry(s(&sc["profile"])).or_default() += 1;
    }
    assert!(
        profiles.get("single_device_offline").copied().unwrap_or(0) > 0
            && profiles.get("dual_root").copied().unwrap_or(0) > 0
            && profiles.len() == 2,
        "profile scenarios {profiles:?}"
    );
    let log_id = s(&f["log_id"]);
    let (mut ran, mut want_steps) = (0usize, 0usize);
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let rate_at_finalization = b(&sc["rate_at_finalization"]);
        let mut store = new_store(i(&sc["start_time"]), &log_id);
        let mut device = None;
        if s(&sc["profile"]) == "single_device_offline" {
            store.set_ack_withheld(true);
            let d = &sc["device"];
            let seed = b64(&d["component_seed_b64"]);
            let mut out = ptr::null_mut();
            check(unsafe {
                ratify_v2_ref_device_new(
                    store.0,
                    ptr_of(&seed),
                    seed.len(),
                    u(&d["capacity"]),
                    i(&d["replay_epoch"]),
                    &mut out,
                )
            })
            .unwrap_or_else(|e| panic!("{name}: device: {e:?}"));
            device = Some(Device(out));
        }
        let ledger = {
            let mut out = ptr::null_mut();
            check(unsafe { ratify_v2_ref_ledger_new(&mut out) }).unwrap();
            Ledger(out)
        };
        let mut set_id = String::new();
        let mut committed: BTreeMap<String, Committed> = BTreeMap::new();
        let mut receipts: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut decisions: BTreeMap<String, Option<Released>> = BTreeMap::new();
        let mut snapshots: BTreeMap<String, Primary> = BTreeMap::new();
        let steps = arr(&sc["steps"]);
        want_steps += steps.len();
        for (n, step) in steps.iter().enumerate() {
            ran += 1;
            let want = &step["expect"];
            let request = s(&step["request"]);
            let at = format!("{name} step {n}");
            let target = if s(&step["set"]).is_empty() {
                set_id.clone()
            } else {
                s(&step["set"])
            };
            let dev = || device.as_ref().expect("device");
            match s(&step["op"]).as_str() {
                "set_time" => store.set_time(i(&step["time"])),
                "set_ack_withheld" => store.set_ack_withheld(b(&step["withheld"])),
                "verify" => {
                    let inputs = request_inputs(&request, store.now(), 0);
                    let setup = setup_for(&inputs, &store, rate_at_finalization);
                    let outcome = verify(&setup, &bundle_of(&request))
                        .unwrap_or_else(|e| panic!("{at}: {e:?}"));
                    assert!(
                        outcome.stage == s(&want["stage"])
                            && outcome.class == s(&want["error_class"]),
                        "{at} verify {request}: stage {} class {:?} ({}), want {want}",
                        outcome.stage,
                        outcome.class,
                        outcome.message
                    );
                    if let Some(c) = outcome.committed {
                        check_committed(&at, &c, want);
                        committed.insert(request.clone(), c);
                    }
                }
                "publish" => {
                    let c = &committed[&request];
                    let wire = store
                        .publish(&c.claim_id(), &c.body())
                        .unwrap_or_else(|e| panic!("{at} publish: {e}"));
                    assert_eq!(
                        receipt_sequence(&wire),
                        i(&want["receipt_sequence"]),
                        "{at} publish sequence"
                    );
                    receipts.insert(request.clone(), wire);
                }
                "release" => {
                    let checkpoint = if s(&step["checkpoint"]) == "device" {
                        dev().callbacks().0
                    } else {
                        store.checkpoint()
                    };
                    let c = committed
                        .get(&request)
                        .unwrap_or_else(|| panic!("{at}: {request} was never committed"));
                    let d = release(
                        &at,
                        c,
                        receipts.get(&request),
                        &log_id,
                        &store,
                        &checkpoint,
                        want,
                    );
                    decisions.insert(request.clone(), d);
                }
                "device_power_loss" => {
                    let op = match s(&step["mode"]).as_str() {
                        "before_commit" => 1,
                        "after_commit" => 2,
                        other => panic!("unknown power loss mode {other}"),
                    };
                    dev().op(op, 0);
                }
                "device_submit" => {
                    let (acked, _, err) = dev().op(3, 0);
                    assert_eq!(
                        (int_list(&acked), err),
                        (int_list(&want["acknowledged"]), s(&want["device_error"])),
                        "{at} device_submit"
                    );
                }
                "device_resubmit" => {
                    let (_, ack_time, err) = dev().op(4, i(&step["sequence"]));
                    assert_eq!(err, s(&want["device_error"]), "{at} device_resubmit");
                    if err.is_empty() {
                        assert_eq!(
                            ack_time,
                            i(&want["ack_time"]),
                            "{at} device_resubmit ack time"
                        );
                    }
                }
                "device_startup" => {
                    let (_, _, status) = dev().op(5, 0);
                    assert_eq!(status, s(&want["device_status"]), "{at} device_startup");
                }
                "snapshot" => {
                    let mut out = ptr::null_mut();
                    check(unsafe { ratify_v2_ref_device_snapshot(dev().0, &mut out) }).unwrap();
                    snapshots.insert(s(&step["snapshot"]), Primary(out));
                }
                "restore" => {
                    let snap = &snapshots[&s(&step["snapshot"])];
                    let mut out = ptr::null_mut();
                    check(unsafe { ratify_v2_ref_device_restore(dev().0, snap.0, &mut out) })
                        .unwrap_or_else(|e| panic!("{at} restore: {e:?}"));
                    store = RefStore(out);
                }
                "stage_status" => {
                    let (_, journal) = dev().callbacks();
                    populate_status_journal(&journal, &file()["requests"][&request]);
                }
                "plant_release" => {
                    store.plant_release(&committed[&request].claim_id(), i(&step["time"]))
                }
                "corrupt_state" => store.corrupt(&committed[&request].claim_id()),
                "upload" => {
                    let (got, _, _) = dev().op(6, 0);
                    assert_eq!(int_list(&got), int_list(&want["uploaded"]), "{at} upload");
                }
                "ledger_open" => {
                    let a = &step["approval_set"];
                    let roots = arr(&a["root_keys"]);
                    let agent_id = fx.id.get(&s(&a["agent_key"])).cloned().unwrap_or_default();
                    // The known-answer context must equal an independent §2.4
                    // derivation through the ABI; the ledger derives its own.
                    let inputs = json_bytes(&json!({
                        "verifier_id": a["verifier_id"],
                        "workspace_id": a["workspace_id"],
                        "agent_id": agent_id,
                        "session_id": a["session_id"],
                        "invocation_id": a["id"],
                        "request_hash_b64": a["request_hash_b64"],
                    }));
                    let derived = buf(|o| unsafe {
                        ratify_v2_session_context(inputs.as_ptr(), inputs.len(), o)
                    });
                    assert_eq!(
                        derived.ok(),
                        Some(b64(&a["session_context_b64"])),
                        "{at} ledger_open: known-answer session context"
                    );
                    let set = json_bytes(&json!({
                        "approval_set_id": a["id"],
                        "verifier_id": a["verifier_id"],
                        "workspace_id": a["workspace_id"],
                        "session_id": a["session_id"],
                        "agent_public_key": pub_json(&s(&a["agent_key"])),
                        "required_scope": a["required_scope"],
                        "request_hash_b64": a["request_hash_b64"],
                        "root_keys": [pub_json(&s(&roots[0])), pub_json(&s(&roots[1]))],
                    }));
                    let mut err: *const c_char = ptr::null();
                    check(unsafe {
                        ratify_v2_ref_ledger_open(ledger.0, set.as_ptr(), set.len(), &mut err)
                    })
                    .unwrap();
                    let err = unsafe { cstr_in(err) };
                    assert_eq!(err, s(&want["ledger_error"]), "{at} ledger_open");
                    if err.is_empty() {
                        set_id = s(&a["id"]);
                    }
                }
                "ledger_record" => {
                    let decision = decisions.get(&request).and_then(Option::as_ref);
                    let (complete, err) =
                        ledger.record(&target, u(&step["slot"]), decision, &bundle_of(&request));
                    let complete = complete && err.is_empty();
                    assert_eq!(
                        (complete, err),
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
                            .map(|(slot, name)| {
                                let (ledger, decisions, set_id, at) =
                                    (&ledger, &decisions, &set_id, &at);
                                scope.spawn(move || {
                                    let decision = decisions.get(name).and_then(Option::as_ref);
                                    let (_, err) = ledger.record(
                                        set_id,
                                        slot as u64,
                                        decision,
                                        &bundle_of(name),
                                    );
                                    assert!(err.is_empty(), "{at} ledger_record_concurrent: {err}");
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().expect("record thread");
                        }
                    });
                    let decision = decisions.get(&names[0]).and_then(Option::as_ref);
                    let (complete, err) =
                        ledger.record(&set_id, 0, decision, &bundle_of(&names[0]));
                    assert!(err.is_empty(), "{at} ledger_record_concurrent: {err}");
                    assert_eq!(
                        complete,
                        b(&want["ledger_complete"]),
                        "{at} ledger_record_concurrent"
                    );
                }
                "ledger_execute" => {
                    let got = ledger.execute(&target, &store.clock());
                    assert_eq!(got, s(&want["ledger_error"]), "{at} ledger_execute");
                }
                "ledger_execute_concurrent" => {
                    let executed = AtomicUsize::new(0);
                    let clock = SendClock(store.clock());
                    std::thread::scope(|scope| {
                        for _ in 0..u(&step["count"]) {
                            scope.spawn(|| match ledger.execute(&set_id, clock.get()).as_str() {
                                "" => {
                                    executed.fetch_add(1, Ordering::SeqCst);
                                }
                                "already_executed" => {}
                                e => panic!("concurrent execute: {e}"),
                            });
                        }
                    });
                    assert_eq!(
                        executed.into_inner() as u64,
                        u(&want["executed"]),
                        "{at} ledger_execute_concurrent"
                    );
                }
                other => panic!("unknown profile op {other}"),
            }
        }
        // Released decisions referenced by the ledger are dropped before it.
        drop(decisions);
    }
    assert_eq!(ran, want_steps, "every profile step must run");
    println!(
        "C-ABI COVERAGE {FILE} profile_scenarios: {} scenarios {profiles:?}, {ran} steps",
        scenarios.len()
    );
}

/// Go `TestV2CancellationAfterClaimLeavesClaimRecoverable`: a callback that
/// returns `RatifyV2ErrCancelled` after the claim commits nothing; an exact
/// retry sees the claim in progress, and lease-expiry recovery terminalizes
/// it (SPEC-v2 §6.11).
#[test]
fn v2c_cancellation_after_claim_leaves_claim_recoverable() {
    let f = file();
    const START: i64 = 1_800_000_000;
    let store = new_store(START, &s(&f["log_id"]));
    let inputs = request_inputs("A", START, 0);
    let mut setup = setup_for(&inputs, &store, false);
    let wrapper = Box::new(ModeStatus {
        inner: setup.status_callbacks(),
        store: store.0,
        claim_cb: store.claim(false),
        claim_id: String::new(),
        mode: String::new(),
        time: 0,
        fired: AtomicUsize::new(0),
        recovered: Mutex::new(None),
        cancel_after: true,
    });
    setup.set_status(wrapper.callbacks());
    let outcome = verify(&setup, &bundle_of("A")).expect("verify");
    assert!(
        outcome.stage == "evaluating"
            && outcome.class == "evaluation_cancelled"
            && outcome.committed.is_none(),
        "cancelled evaluation: stage {} class {} ({})",
        outcome.stage,
        outcome.class,
        outcome.message
    );
    let claim_id = s(&parse(&outcome.claim_record)["claim_id"]);
    assert!(!claim_id.is_empty(), "the claim exists");
    let retry_setup = setup_for(&inputs, &store, false);
    let retry = verify(&retry_setup, &bundle_of("A")).expect("retry");
    assert_eq!(
        (retry.stage.as_str(), retry.disposition.as_str()),
        ("replay", "in_progress"),
        "retry after cancellation"
    );
    let live = recover(&store.claim(false), &claim_id);
    assert_eq!(
        class_of(&live),
        "claim_lease_live",
        "recovery during a live lease"
    );
    store.set_time(START + i(&f["lease_seconds"]));
    let committed = recover(&store.claim(false), &claim_id).expect("recover");
    assert_eq!(
        s(&body_json(&committed.body())["decision_reason"]),
        "evaluation_interrupted"
    );
}
