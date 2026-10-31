//! Shared concurrency scenarios (testvectors/v2/"concurrency-scenarios.json")
//! through the C ABI only. Mirrors v2_conformance_concurrency_test.go: every
//! participant is a `std::thread`, all of them released together from one
//! `Barrier`, and each makes its own `ratify_v2_*` calls (verification,
//! claim, recovery, release, and the reference store's C claim and
//! checkpoint callbacks) against the iteration's one shared reference store,
//! so the store and the C callback boundary see real contention. Set
//! RATIFY_RACE_ITERATIONS to change the per-scenario iteration count.
//!
//! Caller cancellation: the C ABI has no cross-thread cancel handle. A C
//! caller cancels a verification by having one of its callbacks return
//! `RatifyV2ErrCancelled` (SPEC-v2 §6.11). A cancel participant therefore
//! sets a flag shared with its target group after its calibrated delay, and
//! the target verification's cancellable callbacks observe the flag on entry
//! and report the cancellation, as the lifecycle runner's
//! `cancel_before_claim` (the receiver-binding hook, the only callback before
//! the claim) and `cancel_during_status` (the status provider) do. After the
//! claim the claim store's progress and finalize callbacks observe it too,
//! so the signal lands at every point between lookups up to the commit.

mod v2c_common;

use std::collections::BTreeMap;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ratify_c::*;
use serde_json::Value;
use v2c_common::*;

const FILE: &str = "concurrency-scenarios.json";

/// The default per-scenario iteration count of this runner, below the file's
/// `default_iterations` (20). `cargo test` builds the library without
/// optimization, where one verification of request A takes about 0.5 s, so
/// 20 iterations of every scenario take about 3 minutes; 2 keep the added
/// wall time near 20 s. RATIFY_RACE_ITERATIONS=20 runs the file's count.
const C_ABI_DEFAULT_ITERATIONS: usize = 2;

fn file() -> &'static Value {
    static F: OnceLock<Value> = OnceLock::new();
    F.get_or_init(|| load(FILE))
}

/// lifecycle-scenarios.json: requests, bundles, verifier key, log ID, lease.
fn inputs() -> &'static Value {
    static F: OnceLock<Value> = OnceLock::new();
    F.get_or_init(|| load(&s(&file()["inputs"])))
}

fn keys() -> &'static Fixture {
    static K: OnceLock<Fixture> = OnceLock::new();
    K.get_or_init(Fixture::load)
}

fn request_inputs(name: &str, now: i64) -> Value {
    let mut inputs = inputs()["requests"][name].clone();
    inputs["now"] = now.into();
    inputs
}

fn bundle_of(name: &str) -> Vec<u8> {
    let f = inputs();
    b64(&f["bundles_b64"][s(&f["requests"][name]["bundle"])])
}

fn strings(v: &Value) -> Vec<String> {
    arr(v).iter().map(s).collect()
}

fn receipt_sequence(wire: &[u8]) -> i64 {
    i(&parse(&canonicalize(8, wire).expect("published receipt decodes"))["sequence"])
}

fn recover(claim_cb: &RatifyV2ClaimStoreCallbacks, claim_id: &str) -> R<Committed> {
    let id = cs(claim_id);
    let mut out: *mut RatifyV2Committed = ptr::null_mut();
    let code = unsafe { ratify_v2_recover_interrupted_claim(claim_cb, id.as_ptr(), &mut out) };
    let r = check(code);
    let c = (!out.is_null()).then_some(Committed(out));
    r.map(|_| c.expect("committed outcome"))
}

/// Resumes a committed claim through the store's resumption callbacks
/// (SPEC-v2 §7.11).
fn resume(store: &RatifyV2CommittedStoreCallbacks, claim_id: &str) -> R<Committed> {
    let id = cs(claim_id);
    let mut out: *mut RatifyV2Committed = ptr::null_mut();
    let code = unsafe { ratify_v2_resume_committed_claim(store, id.as_ptr(), &mut out) };
    let r = check(code);
    let c = (!out.is_null()).then_some(Committed(out));
    r.map(|_| c.expect("committed outcome"))
}

/// "committed/<decision>/<decision_reason>" of a committed outcome, read
/// from its receipt body for the test only.
fn committed_label(c: &Committed) -> String {
    let body = body_json(&c.body());
    format!(
        "committed/{}/{}",
        s(&body["decision"]),
        s(&body["decision_reason"])
    )
}

/// Go `checkV2CommittedDecision`.
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

// ---------------------------------------------------------------------------
// Claim store and status wrappers

/// The reference store's claim callbacks, forwarded. It records the owner
/// token a created claim returns (Go `v2OwnerCapturingClaimStore`) and, for
/// a cancel target, reports the caller's cancellation from the progress and
/// finalize callbacks once `cancel` is set.
struct ClaimWrap {
    inner: RatifyV2ClaimStoreCallbacks,
    owner: Mutex<Vec<u8>>,
    cancel: Option<Arc<AtomicBool>>,
}

unsafe impl Send for ClaimWrap {}
unsafe impl Sync for ClaimWrap {}

fn wrap(user: *mut c_void) -> &'static ClaimWrap {
    // SAFETY: `user` is the ClaimWrap of `callbacks`, alive for the call.
    unsafe { &*(user as *const ClaimWrap) }
}

impl ClaimWrap {
    fn new(inner: RatifyV2ClaimStoreCallbacks, cancel: Option<Arc<AtomicBool>>) -> ClaimWrap {
        ClaimWrap {
            inner,
            owner: Mutex::new(Vec::new()),
            cancel,
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::SeqCst))
    }

    fn callbacks(&self) -> RatifyV2ClaimStoreCallbacks {
        RatifyV2ClaimStoreCallbacks {
            user: self as *const ClaimWrap as *mut c_void,
            rate_at_finalization: self.inner.rate_at_finalization,
            now: Some(wrap_now),
            claim: Some(wrap_claim),
            finalize: Some(wrap_finalize),
            record_progress: Some(wrap_progress),
            load_interrupted: Some(wrap_load),
            recover: Some(wrap_recover),
        }
    }
}

unsafe extern "C" fn wrap_now(user: *mut c_void, out: *mut i64) -> i32 {
    let w = wrap(user);
    (w.inner.now.unwrap())(w.inner.user, out)
}

unsafe extern "C" fn wrap_claim(
    user: *mut c_void,
    view: *const RatifyV2ClaimView,
    out: *mut RatifyV2ClaimResult,
) -> i32 {
    let w = wrap(user);
    let code = (w.inner.claim.unwrap())(w.inner.user, view, out);
    *w.owner.lock().unwrap() = if code == 0 {
        slice_in((*out).owner_token)
    } else {
        Vec::new()
    };
    code
}

unsafe extern "C" fn wrap_finalize(
    user: *mut c_void,
    id: *const c_char,
    owner: RatifyV2Slice,
    terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    allow_valid_until: i64,
    committed: *mut i32,
) -> i32 {
    let w = wrap(user);
    if w.cancelled() {
        return RatifyV2Code::RatifyV2ErrCancelled as i32;
    }
    (w.inner.finalize.unwrap())(
        w.inner.user,
        id,
        owner,
        terminal,
        body,
        allow_valid_until,
        committed,
    )
}

unsafe extern "C" fn wrap_progress(
    user: *mut c_void,
    id: *const c_char,
    owner: RatifyV2Slice,
    progress: RatifyV2Slice,
) -> i32 {
    let w = wrap(user);
    if w.cancelled() {
        return RatifyV2Code::RatifyV2ErrCancelled as i32;
    }
    (w.inner.record_progress.unwrap())(w.inner.user, id, owner, progress)
}

unsafe extern "C" fn wrap_load(
    user: *mut c_void,
    id: *const c_char,
    out: *mut RatifyV2InterruptedClaim,
) -> i32 {
    let w = wrap(user);
    (w.inner.load_interrupted.unwrap())(w.inner.user, id, out)
}

unsafe extern "C" fn wrap_recover(
    user: *mut c_void,
    id: *const c_char,
    terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    committed: *mut i32,
) -> i32 {
    let w = wrap(user);
    (w.inner.recover.unwrap())(w.inner.user, id, terminal, body, committed)
}

/// A cancel target's status provider: reports the caller's cancellation
/// once `cancel` is set, otherwise delegates.
struct CancelStatus {
    inner: RatifyV2StatusEvidenceCallbacks,
    cancel: Arc<AtomicBool>,
}

unsafe impl Send for CancelStatus {}
unsafe impl Sync for CancelStatus {}

unsafe extern "C" fn cancel_fetch(
    user: *mut c_void,
    req: *const RatifyV2StatusRequest,
    out: *mut RatifyV2StatusBatch,
) -> i32 {
    let c = &*(user as *const CancelStatus);
    if c.cancel.load(Ordering::SeqCst) {
        return RatifyV2Code::RatifyV2ErrCancelled as i32;
    }
    (c.inner.fetch.unwrap())(c.inner.user, req, out)
}

impl CancelStatus {
    fn callbacks(&self) -> RatifyV2StatusEvidenceCallbacks {
        RatifyV2StatusEvidenceCallbacks {
            user: self as *const CancelStatus as *mut c_void,
            fetch: Some(cancel_fetch),
        }
    }
}

/// A released decision handle.
struct Released(*mut RatifyV2Released);

impl Drop for Released {
    fn drop(&mut self) {
        unsafe { ratify_v2_released_free(self.0) };
    }
}

impl Released {
    /// "released/<decision>/<release_time>/<receipt_sequence>"
    fn label(&self) -> String {
        let decision = string(|o| unsafe {
            ratify_v2_released_string(
                self.0,
                RatifyV2ReleasedField::RatifyV2ReleasedDecision as i32,
                o,
            )
        })
        .unwrap();
        let (mut rt, mut exp, mut has, mut h) = (0, 0, 0, 0);
        check(unsafe { ratify_v2_released_times(self.0, &mut rt, &mut exp, &mut has, &mut h) })
            .unwrap();
        let receipt = buf(|o| unsafe { ratify_v2_released_receipt(self.0, o) }).unwrap();
        format!("released/{decision}/{rt}/{}", receipt_sequence(&receipt))
    }
}

// ---------------------------------------------------------------------------
// One iteration

/// A verification built before the start barrier; the boxes hold the
/// callback structs its setup points into.
struct PreparedVerify {
    request: String,
    bundle: Vec<u8>,
    setup: Box<Setup>,
    _claim: Option<Box<ClaimWrap>>,
    _status: Option<Box<CancelStatus>>,
    _binding_flag: Option<Arc<AtomicBool>>,
}

enum Task {
    Verify(PreparedVerify),
    Cancel(Duration, Arc<AtomicBool>),
    Op(Value),
}

/// (claim ID -> committed receipt body, claim IDs in first-recorded order)
type Recorded = (BTreeMap<String, Vec<u8>>, Vec<String>);

/// The state of one iteration of one scenario (Go `v2RaceIteration`).
struct Iteration {
    store: RefStore,
    rate_at_finalization: bool,
    committed: Mutex<BTreeMap<String, Arc<Committed>>>,
    receipts: Mutex<BTreeMap<String, Vec<u8>>>,
    owners: Mutex<BTreeMap<String, Vec<u8>>>,
    recorded: Mutex<Recorded>,
}

impl Iteration {
    fn new(start: i64, rate_at_finalization: bool) -> Iteration {
        let f = inputs();
        Iteration {
            store: RefStore::new(
                start,
                i(&f["lease_seconds"]),
                &s(&f["log_id"]),
                keys().kp(&s(&f["verifier_key"])),
            ),
            rate_at_finalization,
            committed: Mutex::new(BTreeMap::new()),
            receipts: Mutex::new(BTreeMap::new()),
            owners: Mutex::new(BTreeMap::new()),
            recorded: Mutex::new((BTreeMap::new(), Vec::new())),
        }
    }

    fn record(&self, claim_id: &str, body: &[u8]) {
        let mut r = self.recorded.lock().unwrap();
        if !r.0.contains_key(claim_id) {
            r.0.insert(claim_id.to_string(), body.to_vec());
            r.1.push(claim_id.to_string());
        }
    }

    /// Go `recordResumed`: records a resumed handoff as a committed result
    /// of its claim, and reports whether its body equals the one recorded.
    fn record_resumed(&self, c: &Committed) -> bool {
        let (claim_id, body) = (c.claim_id(), c.body());
        let mut r = self.recorded.lock().unwrap();
        if let Some(prior) = r.0.get(&claim_id) {
            return *prior == body;
        }
        r.0.insert(claim_id.clone(), body);
        r.1.push(claim_id);
        true
    }

    fn record_outcome(&self, request: &str, c: Arc<Committed>) {
        let (claim_id, body) = (c.claim_id(), c.body());
        self.committed
            .lock()
            .unwrap()
            .insert(request.to_string(), c);
        self.record(&claim_id, &body);
    }

    /// The protocol claim ID of request (`ratify_v2_claim_id` of its
    /// expected challenge's verifier namespace, replay epoch and value),
    /// claimed or not.
    fn claim_id(&self, request: &str) -> String {
        let e = &inputs()["requests"][request]["expected_challenge"];
        let ns = s(&e["verifier_namespace"]);
        let challenge = b64(&e["value_b64"]);
        string(|o| unsafe {
            ratify_v2_claim_id(
                ptr_of(ns.as_bytes()),
                ns.len(),
                i(&e["replay_epoch"]),
                ptr_of(&challenge),
                challenge.len(),
                o,
            )
        })
        .expect("claim id")
    }

    /// One verification of request at the current store clock, built on the
    /// test thread. A cancel target observes `cancel` in its receiver-binding
    /// hook, status provider, and claim store progress and finalize callbacks.
    fn prepare_verify(&self, request: &str, cancel: Option<Arc<AtomicBool>>) -> PreparedVerify {
        let inputs = request_inputs(request, self.store.now());
        let mut setup = Setup::build(&inputs, &Arc::new(Counts::default()), true);
        let inner = self.store.claim(self.rate_at_finalization);
        let claim = cancel
            .as_ref()
            .map(|flag| Box::new(ClaimWrap::new(inner, Some(Arc::clone(flag)))));
        setup.claim_cb = Some(claim.as_ref().map_or(inner, |w| w.callbacks()));
        if self.rate_at_finalization {
            setup.set_rate(self.store.rate());
        }
        let status = cancel.as_ref().map(|flag| {
            Box::new(CancelStatus {
                inner: setup.status_callbacks(),
                cancel: Arc::clone(flag),
            })
        });
        if let Some(w) = &status {
            setup.set_status(w.callbacks());
        }
        if let Some(flag) = &cancel {
            let flag = Arc::clone(flag);
            setup.set_binding(Binding(Box::new(move || {
                if flag.load(Ordering::SeqCst) {
                    RatifyV2Code::RatifyV2ErrCancelled as i32
                } else {
                    0
                }
            })));
        }
        PreparedVerify {
            request: request.to_string(),
            bundle: bundle_of(request),
            setup,
            _claim: claim,
            _status: status,
            _binding_flag: cancel,
        }
    }

    /// Run a prepared verification; returns its label, the outcome, and the
    /// committed handle (recorded) when it committed.
    fn verify_label(&self, p: &PreparedVerify) -> (String, Outcome, Option<Arc<Committed>>) {
        let mut outcome =
            verify(&p.setup, &p.bundle).unwrap_or_else(|e| panic!("verify {}: {e:?}", p.request));
        let committed = outcome.committed.take().map(Arc::new);
        let label = match (outcome.stage.as_str(), &committed) {
            ("committed", Some(c)) => {
                self.record_outcome(&p.request, Arc::clone(c));
                committed_label(c)
            }
            ("replay", _) => format!("replay/{}", outcome.disposition),
            (stage, _) => format!("{stage}/{}", outcome.class),
        };
        (label, outcome, committed)
    }

    /// `ratify_v2_claim_proof_bundle` for request at the store clock,
    /// recording the owner token: (claim ID or failure, disposition, owner).
    fn claim(&self, request: &str) -> (R<String>, &'static str, Vec<u8>) {
        let mut req = request_json(&inputs()["requests"][request]);
        req["now"] = self.store.now().into();
        let req = json_bytes(&req);
        let bundle = bundle_of(request);
        let w = ClaimWrap::new(self.store.claim(self.rate_at_finalization), None);
        let cb = w.callbacks();
        let mut disposition = 0i32;
        let result = string(|o| unsafe {
            ratify_v2_claim_proof_bundle(
                ptr_of(&bundle),
                bundle.len(),
                req.as_ptr(),
                req.len(),
                &cb,
                &mut disposition,
                o,
            )
        });
        let d = if result.is_ok() {
            disposition_name(disposition)
        } else {
            ""
        };
        (result, d, w.owner.into_inner().unwrap())
    }

    /// Release request's committed outcome with its last published receipt
    /// and the reference checkpoint (Go `releaseLabel`).
    fn release_label(&self, request: &str) -> String {
        let c = self.committed.lock().unwrap().get(request).cloned();
        let Some(c) = c else {
            return format!("{request} was never committed");
        };
        self.release_handoff_label(request, &c)
    }

    /// Release handoff `c` with request's last published receipt and the
    /// reference checkpoint (Go `releaseHandoffLabel`).
    fn release_handoff_label(&self, request: &str, c: &Committed) -> String {
        let receipt = self.receipts.lock().unwrap().get(request).cloned();
        let f = inputs();
        let key = keys().key(&s(&f["verifier_key"]));
        let log = cs(&s(&f["log_id"]));
        let (release_cb, checkpoint) = (self.store.release(), self.store.checkpoint());
        let (mut status, mut reason, mut released) = (0i32, ptr::null_mut(), ptr::null_mut());
        let code = unsafe {
            ratify_v2_release_decision(
                c.0,
                receipt.as_ref().map_or(null_slice(), |r| slice(r)),
                &key,
                log.as_ptr(),
                &release_cb,
                &checkpoint,
                &mut status,
                &mut reason,
                &mut released,
            )
        };
        let reason = take_str(reason);
        let d = (!released.is_null()).then_some(Released(released));
        if let Err(e) = check(code) {
            return format!("release call failed/{}", e.class);
        }
        if status != RatifyV2ReleaseStatus::RatifyV2ReleaseReleased as i32 {
            let name = unsafe { cstr_in(ratify_v2_release_status_str(status)) };
            return format!("{name}/{reason}");
        }
        d.map_or_else(|| "released without a decision".into(), |d| d.label())
    }

    /// One participant's operation; returns its label.
    fn run(&self, task: Task) -> String {
        let p = match task {
            Task::Verify(p) => return self.verify_label(&p).0,
            Task::Cancel(delay, flag) => {
                std::thread::sleep(delay);
                flag.store(true, Ordering::SeqCst);
                return "done".into();
            }
            Task::Op(p) => p,
        };
        let request = s(&p["request"]);
        match s(&p["op"]).as_str() {
            "claim_only" => match self.claim(&request) {
                (Ok(_), d, _) => d.to_string(),
                (Err(e), _, _) => format!("error/{}", e.class),
            },
            op @ ("finalize" | "recover_direct") => {
                // The store's own operation through its C callbacks.
                let claim_id = self.claim_id(&request);
                let owner = self
                    .owners
                    .lock()
                    .unwrap()
                    .get(&request)
                    .cloned()
                    .unwrap_or_default();
                let (terminal, body) = (b64(&p["terminal_b64"]), b64(&p["body_b64"]));
                let cb = self.store.claim(self.rate_at_finalization);
                let id = cs(&claim_id);
                let mut committed = 0i32;
                let code = unsafe {
                    if op == "finalize" {
                        (cb.finalize.unwrap())(
                            cb.user,
                            id.as_ptr(),
                            slice(&owner),
                            slice(&terminal),
                            slice(&body),
                            i(&p["allow_valid_until"]),
                            &mut committed,
                        )
                    } else {
                        (cb.recover.unwrap())(
                            cb.user,
                            id.as_ptr(),
                            slice(&terminal),
                            slice(&body),
                            &mut committed,
                        )
                    }
                };
                if code != 0 {
                    format!("error/{}", class(code))
                } else if committed == 1 {
                    self.record(&claim_id, &body);
                    "committed".into()
                } else {
                    "identical".into()
                }
            }
            "recover" => match recover(&self.store.claim(false), &self.claim_id(&request)) {
                Ok(c) => {
                    let c = Arc::new(c);
                    self.record_outcome(&request, Arc::clone(&c));
                    committed_label(&c)
                }
                Err(e) => format!("error/{}", e.class),
            },
            "resume" => match resume(&self.store.committed(), &self.claim_id(&request)) {
                Err(e) => format!("error/{}", e.class),
                Ok(c) if !self.record_resumed(&c) => "resumed a body other than the committed one".into(),
                Ok(c) if s(&p["mode"]) == "release" => self.release_handoff_label(&request, &c),
                Ok(c) => committed_label(&c),
            },
            "release" => self.release_label(&request),
            "acknowledge" => {
                // The reference checkpoint through its C callbacks, with the
                // published receipt's own entry hash (mode exact).
                let Some(wire) = self.receipts.lock().unwrap().get(&request).cloned() else {
                    return "no published receipt".into();
                };
                let receipt = parse(&canonicalize(8, &wire).expect("receipt decodes"));
                let entry = buf(|o| unsafe {
                    ratify_v2_object_body_digest(8, ptr_of(&wire), wire.len(), o)
                })
                .expect("entry hash");
                let previous = b64(&receipt["previous_receipt_hash"]);
                let log = cs(&s(&receipt["log_id"]));
                let cp = self.store.checkpoint();
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
                        i(&receipt["sequence"]),
                        slice(&previous),
                        slice(&entry),
                        &mut ack,
                    )
                };
                if code != 0 {
                    "refused".into()
                } else {
                    format!("acknowledged/{}", ack.timestamp)
                }
            }
            "set_time" => {
                self.store.set_time(i(&p["time"]));
                "done".into()
            }
            other => format!("unknown op {other}"),
        }
    }

    /// One setup or after step, checked against `want`.
    fn step(&self, at: &str, step: &Value, want: &Value) {
        let request = s(&step["request"]);
        match s(&step["op"]).as_str() {
            "set_time" => self.store.set_time(i(&step["time"])),
            "set_ack_withheld" => self.store.set_ack_withheld(b(&step["withheld"])),
            "verify" => {
                let p = self.prepare_verify(&request, None);
                let (_, outcome, committed) = self.verify_label(&p);
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
                if let Some(c) = committed {
                    check_committed(at, &c, want);
                }
            }
            "claim_only" => {
                let (result, disposition, owner) = self.claim(&request);
                let (class, id) = match result {
                    Ok(id) => (String::new(), id),
                    Err(e) => (e.class, String::new()),
                };
                assert_eq!(
                    (class.as_str(), disposition),
                    (
                        s(&want["error_class"]).as_str(),
                        s(&want["disposition"]).as_str()
                    ),
                    "{at} claim_only"
                );
                assert!(
                    id.is_empty() || id == self.claim_id(&request),
                    "{at} claim_only: claim ID {id} is not the request's protocol claim ID"
                );
                self.owners.lock().unwrap().insert(request, owner);
            }
            "recover" => {
                let result = recover(&self.store.claim(false), &self.claim_id(&request));
                let class = s(&want["error_class"]);
                if !class.is_empty() {
                    assert_eq!(
                        class_of(&result),
                        class,
                        "{at} recover: {:?}",
                        result.as_ref().err()
                    );
                    return;
                }
                let c = result.unwrap_or_else(|e| panic!("{at} recover: {e:?}"));
                check_committed(at, &c, want);
                self.record_outcome(&request, Arc::new(c));
            }
            "resume" => {
                let result = resume(&self.store.committed(), &self.claim_id(&request));
                let class = s(&want["error_class"]);
                if !class.is_empty() {
                    assert_eq!(
                        class_of(&result),
                        class,
                        "{at} resume: {:?}",
                        result.as_ref().err()
                    );
                    return;
                }
                let c = result.unwrap_or_else(|e| panic!("{at} resume: {e:?}"));
                check_committed(at, &c, want);
                assert!(
                    self.record_resumed(&c),
                    "{at} resume: the resumed body differs from the committed one"
                );
                self.committed.lock().unwrap().insert(request, Arc::new(c));
            }
            "publish" => {
                let c = Arc::clone(&self.committed.lock().unwrap()[&request]);
                let wire = self
                    .store
                    .publish(&c.claim_id(), &c.body())
                    .unwrap_or_else(|e| panic!("{at} publish: {e}"));
                assert_eq!(
                    receipt_sequence(&wire),
                    i(&want["receipt_sequence"]),
                    "{at} publish sequence"
                );
                self.receipts.lock().unwrap().insert(request, wire);
            }
            "release" => {
                let got = self.release_label(&request);
                let wanted = if s(&want["release_status"]) == "released" {
                    format!(
                        "released/{}/{}/{}",
                        s(&want["decision"]),
                        i(&want["release_time"]),
                        i(&want["receipt_sequence"])
                    )
                } else {
                    format!(
                        "{}/{}",
                        s(&want["release_status"]),
                        s(&want["release_reason"])
                    )
                };
                assert_eq!(got, wanted, "{at} release");
            }
            other => panic!("{at}: op {other} is not a concurrency setup or after step"),
        }
    }

    /// Publish every recorded result, retrying entries blocked behind an
    /// earlier one, and require sequences 1..k (Go `receiptLogContiguous`).
    fn receipt_log_contiguous(&self) -> Result<(), String> {
        let (recorded, order) = {
            let r = self.recorded.lock().unwrap();
            (r.0.clone(), r.1.clone())
        };
        let mut published: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut progress = true;
        while progress {
            progress = false;
            for id in &order {
                if published.contains_key(id) {
                    continue;
                }
                match self.store.publish(id, &recorded[id]) {
                    Ok(wire) => {
                        published.insert(id.clone(), wire);
                        progress = true;
                    }
                    Err(r) if r == "head_of_line_blocked" => {}
                    Err(r) => return Err(format!("publish {id}: {r}")),
                }
            }
        }
        let mut sequences = Vec::new();
        for id in &order {
            let wire = published
                .get(id)
                .ok_or_else(|| format!("claim {id} never published (head of line blocked)"))?;
            let again = self.store.publish(id, &recorded[id]);
            if again.as_ref() != Ok(wire) {
                return Err(format!(
                    "claim {id} republished differently ({:?})",
                    again.err()
                ));
            }
            sequences.push(receipt_sequence(wire));
        }
        sequences.sort_unstable();
        let want: Vec<i64> = (1..=sequences.len() as i64).collect();
        if sequences != want {
            return Err(format!(
                "receipt sequences {sequences:?}, want 1..{}",
                want.len()
            ));
        }
        Ok(())
    }
}

fn check_invariant(
    inv: &Value,
    labels: &BTreeMap<String, Vec<String>>,
    all: &[String],
) -> Result<(), String> {
    let groups = strings(&inv["groups"]);
    let of = || -> Vec<String> {
        if groups.is_empty() {
            all.to_vec()
        } else {
            groups
                .iter()
                .flat_map(|g| labels.get(g).cloned().unwrap_or_default())
                .collect()
        }
    };
    let outcomes = strings(&inv["outcomes"]);
    match s(&inv["kind"]).as_str() {
        "allowed" => {
            if let Some(l) = of().into_iter().find(|l| !outcomes.contains(l)) {
                return Err(format!(
                    "outcome {l:?} of {groups:?} is not one of {outcomes:?}"
                ));
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
            let winners: Vec<&String> = by_group
                .keys()
                .filter(|g| {
                    labels
                        .get(*g)
                        .is_some_and(|ls| ls.iter().any(|l| winning.contains(l)))
                })
                .collect();
            if winners.len() > 1 {
                return Err(format!("winning groups {winners:?}, want at most one"));
            }
            for (g, rule) in by_group {
                let want = strings(if winners.contains(&g) {
                    &rule["if_winner"]
                } else {
                    &rule["if_loser"]
                });
                for l in labels.get(g).into_iter().flatten() {
                    if !want.contains(l) {
                        return Err(format!(
                            "group {g} (winners {winners:?}) has outcome {l:?}, not one of {want:?}"
                        ));
                    }
                }
            }
        }
        other => return Err(format!("unknown invariant kind {other}")),
    }
    Ok(())
}

/// The duration of one uncancelled verification of the request that group
/// target verifies, on a scratch store, through the same cancel-aware
/// callbacks with the flag never set.
fn measure_verification(sc: &Value, target: &str) -> Duration {
    let p = arr(&sc["participants"])
        .into_iter()
        .find(|p| s(&p["group"]) == target && s(&p["op"]) == "verify")
        .unwrap_or_else(|| panic!("cancel target {target} has no verify participant"));
    let it = Iteration::new(i(&sc["start_time"]), b(&sc["rate_at_finalization"]));
    let prepared = it.prepare_verify(&s(&p["request"]), Some(Arc::new(AtomicBool::new(false))));
    let began = Instant::now();
    it.verify_label(&prepared);
    began.elapsed()
}

/// The cancel delay of iteration `iter` of `iterations`, in tenths of a
/// measured verification: Go's `iter % 13`, or with fewer than 13 iterations
/// spread over the same 0 to 12 range.
fn cancel_tenths(iter: usize, iterations: usize) -> u32 {
    let k = if iterations >= 13 { iter % 13 } else { iter * 12 / (iterations - 1).max(1) };
    k as u32
}

/// RATIFY_RACE_ITERATIONS, else the smaller of the file's default and
/// `C_ABI_DEFAULT_ITERATIONS`.
fn race_iterations(file_default: usize) -> usize {
    match std::env::var("RATIFY_RACE_ITERATIONS") {
        Ok(v) => match v.parse::<usize>() {
            Ok(n) if n >= 1 => n,
            _ => panic!("RATIFY_RACE_ITERATIONS={v:?} is not a positive integer"),
        },
        Err(_) => file_default.min(C_ABI_DEFAULT_ITERATIONS),
    }
}

#[test]
fn v2c_concurrency_scenarios() {
    let f = file();
    let scenarios = arr(&f["scenarios"]);
    assert!(
        i(&f["version"]) == 1 && !scenarios.is_empty(),
        "{FILE} version {} with {} scenarios",
        f["version"],
        scenarios.len()
    );
    let iterations = race_iterations(u(&f["default_iterations"]) as usize);
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let participants = arr(&sc["participants"]);
        // Each distinct outcome per group across iterations, printed so a
        // run with --nocapture shows which interleavings occurred.
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        // One uncancelled verification of a cancel target, measured once.
        let mut span: Option<Duration> = None;
        for iter in 0..iterations {
            let it = Iteration::new(i(&sc["start_time"]), b(&sc["rate_at_finalization"]));
            for (n, step) in arr(&sc["setup"]).iter().enumerate() {
                it.step(
                    &format!("{name} iteration {iter} setup {n}"),
                    step,
                    &step["expect"],
                );
            }
            // Prepare every participant on the test thread, then release
            // them together.
            let cancels: BTreeMap<String, Arc<AtomicBool>> = participants
                .iter()
                .filter(|p| s(&p["op"]) == "cancel")
                .map(|p| (s(&p["target"]), Arc::new(AtomicBool::new(false))))
                .collect();
            let mut groups = Vec::new();
            let mut tasks = Vec::new();
            for p in &participants {
                for _ in 0..u(&p["count"]) {
                    let task = match s(&p["op"]).as_str() {
                        "verify" => Task::Verify(it.prepare_verify(
                            &s(&p["request"]),
                            cancels.get(&s(&p["group"])).cloned(),
                        )),
                        "cancel" => {
                            // Spread the signal over the target's verification
                            // across iterations: 0 to 1.2 times its duration.
                            let target = s(&p["target"]);
                            let span =
                                *span.get_or_insert_with(|| measure_verification(sc, &target));
                            Task::Cancel(
                                span * cancel_tenths(iter, iterations) / 10,
                                Arc::clone(&cancels[&target]),
                            )
                        }
                        _ => Task::Op(p.clone()),
                    };
                    groups.push(s(&p["group"]));
                    tasks.push(task);
                }
            }
            let start = Barrier::new(tasks.len());
            let results: Vec<String> = std::thread::scope(|scope| {
                let handles: Vec<_> = tasks
                    .into_iter()
                    .map(|task| {
                        let (it, start) = (&it, &start);
                        scope.spawn(move || {
                            start.wait();
                            it.run(task)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("participant thread"))
                    .collect()
            });
            let mut labels: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (g, l) in groups.iter().zip(&results) {
                labels.entry(g.clone()).or_default().push(l.clone());
                *seen.entry(format!("{g}:{l}")).or_default() += 1;
            }
            for inv in arr(&sc["invariants"]) {
                let kind = s(&inv["kind"]);
                let result = if kind == "receipt_log_contiguous" {
                    it.receipt_log_contiguous()
                } else {
                    check_invariant(&inv, &labels, &results)
                };
                if let Err(e) = result {
                    panic!("{name} iteration {iter}: invariant {kind}: {e} (outcomes {labels:?})");
                }
            }
            for (n, step) in arr(&sc["after"]).iter().enumerate() {
                let at = format!("{name} iteration {iter} after {n}");
                let by = &step["expect_by_outcome"];
                let want = if by.is_null() {
                    step["expect"].clone()
                } else {
                    let got = labels.get(&s(&by["group"])).cloned().unwrap_or_default();
                    assert_eq!(
                        got.len(),
                        1,
                        "{at}: expect_by_outcome group {} has {} participants",
                        by["group"],
                        got.len()
                    );
                    let case = &by["cases"][&got[0]];
                    assert!(!case.is_null(), "{at}: no case for outcome {}", got[0]);
                    case.clone()
                };
                it.step(&at, step, &want);
            }
        }
        println!("{name}: {iterations} iterations, outcomes {seen:?}");
    }
    println!(
        "C-ABI COVERAGE {FILE}: {} scenarios, {iterations} iterations each",
        scenarios.len()
    );
}
