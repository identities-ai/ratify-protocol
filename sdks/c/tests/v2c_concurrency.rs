//! Concurrency through the C ABI (SPEC-v2 §1.3 thread-safety rules):
//! functions without a handle run concurrently, diagnostics are per thread,
//! independent verifications run in parallel, and concurrent claims of one
//! challenge against one shared store create exactly one claim.

mod v2c_common;

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use ratify_c::*;
use v2c_common::*;

const THREADS: usize = 8;

/// The reference store's callback struct, shared by threads: the store
/// itself is safe for concurrent use (it provides the atomic claim).
struct Shared(RatifyV2ClaimStoreCallbacks);

unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

#[test]
fn v2c_handle_free_functions_run_concurrently_with_per_thread_diagnostics() {
    let objects = Arc::new(load("objects.json"));
    let negatives = Arc::new(load("object-negatives.json"));
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let (objects, negatives) = (Arc::clone(&objects), Arc::clone(&negatives));
            scope.spawn(move || {
                for round in 0..3 {
                    for o in arr(&objects["objects"]) {
                        let wire = b64(&o["wire_b64"]);
                        let kind = kind_code(&s(&o["kind"]));
                        assert_eq!(
                            canonicalize(kind, &wire).expect("decode"),
                            wire,
                            "thread {t}"
                        );
                    }
                    // A failure on this thread is reported on this thread only.
                    let v = &arr(&negatives["vectors"])[(t + round) % 5];
                    let wire = b64(&v["wire_b64"]);
                    let kind = s(&v["kind"]);
                    if kind != "receipt_bundle_binding" {
                        let _ = canonicalize(kind_code(&kind), &wire);
                    }
                    let id = CString::new(format!("thread-{t}-not-a-key-id")).unwrap();
                    let code = unsafe { ratify_v2_key_id_check(id.as_ptr(), ptr::null_mut()) };
                    assert_eq!(class(code), "malformed");
                    assert!(
                        last_error().starts_with("malformed"),
                        "thread {t}: {}",
                        last_error()
                    );
                    assert_eq!(
                        unsafe { ratify_v2_key_id_check(ptr::null(), ptr::null_mut()) },
                        -1
                    );
                    assert!(
                        last_error().contains("key_id is null"),
                        "thread {t}: {}",
                        last_error()
                    );
                }
            });
        }
    });
}

#[test]
fn v2c_independent_verifications_run_in_parallel() {
    let f = Arc::new(load("verifier-ordering.json"));
    let names = [
        "allow_bound_context",
        "allow_context_not_required",
        "bad_challenge_signature",
    ];
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let f = Arc::clone(&f);
            scope.spawn(move || {
                let name = names[t % names.len()];
                let v = arr(&f["vectors"])
                    .into_iter()
                    .find(|v| s(&v["name"]) == name)
                    .expect("vector");
                let bundle = b64(&f["bundles_b64"][s(&v["bundle"])]);
                let counts = Arc::new(Counts::default());
                let mut setup = Setup::build(&v, &counts, true);
                let claimed_at = i(&v["now"]) + i(&v["claim_time_offset"]);
                let fx = Fixture::load_verifier_only();
                let store = RefStore::new(claimed_at, 60, "0123456789abcdef0123456789abcdef", &fx);
                setup.claim_cb = Some(store.claim(false));
                let out = verify(&setup, &bundle).expect("verify ran");
                assert_eq!(
                    out.stage,
                    s(&v["expected"]["stage"]),
                    "thread {t} {name}: {}",
                    out.message
                );
                if let Some(c) = &out.committed {
                    let body = parse(&c.body());
                    assert_eq!(
                        s(&body["decision"]),
                        s(&v["expected"]["decision"]),
                        "thread {t} {name}"
                    );
                }
            });
        }
    });
}

#[test]
fn v2c_concurrent_claims_of_one_challenge_create_exactly_one() {
    let f = load("lifecycle-scenarios.json");
    let inputs = &f["requests"]["A"];
    let bundle = b64(&f["bundles_b64"][s(&inputs["bundle"])]);
    let fx = Fixture::load();
    let store = RefStore::new(
        i(&inputs["now"]),
        i(&f["lease_seconds"]),
        &s(&f["log_id"]),
        fx.kp(&s(&f["verifier_key"])),
    );
    let claim = Shared(store.claim(false));
    let request = json_bytes(&request_json(inputs));
    let dispositions: Vec<i32> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let (bundle, request, claim) = (&bundle, &request, &claim);
                scope.spawn(move || {
                    let mut disposition = 0;
                    let mut id: *mut c_char = ptr::null_mut();
                    let code = unsafe {
                        ratify_v2_claim_proof_bundle(
                            bundle.as_ptr(),
                            bundle.len(),
                            request.as_ptr(),
                            request.len(),
                            &claim.0,
                            &mut disposition,
                            &mut id,
                        )
                    };
                    let _ = take_str(id);
                    check(code).expect("claim");
                    disposition
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let created = dispositions.iter().filter(|d| **d == 1).count();
    let in_progress = dispositions.iter().filter(|d| **d == 2).count();
    assert_eq!((created, in_progress), (1, THREADS - 1), "{dispositions:?}");
}

impl Fixture {
    /// Just the fixture's verifier key pair (for a reference store).
    fn load_verifier_only() -> Kp {
        let keys = load("keys.json");
        let k = arr(&keys["keys"])
            .into_iter()
            .find(|k| s(&k["name"]) == "verifier")
            .expect("verifier key");
        Kp::from_seeds(
            &hex::decode(s(&k["ed25519_seed_hex"])).unwrap(),
            &hex::decode(s(&k["ml_dsa_65_seed_hex"])).unwrap(),
        )
    }
}
