//! status-sequences.json, security-journal.json, and status-publisher.json
//! through the C ABI: the `ratify_v2_status_state_*` reducer handle, the
//! `ratify_v2_journal_*` operations over the reference journal's callback
//! interface, and `ratify_v2_status_publish`. Counts come from the corpus.

mod v2c_common;

use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use ratify_c::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use v2c_common::*;

struct State(*mut RatifyV2StatusState);

impl Drop for State {
    fn drop(&mut self) {
        unsafe { ratify_v2_status_state_free(self.0) };
    }
}

fn status_json(v: &Value) -> Value {
    json!({
        "status": s(&v["status"]),
        "reason": s(&v["reason"]),
        "evidence": arr(&v["evidence"]).iter().map(evidence_json).collect::<Vec<_>>(),
    })
}

/// Compare every member of `expect_state` with the reducer state JSON.
fn check_state(where_: &str, st: &Value, w: &Value) {
    let map = w.as_object().expect("expect_state object");
    for (k, want) in map {
        let got = match k.as_str() {
            "accepted_set" => &st["accepted_cert_ids"],
            "deny_union" => &st["deny_union_cert_ids"],
            "has_floor"
            | "floor"
            | "max_observed_sequence"
            | "fork_sequence"
            | "reconciliation_required"
            | "future_dated_object_observed" => &st[k],
            other => panic!("{where_}: expect_state member {other} is not checked by this harness"),
        };
        assert_eq!(got, want, "{where_}: {k}");
    }
}

#[test]
fn v2c_status_sequences() {
    let fx = Fixture::load();
    let f = load("status-sequences.json");
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no status scenarios");
    let (mut steps_run, mut queries, mut errors, mut total) = (0usize, 0usize, 0usize, 0usize);
    let mut body_digests = 0usize;
    for sc in &scenarios {
        let name = s(&sc["name"]);
        let issuer = cs(&s(&sc["issuer_id"]));
        let mut h = ptr::null_mut();
        check(unsafe { ratify_v2_status_state_new(&mut h) }).unwrap();
        let state = State(h);
        let steps = arr(&sc["steps"]);
        total += steps.len();
        for (n, step) in steps.iter().enumerate() {
            steps_run += 1;
            let key = fx.key(&s(&step["status_key"]));
            let policy = match step.get("policy") {
                Some(p) if !p.is_null() => status_policy_struct(p),
                _ => status_policy_struct(&sc["policy"]),
            };
            let epoch = u(&step["status_key_epoch"]);
            let now = i(&step["now"]);
            let op = s(&step["op"]);
            let label = s(&step["label"]);
            let result = match op.as_str() {
                "apply_list" | "apply_push" => {
                    let wire = b64(&step["wire_b64"]);
                    let kind = if op == "apply_list" { 3 } else { 5 };
                    check(unsafe {
                        ratify_v2_status_state_apply(
                            state.0,
                            kind,
                            ptr_of(&wire),
                            wire.len(),
                            issuer.as_ptr(),
                            epoch,
                            &key,
                            &policy,
                            now,
                        )
                    })
                }
                "transition_epoch" => check(unsafe {
                    ratify_v2_status_state_transition_epoch(state.0, issuer.as_ptr(), epoch, &key)
                }),
                "query" => {
                    queries += 1;
                    let cert = cs(&s(&step["cert_id"]));
                    let r = buf(|o| unsafe {
                        ratify_v2_status_state_query(
                            state.0,
                            issuer.as_ptr(),
                            cert.as_ptr(),
                            epoch,
                            &key,
                            &policy,
                            now,
                            o,
                        )
                    })
                    .unwrap_or_else(|e| panic!("{name} step {n} query: {e:?}"));
                    assert_eq!(
                        status_json(&parse(&r)),
                        status_json(&step["expect_result"]),
                        "{name} step {n} query"
                    );
                    continue;
                }
                other => panic!("unknown op {other:?}"),
            };
            if let Some(class) = step.get("expect_error_class").and_then(Value::as_str) {
                errors += 1;
                assert_eq!(class_of(&result), class, "{name} step {n} {op} {label}");
                continue;
            }
            result.unwrap_or_else(|e| panic!("{name} step {n} {op} {label}: {e:?}"));
            if let Some(w) = step.get("expect_state").filter(|w| !w.is_null()) {
                let st =
                    parse(&buf(|o| unsafe { ratify_v2_status_state_json(state.0, o) }).unwrap());
                check_state(&format!("{name} step {n} {op} {label}"), &st, w);
            }
            // SPEC-v2 §6.6: the observation's body_digest is the unlabelled
            // SHA-384 of the canonical signable body.
            if let Some(want) = step.get("expect_body_digest").and_then(Value::as_str) {
                body_digests += 1;
                let st =
                    parse(&buf(|o| unsafe { ratify_v2_status_state_json(state.0, o) }).unwrap());
                let code = if op == "apply_push" { 5 } else { 3 };
                let found = arr(&st["observations"]).iter().any(|o| {
                    u(&o["status_key_epoch"]) == epoch
                        && u(&o["object_type_code"]) == code
                        && format!("sha384:{}", hex::encode(b64(&o["body_digest"]))) == want
                });
                assert!(
                    found,
                    "{name} step {n} {op} {label}: no observation with body_digest {want}: {st}"
                );
            }
        }
    }
    println!("C-ABI COVERAGE status-sequences.json: {} scenarios, {steps_run} steps ({queries} queries, {errors} errors)", scenarios.len());
    assert_eq!(steps_run, total);
    assert_eq!(
        (scenarios.len(), total, queries, errors, body_digests),
        (22, 112, 43, 3, 63),
        "status-sequences.json"
    );
    let readme = readme_line("status-sequences.json");
    assert!(
        readme.contains(&format!(
            "{} status-reducer scenarios ({total} steps)",
            scenarios.len()
        )),
        "README disagrees: {readme}"
    );
}

fn journal_snapshot(cb: &RatifyV2JournalStoreCallbacks) -> Vec<u8> {
    let mut out = RatifyV2JournalSnapshot {
        snapshot: null_slice(),
        generation: 0,
        digest: ptr::null(),
    };
    let code = unsafe { (cb.load.unwrap())(cb.user, &mut out) };
    assert_eq!(code, 0, "journal load");
    unsafe { slice_in(out.snapshot) }
}

fn journal_digest(snapshot: &[u8]) -> String {
    string(|o| unsafe { ratify_v2_security_journal_digest(ptr_of(snapshot), snapshot.len(), o) })
        .unwrap()
}

#[test]
fn v2c_security_journal() {
    let f = load("security-journal.json");

    // Genesis snapshot and digest.
    let mut generation = 0u64;
    let mut digest_ptr = ptr::null_mut();
    let snapshot =
        buf(|o| unsafe { ratify_v2_journal_genesis(o, &mut generation, &mut digest_ptr) }).unwrap();
    let digest = take_str(digest_ptr);
    assert_eq!(
        String::from_utf8(snapshot.clone()).unwrap(),
        s(&f["genesis_snapshot"])
    );
    assert_eq!(digest, s(&f["genesis_digest"]));
    assert_eq!(journal_digest(&snapshot), digest);

    // Transition scenarios.
    let (mut scenarios, mut steps, mut total) = (0usize, 0usize, 0usize);
    for sc in arr(&f["scenarios"]) {
        let name = s(&sc["name"]);
        let journal = RefJournal::new();
        let cb = journal.callbacks();
        let all = arr(&sc["steps"]);
        total += all.len();
        for (n, step) in all.iter().enumerate() {
            steps += 1;
            let before = journal.head();
            let op = s(&step["op"]);
            let key = if step["key"]["public_key"].is_null() {
                zero_key()
            } else {
                key_struct(&step["key"]["public_key"])
            };
            let issuer = cs(&s(&step["issuer_id"]));
            let epoch = u(&step["epoch"]);
            let result = match op.as_str() {
                "record_key_role" => {
                    let role = cs(&s(&step["role"]));
                    check(unsafe { ratify_v2_journal_record_key_role(&cb, role.as_ptr(), &key) })
                }
                "configure_status_key_epoch" => check(unsafe {
                    ratify_v2_journal_configure_status_key(&cb, issuer.as_ptr(), epoch, &key)
                }),
                "apply_revocation_list" | "apply_revocation_push" => {
                    let wire = b64(&step["wire_b64"]);
                    let kind = if op == "apply_revocation_list" { 3 } else { 5 };
                    let policy = status_policy_struct(&step["policy"]);
                    check(unsafe {
                        ratify_v2_journal_apply(
                            &cb,
                            kind,
                            ptr_of(&wire),
                            wire.len(),
                            issuer.as_ptr(),
                            epoch,
                            &key,
                            &policy,
                            i(&step["now"]),
                        )
                    })
                }
                other => panic!("unknown op {other}"),
            };
            assert_eq!(
                result.is_err(),
                b(&step["expect_rejected"]),
                "{name} step {n} {op}: {result:?}"
            );
            let after = journal.head();
            assert_eq!(
                after != before,
                b(&step["expect_changed"]),
                "{name} step {n} {op}: changed"
            );
            assert_eq!(
                (after.0, after.1.clone()),
                (
                    u(&step["expect_head"]["generation"]),
                    s(&step["expect_head"]["digest"])
                ),
                "{name} step {n} {op}: head"
            );
            let got = journal_snapshot(&cb);
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&b64(&step["expect_snapshot_b64"])),
                "{name} step {n} {op}: snapshot"
            );
            assert_eq!(journal_digest(&got), after.1, "{name} step {n}");
        }
        scenarios += 1;
    }
    assert_eq!(steps, total);
    assert!(scenarios > 0 && steps > 0);

    // Version 1 migration.
    let m = &f["migration"];
    let input = b64(&m["legacy_digest_input_b64"]);
    assert_eq!(
        hex::encode(Sha384::digest(&input)),
        s(&m["legacy_digest"]),
        "legacy digest is not SHA-384 of its input"
    );
    let legacy = b64(&m["legacy_record_b64"]);
    let cleared =
        buf(|o| unsafe { ratify_v2_journal_legacy_encode(legacy.as_ptr(), legacy.len(), 1, o) })
            .unwrap();
    assert_eq!(
        String::from_utf8(cleared).unwrap(),
        String::from_utf8(input).unwrap()
    );
    let mut head = empty_buf();
    let migrated =
        buf(|o| unsafe { ratify_v2_journal_migrate(legacy.as_ptr(), legacy.len(), o, &mut head) })
            .unwrap();
    let head = parse(&take(head));
    assert_eq!(
        (u(&head["generation"]), s(&head["digest"])),
        (
            u(&m["expect_head"]["generation"]),
            s(&m["expect_head"]["digest"])
        )
    );
    assert_eq!(s(&head["previous_digest"]), s(&m["expect_previous_digest"]));
    assert_eq!(migrated, b64(&m["expect_snapshot_b64"]));
    let tampered = b64(&m["tampered_legacy_record_b64"]);
    let mut head2 = empty_buf();
    let r = buf(|o| unsafe {
        ratify_v2_journal_migrate(tampered.as_ptr(), tampered.len(), o, &mut head2)
    });
    take(head2);
    assert!(r.is_err(), "migrated a tampered legacy record");

    // Import negatives.
    let mut negatives = 0usize;
    for neg in arr(&f["import_negatives"]) {
        let name = s(&neg["name"]);
        let snap = b64(&neg["snapshot_b64"]);
        let dg = cs(&s(&neg["head"]["digest"]));
        let r = check(unsafe {
            ratify_v2_journal_import(
                ptr_of(&snap),
                snap.len(),
                u(&neg["head"]["generation"]),
                dg.as_ptr(),
                ptr::null_mut(),
            )
        });
        assert_eq!(
            class_of(&r),
            s(&neg["expect_error_class"]),
            "import_{name}: {r:?}"
        );
        negatives += 1;
    }
    // Transition negatives: valid snapshot pairs whose transition fails.
    let mut transitions = 0usize;
    for neg in arr(&f["transition_negatives"]) {
        let name = s(&neg["name"]);
        let (cur, next) = (
            b64(&neg["current_snapshot_b64"]),
            b64(&neg["next_snapshot_b64"]),
        );
        let (cur_d, next_d) = (
            cs(&s(&neg["current_head"]["digest"])),
            cs(&s(&neg["next_head"]["digest"])),
        );
        for (snap, head, d) in [
            (&cur, &neg["current_head"], &cur_d),
            (&next, &neg["next_head"], &next_d),
        ] {
            check(unsafe {
                ratify_v2_journal_import(
                    ptr_of(snap),
                    snap.len(),
                    u(&head["generation"]),
                    d.as_ptr(),
                    ptr::null_mut(),
                )
            })
            .unwrap_or_else(|e| panic!("transition_{name}: snapshot does not import: {e:?}"));
        }
        let r = check(unsafe {
            ratify_v2_journal_validate_transition(
                ptr_of(&cur),
                cur.len(),
                u(&neg["current_head"]["generation"]),
                cur_d.as_ptr(),
                ptr_of(&next),
                next.len(),
                u(&neg["next_head"]["generation"]),
                next_d.as_ptr(),
            )
        });
        assert_eq!(
            class_of(&r),
            s(&neg["expect_error_class"]),
            "transition_{name}: {r:?}"
        );
        transitions += 1;
    }
    assert_eq!(
        (scenarios, steps, negatives, transitions),
        (2, 17, 20, 6),
        "security-journal.json"
    );
    println!("C-ABI COVERAGE security-journal.json: {scenarios} scenarios, {steps} steps, 1 migration, {negatives} import negatives, {transitions} transition negatives");
    let readme = readme_line("security-journal.json");
    assert!(
        readme.contains(&format!("{scenarios} transition scenarios ({steps} steps"))
            && readme.contains(&format!("{negatives} import negatives"))
            && readme.contains(&format!("{transitions} `transition_negatives`")),
        "README disagrees: {readme}"
    );
}

/// An external signer that counts every method call and refuses to sign.
struct CountingRefusal {
    calls: AtomicUsize,
    key: RatifyV2PublicKey,
}

unsafe extern "C" fn counting_public_key(user: *mut c_void, out: *mut RatifyV2PublicKey) -> i32 {
    let c = &*(user as *const CountingRefusal);
    c.calls.fetch_add(1, Ordering::SeqCst);
    *out = c.key;
    0
}

unsafe extern "C" fn counting_sign(
    user: *mut c_void,
    _req: *const RatifyV2SignRequest,
    _out: *mut RatifyV2Signature,
) -> i32 {
    (*(user as *const CountingRefusal))
        .calls
        .fetch_add(1, Ordering::SeqCst);
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}

/// One publication: list wire, optional push wire, next state JSON.
struct Publication {
    list: Vec<u8>,
    push: Vec<u8>,
    state: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn publish(
    op: i32,
    journal: &RatifyV2JournalStoreCallbacks,
    issuer_key: &RatifyV2PublicKey,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    lifetime: i64,
    state: &[u8],
    cert_ids: &[u8],
    at: i64,
) -> R<Publication> {
    let (mut list, mut push, mut next) = (empty_buf(), empty_buf(), empty_buf());
    let code = unsafe {
        ratify_v2_status_publish(
            op,
            journal,
            issuer_key,
            local,
            external,
            lifetime,
            ptr_of(state),
            state.len(),
            ptr_of(cert_ids),
            cert_ids.len(),
            at,
            &mut list,
            &mut push,
            &mut next,
        )
    };
    let p = Publication {
        list: take(list),
        push: take(push),
        state: take(next),
    };
    check(code).map(|_| p)
}

fn revoked_ids(wire: &Value) -> Vec<String> {
    arr(&wire["revoked"])
        .iter()
        .map(|r| s(&r["cert_id"]))
        .collect()
}

fn strings(v: &Value) -> Vec<String> {
    arr(v).iter().map(s).collect()
}

#[test]
fn v2c_status_publisher() {
    let f = load("status-publisher.json");
    let fx = Fixture::load();
    let all = arr(&f["scenarios"]);
    assert!(!all.is_empty(), "no status publisher scenarios");
    let policy = status_policy_struct(&f["status_policy"]);
    let (mut scenarios, mut steps, mut total) = (0usize, 0usize, 0usize);
    for sc in &all {
        scenarios += 1;
        let name = s(&sc["name"]);
        total += arr(&sc["steps"]).len();
        let issuer_key = fx.key(&s(&sc["issuer"]));
        let status_name = s(&sc["status_key"]);
        let status_key = fx.key(&status_name);
        let issuer_id = fx.id.get(&s(&sc["issuer"])).cloned().unwrap_or_default();
        let issuer_c = cs(&issuer_id);
        let journal = RefJournal::new();
        let cb = journal.callbacks();
        for rk in arr(&sc["role_keys"]) {
            let role = cs(&s(&rk["role"]));
            let key = fx.key(&s(&rk["key"]));
            check(unsafe { ratify_v2_journal_record_key_role(&cb, role.as_ptr(), &key) })
                .unwrap_or_else(|e| panic!("{name}: record role: {e:?}"));
        }
        let mut setup = "not_configured";
        let configured_for = s(&sc["status_configured_for"]);
        if !configured_for.is_empty() {
            setup = "configured";
            let target = cs(&fx.id.get(&configured_for).cloned().unwrap_or_default());
            if check(unsafe {
                ratify_v2_journal_configure_status_key(&cb, target.as_ptr(), 1, &status_key)
            })
            .is_err()
            {
                setup = "rejected";
            }
        }
        assert_eq!(setup, s(&sc["journal_setup"]), "{name}: journal setup");
        let lifetime = i(&sc["lifetime_seconds"]);
        match s(&sc["publisher"]).as_str() {
            "ok" => {}
            "refused" => {
                // Construction is refused before any signing; a counting
                // external signer sees at most the key-binding query.
                let counter = CountingRefusal {
                    calls: AtomicUsize::new(0),
                    key: status_key,
                };
                let ext = RatifyV2ExternalSigner {
                    user: &counter as *const CountingRefusal as *mut c_void,
                    mode: RatifyV2SignerMode::RatifyV2SignerDirect as i32,
                    public_key: Some(counting_public_key),
                    sign: Some(counting_sign),
                };
                let r = publish(
                    1,
                    &cb,
                    &issuer_key,
                    ptr::null(),
                    &ext,
                    lifetime,
                    &[],
                    &[],
                    0,
                );
                assert_eq!(
                    class_of(&r),
                    "configuration_invalid",
                    "{name}: refusal class"
                );
                assert!(
                    counter.calls.load(Ordering::SeqCst) <= 1,
                    "{name}: a refused publisher invoked the signer"
                );
                let local = publish(
                    1,
                    &cb,
                    &issuer_key,
                    fx.kp(&status_name).0,
                    ptr::null(),
                    lifetime,
                    &[],
                    &[],
                    0,
                );
                assert_eq!(
                    class_of(&local),
                    "configuration_invalid",
                    "{name}: local refusal class"
                );
                steps += arr(&sc["steps"]).len();
                continue;
            }
            other => panic!("{name}: unknown publisher expectation {other}"),
        }
        let kp = fx.kp(&status_name);
        let mut state: Vec<u8> = Vec::new();
        let mut publications: Vec<Publication> = Vec::new();
        for (n, step) in arr(&sc["steps"]).iter().enumerate() {
            steps += 1;
            let exp = &step["expect"];
            let at = i(&step["at"]);
            let op = s(&step["op"]);
            let result = match op.as_str() {
                "genesis" => publish(
                    1,
                    &cb,
                    &issuer_key,
                    kp.0,
                    ptr::null(),
                    lifetime,
                    &[],
                    &[],
                    at,
                ),
                "heartbeat" => publish(
                    2,
                    &cb,
                    &issuer_key,
                    kp.0,
                    ptr::null(),
                    lifetime,
                    &state,
                    &[],
                    at,
                ),
                "revoke" => {
                    let ids = json_bytes(&json!(strings(&step["cert_ids"])));
                    publish(
                        3,
                        &cb,
                        &issuer_key,
                        kp.0,
                        ptr::null(),
                        lifetime,
                        &state,
                        &ids,
                        at,
                    )
                }
                "ingest" => {
                    let p = &publications[u(&step["publication"]) as usize];
                    let (kind, wire) = if s(&step["object"]) == "push" {
                        (5, &p.push)
                    } else {
                        (3, &p.list)
                    };
                    assert!(
                        !wire.is_empty(),
                        "{name} step {n}: publication has no {}",
                        s(&step["object"])
                    );
                    check(unsafe {
                        ratify_v2_journal_apply(
                            &cb,
                            kind,
                            wire.as_ptr(),
                            wire.len(),
                            issuer_c.as_ptr(),
                            1,
                            &status_key,
                            &policy,
                            at,
                        )
                    })
                    .unwrap_or_else(|e| panic!("{name} step {n}: ingest: {e:?}"));
                    continue;
                }
                "status" => {
                    let cert = cs(&s(&step["cert_id"]));
                    let r = parse(
                        &buf(|o| unsafe {
                            ratify_v2_journal_status(
                                &cb,
                                issuer_c.as_ptr(),
                                cert.as_ptr(),
                                1,
                                &status_key,
                                &policy,
                                at,
                                o,
                            )
                        })
                        .unwrap_or_else(|e| panic!("{name} step {n}: status: {e:?}")),
                    );
                    assert_eq!(
                        (s(&r["status"]), s(&r["reason"])),
                        (s(&exp["status"]), s(&exp["reason"])),
                        "{name} step {n}: status"
                    );
                    continue;
                }
                other => panic!("{name} step {n}: unknown op {other:?}"),
            };
            if s(&exp["result"]) == "refused" {
                assert!(result.is_err(), "{name} step {n}: {op} was not refused");
                continue;
            }
            let p = result.unwrap_or_else(|e| panic!("{name} step {n}: {op}: {e:?}"));
            let ctx = cs(
                &json!({"bound_issuer_id": issuer_id, "status_key": key_json(&status_key)})
                    .to_string(),
            );
            check(unsafe {
                ratify_v2_verify_object(
                    3,
                    p.list.as_ptr(),
                    p.list.len(),
                    ctx.as_ptr(),
                    ptr::null_mut(),
                )
            })
            .unwrap_or_else(|e| panic!("{name} step {n}: list signature: {e:?}"));
            let l = parse(&p.list);
            let el = &exp["list"];
            assert_eq!(
                (
                    i(&l["sequence"]),
                    i(&l["updated_at"]),
                    i(&l["next_update"]),
                    revoked_ids(&l)
                ),
                (
                    i(&el["sequence"]),
                    i(&el["updated_at"]),
                    i(&el["next_update"]),
                    strings(&el["revoked"])
                ),
                "{name} step {n}: list"
            );
            let ep = exp.get("push").filter(|p| !p.is_null());
            assert_eq!(
                !p.push.is_empty(),
                ep.is_some(),
                "{name} step {n}: push presence mismatch"
            );
            if let Some(ep) = ep {
                check(unsafe {
                    ratify_v2_verify_object(
                        5,
                        p.push.as_ptr(),
                        p.push.len(),
                        ctx.as_ptr(),
                        ptr::null_mut(),
                    )
                })
                .unwrap_or_else(|e| panic!("{name} step {n}: push signature: {e:?}"));
                let pw = parse(&p.push);
                assert_eq!(
                    (i(&pw["sequence"]), i(&pw["pushed_at"]), revoked_ids(&pw)),
                    (
                        i(&ep["sequence"]),
                        i(&ep["pushed_at"]),
                        strings(&ep["revoked"])
                    ),
                    "{name} step {n}: push"
                );
            }
            state = p.state.clone();
            publications.push(p);
        }
    }
    assert_eq!(steps, total);
    println!("C-ABI COVERAGE status-publisher.json: {scenarios} scenarios, {steps} steps");
    let readme = readme_line("status-publisher.json");
    assert!(
        readme.contains(&format!(
            "{scenarios} signed-status publisher scenarios ({steps} steps"
        )),
        "README disagrees: {readme}"
    );
}
