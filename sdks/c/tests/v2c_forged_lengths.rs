//! Forged lengths and counts at the C boundary (SPEC-v2 §1.3, §2.6).
//!
//! A C caller can pass any `size_t` with a pointer. Every `ratify_v2_*`
//! export that takes a (pointer, length) pair must classify a length that
//! no object can have before it forms a Rust slice, which aborts the host
//! process for a length over `isize::MAX`:
//!
//! - an input with a SPEC-v2 §2.6 byte limit (a strict decoder input) is
//!   reported exactly as a real input of that size is (`malformed` from the
//!   decoder's own size gate) and the caller's memory is never read;
//! - any other input over `isize::MAX` is `bad_argument`.
//!
//! Callback answers with forged lengths or counts fail closed the same way.
//! These tests pass a one-byte buffer with lengths up to `SIZE_MAX`.

mod v2c_common;

use std::os::raw::{c_char, c_void};
use std::ptr;

use ratify_c::*;
use v2c_common::*;

static ONE: [u8; 1] = [b'{'];

fn one() -> *const u8 {
    ONE.as_ptr()
}

/// Lengths no real object can have: over `isize::MAX`.
const HUGE: [usize; 2] = [isize::MAX as usize + 1, usize::MAX];

const CERT: usize = 32 << 10;
const BUNDLE: usize = 128 << 10;
const LIST: usize = 4 << 20;
const ROTATION: usize = 32 << 10;
const PUSH: usize = 256 << 10;
const WITNESS: usize = 64 << 10;
const TRANSACTION: usize = 5 << 20;
const RECEIPT: usize = 64 << 10;
const BATCH: usize = 8 << 20;
const ACK: usize = 1024;
const SNAPSHOT: usize = 64 << 20;

/// The SPEC-v2 §2.6 limit of an object kind or signature code.
fn limit(kind: i32) -> usize {
    match kind {
        1 => CERT,
        2 => BUNDLE,
        3 => LIST,
        4 | 9 => ROTATION,
        5 => PUSH,
        6 => WITNESS,
        7 => TRANSACTION,
        8 | 100 => RECEIPT,
        101 => BATCH,
        102 => ACK,
        other => panic!("no limit for kind {other}"),
    }
}

fn buffer_call(f: impl FnOnce(*mut RatifyV2Buffer) -> i32) -> i32 {
    let mut out = empty_buf();
    let code = f(&mut out);
    take(out);
    code
}

fn string_call(f: impl FnOnce(*mut *mut c_char) -> i32) -> i32 {
    let mut out: *mut c_char = ptr::null_mut();
    let code = f(&mut out);
    take_str(out);
    code
}

/// A decoder input with byte limit `limit`: a forged length is reported as
/// a real input one byte over the limit is, and that is `want`.
fn gated(name: &str, limit: usize, want: &str, f: impl Fn(*const u8, usize) -> i32) -> Vec<String> {
    let mut failures = Vec::new();
    let real = vec![b' '; limit + 1];
    let real_class = class(f(real.as_ptr(), real.len()));
    if real_class != want {
        failures.push(format!(
            "{name}: a real oversized input is {real_class}, want {want}"
        ));
    }
    for len in [limit + 1, isize::MAX as usize, HUGE[0], HUGE[1]] {
        let got = class(f(one(), len));
        if got != real_class {
            failures.push(format!(
                "{name}: length {len} is {got}, a real oversized input is {real_class}: {}",
                last_error()
            ));
        }
    }
    failures
}

/// An input with no byte limit: a length over `isize::MAX` is bad_argument.
fn ungated(name: &str, f: impl Fn(*const u8, usize) -> i32) -> Vec<String> {
    let mut failures = Vec::new();
    for len in HUGE {
        let code = f(one(), len);
        let message = last_error();
        if class(code) != "bad_argument" || !message.contains("isize::MAX") {
            failures.push(format!(
                "{name}: length {len} is {}: {message}",
                class(code)
            ));
        }
    }
    failures
}

/// The wire bytes of the first objects.json object of `kind`.
fn fixture(kind: &str) -> Vec<u8> {
    let f = load("objects.json");
    let o = arr(&f["objects"])
        .into_iter()
        .find(|o| s(&o["kind"]) == kind)
        .unwrap_or_else(|| panic!("no {kind} object"));
    b64(&o["wire_b64"])
}

fn finish(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// SPEC-v2 §2.6: an oversized object is `malformed` before parsing, also
/// when the C length is larger than any allocation could be.
#[test]
fn v2c_decoder_inputs_classify_forged_lengths_as_oversized() {
    let kp = Kp::generate().0;
    let pubk = kp.public();
    let pk = &pubk;
    let id = cs(&kp.id());
    let head = br#"{"log_id":"l","sequence":0,"head_hash_b64":"","accepted_digests_b64":{},"frozen":false}"#;
    let policy = RatifyV2StatusPolicy {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 3600,
        clock_skew_seconds: 5,
    };
    let digest = cs("");
    let mut f = Vec::new();

    for kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 101, 102] {
        f.extend(gated(
            &format!("object_decode {kind}"),
            limit(kind),
            "malformed",
            |p, l| buffer_call(|o| unsafe { ratify_v2_object_decode(kind, p, l, o) }),
        ));
    }
    for code in 1..=9u32 {
        f.extend(gated(
            &format!("signable_bytes {code}"),
            limit(code as i32),
            "malformed",
            |p, l| buffer_call(|o| unsafe { ratify_v2_signable_bytes(code, p, l, o) }),
        ));
    }
    for kind in 1..=8 {
        f.extend(gated(
            &format!("object_body_digest {kind}"),
            limit(kind),
            "malformed",
            |p, l| buffer_call(|o| unsafe { ratify_v2_object_body_digest(kind, p, l, o) }),
        ));
    }
    for kind in [3, 5] {
        f.extend(gated(
            &format!("status_evidence_digest {kind}"),
            limit(kind),
            "malformed",
            |p, l| buffer_call(|o| unsafe { ratify_v2_status_evidence_digest(kind, p, l, o) }),
        ));
        f.extend(gated(
            &format!("status_state_apply {kind}"),
            limit(kind),
            "malformed",
            |p, l| {
                let mut st = ptr::null_mut();
                check(unsafe { ratify_v2_status_state_new(&mut st) }).unwrap();
                let code = unsafe {
                    ratify_v2_status_state_apply(st, kind, p, l, id.as_ptr(), 1, pk, &policy, 150)
                };
                unsafe { ratify_v2_status_state_free(st) };
                code
            },
        ));
    }
    for kind in [1, 2] {
        f.extend(gated(
            &format!("verify_object {kind}"),
            limit(kind),
            "malformed",
            |p, l| unsafe { ratify_v2_verify_object(kind, p, l, ptr::null(), ptr::null_mut()) },
        ));
    }
    for kind in [1, 3, 4, 5, 6, 7, 8] {
        f.extend(gated(
            &format!("archival_verify {kind}"),
            limit(kind),
            "malformed",
            |p, l| {
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(kind, p, l, id.as_ptr(), pk, o)
                })
            },
        ));
    }
    // A proof bundle's archival class is in the result, not the return code.
    let archival = |p: *const u8, l: usize| {
        let r = buf(|o| unsafe { ratify_v2_archival_verify(2, p, l, ptr::null(), ptr::null(), o) })
            .expect("archival result");
        s(&parse(&r)["error_class"])
    };
    for len in [BUNDLE + 1, HUGE[0], HUGE[1]] {
        assert_eq!(
            archival(one(), len),
            "malformed",
            "archival_verify 2 length {len}"
        );
    }
    f.extend(gated("delegation_digest", BUNDLE, "malformed", |p, l| {
        buffer_call(|o| unsafe { ratify_v2_delegation_digest(p, l, o) })
    }));
    f.extend(gated("bundle_hash", BUNDLE, "malformed", |p, l| {
        string_call(|o| unsafe { ratify_v2_bundle_hash(p, l, o) })
    }));
    f.extend(gated(
        "proof_bundle_verify_signatures",
        BUNDLE,
        "malformed",
        |p, l| {
            let mut out = [0 as c_char; 128];
            unsafe {
                ratify_v2_proof_bundle_verify_signatures(
                    p,
                    l,
                    out.as_mut_ptr(),
                    out.len(),
                    ptr::null_mut(),
                )
            }
        },
    ));
    f.extend(gated(
        "verification_receipt_body",
        RECEIPT,
        "malformed",
        |p, l| buffer_call(|o| unsafe { ratify_v2_verification_receipt_body(p, l, o) }),
    ));
    f.extend(gated(
        "verification_receipt_verify",
        RECEIPT,
        "malformed",
        |p, l| {
            let h = cs(std::str::from_utf8(head).unwrap());
            unsafe {
                ratify_v2_verification_receipt_verify(
                    p,
                    l,
                    pk.ed25519.as_ptr(),
                    32,
                    pk.ml_dsa_65.as_ptr(),
                    1952,
                    h.as_ptr(),
                    ptr::null_mut(),
                )
            }
        },
    ));
    let bundle = [b' '; 4];
    f.extend(gated(
        "receipt_bundle_binding_check receipt",
        RECEIPT,
        "malformed",
        |p, l| unsafe {
            ratify_v2_receipt_bundle_binding_check(
                p,
                l,
                bundle.as_ptr(),
                bundle.len(),
                ptr::null_mut(),
            )
        },
    ));
    f.extend(gated(
        "witness_entry_append",
        WITNESS,
        "malformed",
        |p, l| {
            let mut result = 0;
            buffer_call(|o| unsafe {
                ratify_v2_witness_entry_append(p, l, head.as_ptr(), head.len(), pk, &mut result, o)
            })
        },
    ));
    f.extend(gated(
        "verification_receipt_append",
        RECEIPT,
        "malformed",
        |p, l| {
            let mut result = 0;
            buffer_call(|o| unsafe {
                ratify_v2_verification_receipt_append(
                    p,
                    l,
                    head.as_ptr(),
                    head.len(),
                    pk,
                    &mut result,
                    o,
                )
            })
        },
    ));
    f.extend(gated(
        "rotation_journal_accept",
        ROTATION,
        "malformed",
        |p, l| {
            let (a, r) = (cs("0123456789abcdef0123456789abcdef"), cs("issuer"));
            let mut j = ptr::null_mut();
            check(unsafe { ratify_v2_rotation_journal_new(a.as_ptr(), 1, r.as_ptr(), pk, &mut j) })
                .unwrap();
            let mut result = 0;
            let code = unsafe { ratify_v2_rotation_journal_accept(j, p, l, 0, 0, &mut result) };
            unsafe { ratify_v2_rotation_journal_free(j) };
            code
        },
    ));
    f.extend(gated("journal_import", SNAPSHOT, "malformed", |p, l| {
        buffer_call(|o| unsafe { ratify_v2_journal_import(p, l, 0, digest.as_ptr(), o) })
    }));
    f.extend(gated(
        "journal_validate_transition current",
        SNAPSHOT,
        "malformed",
        |p, l| unsafe {
            ratify_v2_journal_validate_transition(
                p,
                l,
                0,
                digest.as_ptr(),
                one(),
                1,
                0,
                digest.as_ptr(),
            )
        },
    ));
    f.extend(gated("claim_proof_bundle", BUNDLE, "malformed", |p, l| {
        let store: RatifyV2ClaimStoreCallbacks = unsafe { std::mem::zeroed() };
        let mut disposition = 0;
        string_call(|o| unsafe {
            ratify_v2_claim_proof_bundle(p, l, b"{}".as_ptr(), 2, &store, &mut disposition, o)
        })
    }));
    // Each verifier keeps its own ordering, as for a real oversized input:
    // transaction verification validates its configuration first (SPEC-v2
    // §5.7), while the live verifier decodes the bundle before it checks its
    // configuration (§6.2), so a request with no claim store is malformed.
    f.extend(gated(
        "verify_transaction_receipt",
        TRANSACTION,
        "configuration_invalid",
        |p, l| {
            buffer_call(|o| unsafe {
                ratify_v2_verify_transaction_receipt(
                    p,
                    l,
                    -1,
                    0,
                    b"{}".as_ptr(),
                    2,
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    o,
                )
            })
        },
    ));
    f.extend(gated(
        "verify_proof_bundle",
        BUNDLE,
        "malformed",
        |p, l| {
            let mut outcome = RatifyV2VerifyOutcome {
                stage: 0,
                error_code: 0,
                disposition: 0,
            };
            let mut record = empty_buf();
            let mut committed = ptr::null_mut();
            let code = unsafe {
                ratify_v2_verify_proof_bundle(
                    p,
                    l,
                    b"{}".as_ptr(),
                    2,
                    ptr::null(),
                    ptr::null(),
                    &mut outcome,
                    &mut record,
                    &mut committed,
                )
            };
            take(record);
            if code != 0 {
                code
            } else {
                outcome.error_code
            }
        },
    ));
    finish(f);
}

/// Every other byte input over `isize::MAX` is `bad_argument`, never an
/// abort.
#[test]
fn v2c_other_byte_inputs_reject_lengths_over_isize_max() {
    let kp = Kp::generate().0;
    let pubk = kp.public();
    let pk = &pubk;
    let head = br#"{"log_id":"l","sequence":0,"head_hash_b64":"","accepted_digests_b64":{},"frozen":false}"#;
    let ns = b"ns";
    let receipt = fixture("verification_receipt");
    let witness = fixture("witness_entry");
    let mut f = Vec::new();
    let b = |name: &str, g: &dyn Fn(*mut RatifyV2Buffer, *const u8, usize) -> i32| {
        ungated(name, |p, l| buffer_call(|o| g(o, p, l)))
    };
    let st = |name: &str, g: &dyn Fn(*mut *mut c_char, *const u8, usize) -> i32| {
        ungated(name, |p, l| string_call(|o| g(o, p, l)))
    };
    unsafe {
        f.extend(b("signing_message", &|o, p, l| {
            ratify_v2_signing_message(1, p, l, o)
        }));
        f.extend(b("external_mu", &|o, p, l| {
            ratify_v2_external_mu(pk, 1, p, l, o)
        }));
        f.extend(ungated("verify_statement signable", |p, l| {
            ratify_v2_verify_statement(1, p, l, null_slice(), null_slice(), pk)
        }));
        f.extend(ungated("verify_statement signature", |p, l| {
            let sig = RatifyV2Slice { ptr: p, len: l };
            ratify_v2_verify_statement(1, one(), 1, sig, sig, pk)
        }));
        f.extend(b("challenge_claim_digest", &|o, p, l| {
            ratify_v2_challenge_claim_digest(p, l, o)
        }));
        f.extend(st("claim_id namespace", &|o, p, l| {
            ratify_v2_claim_id(p, l, 0, [0u8; 32].as_ptr(), 32, o)
        }));
        f.extend(st("claim_id challenge", &|o, p, l| {
            ratify_v2_claim_id(ns.as_ptr(), 2, 0, p, l, o)
        }));
        f.extend(st("claim_id_from_digest namespace", &|o, p, l| {
            ratify_v2_claim_id_from_digest(p, l, 0, [0u8; 48].as_ptr(), 48, o)
        }));
        f.extend(st("claim_id_from_digest digest", &|o, p, l| {
            ratify_v2_claim_id_from_digest(ns.as_ptr(), 2, 0, p, l, o)
        }));
        f.extend(b("statement_body_digest", &|o, p, l| {
            ratify_v2_statement_body_digest(3, p, l, o)
        }));
        f.extend(b("revoked_set_digest", &|o, p, l| {
            ratify_v2_revoked_set_digest(p, l, o)
        }));
        f.extend(st("receipt_outbox_digest", &|o, p, l| {
            ratify_v2_receipt_outbox_digest(p, l, o)
        }));
        f.extend(st("security_journal_digest", &|o, p, l| {
            ratify_v2_security_journal_digest(p, l, o)
        }));
        f.extend(b("transaction_context_hash", &|o, p, l| {
            let (t, u) = (cs("t"), cs("urn:x"));
            ratify_v2_transaction_context_hash(t.as_ptr(), u.as_ptr(), p, l, o)
        }));
        f.extend(b("transaction_party_request_hash", &|o, p, l| {
            let scope = cs("files:read");
            ratify_v2_transaction_party_request_hash(p, l, scope.as_ptr(), o)
        }));
        f.extend(b("operation_context_hash", &|o, p, l| {
            ratify_v2_operation_context_hash(p, l, o)
        }));
        f.extend(b("session_context", &|o, p, l| {
            ratify_v2_session_context(p, l, o)
        }));
        f.extend(st("context_policy_digest", &|o, p, l| {
            ratify_v2_context_policy_digest(p, l, o)
        }));
        f.extend(b("canonical_json", &|o, p, l| {
            ratify_v2_canonical_json(p, l, o)
        }));
        f.extend(ungated("validate_scopes", |p, l| {
            ratify_v2_validate_scopes(p, l)
        }));
        f.extend(ungated("validate_request_context", |p, l| {
            ratify_v2_validate_request_context(p, l)
        }));
        f.extend(ungated("evaluate_standard_profile", |p, l| {
            let profile = cs("com.ratifyprotocol.max_count/v1");
            let (mut outcome, mut until, mut detail) = (0, 0, ptr::null_mut());
            let code = ratify_v2_evaluate_standard_profile(
                profile.as_ptr(),
                p,
                l,
                &mut outcome,
                &mut until,
                &mut detail,
            );
            take_str(detail);
            code
        }));
        // The terminal result and receipt body are read only after a valid
        // claim record; v2c_verifier.rs probes them with a real one.
        f.extend(ungated(
            "validate_finalization_payload claim_record",
            |p, l| ratify_v2_validate_finalization_payload(p, l, one(), 1, one(), 1),
        ));
        f.extend(ungated("cross_sdk_fixture_verify", |p, l| {
            let sdk = cs("go");
            ratify_v2_cross_sdk_fixture_verify(p, l, sdk.as_ptr())
        }));
        for arg in 0..2 {
            f.extend(ungated(&format!("key_id {arg}"), |p, l| {
                let mut a = [
                    (pk.ed25519.as_ptr(), 32usize),
                    (pk.ml_dsa_65.as_ptr(), 1952),
                ];
                a[arg] = (p, l);
                let mut out = [0 as c_char; 128];
                ratify_v2_key_id(
                    a[0].0,
                    a[0].1,
                    a[1].0,
                    a[1].1,
                    out.as_mut_ptr(),
                    out.len(),
                    ptr::null_mut(),
                )
            }));
        }
        for arg in 0..2 {
            f.extend(ungated(
                &format!("verification_receipt_verify key {arg}"),
                |p, l| {
                    let mut a = [
                        (pk.ed25519.as_ptr(), 32usize),
                        (pk.ml_dsa_65.as_ptr(), 1952),
                    ];
                    a[arg] = (p, l);
                    let h = cs(std::str::from_utf8(head).unwrap());
                    ratify_v2_verification_receipt_verify(
                        receipt.as_ptr(),
                        receipt.len(),
                        a[0].0,
                        a[0].1,
                        a[1].0,
                        a[1].1,
                        h.as_ptr(),
                        ptr::null_mut(),
                    )
                },
            ));
        }
        f.extend(gated(
            "receipt_bundle_binding_check bundle",
            BUNDLE,
            "malformed",
            |p, l| {
                ratify_v2_receipt_bundle_binding_check(
                    receipt.as_ptr(),
                    receipt.len(),
                    p,
                    l,
                    ptr::null_mut(),
                )
            },
        ));
        let local = kp.0 as *const RatifyV2KeyPair;
        f.extend(b("sign_delegation_certificate", &|o, p, l| {
            ratify_v2_sign_delegation_certificate(p, l, local, ptr::null(), o)
        }));
        f.extend(b("sign_proof_bundle", &|o, p, l| {
            ratify_v2_sign_proof_bundle(p, l, local, ptr::null(), o)
        }));
        let issuer = cs(&kp.id());
        f.extend(b("sign_revocation_list", &|o, p, l| {
            ratify_v2_sign_revocation_list(p, l, issuer.as_ptr(), pk, local, ptr::null(), o)
        }));
        f.extend(b("sign_revocation_push", &|o, p, l| {
            ratify_v2_sign_revocation_push(p, l, issuer.as_ptr(), pk, local, ptr::null(), o)
        }));
        f.extend(b("sign_key_rotation_statement", &|o, p, l| {
            ratify_v2_sign_key_rotation_statement(p, l, local, ptr::null(), local, ptr::null(), o)
        }));
        f.extend(b("sign_witness_entry", &|o, p, l| {
            ratify_v2_sign_witness_entry(p, l, local, ptr::null(), o)
        }));
        f.extend(b("sign_verification_receipt", &|o, p, l| {
            ratify_v2_sign_verification_receipt(p, l, local, ptr::null(), o)
        }));
        f.extend(b("sign_prepared_verification_receipt body", &|o, p, l| {
            ratify_v2_sign_prepared_verification_receipt(
                p,
                l,
                head.as_ptr(),
                head.len(),
                local,
                ptr::null(),
                o,
            )
        }));
        f.extend(b("sign_prepared_verification_receipt head", &|o, p, l| {
            ratify_v2_sign_prepared_verification_receipt(one(), 1, p, l, local, ptr::null(), o)
        }));
        f.extend(b("sign_transaction_receipt_party", &|o, p, l| {
            let party = cs("p");
            ratify_v2_sign_transaction_receipt_party(p, l, party.as_ptr(), local, ptr::null(), o)
        }));
        f.extend(b("witness_entry_append head", &|o, p, l| {
            let mut result = 0;
            ratify_v2_witness_entry_append(
                witness.as_ptr(),
                witness.len(),
                p,
                l,
                pk,
                &mut result,
                o,
            )
        }));
        f.extend(b("verification_receipt_append head", &|o, p, l| {
            let mut result = 0;
            ratify_v2_verification_receipt_append(
                receipt.as_ptr(),
                receipt.len(),
                p,
                l,
                pk,
                &mut result,
                o,
            )
        }));
        f.extend(b("journal_migrate", &|o, p, l| {
            let mut snapshot = empty_buf();
            let code = ratify_v2_journal_migrate(p, l, &mut snapshot, o);
            take(snapshot);
            code
        }));
        f.extend(b("journal_legacy_encode", &|o, p, l| {
            ratify_v2_journal_legacy_encode(p, l, 0, o)
        }));
        f.extend(b("issue_challenge", &|o, p, l| {
            ratify_v2_issue_challenge(p, l, ptr::null(), ptr::null(), ptr::null(), o)
        }));
        f.extend(b("load_expected_challenge", &|o, p, l| {
            let store: RatifyV2IssuanceStoreCallbacks = std::mem::zeroed();
            let n = cs("ns");
            ratify_v2_load_expected_challenge(&store, n.as_ptr(), 0, p, l, o)
        }));
        f.extend(b("verify_transaction_receipt config", &|o, p, l| {
            ratify_v2_verify_transaction_receipt(
                one(),
                1,
                0,
                0,
                p,
                l,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                o,
            )
        }));
        f.extend(st("claim_proof_bundle request", &|o, p, l| {
            let store: RatifyV2ClaimStoreCallbacks = std::mem::zeroed();
            let mut disposition = 0;
            ratify_v2_claim_proof_bundle(one(), 1, p, l, &store, &mut disposition, o)
        }));
        f.extend(ungated("verify_proof_bundle request", |p, l| {
            let mut outcome = RatifyV2VerifyOutcome {
                stage: 0,
                error_code: 0,
                disposition: 0,
            };
            let mut record = empty_buf();
            let mut committed = ptr::null_mut();
            let code = ratify_v2_verify_proof_bundle(
                one(),
                1,
                p,
                l,
                ptr::null(),
                ptr::null(),
                &mut outcome,
                &mut record,
                &mut committed,
            );
            take(record);
            code
        }));
        let journal: RatifyV2JournalStoreCallbacks = std::mem::zeroed();
        for arg in 0..2 {
            f.extend(ungated(&format!("status_publish {arg}"), |p, l| {
                let state = br#"{"issuer_id":"i","status_key_id":"k","sequence":1,"updated_at":1,"revoked":[]}"#;
                let mut a = [(state.as_ptr(), state.len()), (b"[]".as_ptr(), 2)];
                a[arg] = (p, l);
                let (mut x, mut y, mut z) = (empty_buf(), empty_buf(), empty_buf());
                let code = ratify_v2_status_publish(
                    3, &journal, pk, local, ptr::null(), 3600, a[0].0, a[0].1, a[1].0, a[1].1, 0,
                    &mut x, &mut y, &mut z,
                );
                take(x);
                take(y);
                take(z);
                code
            }));
        }
        // Test-reference exports.
        let mut store = ptr::null_mut();
        let log = cs("0123456789abcdef0123456789abcdef");
        check(ratify_v2_ref_store_new(
            1000,
            60,
            log.as_ptr(),
            kp.0,
            &mut store,
        ))
        .unwrap();
        f.extend(b("ref_store_publish", &|o, p, l| {
            let id = cs("c");
            let mut refusal = ptr::null();
            ratify_v2_ref_store_publish(store, id.as_ptr(), p, l, o, &mut refusal)
        }));
        f.extend(ungated("ref_device_new", |p, l| {
            let mut d = ptr::null_mut();
            let code = ratify_v2_ref_device_new(store, p, l, 1, 0, &mut d);
            ratify_v2_ref_device_free(d);
            code
        }));
        ratify_v2_ref_store_free(store);
        f.extend(b("ref_device_state_projection", &|o, p, l| {
            ratify_v2_ref_device_state_projection(p, l, o)
        }));
        let mut ledger = ptr::null_mut();
        check(ratify_v2_ref_ledger_new(&mut ledger)).unwrap();
        f.extend(ungated("ref_ledger_open", |p, l| {
            let mut e = ptr::null();
            ratify_v2_ref_ledger_open(ledger, p, l, &mut e)
        }));
        f.extend(ungated("ref_ledger_record", |p, l| {
            let (set, mut complete, mut e) = (cs("s"), 0, ptr::null());
            ratify_v2_ref_ledger_record(
                ledger,
                set.as_ptr(),
                0,
                ptr::null(),
                p,
                l,
                &mut complete,
                &mut e,
            )
        }));
        ratify_v2_ref_ledger_free(ledger);
        f.extend(ungated("ref_trust_registry_new", |_, l| {
            let mut r = ptr::null_mut();
            let code = ratify_v2_ref_trust_registry_new(pk, l, &mut r);
            ratify_v2_ref_trust_registry_free(r);
            code
        }));
    }
    finish(f);
}

// ---------------------------------------------------------------------------
// Callback answers

unsafe extern "C" fn forged_claim(
    _: *mut c_void,
    _: *const RatifyV2ClaimView,
    out: *mut RatifyV2ClaimResult,
) -> i32 {
    (*out).disposition = 1;
    (*out).owner_token = RatifyV2Slice {
        ptr: one(),
        len: usize::MAX,
    };
    0
}

unsafe extern "C" fn forged_interrupted(
    _: *mut c_void,
    _: *const c_char,
    out: *mut RatifyV2InterruptedClaim,
) -> i32 {
    (*out).record = RatifyV2Slice {
        ptr: one(),
        len: usize::MAX,
    };
    0
}

unsafe extern "C" fn forged_issuance(
    _: *mut c_void,
    _: *const c_char,
    _: i64,
    _: RatifyV2Slice,
    out: *mut RatifyV2Slice,
) -> i32 {
    *out = RatifyV2Slice {
        ptr: one(),
        len: usize::MAX,
    };
    0
}

unsafe extern "C" fn forged_journal_load(_: *mut c_void, out: *mut RatifyV2JournalSnapshot) -> i32 {
    (*out).snapshot = RatifyV2Slice {
        ptr: one(),
        len: usize::MAX,
    };
    (*out).digest = c"".as_ptr();
    0
}

/// A claim store's owner token and an interrupted claim's record with a
/// forged length are store failures, not aborts.
#[test]
fn v2c_claim_store_answers_with_forged_lengths_fail_closed() {
    let mut store: RatifyV2ClaimStoreCallbacks = unsafe { std::mem::zeroed() };
    store.load_interrupted = Some(forged_interrupted);
    let id = cs("claim");
    let mut committed = ptr::null_mut();
    let code = unsafe { ratify_v2_recover_interrupted_claim(&store, id.as_ptr(), &mut committed) };
    assert!(committed.is_null());
    assert_eq!(class(code), "claim_store_unavailable", "{}", last_error());
    assert!(last_error().contains("isize::MAX"), "{}", last_error());

    // The claim answer is read only by a claim that passed preflight; see
    // v2c_verifier.rs for the live path. Here the claim export reaches it
    // through a real preflight-passing bundle from the ordering corpus.
    let f = load("verifier-ordering.json");
    let v = arr(&f["vectors"])
        .into_iter()
        .find(|v| s(&v["expected"]["decision"]) == "allow")
        .expect("an allow vector");
    let bundle = b64(&f["bundles_b64"][s(&v["bundle"])]);
    let request = json_bytes(&request_json(&v));
    let mut claim: RatifyV2ClaimStoreCallbacks = unsafe { std::mem::zeroed() };
    claim.claim = Some(forged_claim);
    let mut disposition = 0;
    let mut claim_id = ptr::null_mut();
    let code = unsafe {
        ratify_v2_claim_proof_bundle(
            bundle.as_ptr(),
            bundle.len(),
            request.as_ptr(),
            request.len(),
            &claim,
            &mut disposition,
            &mut claim_id,
        )
    };
    take_str(claim_id);
    assert_eq!(class(code), "claim_store_unavailable", "{}", last_error());
    assert!(last_error().contains("isize::MAX"), "{}", last_error());
}

/// An issuance record and a journal snapshot with forged lengths fail
/// closed.
#[test]
fn v2c_issuance_and_journal_answers_with_forged_lengths_fail_closed() {
    let issuance = RatifyV2IssuanceStoreCallbacks {
        user: ptr::null_mut(),
        persist: None,
        load: Some(forged_issuance),
    };
    let ns = cs("ns");
    let challenge = [0u8; 32];
    let r = buf(|o| unsafe {
        ratify_v2_load_expected_challenge(&issuance, ns.as_ptr(), 1, challenge.as_ptr(), 32, o)
    });
    assert_eq!(
        class_of(&r),
        "expected_challenge_unavailable",
        "{}",
        last_error()
    );
    assert!(last_error().contains("isize::MAX"), "{}", last_error());

    let journal = RatifyV2JournalStoreCallbacks {
        user: ptr::null_mut(),
        load: Some(forged_journal_load),
        compare_and_swap: None,
    };
    let kp = Kp::generate().0;
    let pk = kp.public();
    let (issuer, cert) = (cs(&kp.id()), cs("c1"));
    let policy = RatifyV2StatusPolicy {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 3600,
        clock_skew_seconds: 5,
    };
    let r = buf(|o| unsafe {
        ratify_v2_journal_status(
            &journal,
            issuer.as_ptr(),
            cert.as_ptr(),
            1,
            &pk,
            &policy,
            150,
            o,
        )
    });
    assert_eq!(class_of(&r), "status_object_rejected", "{}", last_error());
    assert!(last_error().contains("isize::MAX"), "{}", last_error());
}

unsafe extern "C" fn non_utf8_journal_load(_: *mut c_void, out: *mut RatifyV2JournalSnapshot) -> i32 {
    static DIGEST: [u8; 3] = [0xc3, 0x28, 0];
    (*out).snapshot = RatifyV2Slice { ptr: ptr::null(), len: 0 };
    (*out).digest = DIGEST.as_ptr().cast();
    0
}

/// A string a callback answers with must be valid UTF-8: a journal digest
/// that is not is no answer and fails closed, never a lossy copy compared
/// against the anchored head.
#[test]
fn v2c_callback_text_that_is_not_utf8_fails_closed() {
    let journal = RatifyV2JournalStoreCallbacks {
        user: ptr::null_mut(),
        load: Some(non_utf8_journal_load),
        compare_and_swap: None,
    };
    let kp = Kp::generate().0;
    let pk = kp.public();
    let (issuer, cert) = (cs(&kp.id()), cs("c1"));
    let policy = RatifyV2StatusPolicy {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 3600,
        clock_skew_seconds: 5,
    };
    let r = buf(|o| unsafe {
        ratify_v2_journal_status(&journal, issuer.as_ptr(), cert.as_ptr(), 1, &pk, &policy, 150, o)
    });
    assert_eq!(class_of(&r), "status_object_rejected", "{}", last_error());
    assert!(last_error().contains("not valid UTF-8"), "{}", last_error());
}
