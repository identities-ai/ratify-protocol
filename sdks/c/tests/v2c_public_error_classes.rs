//! SPEC-v2 §2.7 through the C ABI, mirroring Go
//! `TestV2PublicAPIErrorsAreClassified` (errors_v2_public_test.go): every
//! fallible `ratify_v2_*` export is called with inputs it must reject, and
//! the result must be one of the 49 §2.7 classes or a documented negative
//! ABI code (`null_pointer`, `bad_argument`, a store sentinel). It must
//! never be success or `internal`, which is reserved for a contained panic
//! or a poisoned handle. Where Go fixes the class for the same input and
//! the C input reaches the same Rust operation, the class is asserted
//! exactly, so a C caller sees the reference class.
//!
//! The export list is checked against `include/ratify.h`: a new fallible
//! export fails here until it is classified.

mod v2c_common;

use std::collections::BTreeSet;
use std::os::raw::{c_char, c_void};
use std::ptr;

use ratify_c::*;
use serde_json::json;
use v2c_common::*;

/// Exports that return no failure code: version and spelling getters,
/// release functions, and the fail-closed boolean queries (0 on any
/// failure, documented in the header).
const NOT_FALLIBLE: &[&str] = &[
    "ratify_v2_abi_version",
    "ratify_v2_protocol_version",
    "ratify_v2_library_version",
    "ratify_v2_tzdb_version",
    "ratify_v2_error_class_str",
    "ratify_v2_last_error_message",
    "ratify_v2_release_status_str",
    "ratify_v2_buffer_free",
    "ratify_v2_string_free",
    "ratify_v2_keypair_free",
    "ratify_v2_status_state_free",
    "ratify_v2_rotation_journal_free",
    "ratify_v2_committed_free",
    "ratify_v2_released_free",
    "ratify_v2_evaluator_call_expired",
    "ratify_v2_challenge_time_current",
    "ratify_v2_valid_release_record_outcome",
    "ratify_v2_released_allowed",
];

/// Documented negative codes a rejection may carry instead of a class.
fn documented_negative(code: i32) -> bool {
    code == RatifyV2Code::RatifyV2ErrNullPointer as i32
        || code == RatifyV2Code::RatifyV2ErrBadArgument as i32
        || (RatifyV2Code::RatifyV2StoreJournalConflict as i32
            ..=RatifyV2Code::RatifyV2StoreUnavailable as i32)
            .contains(&code)
}

struct Call {
    name: &'static str,
    /// The exact class (or ABI code spelling); empty: any listed class or
    /// documented negative code.
    want: &'static str,
    run: Box<dyn Fn() -> i32>,
}

fn call(name: &'static str, want: &'static str, run: impl Fn() -> i32 + 'static) -> Call {
    Call {
        name,
        want,
        run: Box::new(run),
    }
}

/// A journal store whose load and compare-and-swap always fail.
unsafe extern "C" fn failing_load(_: *mut c_void, _: *mut RatifyV2JournalSnapshot) -> i32 {
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}
unsafe extern "C" fn failing_cas(
    _: *mut c_void,
    _: u64,
    _: *const c_char,
    _: *const RatifyV2JournalSnapshot,
) -> i32 {
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}
fn failing_journal() -> RatifyV2JournalStoreCallbacks {
    RatifyV2JournalStoreCallbacks {
        user: ptr::null_mut(),
        load: Some(failing_load),
        compare_and_swap: Some(failing_cas),
    }
}

/// An external signer that reports `user`'s key and then refuses (or
/// cancels, when the behaviour flag is set).
struct FailingSigner {
    key: RatifyV2PublicKey,
    cancel: bool,
}
unsafe extern "C" fn fs_key(user: *mut c_void, out: *mut RatifyV2PublicKey) -> i32 {
    *out = (*(user as *const FailingSigner)).key;
    0
}
unsafe extern "C" fn fs_sign(
    user: *mut c_void,
    _: *const RatifyV2SignRequest,
    _: *mut RatifyV2Signature,
) -> i32 {
    if (*(user as *const FailingSigner)).cancel {
        RatifyV2Code::RatifyV2ErrCancelled as i32
    } else {
        RatifyV2Code::RatifyV2StoreUnavailable as i32
    }
}
fn external(s: &'static FailingSigner) -> RatifyV2ExternalSigner {
    RatifyV2ExternalSigner {
        user: s as *const FailingSigner as *mut c_void,
        mode: RatifyV2SignerMode::RatifyV2SignerDirect as i32,
        public_key: Some(fs_key),
        sign: Some(fs_sign),
    }
}

/// A well-formed signature that verifies under no key.
fn zero_sig() -> serde_json::Value {
    json!({"ed25519": enc(&[0u8; 64]), "ml_dsa_65": enc(&[0u8; 3309])})
}

fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

fn header_exports() -> BTreeSet<String> {
    let h = std::fs::read_to_string(sdk_dir().join("include/ratify.h")).expect("ratify.h");
    h.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with("ratify_v2_") && !w.starts_with("ratify_v2_ref_"))
        .filter(|w| h.contains(&format!("{w}(")))
        .map(str::to_string)
        .collect()
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

#[test]
fn v2c_public_api_errors_are_classified() {
    let kp: &'static Kp = leak(Kp::generate().0);
    let other: &'static Kp = leak(Kp::generate().0);
    let pubk: &'static RatifyV2PublicKey = leak(kp.public());
    let otherk: &'static RatifyV2PublicKey = leak(other.public());
    let key_id: &'static str = leak(kp.id());
    let kid = || cs(key_id);
    let garbage: &'static [u8] = br#"{"version":2}"#;
    let list: &'static [u8] = leak(json_bytes(&json!({
        "version": 2, "issuer_id": key_id, "updated_at": 100, "next_update": 200,
        "sequence": 1, "revoked": [], "signature": zero_sig(),
    })));
    let push: &'static [u8] = leak(json_bytes(&json!({
        "version": 2, "issuer_id": key_id, "sequence": 1, "pushed_at": 100,
        "revoked": [{"cert_id": "c1"}], "signature": zero_sig(),
    })));
    let policy: &'static RatifyV2StatusPolicy = leak(RatifyV2StatusPolicy {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 3600,
        clock_skew_seconds: 5,
    });
    let journal: &'static RatifyV2JournalStoreCallbacks = leak(failing_journal());
    let failing: &'static RatifyV2ExternalSigner = leak(external(leak(FailingSigner {
        key: *pubk,
        cancel: false,
    })));
    let cancelling: &'static RatifyV2ExternalSigner = leak(external(leak(FailingSigner {
        key: *pubk,
        cancel: true,
    })));
    let head = br#"{"log_id":"l","sequence":0,"head_hash_b64":"","accepted_digests_b64":{},"frozen":false}"#;
    let gp = garbage.as_ptr();
    let gl = garbage.len();
    let k = |kind: RatifyV2ObjectKind| kind as i32;
    use RatifyV2ObjectKind::*;

    let mut calls = vec![
        // Decoders and archival verification.
        call("ratify_v2_object_decode", "malformed", move || {
            let mut worst = 0;
            for kind in [1, 2, 3, 4, 5, 6, 7, 8, 100, 101, 102] {
                let c = buffer_call(|o| unsafe { ratify_v2_object_decode(kind, gp, gl, o) });
                if class(c) != "malformed" {
                    worst = c;
                }
            }
            if worst == 0 {
                RatifyV2Code::RatifyV2Malformed as i32
            } else {
                worst
            }
        }),
        call(
            "ratify_v2_object_decode unregistered kind",
            "unsupported_object_type",
            move || buffer_call(|o| unsafe { ratify_v2_object_decode(99, gp, gl, o) }),
        ),
        call(
            "ratify_v2_archival_verify certificate",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindDelegationCertificate),
                        gp,
                        gl,
                        ptr::null(),
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_archival_verify revocation list",
            "malformed",
            move || {
                let id = kid();
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindRevocationList),
                        gp,
                        gl,
                        id.as_ptr(),
                        pubk,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_archival_verify revocation push",
            "malformed",
            move || {
                let id = kid();
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindRevocationPush),
                        gp,
                        gl,
                        id.as_ptr(),
                        pubk,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_archival_verify rotation",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindKeyRotationStatement),
                        gp,
                        gl,
                        ptr::null(),
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_archival_verify witness entry",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindWitnessEntry),
                        gp,
                        gl,
                        ptr::null(),
                        pubk,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_archival_verify verification receipt",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindVerificationReceipt),
                        gp,
                        gl,
                        ptr::null(),
                        pubk,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_archival_verify transaction receipt",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_archival_verify(
                        k(RatifyV2KindTransactionReceipt),
                        gp,
                        gl,
                        ptr::null(),
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        // Encoders, digests and identifiers.
        call("ratify_v2_key_id", "malformed", || {
            let mut out = [0 as c_char; 65];
            let mut err: *mut c_char = ptr::null_mut();
            let ed = [0u8; 3];
            let code = unsafe {
                ratify_v2_key_id(
                    ed.as_ptr(),
                    3,
                    ed.as_ptr(),
                    0,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut err,
                )
            };
            take_str(err);
            code
        }),
        call("ratify_v2_key_id_check", "malformed", || {
            let id = cs("not-a-key-id");
            unsafe { ratify_v2_key_id_check(id.as_ptr(), ptr::null_mut()) }
        }),
        call("ratify_v2_public_key_id", "", move || {
            let mut out = [0 as c_char; 8];
            unsafe { ratify_v2_public_key_id(pubk, out.as_mut_ptr(), out.len()) }
        }),
        call("ratify_v2_public_key_to_json", "", || {
            string_call(|o| unsafe { ratify_v2_public_key_to_json(ptr::null(), o) })
        }),
        call("ratify_v2_keypair_from_seeds", "", || {
            let mut out = ptr::null_mut();
            unsafe { ratify_v2_keypair_from_seeds(ptr::null(), ptr::null(), &mut out) }
        }),
        call("ratify_v2_keypair_generate", "", || unsafe {
            ratify_v2_keypair_generate(ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
        }),
        call("ratify_v2_keypair_public_key", "", || {
            let mut out = zero_key();
            unsafe { ratify_v2_keypair_public_key(ptr::null(), &mut out) }
        }),
        call("ratify_v2_keypair_key_id", "", move || {
            let mut out = [0 as c_char; 8];
            unsafe { ratify_v2_keypair_key_id(kp.0, out.as_mut_ptr(), out.len()) }
        }),
        call("ratify_v2_bundle_hash", "malformed", move || {
            string_call(|o| unsafe { ratify_v2_bundle_hash(gp, gl, o) })
        }),
        call("ratify_v2_delegation_digest", "malformed", move || {
            buffer_call(|o| unsafe { ratify_v2_delegation_digest(gp, gl, o) })
        }),
        call(
            "ratify_v2_verification_receipt_body",
            "malformed",
            move || buffer_call(|o| unsafe { ratify_v2_verification_receipt_body(gp, gl, o) }),
        ),
        call("ratify_v2_signable_bytes", "malformed", move || {
            buffer_call(|o| unsafe { ratify_v2_signable_bytes(0x0001, gp, gl, o) })
        }),
        call(
            "ratify_v2_signable_bytes unregistered code",
            "unsupported_object_type",
            move || buffer_call(|o| unsafe { ratify_v2_signable_bytes(0x0063, gp, gl, o) }),
        ),
        call(
            "ratify_v2_signing_message",
            "unsupported_object_type",
            move || buffer_call(|o| unsafe { ratify_v2_signing_message(0x0063, gp, gl, o) }),
        ),
        call("ratify_v2_mldsa_context", "unsupported_object_type", || {
            buffer_call(|o| unsafe { ratify_v2_mldsa_context(0x0063, o) })
        }),
        call(
            "ratify_v2_external_mu",
            "unsupported_object_type",
            move || buffer_call(|o| unsafe { ratify_v2_external_mu(pubk, 0x0063, gp, gl, o) }),
        ),
        call("ratify_v2_verify_statement", "", move || unsafe {
            ratify_v2_verify_statement(0x0001, gp, gl, null_slice(), null_slice(), pubk)
        }),
        call(
            "ratify_v2_statement_body_digest unregistered code",
            "unsupported_object_type",
            || {
                buffer_call(|o| unsafe {
                    ratify_v2_statement_body_digest(0x0001, b"{}".as_ptr(), 2, o)
                })
            },
        ),
        call(
            "ratify_v2_statement_body_digest bad body",
            "malformed",
            || {
                buffer_call(|o| unsafe {
                    ratify_v2_statement_body_digest(0x0006, b"{}".as_ptr(), 2, o)
                })
            },
        ),
        call(
            "ratify_v2_status_evidence_digest unregistered kind",
            "unsupported_object_type",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_status_evidence_digest(
                        k(RatifyV2KindDelegationCertificate),
                        list.as_ptr(),
                        list.len(),
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_status_evidence_digest wrong value",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_status_evidence_digest(
                        k(RatifyV2KindRevocationList),
                        push.as_ptr(),
                        push.len(),
                        o,
                    )
                })
            },
        ),
        call("ratify_v2_object_body_digest", "malformed", move || {
            buffer_call(|o| unsafe {
                ratify_v2_object_body_digest(k(RatifyV2KindWitnessEntry), b"{}".as_ptr(), 2, o)
            })
        }),
        call("ratify_v2_revoked_set_digest", "", || {
            buffer_call(|o| unsafe { ratify_v2_revoked_set_digest(b"[1]".as_ptr(), 3, o) })
        }),
        // Pure digests over opaque bytes: only an ABI argument can be invalid.
        call("ratify_v2_receipt_outbox_digest", "null_pointer", || {
            string_call(|o| unsafe { ratify_v2_receipt_outbox_digest(ptr::null(), 0, o) })
        }),
        call("ratify_v2_security_journal_digest", "null_pointer", || {
            string_call(|o| unsafe { ratify_v2_security_journal_digest(ptr::null(), 0, o) })
        }),
        call("ratify_v2_challenge_claim_digest", "malformed", || {
            buffer_call(|o| unsafe { ratify_v2_challenge_claim_digest(b"short".as_ptr(), 5, o) })
        }),
        call(
            "ratify_v2_claim_id namespace",
            "configuration_invalid",
            || {
                let challenge = [0u8; 32];
                string_call(|o| unsafe {
                    ratify_v2_claim_id(b"".as_ptr(), 0, 0, challenge.as_ptr(), 32, o)
                })
            },
        ),
        call("ratify_v2_claim_id challenge", "malformed", || {
            string_call(|o| unsafe {
                ratify_v2_claim_id(b"ns".as_ptr(), 2, 0, b"short".as_ptr(), 5, o)
            })
        }),
        call("ratify_v2_claim_id_from_digest", "malformed", || {
            string_call(|o| unsafe {
                ratify_v2_claim_id_from_digest(b"ns".as_ptr(), 2, 0, b"short".as_ptr(), 5, o)
            })
        }),
        call("ratify_v2_payload_digest_decode", "malformed", || {
            let e = cs("!");
            let mut present = 0;
            buffer_call(|o| unsafe { ratify_v2_payload_digest_decode(e.as_ptr(), o, &mut present) })
        }),
        call("ratify_v2_transaction_context_hash", "null_pointer", || {
            let (id, uri) = (cs(""), cs(""));
            buffer_call(|o| unsafe {
                ratify_v2_transaction_context_hash(id.as_ptr(), uri.as_ptr(), ptr::null(), 0, o)
            })
        }),
        call(
            "ratify_v2_transaction_party_request_hash",
            "bad_argument",
            || {
                let scope = [0xffu8, 0];
                buffer_call(|o| unsafe {
                    ratify_v2_transaction_party_request_hash(
                        b"{".as_ptr(),
                        1,
                        scope.as_ptr() as *const c_char,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_operation_context_hash",
            "invalid_required_scope",
            || buffer_call(|o| unsafe { ratify_v2_operation_context_hash(b"{}".as_ptr(), 2, o) }),
        ),
        call("ratify_v2_session_context", "configuration_invalid", || {
            buffer_call(|o| unsafe { ratify_v2_session_context(b"{}".as_ptr(), 2, o) })
        }),
        call(
            "ratify_v2_context_policy_digest",
            "configuration_invalid",
            || {
                let p = br#"{"profile":"","require_bound":true}"#;
                string_call(|o| unsafe { ratify_v2_context_policy_digest(p.as_ptr(), p.len(), o) })
            },
        ),
        call(
            "ratify_v2_constraint_profile_digest",
            "configuration_invalid",
            || {
                let (p, t) = (cs(""), cs(""));
                string_call(|o| unsafe {
                    ratify_v2_constraint_profile_digest(p.as_ptr(), t.as_ptr(), o)
                })
            },
        ),
        call("ratify_v2_canonical_json", "", || {
            buffer_call(|o| unsafe { ratify_v2_canonical_json(b"{".as_ptr(), 1, o) })
        }),
        call("ratify_v2_validate_scopes", "", || unsafe {
            ratify_v2_validate_scopes(br#"["Not A Scope"]"#.as_ptr(), 15)
        }),
        call("ratify_v2_validate_required_scope", "", || {
            let s = cs("");
            unsafe { ratify_v2_validate_required_scope(s.as_ptr()) }
        }),
        call(
            "ratify_v2_validate_request_context",
            "configuration_invalid",
            || {
                let c = format!(r#"{{"extension_counts":{{"{}":1}}}}"#, "x".repeat(300));
                unsafe { ratify_v2_validate_request_context(c.as_ptr(), c.len()) }
            },
        ),
        call("ratify_v2_evaluate_standard_profile", "", || {
            let p = cs("com.example.unknown/v1");
            let (mut outcome, mut until) = (0, 0);
            unsafe {
                ratify_v2_evaluate_standard_profile(
                    p.as_ptr(),
                    b"{}".as_ptr(),
                    2,
                    &mut outcome,
                    &mut until,
                    ptr::null_mut(),
                )
            }
        }),
        call(
            "ratify_v2_check_stream_sequence",
            "stream_sequence_mismatch",
            || ratify_v2_check_stream_sequence(1, 5, 5),
        ),
        call(
            "ratify_v2_validate_finalization_payload",
            "bad_argument",
            || unsafe {
                ratify_v2_validate_finalization_payload(b"[]".as_ptr(), 2, b"{}".as_ptr(), 2, b"{}".as_ptr(), 2)
            },
        ),
        call("ratify_v2_cross_sdk_fixture_verify", "", move || {
            let sdk = cs("c");
            unsafe { ratify_v2_cross_sdk_fixture_verify(gp, gl, sdk.as_ptr()) }
        }),
        // Signing.
        call(
            "ratify_v2_sign_delegation_certificate",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_sign_delegation_certificate(b"{}".as_ptr(), 2, kp.0, ptr::null(), o)
                })
            },
        ),
        call("ratify_v2_sign_proof_bundle", "malformed", move || {
            buffer_call(|o| unsafe {
                ratify_v2_sign_proof_bundle(b"{}".as_ptr(), 2, kp.0, ptr::null(), o)
            })
        }),
        call(
            "ratify_v2_sign_proof_bundle agent key binding",
            "key_id_mismatch",
            move || {
                // A well-formed corpus bundle whose agent is not `kp`.
                let f = load("verifier-ordering.json");
                let (_, wire) = f["bundles_b64"].as_object().unwrap().iter().next().unwrap();
                let wire = b64(wire);
                buffer_call(|o| unsafe {
                    ratify_v2_sign_proof_bundle(wire.as_ptr(), wire.len(), kp.0, ptr::null(), o)
                })
            },
        ),
        call(
            "ratify_v2_sign_revocation_list issuer binding",
            "status_key_binding_mismatch",
            move || {
                let id = cs("other");
                buffer_call(|o| unsafe {
                    ratify_v2_sign_revocation_list(
                        list.as_ptr(),
                        list.len(),
                        id.as_ptr(),
                        pubk,
                        kp.0,
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_sign_revocation_list status key binding",
            "status_key_binding_mismatch",
            move || {
                let id = kid();
                buffer_call(|o| unsafe {
                    ratify_v2_sign_revocation_list(
                        list.as_ptr(),
                        list.len(),
                        id.as_ptr(),
                        otherk,
                        kp.0,
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_sign_revocation_list failing signer",
            "configuration_invalid",
            move || {
                let id = kid();
                buffer_call(|o| unsafe {
                    ratify_v2_sign_revocation_list(
                        list.as_ptr(),
                        list.len(),
                        id.as_ptr(),
                        pubk,
                        ptr::null(),
                        failing,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_sign_revocation_list cancelled",
            "evaluation_cancelled",
            move || {
                let id = kid();
                buffer_call(|o| unsafe {
                    ratify_v2_sign_revocation_list(
                        list.as_ptr(),
                        list.len(),
                        id.as_ptr(),
                        pubk,
                        ptr::null(),
                        cancelling,
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_sign_revocation_push issuer binding",
            "status_key_binding_mismatch",
            move || {
                let id = cs("other");
                buffer_call(|o| unsafe {
                    ratify_v2_sign_revocation_push(
                        push.as_ptr(),
                        push.len(),
                        id.as_ptr(),
                        pubk,
                        kp.0,
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call(
            "ratify_v2_sign_key_rotation_statement",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_sign_key_rotation_statement(
                        b"{}".as_ptr(),
                        2,
                        kp.0,
                        ptr::null(),
                        kp.0,
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call("ratify_v2_sign_witness_entry", "malformed", move || {
            buffer_call(|o| unsafe {
                ratify_v2_sign_witness_entry(b"{}".as_ptr(), 2, kp.0, ptr::null(), o)
            })
        }),
        call(
            "ratify_v2_sign_verification_receipt",
            "malformed",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_sign_verification_receipt(b"{}".as_ptr(), 2, kp.0, ptr::null(), o)
                })
            },
        ),
        call(
            "ratify_v2_sign_prepared_verification_receipt",
            "configuration_invalid",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_sign_prepared_verification_receipt(
                        gp,
                        gl,
                        head.as_ptr(),
                        head.len(),
                        kp.0,
                        ptr::null(),
                        o,
                    )
                })
            },
        ),
        call("ratify_v2_sign_transaction_receipt_party", "", move || {
            let party = cs("p");
            buffer_call(|o| unsafe {
                ratify_v2_sign_transaction_receipt_party(
                    b"{}".as_ptr(),
                    2,
                    party.as_ptr(),
                    kp.0,
                    ptr::null(),
                    o,
                )
            })
        }),
        // Signature and object verification.
        call("ratify_v2_verify_object", "malformed", move || unsafe {
            ratify_v2_verify_object(
                k(RatifyV2KindDelegationCertificate),
                gp,
                gl,
                ptr::null(),
                ptr::null_mut(),
            )
        }),
        call(
            "ratify_v2_proof_bundle_verify_signatures",
            "malformed",
            move || {
                let mut out = [0 as c_char; 128];
                unsafe {
                    ratify_v2_proof_bundle_verify_signatures(
                        gp,
                        gl,
                        out.as_mut_ptr(),
                        out.len(),
                        ptr::null_mut(),
                    )
                }
            },
        ),
        call(
            "ratify_v2_verification_receipt_verify",
            "malformed",
            move || {
                let h = cs(std::str::from_utf8(head).unwrap());
                unsafe {
                    ratify_v2_verification_receipt_verify(
                        gp,
                        gl,
                        pubk.ed25519.as_ptr(),
                        32,
                        pubk.ml_dsa_65.as_ptr(),
                        1952,
                        h.as_ptr(),
                        ptr::null_mut(),
                    )
                }
            },
        ),
        call(
            "ratify_v2_receipt_bundle_binding_check",
            "",
            move || unsafe {
                ratify_v2_receipt_bundle_binding_check(gp, gl, gp, gl, ptr::null_mut())
            },
        ),
        call("ratify_v2_witness_entry_append", "malformed", move || {
            let mut result = 0;
            buffer_call(|o| unsafe {
                ratify_v2_witness_entry_append(
                    gp,
                    gl,
                    head.as_ptr(),
                    head.len(),
                    pubk,
                    &mut result,
                    o,
                )
            })
        }),
        call(
            "ratify_v2_verification_receipt_append",
            "malformed",
            move || {
                let mut result = 0;
                buffer_call(|o| unsafe {
                    ratify_v2_verification_receipt_append(
                        gp,
                        gl,
                        head.as_ptr(),
                        head.len(),
                        pubk,
                        &mut result,
                        o,
                    )
                })
            },
        ),
        // Key rotation journal.
        call(
            "ratify_v2_rotation_journal_new",
            "configuration_invalid",
            || {
                let (a, r) = (cs(""), cs(""));
                let mut out = ptr::null_mut();
                let key = zero_key();
                unsafe {
                    ratify_v2_rotation_journal_new(a.as_ptr(), -1, r.as_ptr(), &key, &mut out)
                }
            },
        ),
        call("ratify_v2_rotation_journal_accept", "", move || {
            let j = rotation_journal(pubk);
            let mut result = 0;
            let code = unsafe { ratify_v2_rotation_journal_accept(j, gp, gl, 0, 0, &mut result) };
            unsafe { ratify_v2_rotation_journal_free(j) };
            code
        }),
        call("ratify_v2_rotation_journal_recover", "", move || {
            let j = rotation_journal(pubk);
            let code = unsafe { ratify_v2_rotation_journal_recover(j, 0, pubk) };
            unsafe { ratify_v2_rotation_journal_free(j) };
            code
        }),
        call("ratify_v2_rotation_journal_state", "", || {
            buffer_call(|o| unsafe { ratify_v2_rotation_journal_state(ptr::null(), o) })
        }),
        // Status reducer and SecurityJournalV2 operations (§5.4, §6.6).
        call("ratify_v2_status_state_new", "", || unsafe {
            ratify_v2_status_state_new(ptr::null_mut())
        }),
        call(
            "ratify_v2_status_state_transition_epoch",
            "status_object_rejected",
            move || {
                with_status_state(|s| {
                    let id = kid();
                    unsafe { ratify_v2_status_state_transition_epoch(s, id.as_ptr(), 3, otherk) }
                })
            },
        ),
        call(
            "ratify_v2_status_state_transition_epoch reused key",
            "status_object_rejected",
            move || {
                with_status_state(|s| {
                    let id = kid();
                    unsafe { ratify_v2_status_state_transition_epoch(s, id.as_ptr(), 2, pubk) }
                })
            },
        ),
        call(
            "ratify_v2_status_state_apply unsigned list",
            "invalid_signature",
            move || {
                with_status_state(|s| {
                    let id = kid();
                    unsafe {
                        ratify_v2_status_state_apply(
                            s,
                            k(RatifyV2KindRevocationList),
                            list.as_ptr(),
                            list.len(),
                            id.as_ptr(),
                            1,
                            pubk,
                            policy,
                            150,
                        )
                    }
                })
            },
        ),
        call(
            "ratify_v2_status_state_apply unsigned push",
            "invalid_signature",
            move || {
                with_status_state(|s| {
                    let id = kid();
                    unsafe {
                        ratify_v2_status_state_apply(
                            s,
                            k(RatifyV2KindRevocationPush),
                            push.as_ptr(),
                            push.len(),
                            id.as_ptr(),
                            1,
                            pubk,
                            policy,
                            150,
                        )
                    }
                })
            },
        ),
        call("ratify_v2_status_state_query", "", move || {
            with_status_state(|s| {
                let (id, cert) = (kid(), cs(""));
                buffer_call(|o| unsafe {
                    ratify_v2_status_state_query(
                        s,
                        id.as_ptr(),
                        cert.as_ptr(),
                        1,
                        pubk,
                        policy,
                        150,
                        o,
                    )
                })
            })
        }),
        call("ratify_v2_status_state_json", "", || {
            buffer_call(|o| unsafe { ratify_v2_status_state_json(ptr::null(), o) })
        }),
        call(
            "ratify_v2_journal_record_key_role",
            "status_object_rejected",
            move || {
                let role = cs("verifier");
                unsafe { ratify_v2_journal_record_key_role(journal, role.as_ptr(), pubk) }
            },
        ),
        call(
            "ratify_v2_journal_record_key_role status role",
            "status_object_rejected",
            move || {
                let role = cs("status");
                unsafe { ratify_v2_journal_record_key_role(journal, role.as_ptr(), pubk) }
            },
        ),
        call(
            "ratify_v2_journal_configure_status_key",
            "status_object_rejected",
            move || {
                let id = kid();
                unsafe { ratify_v2_journal_configure_status_key(journal, id.as_ptr(), 1, pubk) }
            },
        ),
        call(
            "ratify_v2_journal_apply",
            "status_object_rejected",
            move || {
                let id = kid();
                unsafe {
                    ratify_v2_journal_apply(
                        journal,
                        k(RatifyV2KindRevocationList),
                        list.as_ptr(),
                        list.len(),
                        id.as_ptr(),
                        1,
                        pubk,
                        policy,
                        150,
                    )
                }
            },
        ),
        call(
            "ratify_v2_journal_status",
            "status_object_rejected",
            move || {
                let (id, cert) = (kid(), cs("c1"));
                buffer_call(|o| unsafe {
                    ratify_v2_journal_status(
                        journal,
                        id.as_ptr(),
                        cert.as_ptr(),
                        1,
                        pubk,
                        policy,
                        150,
                        o,
                    )
                })
            },
        ),
        call("ratify_v2_journal_genesis", "", || unsafe {
            ratify_v2_journal_genesis(ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
        }),
        call("ratify_v2_journal_import", "malformed", move || {
            let digest = cs("");
            buffer_call(|o| unsafe { ratify_v2_journal_import(gp, gl, 0, digest.as_ptr(), o) })
        }),
        call(
            "ratify_v2_journal_validate_transition",
            "malformed",
            move || {
                let digest = cs("");
                unsafe {
                    ratify_v2_journal_validate_transition(
                        gp,
                        gl,
                        0,
                        digest.as_ptr(),
                        gp,
                        gl,
                        0,
                        digest.as_ptr(),
                    )
                }
            },
        ),
        call("ratify_v2_journal_migrate", "", move || {
            let mut snapshot = empty_buf();
            let code =
                buffer_call(|o| unsafe { ratify_v2_journal_migrate(gp, gl, &mut snapshot, o) });
            take(snapshot);
            code
        }),
        call("ratify_v2_journal_legacy_encode", "", || {
            buffer_call(|o| unsafe { ratify_v2_journal_legacy_encode(b"{".as_ptr(), 1, 0, o) })
        }),
        call(
            "ratify_v2_status_publish genesis",
            "configuration_invalid",
            move || {
                let (mut l, mut p, mut s) = (empty_buf(), empty_buf(), empty_buf());
                let code = unsafe {
                    ratify_v2_status_publish(
                        1,
                        journal,
                        pubk,
                        kp.0,
                        ptr::null(),
                        -1,
                        ptr::null(),
                        0,
                        ptr::null(),
                        0,
                        -1,
                        &mut l,
                        &mut p,
                        &mut s,
                    )
                };
                take(l);
                take(p);
                take(s);
                code
            },
        ),
        // Verifier configuration, preflight, claim and evaluation (§6, §7).
        call("ratify_v2_claim_proof_bundle", "", move || {
            let mut disposition = 0;
            string_call(|o| unsafe {
                ratify_v2_claim_proof_bundle(
                    gp,
                    gl,
                    b"{}".as_ptr(),
                    2,
                    ptr::null(),
                    &mut disposition,
                    o,
                )
            })
        }),
        call("ratify_v2_recover_interrupted_claim", "", || {
            let id = cs("");
            let mut out = ptr::null_mut();
            unsafe { ratify_v2_recover_interrupted_claim(ptr::null(), id.as_ptr(), &mut out) }
        }),
        call("ratify_v2_committed_claim_id", "", || {
            string_call(|o| unsafe { ratify_v2_committed_claim_id(ptr::null(), o) })
        }),
        call("ratify_v2_committed_receipt_body", "", || {
            buffer_call(|o| unsafe { ratify_v2_committed_receipt_body(ptr::null(), o) })
        }),
        call("ratify_v2_committed_receipt_body_digest", "", || {
            string_call(|o| unsafe { ratify_v2_committed_receipt_body_digest(ptr::null(), o) })
        }),
        call("ratify_v2_committed_challenge_expires_at", "", || {
            let mut t = 0;
            unsafe { ratify_v2_committed_challenge_expires_at(ptr::null(), &mut t) }
        }),
        call("ratify_v2_committed_allow_horizon", "", || {
            let (mut has, mut h) = (0, 0);
            unsafe { ratify_v2_committed_allow_horizon(ptr::null(), &mut has, &mut h) }
        }),
        call("ratify_v2_release_decision", "", move || {
            let log = cs("l");
            let (mut status, mut reason, mut released) = (0, ptr::null_mut(), ptr::null_mut());
            let code = unsafe {
                ratify_v2_release_decision(
                    ptr::null(),
                    null_slice(),
                    pubk,
                    log.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    &mut status,
                    &mut reason,
                    &mut released,
                )
            };
            take_str(reason);
            code
        }),
        call("ratify_v2_released_string", "", || {
            string_call(|o| unsafe { ratify_v2_released_string(ptr::null(), 0, o) })
        }),
        call("ratify_v2_released_granted_scope", "", || {
            buffer_call(|o| unsafe { ratify_v2_released_granted_scope(ptr::null(), o) })
        }),
        call("ratify_v2_released_receipt", "", || {
            buffer_call(|o| unsafe { ratify_v2_released_receipt(ptr::null(), o) })
        }),
        call("ratify_v2_released_times", "", || {
            let (mut a, mut b, mut c, mut d) = (0, 0, 0, 0);
            unsafe { ratify_v2_released_times(ptr::null(), &mut a, &mut b, &mut c, &mut d) }
        }),
        call("ratify_v2_issue_challenge", "", || {
            buffer_call(|o| unsafe {
                ratify_v2_issue_challenge(
                    b"{}".as_ptr(),
                    2,
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    o,
                )
            })
        }),
        call("ratify_v2_load_expected_challenge", "", || {
            let ns = cs("ns");
            buffer_call(|o| unsafe {
                ratify_v2_load_expected_challenge(ptr::null(), ns.as_ptr(), 0, ptr::null(), 0, o)
            })
        }),
        call(
            "ratify_v2_verify_transaction_receipt",
            "configuration_invalid",
            move || {
                buffer_call(|o| unsafe {
                    ratify_v2_verify_transaction_receipt(
                        gp,
                        gl,
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
        ),
    ];

    // The live verifier reports a listed class in its outcome, as Go's
    // VerifyProofBundleV2 does for a request without a claim store.
    calls.push(call(
        "ratify_v2_verify_proof_bundle",
        "configuration_invalid",
        move || {
            let mut outcome = RatifyV2VerifyOutcome {
                stage: 0,
                error_code: 0,
                disposition: 0,
            };
            let mut record = empty_buf();
            let mut committed = ptr::null_mut();
            let code = unsafe {
                ratify_v2_verify_proof_bundle(
                    gp,
                    gl,
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
                return code;
            }
            assert_eq!(
                outcome.stage, 1,
                "a request without a claim store fails at preflight"
            );
            outcome.error_code
        },
    ));

    let mut failures = Vec::new();
    let mut covered = BTreeSet::new();
    for c in &calls {
        covered.insert(c.name.split(' ').next().unwrap().to_string());
        let code = (c.run)();
        let spelling = class(code);
        let listed = (1..=RATIFY_V2_ERROR_CLASS_COUNT as i32).contains(&code);
        if code == 0 {
            failures.push(format!("{}: bad input was accepted", c.name));
        } else if !listed && !documented_negative(code) {
            failures.push(format!(
                "{}: code {code} ({spelling}) is not a §2.7 class or a documented ABI code: {}",
                c.name,
                last_error()
            ));
        } else if !c.want.is_empty() && spelling != c.want {
            failures.push(format!(
                "{}: {spelling}, want {}: {}",
                c.name,
                c.want,
                last_error()
            ));
        }
    }

    // Archival verification of a proof bundle reports its class in the
    // language-neutral result rather than the return code.
    let result = buf(|o| unsafe {
        ratify_v2_archival_verify(
            k(RatifyV2KindProofBundle),
            gp,
            gl,
            ptr::null(),
            ptr::null(),
            o,
        )
    })
    .expect("proof bundle archival verification writes a result");
    let archival = parse(&result);
    if s(&archival["error_class"]) != "malformed" {
        failures.push(format!(
            "ratify_v2_archival_verify proof bundle: {archival}"
        ));
    }

    let fallible: BTreeSet<String> = header_exports()
        .into_iter()
        .filter(|e| !NOT_FALLIBLE.contains(&e.as_str()))
        .collect();
    let uncovered: Vec<_> = fallible.difference(&covered).collect();
    let unknown: Vec<_> = covered.difference(&fallible).collect();
    assert!(
        uncovered.is_empty(),
        "fallible exports with no classification probe: {uncovered:?}"
    );
    assert!(
        unknown.is_empty(),
        "probes for exports the header does not declare: {unknown:?}"
    );
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!(
        "C-ABI COVERAGE public error classes: {} probes over {} exports",
        calls.len() + 1,
        fallible.len()
    );
}

fn rotation_journal(key: &RatifyV2PublicKey) -> *mut RatifyV2RotationJournal {
    let (a, r) = (cs("0123456789abcdef0123456789abcdef"), cs("issuer"));
    let mut j = ptr::null_mut();
    check(unsafe { ratify_v2_rotation_journal_new(a.as_ptr(), 1, r.as_ptr(), key, &mut j) })
        .expect("rotation journal");
    j
}

/// A new, empty status reducer state for one probe.
fn with_status_state(f: impl FnOnce(*const RatifyV2StatusState) -> i32) -> i32 {
    let mut st = ptr::null_mut();
    check(unsafe { ratify_v2_status_state_new(&mut st) }).expect("status state");
    let code = f(st);
    unsafe { ratify_v2_status_state_free(st) };
    code
}
