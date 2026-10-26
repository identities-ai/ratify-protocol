//! `ratify_v2_challenge_time_current`, the freshness recheck a C claim store
//! runs over a sealed claim: the documented formula with exclusive deadlines,
//! and 0 (fail closed) for a maximum age or skew outside the SPEC-v2 §2.5
//! configuration bounds, which no verifier seals into a claim. Also
//! `ratify_v2_valid_release_record_outcome`, the release-record rule of
//! SPEC-v2 §6.9 a C release store applies, and
//! `ratify_v2_valid_evaluation_progress`, the progress-record check of §7.5
//! a C claim store applies before storing a record, and
//! `ratify_v2_claim_id_matches_key`, the §7.3 replay-key check a C claim
//! store keyed by claim ID applies before creating a claim.

use std::ffi::CString;

use ratify_c::{
    ratify_v2_challenge_time_current, ratify_v2_claim_id_from_digest, ratify_v2_claim_id_matches_key,
    ratify_v2_string_free, ratify_v2_valid_evaluation_progress,
    ratify_v2_valid_release_record_outcome, RatifyV2ClaimView, RatifyV2ReleaseStatus, RatifyV2Slice,
};
use serde_json::json;

const MAX_AGE: i64 = 300;
const MAX_SKEW: i64 = 300;
const MAX_TS: i64 = 253_402_300_799;

fn current(issued_at: i64, expires_at: i64, max_age: i64, skew: i64, now: i64) -> bool {
    ratify_v2_challenge_time_current(issued_at, expires_at, max_age, skew, now) == 1
}

#[test]
fn matches_the_documented_formula_inside_the_configuration_bounds() {
    let base = 1_800_000_000i64;
    for max_age in [1, 2, 60, MAX_AGE] {
        for skew in [0, 1, 5, MAX_SKEW] {
            for issued_off in [-400, -301, -300, -1, 0, 1, 5, 6, 300, 301] {
                for life in [1, 30, 300, 600] {
                    for now_off in [-1, 0, 1, 29, 30, 299, 300, 301, 599, 600] {
                        let issued = base + issued_off;
                        let expires = issued + life;
                        let now = base + now_off;
                        let want =
                            issued <= now + skew && now < expires && now < issued + max_age;
                        assert_eq!(
                            current(issued, expires, max_age, skew, now),
                            want,
                            "issued {issued} expires {expires} max_age {max_age} skew {skew} now {now}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn out_of_range_configuration_fails_closed() {
    let (issued, expires, now) = (1_800_000_000i64, 1_800_000_060i64, 1_800_000_010i64);
    assert!(current(issued, expires, 60, 0, now), "control");
    for max_age in [i64::MIN, -1, 0, MAX_AGE + 1, i64::MAX] {
        assert!(
            !current(issued, expires, max_age, 0, now),
            "max_age {max_age} must fail closed"
        );
    }
    for skew in [i64::MIN, -1, MAX_SKEW + 1, i64::MAX] {
        assert!(
            !current(issued, expires, 60, skew, now),
            "skew {skew} must fail closed"
        );
    }
    for t in [-1, MAX_TS + 1] {
        assert!(!current(t, expires, 60, 0, now));
        assert!(!current(issued, expires, 60, 0, t));
    }
}

#[test]
fn release_record_outcomes() {
    use RatifyV2ReleaseStatus::*;
    let valid = |outcome: RatifyV2ReleaseStatus, reason: &str| {
        let reason = CString::new(reason).unwrap();
        unsafe { ratify_v2_valid_release_record_outcome(outcome as i32, reason.as_ptr()) == 1 }
    };
    assert!(valid(RatifyV2ReleaseReleased, ""));
    // SPEC-v2 §1.3: a predicate fails closed, so a NULL or non-UTF-8 reason
    // is never a release record.
    assert_eq!(unsafe { ratify_v2_valid_release_record_outcome(RatifyV2ReleaseReleased as i32, std::ptr::null()) }, 0);
    let not_utf8 = [0xffu8, 0];
    assert_eq!(
        unsafe { ratify_v2_valid_release_record_outcome(RatifyV2ReleaseReleased as i32, not_utf8.as_ptr().cast()) },
        0
    );
    for reason in ["clock_regressed", "challenge_expired", "allow_horizon_passed"] {
        assert!(valid(RatifyV2ReleaseWithheld, reason), "withheld {reason}");
        assert!(!valid(RatifyV2ReleaseReleased, reason), "released with {reason}");
    }
    for reason in ["", "receipt_abandoned", "receipt_invalid"] {
        assert!(!valid(RatifyV2ReleaseWithheld, reason), "withheld {reason:?}");
    }
    for outcome in [RatifyV2ReleaseNone, RatifyV2ReleasePending, RatifyV2ReleaseRejected] {
        assert!(!valid(outcome, ""), "{outcome:?}");
    }
    assert_eq!(unsafe { ratify_v2_valid_release_record_outcome(99, std::ptr::null()) }, 0);
}

#[test]
fn evaluation_progress_predicate_accepts_only_a_valid_record() {
    let valid = |record: &[u8]| unsafe { ratify_v2_valid_evaluation_progress(record.as_ptr(), record.len()) == 1 };
    let initial = br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"not_evaluated"}"#;
    assert!(valid(initial));
    assert!(valid(br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"trusted"}"#));
    // A completed status stage, in the RatifyCanonicalJSON form every SDK
    // writes (TypeScript encodeV2EvaluationProgress gives these bytes).
    let digest = format!("sha384:{}", "c".repeat(96));
    let complete = format!(
        r#"{{"context_assessment":"bound","context_policy_digest":"{digest}","status_assessment":"current","status_evidence_digests":[{{"digest":"{digest}","issuer_id":"{a}","object_type_code":3,"sequence":1,"status_key_id":"{b}"}}],"trust_assessment":"trusted"}}"#,
        a = "a".repeat(64),
        b = "b".repeat(64),
    );
    assert!(valid(complete.as_bytes()));
    // A store that kept any of these would hand recovery a record it cannot
    // seal (SPEC-v2 §7.5), stranding the claim instead of interrupting it.
    for bad in [
        &b"{}"[..],
        b"",
        b"null",
        b"[]",
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"maybe"}"#,
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"trusted","extra":1}"#,
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"trusted","trust_assessment":"trusted"}"#,
        // context_policy_digest is a required member, null or a digest.
        br#"{"context_assessment":"not_evaluated","status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"trusted"}"#,
        // Not RatifyCanonicalJSON: whitespace, then member order.
        br#"{"context_assessment": "not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[],"trust_assessment":"trusted"}"#,
        br#"{"trust_assessment":"trusted","context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence_digests":[]}"#,
        // The pre-fix C member name; §7.5 names it status_evidence_digests.
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence":[],"trust_assessment":"trusted"}"#,
        &[0xff, 0xfe],
    ] {
        assert!(!valid(bad), "{}", String::from_utf8_lossy(bad));
    }
    assert_eq!(unsafe { ratify_v2_valid_evaluation_progress(std::ptr::null(), 5) }, 0);
}

// A store keyed by claim ID holds one claim per replay key only if every ID
// it accepts is derived from that key (SPEC-v2 §2.4, §7.3).
#[test]
fn claim_id_matches_key_accepts_only_the_derived_id() {
    let (ns, epoch) = ("device-ns", 3i64);
    let digest = [0x5au8; 48];
    let derived = unsafe {
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        assert_eq!(ratify_v2_claim_id_from_digest(ns.as_ptr(), ns.len(), epoch, digest.as_ptr(), digest.len(), &mut out), 0);
        let id = std::ffi::CStr::from_ptr(out).to_str().unwrap().to_owned();
        ratify_v2_string_free(out);
        id
    };
    let record = |id: &str, digest: String| {
        serde_json::to_vec(&json!({
            "claim_id": id, "namespace": ns, "replay_epoch": epoch, "challenge_digest": digest,
            "proof_digest": format!("sha384:{}", "1".repeat(96)), "bundle_hash": format!("sha384:{}", "2".repeat(96)),
            "issuer_ids": ["a".repeat(64)], "required_scope": "meeting:attend",
            "context_policy_digest": format!("sha384:{}", "3".repeat(96)), "verifier_id": "b".repeat(64),
            "agent_id": "c".repeat(64), "requires_rate": false, "rate_batch": [], "issued_at": 1_800_000_000i64,
            "expires_at": 1_800_000_300i64, "max_age_seconds": 300, "clock_skew_seconds": 5,
            "stream_id": null, "stream_seq": null, "constraint_evaluators": [],
        }))
        .unwrap()
    };
    let hex_digest = format!("sha384:{}", "5a".repeat(48));
    let keyed = |view_id: &str, view_ns: &str, view_epoch: i64, rec: &[u8]| {
        let id = CString::new(view_id).unwrap();
        let ns = CString::new(view_ns).unwrap();
        let view = RatifyV2ClaimView {
            claim_id: id.as_ptr(),
            verifier_namespace: ns.as_ptr(),
            replay_epoch: view_epoch,
            agent_id: std::ptr::null(),
            issued_at: 0,
            expires_at: 0,
            max_age_seconds: 0,
            clock_skew_seconds: 0,
            has_stream_id: 0,
            stream_id: RatifyV2Slice { ptr: std::ptr::null(), len: 0 },
            has_stream_seq: 0,
            stream_seq: 0,
            rate_batch: std::ptr::null(),
            rate_batch_len: 0,
            record: RatifyV2Slice { ptr: rec.as_ptr(), len: rec.len() },
        };
        unsafe { ratify_v2_claim_id_matches_key(&view) == 1 }
    };
    let forged = "f".repeat(64);
    assert!(keyed(&derived, ns, epoch, &record(&derived, hex_digest.clone())));
    // A forged ID beside the real record, or written into the record.
    assert!(!keyed(&forged, ns, epoch, &record(&derived, hex_digest.clone())));
    assert!(!keyed(&forged, ns, epoch, &record(&forged, hex_digest.clone())));
    // The view's namespace or epoch differs from the sealed record's.
    assert!(!keyed(&derived, "other-ns", epoch, &record(&derived, hex_digest.clone())));
    assert!(!keyed(&derived, ns, epoch + 1, &record(&derived, hex_digest.clone())));
    // The challenge digest is not a lowercase sha384: digest.
    assert!(!keyed(&derived, ns, epoch, &record(&derived, hex_digest.to_uppercase())));
    assert!(!keyed(&derived, ns, epoch, &record(&derived, "5a".repeat(48))));
    assert!(!keyed(&derived, ns, epoch, b"{}"));
    assert_eq!(unsafe { ratify_v2_claim_id_matches_key(std::ptr::null()) }, 0);
}
