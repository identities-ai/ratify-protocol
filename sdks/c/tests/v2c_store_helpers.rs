//! `ratify_v2_challenge_time_current`, the freshness recheck a C claim store
//! runs over a sealed claim: the documented formula with exclusive deadlines,
//! and 0 (fail closed) for a maximum age or skew outside the SPEC-v2 §2.5
//! configuration bounds, which no verifier seals into a claim. Also
//! `ratify_v2_valid_release_record_outcome`, the release-record rule of
//! SPEC-v2 §6.9 a C release store applies, and
//! `ratify_v2_valid_evaluation_progress`, the progress-record check of §7.5
//! a C claim store applies before storing a record.

use std::ffi::CString;

use ratify_c::{
    ratify_v2_challenge_time_current, ratify_v2_valid_evaluation_progress, ratify_v2_valid_release_record_outcome,
    RatifyV2ReleaseStatus,
};

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
    let initial = br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence":[],"trust_assessment":"not_evaluated"}"#;
    assert!(valid(initial));
    assert!(valid(br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence":[],"trust_assessment":"trusted"}"#));
    // A store that kept any of these would hand recovery a record it cannot
    // seal (SPEC-v2 §7.5), stranding the claim instead of interrupting it.
    for bad in [
        &b"{}"[..],
        b"",
        b"null",
        b"[]",
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence":[],"trust_assessment":"maybe"}"#,
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence":[],"trust_assessment":"trusted","extra":1}"#,
        br#"{"context_assessment":"not_evaluated","context_policy_digest":null,"status_assessment":"not_evaluated","status_evidence":[],"trust_assessment":"trusted","trust_assessment":"trusted"}"#,
        &[0xff, 0xfe],
    ] {
        assert!(!valid(bad), "{}", String::from_utf8_lossy(bad));
    }
    assert_eq!(unsafe { ratify_v2_valid_evaluation_progress(std::ptr::null(), 5) }, 0);
}
