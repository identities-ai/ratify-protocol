//! `ratify_v2_challenge_time_current`, the freshness recheck a C claim store
//! runs over a sealed claim: the documented formula with exclusive deadlines,
//! and 0 (fail closed) for a maximum age or skew outside the SPEC-v2 §2.5
//! configuration bounds, which no verifier seals into a claim.

use ratify_c::ratify_v2_challenge_time_current;

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
