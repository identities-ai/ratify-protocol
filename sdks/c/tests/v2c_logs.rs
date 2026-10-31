//! log-sequences.json and rotation-sequences.json through the C ABI:
//! `ratify_v2_witness_entry_append`, `ratify_v2_verification_receipt_append`
//! with a harness-managed log head, and the `ratify_v2_rotation_journal_*`
//! handle. Counts come from the corpus.

mod v2c_common;

use std::collections::BTreeMap;
use std::ptr;

use ratify_c::*;
use serde_json::{json, Value};
use v2c_common::*;

fn head_json(
    log_id: &str,
    verifier_id: &str,
    sequence: i64,
    head_hash: &[u8],
    accepted: &BTreeMap<i64, Vec<u8>>,
    frozen: bool,
) -> Vec<u8> {
    let accepted: serde_json::Map<String, Value> = accepted
        .iter()
        .map(|(k, v)| (k.to_string(), json!(enc(v))))
        .collect();
    let mut h = json!({
        "log_id": log_id,
        "sequence": sequence,
        "head_hash_b64": enc(head_hash),
        "accepted_digests_b64": accepted,
        "frozen": frozen,
    });
    if !verifier_id.is_empty() {
        h["verifier_id"] = json!(verifier_id);
    }
    json_bytes(&h)
}

#[test]
fn v2c_log_sequences() {
    let fx = Fixture::load();
    let f = load("log-sequences.json");
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no log scenarios");
    let mut t = Tally::default();
    let mut rows = Vec::new();
    for sc in &scenarios {
        let kind = s(&sc["kind"]);
        let row = format!("log-sequences.json {kind}");
        let verifier_id = if kind == "witness_entry" {
            String::new()
        } else {
            s(&sc["verifier_id"])
        };
        let (mut log_id, mut sequence, mut head_hash, mut accepted, mut frozen) = (
            s(&sc["initial_log_id"]),
            0i64,
            vec![0u8; 48],
            BTreeMap::new(),
            false,
        );
        let mut ran = 0;
        for (n, step) in arr(&sc["steps"]).iter().enumerate() {
            if step["op"] == "recover" {
                log_id = s(&step["log_id"]);
                sequence = 0;
                head_hash = vec![0; 48];
                accepted.clear();
                frozen = false;
                continue;
            }
            assert_eq!(step["op"], "verify", "unknown log op");
            ran += 1;
            let wire = b64(&step["wire_b64"]);
            let key = fx.key(&s(&step["key"]));
            let head = head_json(
                &log_id,
                &verifier_id,
                sequence,
                &head_hash,
                &accepted,
                frozen,
            );
            let mut result = 0;
            let mut digest = empty_buf();
            let code = unsafe {
                if kind == "witness_entry" {
                    ratify_v2_witness_entry_append(
                        wire.as_ptr(),
                        wire.len(),
                        head.as_ptr(),
                        head.len(),
                        &key,
                        &mut result,
                        &mut digest,
                    )
                } else {
                    ratify_v2_verification_receipt_append(
                        wire.as_ptr(),
                        wire.len(),
                        head.as_ptr(),
                        head.len(),
                        &key,
                        &mut result,
                        &mut digest,
                    )
                }
            };
            let digest = take(digest);
            let got = match check(code) {
                Ok(()) if result == RatifyV2LogResult::RatifyV2LogAppended as i32 => {
                    "appended".to_string()
                }
                Ok(()) if result == RatifyV2LogResult::RatifyV2LogReplay as i32 => {
                    "replay".to_string()
                }
                Ok(()) => format!("unknown result {result}"),
                Err(e) => e.class,
            };
            let want = s(&step["expect"]);
            t.check(
                &row,
                &format!("step {n} {}", s(&step["label"])),
                got == want,
                || format!("got {got}, want {want}"),
            );
            match got.as_str() {
                "appended" => {
                    let seq = i(&parse(&wire)["sequence"]);
                    sequence = seq;
                    head_hash = digest.clone();
                    accepted.insert(seq, digest);
                }
                "log_fork" => frozen = true,
                _ => {}
            }
        }
        rows.push((row, ran));
    }
    let rows: Vec<(&str, usize)> = rows.iter().map(|(r, n)| (r.as_str(), *n)).collect();
    t.finish(&rows);
}

struct Journal(*mut RatifyV2RotationJournal);

impl Drop for Journal {
    fn drop(&mut self) {
        unsafe { ratify_v2_rotation_journal_free(self.0) };
    }
}

#[test]
fn v2c_rotation_sequences() {
    let fx = Fixture::load();
    let f = load("rotation-sequences.json");
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no rotation scenarios");
    let mut t = Tally::default();
    let mut rows = Vec::new();
    for sc in &scenarios {
        let (authority, role) = (cs(&s(&sc["authority_id"])), cs(&s(&sc["role"])));
        let genesis = fx.key(&s(&sc["genesis_key"]));
        let mut h = ptr::null_mut();
        check(unsafe {
            ratify_v2_rotation_journal_new(
                authority.as_ptr(),
                i(&sc["recovery_epoch"]),
                role.as_ptr(),
                &genesis,
                &mut h,
            )
        })
        .unwrap();
        let journal = Journal(h);
        let row = format!("rotation-sequences.json {}", s(&sc["name"]));
        let steps = arr(&sc["steps"]);
        for (n, step) in steps.iter().enumerate() {
            let got = if step["op"] == "recover" {
                let key = fx.key(&s(&step["new_genesis_key"]));
                match check(unsafe {
                    ratify_v2_rotation_journal_recover(
                        journal.0,
                        i(&step["new_recovery_epoch"]),
                        &key,
                    )
                }) {
                    Ok(()) => "recovered".to_string(),
                    Err(e) => e.class,
                }
            } else {
                assert_eq!(step["op"], "accept", "unknown rotation op");
                let wire = b64(&step["wire_b64"]);
                let mut result = 0;
                match check(unsafe {
                    ratify_v2_rotation_journal_accept(
                        journal.0,
                        wire.as_ptr(),
                        wire.len(),
                        i(&step["now"]),
                        i(&sc["future_skew_seconds"]),
                        &mut result,
                    )
                }) {
                    Ok(()) if result == 1 => "appended".into(),
                    Ok(()) if result == 2 => "replay".into(),
                    Ok(()) => format!("unknown result {result}"),
                    Err(e) => e.class,
                }
            };
            let state =
                parse(&buf(|o| unsafe { ratify_v2_rotation_journal_state(journal.0, o) }).unwrap());
            let want = s(&step["expect"]);
            let want_key = fx.key_json(&s(&step["expect_current_key"]));
            let state_ok = i(&state["sequence"]) == i(&step["expect_sequence"])
                && state["current_key"]["ml_dsa_65"] == want_key["ml_dsa_65"]
                && i(&state["recovery_epoch"]) == i(&step["expect_recovery_epoch"])
                && state["frozen"] == step["expect_frozen"];
            t.check(
                &row,
                &format!("step {n} {}", s(&step["label"])),
                got == want && state_ok,
                || format!("got {got} (want {want}); state {}", state),
            );
        }
        rows.push((row, steps.len()));
    }
    let rows: Vec<(&str, usize)> = rows.iter().map(|(r, n)| (r.as_str(), *n)).collect();
    t.finish(&rows);
}
