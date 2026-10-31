//! testvectors/v2/status-sequences.json, mirroring Go
//! `TestV2ConformanceStatusSequences` (v2_conformance_test.go).

mod v2_status_common;

use ratify_protocol::v2::{
    apply_revocation_list_v2, apply_revocation_push_v2, decode_revocation_list_v2,
    decode_revocation_push_v2, revocation_status_for_cert_v2,
    transition_revocation_status_epoch_v2, RevocationStatusStateV2, StatusEvidenceEntryV2,
    V2Result,
};
use serde_json::Value;
use v2_status_common::{i, load_v2_keys, load_v2_vector, policy, readme_line, s, u, unb64};

fn evidence(v: &Value) -> StatusEvidenceEntryV2 {
    StatusEvidenceEntryV2 {
        issuer_id: s(&v["issuer_id"]),
        status_key_id: s(&v["status_key_id"]),
        sequence: i(&v["sequence"]),
        object_type: u16::try_from(u(&v["object_type_code"])).expect("code"),
        digest: s(&v["digest"]),
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().expect("array").iter().map(s).collect()
}

fn check_state(where_: &str, st: &RevocationStatusStateV2, w: &Value) {
    let mut checked = 0;
    let mut cmp = |name: &str, got: String, want: Option<String>| {
        if let Some(want) = want {
            assert_eq!(got, want, "{where_}: {name}");
            checked += 1;
        }
    };
    cmp(
        "has_floor",
        st.has_floor.to_string(),
        w.get("has_floor").map(|v| v.to_string()),
    );
    cmp(
        "floor",
        st.floor.to_string(),
        w.get("floor").map(|v| v.to_string()),
    );
    cmp(
        "max_observed_sequence",
        st.max_observed_sequence.to_string(),
        w.get("max_observed_sequence").map(|v| v.to_string()),
    );
    cmp(
        "fork_sequence",
        st.fork_sequence.to_string(),
        w.get("fork_sequence").map(|v| v.to_string()),
    );
    cmp(
        "reconciliation_required",
        st.reconciliation_required.to_string(),
        w.get("reconciliation_required").map(|v| v.to_string()),
    );
    cmp(
        "future_dated_object_observed",
        st.future_dated_object_observed.to_string(),
        w.get("future_dated_object_observed").map(|v| v.to_string()),
    );
    cmp(
        "accepted_set",
        format!("{:?}", st.accepted_cert_ids),
        w.get("accepted_set").map(|v| format!("{:?}", strings(v))),
    );
    cmp(
        "deny_union",
        format!("{:?}", st.deny_union_cert_ids),
        w.get("deny_union").map(|v| format!("{:?}", strings(v))),
    );
    assert_eq!(
        checked,
        w.as_object().expect("expect_state object").len(),
        "{where_}: expect_state has members this harness does not check"
    );
}

#[test]
fn v2_conformance_status_sequences() {
    let fx = load_v2_keys();
    let f = load_v2_vector("status-sequences.json");
    let scenarios = f["scenarios"].as_array().expect("scenarios");
    assert!(!scenarios.is_empty(), "no status scenarios");
    let (mut scenario_count, mut step_count, mut queries, mut errors, mut body_digests) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for sc in scenarios {
        let name = s(&sc["name"]);
        let issuer_id = s(&sc["issuer_id"]);
        let mut state = RevocationStatusStateV2::default();
        for (n, step) in sc["steps"].as_array().expect("steps").iter().enumerate() {
            step_count += 1;
            let key = fx.public(&s(&step["status_key"]));
            let pol = match step.get("policy") {
                Some(p) if !p.is_null() => policy(p),
                _ => policy(&sc["policy"]),
            };
            let epoch = u(&step["status_key_epoch"]);
            let now = i(&step["now"]);
            let op = s(&step["op"]);
            let label = s(&step["label"]);
            let next: V2Result<RevocationStatusStateV2> = match op.as_str() {
                "apply_list" => {
                    decode_revocation_list_v2(&unb64(&step["wire_b64"])).and_then(|l| {
                        apply_revocation_list_v2(&state, &l, &issuer_id, epoch, &key, &pol, now)
                    })
                }
                "apply_push" => {
                    decode_revocation_push_v2(&unb64(&step["wire_b64"])).and_then(|p| {
                        apply_revocation_push_v2(&state, &p, &issuer_id, epoch, &key, &pol, now)
                    })
                }
                "transition_epoch" => {
                    transition_revocation_status_epoch_v2(&state, &issuer_id, epoch, &key)
                }
                "query" => {
                    queries += 1;
                    let cert_id = s(&step["cert_id"]);
                    let r = revocation_status_for_cert_v2(
                        &state, &issuer_id, &cert_id, epoch, &key, &pol, now,
                    )
                    .unwrap_or_else(|e| panic!("{name} step {n} query: {e}"));
                    let want = &step["expect_result"];
                    assert_eq!(
                        (r.status.as_str(), r.reason.as_str()),
                        (s(&want["status"]).as_str(), s(&want["reason"]).as_str()),
                        "{name} step {n} query {cert_id}"
                    );
                    let want_evidence: Vec<StatusEvidenceEntryV2> = want["evidence"]
                        .as_array()
                        .expect("evidence")
                        .iter()
                        .map(evidence)
                        .collect();
                    assert_eq!(
                        r.evidence, want_evidence,
                        "{name} step {n} query {cert_id} evidence"
                    );
                    continue;
                }
                other => panic!("unknown op {other:?}"),
            };
            if let Some(class) = step.get("expect_error_class").and_then(Value::as_str) {
                errors += 1;
                let got = next.as_ref().err().map(|e| e.class.as_str());
                assert_eq!(got, Some(class), "{name} step {n} {op} {label}");
                continue;
            }
            state = next.unwrap_or_else(|e| panic!("{name} step {n} {op} {label}: {e}"));
            if let Some(w) = step.get("expect_state").filter(|w| !w.is_null()) {
                check_state(&format!("{name} step {n} {op} {label}"), &state, w);
            }
            // SPEC-v2 §6.6: the observation's body_digest is the unlabelled
            // SHA-384 of the canonical signable body.
            if let Some(want) = step.get("expect_body_digest").and_then(Value::as_str) {
                body_digests += 1;
                let code = if op == "apply_push" { 5 } else { 3 };
                assert!(
                    state.observations.iter().any(|o| o.status_key_epoch == epoch
                        && o.object_type == code
                        && format!("sha384:{}", hex::encode(&o.body_digest)) == want),
                    "{name} step {n} {op} {label}: no observation with body_digest {want}"
                );
            }
        }
        scenario_count += 1;
    }
    assert_eq!((scenario_count, step_count), (22, 112));
    assert_eq!((queries, errors, body_digests), (43, 3, 63));
    let readme = readme_line("status-sequences.json");
    assert!(
        readme.contains(&format!(
            "{scenario_count} status-reducer scenarios ({step_count} steps)"
        )),
        "README disagrees: {readme}"
    );
}
