//! testvectors/v2/challenge-issuance.json against the issuance helper, the
//! reference issuance store and the reference Part B claim store, mirroring
//! Go `TestV2ConformanceChallengeIssuance`
//! (v2_conformance_challenge_issuance_test.go).

mod v2_status_common;
mod v2_verify_common;

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use ratify_protocol::v2::reference::{PersistFault, Store, TestOnlyChallengeIssuanceStore};
use ratify_protocol::v2::*;
use serde_json::Value;
use v2_status_common::{load_v2_keys, Fixture};
use v2_verify_common::{arr, i, load_v2_vector, readme_line, s, unb64};

// Fixture namespace and replay epoch shared with the other corpus files.
const NAMESPACE: &str = "verify-test";
const EPOCH: i64 = 3;

/// Go `v2PresentIssued`: retrieval, pre-claim checks and the atomic claim
/// for one presented bundle, naming the outcome.
fn present_issued(issuance: &dyn V2ChallengeIssuanceStore, claims: &dyn ClaimStoreV2, wire: &[u8], now: i64) -> String {
    let ctx = V2Context::background();
    let bundle = match decode_proof_bundle_v2(wire) {
        Ok(b) => b,
        Err(e) => return format!("preflight:{}", e.class),
    };
    let expected = match load_expected_challenge_v2(&ctx, issuance, NAMESPACE, EPOCH, &bundle.challenge) {
        Ok(e) => e,
        Err(e) => return format!("preflight:{}", e.class),
    };
    let policy = match &expected.expected_session_context {
        Some(context) => V2ContextPolicy::new(
            "ratify.verify.session-context/v1",
            true,
            &["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"].map(String::from),
            context,
        ),
        None => V2ContextPolicy::new("ratify.conformance.context-not-required/v1", false, &[], &[]),
    };
    let policy = match policy {
        Ok(p) => p,
        Err(e) => return format!("policy error: {e}"),
    };
    let preflight = match preflight_proof_bundle_v2(
        &bundle,
        Some(&expected),
        Some(&policy),
        "data:read",
        NAMESPACE,
        EPOCH,
        &expected.verifier_id,
        now,
        300,
        5,
    ) {
        Ok(p) => p,
        Err(e) => return format!("preflight:{}", e.class),
    };
    match claim_proof_bundle_v2(&ctx, claims, &bundle, &preflight, NAMESPACE, EPOCH, now) {
        Err(e) if e.class == V2ErrorClass::ClaimReplay => "proof_conflict".into(),
        Err(e) => format!("claim error: {e}"),
        Ok((_, disposition, _)) => disposition.as_str().into(),
    }
}

fn run_scenario(sc: &Value, fx: &Fixture) -> usize {
    let ctx = V2Context::background();
    let name = s(&sc["name"]);
    let mut random = Vec::new();
    for r in arr(&sc["random_b64"]) {
        random.extend(unb64(&r));
    }
    let steps = arr(&sc["steps"]);
    let verifier = fx.private.get("verifier").expect("verifier key");
    let claims = Arc::new(
        Store::new(i(&steps[0]["at"]), 60, "0123456789abcdef0123456789abcdef", verifier).expect("store"),
    );
    let issuance = Arc::new(TestOnlyChallengeIssuanceStore::new());
    let issuer = V2ChallengeIssuer {
        clock: claims.clone(),
        store: issuance.clone(),
        random: Some(Arc::new(Mutex::new(Cursor::new(random)))),
    };
    for (n, step) in steps.iter().enumerate() {
        let at = i(&step["at"]);
        if at != 0 {
            claims.set_time(at);
        }
        let exp = &step["expect"];
        match s(&step["op"]).as_str() {
            "issue" => {
                let r = &step["request"];
                let mut req = V2ChallengeIssueRequest {
                    verifier_namespace: s(&r["verifier_namespace"]),
                    replay_epoch: i(&r["replay_epoch"]),
                    verifier_id: s(&r["verifier_id"]),
                    lifetime_seconds: i(&r["lifetime_seconds"]),
                    ..Default::default()
                };
                if !r["expected_agent"].is_null() {
                    let agent = s(&r["expected_agent"]);
                    req.expected_agent_id = fx.id.get(&agent).cloned().unwrap_or_default();
                    req.expected_agent_public_key = Some(fx.public(&agent));
                }
                if !r["expected_receiver_id"].is_null() {
                    req.expected_receiver_id = s(&r["expected_receiver_id"]);
                }
                if !r["expected_session_context_b64"].is_null() {
                    req.expected_session_context = Some(unb64(&r["expected_session_context_b64"]));
                }
                match s(&step["persist_fault"]).as_str() {
                    "fail_before_commit" => issuance.fail_next_persist(PersistFault::FailBeforeCommit),
                    "fail_after_commit" => issuance.fail_next_persist(PersistFault::FailAfterCommit),
                    _ => {}
                }
                let got = issuer.issue_challenge_v2(&ctx, &req);
                match s(&exp["result"]).as_str() {
                    "issued" => {
                        let got = got.unwrap_or_else(|e| panic!("{name} step {n}: issuance failed: {e}"));
                        assert!(
                            got.value == unb64(&exp["challenge_b64"])
                                && got.issued_at == i(&exp["issued_at"])
                                && got.expires_at == i(&exp["expires_at"]),
                            "{name} step {n}: issued {:?}",
                            got
                        );
                        let stored = load_expected_challenge_v2(
                            &ctx,
                            issuance.as_ref(),
                            &req.verifier_namespace,
                            req.replay_epoch,
                            &got.value,
                        )
                        .unwrap_or_else(|e| panic!("{name} step {n}: a returned challenge must already be durably retrievable: {e}"));
                        assert_eq!(stored.expected_agent_id, req.expected_agent_id, "{name} step {n}");
                        assert_eq!(stored.expected_session_context, req.expected_session_context, "{name} step {n}");
                    }
                    "error" => {
                        let e = got.expect_err(&format!("{name} step {n}: issuance returned a challenge"));
                        let want = s(&exp["error_class"]);
                        if !want.is_empty() {
                            assert_eq!(e.class.as_str(), want, "{name} step {n}: {e}");
                        }
                    }
                    other => panic!("{name} step {n}: unknown issue result {other:?}"),
                }
                if !exp["records_after"].is_null() {
                    assert_eq!(issuance.len() as i64, i(&exp["records_after"]), "{name} step {n}: stored records");
                }
            }
            "load" => {
                let got = load_expected_challenge_v2(&ctx, issuance.as_ref(), NAMESPACE, EPOCH, &unb64(&step["challenge_b64"]));
                if s(&exp["result"]) == "found" {
                    let got = got.unwrap_or_else(|e| panic!("{name} step {n}: load: {e}"));
                    assert_eq!((got.issued_at, got.expires_at), (i(&exp["issued_at"]), i(&exp["expires_at"])), "{name} step {n}");
                    if !exp["expected_receiver_id"].is_null() {
                        assert_eq!(got.expected_receiver_id, s(&exp["expected_receiver_id"]), "{name} step {n}: load receiver");
                    }
                } else {
                    let class = got.err().map(|e| e.class.as_str().to_string()).unwrap_or_default();
                    assert_eq!(class, s(&exp["result"]), "{name} step {n}: load class");
                }
            }
            "present" | "present_concurrent" => {
                let wires: Vec<Vec<u8>> = arr(&step["bundles_b64"]).iter().map(unb64).collect();
                let mut outcomes: Vec<String> = std::thread::scope(|scope| {
                    let handles: Vec<_> = wires
                        .iter()
                        .map(|wire| {
                            let (issuance, claims) = (issuance.clone(), claims.clone());
                            scope.spawn(move || present_issued(issuance.as_ref(), claims.as_ref(), wire, at))
                        })
                        .collect();
                    handles.into_iter().map(|h| h.join().unwrap()).collect()
                });
                outcomes.sort();
                let mut want: Vec<String> = match s(&exp["result"]).as_str() {
                    "preflight" => vec![format!("preflight:{}", s(&exp["error_class"]))],
                    "claimed" => arr(&exp["dispositions"]).iter().map(s).collect(),
                    other => panic!("{name} step {n}: unknown present result {other:?}"),
                };
                want.sort();
                assert_eq!(outcomes, want, "{name} step {n}: outcomes");
            }
            other => panic!("{name} step {n}: unknown op {other:?}"),
        }
    }
    steps.len()
}

#[test]
fn v2_conformance_challenge_issuance() {
    let f = load_v2_vector("challenge-issuance.json");
    let fx = load_v2_keys();
    let scenarios = arr(&f["scenarios"]);
    assert!(!scenarios.is_empty(), "no challenge issuance scenarios");
    let steps: usize = scenarios.iter().map(|sc| run_scenario(sc, &fx)).sum();
    assert_eq!((scenarios.len(), steps), (11, 42));
    let readme = readme_line("challenge-issuance.json");
    assert!(readme.contains("11 challenge issuance helper scenarios (42 steps"), "README row: {readme}");
}
