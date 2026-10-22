//! testvectors/v2/status-publisher.json, mirroring Go
//! `TestV2ConformanceStatusPublisher` (v2_conformance_status_publisher_test.go).

mod v2_status_common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ratify_protocol::v2::reference::JournalStore;
use ratify_protocol::v2::{
    apply_revocation_list_to_journal_v2, apply_revocation_push_to_journal_v2,
    configure_status_key_epoch_v2, new_v2_status_publisher, record_security_key_role_v2,
    revocation_status_from_journal_v2, verify_revocation_list_v2_signature,
    verify_revocation_push_v2_signature, LocalSignerV2, RevokedCertV2, SignRequestV2, SignerModeV2,
    SignerV2, V2Context, V2ErrorClass, V2SignResult, V2StatusPublication, V2StatusPublisherState,
};
use ratify_protocol::{HybridPublicKey, HybridSignature};
use serde_json::Value;
use v2_status_common::{i, load_v2_keys, load_v2_vector, policy, readme_line, s};

/// Go `v2CountingSigner`: counts every signer method call.
struct CountingSigner {
    inner: LocalSignerV2,
    calls: Arc<AtomicUsize>,
}

impl SignerV2 for CountingSigner {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.public_key_v2()
    }
    fn mode_v2(&self) -> SignerModeV2 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.mode_v2()
    }
    fn sign_v2(&self, ctx: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_v2(ctx, request)
    }
}

fn revoked_ids(refs: &[RevokedCertV2]) -> Vec<String> {
    refs.iter().map(|r| r.cert_id.clone()).collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(s).collect())
        .unwrap_or_default()
}

#[test]
fn v2_conformance_status_publisher() {
    let f = load_v2_vector("status-publisher.json");
    let fx = load_v2_keys();
    let scenarios_json = f["scenarios"].as_array().expect("scenarios");
    assert!(!scenarios_json.is_empty(), "no status publisher scenarios");
    let pol = policy(&f["status_policy"]);
    let (mut scenarios, mut steps) = (0usize, 0usize);
    for sc in scenarios_json {
        scenarios += 1;
        let name = s(&sc["name"]);
        let ctx = V2Context::background();
        let issuer_key = fx.public(&s(&sc["issuer"]));
        let status_key = fx.public(&s(&sc["status_key"]));
        let issuer_id = fx.id.get(&s(&sc["issuer"])).cloned().unwrap_or_default();
        let journal = JournalStore::new().expect("store");
        for rk in sc["role_keys"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            record_security_key_role_v2(
                &ctx,
                &journal,
                &s(&rk["role"]),
                &fx.public(&s(&rk["key"])),
            )
            .unwrap_or_else(|e| panic!("{name}: record role: {e}"));
        }
        let mut setup = "not_configured";
        let configured_for = s(&sc["status_configured_for"]);
        if !configured_for.is_empty() {
            setup = "configured";
            let target = fx.id.get(&configured_for).cloned().unwrap_or_default();
            if configure_status_key_epoch_v2(&ctx, &journal, &target, 1, &status_key).is_err() {
                setup = "rejected";
            }
        }
        assert_eq!(setup, s(&sc["journal_setup"]), "{name}: journal setup");
        let private = fx
            .private
            .get(&s(&sc["status_key"]))
            .expect("status private key");
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = Arc::new(CountingSigner {
            inner: LocalSignerV2::new(private).expect("local signer"),
            calls: calls.clone(),
        });
        let publisher = new_v2_status_publisher(
            &ctx,
            &journal,
            &issuer_key,
            signer,
            i(&sc["lifetime_seconds"]),
        );
        match s(&sc["publisher"]).as_str() {
            "ok" => {
                if let Err(e) = &publisher {
                    panic!("{name}: publisher refused: {e}");
                }
            }
            "refused" => {
                let e = publisher
                    .as_ref()
                    .err()
                    .unwrap_or_else(|| panic!("{name}: publisher accepted a status key outside the authenticated role configuration"));
                assert_eq!(
                    e.class,
                    V2ErrorClass::ConfigurationInvalid,
                    "{name}: refusal class"
                );
            }
            other => panic!("{name}: unknown publisher expectation {other}"),
        }
        let Ok(publisher) = publisher else {
            assert!(
                calls.load(Ordering::SeqCst) <= 1,
                "{name}: a refused publisher invoked the signer"
            );
            steps += sc["steps"].as_array().map(Vec::len).unwrap_or(0);
            continue;
        };

        let mut state = V2StatusPublisherState::default();
        let mut publications: Vec<V2StatusPublication> = Vec::new();
        for (n, step) in sc["steps"].as_array().expect("steps").iter().enumerate() {
            steps += 1;
            let exp = &step["expect"];
            let at = i(&step["at"]);
            let op = s(&step["op"]);
            let result = match op.as_str() {
                "genesis" => publisher.genesis(&ctx, at),
                "heartbeat" => publisher.heartbeat(&ctx, &state, at),
                "revoke" => publisher.revoke(&ctx, &state, &strings(&step["cert_ids"]), at),
                "ingest" => {
                    let index = usize::try_from(step["publication"].as_u64().expect("publication"))
                        .expect("index");
                    let p = &publications[index];
                    let ingested = if s(&step["object"]) == "push" {
                        let push = p.push.as_ref().expect("publication push");
                        apply_revocation_push_to_journal_v2(
                            &ctx,
                            &journal,
                            push,
                            &issuer_id,
                            1,
                            &status_key,
                            &pol,
                            at,
                        )
                    } else {
                        apply_revocation_list_to_journal_v2(
                            &ctx,
                            &journal,
                            &p.list,
                            &issuer_id,
                            1,
                            &status_key,
                            &pol,
                            at,
                        )
                    };
                    ingested.unwrap_or_else(|e| panic!("{name} step {n}: ingest: {e}"));
                    continue;
                }
                "status" => {
                    let cert_id = s(&step["cert_id"]);
                    let r = revocation_status_from_journal_v2(
                        &ctx,
                        &journal,
                        &issuer_id,
                        &cert_id,
                        1,
                        &status_key,
                        &pol,
                        at,
                    )
                    .unwrap_or_else(|e| panic!("{name} step {n}: status: {e}"));
                    assert_eq!(
                        (r.status.as_str(), r.reason.as_str()),
                        (s(&exp["status"]).as_str(), s(&exp["reason"]).as_str()),
                        "{name} step {n}: {cert_id} status"
                    );
                    continue;
                }
                other => panic!("{name} step {n}: unknown op {other:?}"),
            };
            if s(&exp["result"]) == "refused" {
                assert!(result.is_err(), "{name} step {n}: {op} was not refused");
                continue;
            }
            let pubn = result.unwrap_or_else(|e| panic!("{name} step {n}: {op}: {e}"));
            let l = &pubn.list;
            verify_revocation_list_v2_signature(l, &issuer_id, &status_key)
                .unwrap_or_else(|e| panic!("{name} step {n}: list signature: {e}"));
            let el = &exp["list"];
            assert_eq!(
                (
                    l.sequence,
                    l.updated_at,
                    l.next_update,
                    revoked_ids(&l.revoked)
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
                pubn.push.is_some(),
                ep.is_some(),
                "{name} step {n}: push presence mismatch"
            );
            if let (Some(p), Some(ep)) = (&pubn.push, ep) {
                verify_revocation_push_v2_signature(p, &issuer_id, &status_key)
                    .unwrap_or_else(|e| panic!("{name} step {n}: push signature: {e}"));
                assert_eq!(
                    (p.sequence, p.pushed_at, revoked_ids(&p.revoked)),
                    (
                        i(&ep["sequence"]),
                        i(&ep["pushed_at"]),
                        strings(&ep["revoked"])
                    ),
                    "{name} step {n}: push"
                );
            }
            state = pubn.state.clone();
            publications.push(pubn);
        }
    }
    assert_eq!((scenarios, steps), (13, 39));
    let readme = readme_line("status-publisher.json");
    assert!(
        readme.contains(&format!(
            "{scenarios} signed-status publisher scenarios ({steps} steps"
        )),
        "README disagrees: {readme}"
    );
}
