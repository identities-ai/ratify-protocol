//! Rust counterpart of sdks/python/bench_v2/bench_v2.py: its cert_signature_verify,
//! decision and dual_root_decision measurements over the same flow, for
//! comparing the SDKs on one host.
//!
//! Run from sdks/python/bench_v2/rust: cargo run --release -- [--json out.json] [--scale 1]
//!
//! DEVELOPMENT ONLY: the claim store, receipt log, checkpoint, journal and
//! challenge issuance store are the in-memory reference stores.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratify_protocol::crypto::hybrid_keypair_from_seeds;
use ratify_protocol::v2::reference::{JournalStore, Store, TestOnlyChallengeIssuanceStore};
use ratify_protocol::v2::*;
use ratify_protocol::{HybridPrivateKey, HybridPublicKey, HybridSignature};

const START: i64 = 1_800_000_000;
const EPOCH: i64 = 1;
const LOG_ID: &str = "00000000000000000000000000000001";
const SCOPE: &str = "payments:send";
const NAMES: [&str; 3] = ["cert_signature_verify", "decision", "dual_root_decision"];

fn iterations(name: &str) -> usize {
    match name {
        "cert_signature_verify" => 200,
        "decision" => 50,
        _ => 25,
    }
}

/// Deterministic hybrid keypair number `n` (the Python bench's `_key`).
fn key(n: u8) -> (HybridPublicKey, HybridPrivateKey) {
    hybrid_keypair_from_seeds(&[n; 32], &[n + 100; 32])
}

fn id(public: &HybridPublicKey) -> String {
    key_id_v2(public).expect("key id")
}

fn unsigned() -> HybridSignature {
    HybridSignature {
        ed25519: Vec::new(),
        ml_dsa_65: Vec::new(),
    }
}

/// One root's quickstart verifier flow against a shared reference store.
struct Flow {
    ctx: V2Context,
    store: Arc<Store>,
    journal: Arc<JournalStore>,
    namespace: String,
    agent_pub: HybridPublicKey,
    agent_priv: HybridPrivateKey,
    agent_id: String,
    verifier_pub: HybridPublicKey,
    verifier_id: String,
    root_pub: HybridPublicKey,
    root_id: String,
    certs: Vec<DelegationCertV2>, // leaf first
    status_keys: BTreeMap<String, V2StatusKeyConfig>,
    status_wires: Arc<HashMap<String, Vec<u8>>>,
    issuance: Arc<TestOnlyChallengeIssuanceStore>,
}

struct Presentation {
    challenge: Vec<u8>,
    wire: Vec<u8>,
}

impl Flow {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ctx: &V2Context,
        store: &Arc<Store>,
        journal: &Arc<JournalStore>,
        verifier_pub: &HybridPublicKey,
        agent: &(HybridPublicKey, HybridPrivateKey),
        root_n: u8,
        depth: usize,
        namespace: &str,
    ) -> Flow {
        let (root_pub, root_priv) = key(root_n);
        let (status_pub, status_priv) = key(root_n + 1);
        // Chain from the root down to the agent; depth 2 adds one intermediate.
        let mut holders = vec![(root_pub.clone(), root_priv)];
        for i in 0..depth - 1 {
            holders.push(key(root_n + 2 + i as u8));
        }
        holders.push(agent.clone());
        let mut certs = Vec::new();
        for i in 0..depth {
            let (issuer_pub, issuer_priv) = &holders[i];
            let subject_pub = &holders[i + 1].0;
            // Every certificate above the leaf must also grant identity:delegate.
            let scope = if i == depth - 1 {
                vec![SCOPE.to_string()]
            } else {
                vec![SCOPE.to_string(), "identity:delegate".to_string()]
            };
            certs.push(
                sign_delegation_cert_v2(
                    &DelegationCertV2 {
                        version: 2,
                        cert_id: format!("{namespace}-cert-{i}"),
                        issuer_id: id(issuer_pub),
                        issuer_pub_key: issuer_pub.clone(),
                        subject_id: id(subject_pub),
                        subject_pub_key: subject_pub.clone(),
                        scope,
                        constraints: vec![ConstraintV2 {
                            kind: CONSTRAINT_MAX_AMOUNT.into(),
                            currency: "USD".into(),
                            max_amount_micros: 50_000_000,
                            ..Default::default()
                        }],
                        issued_at: START,
                        expires_at: START + 86400,
                        signature: unsigned(),
                    },
                    issuer_priv,
                )
                .expect("sign cert"),
            );
        }
        certs.reverse();
        let mut roles = vec![
            ("issuer", root_pub.clone()),
            ("delegation", agent.0.clone()),
        ];
        for h in &holders[1..holders.len() - 1] {
            roles.push(("delegation", h.0.clone()));
        }
        for (role, public) in &roles {
            record_security_key_role_v2(ctx, journal.as_ref(), role, public).expect("role");
        }
        // Every issuer in the chain publishes signed status under its own key.
        let mut status_keys = BTreeMap::new();
        let mut status_wires = HashMap::new();
        for (j, (issuer_pub, _)) in holders[..holders.len() - 1].iter().enumerate() {
            let (s_pub, s_priv) = if j == 0 {
                (status_pub.clone(), status_priv.clone())
            } else {
                key(root_n + 50 + j as u8)
            };
            let issuer_id = id(issuer_pub);
            configure_status_key_epoch_v2(ctx, journal.as_ref(), &issuer_id, 1, &s_pub)
                .expect("status epoch");
            let publisher =
                new_v2_status_publisher_with_key(ctx, journal.as_ref(), issuer_pub, &s_priv, 3600)
                    .expect("publisher");
            let genesis = publisher.genesis(ctx, START).expect("genesis");
            status_wires.insert(
                issuer_id.clone(),
                encode_revocation_list_v2(&genesis.list).expect("encode list"),
            );
            status_keys.insert(
                issuer_id,
                V2StatusKeyConfig {
                    epoch: 1,
                    key: s_pub,
                },
            );
        }
        Flow {
            ctx: ctx.clone(),
            store: store.clone(),
            journal: journal.clone(),
            namespace: namespace.into(),
            agent_id: id(&agent.0),
            agent_pub: agent.0.clone(),
            agent_priv: agent.1.clone(),
            verifier_id: id(verifier_pub),
            verifier_pub: verifier_pub.clone(),
            root_id: id(&root_pub),
            root_pub,
            certs,
            status_keys,
            status_wires: Arc::new(status_wires),
            issuance: Arc::new(TestOnlyChallengeIssuanceStore::new()),
        }
    }

    /// Issue a challenge and sign a presentation (agent side, untimed).
    fn present(&self) -> Presentation {
        let issuer = V2ChallengeIssuer {
            clock: self.store.clone(),
            store: self.issuance.clone(),
            random: None,
        };
        let challenge = issuer
            .issue_challenge_v2(
                &self.ctx,
                &V2ChallengeIssueRequest {
                    verifier_namespace: self.namespace.clone(),
                    replay_epoch: EPOCH,
                    verifier_id: self.verifier_id.clone(),
                    lifetime_seconds: 120,
                    expected_agent_id: self.agent_id.clone(),
                    expected_agent_public_key: Some(self.agent_pub.clone()),
                    ..Default::default()
                },
            )
            .expect("challenge");
        let bundle = sign_proof_bundle_v2(
            &ProofBundleV2 {
                version: 2,
                verifier_id: self.verifier_id.clone(),
                agent_id: self.agent_id.clone(),
                agent_pub_key: self.agent_pub.clone(),
                delegations: self.certs.clone(),
                delegation_digest: Vec::new(),
                challenge: challenge.value.clone(),
                challenge_at: challenge.issued_at,
                challenge_sig: unsigned(),
                session_context: None,
                stream_id: None,
                stream_seq: None,
            },
            &self.agent_priv,
        )
        .expect("sign bundle");
        Presentation {
            wire: encode_proof_bundle_v2(&bundle).expect("encode bundle"),
            challenge: bundle.challenge,
        }
    }

    /// Verify, commit, publish, acknowledge and release one decision.
    fn decide(&self, p: &Presentation) {
        let ctx = &self.ctx;
        let expected = load_expected_challenge_v2(
            ctx,
            self.issuance.as_ref(),
            &self.namespace,
            EPOCH,
            &p.challenge,
        )
        .expect("expected challenge");
        let policy =
            V2ContextPolicy::new("example.quickstart/v1", false, &[], &[]).expect("policy");
        let req = V2VerifyRequest {
            bundle: p.wire.clone(),
            expected: Some(expected),
            context_policy: Some(policy),
            required_scope: SCOPE.into(),
            verifier_namespace: self.namespace.clone(),
            replay_epoch: EPOCH,
            now: self.store.now(),
            max_challenge_age_seconds: 300,
            future_skew_seconds: 5,
            context: ConstraintContextV2 {
                has_amount: true,
                requested_amount_micros: 12_500_000,
                requested_currency: "USD".into(),
                ..Default::default()
            },
            tzdb_version: TZDB_VERSION_V2.into(),
            status_keys: self.status_keys.clone(),
            status_policy: RevocationStatusPolicyV2 {
                max_list_lifetime_seconds: 3600,
                max_status_age_seconds: 3600,
                clock_skew_seconds: 5,
            },
            constraint_evaluators: None,
        };
        let (trusted_id, trusted_key) = (self.root_id.clone(), self.root_pub.clone());
        let wires = self.status_wires.clone();
        let cb = V2VerifyCallbacks {
            claim_store: Some(self.store.clone()),
            trust: Some(Arc::new(
                move |_ctx: &V2Context, chain: &[DelegationCertV2]| {
                    Ok(match chain.last() {
                        Some(last) if last.issuer_id == trusted_id => V2TrustResolution {
                            outcome: V2TrustOutcome::Trusted,
                            root_key: trusted_key.clone(),
                        },
                        _ => V2TrustResolution {
                            outcome: V2TrustOutcome::Untrusted,
                            root_key: HybridPublicKey {
                                ed25519: Vec::new(),
                                ml_dsa_65: Vec::new(),
                            },
                        },
                    })
                },
            )),
            status_evidence: Some(Arc::new(
                move |_ctx: &V2Context, sr: &V2StatusEvidenceRequest| {
                    Ok(V2StatusEvidenceBatch {
                        objects: vec![V2StatusEvidenceObject {
                            object_type: 3,
                            wire: wires.get(&sr.issuer_id).cloned().unwrap_or_default(),
                        }],
                    })
                },
            )),
            status_journal: Some(self.journal.clone()),
            ..Default::default()
        };
        let outcome = verify_proof_bundle_v2(ctx, &req, &cb);
        let committed = match (outcome.stage, outcome.committed) {
            (V2VerifyStage::Committed, Some(c)) => c,
            (stage, _) => panic!("verify stopped at {}: {:?}", stage.as_str(), outcome.error),
        };
        let receipt_wire = self
            .store
            .publish_v2_receipt(ctx, &committed.claim_id(), &committed.receipt_body())
            .expect("publish");
        decode_verification_receipt_v2(&receipt_wire).expect("decode receipt");
        let result = release_v2_decision(
            ctx,
            &committed,
            Some(&receipt_wire),
            V2ReleaseConfig {
                verifier_public_key: &self.verifier_pub,
                log_id: LOG_ID,
                claim_store: self.store.as_ref(),
                checkpoint: self.store.as_ref(),
            },
        );
        let status = result.status;
        let reason = result.reason.clone();
        match result.into_decision() {
            Some(d) if d.allowed(ctx, self.store.as_ref()) => {}
            _ => panic!("release {}: {}", status.as_str(), reason),
        }
    }
}

struct Bench {
    store: Arc<Store>,
    clock: i64,
    single: Flow,
    authority: Flow,
    admission: Flow,
}

impl Bench {
    fn new() -> Bench {
        let ctx = V2Context::background();
        let (verifier_pub, verifier_priv) = key(1);
        let agent = key(2);
        let store = Arc::new(Store::new(START, 30, LOG_ID, &verifier_priv).expect("store"));
        let journal = Arc::new(JournalStore::new().expect("journal"));
        record_security_key_role_v2(&ctx, journal.as_ref(), "verifier", &verifier_pub)
            .expect("verifier role");
        Bench {
            single: Flow::new(
                &ctx,
                &store,
                &journal,
                &verifier_pub,
                &agent,
                10,
                1,
                "bench-single",
            ),
            authority: Flow::new(
                &ctx,
                &store,
                &journal,
                &verifier_pub,
                &agent,
                20,
                2,
                "bench-authority",
            ),
            admission: Flow::new(
                &ctx,
                &store,
                &journal,
                &verifier_pub,
                &agent,
                30,
                1,
                "bench-admission",
            ),
            store,
            clock: START,
        }
    }

    /// The reference clock never moves backward: present, then verify 2s later.
    fn tick(&mut self) {
        self.clock += 2;
        self.store.set_time(self.clock);
    }

    fn time(ops: usize, mut f: impl FnMut(usize)) -> Vec<Duration> {
        (0..ops)
            .map(|i| {
                let t0 = Instant::now();
                f(i);
                t0.elapsed()
            })
            .collect()
    }

    /// Per-operation latencies for `n` operations.
    fn run(&mut self, name: &str, n: usize) -> Vec<Duration> {
        match name {
            // verify_delegation_cert_v2_signature: the certificate's structure
            // and key-ID checks plus one strict hybrid verification.
            "cert_signature_verify" => {
                let cert = self.single.certs[0].clone();
                Self::time(n, |_| {
                    verify_delegation_cert_v2_signature(&cert).expect("verify");
                })
            }
            "decision" => {
                self.tick();
                let ps: Vec<_> = (0..n).map(|_| self.single.present()).collect();
                self.tick();
                Self::time(n, |i| self.single.decide(&ps[i]))
            }
            _ => {
                self.tick();
                let ps: Vec<_> = (0..n)
                    .map(|_| (self.authority.present(), self.admission.present()))
                    .collect();
                self.tick();
                Self::time(n, |i| {
                    self.authority.decide(&ps[i].0);
                    self.admission.decide(&ps[i].1);
                })
            }
        }
    }
}

fn round(v: f64, places: i32) -> f64 {
    let p = 10f64.powi(places);
    (v * p).round() / p
}

struct Summary {
    n: usize,
    ops_per_s: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
}

fn summarize(lat: &[Duration]) -> Summary {
    let total: f64 = lat.iter().map(Duration::as_secs_f64).sum();
    let mut ordered = lat.to_vec();
    ordered.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let p95 = ((ordered.len() as f64 * 0.95) as usize).min(ordered.len() - 1);
    Summary {
        n: lat.len(),
        ops_per_s: round(lat.len() as f64 / total, 2),
        mean_ms: round(total * 1000.0 / lat.len() as f64, 3),
        p50_ms: round(ms(ordered[ordered.len() / 2]), 3),
        p95_ms: round(ms(ordered[p95]), 3),
    }
}

fn main() {
    let mut json_path = None;
    let mut scale = 1.0f64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json_path = args.next(),
            "--scale" => {
                scale = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("--scale value")
            }
            other => panic!("unknown argument {other}"),
        }
    }
    let mut bench = Bench::new();
    let mut results = Vec::new();
    for name in NAMES {
        let n = ((iterations(name) as f64 * scale) as usize).max(1);
        bench.run(name, n.min(3)); // warm-up
        results.push((name, summarize(&bench.run(name, n))));
    }
    let machine = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    println!("rust (release) on {machine}");
    println!(
        "{:<22} {:>5} {:>10} {:>10} {:>10} {:>10}",
        "measurement", "n", "ops/s", "mean ms", "p50 ms", "p95 ms"
    );
    for (name, r) in &results {
        println!(
            "{:<22} {:>5} {:>10} {:>10} {:>10} {:>10}",
            name, r.n, r.ops_per_s, r.mean_ms, r.p50_ms, r.p95_ms
        );
    }
    if let Some(path) = json_path {
        let body: Vec<String> = results
            .iter()
            .map(|(name, r)| {
                format!(
                    "    \"{name}\": {{\"n\": {}, \"ops_per_s\": {}, \"mean_ms\": {}, \"p50_ms\": {}, \"p95_ms\": {}}}",
                    r.n, r.ops_per_s, r.mean_ms, r.p50_ms, r.p95_ms
                )
            })
            .collect();
        let json = format!(
            "{{\n  \"sdk\": \"rust\",\n  \"machine\": \"{machine}\",\n  \"results\": {{\n{}\n  }}\n}}\n",
            body.join(",\n")
        );
        std::fs::write(path, json).expect("write json");
    }
}
