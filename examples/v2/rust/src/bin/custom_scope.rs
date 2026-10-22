//! Ratify Protocol v2 custom scope and the standard max_count evaluator
//! profile (com.ratifyprotocol.max_count/v1).
//!
//! DEVELOPMENT ONLY. This program uses the in-memory reference stores from
//! `ratify_protocol::v2::reference`. A production verifier supplies durable
//! Part B stores and an independent checkpoint (SPEC-v2 §7).
//!
//! Run from examples/v2/rust: cargo run --bin custom_scope

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use ratify_protocol::v2::reference::{JournalStore, Store, TestOnlyChallengeIssuanceStore};
use ratify_protocol::v2::*;
use ratify_protocol::{generate_hybrid_keypair, HybridPublicKey, HybridSignature, ParamsValue};

const START: i64 = 1_800_000_000;
const NAMESPACE: &str = "custom-scope";
const EPOCH: i64 = 1;
const LOG_ID: &str = "00000000000000000000000000000003";
const CUSTOM_SCOPE: &str = "custom:acme:deploy";

fn unsigned() -> HybridSignature {
    HybridSignature {
        ed25519: Vec::new(),
        ml_dsa_65: Vec::new(),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let ctx = V2Context::background();
    println!("Ratify Protocol v2 custom scope and max_count profile");
    println!("development only: in-memory reference stores");

    let (root_pub, root_priv) = generate_hybrid_keypair();
    let (agent_pub, agent_priv) = generate_hybrid_keypair();
    let (status_pub, status_priv) = generate_hybrid_keypair();
    let (verifier_pub, verifier_priv) = generate_hybrid_keypair();
    let root_id = key_id_v2(&root_pub)?;
    let agent_id = key_id_v2(&agent_pub)?;
    let verifier_id = key_id_v2(&verifier_pub)?;

    let mut template = DelegationCertV2 {
        version: 2,
        cert_id: "custom-scope-cert-1".into(),
        issuer_id: root_id.clone(),
        issuer_pub_key: root_pub.clone(),
        subject_id: agent_id.clone(),
        subject_pub_key: agent_pub.clone(),
        scope: vec!["custom:*".into()],
        constraints: Vec::new(),
        issued_at: START,
        expires_at: START + 86400,
        signature: unsigned(),
    };

    // A custom scope is one exact name. Wildcards are invalid.
    let refused = sign_delegation_cert_v2(&template, &root_priv);
    println!(
        "issue scope custom:*: refused ({})",
        refused.err().map(|e| e.class().as_str()).unwrap_or("none")
    );

    // The certificate carries an extension constraint. Only a verifier that
    // registered the max_count/v1 profile for this type can evaluate it.
    template.scope = vec![CUSTOM_SCOPE.into()];
    template.constraints = vec![ConstraintV2 {
        kind: CONSTRAINT_MAX_COUNT_V2.into(),
        params: Some(BTreeMap::from([
            ("counter".into(), ParamsValue::Str("nodes".into())),
            ("max".into(), ParamsValue::Int(5)),
        ])),
        ..Default::default()
    }];
    let cert = sign_delegation_cert_v2(&template, &root_priv)?;
    println!("delegation: scope={CUSTOM_SCOPE} constraint={CONSTRAINT_MAX_COUNT_V2}(counter=nodes, max=5)");

    let max_count = standard_max_count_evaluator_v2();
    let digest = constraint_profile_digest_v2(&max_count.descriptor)?;
    println!("profile: {PROFILE_MAX_COUNT_V2} digest={digest}");
    let registry = ConstraintEvaluatorRegistryV2::new(Duration::from_secs(1), vec![max_count])?;

    let journal = Arc::new(JournalStore::new()?);
    record_security_key_role_v2(&ctx, journal.as_ref(), "issuer", &root_pub)?;
    configure_status_key_epoch_v2(&ctx, journal.as_ref(), &root_id, 1, &status_pub)?;
    let publisher =
        new_v2_status_publisher_with_key(&ctx, journal.as_ref(), &root_pub, &status_priv, 3600)?;
    let genesis = publisher.genesis(&ctx, START)?;
    let status_wire = encode_revocation_list_v2(&genesis.list)?;

    let store = Arc::new(Store::new(START, 30, LOG_ID, &verifier_priv)?);
    let issuance = Arc::new(TestOnlyChallengeIssuanceStore::new());

    // attempt verifies one request for `nodes` nodes and releases the result.
    let attempt = |label: &str,
                   nodes: i64,
                   evaluators: Option<ConstraintEvaluatorRegistryV2>|
     -> Result<(), Box<dyn Error>> {
        store.set_time(store.now() + 1);
        let challenge = V2ChallengeIssuer {
            clock: store.clone(),
            store: issuance.clone(),
            random: None,
        }
        .issue_challenge_v2(
            &ctx,
            &V2ChallengeIssueRequest {
                verifier_namespace: NAMESPACE.into(),
                replay_epoch: EPOCH,
                verifier_id: verifier_id.clone(),
                lifetime_seconds: 120,
                expected_agent_id: agent_id.clone(),
                expected_agent_public_key: Some(agent_pub.clone()),
                ..Default::default()
            },
        )?;
        let bundle = sign_proof_bundle_v2(
            &ProofBundleV2 {
                version: 2,
                verifier_id: verifier_id.clone(),
                agent_id: agent_id.clone(),
                agent_pub_key: agent_pub.clone(),
                delegations: vec![cert.clone()],
                delegation_digest: Vec::new(),
                challenge: challenge.value.clone(),
                challenge_at: challenge.issued_at,
                challenge_sig: unsigned(),
                session_context: None,
                stream_id: None,
                stream_seq: None,
            },
            &agent_priv,
        )?;
        let wire = encode_proof_bundle_v2(&bundle)?;
        let expected = load_expected_challenge_v2(
            &ctx,
            issuance.as_ref(),
            NAMESPACE,
            EPOCH,
            &bundle.challenge,
        )?;
        let context_policy = V2ContextPolicy::new("example.custom-scope/v1", false, &[], &[])?;
        let (trusted_id, trusted_key) = (root_id.clone(), root_pub.clone());
        let evidence = status_wire.clone();
        let outcome = verify_proof_bundle_v2(
            &ctx,
            &V2VerifyRequest {
                bundle: wire,
                expected: Some(expected),
                context_policy: Some(context_policy),
                required_scope: CUSTOM_SCOPE.into(),
                verifier_namespace: NAMESPACE.into(),
                replay_epoch: EPOCH,
                now: store.now(),
                max_challenge_age_seconds: 300,
                future_skew_seconds: 5,
                tzdb_version: TZDB_VERSION_V2.into(),
                // The requested quantity comes from the authenticated request,
                // never from the proof.
                context: ConstraintContextV2 {
                    extension_counts: BTreeMap::from([("nodes".to_string(), nodes)]),
                    ..Default::default()
                },
                constraint_evaluators: evaluators,
                status_keys: BTreeMap::from([(
                    root_id.clone(),
                    V2StatusKeyConfig {
                        epoch: 1,
                        key: status_pub.clone(),
                    },
                )]),
                status_policy: RevocationStatusPolicyV2 {
                    max_list_lifetime_seconds: 3600,
                    max_status_age_seconds: 3600,
                    clock_skew_seconds: 5,
                },
            },
            &V2VerifyCallbacks {
                claim_store: Some(store.clone()),
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
                    move |_ctx: &V2Context, _req: &V2StatusEvidenceRequest| {
                        Ok(V2StatusEvidenceBatch {
                            objects: vec![V2StatusEvidenceObject {
                                object_type: 3,
                                wire: evidence.clone(),
                            }],
                        })
                    },
                )),
                status_journal: Some(journal.clone()),
                ..Default::default()
            },
        );
        let committed = match (outcome.stage, outcome.committed) {
            (V2VerifyStage::Committed, Some(c)) => c,
            (stage, _) => {
                return Err(
                    format!("verify stopped at {}: {:?}", stage.as_str(), outcome.error).into(),
                )
            }
        };
        let receipt_wire =
            store.publish_v2_receipt(&ctx, &committed.claim_id(), &committed.receipt_body())?;
        let result = release_v2_decision(
            &ctx,
            &committed,
            Some(&receipt_wire),
            V2ReleaseConfig {
                verifier_public_key: &verifier_pub,
                log_id: LOG_ID,
                claim_store: store.as_ref(),
                checkpoint: store.as_ref(),
            },
        );
        let (status, reason) = (result.status, result.reason.clone());
        let decision = result
            .into_decision()
            .ok_or_else(|| format!("release {}: {}", status.as_str(), reason))?;
        let receipt = decision.receipt()?;
        println!(
            "{label}: decision={} reason={} allowed={}",
            decision.decision(),
            decision.reason(),
            decision.allowed(&ctx, store.as_ref())
        );
        for reference in &receipt.constraint_evaluators {
            println!(
                "  receipt constraint_evaluators: {} {}",
                reference.kind, reference.profile_digest
            );
        }
        Ok(())
    };

    attempt("request nodes=3", 3, Some(registry.clone()))?;
    attempt("request nodes=8", 8, Some(registry))?;
    attempt("request nodes=3 without the profile registered", 3, None)
}
