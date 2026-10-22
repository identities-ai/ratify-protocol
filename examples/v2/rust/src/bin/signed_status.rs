//! Ratify Protocol v2 signed status: a status publisher under a separate
//! status key, journal ingestion, and a revocation that turns a later
//! verification into deny.
//!
//! DEVELOPMENT ONLY. This program uses the in-memory reference stores from
//! `ratify_protocol::v2::reference`. A production verifier supplies durable
//! Part B stores, an anchored journal store and an independent checkpoint
//! (SPEC-v2 §7).
//!
//! Run from examples/v2/rust: cargo run --bin signed_status

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use ratify_protocol::v2::reference::{JournalStore, Store, TestOnlyChallengeIssuanceStore};
use ratify_protocol::v2::*;
use ratify_protocol::{generate_hybrid_keypair, HybridPublicKey, HybridSignature};

const START: i64 = 1_800_000_000;
const NAMESPACE: &str = "signed-status";
const EPOCH: i64 = 1;
const LOG_ID: &str = "00000000000000000000000000000002";
const CERT_ID: &str = "status-demo-cert-1";

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
    println!("Ratify Protocol v2 signed status");
    println!("development only: in-memory reference stores");

    let (root_pub, root_priv) = generate_hybrid_keypair();
    let (agent_pub, agent_priv) = generate_hybrid_keypair();
    let (status_pub, status_priv) = generate_hybrid_keypair();
    let (verifier_pub, verifier_priv) = generate_hybrid_keypair();
    let root_id = key_id_v2(&root_pub)?;
    let agent_id = key_id_v2(&agent_pub)?;
    let verifier_id = key_id_v2(&verifier_pub)?;

    let cert = sign_delegation_cert_v2(
        &DelegationCertV2 {
            version: 2,
            cert_id: CERT_ID.into(),
            issuer_id: root_id.clone(),
            issuer_pub_key: root_pub.clone(),
            subject_id: agent_id.clone(),
            subject_pub_key: agent_pub.clone(),
            scope: vec!["data:read".into()],
            constraints: Vec::new(),
            issued_at: START,
            expires_at: START + 86400,
            signature: unsigned(),
        },
        &root_priv,
    )?;
    println!("delegation: {CERT_ID} scope=data:read");

    // The journal is the verifier's anchored record of key roles, status-key
    // epochs and accepted status. Roles are recorded once, when the
    // deployment authenticates its trust configuration.
    let journal = Arc::new(JournalStore::new()?);
    for (role, public) in [
        ("issuer", &root_pub),
        ("delegation", &agent_pub),
        ("verifier", &verifier_pub),
    ] {
        record_security_key_role_v2(&ctx, journal.as_ref(), role, public)?;
    }
    configure_status_key_epoch_v2(&ctx, journal.as_ref(), &root_id, 1, &status_pub)?;
    println!("journal: key roles recorded; status key configured for the root at epoch 1");

    // Role separation: the root key can never sign status for itself.
    let refused =
        new_v2_status_publisher_with_key(&ctx, journal.as_ref(), &root_pub, &root_priv, 3600);
    println!(
        "publisher with the root key as status key: refused ({})",
        v2_error_class_of(&refused)
            .map(|c| c.as_str())
            .unwrap_or("none")
    );

    let publisher =
        new_v2_status_publisher_with_key(&ctx, journal.as_ref(), &root_pub, &status_priv, 3600)?;
    let policy = RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 3600,
        clock_skew_seconds: 5,
    };

    // Genesis: sequence 1, nothing revoked. The caller persists the returned
    // state before publishing the signed list.
    let genesis = publisher.genesis(&ctx, START)?;
    let genesis_wire = encode_revocation_list_v2(&genesis.list)?;
    println!("publisher: genesis list sequence {}", genesis.list.sequence);
    apply_revocation_list_to_journal_v2(
        &ctx,
        journal.as_ref(),
        &genesis.list,
        &root_id,
        1,
        &status_pub,
        &policy,
        START,
    )?;
    let status = revocation_status_from_journal_v2(
        &ctx,
        journal.as_ref(),
        &root_id,
        CERT_ID,
        1,
        &status_pub,
        &policy,
        START,
    )?;
    println!(
        "journal: ingested list sequence {}; {CERT_ID} is {}",
        genesis.list.sequence, status.status
    );

    let store = Arc::new(Store::new(START, 30, LOG_ID, &verifier_priv)?);
    let issuance = Arc::new(TestOnlyChallengeIssuanceStore::new());
    let evidence: Arc<Mutex<Vec<V2StatusEvidenceObject>>> =
        Arc::new(Mutex::new(vec![V2StatusEvidenceObject {
            object_type: 3,
            wire: genesis_wire,
        }]));

    // verify_and_release runs one complete live verification at the store's
    // current time and returns the released decision.
    let verify_and_release = |label: &str| -> Result<(), Box<dyn Error>> {
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
        let context_policy = V2ContextPolicy::new("example.signed-status/v1", false, &[], &[])?;
        let (trusted_id, trusted_key) = (root_id.clone(), root_pub.clone());
        let provided = evidence.clone();
        let outcome = verify_proof_bundle_v2(
            &ctx,
            &V2VerifyRequest {
                bundle: wire,
                expected: Some(expected),
                context_policy: Some(context_policy),
                required_scope: "data:read".into(),
                verifier_namespace: NAMESPACE.into(),
                replay_epoch: EPOCH,
                now: store.now(),
                max_challenge_age_seconds: 300,
                future_skew_seconds: 5,
                tzdb_version: TZDB_VERSION_V2.into(),
                status_keys: BTreeMap::from([(
                    root_id.clone(),
                    V2StatusKeyConfig {
                        epoch: 1,
                        key: status_pub.clone(),
                    },
                )]),
                status_policy: policy,
                ..Default::default()
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
                // The provider returns signed objects only; the verifier checks
                // each signature against the configured status key and applies
                // it to the journal before it derives a status.
                status_evidence: Some(Arc::new(
                    move |_ctx: &V2Context, _req: &V2StatusEvidenceRequest| {
                        Ok(V2StatusEvidenceBatch {
                            objects: provided.lock().expect("evidence").clone(),
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
            "{label}: decision={} reason={} status_assessment={} allowed={}",
            decision.decision(),
            decision.reason(),
            receipt.status_assessment,
            decision.allowed(&ctx, store.as_ref())
        );
        Ok(())
    };

    store.set_time(START + 5);
    verify_and_release("verify before revocation")?;

    // Revoke: a push with the newly revoked ID and the cumulative list, both
    // at sequence 2.
    let revoked = publisher.revoke(&ctx, &genesis.state, &[CERT_ID.to_string()], START + 10)?;
    let push = revoked.push.clone().ok_or("revocation produced no push")?;
    let push_wire = encode_revocation_push_v2(&push)?;
    let list_wire = encode_revocation_list_v2(&revoked.list)?;
    println!(
        "publisher: revoked {CERT_ID} (push sequence {}, list sequence {})",
        push.sequence, revoked.list.sequence
    );
    apply_revocation_push_to_journal_v2(
        &ctx,
        journal.as_ref(),
        &push,
        &root_id,
        1,
        &status_pub,
        &policy,
        START + 10,
    )?;
    let status = revocation_status_from_journal_v2(
        &ctx,
        journal.as_ref(),
        &root_id,
        CERT_ID,
        1,
        &status_pub,
        &policy,
        START + 10,
    )?;
    println!(
        "journal: ingested push sequence {}; {CERT_ID} is {}",
        push.sequence, status.status
    );

    *evidence.lock().expect("evidence") = vec![
        V2StatusEvidenceObject {
            object_type: 5,
            wire: push_wire,
        },
        V2StatusEvidenceObject {
            object_type: 3,
            wire: list_wire,
        },
    ];
    store.set_time(START + 15);
    verify_and_release("verify after revocation")
}
