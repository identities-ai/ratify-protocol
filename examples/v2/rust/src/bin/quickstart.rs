//! Ratify Protocol v2 quickstart: delegate, present, verify, publish, release.
//!
//! DEVELOPMENT ONLY. This program uses the in-memory reference stores from
//! `ratify_protocol::v2::reference` (claim store, receipt log, checkpoint,
//! journal and challenge issuance store). They exist for tests and examples.
//! A production verifier supplies durable Part B stores and an independent
//! checkpoint (SPEC-v2 §7).
//!
//! Run from examples/v2/rust: cargo run --bin quickstart

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use ratify_protocol::v2::reference::{JournalStore, Store, TestOnlyChallengeIssuanceStore};
use ratify_protocol::v2::*;
use ratify_protocol::{generate_hybrid_keypair, HybridPublicKey, HybridSignature};

const START: i64 = 1_800_000_000; // fixed clock so the output is reproducible
const NAMESPACE: &str = "quickstart";
const EPOCH: i64 = 1;
const LOG_ID: &str = "00000000000000000000000000000001";

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
    println!("Ratify Protocol v2 quickstart");
    println!("development only: in-memory reference stores");

    // 1. Keys. Every party holds a hybrid Ed25519 + ML-DSA-65 key. The status
    // key is separate from the root key that issues delegations.
    let (root_pub, root_priv) = generate_hybrid_keypair();
    let (agent_pub, agent_priv) = generate_hybrid_keypair();
    let (status_pub, status_priv) = generate_hybrid_keypair();
    let (verifier_pub, verifier_priv) = generate_hybrid_keypair();
    let root_id = key_id_v2(&root_pub)?;
    let agent_id = key_id_v2(&agent_pub)?;
    let verifier_id = key_id_v2(&verifier_pub)?;
    println!(
        "keys: root, agent, status and verifier generated (key IDs are {} hex characters)",
        root_id.len()
    );

    // 2. The root delegates payments:send to the agent, capped at 50.00 USD
    // per action (amounts are integer micro-units in v2).
    let cert = sign_delegation_cert_v2(
        &DelegationCertV2 {
            version: 2,
            cert_id: "quickstart-cert-1".into(),
            issuer_id: root_id.clone(),
            issuer_pub_key: root_pub.clone(),
            subject_id: agent_id.clone(),
            subject_pub_key: agent_pub.clone(),
            scope: vec!["payments:send".into()],
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
        &root_priv,
    )?;
    println!("delegation: scope=payments:send max_amount=50000000 USD micros lifetime=86400s");

    // 3. Verifier state: the reference store is the claim store, receipt log,
    // checkpoint and authoritative clock. The journal records key roles and
    // the root's status key.
    let store = Arc::new(Store::new(START, 30, LOG_ID, &verifier_priv)?);
    let journal = Arc::new(JournalStore::new()?);
    for (role, public) in [
        ("issuer", &root_pub),
        ("delegation", &agent_pub),
        ("verifier", &verifier_pub),
    ] {
        record_security_key_role_v2(&ctx, journal.as_ref(), role, public)?;
    }
    configure_status_key_epoch_v2(&ctx, journal.as_ref(), &root_id, 1, &status_pub)?;

    // 4. The root's status publisher signs a genesis revocation list (no
    // revocations) under the separate status key.
    let publisher =
        new_v2_status_publisher_with_key(&ctx, journal.as_ref(), &root_pub, &status_priv, 3600)?;
    let genesis = publisher.genesis(&ctx, START)?;
    let status_wire = encode_revocation_list_v2(&genesis.list)?;
    println!(
        "status: genesis list signed by the status key (sequence {}, {} revoked)",
        genesis.state.sequence,
        genesis.state.revoked.len()
    );

    // 5. The verifier issues a challenge. The helper persists the record
    // before it returns the challenge.
    let issuance = Arc::new(TestOnlyChallengeIssuanceStore::new());
    let issuer = V2ChallengeIssuer {
        clock: store.clone(),
        store: issuance.clone(),
        random: None,
    };
    let challenge = issuer.issue_challenge_v2(
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
    println!(
        "challenge: issued and persisted, expires in {}s",
        challenge.expires_at - challenge.issued_at
    );

    // 6. The agent signs a proof bundle over the challenge.
    store.set_time(START + 2);
    let bundle = sign_proof_bundle_v2(
        &ProofBundleV2 {
            version: 2,
            verifier_id: verifier_id.clone(),
            agent_id: agent_id.clone(),
            agent_pub_key: agent_pub.clone(),
            delegations: vec![cert],
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
    let bundle_wire = encode_proof_bundle_v2(&bundle)?;
    println!(
        "proof: agent signed the presentation ({} delegation)",
        bundle.delegations.len()
    );

    // 7. Verify. The verifier loads the issuance record for the presented
    // challenge, then runs the full v2 decision path.
    let verify = || -> Result<V2VerifyOutcome, Box<dyn Error>> {
        let expected = load_expected_challenge_v2(
            &ctx,
            issuance.as_ref(),
            NAMESPACE,
            EPOCH,
            &bundle.challenge,
        )?;
        let policy = V2ContextPolicy::new("example.quickstart/v1", false, &[], &[])?;
        let req = V2VerifyRequest {
            bundle: bundle_wire.clone(),
            expected: Some(expected),
            context_policy: Some(policy),
            required_scope: "payments:send".into(),
            verifier_namespace: NAMESPACE.into(),
            replay_epoch: EPOCH,
            now: store.now(),
            max_challenge_age_seconds: 300,
            future_skew_seconds: 5,
            context: ConstraintContextV2 {
                has_amount: true,
                requested_amount_micros: 12_500_000,
                requested_currency: "USD".into(),
                ..Default::default()
            },
            tzdb_version: TZDB_VERSION_V2.into(),
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
            constraint_evaluators: None,
        };
        let (trusted_id, trusted_key) = (root_id.clone(), root_pub.clone());
        let evidence = status_wire.clone();
        let cb = V2VerifyCallbacks {
            claim_store: Some(store.clone()),
            // Trust is pinned to the complete root public key, never a key ID.
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
        };
        Ok(verify_proof_bundle_v2(&ctx, &req, &cb))
    };
    let outcome = verify()?;
    let committed = match (outcome.stage, outcome.committed) {
        (V2VerifyStage::Committed, Some(c)) => c,
        (stage, _) => {
            return Err(format!("verify stopped at {}: {:?}", stage.as_str(), outcome.error).into())
        }
    };
    println!("verify: stage=committed (not actionable until released)");

    // 8. Publish the signed receipt to the log; the checkpoint acknowledges it.
    let receipt_wire =
        store.publish_v2_receipt(&ctx, &committed.claim_id(), &committed.receipt_body())?;
    let receipt = decode_verification_receipt_v2(&receipt_wire)?;
    println!("receipt: published at log sequence {}", receipt.sequence);
    let ack = store.get_v2_acknowledgement(&ctx, LOG_ID, receipt.sequence)?;
    println!("checkpoint: acknowledged sequence {}", ack.sequence);

    // 9. Release. Only a released decision is actionable.
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
    let status = result.status;
    let reason = result.reason.clone();
    let decision = result
        .into_decision()
        .ok_or_else(|| format!("release {}: {}", status.as_str(), reason))?;
    println!(
        "release: status={} decision={} reason={}",
        status.as_str(),
        decision.decision(),
        decision.reason()
    );
    println!("granted scope: {}", decision.granted_scope().join(","));

    // 10. Gate the side effect on allowed at the receiver's authoritative time.
    println!("allowed now: {}", decision.allowed(&ctx, store.as_ref()));

    // 11. Presenting the same proof again is a replay and is never evaluated.
    store.set_time(START + 3);
    let replay = verify()?;
    println!(
        "replay: stage={} disposition={}",
        replay.stage.as_str(),
        replay.disposition.map(|d| d.as_str()).unwrap_or("")
    );

    // 12. The released allow ends at the challenge expiry (an exclusive deadline).
    store.set_time(challenge.expires_at);
    println!(
        "allowed at challenge expiry: {}",
        decision.allowed(&ctx, store.as_ref())
    );
    Ok(())
}
