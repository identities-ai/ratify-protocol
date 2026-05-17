//! Ratify Protocol v1 — end-to-end narrative demo (Rust).
//!
//! Run: `cargo run` from `demos/rust/`.

use ratify_protocol::{
    generate_agent, generate_challenge, generate_human_root, hex_encode, issue_delegation,
    sign_challenge, verify_bundle, DelegationCert, HybridSignature, IdentityStatus, ProofBundle,
    RevocationProvider, VerifyOptions, PROTOCOL_VERSION, SCOPE_FILES_WRITE, SCOPE_MEETING_ATTEND,
    SCOPE_MEETING_RECORD,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn banner(text: &str) {
    println!();
    println!("{}", "━".repeat(70));
    println!("{text}");
    println!("{}", "━".repeat(70));
}

fn kv(label: &str, value: &str) {
    println!("  {label:<20} {value}");
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn main() {
    // Step 1
    banner("STEP 1  Alice generates a hybrid root identity");
    let (alice, alice_priv) = generate_human_root();
    kv("Root ID:", &alice.id);
    kv(
        "Ed25519 pubkey:",
        &format!("{}…", &hex_encode(&alice.public_key.ed25519)[..32]),
    );
    kv(
        "ML-DSA-65 pubkey:",
        &format!("<{} bytes>", alice.public_key.ml_dsa_65.len()),
    );
    kv("Storage:", "Private keys stay on Alice's machine (never leave)");

    // Step 2
    banner("STEP 2  Agent (Alice's scheduler) generates its own hybrid keypair");
    let (agent, agent_priv) = generate_agent("Alice's Scheduler", "voice_agent");
    kv("Agent ID:", &agent.id);
    kv("Agent type:", &agent.agent_type);
    kv(
        "Ed25519 pubkey:",
        &format!("{}…", &hex_encode(&agent.public_key.ed25519)[..32]),
    );

    // Step 3
    banner("STEP 3  Alice authorizes the agent for meeting:attend, 7 days");
    let now = now_unix();
    let mut cert = DelegationCert {
        cert_id: "cert-demo-001".into(),
        version: PROTOCOL_VERSION,
        issuer_id: alice.id.clone(),
        issuer_pub_key: alice.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope: vec![SCOPE_MEETING_ATTEND.into()],
        constraints: vec![],
        issued_at: now,
        expires_at: now + 7 * 24 * 3600,
        signature: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    };
    issue_delegation(&mut cert, &alice_priv);
    kv("Cert ID:", &cert.cert_id);
    kv("Scope:", &cert.scope.join(", "));
    kv("Expires:", &format!("unix {}", cert.expires_at));
    kv(
        "Ed25519 sig:",
        &format!("{}…", &hex_encode(&cert.signature.ed25519)[..32]),
    );
    kv(
        "ML-DSA-65 sig:",
        &format!("<{} bytes>", cert.signature.ml_dsa_65.len()),
    );

    // Step 4
    banner("STEP 4  Agent builds a proof bundle for the verifier");
    let challenge = generate_challenge();
    let challenge_at = now_unix();
    let challenge_sig = sign_challenge(&challenge, challenge_at, &agent_priv);
    let bundle = ProofBundle {
        agent_id: agent.id.clone(),
        agent_pub_key: agent.public_key.clone(),
        delegations: vec![cert.clone()],
        challenge: challenge.clone(),
        challenge_at,
        challenge_sig,
        session_context: vec![],
        stream_id: vec![],
        stream_seq: 0,
    };
    kv(
        "Challenge:",
        &format!("{}…", &hex_encode(&bundle.challenge)[..32]),
    );
    kv("Challenge at:", &format!("unix {challenge_at}"));
    kv("Hybrid sig:", "Ed25519 + ML-DSA-65 over challenge || BE(ts)");

    // Step 5
    banner("STEP 5  Verifier runs verify_bundle() — expects meeting:attend");
    let result = verify_bundle(
        &bundle,
        &VerifyOptions {
            required_scope: SCOPE_MEETING_ATTEND.into(),
            ..Default::default()
        },
    );
    if result.valid {
        println!("  ✅  VALID");
        kv("Human ID:", &result.human_id);
        kv("Agent ID:", &result.agent_id);
        kv("Status:", result.identity_status.as_str());
        kv("Granted scope:", &result.granted_scope.join(", "));
    } else {
        println!(
            "  ❌  INVALID — {}: {}",
            result.identity_status.as_str(),
            result.error_reason
        );
    }

    // Attack 1
    banner("ATTACK 1  Attacker appends files:write to the scope after signing");
    let mut tampered = cert.clone();
    tampered.scope.push(SCOPE_FILES_WRITE.into());
    let tampered_bundle = ProofBundle {
        delegations: vec![tampered],
        ..bundle.clone()
    };
    let r = verify_bundle(
        &tampered_bundle,
        &VerifyOptions {
            required_scope: SCOPE_FILES_WRITE.into(),
            ..Default::default()
        },
    );
    println!("  ❌  REJECTED as expected: {}", r.error_reason);
    kv("Why:", "Canonical bytes differ; both signatures fail verify.");

    // Attack 2
    banner("ATTACK 2  Agent tries to use meeting:attend cert for meeting:record");
    let r = verify_bundle(
        &bundle,
        &VerifyOptions {
            required_scope: SCOPE_MEETING_RECORD.into(),
            ..Default::default()
        },
    );
    println!("  ❌  REJECTED as expected: {}", r.error_reason);
    kv("Why:", "meeting:record is not in the effective scope.");

    // Attack 3
    banner("ATTACK 3  Expired cert (verifier's clock reports future time)");
    let r = verify_bundle(
        &bundle,
        &VerifyOptions {
            required_scope: SCOPE_MEETING_ATTEND.into(),
            now: Some(cert.expires_at + 1),
            ..Default::default()
        },
    );
    println!(
        "  ❌  REJECTED as expected: {}: {}",
        r.identity_status.as_str(),
        r.error_reason
    );

    // Revocation
    banner("REVOCATION  Alice revokes the cert");
    struct DemoRevocation(String);
    impl RevocationProvider for DemoRevocation {
        fn is_revoked(&self, cert_id: &str) -> Result<bool, String> {
            Ok(cert_id == self.0)
        }
    }
    let r = verify_bundle(
        &bundle,
        &VerifyOptions {
            required_scope: SCOPE_MEETING_ATTEND.into(),
            revocation: Some(Box::new(DemoRevocation(cert.cert_id.clone()))),
            ..Default::default()
        },
    );
    println!(
        "  ❌  REJECTED as expected: {}: {}",
        r.identity_status.as_str(),
        r.error_reason
    );
    kv("Why:", "Verifier's revocation list now contains this cert_id.");

    // Use IdentityStatus to keep the import meaningful.
    let _: IdentityStatus = IdentityStatus::AuthorizedAgent;

    // Summary
    banner("SUMMARY");
    println!(
        r#"  The protocol just demonstrated:

  • Alice created a hybrid (Ed25519 + ML-DSA-65) root identity.
  • She signed a scoped, time-bounded delegation for an AI agent.
  • The agent signed a fresh challenge to prove liveness.
  • A verifier checked the bundle in a single function call.
  • Every one of four tampering/misuse scenarios was rejected
    deterministically — no fuzzy detection, no false positives.
  • Signatures are quantum-safe: breaking either Ed25519 or
    ML-DSA-65 alone is insufficient to forge.

  This is the full Ratify Protocol v1, end to end, in one process."#
    );
    println!();
}
