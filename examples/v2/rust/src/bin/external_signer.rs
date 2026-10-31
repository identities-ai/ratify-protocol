//! Ratify Protocol v2 external signer: a signing provider holds the private
//! key; the SDK prepares each typed statement and verifies every returned
//! signature before using it.
//!
//! The provider here is an in-process stand-in for a remote signing service.
//! The interface makes no claim about any particular KMS or HSM.
//!
//! Run from examples/v2/rust: cargo run --bin external_signer

use std::error::Error;
use std::sync::Mutex;

use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _};
use rand_core::OsRng;
use ratify_protocol::v2::*;
use ratify_protocol::{generate_hybrid_keypair, HybridPublicKey, HybridSignature};

const START: i64 = 1_800_000_000;

/// A signing service. Its private key never leaves it. It signs in direct
/// mode: Ed25519 over the 77-byte message M and ML-DSA-65 over M with the
/// SDK-chosen context string.
struct Provider {
    name: String,
    public: HybridPublicKey,
    ed: SigningKey,
    ml: Mutex<ml_dsa_65::PrivateKey>,
    log: Mutex<Vec<String>>,
}

impl Provider {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let ed = SigningKey::generate(&mut OsRng);
        let (ml_pub, ml_priv) = ml_dsa_65::try_keygen()?;
        Ok(Provider {
            name: name.into(),
            public: HybridPublicKey {
                ed25519: ed.verifying_key().to_bytes().to_vec(),
                ml_dsa_65: ml_pub.into_bytes().to_vec(),
            },
            ed,
            ml: Mutex::new(ml_priv),
            log: Mutex::new(Vec::new()),
        })
    }

    fn first_log(&self) -> String {
        self.log
            .lock()
            .expect("log")
            .first()
            .cloned()
            .unwrap_or_default()
    }
}

impl SignerV2 for Provider {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.public.clone()
    }

    fn mode_v2(&self) -> SignerModeV2 {
        SignerModeV2::Direct
    }

    fn sign_v2(&self, _ctx: &V2Context, req: &SignRequestV2) -> V2SignResult<HybridSignature> {
        // A provider refuses any request for a key it does not hold.
        if req.public_key != self.public {
            return Err(V2SignError::Provider(format!(
                "{}: request names a key this provider does not hold",
                self.name
            )));
        }
        let context = req
            .ml_dsa_context
            .clone()
            .ok_or_else(|| V2SignError::Provider("direct mode requires a context".into()))?;
        self.log.lock().expect("log").push(format!(
            "{} signed: mode=direct message={} bytes context={}",
            self.name,
            req.message.len(),
            String::from_utf8_lossy(&context)
        ));
        let ml = self
            .ml
            .lock()
            .expect("key")
            .try_sign(&req.message, &context)
            .map_err(|e| V2SignError::Provider(e.to_string()))?;
        Ok(HybridSignature {
            ed25519: self.ed.sign(&req.message).to_bytes().to_vec(),
            ml_dsa_65: ml.to_vec(),
        })
    }
}

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
    println!("Ratify Protocol v2 external signer");

    let issuer = Provider::new("issuer provider")?;
    let agent = Provider::new("agent provider")?;
    let (verifier_pub, _) = generate_hybrid_keypair();
    let issuer_id = key_id_v2(&issuer.public)?;
    let agent_id = key_id_v2(&agent.public)?;
    let verifier_id = key_id_v2(&verifier_pub)?;

    let cert = sign_delegation_cert_v2_with_signer(
        &ctx,
        &DelegationCertV2 {
            version: 2,
            cert_id: "external-signer-cert-1".into(),
            issuer_id,
            issuer_pub_key: issuer.public.clone(),
            subject_id: agent_id.clone(),
            subject_pub_key: agent.public.clone(),
            scope: vec!["files:read".into()],
            constraints: Vec::new(),
            issued_at: START,
            expires_at: START + 86400,
            signature: unsigned(),
        },
        &issuer,
    )?;
    println!("{}", issuer.first_log());
    println!(
        "delegation: signature verified by the SDK ({})",
        verify_delegation_cert_v2_signature(&cert).is_ok()
    );

    let unsigned_bundle = ProofBundleV2 {
        version: 2,
        verifier_id,
        agent_id,
        agent_pub_key: agent.public.clone(),
        delegations: vec![cert],
        delegation_digest: Vec::new(),
        challenge: vec![0x42; 32],
        challenge_at: START,
        challenge_sig: unsigned(),
        session_context: None,
        stream_id: None,
        stream_seq: None,
    };
    let bundle = sign_proof_bundle_v2_with_signer(&ctx, &unsigned_bundle, &agent)?;
    println!("{}", agent.first_log());
    println!(
        "proof bundle: signatures verified by the SDK ({})",
        verify_proof_bundle_v2_signatures(&bundle).is_ok()
    );

    // A faulty provider returns an ML-DSA-65 signature from a different key.
    // The SDK verifies before use, so nothing is signed.
    let (_, wrong) = ml_dsa_65::try_keygen()?;
    *agent.ml.lock().expect("key") = wrong;
    let refused = sign_proof_bundle_v2_with_signer(&ctx, &unsigned_bundle, &agent);
    println!(
        "faulty provider: refused ({})",
        refused.err().map(|e| e.class().as_str()).unwrap_or("none")
    );
    Ok(())
}
