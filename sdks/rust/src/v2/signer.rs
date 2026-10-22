//! Typed signers and the external signer interface (SPEC-v2 §3.2, Go
//! `signer_v2.go`).
//!
//! The SDK computes `M`, the ML-DSA-65 context, and (for external-μ
//! providers) `mu`; a provider never receives an object, a type code, or a
//! caller-selected message. Every returned signature is verified under the
//! bound key before use. No function in this crate signs caller-selected
//! bytes, codes, or contexts.

use std::fmt;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use super::context::V2Context;
use super::crypto::{
    ed_seed, key_id_v2, ml_secret, sign_v2_message, v2_mldsa_context, v2_signing_message,
    verify_v2_statement, V2ObjectType,
};
use super::errors::{V2SignError, V2SignResult};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature};

/// Length of `M`: `"ratify-protocol-signature" || 0x00 || 0x02 || u16 || SHA-384`.
pub const V2_SIGNING_MESSAGE_SIZE: usize = 77;

/// Which ML-DSA-65 input an external signer receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerModeV2 {
    /// The provider signs `message` with ML-DSA-65 under `ml_dsa_context`
    /// (FIPS 204 pure mode with a context string).
    Direct,
    /// The provider signs the 64-byte `ml_dsa_mu` the SDK derived as
    /// `SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)` with
    /// `tr = SHAKE256(ml_dsa_65_public_key, 64)`.
    ExternalMu,
}

/// Everything an external signer receives for one typed v2 statement. The
/// SDK computes every field. Ed25519 always signs `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequestV2 {
    pub mode: SignerModeV2,
    /// The 77-byte `M`.
    pub message: Vec<u8>,
    /// The 22-byte FIPS 204 context in direct mode; `None` in external-μ mode.
    pub ml_dsa_context: Option<Vec<u8>>,
    /// The 64-byte external μ in external-μ mode; `None` in direct mode.
    pub ml_dsa_mu: Option<Vec<u8>>,
    /// The complete hybrid public key the provider must sign under, and its
    /// v2 key ID. A provider holding any other key must refuse.
    pub public_key: HybridPublicKey,
    pub key_id: String,
}

/// An external signing provider. The SDK never trusts its output: every
/// returned hybrid signature is verified against [`SignerV2::public_key_v2`]
/// before use. ML-DSA-65 signing may be hedged, so retries may return
/// different valid bytes; idempotency compares statement body digests.
pub trait SignerV2: Send + Sync {
    /// The complete hybrid public key the provider signs under. It must be
    /// stable for the lifetime of the signer.
    fn public_key_v2(&self) -> HybridPublicKey;
    /// The ML-DSA-65 input mode the provider implements.
    fn mode_v2(&self) -> SignerModeV2;
    /// Sign one SDK-prepared request. Return [`V2SignError::Provider`] or
    /// [`V2SignError::Cancelled`] on failure.
    fn sign_v2(&self, ctx: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature>;
}

/// A direct-mode [`SignerV2`] backed by an in-process hybrid private key.
/// ML-DSA-65 signatures are hedged. The Ed25519 component may be the 32-byte
/// seed or the 64-byte seed-and-public form whose public half matches.
#[derive(Clone)]
pub struct LocalSignerV2 {
    private_key: HybridPrivateKey,
    public_key: HybridPublicKey,
}

impl LocalSignerV2 {
    /// Validate the private key and derive its complete public key.
    pub fn new(private_key: &HybridPrivateKey) -> V2SignResult<Self> {
        let public_key = super::crypto::public_key_v2(private_key)
            .map_err(|e| V2SignError::InvalidSignerKey(e.message))?;
        Ok(LocalSignerV2 {
            private_key: private_key.clone(),
            public_key,
        })
    }
}

impl fmt::Debug for LocalSignerV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSignerV2")
            .field("key_id", &key_id_v2(&self.public_key).ok())
            .finish_non_exhaustive()
    }
}

impl SignerV2 for LocalSignerV2 {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.public_key.clone()
    }

    fn mode_v2(&self) -> SignerModeV2 {
        SignerModeV2::Direct
    }

    fn sign_v2(&self, ctx: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature> {
        if ctx.is_done() {
            return Err(V2SignError::Cancelled);
        }
        let context = match (&request.mode, &request.ml_dsa_context) {
            (SignerModeV2::Direct, Some(c)) if !c.is_empty() => c,
            _ => {
                return Err(V2SignError::Provider(
                    "local v2 signer supports only direct-mode requests".into(),
                ))
            }
        };
        if request.message.len() != V2_SIGNING_MESSAGE_SIZE {
            return Err(V2SignError::Provider(
                "local v2 signer supports only direct-mode requests".into(),
            ));
        }
        let seed = ed_seed(&self.private_key).map_err(|e| V2SignError::InvalidSignerKey(e.message))?;
        let ml = ml_secret(&self.private_key).map_err(|e| V2SignError::InvalidSignerKey(e.message))?;
        sign_v2_message(&seed, &ml, &request.message, context, true)
            .map_err(|e| V2SignError::Provider(e.message))
    }
}

/// FIPS 204 external μ for a v2 statement:
/// `SHAKE256(SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx || M, 64)`.
pub fn external_mu_v2(ml_dsa_public_key: &[u8], ml_dsa_context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut tr = [0u8; 64];
    let mut h = Shake256::default();
    h.update(ml_dsa_public_key);
    h.finalize_xof().read(&mut tr);
    let mut h = Shake256::default();
    h.update(&tr);
    // Contexts are fixed 22-byte registry strings; the cast cannot truncate.
    h.update(&[0u8, ml_dsa_context.len() as u8]);
    h.update(ml_dsa_context);
    h.update(message);
    let mut mu = vec![0u8; 64];
    h.finalize_xof().read(&mut mu);
    mu
}

/// The complete public key a signer signs under, with exact component
/// lengths (Go `signerPublicKeyV2`).
pub(crate) fn signer_public_key_v2(signer: &dyn SignerV2) -> V2SignResult<HybridPublicKey> {
    let public_key = signer.public_key_v2();
    key_id_v2(&public_key)
        .map_err(|e| V2SignError::InvalidSignerKey(format!("v2 signer public key: {}", e.message)))?;
    Ok(public_key)
}

/// Prepare the typed request, call the signer, and verify the returned
/// signature under `public_key` before returning it (Go
/// `signV2StatementWithSigner`).
pub(crate) fn sign_v2_statement_with_signer(
    ctx: &V2Context,
    object_type: V2ObjectType,
    signable: &[u8],
    signer: &dyn SignerV2,
    public_key: &HybridPublicKey,
) -> V2SignResult<HybridSignature> {
    if ctx.is_done() {
        return Err(V2SignError::Cancelled);
    }
    let message = v2_signing_message(object_type, signable);
    let context = v2_mldsa_context(object_type);
    let key_id = key_id_v2(public_key).map_err(|e| V2SignError::InvalidSignerKey(e.message))?;
    let mode = signer.mode_v2();
    let mut request = SignRequestV2 {
        mode,
        message,
        ml_dsa_context: None,
        ml_dsa_mu: None,
        public_key: public_key.clone(),
        key_id,
    };
    match mode {
        SignerModeV2::Direct => request.ml_dsa_context = Some(context),
        SignerModeV2::ExternalMu => {
            request.ml_dsa_mu = Some(external_mu_v2(&public_key.ml_dsa_65, &context, &request.message))
        }
    }
    let signature = match signer.sign_v2(ctx, &request) {
        Ok(signature) => signature,
        Err(V2SignError::Cancelled) => return Err(V2SignError::Cancelled),
        Err(V2SignError::Provider(m)) => return Err(V2SignError::Provider(m)),
        Err(other) => return Err(V2SignError::Provider(other.to_string())),
    };
    if ctx.is_done() {
        return Err(V2SignError::Cancelled);
    }
    verify_v2_statement(object_type, signable, &signature, public_key)
        .map_err(V2SignError::SignatureRejected)?;
    Ok(signature)
}

/// Sign under a local private key through the same path as an external
/// signer, including verification of the produced signature.
pub(crate) fn sign_v2_statement_local(
    object_type: V2ObjectType,
    signable: &[u8],
    private_key: &HybridPrivateKey,
) -> V2SignResult<HybridSignature> {
    let signer = LocalSignerV2::new(private_key)?;
    let public_key = signer.public_key.clone();
    sign_v2_statement_with_signer(
        &V2Context::background(),
        object_type,
        signable,
        &signer,
        &public_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid_keypair_from_seeds;

    struct Emulated {
        private_key: HybridPrivateKey,
        public_key: HybridPublicKey,
        mode: SignerModeV2,
        mu_context: Vec<u8>,
        tamper: bool,
    }

    impl SignerV2 for Emulated {
        fn public_key_v2(&self) -> HybridPublicKey {
            self.public_key.clone()
        }
        fn mode_v2(&self) -> SignerModeV2 {
            self.mode
        }
        fn sign_v2(&self, _: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature> {
            // fips204 has no external-μ entry point; like the Go tests, the
            // emulated provider signs M under the registry context it was
            // configured with and the SDK verifies the result.
            let context = match self.mode {
                SignerModeV2::Direct => request.ml_dsa_context.clone().unwrap_or_default(),
                SignerModeV2::ExternalMu => self.mu_context.clone(),
            };
            let seed = ed_seed(&self.private_key).map_err(|e| V2SignError::Provider(e.message))?;
            let ml = ml_secret(&self.private_key).map_err(|e| V2SignError::Provider(e.message))?;
            let mut signature = sign_v2_message(&seed, &ml, &request.message, &context, true)
                .map_err(|e| V2SignError::Provider(e.message))?;
            if self.tamper {
                signature.ml_dsa_65[0] ^= 1;
            }
            Ok(signature)
        }
    }

    fn keys() -> (HybridPrivateKey, HybridPublicKey) {
        let (public_key, private_key) = hybrid_keypair_from_seeds(&[7u8; 32], &[9u8; 32]);
        (private_key, public_key)
    }

    #[test]
    fn external_mu_request_carries_only_mu() {
        let (private_key, public_key) = keys();
        let signer = Emulated {
            private_key,
            public_key: public_key.clone(),
            mode: SignerModeV2::ExternalMu,
            mu_context: b"ratify-protocol/2/0001".to_vec(),
            tamper: false,
        };
        let signature = sign_v2_statement_with_signer(
            &V2Context::background(),
            V2ObjectType::DelegationCertificate,
            b"{}",
            &signer,
            &public_key,
        )
        .expect("sign");
        verify_v2_statement(V2ObjectType::DelegationCertificate, b"{}", &signature, &public_key)
            .expect("verify");
    }

    #[test]
    fn wrong_context_or_tampered_signature_is_rejected() {
        let (private_key, public_key) = keys();
        for (mu_context, tamper) in [(b"ratify-protocol/2/0002".to_vec(), false), (b"ratify-protocol/2/0001".to_vec(), true)] {
            let signer = Emulated {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                mode: SignerModeV2::ExternalMu,
                mu_context,
                tamper,
            };
            let result = sign_v2_statement_with_signer(
                &V2Context::background(),
                V2ObjectType::DelegationCertificate,
                b"{}",
                &signer,
                &public_key,
            );
            assert!(matches!(result, Err(V2SignError::SignatureRejected(_))), "{result:?}");
        }
    }

    #[test]
    fn cancelled_context_never_calls_the_signer() {
        let (private_key, public_key) = keys();
        let signer = LocalSignerV2::new(&private_key).expect("signer");
        let (ctx, cancel) = V2Context::background().with_cancel();
        cancel.cancel();
        let result = sign_v2_statement_with_signer(
            &ctx,
            V2ObjectType::DelegationCertificate,
            b"{}",
            &signer,
            &public_key,
        );
        assert_eq!(result, Err(V2SignError::Cancelled));
    }

    #[test]
    fn local_signer_accepts_seed_and_seed_public_forms() {
        let (private_key, public_key) = keys();
        let mut long = private_key.clone();
        long.ed25519.extend_from_slice(&public_key.ed25519);
        assert_eq!(LocalSignerV2::new(&long).expect("64-byte").public_key_v2(), public_key);
        let mut bad = long.clone();
        bad.ed25519[40] ^= 1;
        assert!(LocalSignerV2::new(&bad).is_err());
        let mut short = private_key;
        short.ed25519.truncate(31);
        assert!(LocalSignerV2::new(&short).is_err());
    }
}
