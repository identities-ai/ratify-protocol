//! An emulated external signing provider for tests. The SDK exports no local
//! raw signer, so tests that need a `SignerV2` sign the SDK-prepared request
//! here, outside the SDK, the way an HSM or KMS would. The SDK verifies every
//! signature it returns.

use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _};
use ratify_protocol::v2::{
    public_key_v2, SignRequestV2, SignerModeV2, SignerV2, V2Context, V2SignError, V2SignResult,
};
use ratify_protocol::{HybridPrivateKey, HybridPublicKey, HybridSignature};

/// A direct-mode provider holding one hybrid key.
pub struct ProviderSigner {
    private: HybridPrivateKey,
    public: HybridPublicKey,
}

impl ProviderSigner {
    pub fn new(private: &HybridPrivateKey) -> Self {
        let public = public_key_v2(private).expect("provider key");
        ProviderSigner {
            private: private.clone(),
            public,
        }
    }
}

impl SignerV2 for ProviderSigner {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.public.clone()
    }

    fn mode_v2(&self) -> SignerModeV2 {
        SignerModeV2::Direct
    }

    fn sign_v2(&self, ctx: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature> {
        if ctx.is_done() {
            return Err(V2SignError::Cancelled);
        }
        if request.public_key != self.public {
            return Err(V2SignError::Provider("request names another key".into()));
        }
        let context = request
            .ml_dsa_context
            .as_deref()
            .ok_or_else(|| V2SignError::Provider("direct mode requires a context".into()))?;
        let seed: [u8; 32] = self.private.ed25519()[..32].try_into().expect("seed");
        let ed = SigningKey::from_bytes(&seed).sign(&request.message);
        let sk: [u8; ml_dsa_65::SK_LEN] = self.private.ml_dsa_65().try_into().expect("sk");
        let ml = ml_dsa_65::PrivateKey::try_from_bytes(sk)
            .and_then(|k| k.try_sign(&request.message, context))
            .map_err(|e| V2SignError::Provider(e.to_string()))?;
        Ok(HybridSignature {
            ed25519: ed.to_bytes().to_vec(),
            ml_dsa_65: ml.to_vec(),
        })
    }
}
