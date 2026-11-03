//! Android split custody (build plan §4.2): an Ed25519 key in Android
//! Keystore, which signs through a foreign callback, and an ML-DSA-65 key
//! from a software seed held only in the key's sealed storage record. The
//! composite signs only SDK-computed requests in direct mode and is never
//! exposed as a public signer; the core verifies both components.

use std::sync::Arc;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _};
use ratify_protocol::v2::{key_id_v2, V2ErrorClass};
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPrivateKey, HybridPublicKey};
use zeroize::Zeroizing;

use crate::error::{protocol, FfiResult};
use crate::guard::{call, call_on, Poison};
use crate::keys::FfiPublicKey;
use crate::objects::FfiSignature;
use crate::sign::{FfiSignContext, FfiSignRequest, FfiSigner, FfiSignerError, FfiSignerMode};
use crate::storage::{
    self, TAG_ED25519_PUBLIC, TAG_KEYSTORE_ALIAS, TAG_MLDSA65_SEED, TYPE_ANDROID_SPLIT,
};

/// The Keystore Ed25519 half: signs the SDK's 77-byte message.
#[uniffi::export(with_foreign)]
pub trait FfiEd25519Signer: Send + Sync {
    fn sign(
        &self,
        message: Vec<u8>,
        context: Arc<FfiSignContext>,
    ) -> Result<Vec<u8>, FfiSignerError>;
}

/// A split-custody key: its Ed25519 public key (Keystore) and ML-DSA-65 seed.
#[derive(uniffi::Object)]
pub struct FfiSplitKey {
    poison: Poison,
    ml_seed: Zeroizing<[u8; 32]>,
    ml_private: HybridPrivateKey,
    public: HybridPublicKey,
    key_id: String,
}

impl FfiSplitKey {
    fn build(ml_seed: &[u8], ed25519_public: Vec<u8>) -> FfiResult<Arc<Self>> {
        let mut seed = Zeroizing::new([0u8; 32]);
        if ml_seed.len() != 32 || ed25519_public.len() != 32 {
            return Err(protocol(
                V2ErrorClass::Malformed,
                "split key needs a 32-byte ML-DSA-65 seed and Ed25519 public key",
            ));
        }
        seed.copy_from_slice(ml_seed);
        // The Ed25519 seed is unused: only the ML-DSA-65 half is derived here.
        let (derived, ml_private) = hybrid_keypair_from_seeds(&[0; 32], &seed);
        let public = HybridPublicKey {
            ed25519: ed25519_public,
            ml_dsa_65: derived.ml_dsa_65,
        };
        let key_id = key_id_v2(&public)?;
        Ok(Arc::new(FfiSplitKey {
            poison: Poison::default(),
            ml_seed: seed,
            ml_private,
            public,
            key_id,
        }))
    }
}

#[uniffi::export]
impl FfiSplitKey {
    /// A key from a fresh (or stored) ML-DSA-65 seed and the Keystore Ed25519 public key.
    #[uniffi::constructor]
    pub fn new(ml_dsa_65_seed: Vec<u8>, ed25519_public: Vec<u8>) -> FfiResult<Arc<Self>> {
        call(move || {
            let seed = Zeroizing::new(ml_dsa_65_seed);
            Self::build(&seed, ed25519_public)
        })
    }

    /// A key from its type 0x03 storage record, checked against the recorded key ID.
    #[uniffi::constructor]
    pub fn from_storage_record(data: Vec<u8>) -> FfiResult<Arc<Self>> {
        call(move || {
            let data = Zeroizing::new(data);
            let r = storage::parse(&data)?;
            if r.record_type != TYPE_ANDROID_SPLIT {
                return Err(protocol(
                    V2ErrorClass::Malformed,
                    "key storage record: not an Android split-custody key",
                ));
            }
            let get = |t: u8| {
                r.fields
                    .iter()
                    .find(|f| f.tag == t)
                    .map(|f| f.value.clone())
                    .unwrap_or_default()
            };
            let key = Self::build(
                &Zeroizing::new(get(TAG_MLDSA65_SEED)),
                get(TAG_ED25519_PUBLIC),
            )?;
            if key.key_id != r.key_id {
                return Err(protocol(
                    V2ErrorClass::KeyIdMismatch,
                    "key storage record: the stored keys derive another key ID",
                ));
            }
            Ok(key)
        })
    }

    pub fn public_key(&self) -> FfiResult<FfiPublicKey> {
        call_on(&self.poison, || Ok((&self.public).into()))
    }

    pub fn key_id(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.key_id.clone()))
    }

    /// This key's type 0x03 storage record, naming its Keystore alias.
    pub fn storage_record(&self, keystore_alias: String) -> FfiResult<Vec<u8>> {
        call_on(&self.poison, || {
            Ok(storage::encode(
                TYPE_ANDROID_SPLIT,
                &self.key_id,
                &[
                    (TAG_MLDSA65_SEED, &self.ml_seed[..]),
                    (TAG_ED25519_PUBLIC, &self.public.ed25519),
                    (TAG_KEYSTORE_ALIAS, keystore_alias.as_bytes()),
                ],
            )?
            .to_vec())
        })
    }

    /// The SDK-internal composite signer over this key and its Keystore half.
    pub fn signer(
        self: Arc<Self>,
        ed25519: Arc<dyn FfiEd25519Signer>,
    ) -> FfiResult<Arc<dyn FfiSigner>> {
        call_on(&self.poison, || {
            Ok(Arc::new(Composite {
                key: self.clone(),
                ed25519,
            }) as Arc<dyn FfiSigner>)
        })
    }
}

/// Keystore Ed25519 plus seed ML-DSA-65, direct mode.
struct Composite {
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
}

impl FfiSigner for Composite {
    fn public_key(&self) -> FfiPublicKey {
        (&self.key.public).into()
    }

    fn mode(&self) -> FfiSignerMode {
        FfiSignerMode::Direct
    }

    fn sign(
        &self,
        request: FfiSignRequest,
        context: Arc<FfiSignContext>,
    ) -> Result<FfiSignature, FfiSignerError> {
        let refused = |m: &str| FfiSignerError::Provider {
            detail: m.to_string(),
        };
        let ctx = request
            .ml_dsa_context
            .clone()
            .ok_or_else(|| refused("direct mode requires a context"))?;
        if HybridPublicKey::from(request.public_key.clone()) != self.key.public {
            return Err(refused("the request names another key"));
        }
        let ed25519 = self.ed25519.sign(request.message.clone(), context)?;
        let sk: [u8; ml_dsa_65::SK_LEN] = self
            .key
            .ml_private
            .ml_dsa_65()
            .try_into()
            .map_err(|_| refused("ML-DSA-65 key material is invalid"))?;
        let sk = Zeroizing::new(sk);
        let ml = ml_dsa_65::PrivateKey::try_from_bytes(*sk)
            .and_then(|k| k.try_sign(&request.message, &ctx))
            .map_err(|e| refused(&format!("ML-DSA-65 signing failed: {e}")))?;
        Ok(FfiSignature {
            ed25519,
            ml_dsa_65: ml.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::FfiCancelToken;
    use crate::objects::FfiDelegationCert;
    use crate::sign::ffi_sign_delegation_cert_with_signer;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// Stands in for the Keystore Ed25519 key.
    struct Ed(SigningKey);
    impl FfiEd25519Signer for Ed {
        fn sign(
            &self,
            message: Vec<u8>,
            _: Arc<FfiSignContext>,
        ) -> Result<Vec<u8>, FfiSignerError> {
            Ok(self.0.sign(&message).to_bytes().to_vec())
        }
    }

    fn fixture_cert() -> FfiDelegationCert {
        let objects: serde_json::Value =
            serde_json::from_str(include_str!("../../../testvectors/v2/objects.json")).unwrap();
        let o = objects["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["kind"] == "delegation_certificate")
            .unwrap();
        use base64::Engine as _;
        let wire = base64::engine::general_purpose::STANDARD
            .decode(o["wire_b64"].as_str().unwrap())
            .unwrap();
        crate::objects::ffi_decode_delegation_cert(wire).unwrap()
    }

    #[test]
    fn split_key_signs_verifiable_certificates_and_round_trips() {
        let ed = SigningKey::from_bytes(&[7; 32]);
        let key = FfiSplitKey::new(vec![9; 32], ed.verifying_key().to_bytes().to_vec()).unwrap();
        let mut cert = fixture_cert();
        cert.issuer_pub_key = key.public_key().unwrap();
        cert.issuer_id = key.key_id().unwrap();
        let signer = key.clone().signer(Arc::new(Ed(ed))).unwrap();
        let signed =
            ffi_sign_delegation_cert_with_signer(FfiCancelToken::new(None).unwrap(), cert, signer)
                .unwrap();
        crate::verify::ffi_verify_delegation_cert_signature(signed).unwrap();

        let rec = key.storage_record("ratify.v2.ed25519.x".into()).unwrap();
        let again = FfiSplitKey::from_storage_record(rec.clone()).unwrap();
        assert_eq!(again.key_id().unwrap(), key.key_id().unwrap());
        let mut bad = rec;
        bad[8 + 64 + 1 + 3] ^= 1; // the ML-DSA seed now derives another key
        assert!(
            matches!(FfiSplitKey::from_storage_record(bad), Err(crate::error::FfiError::Protocol { ref class, .. }) if class == "key_id_mismatch")
        );
    }

    #[test]
    fn split_key_refuses_a_request_for_another_key() {
        let ed = SigningKey::from_bytes(&[7; 32]);
        let key = FfiSplitKey::new(vec![9; 32], ed.verifying_key().to_bytes().to_vec()).unwrap();
        let cert = fixture_cert(); // issued by the fixture root, not this key
        let signer = key.signer(Arc::new(Ed(ed))).unwrap();
        let r =
            ffi_sign_delegation_cert_with_signer(FfiCancelToken::new(None).unwrap(), cert, signer);
        assert!(
            matches!(r, Err(crate::error::FfiError::Signing { .. })),
            "{r:?}"
        );
    }
}
