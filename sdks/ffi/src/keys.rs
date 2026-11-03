//! Hybrid key pairs and v2 key IDs (SPEC-v2 §2.3).

use std::sync::Arc;

use ratify_protocol::v2::{key_id_v2, valid_v2_id, V2ErrorClass};
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPrivateKey, HybridPublicKey};
use zeroize::Zeroizing;

use crate::error::{protocol, FfiError, FfiResult};
use crate::guard::{call, call_on, Poison};

/// A complete hybrid public key: Ed25519 (32 bytes) and ML-DSA-65 (1952).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiPublicKey {
    pub ed25519: Vec<u8>,
    pub ml_dsa_65: Vec<u8>,
}

impl From<&HybridPublicKey> for FfiPublicKey {
    fn from(k: &HybridPublicKey) -> Self {
        FfiPublicKey {
            ed25519: k.ed25519.clone(),
            ml_dsa_65: k.ml_dsa_65.clone(),
        }
    }
}

impl From<FfiPublicKey> for HybridPublicKey {
    fn from(k: FfiPublicKey) -> Self {
        HybridPublicKey {
            ed25519: k.ed25519,
            ml_dsa_65: k.ml_dsa_65,
        }
    }
}

/// A software-held hybrid private key, kept as its two 32-byte seeds (the
/// documented storage form) plus the derived key pair. Seeds are wiped on drop
/// and never cross the FFI boundary on their own: storage (next milestone)
/// exchanges the whole documented storage record as one buffer.
#[derive(uniffi::Object)]
pub struct FfiSoftwareKey {
    pub(crate) poison: Poison,
    pub(crate) ed_seed: Zeroizing<[u8; 32]>,
    pub(crate) ml_seed: Zeroizing<[u8; 32]>,
    pub(crate) private: HybridPrivateKey,
    pub(crate) public: HybridPublicKey,
    key_id: String,
}

fn seed32(b: &[u8], name: &str) -> FfiResult<Zeroizing<[u8; 32]>> {
    let mut s = Zeroizing::new([0u8; 32]);
    if b.len() != 32 {
        return Err(protocol(
            V2ErrorClass::Malformed,
            format!("{name} must be 32 bytes, got {}", b.len()),
        ));
    }
    s.copy_from_slice(b);
    Ok(s)
}

impl FfiSoftwareKey {
    pub(crate) fn key_id_str(&self) -> String {
        self.key_id.clone()
    }

    pub(crate) fn from_seed_slices(ed: &[u8], ml: &[u8]) -> FfiResult<Arc<Self>> {
        Self::build(seed32(ed, "ed25519 seed")?, seed32(ml, "ml-dsa-65 seed")?)
    }

    fn build(ed_seed: Zeroizing<[u8; 32]>, ml_seed: Zeroizing<[u8; 32]>) -> FfiResult<Arc<Self>> {
        let (public, private) = hybrid_keypair_from_seeds(&ed_seed, &ml_seed);
        let key_id = key_id_v2(&public)?;
        Ok(Arc::new(FfiSoftwareKey {
            poison: Poison::default(),
            ed_seed,
            ml_seed,
            private,
            public,
            key_id,
        }))
    }
}

#[uniffi::export]
impl FfiSoftwareKey {
    /// Derive the key from a 32-byte Ed25519 seed and a 32-byte ML-DSA-65
    /// FIPS 204 seed, the derivation every SDK and `keys.json` use.
    #[uniffi::constructor]
    pub fn from_seeds(ed25519_seed: Vec<u8>, ml_dsa_65_seed: Vec<u8>) -> FfiResult<Arc<Self>> {
        // The seeds are wrapped before the guard runs, so they are wiped on
        // every path, including a panic before the body starts.
        call({
            let (ed_in, ml_in) = (Zeroizing::new(ed25519_seed), Zeroizing::new(ml_dsa_65_seed));
            move || {
                let ed = seed32(&ed_in, "ed25519 seed")?;
                let ml = seed32(&ml_in, "ml-dsa-65 seed")?;
                Self::build(ed, ml)
            }
        })
    }

    /// Generate a fresh key from the operating-system random source.
    #[uniffi::constructor]
    pub fn generate() -> FfiResult<Arc<Self>> {
        call(|| {
            let mut ed = Zeroizing::new([0u8; 32]);
            let mut ml = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(ed.as_mut())
                .and_then(|_| getrandom::getrandom(ml.as_mut()))
                .map_err(|e| FfiError::Internal {
                    kind: "random_source".into(),
                    detail: format!("the operating-system random source failed: {e}"),
                })?;
            Self::build(ed, ml)
        })
    }

    pub fn public_key(&self) -> FfiResult<FfiPublicKey> {
        call_on(&self.poison, || Ok((&self.public).into()))
    }

    pub fn key_id(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.key_id.clone()))
    }
}

/// `key_id_v2` of a complete public key.
#[uniffi::export]
pub fn ffi_key_id(key: FfiPublicKey) -> FfiResult<String> {
    call(|| Ok(key_id_v2(&key.into())?))
}

/// Whether `id` is a well-formed v2 key ID (64 lowercase hex characters).
#[uniffi::export]
pub fn ffi_valid_id(id: String) -> FfiResult<bool> {
    call(|| Ok(valid_v2_id(&id)))
}
