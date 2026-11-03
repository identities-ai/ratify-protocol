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

use crate::context::FfiCancelToken;
use crate::error::{protocol, FfiResult};
use crate::guard::{call, call_on, Poison};
use crate::keys::FfiPublicKey;
use crate::keys::FfiSoftwareKey;
use crate::objects::*;
use crate::sign::{
    self as typed, FfiSignContext, FfiSignRequest, FfiSigner, FfiSignerError, FfiSignerMode,
};
use crate::storage::{
    self, TAG_ED25519_PUBLIC, TAG_KEYSTORE_ALIAS, TAG_MLDSA65_SEED, TYPE_ANDROID_SPLIT,
};
use crate::verify::FfiReceiptHead;

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
}

/// Keystore Ed25519 plus seed ML-DSA-65, direct mode. Built only inside the
/// typed signing functions below, around a request the core computed; it
/// never crosses the FFI, so no caller can hand it a message to sign.
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

impl Composite {
    fn new(
        key: &Arc<FfiSplitKey>,
        ed25519: Arc<dyn FfiEd25519Signer>,
    ) -> FfiResult<Arc<dyn FfiSigner>> {
        if key.poison.is_set() {
            return Err(crate::guard::poisoned());
        }
        Ok(Arc::new(Composite {
            key: key.clone(),
            ed25519,
        }))
    }
}

/// A software key's half of a mixed rotation (software and hardware keys):
/// signs the core-computed request with Ed25519 and ML-DSA-65 from the key's
/// seeds. Built only inside [`ffi_sign_key_rotation_statement_with_slots`];
/// it never crosses the FFI.
struct SoftwareHalf(Arc<FfiSoftwareKey>);

impl FfiSigner for SoftwareHalf {
    fn public_key(&self) -> FfiPublicKey {
        (&self.0.public).into()
    }
    fn mode(&self) -> FfiSignerMode {
        FfiSignerMode::Direct
    }
    fn sign(
        &self,
        request: FfiSignRequest,
        _: Arc<FfiSignContext>,
    ) -> Result<FfiSignature, FfiSignerError> {
        use ed25519_dalek::Signer as _;
        let refused = |m: &str| FfiSignerError::Provider {
            detail: m.to_string(),
        };
        let ctx = request
            .ml_dsa_context
            .clone()
            .ok_or_else(|| refused("direct mode requires a context"))?;
        if HybridPublicKey::from(request.public_key.clone()) != self.0.public {
            return Err(refused("the request names another key"));
        }
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&self.0.ed_seed)
            .sign(&request.message)
            .to_bytes()
            .to_vec();
        let sk: [u8; ml_dsa_65::SK_LEN] = self
            .0
            .private
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

/// One rotation signer: exactly one of a software key, an app signer, or a
/// split-custody key with its Keystore half.
fn slot(
    software: Option<Arc<FfiSoftwareKey>>,
    signer: Option<Arc<dyn FfiSigner>>,
    split: Option<Arc<FfiSplitKey>>,
    split_ed25519: Option<Arc<dyn FfiEd25519Signer>>,
    name: &str,
) -> FfiResult<Arc<dyn FfiSigner>> {
    match (software, signer, split, split_ed25519) {
        (Some(k), None, None, None) => {
            if k.poison.is_set() {
                return Err(crate::guard::poisoned());
            }
            Ok(Arc::new(SoftwareHalf(k)))
        }
        (None, Some(s), None, None) => Ok(s),
        (None, None, Some(k), Some(ed)) => Composite::signer(&k, ed),
        _ => Err(protocol(
            V2ErrorClass::ConfigurationInvalid,
            format!("the {name} rotation key must be exactly one of a software key, a signer, or a split-custody key"),
        )),
    }
}

/// Sign a key-rotation statement with any combination of key kinds for the
/// old (0x0004) and new (0x0009) halves, such as a software root moving
/// into hardware. The core computes both requests and verifies both results.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn ffi_sign_key_rotation_statement_with_slots(
    cancel: Arc<FfiCancelToken>,
    statement: FfiKeyRotationStatement,
    old_software: Option<Arc<FfiSoftwareKey>>,
    old_signer: Option<Arc<dyn FfiSigner>>,
    old_split: Option<Arc<FfiSplitKey>>,
    old_split_ed25519: Option<Arc<dyn FfiEd25519Signer>>,
    new_software: Option<Arc<FfiSoftwareKey>>,
    new_signer: Option<Arc<dyn FfiSigner>>,
    new_split: Option<Arc<FfiSplitKey>>,
    new_split_ed25519: Option<Arc<dyn FfiEd25519Signer>>,
) -> FfiResult<FfiKeyRotationStatement> {
    call(|| {
        let old = slot(
            old_software,
            old_signer,
            old_split,
            old_split_ed25519,
            "old",
        )?;
        let new = slot(
            new_software,
            new_signer,
            new_split,
            new_split_ed25519,
            "new",
        )?;
        typed::sign_key_rotation_statement(&cancel, statement, old, new)
    })
}

// ---- typed signing with a split-custody key (blocking; run on an SDK worker) --

#[uniffi::export]
pub fn ffi_sign_delegation_cert_with_split_key(
    cancel: Arc<FfiCancelToken>,
    cert: FfiDelegationCert,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiDelegationCert> {
    call(|| typed::sign_delegation_cert(&cancel, cert, Composite::signer(&key, ed25519)?))
}
#[uniffi::export]
pub fn ffi_sign_proof_bundle_with_split_key(
    cancel: Arc<FfiCancelToken>,
    bundle: FfiProofBundle,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiProofBundle> {
    call(|| typed::sign_proof_bundle(&cancel, bundle, Composite::signer(&key, ed25519)?))
}
#[uniffi::export]
pub fn ffi_sign_revocation_list_with_split_key(
    cancel: Arc<FfiCancelToken>,
    list: FfiRevocationList,
    bound_issuer_id: String,
    bound_status_key: FfiPublicKey,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiRevocationList> {
    call(|| {
        typed::sign_revocation_list(
            &cancel,
            list,
            bound_issuer_id,
            bound_status_key,
            Composite::signer(&key, ed25519)?,
        )
    })
}
#[uniffi::export]
pub fn ffi_sign_revocation_push_with_split_key(
    cancel: Arc<FfiCancelToken>,
    push: FfiRevocationPush,
    bound_issuer_id: String,
    bound_status_key: FfiPublicKey,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiRevocationPush> {
    call(|| {
        typed::sign_revocation_push(
            &cancel,
            push,
            bound_issuer_id,
            bound_status_key,
            Composite::signer(&key, ed25519)?,
        )
    })
}
#[uniffi::export]
pub fn ffi_sign_witness_entry_with_split_key(
    cancel: Arc<FfiCancelToken>,
    entry: FfiWitnessEntry,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiWitnessEntry> {
    call(|| typed::sign_witness_entry(&cancel, entry, Composite::signer(&key, ed25519)?))
}
#[uniffi::export]
pub fn ffi_sign_verification_receipt_with_split_key(
    cancel: Arc<FfiCancelToken>,
    receipt: FfiVerificationReceipt,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiVerificationReceipt> {
    call(|| typed::sign_verification_receipt(&cancel, receipt, Composite::signer(&key, ed25519)?))
}
#[uniffi::export]
pub fn ffi_sign_prepared_verification_receipt_with_split_key(
    cancel: Arc<FfiCancelToken>,
    data: Vec<u8>,
    head: FfiReceiptHead,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiVerificationReceipt> {
    call(|| {
        typed::sign_prepared_verification_receipt(
            &cancel,
            data,
            head,
            Composite::signer(&key, ed25519)?,
        )
    })
}
#[uniffi::export]
pub fn ffi_sign_transaction_receipt_party_with_split_key(
    cancel: Arc<FfiCancelToken>,
    receipt: FfiTransactionReceipt,
    party_id: String,
    key: Arc<FfiSplitKey>,
    ed25519: Arc<dyn FfiEd25519Signer>,
) -> FfiResult<FfiTransactionReceiptSignature> {
    call(|| {
        typed::sign_transaction_receipt_party(
            &cancel,
            receipt,
            party_id,
            Composite::signer(&key, ed25519)?,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::FfiCancelToken;
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
        let signed = ffi_sign_delegation_cert_with_split_key(
            FfiCancelToken::new(None).unwrap(),
            cert,
            key.clone(),
            Arc::new(Ed(ed)),
        )
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

    /// A software root rotates into a split-custody key, and back.
    #[test]
    fn mixed_rotation_signs_both_halves() {
        use crate::verify::ffi_verify_statement;
        let software = FfiSoftwareKey::from_seeds(vec![0x41; 32], vec![0xc1; 32]).unwrap();
        let ed = SigningKey::from_bytes(&[7; 32]);
        let split = FfiSplitKey::new(vec![9; 32], ed.verifying_key().to_bytes().to_vec()).unwrap();
        let stmt = |old: FfiPublicKey, new: FfiPublicKey| FfiKeyRotationStatement {
            version: 2,
            authority_id: "0123456789abcdef0123456789abcdef".into(),
            recovery_epoch: 1,
            role: "organization_root".into(),
            sequence: 1,
            previous_statement_hash: vec![0; 48],
            old_key_id: crate::keys::ffi_key_id(old.clone()).unwrap(),
            new_key_id: crate::keys::ffi_key_id(new.clone()).unwrap(),
            old_key: old,
            new_key: new,
            issued_at: 1_800_000_000,
            not_before: 1_800_000_000,
            old_signature: FfiSignature {
                ed25519: vec![],
                ml_dsa_65: vec![],
            },
            new_signature: FfiSignature {
                ed25519: vec![],
                ml_dsa_65: vec![],
            },
        };
        let check = |signed: FfiKeyRotationStatement, old: FfiPublicKey, new: FfiPublicKey| {
            let signable =
                crate::verify::ffi_key_rotation_statement_signable_bytes(signed.clone()).unwrap();
            ffi_verify_statement(0x0004, signable.clone(), signed.old_signature, old).unwrap();
            ffi_verify_statement(0x0009, signable, signed.new_signature, new).unwrap();
        };
        let (sp, xp) = (software.public_key().unwrap(), split.public_key().unwrap());
        let up = ffi_sign_key_rotation_statement_with_slots(
            FfiCancelToken::new(None).unwrap(),
            stmt(sp.clone(), xp.clone()),
            Some(software.clone()),
            None,
            None,
            None,
            None,
            None,
            Some(split.clone()),
            Some(Arc::new(Ed(ed.clone()))),
        )
        .unwrap();
        check(up, sp.clone(), xp.clone());
        let down = ffi_sign_key_rotation_statement_with_slots(
            FfiCancelToken::new(None).unwrap(),
            stmt(xp.clone(), sp.clone()),
            None,
            None,
            Some(split.clone()),
            Some(Arc::new(Ed(ed.clone()))),
            Some(software.clone()),
            None,
            None,
            None,
        )
        .unwrap();
        check(down, xp, sp);
        // A slot must name exactly one key.
        let empty = ffi_sign_key_rotation_statement_with_slots(
            FfiCancelToken::new(None).unwrap(),
            stmt(software.public_key().unwrap(), split.public_key().unwrap()),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(split.clone()),
            Some(Arc::new(Ed(ed.clone()))),
        );
        assert!(
            matches!(empty, Err(crate::error::FfiError::Protocol { ref class, .. }) if class == "configuration_invalid")
        );
        let both = ffi_sign_key_rotation_statement_with_slots(
            FfiCancelToken::new(None).unwrap(),
            stmt(software.public_key().unwrap(), split.public_key().unwrap()),
            Some(software.clone()),
            None,
            Some(split.clone()),
            Some(Arc::new(Ed(ed.clone()))),
            None,
            None,
            Some(split),
            Some(Arc::new(Ed(ed))),
        );
        assert!(
            matches!(both, Err(crate::error::FfiError::Protocol { ref class, .. }) if class == "configuration_invalid")
        );
    }

    #[test]
    fn split_key_refuses_a_request_for_another_key() {
        let ed = SigningKey::from_bytes(&[7; 32]);
        let key = FfiSplitKey::new(vec![9; 32], ed.verifying_key().to_bytes().to_vec()).unwrap();
        let cert = fixture_cert(); // issued by the fixture root, not this key
        let r = ffi_sign_delegation_cert_with_split_key(
            FfiCancelToken::new(None).unwrap(),
            cert,
            key,
            Arc::new(Ed(ed)),
        );
        assert!(
            matches!(r, Err(crate::error::FfiError::Signing { .. })),
            "{r:?}"
        );
    }
}
