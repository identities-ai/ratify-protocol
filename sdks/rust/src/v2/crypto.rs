//! Typed v2 signing transcripts for every registered object code
//! (mirrors Go `crypto_v2.go`).

use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use sha2::{Digest, Sha256, Sha384};

use super::errors::{err, plain, V2Error, V2ErrorClass, V2Result};
use crate::crypto_v2::{validate_ed_public_key, validate_ed_signature};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature};

/// The closed v2 signed-object registry (SPEC-v2 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum V2ObjectType {
    DelegationCertificate = 0x0001,
    ChallengePresentation = 0x0002,
    RevocationList = 0x0003,
    KeyRotationAuthorization = 0x0004,
    RevocationPush = 0x0005,
    WitnessEntry = 0x0006,
    TransactionPartyStatement = 0x0007,
    VerificationReceipt = 0x0008,
    KeyRotationProofOfPossession = 0x0009,
}

impl V2ObjectType {
    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn from_code(code: u16) -> Option<Self> {
        use V2ObjectType::*;
        Some(match code {
            0x0001 => DelegationCertificate,
            0x0002 => ChallengePresentation,
            0x0003 => RevocationList,
            0x0004 => KeyRotationAuthorization,
            0x0005 => RevocationPush,
            0x0006 => WitnessEntry,
            0x0007 => TransactionPartyStatement,
            0x0008 => VerificationReceipt,
            0x0009 => KeyRotationProofOfPossession,
            _ => return None,
        })
    }
}

/// Full 256-bit v2 key ID: hex(SHA-256("ratify-key-id-v2\0" || ed25519 || ml_dsa_65)).
pub fn key_id_v2(key: &HybridPublicKey) -> V2Result<String> {
    if key.ed25519.len() != 32 {
        return plain(format!(
            "Ed25519 public key wrong length: {}",
            key.ed25519.len()
        ));
    }
    if key.ml_dsa_65.len() != ml_dsa_65::PK_LEN {
        return plain(format!(
            "ML-DSA-65 public key wrong length: {}",
            key.ml_dsa_65.len()
        ));
    }
    let mut h = Sha256::new();
    h.update(b"ratify-key-id-v2\0");
    h.update(&key.ed25519);
    h.update(&key.ml_dsa_65);
    Ok(hex::encode(h.finalize()))
}

/// M = "ratify-protocol-signature\0\x02" || code_be16 || SHA-384(signable).
pub fn v2_signing_message(object_type: V2ObjectType, signable: &[u8]) -> Vec<u8> {
    let digest = Sha384::digest(signable);
    let mut m = Vec::with_capacity(77);
    m.extend_from_slice(b"ratify-protocol-signature\0\x02");
    m.extend_from_slice(&object_type.code().to_be_bytes());
    m.extend_from_slice(&digest);
    m
}

/// ML-DSA-65 context string "ratify-protocol/2/XXXX".
pub fn v2_mldsa_context(object_type: V2ObjectType) -> Vec<u8> {
    format!("ratify-protocol/2/{:04x}", object_type.code()).into_bytes()
}

fn ed_seed(private_key: &HybridPrivateKey) -> V2Result<[u8; 32]> {
    // The Rust SDK stores the 32-byte seed; a 64-byte seed||public form is
    // also accepted when its public half matches the seed (Go layout).
    match private_key.ed25519.len() {
        32 => Ok(private_key.ed25519.as_slice().try_into().expect("32 bytes")),
        64 => {
            let seed: [u8; 32] = private_key.ed25519[..32].try_into().expect("32 bytes");
            if SigningKey::from_bytes(&seed).verifying_key().to_bytes()[..]
                != private_key.ed25519[32..]
            {
                return plain("Ed25519 private key seed and public component do not match");
            }
            Ok(seed)
        }
        _ => plain("incomplete hybrid private key"),
    }
}

fn ml_secret(private_key: &HybridPrivateKey) -> V2Result<ml_dsa_65::PrivateKey> {
    let bytes: [u8; ml_dsa_65::SK_LEN] = private_key
        .ml_dsa_65
        .as_slice()
        .try_into()
        .map_err(|_| V2Error::plain("incomplete hybrid private key"))?;
    ml_dsa_65::PrivateKey::try_from_bytes(bytes)
        .map_err(|_| V2Error::plain("ML-DSA-65 secret key malformed"))
}

/// Derive the hybrid public key of a private key (both components validated).
pub fn public_key_v2(private_key: &HybridPrivateKey) -> V2Result<HybridPublicKey> {
    let seed = ed_seed(private_key)?;
    let ml = ml_secret(private_key)?;
    Ok(HybridPublicKey {
        ed25519: SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
        ml_dsa_65: ml.get_public_key().into_bytes().to_vec(),
    })
}

/// Sign `signable` under `object_type` with both mandatory components.
/// ML-DSA-65 signing is hedged (randomized); Ed25519 is deterministic.
pub fn sign_v2_statement(
    object_type: V2ObjectType,
    signable: &[u8],
    private_key: &HybridPrivateKey,
) -> V2Result<HybridSignature> {
    let seed = ed_seed(private_key)?;
    let ml = ml_secret(private_key)?;
    let message = v2_signing_message(object_type, signable);
    let ed = SigningKey::from_bytes(&seed).sign(&message);
    let ml_sig = ml
        .try_sign(&message, &v2_mldsa_context(object_type))
        .map_err(|e| V2Error::plain(format!("ML-DSA-65 v2 sign: {e}")))?;
    Ok(HybridSignature {
        ed25519: ed.to_bytes().to_vec(),
        ml_dsa_65: ml_sig.to_vec(),
    })
}

/// Strict AND verification of both components. An unregistered code is
/// `unsupported_object_type`; every other failure is `invalid_signature`.
pub fn verify_v2_statement_code(
    object_type_code: u16,
    signable: &[u8],
    signature: &HybridSignature,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    let Some(object_type) = V2ObjectType::from_code(object_type_code) else {
        return err(
            V2ErrorClass::UnsupportedObjectType,
            format!("unsupported v2 object type: {object_type_code:04x}"),
        );
    };
    verify_v2_statement(object_type, signable, signature, public_key)
}

/// Strict AND verification of both components under a registered code.
pub fn verify_v2_statement(
    object_type: V2ObjectType,
    signable: &[u8],
    signature: &HybridSignature,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    verify_unclassified(object_type, signable, signature, public_key)
        .map_err(|m| V2Error::new(V2ErrorClass::InvalidSignature, m))
}

fn verify_unclassified(
    object_type: V2ObjectType,
    signable: &[u8],
    signature: &HybridSignature,
    public_key: &HybridPublicKey,
) -> Result<(), String> {
    if public_key.ed25519.len() != 32 || public_key.ml_dsa_65.len() != ml_dsa_65::PK_LEN {
        return Err("hybrid public key has invalid component length".into());
    }
    if signature.ed25519.len() != 64 || signature.ml_dsa_65.len() != ml_dsa_65::SIG_LEN {
        return Err("hybrid signature has invalid component length".into());
    }
    validate_ed_public_key(&public_key.ed25519)?;
    validate_ed_signature(&signature.ed25519)?;
    let message = v2_signing_message(object_type, signable);
    let ed_key = VerifyingKey::from_bytes(&public_key.ed25519[..].try_into().expect("32 bytes"))
        .map_err(|_| "Ed25519 v2 public key malformed".to_string())?;
    let ed_sig = EdSignature::from_slice(&signature.ed25519)
        .map_err(|_| "Ed25519 v2 signature malformed".to_string())?;
    ed_key
        .verify_strict(&message, &ed_sig)
        .map_err(|_| "Ed25519 v2 signature invalid".to_string())?;
    let ml_pk =
        ml_dsa_65::PublicKey::try_from_bytes(public_key.ml_dsa_65[..].try_into().expect("PK_LEN"))
            .map_err(|_| "ML-DSA-65 public key malformed".to_string())?;
    let ml_sig: [u8; ml_dsa_65::SIG_LEN] = signature.ml_dsa_65[..].try_into().expect("SIG_LEN");
    if !ml_pk.verify(&message, &ml_sig, &v2_mldsa_context(object_type)) {
        return Err("ML-DSA-65 v2 signature invalid".into());
    }
    Ok(())
}

pub(crate) fn equal_keys(a: &HybridPublicKey, b: &HybridPublicKey) -> bool {
    a.ed25519 == b.ed25519 && a.ml_dsa_65 == b.ml_dsa_65
}

/// 64 lowercase hexadecimal characters (a full v2 key ID).
pub fn valid_v2_id(id: &str) -> bool {
    id.len() == 64 && lower_hex(id)
}

pub(crate) fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// "sha384:" followed by 96 lowercase hexadecimal characters.
pub(crate) fn valid_prefixed_digest(value: &str) -> bool {
    value
        .strip_prefix("sha384:")
        .is_some_and(|h| h.len() == 96 && lower_hex(h))
}

pub(crate) fn sha384(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

pub(crate) fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Big-endian u64 length prefix followed by the bytes.
pub(crate) fn lp(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u64).to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}
