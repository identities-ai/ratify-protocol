//! Protocol v2 delegation signature primitives.
//!
//! This module intentionally implements the v2 signature transcript only; it
//! does not parse or validate complete v2 protocol objects.

use alloc::{string::{String, ToString}, vec::Vec};

use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
#[cfg(test)]
use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
#[cfg(test)]
use fips204::traits::Signer;
use sha2::{Digest, Sha256, Sha384};

#[cfg(test)]
use crate::types::HybridPrivateKey;
use crate::types::{HybridPublicKey, HybridSignature};

const SIGNATURE_PREFIX: &[u8] = b"ratify-protocol-signature\0\x02";
const KEY_ID_PREFIX: &[u8] = b"ratify-key-id-v2\0";
const DELEGATION_CODE: u16 = 0x0001;
const ML_DSA_CONTEXT: &[u8] = b"ratify-protocol/2/0001";
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Construct the fixed v2 signing message for a delegation certificate.
pub fn delegation_signature_message_v2(signable_bytes: &[u8]) -> Vec<u8> {
    signature_message(DELEGATION_CODE, signable_bytes)
}

fn signature_message(object_type_code: u16, signable_bytes: &[u8]) -> Vec<u8> {
    let digest = Sha384::digest(signable_bytes);
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + 2 + digest.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&object_type_code.to_be_bytes());
    message.extend_from_slice(&digest);
    message
}

/// Derive the v2 hybrid key ID from both public key components.
pub fn derive_key_id_v2(pub_key: &HybridPublicKey) -> Result<String, String> {
    if pub_key.ed25519.len() != 32 || pub_key.ml_dsa_65.len() != ml_dsa_65::PK_LEN {
        return Err("v2 hybrid public key has a component with the wrong length".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_PREFIX);
    hasher.update(&pub_key.ed25519);
    hasher.update(&pub_key.ml_dsa_65);
    Ok(hex::encode(hasher.finalize()))
}

/// Sign delegation signable bytes with both v2 components and fixed contexts.
/// Test-only: no exported function signs caller-selected bytes (SPEC-v2 §3.2).
#[cfg(test)]
pub(crate) fn sign_delegation_v2(
    signable_bytes: &[u8],
    private_key: &HybridPrivateKey,
) -> Result<HybridSignature, String> {
    let message = signature_message(DELEGATION_CODE, signable_bytes);
    let ed_seed: [u8; 32] = private_key
        .ed25519()
        .try_into()
        .map_err(|_| "v2 Ed25519 seed must be 32 bytes".to_string())?;
    let ed_signature = SigningKey::from_bytes(&ed_seed).sign(&message);

    let ml_sk_bytes: [u8; ml_dsa_65::SK_LEN] = private_key
        .ml_dsa_65()
        .try_into()
        .map_err(|_| "v2 ML-DSA-65 secret key has wrong length".to_string())?;
    let ml_sk = ml_dsa_65::PrivateKey::try_from_bytes(ml_sk_bytes)
        .map_err(|_| "v2 ML-DSA-65 secret key malformed".to_string())?;
    let ml_signature = ml_sk
        .try_sign(&message, ML_DSA_CONTEXT)
        .map_err(|_| "v2 ML-DSA-65 signing failed".to_string())?;

    Ok(HybridSignature {
        ed25519: ed_signature.to_bytes().to_vec(),
        ml_dsa_65: ml_signature.to_vec(),
    })
}

/// Verify both mandatory components using the v2 fixed message and context.
pub fn verify_delegation_v2(
    signable_bytes: &[u8],
    signature: &HybridSignature,
    public_key: &HybridPublicKey,
) -> Result<(), String> {
    if public_key.ed25519.len() != 32 || signature.ed25519.len() != 64 {
        return Err("v2 Ed25519 key or signature has wrong length".into());
    }
    if public_key.ml_dsa_65.len() != ml_dsa_65::PK_LEN
        || signature.ml_dsa_65.len() != ml_dsa_65::SIG_LEN
    {
        return Err("v2 ML-DSA-65 key or signature has wrong length".into());
    }
    validate_ed_public_key(&public_key.ed25519)?;
    validate_ed_signature(&signature.ed25519)?;

    let ed_bytes: [u8; 32] = public_key.ed25519.as_slice().try_into().unwrap();
    let ed_key = VerifyingKey::from_bytes(&ed_bytes)
        .map_err(|_| "v2 Ed25519 public key malformed".to_string())?;
    let ed_signature = EdSignature::from_slice(&signature.ed25519)
        .map_err(|_| "v2 Ed25519 signature malformed".to_string())?;
    let message = signature_message(DELEGATION_CODE, signable_bytes);
    ed_key
        .verify_strict(&message, &ed_signature)
        .map_err(|_| "v2 Ed25519 signature invalid".to_string())?;

    let ml_pk_bytes: [u8; ml_dsa_65::PK_LEN] = public_key.ml_dsa_65.as_slice().try_into().unwrap();
    let ml_pk = ml_dsa_65::PublicKey::try_from_bytes(ml_pk_bytes)
        .map_err(|_| "v2 ML-DSA-65 public key malformed".to_string())?;
    let ml_sig: [u8; ml_dsa_65::SIG_LEN] = signature.ml_dsa_65.as_slice().try_into().unwrap();
    if !ml_pk.verify(&message, &ml_sig, ML_DSA_CONTEXT) {
        return Err("v2 ML-DSA-65 signature invalid".into());
    }
    Ok(())
}

pub(crate) fn validate_ed_public_key(encoded: &[u8]) -> Result<(), String> {
    if encoded.len() != 32 {
        return Err("v2 Ed25519 public key must be 32 bytes".into());
    }
    let bytes: [u8; 32] = encoded.try_into().unwrap();
    let mut y_bytes = bytes;
    y_bytes[31] &= 0x7f;
    if little_endian_ge(&y_bytes, &FIELD_MODULUS_LE) {
        return Err("v2 Ed25519 point encoding is non-canonical".into());
    }
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| "v2 Ed25519 point is not on curve".to_string())?;
    if point.compress().to_bytes() != bytes || point.is_identity() || !point.is_torsion_free() {
        return Err("v2 Ed25519 point must be canonical, non-identity, and prime-order".into());
    }
    Ok(())
}

pub(crate) fn validate_ed_signature(encoded: &[u8]) -> Result<(), String> {
    if encoded.len() != 64 {
        return Err("v2 Ed25519 signature must be 64 bytes".into());
    }
    validate_ed_public_key(&encoded[..32])
        .map_err(|_| "v2 Ed25519 R point is invalid".to_string())?;
    if little_endian_ge(&encoded[32..], &ED25519_ORDER_LE) {
        return Err("v2 Ed25519 scalar S is non-canonical".into());
    }
    Ok(())
}

const FIELD_MODULUS_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

fn little_endian_ge(left: &[u8], right: &[u8; 32]) -> bool {
    left.iter().rev().cmp(right.iter().rev()).is_ge()
}

#[cfg(test)]
mod tests {
    use super::{
        sign_delegation_v2, validate_ed_public_key, validate_ed_signature, verify_delegation_v2,
    };
    use crate::crypto::generate_hybrid_keypair;
    use crate::v2::{verify_v2_statement, V2ObjectType};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use ed25519_dalek::{Signer, SigningKey};

    // The delegation helper and the typed registry must produce the same
    // transcript: a delegation signed one way verifies the other way.
    #[test]
    fn delegation_signing_matches_the_typed_registry_transcript() {
        let (public, private) = generate_hybrid_keypair();
        let signable = b"delegation signable bytes";
        let signature = sign_delegation_v2(signable, &private).unwrap();
        verify_delegation_v2(signable, &signature, &public).unwrap();
        verify_v2_statement(
            V2ObjectType::DelegationCertificate,
            signable,
            &signature,
            &public,
        )
        .unwrap();
        assert!(verify_delegation_v2(b"other bytes", &signature, &public).is_err());
    }

    fn mixed_order_encoding() -> [u8; 32] {
        let prime = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let prime = CompressedEdwardsY(prime.to_bytes()).decompress().unwrap();
        let mut order_two_bytes = [0xff; 32];
        order_two_bytes[0] = 0xec;
        order_two_bytes[31] = 0x7f;
        let order_two = CompressedEdwardsY(order_two_bytes).decompress().unwrap();
        (prime + order_two).compress().to_bytes()
    }

    #[test]
    fn v2_point_validation_rejects_mixed_order_a_and_r_at_the_subgroup_gate() {
        let mixed = mixed_order_encoding();
        assert_eq!(
            validate_ed_public_key(&mixed).unwrap_err(),
            "v2 Ed25519 point must be canonical, non-identity, and prime-order"
        );

        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut signature = signing_key.sign(b"test").to_bytes();
        signature[..32].copy_from_slice(&mixed);
        assert_eq!(
            validate_ed_signature(&signature).unwrap_err(),
            "v2 Ed25519 R point is invalid"
        );
    }

    #[test]
    fn v2_point_validation_rejects_identity_small_order_and_noncanonical_y() {
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(validate_ed_public_key(&identity).is_err());

        let mut order_two = [0xff; 32];
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        assert!(validate_ed_public_key(&order_two).is_err());

        let mut y_above_modulus = [0xff; 32];
        y_above_modulus[0] = 0xee;
        y_above_modulus[31] = 0x7f;
        assert_eq!(
            validate_ed_public_key(&y_above_modulus).unwrap_err(),
            "v2 Ed25519 point encoding is non-canonical"
        );

        let mut negative_zero = [0; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert!(validate_ed_public_key(&negative_zero).is_err());
    }

    #[test]
    fn v2_point_validation_rejects_noncanonical_s() {
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let mut signature = signing_key.sign(b"test").to_bytes();
        signature[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ]);
        assert_eq!(
            validate_ed_signature(&signature).unwrap_err(),
            "v2 Ed25519 scalar S is non-canonical"
        );
    }
}
