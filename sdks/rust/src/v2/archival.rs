//! Archival verification of stored v2 objects (SPEC-v2 §6.10). Mirrors Go
//! `archival_v2.go`. No result here is an authorization decision: no
//! challenge was consumed, and no trust root, issuer status, revocation,
//! current expiry, receipt log position or rotation state was evaluated.

use super::crypto::{key_id_v2, verify_v2_statement, V2ObjectType};
use super::errors::{err, Classify, V2ErrorClass, V2Result};
use super::json::{canonical, CJ};
use super::receipt::{
    decode_verification_receipt_v2, verification_receipt_v2_digest, verification_receipt_v2_signable_bytes,
};
use super::rotation::{decode_key_rotation_statement_v2, key_rotation_statement_v2_digest, key_rotation_statement_v2_signable_bytes};
use super::transaction::decode_transaction_receipt_v2;
use super::wire::{
    bundle_hash_v2, decode_delegation_cert_v2, decode_proof_bundle_v2, decode_revocation_list_v2,
    decode_revocation_push_v2, status_evidence_digest_list_v2, status_evidence_digest_push_v2,
    verify_delegation_cert_v2_signature, verify_proof_bundle_v2_signatures, verify_revocation_list_v2_signature,
    verify_revocation_push_v2_signature,
};
use super::witness::{decode_witness_entry_v2, witness_entry_v2_digest, witness_entry_v2_signable_bytes};
use crate::types::HybridPublicKey;

/// The mandatory label of every archival result.
pub const FRESHNESS_UNVERIFIED_V2: &str = "freshness_unverified";

/// One stored v2 object decoded strictly and its signatures verify. It is
/// NOT an authorization decision and MUST NOT be used to allow an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivalVerificationV2 {
    /// The SPEC-v2 object code of the verified object.
    pub object_type: u16,
    /// Always [`FRESHNESS_UNVERIFIED_V2`].
    pub freshness: String,
    /// Always false.
    pub actionable: bool,
    /// `"sha384:" + 96 hex` of the registered object digest; empty for
    /// certificates and transaction receipts, which have none.
    pub digest: String,
    /// The v2 key IDs whose signatures were verified, in object order.
    pub signer_key_ids: Vec<String>,
}

fn archival_result_v2(code: V2ObjectType, digest: Option<&[u8]>, signers: Vec<String>) -> ArchivalVerificationV2 {
    ArchivalVerificationV2 {
        object_type: code.code(),
        freshness: FRESHNESS_UNVERIFIED_V2.into(),
        actionable: false,
        digest: digest.map(|d| format!("sha384:{}", hex::encode(d))).unwrap_or_default(),
        signer_key_ids: signers,
    }
}

/// The SPEC-v2 §6.10 archival proof-bundle result. It has no decision
/// field and is never actionable. `error_class` is `None` when every check
/// passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivalProofBundleResultV2 {
    pub assessment: String,
    pub actionable: bool,
    pub bundle_hash: String,
    pub agent_id: String,
    pub issuer_ids: Vec<String>,
    pub error_class: Option<V2ErrorClass>,
    /// The diagnostic for `error_class`; not part of the language-neutral
    /// result.
    pub error_message: String,
}

impl ArchivalProofBundleResultV2 {
    /// The language-neutral JSON (Go `MarshalJSON`): RatifyCanonicalJSON of
    /// `{"actionable","agent_id","assessment","bundle_hash","error_class",
    /// "issuer_ids"}` with `error_class` null when every check passed.
    pub fn to_json(&self) -> V2Result<Vec<u8>> {
        canonical(&CJ::obj(vec![
            ("actionable", CJ::Bool(self.actionable)),
            ("agent_id", CJ::s(&self.agent_id)),
            ("assessment", CJ::s(&self.assessment)),
            ("bundle_hash", CJ::s(&self.bundle_hash)),
            (
                "error_class",
                self.error_class.map_or(CJ::Null, |c| CJ::s(c.as_str())),
            ),
            ("issuer_ids", CJ::strs(&self.issuer_ids)),
        ]))
        .classify(V2ErrorClass::Malformed)
    }
}

/// Go `VerifyArchivalProofBundleV2`: only the signature-and-structure
/// pre-claim steps on a stored proof bundle (bounded strict decode, key IDs,
/// delegation digest, duplicate CertificateRef and linkage, every
/// certificate and challenge signature). It omits required-scope validation,
/// expected-challenge checks and every provider.
pub fn verify_archival_proof_bundle_v2(data: &[u8]) -> ArchivalProofBundleResultV2 {
    let mut result = ArchivalProofBundleResultV2 {
        assessment: FRESHNESS_UNVERIFIED_V2.into(),
        actionable: false,
        bundle_hash: String::new(),
        agent_id: String::new(),
        issuer_ids: Vec::new(),
        error_class: None,
        error_message: String::new(),
    };
    let fail = |mut result: ArchivalProofBundleResultV2, e: super::errors::V2Error| {
        result.error_class = Some(e.class);
        result.error_message = e.message;
        result
    };
    let bundle = match decode_proof_bundle_v2(data) {
        Ok(b) => b,
        Err(e) => return fail(result, e),
    };
    result.agent_id = bundle.agent_id.clone();
    match bundle_hash_v2(&bundle).classify(V2ErrorClass::Malformed) {
        Ok(h) => result.bundle_hash = h,
        Err(e) => return fail(result, e),
    }
    result.issuer_ids = bundle.delegations.iter().map(|c| c.issuer_id.clone()).collect();
    result.issuer_ids.sort();
    result.issuer_ids.dedup();
    if let Err(e) = verify_proof_bundle_v2_signatures(&bundle) {
        return fail(result, e);
    }
    result
}

/// Go `VerifyArchivalDelegationCertV2`: one stored certificate and its
/// issuer signature under the issuer key it carries.
pub fn verify_archival_delegation_cert_v2(data: &[u8]) -> V2Result<ArchivalVerificationV2> {
    let cert = decode_delegation_cert_v2(data)?;
    verify_delegation_cert_v2_signature(&cert)?;
    Ok(archival_result_v2(V2ObjectType::DelegationCertificate, None, vec![cert.issuer_id]))
}

/// Go `VerifyArchivalRevocationListV2`: a stored revocation list under a
/// caller-authenticated issuer status key.
pub fn verify_archival_revocation_list_v2(
    data: &[u8],
    issuer_id: &str,
    status_key: &HybridPublicKey,
) -> V2Result<ArchivalVerificationV2> {
    let list = decode_revocation_list_v2(data)?;
    verify_revocation_list_v2_signature(&list, issuer_id, status_key)?;
    let digest = status_evidence_digest_list_v2(&list).classify(V2ErrorClass::Malformed)?;
    let key_id = key_id_v2(status_key).unwrap_or_default();
    Ok(archival_result_v2(V2ObjectType::RevocationList, Some(&digest), vec![key_id]))
}

/// Go `VerifyArchivalRevocationPushV2`: a stored revocation push under a
/// caller-authenticated issuer status key.
pub fn verify_archival_revocation_push_v2(
    data: &[u8],
    issuer_id: &str,
    status_key: &HybridPublicKey,
) -> V2Result<ArchivalVerificationV2> {
    let push = decode_revocation_push_v2(data)?;
    verify_revocation_push_v2_signature(&push, issuer_id, status_key)?;
    let digest = status_evidence_digest_push_v2(&push).classify(V2ErrorClass::Malformed)?;
    let key_id = key_id_v2(status_key).unwrap_or_default();
    Ok(archival_result_v2(V2ObjectType::RevocationPush, Some(&digest), vec![key_id]))
}

/// Go `VerifyArchivalKeyRotationStatementV2`: a stored rotation statement's
/// old-key authorization and new-key proof of possession under the keys it
/// names. It does not establish that old_key was the authority's current key.
pub fn verify_archival_key_rotation_statement_v2(data: &[u8]) -> V2Result<ArchivalVerificationV2> {
    let stmt = decode_key_rotation_statement_v2(data)?;
    let signable = key_rotation_statement_v2_signable_bytes(&stmt).classify(V2ErrorClass::Malformed)?;
    verify_v2_statement(V2ObjectType::KeyRotationAuthorization, &signable, &stmt.old_signature, &stmt.old_key)
        .map_err(|e| e.context("old-key rotation authorization"))?;
    verify_v2_statement(
        V2ObjectType::KeyRotationProofOfPossession,
        &signable,
        &stmt.new_signature,
        &stmt.new_key,
    )
    .map_err(|e| e.context("new-key proof of possession"))?;
    let digest = key_rotation_statement_v2_digest(&stmt).classify(V2ErrorClass::Malformed)?;
    Ok(archival_result_v2(
        V2ObjectType::KeyRotationAuthorization,
        Some(&digest),
        vec![stmt.old_key_id.clone(), stmt.new_key_id.clone()],
    ))
}

/// Go `VerifyArchivalWitnessEntryV2`: a stored witness entry under a
/// caller-authenticated witness key, without log position or fork checks.
pub fn verify_archival_witness_entry_v2(
    data: &[u8],
    witness_public: &HybridPublicKey,
) -> V2Result<ArchivalVerificationV2> {
    let entry = decode_witness_entry_v2(data)?;
    let witness_id = match key_id_v2(witness_public) {
        Ok(id) if id == entry.witness_id => id,
        _ => return err(V2ErrorClass::KeyIdMismatch, "witness key does not match witness_id"),
    };
    let body = witness_entry_v2_signable_bytes(&entry).classify(V2ErrorClass::Malformed)?;
    verify_v2_statement(V2ObjectType::WitnessEntry, &body, &entry.signature, witness_public)?;
    let digest = witness_entry_v2_digest(&entry).classify(V2ErrorClass::Malformed)?;
    Ok(archival_result_v2(V2ObjectType::WitnessEntry, Some(&digest), vec![witness_id]))
}

/// Go `VerifyArchivalVerificationReceiptV2`: a stored verification receipt
/// under a caller-authenticated verifier key, without log position, fork or
/// bundle-binding checks.
pub fn verify_archival_verification_receipt_v2(
    data: &[u8],
    verifier_public: &HybridPublicKey,
) -> V2Result<ArchivalVerificationV2> {
    let receipt = decode_verification_receipt_v2(data)?;
    let verifier_id = match key_id_v2(verifier_public) {
        Ok(id) if id == receipt.verifier_id => id,
        _ => return err(V2ErrorClass::KeyIdMismatch, "verifier key does not match verifier_id"),
    };
    let body = verification_receipt_v2_signable_bytes(&receipt).classify(V2ErrorClass::Malformed)?;
    verify_v2_statement(V2ObjectType::VerificationReceipt, &body, &receipt.signature, verifier_public)?;
    let digest = verification_receipt_v2_digest(&receipt).classify(V2ErrorClass::Malformed)?;
    Ok(archival_result_v2(V2ObjectType::VerificationReceipt, Some(&digest), vec![verifier_id]))
}

/// Go `VerifyArchivalTransactionReceiptV2`: a stored transaction receipt's
/// canonical form, every party signature, and every embedded proof bundle's
/// signatures, hash and transaction context. Use
/// [`super::verify_transaction_receipt_v2`] for per-party trust and status.
pub fn verify_archival_transaction_receipt_v2(data: &[u8]) -> V2Result<ArchivalVerificationV2> {
    let receipt = decode_transaction_receipt_v2(data)?;
    let signers = receipt.parties.iter().map(|p| p.agent_id.clone()).collect();
    Ok(archival_result_v2(V2ObjectType::TransactionPartyStatement, None, signers))
}
