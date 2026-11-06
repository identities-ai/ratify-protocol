//! Archival verification (SPEC-v2 §6.10): stored objects decoded strictly
//! with their signatures verified. Never an authorization decision.

use ratify_protocol::v2::{
    self as core, ArchivalProofBundleResultV2, ArchivalVerificationV2, StatusEvidenceObjectV2,
    V2ErrorClass,
};

use crate::error::{protocol, FfiResult};
use crate::guard::call;
use crate::keys::FfiPublicKey;
use crate::objects::{FfiRevocationList, FfiRevocationPush};

/// One stored object decoded strictly with its signatures verified.
/// `actionable` is always false; `freshness` is always "unverified".
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiArchivalVerification {
    pub object_type: u16,
    pub freshness: String,
    pub actionable: bool,
    /// `sha384:` + 96 hex of the registered digest; empty when the object has none.
    pub digest: String,
    /// The v2 key IDs whose signatures were verified, in object order.
    pub signer_key_ids: Vec<String>,
}

impl From<ArchivalVerificationV2> for FfiArchivalVerification {
    fn from(r: ArchivalVerificationV2) -> Self {
        FfiArchivalVerification {
            object_type: r.object_type,
            freshness: r.freshness,
            actionable: r.actionable,
            digest: r.digest,
            signer_key_ids: r.signer_key_ids,
        }
    }
}

/// The §6.10 archival proof-bundle result. It has no decision and is never
/// actionable; `error_class` is None when every check passed.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiArchivalProofBundleResult {
    pub assessment: String,
    pub actionable: bool,
    pub bundle_hash: String,
    pub agent_id: String,
    pub issuer_ids: Vec<String>,
    pub error_class: Option<String>,
    pub error_message: String,
}

impl From<ArchivalProofBundleResultV2> for FfiArchivalProofBundleResult {
    fn from(r: ArchivalProofBundleResultV2) -> Self {
        FfiArchivalProofBundleResult {
            assessment: r.assessment,
            actionable: r.actionable,
            bundle_hash: r.bundle_hash,
            agent_id: r.agent_id,
            issuer_ids: r.issuer_ids,
            error_class: r.error_class.map(|c| c.as_str().to_string()),
            error_message: r.error_message,
        }
    }
}

impl TryFrom<FfiArchivalProofBundleResult> for ArchivalProofBundleResultV2 {
    type Error = crate::error::FfiError;
    fn try_from(r: FfiArchivalProofBundleResult) -> FfiResult<Self> {
        let error_class = match r.error_class {
            None => None,
            Some(c) => Some(V2ErrorClass::parse(&c).ok_or_else(|| {
                protocol(
                    V2ErrorClass::Malformed,
                    format!("{c} is not a SPEC-v2 error class"),
                )
            })?),
        };
        Ok(ArchivalProofBundleResultV2 {
            assessment: r.assessment,
            actionable: r.actionable,
            bundle_hash: r.bundle_hash,
            agent_id: r.agent_id,
            issuer_ids: r.issuer_ids,
            error_class,
            error_message: r.error_message,
        })
    }
}

#[uniffi::export]
pub fn ffi_verify_archival_proof_bundle(data: Vec<u8>) -> FfiResult<FfiArchivalProofBundleResult> {
    call(|| Ok(core::verify_archival_proof_bundle_v2(&data).into()))
}
/// The language-neutral JSON of an archival proof-bundle result.
#[uniffi::export]
pub fn ffi_archival_proof_bundle_result_json(
    result: FfiArchivalProofBundleResult,
) -> FfiResult<Vec<u8>> {
    call(|| Ok(ArchivalProofBundleResultV2::try_from(result)?.to_json()?))
}
#[uniffi::export]
pub fn ffi_verify_archival_delegation_cert(data: Vec<u8>) -> FfiResult<FfiArchivalVerification> {
    call(|| Ok(core::verify_archival_delegation_cert_v2(&data)?.into()))
}
#[uniffi::export]
pub fn ffi_verify_archival_revocation_list(
    data: Vec<u8>,
    issuer_id: String,
    status_key: FfiPublicKey,
) -> FfiResult<FfiArchivalVerification> {
    call(|| {
        Ok(core::verify_archival_revocation_list_v2(&data, &issuer_id, &status_key.into())?.into())
    })
}
#[uniffi::export]
pub fn ffi_verify_archival_revocation_push(
    data: Vec<u8>,
    issuer_id: String,
    status_key: FfiPublicKey,
) -> FfiResult<FfiArchivalVerification> {
    call(|| {
        Ok(core::verify_archival_revocation_push_v2(&data, &issuer_id, &status_key.into())?.into())
    })
}
#[uniffi::export]
pub fn ffi_verify_archival_key_rotation_statement(
    data: Vec<u8>,
) -> FfiResult<FfiArchivalVerification> {
    call(|| Ok(core::verify_archival_key_rotation_statement_v2(&data)?.into()))
}
#[uniffi::export]
pub fn ffi_verify_archival_witness_entry(
    data: Vec<u8>,
    witness_key: FfiPublicKey,
) -> FfiResult<FfiArchivalVerification> {
    call(|| Ok(core::verify_archival_witness_entry_v2(&data, &witness_key.into())?.into()))
}
#[uniffi::export]
pub fn ffi_verify_archival_verification_receipt(
    data: Vec<u8>,
    verifier_key: FfiPublicKey,
) -> FfiResult<FfiArchivalVerification> {
    call(|| Ok(core::verify_archival_verification_receipt_v2(&data, &verifier_key.into())?.into()))
}
#[uniffi::export]
pub fn ffi_verify_archival_transaction_receipt(
    data: Vec<u8>,
) -> FfiResult<FfiArchivalVerification> {
    call(|| Ok(core::verify_archival_transaction_receipt_v2(&data)?.into()))
}

/// `StatementBodyDigestV2` under an explicit object type code (SPEC-v2 §4).
#[uniffi::export]
pub fn ffi_statement_body_digest(
    object_type_code: u16,
    signable_body: Vec<u8>,
) -> FfiResult<Vec<u8>> {
    call(|| {
        Ok(core::statement_body_digest_v2(
            object_type_code,
            &signable_body,
        )?)
    })
}

/// A status object: a full revocation list or an incremental push.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum FfiStatusObject {
    List { list: FfiRevocationList },
    Push { push: FfiRevocationPush },
}

/// `StatusEvidenceDigest` under an explicit object type code: 0x0003
/// requires a list and 0x0005 a push.
#[uniffi::export]
pub fn ffi_status_evidence_digest(
    object_type_code: u16,
    object: FfiStatusObject,
) -> FfiResult<Vec<u8>> {
    call(|| match object {
        FfiStatusObject::List { list } => Ok(core::status_evidence_digest_v2(
            object_type_code,
            StatusEvidenceObjectV2::List(&list.into()),
        )?),
        FfiStatusObject::Push { push } => Ok(core::status_evidence_digest_v2(
            object_type_code,
            StatusEvidenceObjectV2::Push(&push.into()),
        )?),
    })
}
