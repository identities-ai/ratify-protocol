//! Encoders, signature verification, signing transcripts and digests for the
//! v2 signed objects. Each export is one core call; conversions copy fields.

use std::collections::{BTreeMap, HashMap};

use ratify_protocol::v2::{
    self as core, KeyRotationV2State, ReceiptV2Head, V2ErrorClass, V2ObjectType,
    WitnessEntryV2Result, WitnessV2Head,
};

use crate::error::{protocol, FfiResult};
use crate::guard::call;
use crate::keys::FfiPublicKey;
use crate::objects::*;

/// The SPEC-v2 object type for a signature code (0x0001..=0x0009).
fn object_type(code: u16) -> FfiResult<V2ObjectType> {
    V2ObjectType::from_code(code).ok_or_else(|| {
        protocol(
            V2ErrorClass::UnsupportedObjectType,
            format!("unknown v2 object type code {code}"),
        )
    })
}

// ---- encoders ----------------------------------------------------------

#[uniffi::export]
pub fn ffi_encode_delegation_cert(cert: FfiDelegationCert) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_delegation_cert_v2(&cert.into())?))
}
#[uniffi::export]
pub fn ffi_encode_proof_bundle(bundle: FfiProofBundle) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_proof_bundle_v2(&bundle.into())?))
}
#[uniffi::export]
pub fn ffi_encode_revocation_list(list: FfiRevocationList) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_revocation_list_v2(&list.into())?))
}
#[uniffi::export]
pub fn ffi_encode_revocation_push(push: FfiRevocationPush) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_revocation_push_v2(&push.into())?))
}
#[uniffi::export]
pub fn ffi_encode_key_rotation_statement(statement: FfiKeyRotationStatement) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_key_rotation_statement_v2(&statement.into())?))
}
#[uniffi::export]
pub fn ffi_encode_witness_entry(entry: FfiWitnessEntry) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_witness_entry_v2(&entry.into())?))
}
#[uniffi::export]
pub fn ffi_encode_verification_receipt(receipt: FfiVerificationReceipt) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_verification_receipt_v2(&receipt.into())?))
}
#[uniffi::export]
pub fn ffi_encode_transaction_receipt(receipt: FfiTransactionReceipt) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::encode_transaction_receipt_v2(&receipt.into())?))
}

// ---- verification state ------------------------------------------------

/// Caller-authenticated rotation state for one authority and role.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiRotationState {
    pub authority_id: String,
    pub recovery_epoch: i64,
    pub role: String,
    pub sequence: i64,
    pub head_hash: Vec<u8>,
    pub current_key: FfiPublicKey,
    pub used_key_ids: Vec<String>,
}

impl From<FfiRotationState> for KeyRotationV2State {
    fn from(s: FfiRotationState) -> Self {
        KeyRotationV2State {
            authority_id: s.authority_id,
            recovery_epoch: s.recovery_epoch,
            role: s.role,
            sequence: s.sequence,
            head_hash: s.head_hash,
            current_key: s.current_key.into(),
            used_key_ids: s.used_key_ids,
        }
    }
}

/// Caller-authenticated witness-log state before an entry.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiWitnessHead {
    pub log_id: String,
    pub sequence: i64,
    pub head_hash: Vec<u8>,
    /// Every accepted sequence's body digest, for replay and fork checks.
    pub accepted_digests: HashMap<i64, Vec<u8>>,
    pub frozen: bool,
}

impl From<FfiWitnessHead> for WitnessV2Head {
    fn from(h: FfiWitnessHead) -> Self {
        WitnessV2Head {
            log_id: h.log_id,
            sequence: h.sequence,
            head_hash: h.head_hash,
            accepted_digests: h.accepted_digests.into_iter().collect::<BTreeMap<_, _>>(),
            frozen: h.frozen,
        }
    }
}

/// Caller-authenticated receipt-log state before a receipt.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiReceiptHead {
    pub log_id: String,
    pub verifier_id: String,
    pub sequence: i64,
    pub head_hash: Vec<u8>,
    pub accepted_digests: HashMap<i64, Vec<u8>>,
    pub frozen: bool,
}

impl From<FfiReceiptHead> for ReceiptV2Head {
    fn from(h: FfiReceiptHead) -> Self {
        ReceiptV2Head {
            log_id: h.log_id,
            verifier_id: h.verifier_id,
            sequence: h.sequence,
            head_hash: h.head_hash,
            accepted_digests: h.accepted_digests.into_iter().collect::<BTreeMap<_, _>>(),
            frozen: h.frozen,
        }
    }
}

/// What a valid log entry does to its log.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfiLogResult {
    /// The next valid entry; the caller must atomically persist the new head.
    Appended,
    /// An exact accepted body at an accepted sequence; state is unchanged.
    Replay,
}

impl From<WitnessEntryV2Result> for FfiLogResult {
    fn from(r: WitnessEntryV2Result) -> Self {
        match r {
            WitnessEntryV2Result::Appended => FfiLogResult::Appended,
            WitnessEntryV2Result::Replay => FfiLogResult::Replay,
        }
    }
}

// ---- verification ------------------------------------------------------

#[uniffi::export]
pub fn ffi_verify_delegation_cert_signature(cert: FfiDelegationCert) -> FfiResult<()> {
    call(|| Ok(core::verify_delegation_cert_v2_signature(&cert.into())?))
}
#[uniffi::export]
pub fn ffi_verify_proof_bundle_signatures(bundle: FfiProofBundle) -> FfiResult<()> {
    call(|| Ok(core::verify_proof_bundle_v2_signatures(&bundle.into())?))
}
#[uniffi::export]
pub fn ffi_verify_revocation_list_signature(
    list: FfiRevocationList,
    trusted_issuer_id: String,
    status_key: FfiPublicKey,
) -> FfiResult<()> {
    call(|| {
        Ok(core::verify_revocation_list_v2_signature(
            &list.into(),
            &trusted_issuer_id,
            &status_key.into(),
        )?)
    })
}
#[uniffi::export]
pub fn ffi_verify_revocation_push_signature(
    push: FfiRevocationPush,
    trusted_issuer_id: String,
    status_key: FfiPublicKey,
) -> FfiResult<()> {
    call(|| {
        Ok(core::verify_revocation_push_v2_signature(
            &push.into(),
            &trusted_issuer_id,
            &status_key.into(),
        )?)
    })
}
#[uniffi::export]
pub fn ffi_verify_key_rotation_statement(
    statement: FfiKeyRotationStatement,
    state: FfiRotationState,
    now: i64,
    future_skew: i64,
) -> FfiResult<()> {
    call(|| {
        Ok(core::verify_key_rotation_statement_v2(
            &statement.into(),
            &state.into(),
            now,
            future_skew,
        )?)
    })
}
#[uniffi::export]
pub fn ffi_verify_witness_entry(
    entry: FfiWitnessEntry,
    head: FfiWitnessHead,
    witness_key: FfiPublicKey,
) -> FfiResult<FfiLogResult> {
    call(|| {
        Ok(core::verify_witness_entry_v2(&entry.into(), &head.into(), &witness_key.into())?.into())
    })
}
#[uniffi::export]
pub fn ffi_verify_transaction_receipt_signatures(receipt: FfiTransactionReceipt) -> FfiResult<()> {
    call(|| {
        Ok(core::verify_transaction_receipt_v2_signatures(
            &receipt.into(),
        )?)
    })
}
#[uniffi::export]
pub fn ffi_verify_verification_receipt(
    receipt: FfiVerificationReceipt,
    verifier_key: FfiPublicKey,
    head: FfiReceiptHead,
) -> FfiResult<FfiLogResult> {
    call(|| {
        Ok(core::verify_verification_receipt_v2(
            &receipt.into(),
            &verifier_key.into(),
            &head.into(),
        )?
        .into())
    })
}
#[uniffi::export]
pub fn ffi_check_verification_receipt_bundle_binding(
    receipt: FfiVerificationReceipt,
    bundle: FfiProofBundle,
) -> FfiResult<()> {
    call(|| {
        Ok(core::check_verification_receipt_v2_bundle_binding(
            &receipt.into(),
            &bundle.into(),
        )?)
    })
}

// ---- signing transcript (SPEC-v2 §3) -----------------------------------

/// The 77-byte signing message `M` for an object type code and signable bytes.
#[uniffi::export]
pub fn ffi_signing_message(object_type_code: u16, signable: Vec<u8>) -> FfiResult<Vec<u8>> {
    call(|| {
        Ok(core::v2_signing_message(
            object_type(object_type_code)?,
            &signable,
        ))
    })
}
/// The 22-byte ML-DSA-65 context string for an object type code.
#[uniffi::export]
pub fn ffi_mldsa_context(object_type_code: u16) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::v2_mldsa_context(object_type(object_type_code)?)))
}
/// Verify both components of a hybrid signature over an object's signable bytes.
#[uniffi::export]
pub fn ffi_verify_statement(
    object_type_code: u16,
    signable: Vec<u8>,
    signature: FfiSignature,
    public_key: FfiPublicKey,
) -> FfiResult<()> {
    call(|| {
        Ok(core::verify_v2_statement(
            object_type(object_type_code)?,
            &signable,
            &signature.into(),
            &public_key.into(),
        )?)
    })
}
/// The FIPS 204 external `mu` for an ML-DSA-65 public key, context and message.
#[uniffi::export]
pub fn ffi_external_mu(
    ml_dsa_public_key: Vec<u8>,
    ml_dsa_context: Vec<u8>,
    message: Vec<u8>,
) -> FfiResult<Vec<u8>> {
    call(|| {
        Ok(core::external_mu_v2(
            &ml_dsa_public_key,
            &ml_dsa_context,
            &message,
        ))
    })
}

// ---- digests -----------------------------------------------------------

#[uniffi::export]
pub fn ffi_bundle_hash(bundle: FfiProofBundle) -> FfiResult<String> {
    call(|| Ok(core::bundle_hash_v2(&bundle.into())?))
}
#[uniffi::export]
pub fn ffi_challenge_claim_digest(challenge: Vec<u8>) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::challenge_claim_digest_v2(&challenge)?))
}
#[uniffi::export]
pub fn ffi_protocol_claim_id(
    namespace: String,
    replay_epoch: i64,
    challenge: Vec<u8>,
) -> FfiResult<String> {
    call(|| {
        Ok(core::protocol_claim_id_v2(
            &namespace,
            replay_epoch,
            &challenge,
        )?)
    })
}
#[uniffi::export]
pub fn ffi_verification_receipt_body(receipt: FfiVerificationReceipt) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::verification_receipt_v2_body(&receipt.into())?))
}
#[uniffi::export]
pub fn ffi_status_evidence_digest_list(list: FfiRevocationList) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::status_evidence_digest_list_v2(&list.into())?))
}
#[uniffi::export]
pub fn ffi_status_evidence_digest_push(push: FfiRevocationPush) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::status_evidence_digest_push_v2(&push.into())?))
}
#[uniffi::export]
pub fn ffi_key_rotation_statement_digest(statement: FfiKeyRotationStatement) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::key_rotation_statement_v2_digest(&statement.into())?))
}
#[uniffi::export]
pub fn ffi_witness_entry_digest(entry: FfiWitnessEntry) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::witness_entry_v2_digest(&entry.into())?))
}
#[uniffi::export]
pub fn ffi_verification_receipt_digest(receipt: FfiVerificationReceipt) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::verification_receipt_v2_digest(&receipt.into())?))
}
#[uniffi::export]
pub fn ffi_transaction_context_hash(receipt: FfiTransactionReceipt) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::transaction_context_hash_v2(&receipt.into())))
}
#[uniffi::export]
pub fn ffi_transaction_party_request_hash(
    transaction_hash: Vec<u8>,
    required_scope: String,
) -> FfiResult<Vec<u8>> {
    call(|| {
        Ok(core::transaction_party_request_hash_v2(
            &transaction_hash,
            &required_scope,
        ))
    })
}

// ---- signable projections (SPEC-v2 §5) ----------------------------------

#[uniffi::export]
pub fn ffi_delegation_cert_signable_bytes(cert: FfiDelegationCert) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::delegation_cert_v2_signable_bytes(&cert.into())?))
}
#[uniffi::export]
pub fn ffi_presentation_signable_bytes(bundle: FfiProofBundle) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::presentation_v2_signable_bytes(&bundle.into())?))
}
#[uniffi::export]
pub fn ffi_revocation_list_signable_bytes(list: FfiRevocationList) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::revocation_list_v2_signable_bytes(&list.into())?))
}
#[uniffi::export]
pub fn ffi_revocation_push_signable_bytes(push: FfiRevocationPush) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::revocation_push_v2_signable_bytes(&push.into())?))
}
#[uniffi::export]
pub fn ffi_key_rotation_statement_signable_bytes(
    statement: FfiKeyRotationStatement,
) -> FfiResult<Vec<u8>> {
    call(|| {
        Ok(core::key_rotation_statement_v2_signable_bytes(
            &statement.into(),
        )?)
    })
}
#[uniffi::export]
pub fn ffi_witness_entry_signable_bytes(entry: FfiWitnessEntry) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::witness_entry_v2_signable_bytes(&entry.into())?))
}
#[uniffi::export]
pub fn ffi_verification_receipt_signable_bytes(
    receipt: FfiVerificationReceipt,
) -> FfiResult<Vec<u8>> {
    call(|| {
        Ok(core::verification_receipt_v2_signable_bytes(
            &receipt.into(),
        )?)
    })
}
#[uniffi::export]
pub fn ffi_transaction_receipt_sign_bytes(receipt: FfiTransactionReceipt) -> FfiResult<Vec<u8>> {
    call(|| Ok(core::transaction_receipt_v2_sign_bytes(&receipt.into())?))
}
