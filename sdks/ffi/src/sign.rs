//! Typed signing (SPEC-v2 §3.2): software keys sign through the core's typed
//! functions; app-held keys sign through an external signer callback. The SDK
//! computes the message and context, and the core verifies every returned
//! component before using it.

use std::sync::Arc;

use ratify_protocol::v2::{
    self as core, SignRequestV2, SignerModeV2, SignerV2, V2Context, V2SignError,
};
use ratify_protocol::{HybridPublicKey, HybridSignature};

use crate::context::FfiCancelToken;
use crate::error::{FfiError, FfiResult};
use crate::guard::{call, call_on, Poison};
use crate::keys::{FfiPublicKey, FfiSoftwareKey};
use crate::objects::*;
use crate::verify::FfiReceiptHead;

impl From<V2SignError> for FfiError {
    fn from(e: V2SignError) -> Self {
        let kind = match &e {
            V2SignError::InvalidObject(_) => "invalid_object",
            V2SignError::IssuerDuty(_) => "issuer_duty",
            V2SignError::KeyBinding(_) => "key_binding",
            V2SignError::InvalidSignerKey(_) => "invalid_signer_key",
            V2SignError::UnsupportedMode => "unsupported_mode",
            V2SignError::Provider(_) => "provider",
            V2SignError::Cancelled => "cancelled",
            V2SignError::SignatureRejected(_) => "signature_rejected",
        };
        FfiError::Signing {
            class: e.class().as_str().to_string(),
            kind: kind.to_string(),
            detail: e.to_string(),
        }
    }
}

/// How an external signer computes ML-DSA-65 (SPEC-v2 §3.2).
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfiSignerMode {
    /// The provider signs `M` with the supplied context.
    Direct,
    /// The provider signs the supplied external `mu`.
    ExternalMu,
}

impl From<SignerModeV2> for FfiSignerMode {
    fn from(m: SignerModeV2) -> Self {
        match m {
            SignerModeV2::Direct => FfiSignerMode::Direct,
            SignerModeV2::ExternalMu => FfiSignerMode::ExternalMu,
        }
    }
}
impl From<FfiSignerMode> for SignerModeV2 {
    fn from(m: FfiSignerMode) -> Self {
        match m {
            FfiSignerMode::Direct => SignerModeV2::Direct,
            FfiSignerMode::ExternalMu => SignerModeV2::ExternalMu,
        }
    }
}

/// What the SDK asks an external signer to sign.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiSignRequest {
    pub mode: FfiSignerMode,
    /// The 77-byte signing message `M` (always present; Ed25519 signs it).
    pub message: Vec<u8>,
    /// The 22-byte ML-DSA-65 context, in direct mode.
    pub ml_dsa_context: Option<Vec<u8>>,
    /// The external `mu`, in external-mu mode.
    pub ml_dsa_mu: Option<Vec<u8>>,
    pub public_key: FfiPublicKey,
    pub key_id: String,
}

impl From<&SignRequestV2> for FfiSignRequest {
    fn from(r: &SignRequestV2) -> Self {
        FfiSignRequest {
            mode: r.mode.into(),
            message: r.message.clone(),
            ml_dsa_context: r.ml_dsa_context.clone(),
            ml_dsa_mu: r.ml_dsa_mu.clone(),
            public_key: (&r.public_key).into(),
            key_id: r.key_id.clone(),
        }
    }
}

/// Why an external signer did not return a signature.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiSignerError {
    /// The provider failed or refused.
    #[error("{detail}")]
    Provider { detail: String },
    /// The signer observed cancellation and stopped.
    #[error("cancelled")]
    Cancelled,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiSignerError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        FfiSignerError::Provider {
            detail: format!("external signer failed: {}", e.reason),
        }
    }
}

/// The signing call's context, as seen by an external signer: it can only
/// observe cancellation.
#[derive(uniffi::Object)]
pub struct FfiSignContext {
    poison: Poison,
    ctx: V2Context,
}

#[uniffi::export]
impl FfiSignContext {
    /// Whether the caller cancelled the signing call (or its deadline passed).
    pub fn is_cancelled(&self) -> FfiResult<bool> {
        call_on(&self.poison, || Ok(self.ctx.is_done()))
    }
}

/// An app-held key that signs through the platform or a remote provider.
/// Implemented in Swift and Kotlin by the SDK's bridge over the public
/// `ExternalSigner`; called on an SDK worker thread.
#[uniffi::export(with_foreign)]
pub trait FfiSigner: Send + Sync {
    fn public_key(&self) -> FfiPublicKey;
    fn mode(&self) -> FfiSignerMode;
    fn sign(
        &self,
        request: FfiSignRequest,
        context: Arc<FfiSignContext>,
    ) -> Result<FfiSignature, FfiSignerError>;
}

/// Adapts a foreign signer to the core's `SignerV2`. One foreign call per
/// trait method; the core verifies whatever comes back.
struct Foreign(Arc<dyn FfiSigner>);

impl SignerV2 for Foreign {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.0.public_key().into()
    }
    fn mode_v2(&self) -> SignerModeV2 {
        self.0.mode().into()
    }
    fn sign_v2(
        &self,
        ctx: &V2Context,
        request: &SignRequestV2,
    ) -> Result<HybridSignature, V2SignError> {
        let context = Arc::new(FfiSignContext {
            poison: Poison::default(),
            ctx: ctx.clone(),
        });
        match self.0.sign(request.into(), context) {
            Ok(sig) => Ok(sig.into()),
            Err(FfiSignerError::Cancelled) => Err(V2SignError::Cancelled),
            Err(FfiSignerError::Provider { detail }) => Err(V2SignError::Provider(detail)),
        }
    }
}

// ---- software-key typed signing (methods: a panic poisons the key) -------

#[uniffi::export]
impl FfiSoftwareKey {
    pub fn sign_delegation_cert(&self, cert: FfiDelegationCert) -> FfiResult<FfiDelegationCert> {
        call_on(&self.poison, || {
            Ok((&core::sign_delegation_cert_v2(&cert.into(), &self.private)?).into())
        })
    }
    pub fn sign_proof_bundle(&self, bundle: FfiProofBundle) -> FfiResult<FfiProofBundle> {
        call_on(&self.poison, || {
            Ok((&core::sign_proof_bundle_v2(&bundle.into(), &self.private)?).into())
        })
    }
    pub fn sign_revocation_list(
        &self,
        list: FfiRevocationList,
        bound_issuer_id: String,
        bound_status_key: FfiPublicKey,
    ) -> FfiResult<FfiRevocationList> {
        call_on(&self.poison, || {
            Ok((&core::sign_revocation_list_v2(
                &list.into(),
                &bound_issuer_id,
                &bound_status_key.into(),
                &self.private,
            )?)
                .into())
        })
    }
    pub fn sign_revocation_push(
        &self,
        push: FfiRevocationPush,
        bound_issuer_id: String,
        bound_status_key: FfiPublicKey,
    ) -> FfiResult<FfiRevocationPush> {
        call_on(&self.poison, || {
            Ok((&core::sign_revocation_push_v2(
                &push.into(),
                &bound_issuer_id,
                &bound_status_key.into(),
                &self.private,
            )?)
                .into())
        })
    }
    /// Sign as the old key; `new_key` signs the proof of possession. A panic
    /// poisons both keys.
    pub fn sign_key_rotation_statement(
        &self,
        statement: FfiKeyRotationStatement,
        new_key: Arc<FfiSoftwareKey>,
    ) -> FfiResult<FfiKeyRotationStatement> {
        crate::guard::call_with(&[&self.poison, &new_key.poison], || {
            Ok((&core::sign_key_rotation_statement_v2(
                &statement.into(),
                &self.private,
                &new_key.private,
            )?)
                .into())
        })
    }
    pub fn sign_witness_entry(&self, entry: FfiWitnessEntry) -> FfiResult<FfiWitnessEntry> {
        call_on(&self.poison, || {
            Ok((&core::sign_witness_entry_v2(&entry.into(), &self.private)?).into())
        })
    }
    pub fn sign_verification_receipt(
        &self,
        receipt: FfiVerificationReceipt,
    ) -> FfiResult<FfiVerificationReceipt> {
        call_on(&self.poison, || {
            Ok((&core::sign_verification_receipt_v2(&receipt.into(), &self.private)?).into())
        })
    }
    pub fn sign_prepared_verification_receipt(
        &self,
        data: Vec<u8>,
        head: FfiReceiptHead,
    ) -> FfiResult<FfiVerificationReceipt> {
        call_on(&self.poison, || {
            Ok(
                (&core::sign_prepared_verification_receipt_v2(&data, &head.into(), &self.private)?)
                    .into(),
            )
        })
    }
    pub fn sign_transaction_receipt_party(
        &self,
        receipt: FfiTransactionReceipt,
        party_id: String,
    ) -> FfiResult<FfiTransactionReceiptSignature> {
        call_on(&self.poison, || {
            let s =
                core::sign_transaction_receipt_party_v2(&receipt.into(), &party_id, &self.private)?;
            Ok(FfiTransactionReceiptSignature {
                party_id: s.party_id,
                signature: (&s.signature).into(),
            })
        })
    }
}

// ---- external-signer typed signing (blocking; run on an SDK worker) -----

#[uniffi::export]
pub fn ffi_sign_delegation_cert_with_signer(
    cancel: Arc<FfiCancelToken>,
    cert: FfiDelegationCert,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiDelegationCert> {
    call(|| {
        Ok((&core::sign_delegation_cert_v2_with_signer(
            cancel.context(),
            &cert.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_proof_bundle_with_signer(
    cancel: Arc<FfiCancelToken>,
    bundle: FfiProofBundle,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiProofBundle> {
    call(|| {
        Ok((&core::sign_proof_bundle_v2_with_signer(
            cancel.context(),
            &bundle.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_revocation_list_with_signer(
    cancel: Arc<FfiCancelToken>,
    list: FfiRevocationList,
    bound_issuer_id: String,
    bound_status_key: FfiPublicKey,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiRevocationList> {
    call(|| {
        Ok((&core::sign_revocation_list_v2_with_signer(
            cancel.context(),
            &list.into(),
            &bound_issuer_id,
            &bound_status_key.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_revocation_push_with_signer(
    cancel: Arc<FfiCancelToken>,
    push: FfiRevocationPush,
    bound_issuer_id: String,
    bound_status_key: FfiPublicKey,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiRevocationPush> {
    call(|| {
        Ok((&core::sign_revocation_push_v2_with_signer(
            cancel.context(),
            &push.into(),
            &bound_issuer_id,
            &bound_status_key.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_key_rotation_statement_with_signers(
    cancel: Arc<FfiCancelToken>,
    statement: FfiKeyRotationStatement,
    old_signer: Arc<dyn FfiSigner>,
    new_signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiKeyRotationStatement> {
    call(|| {
        Ok((&core::sign_key_rotation_statement_v2_with_signers(
            cancel.context(),
            &statement.into(),
            &Foreign(old_signer),
            &Foreign(new_signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_witness_entry_with_signer(
    cancel: Arc<FfiCancelToken>,
    entry: FfiWitnessEntry,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiWitnessEntry> {
    call(|| {
        Ok((&core::sign_witness_entry_v2_with_signer(
            cancel.context(),
            &entry.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_verification_receipt_with_signer(
    cancel: Arc<FfiCancelToken>,
    receipt: FfiVerificationReceipt,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiVerificationReceipt> {
    call(|| {
        Ok((&core::sign_verification_receipt_v2_with_signer(
            cancel.context(),
            &receipt.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_prepared_verification_receipt_with_signer(
    cancel: Arc<FfiCancelToken>,
    data: Vec<u8>,
    head: FfiReceiptHead,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiVerificationReceipt> {
    call(|| {
        Ok((&core::sign_prepared_verification_receipt_v2_with_signer(
            cancel.context(),
            &data,
            &head.into(),
            &Foreign(signer),
        )?)
            .into())
    })
}
#[uniffi::export]
pub fn ffi_sign_transaction_receipt_party_with_signer(
    cancel: Arc<FfiCancelToken>,
    receipt: FfiTransactionReceipt,
    party_id: String,
    signer: Arc<dyn FfiSigner>,
) -> FfiResult<FfiTransactionReceiptSignature> {
    call(|| {
        let s = core::sign_transaction_receipt_party_v2_with_signer(
            cancel.context(),
            &receipt.into(),
            &party_id,
            &Foreign(signer),
        )?;
        Ok(FfiTransactionReceiptSignature {
            party_id: s.party_id,
            signature: (&s.signature).into(),
        })
    })
}

// ---- shared typed signing over any FfiSigner (callers guard) --

pub(crate) fn sign_delegation_cert(
    c: &FfiCancelToken,
    cert: FfiDelegationCert,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiDelegationCert> {
    Ok(
        (&core::sign_delegation_cert_v2_with_signer(c.context(), &cert.into(), &Foreign(s))?)
            .into(),
    )
}
pub(crate) fn sign_proof_bundle(
    c: &FfiCancelToken,
    bundle: FfiProofBundle,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiProofBundle> {
    Ok((&core::sign_proof_bundle_v2_with_signer(c.context(), &bundle.into(), &Foreign(s))?).into())
}
pub(crate) fn sign_revocation_list(
    c: &FfiCancelToken,
    list: FfiRevocationList,
    issuer: String,
    key: FfiPublicKey,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiRevocationList> {
    Ok((&core::sign_revocation_list_v2_with_signer(
        c.context(),
        &list.into(),
        &issuer,
        &key.into(),
        &Foreign(s),
    )?)
        .into())
}
pub(crate) fn sign_revocation_push(
    c: &FfiCancelToken,
    push: FfiRevocationPush,
    issuer: String,
    key: FfiPublicKey,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiRevocationPush> {
    Ok((&core::sign_revocation_push_v2_with_signer(
        c.context(),
        &push.into(),
        &issuer,
        &key.into(),
        &Foreign(s),
    )?)
        .into())
}
pub(crate) fn sign_key_rotation_statement(
    c: &FfiCancelToken,
    st: FfiKeyRotationStatement,
    old: Arc<dyn FfiSigner>,
    new: Arc<dyn FfiSigner>,
) -> FfiResult<FfiKeyRotationStatement> {
    Ok((&core::sign_key_rotation_statement_v2_with_signers(
        c.context(),
        &st.into(),
        &Foreign(old),
        &Foreign(new),
    )?)
        .into())
}
pub(crate) fn sign_witness_entry(
    c: &FfiCancelToken,
    e: FfiWitnessEntry,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiWitnessEntry> {
    Ok((&core::sign_witness_entry_v2_with_signer(c.context(), &e.into(), &Foreign(s))?).into())
}
pub(crate) fn sign_verification_receipt(
    c: &FfiCancelToken,
    r: FfiVerificationReceipt,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiVerificationReceipt> {
    Ok(
        (&core::sign_verification_receipt_v2_with_signer(c.context(), &r.into(), &Foreign(s))?)
            .into(),
    )
}
pub(crate) fn sign_prepared_verification_receipt(
    c: &FfiCancelToken,
    data: Vec<u8>,
    head: FfiReceiptHead,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiVerificationReceipt> {
    Ok((&core::sign_prepared_verification_receipt_v2_with_signer(
        c.context(),
        &data,
        &head.into(),
        &Foreign(s),
    )?)
        .into())
}
pub(crate) fn sign_transaction_receipt_party(
    c: &FfiCancelToken,
    r: FfiTransactionReceipt,
    party: String,
    s: Arc<dyn FfiSigner>,
) -> FfiResult<FfiTransactionReceiptSignature> {
    let sig = core::sign_transaction_receipt_party_v2_with_signer(
        c.context(),
        &r.into(),
        &party,
        &Foreign(s),
    )?;
    Ok(FfiTransactionReceiptSignature {
        party_id: sig.party_id,
        signature: (&sig.signature).into(),
    })
}
