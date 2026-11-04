//! Foreign trust, audience, and status evidence providers for live verification.

use std::sync::Arc;

use ratify_protocol::v2::{self as core, V2Context};

use crate::keys::FfiPublicKey;
use crate::challenge_issuance::FfiExpectedChallenge;
use crate::objects::{FfiDelegationCert, FfiProofBundle, FfiStatusEvidenceObject};
use crate::store::FfiStoreContext;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiProviderError {
    #[error("provider failed: {detail}")]
    Failed { detail: String },
    #[error("provider callback cancelled")]
    Cancelled,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiProviderError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { detail: e.reason }
    }
}

/// A pure, side-effect-free check of verifier-authenticated receiver bindings.
#[uniffi::export(with_foreign)]
pub trait FfiReceiverBindingHook: Send + Sync {
    fn validate(&self, bundle: FfiProofBundle, expected: FfiExpectedChallenge) -> Result<(), FfiProviderError>;
}

pub(crate) fn receiver_binding_callback(hook: Arc<dyn FfiReceiverBindingHook>) -> core::V2ReceiverBindingHook {
    Arc::new(move |bundle, expected| {
        hook.validate(FfiProofBundle::from(bundle), FfiExpectedChallenge::from(expected.clone()))
            .map_err(|e| core::V2ProviderError::new(e.to_string()))
    })
}

#[derive(uniffi::Record)]
pub struct FfiTrustResolution {
    pub outcome: String,
    pub root_key: FfiPublicKey,
}

#[uniffi::export(with_foreign)]
pub trait FfiTrustProvider: Send + Sync {
    fn resolve(
        &self,
        chain: Vec<FfiDelegationCert>,
        context: Arc<FfiStoreContext>,
    ) -> Result<FfiTrustResolution, FfiProviderError>;
}

pub(crate) fn trust_callback(provider: Arc<dyn FfiTrustProvider>) -> core::V2TrustProvider {
    Arc::new(move |ctx: &V2Context, chain| {
        let chain = chain.iter().map(FfiDelegationCert::from).collect();
        let result = provider.resolve(chain, FfiStoreContext::new(ctx))
            .map_err(|e| core::V2ProviderError::new(e.to_string()))?;
        Ok(core::V2TrustResolution {
            outcome: core::V2TrustOutcome::parse(&result.outcome).unwrap_or(core::V2TrustOutcome::Ambiguous),
            root_key: result.root_key.into(),
        })
    })
}

#[derive(uniffi::Record)]
pub struct FfiDeferredConstraint {
    pub delegation_index: u64,
    pub constraint_index: u64,
    pub issuer_id: String,
    pub cert_id: String,
    pub kind: String,
    pub canonical_json: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiAudienceMembership {
    pub delegation_index: u64,
    pub constraint_index: u64,
    pub receiver_id: String,
    pub trust_domain_ids: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub evidence_digest: String,
}

#[uniffi::export(with_foreign)]
pub trait FfiAudienceProvider: Send + Sync {
    fn memberships(
        &self,
        deferred: Vec<FfiDeferredConstraint>,
        receiver_id: String,
        context: Arc<FfiStoreContext>,
    ) -> Result<Vec<FfiAudienceMembership>, FfiProviderError>;
}

pub(crate) fn audience_callback(provider: Arc<dyn FfiAudienceProvider>) -> core::V2AudienceProvider {
    Arc::new(move |ctx: &V2Context, deferred, receiver_id| {
        let input = deferred.iter().map(|d| FfiDeferredConstraint {
            delegation_index: d.delegation_index as u64,
            constraint_index: d.constraint_index as u64,
            issuer_id: d.issuer_id.clone(),
            cert_id: d.cert_id.clone(),
            kind: d.kind.clone(),
            canonical_json: d.canonical_json.clone(),
        }).collect();
        provider.memberships(input, receiver_id.into(), FfiStoreContext::new(ctx))
            .map_err(|e| core::V2ProviderError::new(e.to_string()))?
            .into_iter().map(|m| {
                Ok(core::V2AudienceMembership {
                    delegation_index: usize::try_from(m.delegation_index)
                        .map_err(|_| core::V2ProviderError::new("delegation index exceeds platform size"))?,
                    constraint_index: usize::try_from(m.constraint_index)
                        .map_err(|_| core::V2ProviderError::new("constraint index exceeds platform size"))?,
                    receiver_id: m.receiver_id,
                    trust_domain_ids: m.trust_domain_ids,
                    issued_at: m.issued_at,
                    expires_at: m.expires_at,
                    evidence_digest: m.evidence_digest,
                })
            }).collect()
    })
}

#[derive(uniffi::Record)]
pub struct FfiCertificateRef {
    pub issuer_id: String,
    pub cert_id: String,
}

#[derive(uniffi::Record)]
pub struct FfiStatusEvidenceRequest {
    pub issuer_id: String,
    pub status_key_epoch: u64,
    pub status_key_id: String,
    pub refs: Vec<FfiCertificateRef>,
}

#[uniffi::export(with_foreign)]
pub trait FfiStatusEvidenceProvider: Send + Sync {
    fn provide(
        &self,
        request: FfiStatusEvidenceRequest,
        context: Arc<FfiStoreContext>,
    ) -> Result<Vec<FfiStatusEvidenceObject>, FfiProviderError>;
}

pub(crate) fn status_callback(provider: Arc<dyn FfiStatusEvidenceProvider>) -> core::V2StatusEvidenceProvider {
    Arc::new(move |ctx: &V2Context, request| {
        let request = FfiStatusEvidenceRequest {
            issuer_id: request.issuer_id.clone(),
            status_key_epoch: request.status_key_epoch,
            status_key_id: request.status_key_id.clone(),
            refs: request.refs.iter().map(|r| FfiCertificateRef {
                issuer_id: r.issuer_id.clone(),
                cert_id: r.cert_id.clone(),
            }).collect(),
        };
        let objects = provider.provide(request, FfiStoreContext::new(ctx))
            .map_err(|e| core::V2StatusProviderError::new(e.to_string()))?
            .into_iter().map(|o| core::V2StatusEvidenceObject { object_type: o.object_type, wire: o.wire }).collect();
        Ok(core::V2StatusEvidenceBatch { objects })
    })
}
