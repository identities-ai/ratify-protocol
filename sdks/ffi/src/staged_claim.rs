//! Sealed claim ownership for the direct staged mobile API.

use std::sync::Arc;

use ratify_protocol::v2::{self as core, V2EvaluationToken};

use crate::claim::{FfiChallengeClaim, FfiClaimDisposition, FfiClaimStore, FfiRateReservationStore,
    ForeignBarrierClaimStore, ForeignClaimStore, ForeignRateReservationStore};
use crate::challenge_issuance::FfiExpectedChallenge;
use crate::context::{FfiCancelToken, FfiContextPolicy};
use crate::error::{protocol, FfiResult};
use crate::evaluator::FfiConstraintContext;
use crate::guard::{call, call_token_on, Poison, TokenBusy};
use crate::keys::FfiPublicKey;
use crate::live_verify::FfiPreflightResult;
use crate::live_providers::{FfiAudienceMembership, FfiDeferredConstraint};
use crate::objects::FfiStatusEvidenceEntry;
use crate::reference_store::FfiReferenceStoreFailure;
use crate::status::evidence_out;

#[derive(uniffi::Object)]
pub struct FfiEvaluationToken {
    pub(crate) inner: V2EvaluationToken,
    pub(crate) poison: Poison,
    pub(crate) busy: TokenBusy,
}

#[derive(uniffi::Record)]
pub struct FfiStagedClaim {
    pub claim: FfiChallengeClaim,
    pub disposition: FfiClaimDisposition,
    pub evaluation_token: Option<Arc<FfiEvaluationToken>>,
}

#[derive(uniffi::Record)]
pub struct FfiLocalAuthorizationOptions {
    pub future_skew_seconds: i64,
    pub required_scope: String,
    pub trusted_root_id: String,
    pub trusted_root_key: FfiPublicKey,
    pub trust_configured: bool,
    pub context: FfiConstraintContext,
    pub tzdb_version: String,
    pub context_policy: Option<Arc<FfiContextPolicy>>,
    pub expected_challenge: Option<FfiExpectedChallenge>,
    pub claim_token: Arc<FfiEvaluationToken>,
}

#[derive(uniffi::Record)]
pub struct FfiCertificateStatusCheck {
    pub delegation_index: u64,
    pub issuer_id: String,
    pub subject_id: String,
    pub cert_id: String,
}

#[derive(uniffi::Record)]
pub struct FfiLocalPolicyFailure {
    pub status: String,
    pub reason: String,
    pub detail: String,
}

#[derive(uniffi::Record)]
pub struct FfiLocalAuthorizationAssessment {
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub agent_id: String,
    pub root_id: String,
    pub required_scope: String,
    pub delegation_digest: Vec<u8>,
    pub effective_scope: Vec<String>,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub status_assessment: String,
    pub delegation_valid_until: i64,
    pub local_time_valid_until: i64,
    pub extension_valid_until: i64,
    pub status_fresh_until: i64,
    pub audience_fresh_until: i64,
    pub status_evidence: Vec<FfiStatusEvidenceEntry>,
    pub audience_evidence_digests: Vec<String>,
    pub rate_store_unavailable: bool,
    pub rate_admission_deferred: bool,
    pub status_checks: Vec<FfiCertificateStatusCheck>,
    pub deferred: Vec<FfiDeferredConstraint>,
    pub local_policy_failure: Option<FfiLocalPolicyFailure>,
    pub status: String,
    pub reason: String,
    pub detail: String,
}

#[derive(uniffi::Record)]
pub struct FfiFinalizeReply {
    pub finalized: Option<bool>,
    pub failure: Option<FfiReferenceStoreFailure>,
}

impl From<core::V2LocalAuthorizationAssessment> for FfiLocalAuthorizationAssessment {
    fn from(a: core::V2LocalAuthorizationAssessment) -> Self {
        Self {
            bundle_hash: a.bundle_hash,
            issuer_ids: a.issuer_ids,
            agent_id: a.agent_id,
            root_id: a.root_id,
            required_scope: a.required_scope,
            delegation_digest: a.delegation_digest,
            effective_scope: a.effective_scope,
            context_assessment: a.context_assessment,
            context_policy_digest: a.context_policy_digest,
            status_assessment: a.status_assessment,
            delegation_valid_until: a.delegation_valid_until,
            local_time_valid_until: a.local_time_valid_until,
            extension_valid_until: a.extension_valid_until,
            status_fresh_until: a.status_fresh_until,
            audience_fresh_until: a.audience_fresh_until,
            status_evidence: a.status_evidence.iter().map(evidence_out).collect(),
            audience_evidence_digests: a.audience_evidence_digests,
            rate_store_unavailable: a.rate_store_unavailable,
            rate_admission_deferred: a.rate_admission_deferred,
            status_checks: a.status_checks.into_iter().map(|c| FfiCertificateStatusCheck {
                delegation_index: c.delegation_index as u64,
                issuer_id: c.issuer_id, subject_id: c.subject_id, cert_id: c.cert_id,
            }).collect(),
            deferred: a.deferred.into_iter().map(|d| FfiDeferredConstraint {
                delegation_index: d.delegation_index as u64,
                constraint_index: d.constraint_index as u64,
                issuer_id: d.issuer_id, cert_id: d.cert_id, kind: d.kind,
                canonical_json: d.canonical_json,
            }).collect(),
            local_policy_failure: a.local_policy_failure.map(|f| FfiLocalPolicyFailure {
                status: f.status, reason: f.reason, detail: f.detail,
            }),
            status: a.status,
            reason: a.reason,
            detail: a.detail,
        }
    }
}

#[uniffi::export]
pub fn ffi_claim_proof_bundle(
    bundle: Vec<u8>,
    preflight: Arc<FfiPreflightResult>,
    configured_namespace: String,
    configured_replay_epoch: i64,
    now: i64,
    store: Arc<dyn FfiClaimStore>,
    token: Arc<FfiCancelToken>,
) -> FfiResult<FfiStagedClaim> {
    call(|| {
        let bundle = core::decode_proof_bundle_v2(&bundle)?;
        let (claim, disposition, evaluation_token) = core::claim_proof_bundle_v2(
            token.context(), &ForeignClaimStore(store), &bundle, &preflight.inner,
            &configured_namespace, configured_replay_epoch, now,
        )?;
        Ok(FfiStagedClaim {
            claim: claim.into(),
            disposition: disposition.into(),
            evaluation_token: evaluation_token.map(|inner| Arc::new(FfiEvaluationToken {
                inner, poison: Poison::default(), busy: TokenBusy::default(),
            })),
        })
    })
}

#[uniffi::export]
pub fn ffi_evaluate_local_authorization(
    bundle: Vec<u8>,
    options: FfiLocalAuthorizationOptions,
) -> FfiResult<FfiLocalAuthorizationAssessment> {
    call_token_on(&options.claim_token.poison, &options.claim_token.busy, || {
        if options.context_policy.as_ref().is_some_and(|p| p.poison.is_set()) {
            return Err(protocol(core::V2ErrorClass::ConfigurationInvalid, "context policy handle is poisoned"));
        }
        let bundle = core::decode_proof_bundle_v2(&bundle)?;
        let expected_challenge = options.expected_challenge.map(TryInto::try_into).transpose()
            .map_err(|_| protocol(core::V2ErrorClass::ConfigurationInvalid, "expected challenge is invalid"))?;
        let core_options = core::V2LocalAuthorizationOptions {
            future_skew_seconds: options.future_skew_seconds,
            required_scope: options.required_scope,
            trusted_root_id: options.trusted_root_id,
            trusted_root_key: options.trusted_root_key.into(),
            trust_configured: options.trust_configured,
            context: options.context.into(),
            tzdb_version: options.tzdb_version,
            context_policy: options.context_policy.map(|p| p.inner.clone()),
            expected_challenge,
            claim_token: Some(options.claim_token.inner.clone()),
        };
        Ok(core::evaluate_proof_bundle_v2_local_authorization(&bundle, &core_options).into())
    })
}

#[uniffi::export]
pub fn ffi_resolve_claim_after_audience(
    token: Arc<FfiEvaluationToken>,
    memberships: Vec<FfiAudienceMembership>,
) -> FfiResult<FfiLocalAuthorizationAssessment> {
    call_token_on(&token.poison, &token.busy, || {
        let memberships = memberships.into_iter().map(|m| {
            Ok(core::V2AudienceMembership {
                delegation_index: usize::try_from(m.delegation_index)
                    .map_err(|_| protocol(core::V2ErrorClass::ConfigurationInvalid, "delegation index exceeds platform size"))?,
                constraint_index: usize::try_from(m.constraint_index)
                    .map_err(|_| protocol(core::V2ErrorClass::ConfigurationInvalid, "constraint index exceeds platform size"))?,
                receiver_id: m.receiver_id, trust_domain_ids: m.trust_domain_ids,
                issued_at: m.issued_at, expires_at: m.expires_at, evidence_digest: m.evidence_digest,
            })
        }).collect::<FfiResult<Vec<_>>>()?;
        Ok(core::resolve_claim_proof_bundle_v2_after_audience(&token.inner, &memberships)?.into())
    })
}

#[uniffi::export]
pub fn ffi_resolve_claim_after_rate(
    token: Arc<FfiEvaluationToken>,
    store: Option<Arc<dyn FfiRateReservationStore>>,
    cancel: Arc<FfiCancelToken>,
) -> FfiResult<FfiLocalAuthorizationAssessment> {
    call_token_on(&token.poison, &token.busy, || {
        let store = store.map(ForeignRateReservationStore);
        Ok(core::resolve_claim_proof_bundle_v2_after_rate(
            cancel.context(), store.as_ref().map(|s| s as &dyn core::V2RateReservationStore),
            &token.inner,
        )?.into())
    })
}

#[uniffi::export]
pub fn ffi_resolve_claim_after_rate_barrier(
    token: Arc<FfiEvaluationToken>,
    store: Arc<dyn FfiClaimStore>,
    cancel: Arc<FfiCancelToken>,
) -> FfiResult<FfiLocalAuthorizationAssessment> {
    call_token_on(&token.poison, &token.busy, || {
        let store = ForeignBarrierClaimStore(ForeignClaimStore(store));
        Ok(core::resolve_claim_proof_bundle_v2_after_rate(
            cancel.context(), Some(&store), &token.inner,
        )?.into())
    })
}

#[uniffi::export]
pub fn ffi_finalize_claim_proof_bundle(
    token: Arc<FfiEvaluationToken>,
    store: Arc<dyn FfiClaimStore>,
    cancel: Arc<FfiCancelToken>,
    terminal_result: Vec<u8>,
    receipt_body: Vec<u8>,
) -> FfiResult<FfiFinalizeReply> {
    call_token_on(&token.poison, &token.busy, || {
        let result = core::finalize_claim_proof_bundle_v2(cancel.context(),
            &ForeignClaimStore(store), &token.inner, &terminal_result, &receipt_body);
        Ok(match result {
            Ok(finalized) => FfiFinalizeReply { finalized: Some(finalized), failure: None },
            Err(error) => FfiFinalizeReply { finalized: None, failure: Some(error.into()) },
        })
    })
}

#[uniffi::export]
pub fn ffi_finalize_claim_proof_bundle_barrier(
    token: Arc<FfiEvaluationToken>,
    store: Arc<dyn FfiClaimStore>,
    cancel: Arc<FfiCancelToken>,
    terminal_result: Vec<u8>,
    receipt_body: Vec<u8>,
) -> FfiResult<FfiFinalizeReply> {
    call_token_on(&token.poison, &token.busy, || {
        let result = core::finalize_claim_proof_bundle_v2(cancel.context(),
            &ForeignBarrierClaimStore(ForeignClaimStore(store)), &token.inner,
            &terminal_result, &receipt_body);
        Ok(match result {
            Ok(finalized) => FfiFinalizeReply { finalized: Some(finalized), failure: None },
            Err(error) => FfiFinalizeReply { finalized: None, failure: Some(error.into()) },
        })
    })
}
