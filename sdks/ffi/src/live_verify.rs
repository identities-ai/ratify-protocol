//! Live verification entry point. The host supplies the durable claim store.

use std::collections::BTreeMap;
use std::sync::Arc;

use ratify_protocol::v2::{self as core, V2VerifyCallbacks, V2VerifyRequest};

use crate::challenge_issuance::FfiExpectedChallenge;
use crate::claim::{FfiChallengeClaim, FfiClaimDisposition, FfiClaimStore, FfiCommittedOutcome, FfiRateReservationStore, ForeignBarrierClaimStore, ForeignClaimStore, ForeignRateReservationStore};
use crate::context::{FfiCancelToken, FfiContextPolicy};
use crate::error::{protocol, FfiResult};
use crate::evaluator::{FfiConstraintContext, FfiConstraintEvaluatorRegistry};
use crate::guard::call;
use crate::journal::{FfiJournalStore, ForeignJournalStore};
use crate::keys::FfiPublicKey;
use crate::live_providers::{audience_callback, receiver_binding_callback, status_callback, trust_callback, FfiAudienceProvider, FfiReceiverBindingHook, FfiStatusEvidenceProvider, FfiTrustProvider};
use crate::status::FfiStatusPolicy;

#[derive(uniffi::Record)]
pub struct FfiStatusKeyConfig {
    pub epoch: u64,
    pub key: FfiPublicKey,
}

#[derive(uniffi::Record)]
pub struct FfiLiveVerifyRequest {
    pub bundle: Vec<u8>,
    pub expected: Option<FfiExpectedChallenge>,
    pub context_policy: Option<Arc<FfiContextPolicy>>,
    pub required_scope: String,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub now: i64,
    pub max_challenge_age_seconds: i64,
    pub future_skew_seconds: i64,
    pub context: FfiConstraintContext,
    pub tzdb_version: String,
    pub status_keys: std::collections::HashMap<String, FfiStatusKeyConfig>,
    pub status_policy: FfiStatusPolicy,
    pub constraint_evaluators: Option<Arc<FfiConstraintEvaluatorRegistry>>,
}

impl TryFrom<FfiLiveVerifyRequest> for V2VerifyRequest {
    type Error = crate::error::FfiError;

    fn try_from(r: FfiLiveVerifyRequest) -> Result<Self, Self::Error> {
        if r.context_policy.as_ref().is_some_and(|p| p.poison.is_set()) {
            return Err(protocol(core::V2ErrorClass::ConfigurationInvalid, "context policy handle is poisoned"));
        }
        if r.constraint_evaluators.as_ref().is_some_and(|p| p.poison.is_set()) {
            return Err(protocol(core::V2ErrorClass::ConfigurationInvalid, "constraint evaluator registry is poisoned"));
        }
        let expected = r.expected.map(TryInto::try_into).transpose()
            .map_err(|_| protocol(core::V2ErrorClass::ConfigurationInvalid, "expected challenge is invalid"))?;
        Ok(Self {
            bundle: r.bundle,
            expected,
            context_policy: r.context_policy.map(|p| p.inner.clone()),
            required_scope: r.required_scope,
            verifier_namespace: r.verifier_namespace,
            replay_epoch: r.replay_epoch,
            verifier_id: r.verifier_id,
            now: r.now,
            max_challenge_age_seconds: r.max_challenge_age_seconds,
            future_skew_seconds: r.future_skew_seconds,
            context: r.context.into(),
            tzdb_version: r.tzdb_version,
            status_keys: r.status_keys.into_iter().map(|(issuer, config)| (issuer, core::V2StatusKeyConfig {
                epoch: config.epoch,
                key: config.key.into(),
            })).collect::<BTreeMap<_, _>>(),
            status_policy: r.status_policy.into(),
            constraint_evaluators: r.constraint_evaluators.map(|p| p.inner.clone()),
            ..Default::default()
        })
    }
}

#[derive(uniffi::Record)]
pub struct FfiLiveVerifyOutcome {
    pub stage: String,
    pub error_class: Option<String>,
    pub error_detail: Option<String>,
    pub disposition: Option<FfiClaimDisposition>,
    pub claim: FfiChallengeClaim,
    pub committed: Option<Arc<FfiCommittedOutcome>>,
}

impl From<core::V2VerifyOutcome> for FfiLiveVerifyOutcome {
    fn from(o: core::V2VerifyOutcome) -> Self {
        Self {
            stage: o.stage.as_str().into(),
            error_class: o.error_class.map(|c| c.as_str().into()),
            error_detail: o.error.map(|e| e.message),
            disposition: o.disposition.map(Into::into),
            claim: o.claim.into(),
            committed: o.committed.map(FfiCommittedOutcome::new),
        }
    }
}

/// Sealed successful preflight state. Only the core can construct it.
#[derive(uniffi::Object)]
pub struct FfiPreflightResult {
    pub(crate) inner: core::V2PreflightResult,
}

#[derive(uniffi::Record)]
pub struct FfiPreflightRequest {
    pub bundle: Vec<u8>,
    pub expected: Option<FfiExpectedChallenge>,
    pub context_policy: Option<Arc<FfiContextPolicy>>,
    pub required_scope: String,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub now: i64,
    pub max_challenge_age_seconds: i64,
    pub future_skew_seconds: i64,
}

#[uniffi::export]
pub fn ffi_preflight_proof_bundle(request: FfiPreflightRequest) -> FfiResult<Arc<FfiPreflightResult>> {
    call(|| {
        if request.context_policy.as_ref().is_some_and(|p| p.poison.is_set()) {
            return Err(protocol(core::V2ErrorClass::ConfigurationInvalid, "context policy handle is poisoned"));
        }
        let expected = request.expected.map(TryInto::try_into).transpose()
            .map_err(|_| protocol(core::V2ErrorClass::ConfigurationInvalid, "expected challenge is invalid"))?;
        let bundle = core::decode_proof_bundle_v2(&request.bundle)?;
        let inner = core::preflight_proof_bundle_v2(
            &bundle,
            expected.as_ref(),
            request.context_policy.as_ref().map(|p| &p.inner),
            &request.required_scope,
            &request.verifier_namespace,
            request.replay_epoch,
            &request.verifier_id,
            request.now,
            request.max_challenge_age_seconds,
            request.future_skew_seconds,
        )?;
        Ok(Arc::new(FfiPreflightResult { inner }))
    })
}

#[uniffi::export]
pub fn ffi_live_verify_proof_bundle(
    request: FfiLiveVerifyRequest,
    claim_store: Option<Arc<dyn FfiClaimStore>>,
    receiver_binding: Option<Arc<dyn FfiReceiverBindingHook>>,
    trust: Option<Arc<dyn FfiTrustProvider>>,
    audience: Option<Arc<dyn FfiAudienceProvider>>,
    status_evidence: Option<Arc<dyn FfiStatusEvidenceProvider>>,
    status_journal: Option<Arc<dyn FfiJournalStore>>,
    rate: Option<Arc<dyn FfiRateReservationStore>>,
    token: Arc<FfiCancelToken>,
) -> FfiResult<FfiLiveVerifyOutcome> {
    call(|| {
        let request = request.try_into()?;
        Ok(verify(request, claim_store.map(|store| Arc::new(ForeignClaimStore(store)) as Arc<dyn core::ClaimStoreV2>),
            rate.map(|s| Arc::new(ForeignRateReservationStore(s)) as Arc<dyn core::V2RateReservationStore>),
            receiver_binding, trust, audience, status_evidence, status_journal, token))
    })
}

/// The claim and rate capability views refer to the same foreign store object.
#[uniffi::export]
pub fn ffi_live_verify_proof_bundle_barrier(
    request: FfiLiveVerifyRequest,
    claim_store: Arc<dyn FfiClaimStore>,
    receiver_binding: Option<Arc<dyn FfiReceiverBindingHook>>,
    trust: Option<Arc<dyn FfiTrustProvider>>,
    audience: Option<Arc<dyn FfiAudienceProvider>>,
    status_evidence: Option<Arc<dyn FfiStatusEvidenceProvider>>,
    status_journal: Option<Arc<dyn FfiJournalStore>>,
    token: Arc<FfiCancelToken>,
) -> FfiResult<FfiLiveVerifyOutcome> {
    call(|| {
        let request = request.try_into()?;
        let store = Arc::new(ForeignBarrierClaimStore(ForeignClaimStore(claim_store)));
        Ok(verify(request, Some(store.clone()), Some(store), receiver_binding, trust,
            audience, status_evidence, status_journal, token))
    })
}

fn verify(
    request: V2VerifyRequest,
    claim_store: Option<Arc<dyn core::ClaimStoreV2>>,
    rate: Option<Arc<dyn core::V2RateReservationStore>>,
    receiver_binding: Option<Arc<dyn FfiReceiverBindingHook>>,
    trust: Option<Arc<dyn FfiTrustProvider>>,
    audience: Option<Arc<dyn FfiAudienceProvider>>,
    status_evidence: Option<Arc<dyn FfiStatusEvidenceProvider>>,
    status_journal: Option<Arc<dyn FfiJournalStore>>,
    token: Arc<FfiCancelToken>,
) -> FfiLiveVerifyOutcome {
    let callbacks = V2VerifyCallbacks {
        claim_store,
        receiver_binding: receiver_binding.map(receiver_binding_callback),
        trust: trust.map(trust_callback),
        audience: audience.map(audience_callback),
        status_evidence: status_evidence.map(status_callback),
        status_journal: status_journal.map(|s| Arc::new(ForeignJournalStore(s)) as Arc<dyn core::SecurityJournalStoreV2>),
        rate,
        ..Default::default()
    };
    core::verify_proof_bundle_v2(token.context(), &request, &callbacks).into()
}
