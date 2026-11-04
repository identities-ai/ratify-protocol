//! Owned Part B claim records and the atomic foreign store boundary.

use std::sync::Arc;

use ratify_protocol::v2::{
    self as core, ClaimStoreV2, CommittedV2Outcome, ConstraintEvaluatorRefV2,
    StatusEvidenceEntryV2, V2AuthoritativeClock, V2ChallengeClaim, V2ClaimDisposition,
    V2ClaimResult, V2CommittedClaim, V2CommittedClaimStore, V2Context, V2EvaluationProgress,
    V2InterruptedClaim, V2RateReservation, V2RateReservationStore, V2StoreError,
};

use crate::context::FfiCancelToken;
use crate::error::FfiResult;
use crate::guard::{call, call_on, Poison};
use crate::objects::{FfiConstraintEvaluatorRef, FfiStatusEvidenceEntry};
use crate::store::{FfiStoreContext, FfiStoreError};

#[derive(uniffi::Record, Clone)]
pub struct FfiRateReservation {
    pub issuer_id: String,
    pub cert_id: String,
    pub window_s: i64,
    pub limit: i64,
}

impl From<V2RateReservation> for FfiRateReservation {
    fn from(r: V2RateReservation) -> Self {
        Self {
            issuer_id: r.issuer_id,
            cert_id: r.cert_id,
            window_s: r.window_s,
            limit: r.limit,
        }
    }
}
impl From<FfiRateReservation> for V2RateReservation {
    fn from(r: FfiRateReservation) -> Self {
        Self {
            issuer_id: r.issuer_id,
            cert_id: r.cert_id,
            window_s: r.window_s,
            limit: r.limit,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiChallengeClaim {
    pub claim_id: String,
    pub namespace: String,
    pub replay_epoch: i64,
    pub challenge_digest: String,
    pub proof_digest: String,
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub required_scope: String,
    pub context_policy_digest: String,
    pub verifier_id: String,
    pub agent_id: String,
    pub requires_rate: bool,
    pub rate_batch: Vec<FfiRateReservation>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub max_age_seconds: i64,
    pub clock_skew_seconds: i64,
    pub stream_id: Option<Vec<u8>>,
    pub stream_seq: Option<i64>,
    pub constraint_evaluators: Vec<FfiConstraintEvaluatorRef>,
}

impl From<V2ChallengeClaim> for FfiChallengeClaim {
    fn from(c: V2ChallengeClaim) -> Self {
        Self {
            claim_id: c.claim_id,
            namespace: c.namespace,
            replay_epoch: c.replay_epoch,
            challenge_digest: c.challenge_digest,
            proof_digest: c.proof_digest,
            bundle_hash: c.bundle_hash,
            issuer_ids: c.issuer_ids,
            required_scope: c.required_scope,
            context_policy_digest: c.context_policy_digest,
            verifier_id: c.verifier_id,
            agent_id: c.agent_id,
            requires_rate: c.requires_rate,
            rate_batch: c.rate_batch.into_iter().map(Into::into).collect(),
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            max_age_seconds: c.max_age_seconds,
            clock_skew_seconds: c.clock_skew_seconds,
            stream_id: c.stream_id,
            stream_seq: c.stream_seq,
            constraint_evaluators: c
                .constraint_evaluators
                .into_iter()
                .map(|e| FfiConstraintEvaluatorRef {
                    kind: e.kind,
                    profile_digest: e.profile_digest,
                })
                .collect(),
        }
    }
}

impl From<FfiChallengeClaim> for V2ChallengeClaim {
    fn from(c: FfiChallengeClaim) -> Self {
        Self {
            claim_id: c.claim_id,
            namespace: c.namespace,
            replay_epoch: c.replay_epoch,
            challenge_digest: c.challenge_digest,
            proof_digest: c.proof_digest,
            bundle_hash: c.bundle_hash,
            issuer_ids: c.issuer_ids,
            required_scope: c.required_scope,
            context_policy_digest: c.context_policy_digest,
            verifier_id: c.verifier_id,
            agent_id: c.agent_id,
            requires_rate: c.requires_rate,
            rate_batch: c.rate_batch.into_iter().map(Into::into).collect(),
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            max_age_seconds: c.max_age_seconds,
            clock_skew_seconds: c.clock_skew_seconds,
            stream_id: c.stream_id,
            stream_seq: c.stream_seq,
            constraint_evaluators: c
                .constraint_evaluators
                .into_iter()
                .map(|e| ConstraintEvaluatorRefV2 {
                    kind: e.kind,
                    profile_digest: e.profile_digest,
                })
                .collect(),
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum FfiClaimDisposition {
    Created,
    InProgress,
    TerminalReplay,
}

impl From<V2ClaimDisposition> for FfiClaimDisposition {
    fn from(d: V2ClaimDisposition) -> Self {
        match d {
            V2ClaimDisposition::Created => Self::Created,
            V2ClaimDisposition::InProgress => Self::InProgress,
            V2ClaimDisposition::TerminalReplay => Self::TerminalReplay,
        }
    }
}
impl From<FfiClaimDisposition> for V2ClaimDisposition {
    fn from(d: FfiClaimDisposition) -> Self {
        match d {
            FfiClaimDisposition::Created => Self::Created,
            FfiClaimDisposition::InProgress => Self::InProgress,
            FfiClaimDisposition::TerminalReplay => Self::TerminalReplay,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiClaimResult {
    pub disposition: FfiClaimDisposition,
    pub claimed_at: i64,
    pub owner_token: Vec<u8>,
}

impl From<V2ClaimResult> for FfiClaimResult {
    fn from(r: V2ClaimResult) -> Self {
        Self {
            disposition: r.disposition.into(),
            claimed_at: r.claimed_at,
            owner_token: r.owner_token,
        }
    }
}
impl From<FfiClaimResult> for V2ClaimResult {
    fn from(r: FfiClaimResult) -> Self {
        Self {
            disposition: r.disposition.into(),
            claimed_at: r.claimed_at,
            owner_token: r.owner_token,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiEvaluationProgress {
    pub trust_assessment: String,
    pub status_assessment: String,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub status_evidence: Vec<FfiStatusEvidenceEntry>,
}

impl From<V2EvaluationProgress> for FfiEvaluationProgress {
    fn from(p: V2EvaluationProgress) -> Self {
        Self {
            trust_assessment: p.trust_assessment,
            status_assessment: p.status_assessment,
            context_assessment: p.context_assessment,
            context_policy_digest: p.context_policy_digest,
            status_evidence: p
                .status_evidence
                .into_iter()
                .map(|e| FfiStatusEvidenceEntry {
                    issuer_id: e.issuer_id,
                    status_key_id: e.status_key_id,
                    sequence: e.sequence,
                    object_type: e.object_type,
                    digest: e.digest,
                })
                .collect(),
        }
    }
}
impl From<FfiEvaluationProgress> for V2EvaluationProgress {
    fn from(p: FfiEvaluationProgress) -> Self {
        Self {
            trust_assessment: p.trust_assessment,
            status_assessment: p.status_assessment,
            context_assessment: p.context_assessment,
            context_policy_digest: p.context_policy_digest,
            status_evidence: p
                .status_evidence
                .into_iter()
                .map(|e| StatusEvidenceEntryV2 {
                    issuer_id: e.issuer_id,
                    status_key_id: e.status_key_id,
                    sequence: e.sequence,
                    object_type: e.object_type,
                    digest: e.digest,
                })
                .collect(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiInterruptedClaim {
    pub claim: FfiChallengeClaim,
    pub claimed_at: i64,
    pub progress: FfiEvaluationProgress,
}
impl From<V2InterruptedClaim> for FfiInterruptedClaim {
    fn from(r: V2InterruptedClaim) -> Self {
        Self {
            claim: r.claim.into(),
            claimed_at: r.claimed_at,
            progress: r.progress.into(),
        }
    }
}
impl From<FfiInterruptedClaim> for V2InterruptedClaim {
    fn from(r: FfiInterruptedClaim) -> Self {
        Self {
            claim: r.claim.into(),
            claimed_at: r.claimed_at,
            progress: r.progress.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiCommittedClaim {
    pub claim: FfiChallengeClaim,
    pub terminal_result: Vec<u8>,
    pub receipt_body: Vec<u8>,
    pub allow_horizon: i64,
}
impl From<V2CommittedClaim> for FfiCommittedClaim {
    fn from(r: V2CommittedClaim) -> Self {
        Self {
            claim: r.claim.into(),
            terminal_result: r.terminal_result,
            receipt_body: r.receipt_body,
            allow_horizon: r.allow_horizon,
        }
    }
}
impl From<FfiCommittedClaim> for V2CommittedClaim {
    fn from(r: FfiCommittedClaim) -> Self {
        Self {
            claim: r.claim.into(),
            terminal_result: r.terminal_result,
            receipt_body: r.receipt_body,
            allow_horizon: r.allow_horizon,
        }
    }
}

/// The host supplies one durable object for the clock and every claim transaction.
#[uniffi::export(with_foreign)]
pub trait FfiClaimStore: Send + Sync {
    fn authoritative_time(&self, context: Arc<FfiStoreContext>) -> Result<i64, FfiStoreError>;
    fn claim(
        &self,
        claim: FfiChallengeClaim,
        context: Arc<FfiStoreContext>,
    ) -> Result<FfiClaimResult, FfiStoreError>;
    fn finalize(
        &self,
        claim_id: String,
        owner_token: Vec<u8>,
        terminal_result: Vec<u8>,
        receipt_body: Vec<u8>,
        allow_valid_until: i64,
        context: Arc<FfiStoreContext>,
    ) -> Result<bool, FfiStoreError>;
    fn record_progress(
        &self,
        claim_id: String,
        owner_token: Vec<u8>,
        progress: FfiEvaluationProgress,
        context: Arc<FfiStoreContext>,
    ) -> Result<(), FfiStoreError>;
    fn load_interrupted(
        &self,
        claim_id: String,
        context: Arc<FfiStoreContext>,
    ) -> Result<FfiInterruptedClaim, FfiStoreError>;
    fn recover_interrupted(
        &self,
        claim_id: String,
        terminal_result: Vec<u8>,
        receipt_body: Vec<u8>,
        context: Arc<FfiStoreContext>,
    ) -> Result<bool, FfiStoreError>;
}

pub(crate) struct ForeignClaimStore(pub(crate) Arc<dyn FfiClaimStore>);

impl V2AuthoritativeClock for ForeignClaimStore {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.0
            .authoritative_time(FfiStoreContext::new(ctx))
            .map_err(Into::into)
    }
}

impl ClaimStoreV2 for ForeignClaimStore {
    fn claim_v2(
        &self,
        ctx: &V2Context,
        claim: V2ChallengeClaim,
    ) -> Result<V2ClaimResult, V2StoreError> {
        self.0
            .claim(claim.into(), FfiStoreContext::new(ctx))
            .map(Into::into)
            .map_err(Into::into)
    }

    fn finalize_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError> {
        self.0
            .finalize(
                claim_id.into(),
                owner_token.into(),
                terminal_result.into(),
                receipt_body.into(),
                allow_valid_until,
                FfiStoreContext::new(ctx),
            )
            .map_err(Into::into)
    }

    fn record_v2_evaluation_progress(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError> {
        self.0
            .record_progress(
                claim_id.into(),
                owner_token.into(),
                progress.into(),
                FfiStoreContext::new(ctx),
            )
            .map_err(Into::into)
    }

    fn load_v2_interrupted_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
    ) -> Result<V2InterruptedClaim, V2StoreError> {
        self.0
            .load_interrupted(claim_id.into(), FfiStoreContext::new(ctx))
            .map(Into::into)
            .map_err(Into::into)
    }

    fn recover_interrupted_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, V2StoreError> {
        self.0
            .recover_interrupted(
                claim_id.into(),
                terminal_result.into(),
                receipt_body.into(),
                FfiStoreContext::new(ctx),
            )
            .map_err(Into::into)
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiCommittedClaimStore: Send + Sync {
    fn load_committed(
        &self,
        claim_id: String,
        context: Arc<FfiStoreContext>,
    ) -> Result<FfiCommittedClaim, FfiStoreError>;
}

pub(crate) struct ForeignCommittedClaimStore(pub(crate) Arc<dyn FfiCommittedClaimStore>);

/// Atomically reserves the complete sealed rate batch; an exact retry is idempotent.
#[uniffi::export(with_foreign)]
pub trait FfiRateReservationStore: Send + Sync {
    fn reserve(
        &self,
        claim_id: String,
        owner_token: Vec<u8>,
        bundle_hash: String,
        batch: Vec<FfiRateReservation>,
        context: Arc<FfiStoreContext>,
    ) -> Result<(), FfiStoreError>;
}

pub(crate) struct ForeignRateReservationStore(pub(crate) Arc<dyn FfiRateReservationStore>);

impl V2RateReservationStore for ForeignRateReservationStore {
    fn reserve_v2_rate_batch(&self, ctx: &V2Context, claim_id: &str, owner_token: &[u8],
                             bundle_hash: &str, batch: &[V2RateReservation]) -> Result<(), V2StoreError> {
        self.0.reserve(claim_id.into(), owner_token.into(), bundle_hash.into(),
            batch.iter().cloned().map(Into::into).collect(), FfiStoreContext::new(ctx)).map_err(Into::into)
    }
}

impl V2CommittedClaimStore for ForeignCommittedClaimStore {
    fn load_v2_committed_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
    ) -> Result<V2CommittedClaim, V2StoreError> {
        self.0
            .load_committed(claim_id.into(), FfiStoreContext::new(ctx))
            .map(Into::into)
            .map_err(Into::into)
    }
}

/// Non-actionable handoff; only the release API can produce a released decision.
#[derive(uniffi::Object)]
pub struct FfiCommittedOutcome {
    poison: Poison,
    inner: CommittedV2Outcome,
}

impl FfiCommittedOutcome {
    pub(crate) fn new(inner: CommittedV2Outcome) -> Arc<Self> {
        Arc::new(Self {
            poison: Poison::default(),
            inner,
        })
    }
}

#[uniffi::export]
impl FfiCommittedOutcome {
    pub fn claim_id(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.inner.claim_id()))
    }
    pub fn receipt_body(&self) -> FfiResult<Vec<u8>> {
        call_on(&self.poison, || Ok(self.inner.receipt_body()))
    }
    pub fn receipt_body_digest(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.inner.receipt_body_digest()))
    }
    pub fn challenge_expires_at(&self) -> FfiResult<i64> {
        call_on(&self.poison, || Ok(self.inner.challenge_expires_at()))
    }
    pub fn allow_horizon(&self) -> FfiResult<Option<i64>> {
        call_on(&self.poison, || Ok(self.inner.allow_horizon()))
    }
}

#[uniffi::export]
pub fn ffi_resume_committed_claim(
    store: Arc<dyn FfiCommittedClaimStore>,
    token: Arc<FfiCancelToken>,
    claim_id: String,
) -> FfiResult<Arc<FfiCommittedOutcome>> {
    call(|| {
        Ok(FfiCommittedOutcome::new(core::resume_committed_claim_v2(
            token.context(),
            &ForeignCommittedClaimStore(store),
            &claim_id,
        )?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct TestStore(Mutex<Vec<&'static str>>);

    impl FfiClaimStore for TestStore {
        fn authoritative_time(&self, context: Arc<FfiStoreContext>) -> Result<i64, FfiStoreError> {
            assert!(!context.is_cancelled().unwrap());
            self.0.lock().unwrap().push("time");
            Ok(42)
        }
        fn claim(
            &self,
            claim: FfiChallengeClaim,
            _: Arc<FfiStoreContext>,
        ) -> Result<FfiClaimResult, FfiStoreError> {
            assert_eq!(claim.claim_id, "claim");
            self.0.lock().unwrap().push("claim");
            Ok(FfiClaimResult {
                disposition: FfiClaimDisposition::Created,
                claimed_at: 42,
                owner_token: vec![1, 2],
            })
        }
        fn finalize(
            &self,
            claim_id: String,
            token: Vec<u8>,
            terminal: Vec<u8>,
            body: Vec<u8>,
            horizon: i64,
            _: Arc<FfiStoreContext>,
        ) -> Result<bool, FfiStoreError> {
            assert_eq!(
                (claim_id.as_str(), token, terminal, body, horizon),
                ("claim", vec![1, 2], vec![3], vec![4], 50)
            );
            self.0.lock().unwrap().push("finalize");
            Ok(true)
        }
        fn record_progress(
            &self,
            claim_id: String,
            token: Vec<u8>,
            progress: FfiEvaluationProgress,
            _: Arc<FfiStoreContext>,
        ) -> Result<(), FfiStoreError> {
            assert_eq!(
                (claim_id.as_str(), token, progress.trust_assessment.as_str()),
                ("claim", vec![1, 2], "trusted")
            );
            self.0.lock().unwrap().push("progress");
            Ok(())
        }
        fn load_interrupted(
            &self,
            claim_id: String,
            _: Arc<FfiStoreContext>,
        ) -> Result<FfiInterruptedClaim, FfiStoreError> {
            assert_eq!(claim_id, "claim");
            self.0.lock().unwrap().push("load");
            Ok(V2InterruptedClaim::default().into())
        }
        fn recover_interrupted(
            &self,
            claim_id: String,
            terminal: Vec<u8>,
            body: Vec<u8>,
            _: Arc<FfiStoreContext>,
        ) -> Result<bool, FfiStoreError> {
            assert_eq!(
                (claim_id.as_str(), terminal, body),
                ("claim", vec![3], vec![4])
            );
            self.0.lock().unwrap().push("recover");
            Ok(true)
        }
    }

    impl FfiCommittedClaimStore for TestStore {
        fn load_committed(
            &self,
            claim_id: String,
            _: Arc<FfiStoreContext>,
        ) -> Result<FfiCommittedClaim, FfiStoreError> {
            assert_eq!(claim_id, "claim");
            self.0.lock().unwrap().push("committed");
            Ok(V2CommittedClaim::default().into())
        }
    }

    impl FfiRateReservationStore for TestStore {
        fn reserve(&self, claim_id: String, owner_token: Vec<u8>, bundle_hash: String,
                   batch: Vec<FfiRateReservation>, _: Arc<FfiStoreContext>) -> Result<(), FfiStoreError> {
            assert_eq!((claim_id.as_str(), owner_token, bundle_hash.as_str()),
                ("claim", vec![1, 2], "bundle"));
            assert_eq!(batch.len(), 1);
            self.0.lock().unwrap().push("rate");
            Ok(())
        }
    }

    #[test]
    fn each_atomic_store_method_is_one_foreign_call() {
        let store = Arc::new(TestStore::default());
        let claim = ForeignClaimStore(store.clone());
        let committed = ForeignCommittedClaimStore(store.clone());
        let rate = ForeignRateReservationStore(store.clone());
        let ctx = V2Context::background();
        assert_eq!(claim.authoritative_time_v2(&ctx).unwrap(), 42);
        assert_eq!(
            claim
                .claim_v2(
                    &ctx,
                    V2ChallengeClaim {
                        claim_id: "claim".into(),
                        ..Default::default()
                    }
                )
                .unwrap()
                .owner_token,
            vec![1, 2]
        );
        assert!(claim
            .finalize_v2_claim(&ctx, "claim", &[1, 2], &[3], &[4], 50)
            .unwrap());
        claim
            .record_v2_evaluation_progress(
                &ctx,
                "claim",
                &[1, 2],
                V2EvaluationProgress {
                    trust_assessment: "trusted".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        claim.load_v2_interrupted_claim(&ctx, "claim").unwrap();
        assert!(claim
            .recover_interrupted_v2_claim(&ctx, "claim", &[3], &[4])
            .unwrap());
        committed.load_v2_committed_claim(&ctx, "claim").unwrap();
        rate.reserve_v2_rate_batch(&ctx, "claim", &[1, 2], "bundle", &[V2RateReservation {
            issuer_id: "issuer".into(), cert_id: "cert".into(), window_s: 60, limit: 2,
        }]).unwrap();
        assert_eq!(
            *store.0.lock().unwrap(),
            [
                "time",
                "claim",
                "finalize",
                "progress",
                "load",
                "recover",
                "committed",
                "rate"
            ]
        );
    }

    #[test]
    fn sealed_claim_and_progress_survive_foreign_round_trip() {
        let claim = V2ChallengeClaim {
            claim_id: "claim".into(),
            namespace: "namespace".into(),
            replay_epoch: 9,
            challenge_digest: "challenge".into(),
            proof_digest: "proof".into(),
            bundle_hash: "bundle".into(),
            issuer_ids: vec!["issuer".into()],
            required_scope: "data:read".into(),
            context_policy_digest: "context".into(),
            verifier_id: "verifier".into(),
            agent_id: "agent".into(),
            requires_rate: true,
            rate_batch: vec![V2RateReservation {
                issuer_id: "issuer".into(),
                cert_id: "cert".into(),
                window_s: 60,
                limit: 3,
            }],
            issued_at: 10,
            expires_at: 100,
            max_age_seconds: 30,
            clock_skew_seconds: 5,
            stream_id: Some(vec![1, 2]),
            stream_seq: Some(7),
            constraint_evaluators: vec![ConstraintEvaluatorRefV2 {
                kind: "example.profile.type".into(),
                profile_digest: "digest".into(),
            }],
        };
        let progress = V2EvaluationProgress {
            trust_assessment: "trusted".into(),
            status_assessment: "current".into(),
            context_assessment: "bound".into(),
            context_policy_digest: Some("context".into()),
            status_evidence: vec![StatusEvidenceEntryV2 {
                issuer_id: "issuer".into(),
                status_key_id: "key".into(),
                sequence: 4,
                object_type: 3,
                digest: "evidence".into(),
            }],
        };
        let foreign: FfiChallengeClaim = claim.clone().into();
        assert_eq!(V2ChallengeClaim::from(foreign), claim);
        let foreign: FfiEvaluationProgress = progress.clone().into();
        assert_eq!(V2EvaluationProgress::from(foreign), progress);
        let interrupted = V2InterruptedClaim {
            claim: claim.clone(),
            claimed_at: 12,
            progress,
        };
        let foreign: FfiInterruptedClaim = interrupted.clone().into();
        assert_eq!(V2InterruptedClaim::from(foreign), interrupted);
        let committed = V2CommittedClaim {
            claim,
            terminal_result: vec![3, 4],
            receipt_body: vec![5, 6],
            allow_horizon: 90,
        };
        let foreign: FfiCommittedClaim = committed.clone().into();
        assert_eq!(V2CommittedClaim::from(foreign), committed);
        for disposition in [
            V2ClaimDisposition::Created,
            V2ClaimDisposition::InProgress,
            V2ClaimDisposition::TerminalReplay,
        ] {
            let result = V2ClaimResult {
                disposition,
                claimed_at: 11,
                owner_token: vec![7, 8],
            };
            let foreign: FfiClaimResult = result.clone().into();
            assert_eq!(V2ClaimResult::from(foreign), result);
        }
    }
}
