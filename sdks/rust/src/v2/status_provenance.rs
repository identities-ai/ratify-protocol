//! Authenticated status at the verifier boundary (SPEC-v2 §6.5). Mirrors Go
//! `status_provenance_v2.go`.
//!
//! The status provider never supplies a StatusResult. For each distinct
//! issuer in the verified chain, in ascending byte order of issuer ID, the
//! verifier:
//!  1. loads the committed `SecurityJournalV2` at its anchored head and
//!     requires the caller-authenticated status key to equal the journal's
//!     current epoch binding for the issuer;
//!  2. checks role separation by complete key ID and both component digests;
//!  3. asks the provider for a bounded batch of signed lists and pushes;
//!  4. decodes every object and verifies it under the selected key (any
//!     failure rejects the whole batch);
//!  5. applies the batch, sorted by sequence, then code, then
//!     StatusEvidenceDigest, as one journal transition committed by
//!     compare-and-swap against the head loaded in step 1; on a conflict it
//!     reloads, rechecks steps 1 and 2, and reapplies the same batch exactly
//!     once more;
//!  6. derives each CertificateRef result from the committed journal state.
//!
//! A missing binding, unanchored or unmigrated journal, role violation,
//! provider error/panic, malformed/oversized/unauthenticated batch, reducer
//! rejection, store failure or panic, or compare-and-swap conflict makes every
//! reference of that issuer indeterminate/unavailable with no evidence. If
//! the caller's context ends during the stage, nothing is committed and the
//! stage reports cancellation.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use super::context::V2Context;
use super::errors::{plain, V2Error, V2Result};
use super::journal::{
    commit_security_journal_transition_v2, key_role_binding_v2, load_anchored_security_journal_v2,
    require_journal_status_key_v2, KeyRoleBindingV2, SecurityJournalStoreErrorV2,
    SecurityJournalStoreV2, SecurityJournalV2,
};
use super::limits::{MAX_STATUS_EVIDENCE_BATCH_BYTES_V2, MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2};
use super::status::{
    aggregate_certificate_status_v2, apply_revocation_list_v2, apply_revocation_push_v2,
    key_id_plain, revocation_status_for_cert_inner, RevocationStatusPolicyV2,
    RevocationStatusResultV2, V2CertificateStatusCheck, V2StatusAssessment, V2StatusRoleBindings,
    LIST, PUSH,
};
use super::status_batch::v2_status_evidence_batch_encoded_length;
use super::wire::{
    decode_revocation_list_v2, decode_revocation_push_v2, status_evidence_digest_list_v2,
    status_evidence_digest_push_v2, verify_revocation_list_v2_signature,
    verify_revocation_push_v2_signature, ProofBundleV2, RevocationListV2, RevocationPushV2,
};
use crate::types::HybridPublicKey;

/// An issuer-scoped certificate reference (Go `CertificateRefV2`, declared
/// in `verify_v2.go`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CertificateRefV2 {
    pub issuer_id: String,
    pub cert_id: String,
}

/// The caller-authenticated status-key binding for one issuer. It must equal
/// the binding retained in the security journal at that epoch, and the epoch
/// must be the issuer's current journal epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2StatusKeyConfig {
    pub epoch: u64,
    pub key: HybridPublicKey,
}

/// What the verifier asks a status provider for. It is chosen by the
/// verifier from authenticated configuration, never from the proof. `refs`
/// are the issuer's CertificateRefs in chain order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2StatusEvidenceRequest {
    pub issuer_id: String,
    pub status_key_epoch: u64,
    pub status_key_id: String,
    pub refs: Vec<CertificateRefV2>,
}

/// One signed status object exactly as received. `object_type` is 0x0003
/// (revocation list) or 0x0005 (revocation push).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2StatusEvidenceObject {
    pub object_type: u16,
    pub wire: Vec<u8>,
}

/// A provider's bounded response for one issuer. An empty batch is valid:
/// the result then comes from retained journal state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2StatusEvidenceBatch {
    pub objects: Vec<V2StatusEvidenceObject>,
}

/// A status provider's failure. Any provider failure (including a panic,
/// which the verifier contains) makes every reference of the issuer
/// unavailable; the message is diagnostic only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2StatusProviderError {
    pub message: String,
}

impl V2StatusProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        V2StatusProviderError {
            message: message.into(),
        }
    }
}

impl fmt::Display for V2StatusProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v2 status provider: {}", self.message)
    }
}

impl std::error::Error for V2StatusProviderError {}

/// The status evidence provider (Go `V2VerifyCallbacks.StatusEvidence`): a
/// shared, thread-safe closure returning a bounded batch of signed status
/// objects for one issuer. It never returns a status result.
pub type V2StatusEvidenceProvider = Arc<
    dyn Fn(
            &V2Context,
            &V2StatusEvidenceRequest,
        ) -> Result<V2StatusEvidenceBatch, V2StatusProviderError>
        + Send
        + Sync,
>;

/// Exactly the inputs Go `runV2StatusStage` reads from `V2VerifyRequest`
/// (`StatusKeys`, `StatusPolicy`) and `V2VerifyCallbacks` (`StatusEvidence`,
/// `StatusJournal`). A `None` provider or journal makes every issuer
/// unavailable, as a nil Go callback does.
#[allow(dead_code)]
pub(crate) struct V2StatusStageInputs<'a> {
    pub status_evidence: Option<&'a V2StatusEvidenceProvider>,
    pub status_journal: Option<&'a dyn SecurityJournalStoreV2>,
    pub status_keys: &'a BTreeMap<String, V2StatusKeyConfig>,
    pub status_policy: &'a RevocationStatusPolicyV2,
}

/// Go `v2StatusStageResult`. `cancelled` replaces Go's `ctx.Err()`: the
/// caller's context ended during the stage and nothing further was committed.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct V2StatusStageResult {
    pub assessment: V2StatusAssessment,
    pub cancelled: bool,
    pub queries: usize,
}

pub(crate) enum V2VerifiedStatusPayload {
    List(RevocationListV2),
    Push(RevocationPushV2),
}

pub(crate) struct V2VerifiedStatusObject {
    pub code: u16,
    pub sequence: i64,
    pub digest: Vec<u8>,
    pub payload: V2VerifiedStatusPayload,
}

fn unavailable_assessment() -> V2StatusAssessment {
    V2StatusAssessment {
        assessment: "unavailable".into(),
        reason: "status_unavailable".into(),
        evidence: Vec::new(),
        fresh_until: 0,
    }
}

/// Go `callV2JournalSafely`: a panicking store is a failure, not a crash.
fn call_journal_safely<T>(
    f: impl FnOnce() -> Result<T, SecurityJournalStoreErrorV2>,
) -> Result<T, SecurityJournalStoreErrorV2> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(SecurityJournalStoreErrorV2::Failed(V2Error::plain(
            "v2 status journal panicked",
        ))),
    }
}

/// Go `runV2StatusStage`: the status stage for every CertificateRef check.
// Called by the live and transaction verifiers (Go verify_v2.go,
// transaction_verify_v2.go), which are ported separately.
#[allow(dead_code)]
pub(crate) fn run_v2_status_stage(
    ctx: &V2Context,
    bundle: &ProofBundleV2,
    checks: &[V2CertificateStatusCheck],
    inputs: &V2StatusStageInputs<'_>,
    now: i64,
) -> V2StatusStageResult {
    let mut issuer_ids: Vec<String> = Vec::new();
    let mut refs_by_issuer: BTreeMap<String, Vec<CertificateRefV2>> = BTreeMap::new();
    for check in checks {
        if !refs_by_issuer.contains_key(&check.issuer_id) {
            issuer_ids.push(check.issuer_id.clone());
        }
        refs_by_issuer
            .entry(check.issuer_id.clone())
            .or_default()
            .push(CertificateRefV2 {
                issuer_id: check.issuer_id.clone(),
                cert_id: check.cert_id.clone(),
            });
    }
    issuer_ids.sort();
    let mut results: Vec<RevocationStatusResultV2> = checks
        .iter()
        .map(|_| RevocationStatusResultV2::unavailable())
        .collect();
    let mut roles = V2StatusRoleBindings::default();
    let mut queries = 0usize;
    let cancelled = |queries: usize| V2StatusStageResult {
        assessment: unavailable_assessment(),
        cancelled: true,
        queries,
    };
    for issuer_id in &issuer_ids {
        if ctx.is_done() {
            return cancelled(queries);
        }
        let (Some(config), Some(journal_store), Some(provider)) = (
            inputs.status_keys.get(issuer_id),
            inputs.status_journal,
            inputs.status_evidence,
        ) else {
            continue;
        };
        // 1. Anchored journal and current epoch binding.
        let loaded =
            call_journal_safely(|| Ok(load_anchored_security_journal_v2(ctx, journal_store)?));
        let mut current = match loaded {
            Ok(j) => j,
            Err(_) => {
                if ctx.is_done() {
                    return cancelled(queries);
                }
                continue;
            }
        };
        // 2. Role separation.
        if check_v2_status_role_separation(&current, issuer_id, config, bundle).is_err() {
            continue;
        }
        let status_key_id = key_id_plain(&config.key).unwrap_or_default();
        // 3. Provider.
        queries += 1;
        let request = V2StatusEvidenceRequest {
            issuer_id: issuer_id.clone(),
            status_key_epoch: config.epoch,
            status_key_id: status_key_id.clone(),
            refs: refs_by_issuer.get(issuer_id).cloned().unwrap_or_default(),
        };
        let batch = match call_v2_status_provider(ctx, provider, &request) {
            Ok(b) => b,
            Err(_) => {
                if ctx.is_done() {
                    return cancelled(queries);
                }
                continue;
            }
        };
        // 4. Authenticate.
        let Ok(objects) = verify_v2_status_evidence_batch(&batch, issuer_id, &config.key) else {
            continue;
        };
        // 5. Apply as one transition against the loaded head. On a
        // compare-and-swap conflict, reload the anchored journal, repeat the
        // binding and role-separation checks, and reapply the same batch
        // exactly once more (no second provider call); a second conflict or
        // any other failure makes the issuer unavailable.
        let mut committed: Option<SecurityJournalV2> = None;
        for attempt in 0..2 {
            if attempt > 0 {
                match call_journal_safely(|| {
                    Ok(load_anchored_security_journal_v2(ctx, journal_store)?)
                }) {
                    Ok(j) => current = j,
                    Err(_) => break,
                }
                if check_v2_status_role_separation(&current, issuer_id, config, bundle).is_err() {
                    break;
                }
            }
            match call_journal_safely(|| {
                apply_v2_status_batch_to_journal(
                    ctx,
                    journal_store,
                    &current,
                    issuer_id,
                    config,
                    &objects,
                    inputs.status_policy,
                    now,
                )
            }) {
                Ok(j) => {
                    committed = Some(j);
                    break;
                }
                Err(SecurityJournalStoreErrorV2::Conflict) => {}
                Err(SecurityJournalStoreErrorV2::Failed(_)) => break,
            }
        }
        if ctx.is_done() {
            return cancelled(queries);
        }
        let Some(committed) = committed else {
            continue;
        };
        // 6. Derive from committed state.
        for binding in &committed.status_key_history {
            if binding.issuer_id == *issuer_id {
                roles
                    .status_key_issuers
                    .insert(binding.status_key_id.clone(), issuer_id.clone());
            }
        }
        roles
            .current_status_key_ids
            .insert(issuer_id.clone(), status_key_id.clone());
        let state = committed
            .status_by_issuer
            .get(issuer_id)
            .cloned()
            .unwrap_or_default();
        for (i, check) in checks.iter().enumerate() {
            if check.issuer_id != *issuer_id {
                continue;
            }
            let result = revocation_status_for_cert_inner(
                &state,
                issuer_id,
                &check.cert_id,
                config.epoch,
                &config.key,
                inputs.status_policy,
                now,
            )
            .unwrap_or_else(|_| RevocationStatusResultV2::unavailable());
            if let Some(slot) = results.get_mut(i) {
                *slot = result;
            }
        }
    }
    let assessment = aggregate_certificate_status_v2(checks, &results, &roles, true)
        .unwrap_or_else(|_| unavailable_assessment());
    V2StatusStageResult {
        assessment,
        cancelled: false,
        queries,
    }
}

/// Go `callV2StatusProvider`: a provider panic is contained and reported as
/// a provider error.
pub(crate) fn call_v2_status_provider(
    ctx: &V2Context,
    provider: &V2StatusEvidenceProvider,
    request: &V2StatusEvidenceRequest,
) -> Result<V2StatusEvidenceBatch, V2StatusProviderError> {
    match catch_unwind(AssertUnwindSafe(|| provider(ctx, request))) {
        Ok(r) => r,
        Err(_) => Err(V2StatusProviderError::new("v2 status provider panicked")),
    }
}

/// Go `verifyV2StatusEvidenceBatch`: decodes and authenticates every object
/// before any is applied, and returns them in the deterministic application
/// order: ascending sequence, then object type code (list before push), then
/// evidence digest bytes. Errors keep the decoder's or verifier's class.
pub(crate) fn verify_v2_status_evidence_batch(
    batch: &V2StatusEvidenceBatch,
    issuer_id: &str,
    key: &HybridPublicKey,
) -> V2Result<Vec<V2VerifiedStatusObject>> {
    if batch.objects.len() > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 {
        return plain(format!(
            "v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects"
        ));
    }
    if v2_status_evidence_batch_encoded_length(batch) > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2 {
        return plain(format!(
            "v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_BYTES_V2} bytes"
        ));
    }
    let mut out = Vec::with_capacity(batch.objects.len());
    for object in &batch.objects {
        match object.object_type {
            LIST => {
                let list = decode_revocation_list_v2(&object.wire)?;
                verify_revocation_list_v2_signature(&list, issuer_id, key)?;
                let digest = status_evidence_digest_list_v2(&list)?;
                out.push(V2VerifiedStatusObject {
                    code: LIST,
                    sequence: list.sequence,
                    digest,
                    payload: V2VerifiedStatusPayload::List(list),
                });
            }
            PUSH => {
                let push = decode_revocation_push_v2(&object.wire)?;
                verify_revocation_push_v2_signature(&push, issuer_id, key)?;
                let digest = status_evidence_digest_push_v2(&push)?;
                out.push(V2VerifiedStatusObject {
                    code: PUSH,
                    sequence: push.sequence,
                    digest,
                    payload: V2VerifiedStatusPayload::Push(push),
                });
            }
            other => {
                return plain(format!(
                    "v2 status batch contains unsupported object type 0x{other:04x}"
                ))
            }
        }
    }
    out.sort_by(|a, b| (a.sequence, a.code, &a.digest).cmp(&(b.sequence, b.code, &b.digest)));
    Ok(out)
}

/// Go `applyV2StatusBatchToJournal`: applies one issuer's authenticated batch
/// to the loaded journal and commits it by compare-and-swap against the
/// loaded head. A no-op batch returns the loaded journal unchanged.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_v2_status_batch_to_journal(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    current: &SecurityJournalV2,
    issuer_id: &str,
    config: &V2StatusKeyConfig,
    objects: &[V2VerifiedStatusObject],
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> Result<SecurityJournalV2, SecurityJournalStoreErrorV2> {
    let mut next = current.clone();
    let mut state = next
        .status_by_issuer
        .get(issuer_id)
        .cloned()
        .unwrap_or_default();
    for object in objects {
        state = match &object.payload {
            V2VerifiedStatusPayload::List(list) => apply_revocation_list_v2(
                &state,
                list,
                issuer_id,
                config.epoch,
                &config.key,
                policy,
                now,
            )?,
            V2VerifiedStatusPayload::Push(push) => apply_revocation_push_v2(
                &state,
                push,
                issuer_id,
                config.epoch,
                &config.key,
                policy,
                now,
            )?,
        };
    }
    next.status_by_issuer.insert(issuer_id.to_string(), state);
    commit_security_journal_transition_v2(ctx, store, current, next)
}

/// Go `checkV2StatusRoleSeparation` (SPEC-v2 §5.4, §6.5): the configured
/// status key must be the issuer's current journal epoch binding; its global
/// role history entry must be exactly the status role; and neither its
/// complete key ID nor either component may equal the key ID or either
/// component of any other journal role or of any key in the proof (issuers,
/// subjects, agent), or the proof's verifier ID.
pub(crate) fn check_v2_status_role_separation(
    journal: &SecurityJournalV2,
    issuer_id: &str,
    config: &V2StatusKeyConfig,
    bundle: &ProofBundleV2,
) -> V2Result<()> {
    require_journal_status_key_v2(journal, issuer_id, config.epoch, &config.key)?;
    let status = key_role_binding_v2("status", &config.key)?;
    let overlaps = |other: &KeyRoleBindingV2| {
        let components = [&status.ed25519_digest, &status.ml_dsa_65_digest];
        other.key_id == status.key_id
            || components.contains(&&other.ed25519_digest)
            || components.contains(&&other.ml_dsa_65_digest)
    };
    let mut recorded = false;
    for binding in &journal.key_role_history {
        if *binding == status {
            recorded = true;
            continue;
        }
        if overlaps(binding) {
            return plain(format!(
                "status key shares a key ID or component with journal role {:?}",
                binding.role
            ));
        }
    }
    if !recorded {
        return plain("status key lacks its permanent status role in the journal");
    }
    let mut keys = vec![&bundle.agent_pub_key];
    for cert in &bundle.delegations {
        keys.push(&cert.issuer_pub_key);
        keys.push(&cert.subject_pub_key);
    }
    for key in keys {
        let chain_key = key_role_binding_v2("other", key)?;
        // No chain key may share an ID or component with any current or
        // retired status binding of any issuer (§6.5 step 2).
        for binding in journal
            .key_role_history
            .iter()
            .filter(|b| b.role == "status")
        {
            let components = [&binding.ed25519_digest, &binding.ml_dsa_65_digest];
            if chain_key.key_id == binding.key_id
                || components.contains(&&chain_key.ed25519_digest)
                || components.contains(&&chain_key.ml_dsa_65_digest)
            {
                return plain("a proof key shares a key ID or component with a status key");
            }
        }
    }
    if status.key_id == bundle.verifier_id {
        return plain("status key equals the verifier identity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::crypto::hybrid_keypair_from_seeds;
    use crate::types::{HybridPrivateKey, HybridSignature};
    use crate::v2::crypto::key_id_v2;
    use crate::v2::journal::{configure_status_key_epoch_v2, SecurityJournalHeadV2};
    use crate::v2::reference::JournalStore;
    use crate::v2::wire::{encode_revocation_list_v2, sign_revocation_list_v2, RevokedCertV2};

    const NOW: i64 = 1_800_000_000;

    /// Wraps the reference store: counts loads and compare-and-swaps and
    /// reports `conflicts` conflicts before delegating.
    struct ConflictingStore {
        inner: JournalStore,
        conflicts: AtomicUsize,
        loads: AtomicUsize,
        swaps: AtomicUsize,
    }

    impl SecurityJournalStoreV2 for ConflictingStore {
        fn load(
            &self,
            ctx: &V2Context,
        ) -> V2Result<(SecurityJournalV2, crate::v2::journal::SecurityJournalHeadV2)> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.load(ctx)
        }
        fn compare_and_swap(
            &self,
            ctx: &V2Context,
            expected: &SecurityJournalHeadV2,
            next: &SecurityJournalV2,
        ) -> Result<(), SecurityJournalStoreErrorV2> {
            self.swaps.fetch_add(1, Ordering::SeqCst);
            if self
                .conflicts
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |c| c.checked_sub(1))
                .is_ok()
            {
                return Err(SecurityJournalStoreErrorV2::Conflict);
            }
            self.inner.compare_and_swap(ctx, expected, next)
        }
    }

    struct Setup {
        store: ConflictingStore,
        issuer_id: String,
        status_public: HybridPublicKey,
        status_private: HybridPrivateKey,
        bundle: ProofBundleV2,
        checks: Vec<V2CertificateStatusCheck>,
    }

    fn setup(conflicts: usize) -> Setup {
        let (issuer_public, _) = hybrid_keypair_from_seeds(&[11; 32], &[12; 32]);
        let (status_public, status_private) = hybrid_keypair_from_seeds(&[13; 32], &[14; 32]);
        let (agent_public, _) = hybrid_keypair_from_seeds(&[15; 32], &[16; 32]);
        let issuer_id = key_id_v2(&issuer_public).expect("issuer id");
        let inner = JournalStore::new().expect("store");
        configure_status_key_epoch_v2(
            &V2Context::background(),
            &inner,
            &issuer_id,
            1,
            &status_public,
        )
        .expect("configure status key");
        let bundle = ProofBundleV2 {
            version: 2,
            verifier_id: "a".repeat(64),
            agent_id: key_id_v2(&agent_public).expect("agent id"),
            agent_pub_key: agent_public.clone(),
            delegations: Vec::new(),
            delegation_digest: Vec::new(),
            challenge: Vec::new(),
            challenge_at: NOW,
            challenge_sig: HybridSignature {
                ed25519: vec![],
                ml_dsa_65: vec![],
            },
            session_context: None,
            stream_id: None,
            stream_seq: None,
        };
        let checks = vec![V2CertificateStatusCheck {
            delegation_index: 0,
            issuer_id: issuer_id.clone(),
            subject_id: key_id_v2(&agent_public).expect("subject id"),
            cert_id: "c1".into(),
        }];
        Setup {
            store: ConflictingStore {
                inner,
                conflicts: AtomicUsize::new(conflicts),
                loads: AtomicUsize::new(0),
                swaps: AtomicUsize::new(0),
            },
            issuer_id,
            status_public,
            status_private,
            bundle,
            checks,
        }
    }

    fn signed_list(s: &Setup, revoked: &[&str]) -> Vec<u8> {
        let list = RevocationListV2 {
            version: 2,
            issuer_id: s.issuer_id.clone(),
            updated_at: NOW - 10,
            next_update: NOW + 600,
            sequence: 1,
            revoked: revoked
                .iter()
                .map(|c| RevokedCertV2 {
                    cert_id: c.to_string(),
                })
                .collect(),
            signature: HybridSignature {
                ed25519: vec![],
                ml_dsa_65: vec![],
            },
        };
        let signed =
            sign_revocation_list_v2(&list, &s.issuer_id, &s.status_public, &s.status_private)
                .expect("sign");
        encode_revocation_list_v2(&signed).expect("encode")
    }

    fn run(s: &Setup, provider: V2StatusEvidenceProvider) -> V2StatusStageResult {
        let keys: BTreeMap<String, V2StatusKeyConfig> = [(
            s.issuer_id.clone(),
            V2StatusKeyConfig {
                epoch: 1,
                key: s.status_public.clone(),
            },
        )]
        .into_iter()
        .collect();
        let policy = RevocationStatusPolicyV2 {
            max_list_lifetime_seconds: 3600,
            max_status_age_seconds: 600,
            clock_skew_seconds: 5,
        };
        let inputs = V2StatusStageInputs {
            status_evidence: Some(&provider),
            status_journal: Some(&s.store),
            status_keys: &keys,
            status_policy: &policy,
        };
        run_v2_status_stage(&V2Context::background(), &s.bundle, &s.checks, &inputs, NOW)
    }

    fn list_provider(wire: Vec<u8>, calls: Arc<AtomicUsize>) -> V2StatusEvidenceProvider {
        Arc::new(move |_: &V2Context, _: &V2StatusEvidenceRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(V2StatusEvidenceBatch {
                objects: vec![V2StatusEvidenceObject {
                    object_type: LIST,
                    wire: wire.clone(),
                }],
            })
        })
    }

    #[test]
    fn a_conflict_is_retried_exactly_once_without_a_second_provider_call() {
        let s = setup(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let before = s.store.inner.head();
        let out = run(&s, list_provider(signed_list(&s, &[]), calls.clone()));
        assert!(!out.cancelled);
        assert_eq!(out.assessment.assessment, "current", "{:?}", out.assessment);
        assert_eq!(out.queries, 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the provider is never called again"
        );
        assert_eq!(
            s.store.swaps.load(Ordering::SeqCst),
            2,
            "one conflicted swap, one committed retry"
        );
        assert_eq!(
            s.store.loads.load(Ordering::SeqCst),
            2,
            "the retry reloads the anchored journal"
        );
        assert_eq!(s.store.inner.head().generation, before.generation + 1);
    }

    #[test]
    fn a_second_conflict_makes_the_issuer_unavailable() {
        let s = setup(usize::MAX);
        let calls = Arc::new(AtomicUsize::new(0));
        let before = s.store.inner.head();
        let out = run(&s, list_provider(signed_list(&s, &[]), calls.clone()));
        assert!(!out.cancelled);
        assert_eq!(
            (
                out.assessment.assessment.as_str(),
                out.assessment.reason.as_str()
            ),
            ("unavailable", "status_unavailable")
        );
        assert!(out.assessment.evidence.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            s.store.swaps.load(Ordering::SeqCst),
            2,
            "exactly one bounded retry"
        );
        assert_eq!(s.store.loads.load(Ordering::SeqCst), 2);
        assert_eq!(s.store.inner.head(), before, "nothing was committed");
    }

    #[test]
    fn without_conflict_one_swap_commits_and_revocation_wins() {
        let s = setup(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let out = run(&s, list_provider(signed_list(&s, &["c1"]), calls.clone()));
        assert_eq!(out.assessment.assessment, "revoked");
        assert_eq!(s.store.swaps.load(Ordering::SeqCst), 1);
        assert_eq!(s.store.loads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn provider_panics_and_errors_are_contained() {
        let s = setup(0);
        let before = s.store.inner.head();
        let panicking: V2StatusEvidenceProvider =
            Arc::new(|_: &V2Context, _: &V2StatusEvidenceRequest| {
                panic!("provider exploded");
            });
        let out = run(&s, panicking);
        assert_eq!(out.assessment.assessment, "unavailable");
        assert_eq!(out.queries, 1);
        let failing: V2StatusEvidenceProvider =
            Arc::new(|_: &V2Context, _: &V2StatusEvidenceRequest| {
                Err(V2StatusProviderError::new("offline"))
            });
        assert_eq!(run(&s, failing).assessment.assessment, "unavailable");
        assert_eq!(s.store.swaps.load(Ordering::SeqCst), 0);
        assert_eq!(s.store.inner.head(), before);
    }

    #[test]
    fn a_tampered_object_rejects_the_whole_batch() {
        let s = setup(0);
        let mut wire = signed_list(&s, &[]);
        let text = String::from_utf8(wire.clone())
            .expect("utf8")
            .replace("\"sequence\":1", "\"sequence\":2");
        wire = text.into_bytes();
        let calls = Arc::new(AtomicUsize::new(0));
        let out = run(&s, list_provider(wire, calls));
        assert_eq!(out.assessment.assessment, "unavailable");
        assert_eq!(s.store.swaps.load(Ordering::SeqCst), 0);
    }
}
