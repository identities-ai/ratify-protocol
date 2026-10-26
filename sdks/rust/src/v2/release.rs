//! Committed versus released (SPEC-v2 §6.9, §7.9). Mirrors Go
//! `release_v2.go`.
//!
//! [`super::verify_proof_bundle_v2`] commits a terminal Protocol result and
//! returns an opaque [`CommittedV2Outcome`] holding the handoff tuple
//! {claim_id, receipt_body_digest, challenge_expires_at, allow_horizon} and
//! the sealed receipt outbox body. It exposes no decision.
//! [`release_v2_decision`] is the only path to an actionable decision; it
//! returns released, pending (retryable), withheld (permanent for the claim
//! once recorded), or rejected (a result of that call's inputs that changes
//! no claim state).
//!
//! There is no production local-log substitute for an independent
//! checkpoint. The in-memory store in [`super::reference`] exists only for
//! tests and conformance scenarios.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::checkpoint_ack::V2CheckpointAcknowledgement;
use super::claim_store::{V2AuthoritativeClock, V2ChallengeClaim, V2StoreError};
use super::context::V2Context;
use super::crypto::{key_id_v2, lower_hex, sha384, verify_v2_statement, V2ObjectType};
use super::errors::{err, V2Error, V2ErrorClass, V2Result};
use super::limits::{valid_v2_timestamp, V2_MAX_TIMESTAMP_SECONDS};
use super::receipt::{
    decode_verification_receipt_v2, verification_receipt_v2_body, verification_receipt_v2_digest,
    verification_receipt_v2_signable_bytes, VerificationReceiptV2,
};
use crate::types::HybridPublicKey;

/// The immutable, non-actionable handoff from a committed verification to
/// publication and [`release_v2_decision`]. It carries no decision.
pub struct CommittedV2Outcome {
    claim_id: String,
    verifier_id: String,
    receipt_body: Vec<u8>,
    challenge_expires_at: i64,
    allow_horizon: i64,
}

impl fmt::Debug for CommittedV2Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedV2Outcome")
            .field("claim_id", &self.claim_id)
            .field("receipt_body_digest", &self.receipt_body_digest())
            .finish_non_exhaustive()
    }
}

impl CommittedV2Outcome {
    pub(crate) fn new(claim: &V2ChallengeClaim, body: &[u8], allow_horizon: i64) -> Self {
        CommittedV2Outcome {
            claim_id: claim.claim_id.clone(),
            verifier_id: claim.verifier_id.clone(),
            receipt_body: body.to_vec(),
            challenge_expires_at: claim.expires_at,
            allow_horizon,
        }
    }

    /// The Protocol claim ID of the committed evaluation.
    pub fn claim_id(&self) -> String {
        self.claim_id.clone()
    }

    /// A copy of the sealed receipt outbox body, for the receipt publisher
    /// only. Applications must not parse it to authorize.
    pub fn receipt_body(&self) -> Vec<u8> {
        self.receipt_body.clone()
    }

    /// [`receipt_outbox_digest_v2`] of the sealed body (SPEC-v2 §4).
    pub fn receipt_body_digest(&self) -> String {
        receipt_outbox_digest_v2(&self.receipt_body)
    }

    /// The sealed exclusive challenge deadline.
    pub fn challenge_expires_at(&self) -> i64 {
        self.challenge_expires_at
    }

    /// The exclusive allow deadline; `None` (null) unless the committed
    /// result can become an allow.
    pub fn allow_horizon(&self) -> Option<i64> {
        (self.allow_horizon > 0).then_some(self.allow_horizon)
    }
}

/// `"sha384:" + hex(SHA-384("ratify-protocol-receipt-outbox-v2" || 0x00 || body))`.
pub fn receipt_outbox_digest_v2(body: &[u8]) -> String {
    format!(
        "sha384:{}",
        hex::encode(sha384(&[b"ratify-protocol-receipt-outbox-v2", &[0], body]))
    )
}

/// The Part B receipt outbox drain (§7.7). It signs and appends the exact
/// committed body for `claim_id` at the next ordered log position, or
/// returns the receipt already appended for that claim, and returns the
/// signed receipt wire. It refuses a body that differs from the committed
/// outbox body.
pub trait V2ReceiptPublisher: Send + Sync {
    fn publish_v2_receipt(&self, ctx: &V2Context, claim_id: &str, receipt_body: &[u8]) -> Result<Vec<u8>, V2StoreError>;
}

/// The caller-configured independent checkpoint (§7.8).
/// `acknowledge_v2_receipt` accepts only the next sequence of the log,
/// linked by `previous_entry_hash`, and returns the original acknowledgement
/// on an identical retry. `get_v2_acknowledgement` returns an
/// acknowledgement, [`V2StoreError::AcknowledgementNotFound`], or another
/// error for unavailability.
pub trait V2ReceiptCheckpoint: Send + Sync {
    fn acknowledge_v2_receipt(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError>;
    fn get_v2_acknowledgement(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError>;
}

/// The durable release record of SPEC-v2 §6.9: the release of step 9
/// (`outcome` released, `reason` empty) or a withheld result of steps 7 and
/// 8 (`outcome` withheld, `reason` `clock_regressed`, `challenge_expired`, or
/// `allow_horizon_passed`). `entry_hash` and `ack_timestamp` name the
/// verified receipt entry and its acknowledgement. The first record for a
/// claim wins; a claim store returns [`V2StoreError::ReleaseStateMismatch`]
/// for any different later record and must persist and return every field
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ReleaseRecord {
    pub claim_id: String,
    pub entry_hash: Vec<u8>,
    pub ack_timestamp: i64,
    pub outcome: V2ReleaseStatus,
    pub reason: String,
}

/// Go `ValidV2ReleaseRecordOutcome`: whether `outcome` and `reason` form a
/// release record: released with no reason, or withheld with one of the
/// reasons release steps 7 and 8 record.
pub fn valid_v2_release_record_outcome(outcome: V2ReleaseStatus, reason: &str) -> bool {
    match outcome {
        V2ReleaseStatus::Released => reason.is_empty(),
        V2ReleaseStatus::Withheld => {
            matches!(reason, "clock_regressed" | "challenge_expired" | "allow_horizon_passed")
        }
        _ => false,
    }
}

/// What the claim store returns to release (§7.3): the sealed handoff
/// values, the recorded finalization time T_final, any receipt_abandoned
/// marking, and any prior release record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2TerminalClaimRecord {
    pub terminal: bool,
    pub receipt_outbox_digest: String,
    pub challenge_expires_at: i64,
    pub allow_horizon: i64,
    pub finalized_at: i64,
    pub receipt_abandoned: bool,
    pub release: Option<V2ReleaseRecord>,
}

/// The claim-store view release needs. `load_v2_terminal_claim` reports a
/// claim the store does not hold with a `claim_not_found` error, which
/// release answers with `rejected / release_state_mismatch`; any other error
/// is store unavailability (`pending / claim_store_unavailable`).
/// `record_v2_release` returns [`V2StoreError::ReleaseStateMismatch`] when a
/// different release or withheld record already exists for the claim.
pub trait V2ReleaseClaimStore: V2AuthoritativeClock {
    fn load_v2_terminal_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2TerminalClaimRecord, V2StoreError>;
    fn record_v2_release(&self, ctx: &V2Context, record: V2ReleaseRecord) -> Result<(), V2StoreError>;
}

/// Caller-authenticated release configuration.
#[derive(Clone, Copy)]
pub struct V2ReleaseConfig<'a> {
    pub verifier_public_key: &'a HybridPublicKey,
    pub log_id: &'a str,
    pub claim_store: &'a dyn V2ReleaseClaimStore,
    pub checkpoint: &'a dyn V2ReceiptCheckpoint,
}

/// The release outcome class of §6.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V2ReleaseStatus {
    Released,
    Pending,
    Withheld,
    Rejected,
}

impl V2ReleaseStatus {
    /// `released`, `pending`, `withheld`, or `rejected`.
    pub fn as_str(self) -> &'static str {
        match self {
            V2ReleaseStatus::Released => "released",
            V2ReleaseStatus::Pending => "pending",
            V2ReleaseStatus::Withheld => "withheld",
            V2ReleaseStatus::Rejected => "rejected",
        }
    }
}

/// The only actionable value in this crate (SPEC-v2 §6.9). It is sealed:
/// every field is private, [`release_v2_decision`] is its only constructor,
/// it implements neither `Default`, `Clone` nor any deserializer, and every
/// accessor returns a copy, so a caller can neither forge a released
/// decision nor change one it was given.
pub struct V2ReleasedDecision {
    claim_id: String,
    decision: String,
    reason: String,
    identity_status: String,
    granted_scope: Vec<String>,
    receipt_wire: Vec<u8>,
    release_time: i64,
    challenge_expires_at: i64,
    allow_horizon: i64,
}

impl fmt::Debug for V2ReleasedDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2ReleasedDecision")
            .field("claim_id", &self.claim_id)
            .field("decision", &self.decision)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl V2ReleasedDecision {
    /// The Protocol claim ID of the released evaluation.
    pub fn claim_id(&self) -> String {
        self.claim_id.clone()
    }

    /// The released decision: "allow", "deny", or "indeterminate". Use
    /// [`V2ReleasedDecision::allowed`], not this value, to gate a side effect.
    pub fn decision(&self) -> String {
        self.decision.clone()
    }

    /// The released decision reason.
    pub fn reason(&self) -> String {
        self.reason.clone()
    }

    /// The released identity status.
    pub fn identity_status(&self) -> String {
        self.identity_status.clone()
    }

    /// A copy of the released granted scope.
    pub fn granted_scope(&self) -> Vec<String> {
        self.granted_scope.clone()
    }

    /// A copy of the signed receipt wire verified during release.
    pub fn receipt_wire(&self) -> Vec<u8> {
        self.receipt_wire.clone()
    }

    /// A freshly decoded copy of the signed receipt verified during release.
    pub fn receipt(&self) -> V2Result<VerificationReceiptV2> {
        if self.receipt_wire.is_empty() {
            return err(V2ErrorClass::Malformed, "v2 released decision carries no receipt");
        }
        decode_verification_receipt_v2(&self.receipt_wire)
    }

    /// The checkpoint acknowledgement time of the release.
    pub fn release_time(&self) -> i64 {
        self.release_time
    }

    /// The sealed exclusive challenge deadline.
    pub fn challenge_expires_at(&self) -> i64 {
        self.challenge_expires_at
    }

    /// The sealed exclusive allow deadline; `None` unless the released
    /// decision is an allow.
    pub fn allow_horizon(&self) -> Option<i64> {
        (self.allow_horizon > 0).then_some(self.allow_horizon)
    }

    /// Whether this released allow may be acted on now. It reads the
    /// receiver's authoritative clock and compares that time only with the
    /// sealed exclusive deadlines: true only when the released decision is an
    /// allow and now < challenge_expires_at and now < allow_horizon. A clock
    /// error, panic, regression, or reading outside the timestamp domain is
    /// false. Call it immediately before the side effect.
    pub fn allowed(&self, ctx: &V2Context, clock: &dyn V2AuthoritativeClock) -> bool {
        if self.decision != "allow" || self.receipt_wire.is_empty() || self.allow_horizon <= 0 {
            return false;
        }
        match read_v2_authoritative_time(ctx, clock) {
            Ok(now) => now < self.challenge_expires_at && now < self.allow_horizon,
            Err(_) => false,
        }
    }
}

/// The result of [`release_v2_decision`]. `decision` is present only when
/// `status` is released; `reason` is empty only when released. Only
/// [`V2ReleasedDecision::allowed`] may gate a side effect.
#[derive(Debug)]
pub struct V2ReleaseResult {
    pub status: V2ReleaseStatus,
    pub reason: String,
    decision: Option<V2ReleasedDecision>,
}

impl V2ReleaseResult {
    /// The released decision (present only when released).
    pub fn decision(&self) -> Option<&V2ReleasedDecision> {
        self.decision.as_ref()
    }

    /// Take the released decision out of the result.
    pub fn into_decision(self) -> Option<V2ReleasedDecision> {
        self.decision
    }
}

fn release_result_v2(status: V2ReleaseStatus, reason: &str) -> V2ReleaseResult {
    V2ReleaseResult {
        status,
        reason: reason.into(),
        decision: None,
    }
}

/// Go `ReleaseV2Decision`: the release steps of SPEC-v2 §6.9 in order,
/// stopping at the first that does not pass. `signed_receipt` is the
/// publisher's signed receipt wire, or `None` when it has not been appended
/// yet.
pub fn release_v2_decision(
    ctx: &V2Context,
    committed: &CommittedV2Outcome,
    signed_receipt: Option<&[u8]>,
    config: V2ReleaseConfig<'_>,
) -> V2ReleaseResult {
    use V2ReleaseStatus::*;
    if committed.claim_id.is_empty() || committed.receipt_body.is_empty() {
        return release_result_v2(Rejected, "release_state_mismatch");
    }
    if config.log_id.len() != 32 || !lower_hex(config.log_id) {
        return release_result_v2(Rejected, "release_state_mismatch");
    }
    // 1. Committed state.
    let record = match catch_unwind(AssertUnwindSafe(|| {
        config.claim_store.load_v2_terminal_claim(ctx, &committed.claim_id)
    })) {
        Ok(Ok(r)) => r,
        // Only an unavailable store is retryable. A store that answers that
        // it holds no such claim (claim_not_found) did not produce this
        // handoff: a state mismatch, never pending.
        Ok(Err(e)) if e.class() == Some(V2ErrorClass::ClaimNotFound) => {
            return release_result_v2(Rejected, "release_state_mismatch")
        }
        _ => return release_result_v2(Pending, "claim_store_unavailable"),
    };
    if record.receipt_abandoned {
        return release_result_v2(Withheld, "receipt_abandoned");
    }
    let verifier_id = key_id_v2(config.verifier_public_key);
    if !record.terminal
        || record.receipt_outbox_digest != committed.receipt_body_digest()
        || record.challenge_expires_at != committed.challenge_expires_at
        || record.allow_horizon != committed.allow_horizon
        || verifier_id.as_deref().ok() != Some(committed.verifier_id.as_str())
    {
        return release_result_v2(Rejected, "release_state_mismatch");
    }
    // A recorded withheld result is permanent for the claim and is returned
    // before any other step. A record that is neither a valid withheld nor a
    // valid released record for this claim is a state mismatch.
    if let Some(release) = &record.release {
        if release.claim_id != committed.claim_id || !valid_v2_release_record_outcome(release.outcome, &release.reason) {
            return release_result_v2(Rejected, "release_state_mismatch");
        }
        if release.outcome == Withheld {
            return release_result_v2(Withheld, &release.reason);
        }
    }
    // 2. Receipt.
    let Some(signed_receipt) = signed_receipt.filter(|r| !r.is_empty()) else {
        return release_result_v2(Pending, "receipt_not_appended");
    };
    let receipt = match verify_published_v2_receipt(signed_receipt, config) {
        Ok(r) if r.verifier_id == committed.verifier_id => r,
        _ => return release_result_v2(Rejected, "receipt_invalid"),
    };
    // 3. Body binding.
    match verification_receipt_v2_body(&receipt) {
        Ok(body) if body == committed.receipt_body => {}
        _ => return release_result_v2(Rejected, "receipt_body_mismatch"),
    }
    let Ok(entry_hash) = verification_receipt_v2_digest(&receipt) else {
        return release_result_v2(Rejected, "receipt_invalid");
    };
    // 4. Prior release: the same receipt entry. A recorded release only
    // enforces sameness; it never substitutes for the acknowledgement.
    if record.release.as_ref().is_some_and(|r| r.entry_hash != entry_hash) {
        return release_result_v2(Rejected, "release_state_mismatch");
    }
    // 5. Predecessor.
    if receipt.sequence > 1 {
        let previous = match get_v2_acknowledgement_safely(ctx, config.checkpoint, &receipt.log_id, receipt.sequence - 1) {
            Ok(a) => a,
            Err(_) => return release_result_v2(Pending, "acknowledgement_unavailable"),
        };
        if previous.log_id != receipt.log_id
            || previous.sequence != receipt.sequence - 1
            || previous.entry_hash != receipt.previous_receipt_hash
        {
            return release_result_v2(Rejected, "log_predecessor_mismatch");
        }
    }
    // 6. Acknowledgement.
    let ack = match get_v2_acknowledgement_safely(ctx, config.checkpoint, &receipt.log_id, receipt.sequence) {
        Ok(a) => a,
        Err(_) => return release_result_v2(Pending, "acknowledgement_unavailable"),
    };
    if ack.log_id != receipt.log_id || ack.sequence != receipt.sequence || ack.entry_hash != entry_hash {
        return release_result_v2(Rejected, "acknowledgement_mismatch");
    }
    if record.release.as_ref().is_some_and(|r| r.ack_timestamp != ack.timestamp) {
        return release_result_v2(Rejected, "release_state_mismatch");
    }
    // withhold ends release at step 7 or 8. With no release recorded it
    // durably records the withheld result first, so it is permanent for the
    // claim; if the store is unavailable this call is still withheld. With a
    // release already recorded, that first record stands and this call alone
    // is withheld.
    let withhold = |reason: &str| -> V2ReleaseResult {
        if record.release.is_none() {
            let withheld = V2ReleaseRecord {
                claim_id: committed.claim_id.clone(),
                entry_hash: entry_hash.clone(),
                ack_timestamp: ack.timestamp,
                outcome: Withheld,
                reason: reason.into(),
            };
            if let Err(V2StoreError::ReleaseStateMismatch) = record_v2_release_safely(ctx, config.claim_store, withheld) {
                return release_result_v2(Rejected, "release_state_mismatch");
            }
        }
        release_result_v2(Withheld, reason)
    };
    // 7. Clock.
    let now = match read_v2_authoritative_time(ctx, config.claim_store) {
        Ok(now) => now,
        Err(e) if e.class == V2ErrorClass::ClockRegressed && e.is_classified() => return withhold("clock_regressed"),
        Err(_) => return release_result_v2(Pending, "clock_unavailable"),
    };
    if !valid_v2_timestamp(record.finalized_at)
        || !valid_v2_timestamp(ack.timestamp)
        || record.finalized_at > ack.timestamp
        || ack.timestamp > now
    {
        return withhold("clock_regressed");
    }
    // 8. Deadlines.
    if ack.timestamp >= committed.challenge_expires_at || now >= committed.challenge_expires_at {
        return withhold("challenge_expired");
    }
    if receipt.decision == "allow"
        && (committed.allow_horizon <= 0 || ack.timestamp >= committed.allow_horizon || now >= committed.allow_horizon)
    {
        return withhold("allow_horizon_passed");
    }
    // 9. Record.
    if record.release.is_none() {
        let new_record = V2ReleaseRecord {
            claim_id: committed.claim_id.clone(),
            entry_hash: entry_hash.clone(),
            ack_timestamp: ack.timestamp,
            outcome: Released,
            reason: String::new(),
        };
        match record_v2_release_safely(ctx, config.claim_store, new_record) {
            Ok(()) => {}
            Err(V2StoreError::ReleaseStateMismatch) => return release_result_v2(Rejected, "release_state_mismatch"),
            Err(_) => return release_result_v2(Pending, "claim_store_unavailable"),
        }
    }
    // 10. Return.
    let allow = receipt.decision == "allow";
    V2ReleaseResult {
        status: Released,
        reason: String::new(),
        decision: Some(V2ReleasedDecision {
            claim_id: committed.claim_id.clone(),
            decision: receipt.decision.clone(),
            reason: receipt.decision_reason.clone(),
            identity_status: receipt.identity_status.clone(),
            granted_scope: receipt.granted_scope.clone(),
            receipt_wire: signed_receipt.to_vec(),
            release_time: ack.timestamp,
            challenge_expires_at: committed.challenge_expires_at,
            allow_horizon: if allow { committed.allow_horizon } else { 0 },
        }),
    }
}

fn verify_published_v2_receipt(wire: &[u8], config: V2ReleaseConfig<'_>) -> V2Result<VerificationReceiptV2> {
    let receipt = decode_verification_receipt_v2(wire)?;
    if receipt.log_id != config.log_id {
        return err(V2ErrorClass::LogStateMismatch, "v2 published receipt belongs to an unconfigured log");
    }
    let body = verification_receipt_v2_signable_bytes(&receipt)?;
    verify_v2_statement(
        V2ObjectType::VerificationReceipt,
        &body,
        &receipt.signature,
        config.verifier_public_key,
    )?;
    Ok(receipt)
}

fn record_v2_release_safely(
    ctx: &V2Context,
    store: &dyn V2ReleaseClaimStore,
    record: V2ReleaseRecord,
) -> Result<(), V2StoreError> {
    catch_unwind(AssertUnwindSafe(|| store.record_v2_release(ctx, record)))
        .unwrap_or_else(|_| Err(V2StoreError::Unavailable("claim store panicked".into())))
}

fn get_v2_acknowledgement_safely(
    ctx: &V2Context,
    checkpoint: &dyn V2ReceiptCheckpoint,
    log_id: &str,
    sequence: i64,
) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
    catch_unwind(AssertUnwindSafe(|| checkpoint.get_v2_acknowledgement(ctx, log_id, sequence)))
        .unwrap_or_else(|_| Err(V2StoreError::Unavailable("checkpoint panicked".into())))
}

/// Go `readV2AuthoritativeTime`: a store-reported `clock_regressed` keeps its
/// class; any other failure, a panic, or a reading outside the timestamp
/// domain is an unavailable clock (an unclassified error).
pub(crate) fn read_v2_authoritative_time(ctx: &V2Context, clock: &dyn V2AuthoritativeClock) -> V2Result<i64> {
    let now = match catch_unwind(AssertUnwindSafe(|| clock.authoritative_time_v2(ctx))) {
        Ok(Ok(now)) => now,
        Ok(Err(e)) => return Err(e.into_v2()),
        Err(_) => return Err(V2Error::plain("v2 authoritative clock panicked")),
    };
    if !valid_v2_timestamp(now) {
        return Err(V2Error::plain(format!(
            "v2 authoritative clock returned {now} outside 0..{V2_MAX_TIMESTAMP_SECONDS}"
        )));
    }
    Ok(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_hybrid_keypair;
    use crate::v2::reference::Store;

    // lifecycle-scenarios.json `release_forged`: an outcome the verifier never
    // produced (the Go zero value) is always rejected. Callers cannot build
    // one, so this crate-internal test is where the vector's expectation runs.
    #[test]
    fn forged_zero_value_outcome_is_rejected() {
        let (public, private) = generate_hybrid_keypair();
        let log_id = "dddddddddddddddddddddddddddddd01";
        let store = Store::new(1_800_000_000, 30, log_id, &private).unwrap();
        let forged = CommittedV2Outcome {
            claim_id: String::new(),
            verifier_id: String::new(),
            receipt_body: Vec::new(),
            challenge_expires_at: 0,
            allow_horizon: 0,
        };
        let result = release_v2_decision(
            &V2Context::background(),
            &forged,
            None,
            V2ReleaseConfig {
                verifier_public_key: &public,
                log_id,
                claim_store: &store,
                checkpoint: &store,
            },
        );
        assert_eq!(
            (result.status, result.reason.as_str()),
            (V2ReleaseStatus::Rejected, "release_state_mismatch")
        );
        assert!(result.decision().is_none());
    }
}
