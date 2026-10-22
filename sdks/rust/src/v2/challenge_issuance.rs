//! Challenge issuance helper (SPEC-v2 Part B, §7.3). Mirrors Go
//! `challenge_issuance_v2.go`.
//!
//! A live v2 verification needs an authenticated [`ExpectedChallengeV2`].
//! The helper generates 32 unpredictable challenge bytes, reads the
//! authoritative clock, and durably persists the complete issuance record
//! BEFORE it returns the challenge. A failure at any step returns no
//! challenge; a record persisted without being returned is never presented
//! and simply expires.

use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};

use super::claim_store::{V2AuthoritativeClock, V2StoreError};
use super::context::V2Context;
use super::crypto::{key_id_v2, valid_v2_id};
use super::errors::{err, V2Error, V2ErrorClass, V2Result};
use super::limits::{checked_add_v2, valid_v2_timestamp, V2_MAX_CHALLENGE_AGE_SECONDS};
use super::operation_context::challenge_claim_digest_v2;
use super::preflight::ExpectedChallengeV2;
use super::release::read_v2_authoritative_time;
use super::wire::MAX_SAFE;
use crate::types::{HybridPublicKey, MAX_IDENTIFIER_LENGTH_BYTES};

/// The durable issuance record store, keyed by (verifier namespace, replay
/// epoch, ChallengeClaimDigestV2(challenge)), the same key as the claim
/// store, retaining each record at least until its expires_at plus the
/// configured clock skew.
///
/// `persist_v2_challenge` inserts atomically and returns only after the
/// record is durable; an existing key returns
/// [`V2StoreError::ChallengeIssuanceConflict`] and changes nothing. Any other
/// error means the challenge must not be exposed.
///
/// `load_v2_challenge` returns a copy of the record,
/// [`V2StoreError::ChallengeIssuanceNotFound`], or another error when the
/// store is unavailable.
pub trait V2ChallengeIssuanceStore: Send + Sync {
    fn persist_v2_challenge(&self, ctx: &V2Context, record: ExpectedChallengeV2) -> Result<(), V2StoreError>;
    fn load_v2_challenge(
        &self,
        ctx: &V2Context,
        namespace: &str,
        replay_epoch: i64,
        claim_digest: &[u8],
    ) -> Result<ExpectedChallengeV2, V2StoreError>;
}

/// The authenticated issuance context. Every expected binding comes from the
/// issuer's own authenticated state, never from the party that will present
/// the proof.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V2ChallengeIssueRequest {
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    /// expires_at = issued_at + lifetime_seconds; 1..300.
    pub lifetime_seconds: i64,
    pub expected_agent_id: String,
    pub expected_agent_public_key: Option<HybridPublicKey>,
    pub expected_receiver_id: String,
    pub expected_session_context: Option<Vec<u8>>,
}

/// A scripted or alternative randomness source (Go `io.Reader`).
pub type V2RandomSource = Arc<Mutex<dyn Read + Send>>;

/// Issues challenges. `random` defaults to the operating system's
/// cryptographic generator and exists only so tests can script the bytes.
#[derive(Clone)]
pub struct V2ChallengeIssuer {
    pub clock: Arc<dyn V2AuthoritativeClock>,
    pub store: Arc<dyn V2ChallengeIssuanceStore>,
    pub random: Option<V2RandomSource>,
}

/// Retries after a key conflict. A conflict with 32 random bytes indicates a
/// broken random source, so the issuer fails rather than looping.
const MAX_V2_ISSUANCE_ATTEMPTS: usize = 3;

impl V2ChallengeIssuer {
    /// Go `IssueChallengeV2`: validate the request (`configuration_invalid`),
    /// read the authoritative clock as issued_at, draw 32 random bytes,
    /// persist the complete record, and only then return it. A key conflict
    /// draws fresh bytes (at most three attempts) and never overwrites.
    ///
    /// Classes where Go returns an unclassified error: an unavailable clock
    /// or store is `claim_store_unavailable` (a classified store error, such
    /// as `clock_regressed`, keeps its class); a failing random source or
    /// three consecutive key conflicts is `configuration_invalid`.
    pub fn issue_challenge_v2(&self, ctx: &V2Context, req: &V2ChallengeIssueRequest) -> V2Result<ExpectedChallengeV2> {
        validate_v2_challenge_issue_request(req)?;
        let issued_at = read_v2_authoritative_time(ctx, self.clock.as_ref())
            .map_err(|e| e.context("v2 challenge issuance: authoritative clock").classify(V2ErrorClass::ClaimStoreUnavailable))?;
        let expires_at = match checked_add_v2(issued_at, req.lifetime_seconds) {
            Some(t) if valid_v2_timestamp(t) => t,
            _ => {
                return err(
                    V2ErrorClass::ConfigurationInvalid,
                    "v2 challenge expiry leaves the timestamp domain",
                )
            }
        };
        for _ in 0..MAX_V2_ISSUANCE_ATTEMPTS {
            let mut value = vec![0u8; 32];
            self.fill_random(&mut value)?;
            let record = ExpectedChallengeV2 {
                value,
                issued_at,
                expires_at,
                verifier_namespace: req.verifier_namespace.clone(),
                replay_epoch: req.replay_epoch,
                verifier_id: req.verifier_id.clone(),
                expected_agent_id: req.expected_agent_id.clone(),
                expected_agent_public_key: req.expected_agent_public_key.clone(),
                expected_receiver_id: req.expected_receiver_id.clone(),
                expected_session_context: req.expected_session_context.clone(),
                context_policy: None,
            };
            let persisted = catch_unwind(AssertUnwindSafe(|| self.store.persist_v2_challenge(ctx, record.clone())))
                .unwrap_or_else(|_| Err(V2StoreError::Unavailable("issuance store panicked".into())));
            match persisted {
                Ok(()) => return Ok(record),
                Err(V2StoreError::ChallengeIssuanceConflict) => continue,
                Err(e) => {
                    return Err(e
                        .classified_or(V2ErrorClass::ClaimStoreUnavailable)
                        .context("v2 challenge issuance: the record was not durably persisted, so the challenge is not exposed"))
                }
            }
        }
        err(
            V2ErrorClass::ConfigurationInvalid,
            format!(
                "v2 challenge issuance: {MAX_V2_ISSUANCE_ATTEMPTS} consecutive key conflicts; the random source is not trustworthy"
            ),
        )
    }

    fn fill_random(&self, buf: &mut [u8]) -> V2Result<()> {
        let failed = |m: String| V2Error::new(V2ErrorClass::ConfigurationInvalid, format!("v2 challenge issuance: random source: {m}"));
        match &self.random {
            None => OsRng.try_fill_bytes(buf).map_err(|e| failed(e.to_string())),
            Some(source) => {
                let mut reader = source.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                reader.read_exact(buf).map_err(|e| failed(e.to_string()))
            }
        }
    }
}

/// Go `LoadExpectedChallengeV2`: retrieve the issuance record for presented
/// challenge bytes by ChallengeClaimDigestV2. A missing record is
/// `expected_challenge_unavailable`. The caller still runs the complete
/// pre-claim checks of SPEC-v2 §6.2 against the returned record; a public API
/// MUST collapse unknown, expired, consumed and wrong-binding challenges into
/// one response.
pub fn load_expected_challenge_v2(
    ctx: &V2Context,
    store: &dyn V2ChallengeIssuanceStore,
    namespace: &str,
    replay_epoch: i64,
    challenge: &[u8],
) -> V2Result<ExpectedChallengeV2> {
    let Ok(digest) = challenge_claim_digest_v2(challenge) else {
        return err(
            V2ErrorClass::ExpectedChallengeUnavailable,
            "v2 presented challenge is not 32 bytes",
        );
    };
    let record = catch_unwind(AssertUnwindSafe(|| store.load_v2_challenge(ctx, namespace, replay_epoch, &digest)))
        .unwrap_or_else(|_| Err(V2StoreError::Unavailable("issuance store panicked".into())))
        .map_err(|e| e.classified_or(V2ErrorClass::ExpectedChallengeUnavailable))?;
    // The store is keyed by digest; the record must still name these exact
    // bytes and key, or it is not this challenge's record.
    if record.value != challenge || record.verifier_namespace != namespace || record.replay_epoch != replay_epoch {
        return err(
            V2ErrorClass::ExpectedChallengeUnavailable,
            "v2 issuance store returned a record for another challenge",
        );
    }
    Ok(record)
}

fn validate_v2_challenge_issue_request(req: &V2ChallengeIssueRequest) -> V2Result<()> {
    let invalid = |m: String| err(V2ErrorClass::ConfigurationInvalid, m);
    if req.verifier_namespace.is_empty() {
        return invalid("v2 challenge issuance requires a non-empty UTF-8 verifier namespace".into());
    }
    if !(0..=MAX_SAFE).contains(&req.replay_epoch) {
        return invalid(format!("v2 challenge replay epoch must be 0..{MAX_SAFE}"));
    }
    if !valid_v2_id(&req.verifier_id) {
        return invalid("v2 challenge verifier_id must be a v2 key ID".into());
    }
    if !(1..=V2_MAX_CHALLENGE_AGE_SECONDS).contains(&req.lifetime_seconds) {
        return invalid(format!("v2 challenge lifetime must be 1..{V2_MAX_CHALLENGE_AGE_SECONDS} seconds"));
    }
    if req.expected_agent_id.is_empty() != req.expected_agent_public_key.is_none() {
        return invalid("v2 expected agent ID and public key must be supplied together".into());
    }
    if let Some(key) = &req.expected_agent_public_key {
        match key_id_v2(key) {
            Ok(id) if id == req.expected_agent_id => {}
            _ => return invalid("v2 expected agent ID does not match its complete public key".into()),
        }
    }
    if req.expected_receiver_id.len() > MAX_IDENTIFIER_LENGTH_BYTES {
        return invalid(format!(
            "v2 expected receiver ID must be valid UTF-8 of at most {MAX_IDENTIFIER_LENGTH_BYTES} bytes"
        ));
    }
    if req.expected_session_context.as_ref().is_some_and(|c| c.len() != 32) {
        return invalid("v2 expected session context must be absent or exactly 32 bytes".into());
    }
    Ok(())
}
