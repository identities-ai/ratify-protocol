//! ChallengeStore — single-use tracking for verifier-issued challenges
//! (SPEC §10).
//!
//! `verify_bundle` consumes a challenge through this interface at the
//! locked point in the algorithm: after the structural, chain, and
//! challenge-signature checks pass, and before authorization evaluation —
//! so a forged presentation cannot burn a legitimate challenge, and a
//! cryptographically valid presentation spends its challenge even when
//! authorization is subsequently denied.
//!
//! The bundled implementation is in-memory ([`MemoryChallengeStore`],
//! `std` only). Deployments that need issuance state to survive restarts
//! or span verifier replicas implement the trait over shared storage;
//! `consume` MUST remain atomic (compare-and-set) so two concurrent
//! presentations of one challenge cannot both succeed.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// The uniform rejection detail for a challenge that cannot be consumed:
/// never issued, expired, already consumed, or issued under a different
/// session binding. Deliberately identical across those cases so a
/// rejection's public detail does not distinguish them. `verify_bundle`
/// normalizes EVERY store failure — custom-store error strings included —
/// to this text in the public result, so implementations cannot leak
/// record state through error strings even accidentally.
pub const UNKNOWN_CHALLENGE: &str =
    "challenge was not issued by this verifier or has already been used";

/// Tracks verifier-issued challenges so each is accepted at most once
/// within its freshness window (SPEC §10).
pub trait ChallengeStore {
    /// Generate a fresh challenge bound to `session_context` (which must
    /// be empty or exactly 32 bytes; empty = unbound), valid for
    /// `ttl_seconds` (which must be positive). Returns the challenge and
    /// its expiry (unix seconds).
    fn issue(&self, session_context: &[u8], ttl_seconds: i64) -> Result<(Vec<u8>, i64), String>;

    /// Report whether `challenge` could be consumed right now — issued,
    /// unexpired, unconsumed, and bound to `session_context` — WITHOUT
    /// consuming it. `verify_bundle` calls this before any signature work.
    fn validate(&self, challenge: &[u8], session_context: &[u8], now: i64) -> Result<(), String>;

    /// Atomically remove the challenge's issuance record. Exactly one
    /// consume of a given challenge may ever succeed; all later calls
    /// (and calls with a mismatched `session_context`, which do NOT
    /// remove the record) return an error. Removing the record keeps the
    /// store's capacity a count of PENDING challenges — a consumed
    /// challenge frees its slot immediately.
    fn consume(&self, challenge: &[u8], session_context: &[u8], now: i64) -> Result<(), String>;
}

// A shared reference to a store is itself a store, so one store can serve
// many verifications (`challenge_store: Some(Box::new(&store))`).
impl<T: ChallengeStore + ?Sized> ChallengeStore for &T {
    fn issue(&self, session_context: &[u8], ttl_seconds: i64) -> Result<(Vec<u8>, i64), String> {
        (**self).issue(session_context, ttl_seconds)
    }
    fn validate(&self, challenge: &[u8], session_context: &[u8], now: i64) -> Result<(), String> {
        (**self).validate(challenge, session_context, now)
    }
    fn consume(&self, challenge: &[u8], session_context: &[u8], now: i64) -> Result<(), String> {
        (**self).consume(challenge, session_context, now)
    }
}

#[cfg(feature = "std")]
mod memory {
    use super::{ChallengeStore, UNKNOWN_CHALLENGE};
    use crate::canonical::base64_std_encode;
    use crate::crypto::generate_challenge;
    use std::collections::HashMap;
    use std::string::{String, ToString};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::vec::Vec;

    struct Record {
        session_context: Vec<u8>,
        expires_at: i64,
    }

    /// In-memory [`ChallengeStore`]: mutex-guarded map with lazy expiry
    /// and a capacity cap. Single-process only — state does not survive
    /// restarts (an unconsumed challenge dies with the process, which
    /// fails closed), and replicas sharing verification traffic would
    /// each accept the same challenge once. Deployments spanning
    /// processes or hosts need a [`ChallengeStore`] over shared storage
    /// whose `consume` is atomic (e.g. a single-row DELETE ... RETURNING).
    pub struct MemoryChallengeStore {
        records: Mutex<HashMap<String, Record>>,
        max_size: usize,
    }

    impl MemoryChallengeStore {
        /// Create a store holding at most `max_size` pending challenges.
        ///
        /// # Panics
        ///
        /// Panics if `max_size` is 0 — a store that can never hold a
        /// challenge is a misconfiguration, not a policy.
        pub fn new(max_size: usize) -> Self {
            assert!(
                max_size > 0,
                "MemoryChallengeStore max_size must be >= 1, got 0"
            );
            MemoryChallengeStore {
                records: Mutex::new(HashMap::new()),
                max_size,
            }
        }

        fn expire(records: &mut HashMap<String, Record>, now: i64) {
            records.retain(|_, r| r.expires_at >= now);
        }

        /// Resolve a presentable record key, or None. A session-context
        /// mismatch fails WITHOUT touching the record, so a presentation
        /// under the wrong binding cannot burn the legitimate one.
        fn lookup(
            records: &mut HashMap<String, Record>,
            challenge: &[u8],
            session_context: &[u8],
            now: i64,
        ) -> Option<String> {
            Self::expire(records, now);
            let key = base64_std_encode(challenge);
            match records.get(&key) {
                Some(r) if r.session_context == session_context => Some(key),
                _ => None,
            }
        }
    }

    impl ChallengeStore for MemoryChallengeStore {
        fn issue(
            &self,
            session_context: &[u8],
            ttl_seconds: i64,
        ) -> Result<(Vec<u8>, i64), String> {
            if !session_context.is_empty() && session_context.len() != 32 {
                return Err(format!(
                    "session context must be empty or 32 bytes, got {}",
                    session_context.len()
                ));
            }
            if ttl_seconds <= 0 {
                return Err(format!(
                    "challenge ttl must be positive, got {}",
                    ttl_seconds
                ));
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let expires_at = now + ttl_seconds;
            let challenge = generate_challenge();
            let mut records = self.records.lock().expect("challenge store lock poisoned");
            Self::expire(&mut records, now);
            if records.len() >= self.max_size {
                return Err("challenge store full — too many pending challenges".to_string());
            }
            records.insert(
                base64_std_encode(&challenge),
                Record {
                    session_context: session_context.to_vec(),
                    expires_at,
                },
            );
            Ok((challenge, expires_at))
        }

        fn validate(
            &self,
            challenge: &[u8],
            session_context: &[u8],
            now: i64,
        ) -> Result<(), String> {
            let mut records = self.records.lock().expect("challenge store lock poisoned");
            match Self::lookup(&mut records, challenge, session_context, now) {
                Some(_) => Ok(()),
                None => Err(UNKNOWN_CHALLENGE.to_string()),
            }
        }

        // Check-and-remove under one lock: of two concurrent
        // presentations of the same challenge, exactly one can succeed.
        // Removal frees the record's capacity slot immediately; a
        // session-context mismatch leaves the record in place.
        fn consume(
            &self,
            challenge: &[u8],
            session_context: &[u8],
            now: i64,
        ) -> Result<(), String> {
            let mut records = self.records.lock().expect("challenge store lock poisoned");
            match Self::lookup(&mut records, challenge, session_context, now) {
                Some(key) => {
                    records.remove(&key);
                    Ok(())
                }
                None => Err(UNKNOWN_CHALLENGE.to_string()),
            }
        }
    }
}

#[cfg(feature = "std")]
pub use memory::MemoryChallengeStore;
