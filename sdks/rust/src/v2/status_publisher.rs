//! Minimal signed-status publisher (SPEC-v2 §5.4, status publisher duties).
//! Mirrors Go `status_publisher_v2.go`.
//!
//! A v2 allow needs current signed status for every certificate in the
//! chain. [`V2StatusPublisher`] produces that feed for one issuer under a
//! separate status key: a genesis full list, same-sequence heartbeats that
//! refresh freshness, and revocations as a push plus the cumulative full
//! list at the next sequence. Each operation is a pure transition of
//! [`V2StatusPublisherState`]; the caller MUST durably persist the returned
//! state before publishing the returned objects, so a crash can never sign
//! two different bodies at one sequence.
//!
//! Errors: construction failures are `configuration_invalid` (as in Go).
//! Signing operations return [`V2SignError`]. A publisher refusal (a state
//! that does not belong to this issuer and status key, a malformed state,
//! non-advancing time, invalid or repeated revocation IDs, exhausted sequence
//! or time domain) is [`V2SignError::InvalidObject`] carrying
//! `configuration_invalid`, as Go classifies it; signer failures and status
//! object refusals keep their own variant and class
//! ([`V2SignError::class`]).

use std::sync::Arc;

use super::context::V2Context;
use super::errors::{err, V2Error, V2ErrorClass, V2Result, V2SignError, V2SignResult};
use super::journal::{
    key_role_binding_v2, load_anchored_security_journal_v2, SecurityJournalStoreV2,
    StatusKeyBindingV2,
};
use super::limits::{
    checked_add_v2, valid_v2_timestamp, MAX_REVOCATION_LIST_REFS_V2, MAX_REVOCATION_PUSH_REFS_V2,
    V2_MAX_STATUS_LIFETIME_SECONDS,
};
use super::signer::{signer_public_key_v2, SignerV2};
use super::wire::{
    placeholder_signature, sign_revocation_list_v2_with_signer,
    sign_revocation_push_v2_with_signer, RevocationListV2, RevocationPushV2, RevokedCertV2,
    MAX_SAFE,
};
use crate::types::{HybridPublicKey, MAX_IDENTIFIER_LENGTH_BYTES};

/// The publisher's durable state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2StatusPublisherState {
    pub issuer_id: String,
    pub status_key_id: String,
    /// The last signed sequence.
    pub sequence: i64,
    /// The `updated_at` of the last signed full list.
    pub updated_at: i64,
    /// The cumulative sorted revoked set.
    pub revoked: Vec<String>,
}

/// One transition's output: the next state and the signed objects to
/// publish after that state is durable. `push` is `None` except for a
/// revocation.
#[derive(Debug, Clone)]
pub struct V2StatusPublication {
    pub state: V2StatusPublisherState,
    pub list: RevocationListV2,
    pub push: Option<RevocationPushV2>,
}

/// Signs status for one issuer under one status key.
pub struct V2StatusPublisher {
    issuer_id: String,
    status_key: HybridPublicKey,
    status_key_id: String,
    signer: Arc<dyn SignerV2>,
    lifetime: i64,
}

impl std::fmt::Debug for V2StatusPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2StatusPublisher")
            .field("issuer_id", &self.issuer_id)
            .field("status_key_id", &self.status_key_id)
            .field("lifetime", &self.lifetime)
            .finish()
    }
}

fn config_invalid(e: V2Error) -> V2Error {
    e.classify(V2ErrorClass::ConfigurationInvalid)
}

/// Bind an issuer's complete key to a separate status signer, using the
/// deployment's authenticated role configuration: the anchored
/// `SecurityJournalV2` in `roles`, whose key-role history records every
/// non-status key the deployment knows and whose status-key history binds the
/// issuer to its current status key (SPEC-v2 §5.4, §6.6). It refuses
/// (`configuration_invalid`), before any signature exists, when `roles` does
/// not load as an anchored journal; when the issuer key is not recorded there
/// under a non-status role; when the status key's ID or either component
/// equals the ID or a component of any recorded non-status key; or when the
/// status key is not the issuer's highest-epoch configured status key.
/// `lifetime_seconds` sets `next_update - updated_at` for every full list and
/// is 1..86400; it must not exceed the relying verifiers' configured maximum
/// list lifetime.
pub fn new_v2_status_publisher(
    ctx: &V2Context,
    roles: &dyn SecurityJournalStoreV2,
    issuer_key: &HybridPublicKey,
    status_signer: Arc<dyn SignerV2>,
    lifetime_seconds: i64,
) -> V2Result<V2StatusPublisher> {
    if !(1..=V2_MAX_STATUS_LIFETIME_SECONDS).contains(&lifetime_seconds) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("v2 status list lifetime must be 1..{V2_MAX_STATUS_LIFETIME_SECONDS} seconds"),
        );
    }
    let issuer_binding = key_role_binding_v2("issuer", issuer_key)
        .map_err(|e| config_invalid(e.context("v2 status publisher issuer key")))?;
    let status_key = signer_public_key_v2(status_signer.as_ref())
        .map_err(|e| V2Error::new(V2ErrorClass::ConfigurationInvalid, e.to_string()))?;
    let status_binding = key_role_binding_v2("status", &status_key).map_err(config_invalid)?;
    let journal = load_anchored_security_journal_v2(ctx, roles)
        .map_err(|e| config_invalid(e.context("v2 status publisher role configuration")))?;
    let mut issuer_known = false;
    for b in &journal.key_role_history {
        if b.role == "status" {
            continue;
        }
        if b.key_id == issuer_binding.key_id
            && b.ed25519_digest == issuer_binding.ed25519_digest
            && b.ml_dsa_65_digest == issuer_binding.ml_dsa_65_digest
        {
            issuer_known = true;
        }
        if b.key_id == status_binding.key_id
            || b.ed25519_digest == status_binding.ed25519_digest
            || b.ml_dsa_65_digest == status_binding.ml_dsa_65_digest
            || b.ed25519_digest == status_binding.ml_dsa_65_digest
            || b.ml_dsa_65_digest == status_binding.ed25519_digest
        {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                format!(
                    "v2 status key reuses the key or a component of recorded {} key {}; status keys must be role-separated",
                    b.role, b.key_id
                ),
            );
        }
    }
    if !issuer_known {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 status publisher issuer key is not recorded under a non-status role",
        );
    }
    let mut current = StatusKeyBindingV2::default();
    for b in &journal.status_key_history {
        if b.issuer_id == issuer_binding.key_id && b.epoch > current.epoch {
            current = b.clone();
        }
    }
    if current.epoch == 0
        || current.status_key_id != status_binding.key_id
        || current.ed25519_digest != status_binding.ed25519_digest
        || current.ml_dsa_65_digest != status_binding.ml_dsa_65_digest
    {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 status signer is not the issuer's current configured status key",
        );
    }
    Ok(V2StatusPublisher {
        issuer_id: issuer_binding.key_id,
        status_key,
        status_key_id: status_binding.key_id,
        signer: status_signer,
        lifetime: lifetime_seconds,
    })
}

fn duty(message: impl Into<String>) -> V2SignError {
    V2SignError::InvalidObject(V2Error::new(V2ErrorClass::ConfigurationInvalid, message))
}

impl V2StatusPublisher {
    /// The issuer ID a verifier configures.
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// A copy of the complete status public key a verifier configures.
    pub fn status_key(&self) -> HybridPublicKey {
        self.status_key.clone()
    }

    /// Sign the first full list: sequence 1, an empty revoked set.
    pub fn genesis(&self, ctx: &V2Context, updated_at: i64) -> V2SignResult<V2StatusPublication> {
        let state = V2StatusPublisherState {
            issuer_id: self.issuer_id.clone(),
            status_key_id: self.status_key_id.clone(),
            ..Default::default()
        };
        self.list(ctx, &state, 1, updated_at)
    }

    /// Re-sign the current sequence and revoked set with a later
    /// `updated_at`, which refreshes freshness without a new sequence.
    pub fn heartbeat(
        &self,
        ctx: &V2Context,
        state: &V2StatusPublisherState,
        updated_at: i64,
    ) -> V2SignResult<V2StatusPublication> {
        self.check_state(state, updated_at)?;
        self.list(ctx, state, state.sequence, updated_at)
    }

    /// Advance one sequence: a push carrying exactly the newly revoked
    /// certificate IDs, and the cumulative full list at the same sequence,
    /// both timestamped `at`. Every ID must be new, unique, and 1..512 bytes.
    pub fn revoke(
        &self,
        ctx: &V2Context,
        state: &V2StatusPublisherState,
        cert_ids: &[String],
        at: i64,
    ) -> V2SignResult<V2StatusPublication> {
        self.check_state(state, at)?;
        if cert_ids.is_empty() || cert_ids.len() > MAX_REVOCATION_PUSH_REFS_V2 {
            return Err(duty(format!(
                "v2 status revocation must name 1..{MAX_REVOCATION_PUSH_REFS_V2} certificate IDs"
            )));
        }
        let mut added = cert_ids.to_vec();
        added.sort();
        for (i, id) in added.iter().enumerate() {
            if id.is_empty()
                || id.len() > MAX_IDENTIFIER_LENGTH_BYTES
                || (i > 0 && added[i - 1] == *id)
            {
                return Err(duty(format!(
                    "v2 status revocation IDs must be unique UTF-8 of 1..{MAX_IDENTIFIER_LENGTH_BYTES} bytes"
                )));
            }
            if state.revoked.binary_search(id).is_ok() {
                return Err(duty(format!(
                    "v2 certificate {id:?} is already revoked; revocation is monotonic"
                )));
            }
        }
        if state.revoked.len() + added.len() > MAX_REVOCATION_LIST_REFS_V2 {
            return Err(duty(format!(
                "v2 status list would exceed {MAX_REVOCATION_LIST_REFS_V2} revoked references"
            )));
        }
        let sequence = state.sequence + 1;
        if sequence > MAX_SAFE {
            return Err(duty("v2 status sequence is exhausted"));
        }
        let push = RevocationPushV2 {
            version: 2,
            issuer_id: self.issuer_id.clone(),
            sequence,
            pushed_at: at,
            revoked: added
                .iter()
                .map(|id| RevokedCertV2 {
                    cert_id: id.clone(),
                })
                .collect(),
            signature: placeholder_signature(),
        };
        let push = sign_revocation_push_v2_with_signer(
            ctx,
            &push,
            &self.issuer_id,
            &self.status_key,
            self.signer.as_ref(),
        )?;
        let mut next = state.clone();
        next.revoked.extend(added);
        next.revoked.sort();
        let mut out = self.list(ctx, &next, sequence, at)?;
        out.push = Some(push);
        Ok(out)
    }

    fn check_state(&self, state: &V2StatusPublisherState, at: i64) -> V2SignResult<()> {
        if state.issuer_id != self.issuer_id || state.status_key_id != self.status_key_id {
            return Err(duty(
                "v2 status publisher state does not belong to this issuer and status key",
            ));
        }
        let sorted_unique = state.revoked.windows(2).all(|w| w[0] < w[1]);
        if state.sequence < 1
            || state.sequence > MAX_SAFE
            || !valid_v2_timestamp(state.updated_at)
            || !sorted_unique
        {
            return Err(duty(
                "v2 status publisher state is invalid, or its revoked set is not sorted and unique",
            ));
        }
        if at <= state.updated_at {
            return Err(duty(format!(
                "v2 status update time {at} must be later than the last list's updated_at {}",
                state.updated_at
            )));
        }
        Ok(())
    }

    fn list(
        &self,
        ctx: &V2Context,
        state: &V2StatusPublisherState,
        sequence: i64,
        updated_at: i64,
    ) -> V2SignResult<V2StatusPublication> {
        let next_update = checked_add_v2(updated_at, self.lifetime);
        let Some(next_update) =
            next_update.filter(|n| valid_v2_timestamp(updated_at) && valid_v2_timestamp(*n))
        else {
            return Err(duty("v2 status list times leave the timestamp domain"));
        };
        let list = RevocationListV2 {
            version: 2,
            issuer_id: self.issuer_id.clone(),
            updated_at,
            next_update,
            sequence,
            revoked: state
                .revoked
                .iter()
                .map(|id| RevokedCertV2 {
                    cert_id: id.clone(),
                })
                .collect(),
            signature: placeholder_signature(),
        };
        let list = sign_revocation_list_v2_with_signer(
            ctx,
            &list,
            &self.issuer_id,
            &self.status_key,
            self.signer.as_ref(),
        )?;
        let mut next = state.clone();
        next.sequence = sequence;
        next.updated_at = updated_at;
        Ok(V2StatusPublication {
            state: next,
            list,
            push: None,
        })
    }
}
