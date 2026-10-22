//! Composed transaction-receipt verification (SPEC-v2 §5.7). Mirrors Go
//! `transaction_verify_v2.go`.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::archival::FRESHNESS_UNVERIFIED_V2;
use super::context::V2Context;
use super::crypto::{equal_keys, key_id_v2};
use super::errors::{err, V2ErrorClass, V2Result};
use super::journal::SecurityJournalStoreV2;
use super::limits::{checked_add_v2, valid_v2_timestamp, V2_MAX_DELEGATION_LIFETIME_SECONDS, V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_TIMESTAMP_SECONDS};
use super::receipt::StatusEvidenceEntryV2;
use super::status::{RevocationStatusPolicyV2, V2CertificateStatusCheck};
use super::status_provenance::{run_v2_status_stage, V2StatusEvidenceProvider, V2StatusKeyConfig, V2StatusStageInputs};
use super::transaction::{decode_transaction_receipt_v2, TransactionReceiptPartyV2};
use super::verify::{call_v2_trust_safely, validate_v2_status_configuration, V2TrustOutcome, V2TrustProvider};
use super::wire::validate_scopes_v2;
use crate::scope::{intersect_scopes, SCOPE_IDENTITY_DELEGATE};

/// The caller-authenticated trust and status sources for composed
/// transaction-receipt verification. They have the same shapes as the live
/// verifier's callbacks and request configuration, so one deployment
/// configuration serves both. A `None` trust means trust is unavailable; a
/// `None` status provider or journal, or an issuer without a status key,
/// makes that issuer's status unavailable.
#[derive(Clone, Default)]
pub struct TransactionVerifySourcesV2 {
    pub trust: Option<V2TrustProvider>,
    pub status_evidence: Option<V2StatusEvidenceProvider>,
    pub status_journal: Option<Arc<dyn SecurityJournalStoreV2>>,
    pub status_keys: BTreeMap<String, V2StatusKeyConfig>,
    pub status_policy: RevocationStatusPolicyV2,
}

/// One composed transaction-receipt check. `now` is the caller-supplied
/// authoritative evaluation time and `future_skew_seconds` the configured
/// future skew (0..300) for delegation issuance times.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionVerifyRequestV2 {
    pub receipt: Vec<u8>,
    pub now: i64,
    pub future_skew_seconds: i64,
}

/// The per-party evidence of SPEC-v2 §5.7. A dimension after a non-trusted
/// trust assessment is `not_evaluated`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionPartyVerificationV2 {
    pub party_id: String,
    pub agent_id: String,
    pub required_scope: String,
    /// trusted | untrusted | unavailable.
    pub trust_assessment: String,
    /// current | expired | invalid | not_evaluated.
    pub delegation_assessment: String,
    /// The earliest expires_at in the chain, or `None` when the delegation
    /// dimension was not evaluated.
    pub delegation_expires_at: Option<i64>,
    /// current | revoked | stale | unavailable | not_evaluated.
    pub status_assessment: String,
    /// covered | not_covered | invalid_scope | delegation_not_authorized |
    /// not_evaluated.
    pub scope_assessment: String,
    /// Always `freshness_unverified`: no live challenge is consumed.
    pub freshness: String,
    pub status_evidence: Vec<StatusEvidenceEntryV2>,
}

/// Evidence about signed authority. It is never an authorization decision:
/// `actionable` is always false. Parties are sorted by party_id.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionReceiptVerificationV2 {
    pub transaction_id: String,
    pub actionable: bool,
    pub parties: Vec<TransactionPartyVerificationV2>,
}

/// Go `VerifyTransactionReceiptV2`: first verifies the complete receipt
/// (structure, every party signature, bundle hash, bundle signature, party
/// binding and transaction-derived context); any failure returns its error
/// class and invokes no provider. It then evaluates each party in party_id
/// order: trust, delegation times, status of every chain CertificateRef, and
/// the effective delegated scope. It never claims a challenge and never
/// evaluates request-context constraints. A cancelled context is
/// `evaluation_cancelled` (Go returns the context error).
pub fn verify_transaction_receipt_v2(
    ctx: &V2Context,
    req: &TransactionVerifyRequestV2,
    sources: &TransactionVerifySourcesV2,
) -> V2Result<TransactionReceiptVerificationV2> {
    validate_v2_transaction_verify_configuration(req, sources)?;
    let receipt = decode_transaction_receipt_v2(&req.receipt)?;
    let mut result = TransactionReceiptVerificationV2 {
        transaction_id: receipt.transaction_id.clone(),
        actionable: false,
        parties: Vec::new(),
    };
    for party in &receipt.parties {
        if ctx.is_done() {
            return cancelled();
        }
        result.parties.push(verify_transaction_party_v2(ctx, party, req, sources)?);
    }
    Ok(result)
}

fn cancelled<T>() -> V2Result<T> {
    err(V2ErrorClass::EvaluationCancelled, "transaction verification context is done")
}

fn validate_v2_transaction_verify_configuration(
    req: &TransactionVerifyRequestV2,
    sources: &TransactionVerifySourcesV2,
) -> V2Result<()> {
    if !valid_v2_timestamp(req.now) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("transaction verification time is outside 0..{V2_MAX_TIMESTAMP_SECONDS}"),
        );
    }
    if !(0..=V2_MAX_FUTURE_SKEW_SECONDS).contains(&req.future_skew_seconds) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("transaction verification future skew must be 0..{V2_MAX_FUTURE_SKEW_SECONDS} seconds"),
        );
    }
    validate_v2_status_configuration(&sources.status_keys, &sources.status_policy)
}

fn verify_transaction_party_v2(
    ctx: &V2Context,
    party: &TransactionReceiptPartyV2,
    req: &TransactionVerifyRequestV2,
    sources: &TransactionVerifySourcesV2,
) -> V2Result<TransactionPartyVerificationV2> {
    let mut out = TransactionPartyVerificationV2 {
        party_id: party.party_id.clone(),
        agent_id: party.agent_id.clone(),
        required_scope: party.required_scope.clone(),
        trust_assessment: "unavailable".into(),
        delegation_assessment: "not_evaluated".into(),
        delegation_expires_at: None,
        status_assessment: "not_evaluated".into(),
        scope_assessment: "not_evaluated".into(),
        freshness: FRESHNESS_UNVERIFIED_V2.into(),
        status_evidence: Vec::new(),
    };
    // Decoding rejects a party without a proof or with an empty chain.
    let Some(bundle) = &party.proof_bundle else {
        return err(V2ErrorClass::TransactionPartyMismatch, "transaction party has no proof bundle");
    };
    let chain = &bundle.delegations;
    let (Some(first), Some(root)) = (chain.first(), chain.last()) else {
        return err(V2ErrorClass::TransactionPartyMismatch, "transaction party proof has no delegation");
    };
    let resolution = call_v2_trust_safely(ctx, sources.trust.as_ref(), chain);
    if resolution.is_err() && ctx.is_done() {
        return cancelled();
    }
    if let (Ok(resolution), Some(_)) = (&resolution, &sources.trust) {
        match resolution.outcome {
            V2TrustOutcome::Trusted => {
                if let Ok(root_id) = key_id_v2(&resolution.root_key) {
                    if root_id == root.issuer_id && equal_keys(&resolution.root_key, &root.issuer_pub_key) {
                        out.trust_assessment = "trusted".into();
                    }
                }
            }
            V2TrustOutcome::Untrusted => out.trust_assessment = "untrusted".into(),
            V2TrustOutcome::Unavailable | V2TrustOutcome::Ambiguous => {}
        }
    }
    if out.trust_assessment != "trusted" {
        return Ok(out);
    }

    // Delegation validity uses the §6.7 rules at the evaluation time.
    out.delegation_assessment = "current".into();
    let mut earliest = first.expires_at;
    for cert in chain {
        earliest = earliest.min(cert.expires_at);
        let latest_issue = checked_add_v2(req.now, req.future_skew_seconds);
        let invalid = latest_issue.is_none_or(|latest| cert.issued_at > latest)
            || cert.issued_at >= cert.expires_at
            || cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS;
        if invalid {
            out.delegation_assessment = "invalid".into();
        } else if req.now >= cert.expires_at && out.delegation_assessment == "current" {
            out.delegation_assessment = "expired".into();
        }
    }
    out.delegation_expires_at = Some(earliest);

    let checks: Vec<V2CertificateStatusCheck> = chain
        .iter()
        .enumerate()
        .map(|(i, cert)| V2CertificateStatusCheck {
            delegation_index: i,
            issuer_id: cert.issuer_id.clone(),
            subject_id: cert.subject_id.clone(),
            cert_id: cert.cert_id.clone(),
        })
        .collect();
    let inputs = V2StatusStageInputs {
        status_evidence: sources.status_evidence.as_ref(),
        status_journal: sources.status_journal.as_deref(),
        status_keys: &sources.status_keys,
        status_policy: &sources.status_policy,
    };
    let stage = run_v2_status_stage(ctx, bundle, &checks, &inputs, req.now);
    if stage.cancelled {
        return cancelled();
    }
    out.status_assessment = stage.assessment.assessment.clone();
    out.status_evidence = stage.assessment.evidence.clone();

    out.scope_assessment = "covered".into();
    for cert in chain {
        if validate_scopes_v2(&cert.scope).is_err() {
            out.scope_assessment = "invalid_scope".into();
            return Ok(out);
        }
    }
    for pair in chain.windows(2) {
        if let [_, parent] = pair {
            if !parent.scope.iter().any(|s| s == SCOPE_IDENTITY_DELEGATE) {
                out.scope_assessment = "delegation_not_authorized".into();
                return Ok(out);
            }
        }
    }
    let scopes: Vec<&[String]> = chain.iter().map(|c| c.scope.as_slice()).collect();
    if !intersect_scopes(&scopes).contains(&party.required_scope) {
        out.scope_assessment = "not_covered".into();
    }
    Ok(out)
}
