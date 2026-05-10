//! Verify — the core verifier. Mirrors the Go reference verify.go exactly.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::constraints::evaluate_constraints;
use std::collections::HashMap;

use crate::crypto::{
    transaction_receipt_sign_bytes, verify_both, verify_challenge_signature_with_stream,
    verify_delegation_signature_e, verify_session_token_e,
};
use crate::scope::{intersect_scopes, SCOPE_IDENTITY_DELEGATE};
use crate::types::{
    HybridPublicKey, HybridSignature, IdentityStatus, ProofBundle, SessionToken,
    TransactionReceipt, TransactionReceiptResult, VerifyOptions, VerifyResult,
    CHALLENGE_WINDOW_SECONDS, ED25519_PUBLIC_KEY_SIZE, MAX_DELEGATION_CHAIN_DEPTH,
    MLDSA65_PUBLIC_KEY_SIZE, PROTOCOL_VERSION,
};

pub fn verify_bundle(bundle: &ProofBundle, opts: &VerifyOptions) -> VerifyResult {
    let now = opts.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    });

    // --- Structure ---
    if bundle.delegations.is_empty() {
        return invalid(
            "no_delegations",
            "proof bundle contains no delegation certificates",
        );
    }
    if bundle.delegations.len() > MAX_DELEGATION_CHAIN_DEPTH {
        return invalid("chain_too_deep", "delegation chain exceeds maximum depth");
    }
    if bundle.challenge.is_empty() {
        return invalid("no_challenge", "proof bundle contains no challenge");
    }
    if !bundle.session_context.is_empty() && bundle.session_context.len() != 32 {
        return invalid(
            "invalid_session_context",
            &format!(
                "session_context must be 32 bytes, got {}",
                bundle.session_context.len()
            ),
        );
    }
    if !opts.session_context.is_empty() && opts.session_context.len() != 32 {
        return invalid(
            "invalid_session_context",
            &format!(
                "verify option session_context must be 32 bytes, got {}",
                opts.session_context.len()
            ),
        );
    }
    if !opts.session_context.is_empty() {
        if bundle.session_context.is_empty() {
            return invalid(
                "missing_session_context",
                "verifier requires a session-bound challenge but bundle has no session_context",
            );
        }
        if bundle.session_context != opts.session_context {
            return invalid(
                "session_context_mismatch",
                "bundle session_context does not match verifier context",
            );
        }
    } else if !bundle.session_context.is_empty() {
        return invalid(
            "session_context_unverifiable",
            "bundle has session_context but verifier did not provide one",
        );
    }

    // --- v1.1 stream binding checks (SPEC §5.8, §6.4.2) ---
    if !bundle.stream_id.is_empty() && bundle.stream_id.len() != 32 {
        return invalid(
            "invalid_stream_id",
            &format!("stream_id must be 32 bytes, got {}", bundle.stream_id.len()),
        );
    }
    if bundle.stream_id.is_empty() && bundle.stream_seq != 0 {
        return invalid("invalid_stream_seq", "stream_seq set without stream_id");
    }
    if !bundle.stream_id.is_empty() && bundle.stream_seq < 1 {
        return invalid(
            "invalid_stream_seq",
            &format!("stream_seq must be >=1, got {}", bundle.stream_seq),
        );
    }
    if let Some(stream) = &opts.stream {
        if stream.stream_id.len() != 32 {
            return invalid(
                "invalid_stream_id",
                &format!(
                    "verify option stream_id must be 32 bytes, got {}",
                    stream.stream_id.len()
                ),
            );
        }
        if bundle.stream_id.is_empty() {
            return invalid(
                "missing_stream_context",
                "verifier requires a stream-bound challenge but bundle has no stream_id",
            );
        }
        if bundle.stream_id != stream.stream_id {
            return invalid(
                "stream_id_mismatch",
                "bundle stream_id does not match verifier stream context",
            );
        }
        let expected = stream.last_seen_seq + 1;
        if bundle.stream_seq <= stream.last_seen_seq {
            return invalid(
                "stream_seq_replay",
                &format!(
                    "stream_seq {} already seen (last={})",
                    bundle.stream_seq, stream.last_seen_seq
                ),
            );
        }
        if bundle.stream_seq != expected {
            return invalid(
                "stream_seq_skip",
                &format!(
                    "stream_seq {} skips expected {}",
                    bundle.stream_seq, expected
                ),
            );
        }
    } else if !bundle.stream_id.is_empty() {
        return invalid(
            "stream_context_unverifiable",
            "bundle has stream_id but verifier did not provide a stream context",
        );
    }

    if let Some(err) = validate_hybrid_pubkey_lens(&bundle.agent_pub_key, "agent") {
        return invalid("invalid_agent_key", &err);
    }

    let first_cert = &bundle.delegations[0];
    let human_id = bundle.delegations.last().unwrap().issuer_id.clone();

    if !hybrid_pub_key_equal(&bundle.agent_pub_key, &first_cert.subject_pub_key) {
        return invalid(
            "key_mismatch",
            "agent public key does not match delegation subject",
        );
    }
    if bundle.agent_id != first_cert.subject_id {
        return invalid(
            "id_mismatch",
            "agent ID does not match delegation subject ID",
        );
    }

    if opts.force_revocation_check && opts.is_revoked.is_none() {
        return invalid(
            "force_revocation_no_callback",
            "force_revocation_check is true but is_revoked callback is missing",
        );
    }

    // --- Per-cert ---
    for (i, cert) in bundle.delegations.iter().enumerate() {
        if cert.version != PROTOCOL_VERSION {
            return invalid(
                "version_mismatch",
                &format!("cert {} has unsupported version {}", i, cert.version),
            );
        }
        if now > cert.expires_at {
            return expired(&human_id, &bundle.agent_id);
        }
        if now < cert.issued_at {
            return invalid("not_yet_valid", &format!("cert {} is not yet valid", i));
        }
        if let Some(check) = &opts.is_revoked {
            if check(&cert.cert_id) {
                return revoked(&human_id, &bundle.agent_id);
            }
        }
        if let Err(sig_err) = verify_delegation_signature_e(cert) {
            return invalid("bad_signature", &format!("cert {}: {}", i, sig_err));
        }
        // Constraint evaluation — each cert's first-class constraints must all
        // pass against the caller-supplied VerifierContext. Fail-closed.
        if let Err(constraint_err) = evaluate_constraints(cert, &opts.context, now) {
            // Route constraint failures to the specific identity_status so
            // audit layers can distinguish unverifiable / unknown / denied.
            // Matches Go/TS/Python.
            let status = if constraint_err.contains("constraint_unverifiable") {
                "constraint_unverifiable"
            } else if constraint_err.contains("constraint_unknown") {
                "constraint_unknown"
            } else {
                "constraint_denied"
            };
            return fail_with_status(status, &format!("cert {}: {}", i, constraint_err));
        }
        // Chain linkage
        if i + 1 < bundle.delegations.len() {
            let next = &bundle.delegations[i + 1];
            if cert.issuer_id != next.subject_id {
                return invalid(
                    "broken_chain",
                    &format!("cert {} issuer does not match cert {} subject", i, i + 1),
                );
            }
            if !hybrid_pub_key_equal(&cert.issuer_pub_key, &next.subject_pub_key) {
                return invalid(
                    "broken_chain_keys",
                    &format!(
                        "cert {} issuer key does not match cert {} subject key",
                        i,
                        i + 1
                    ),
                );
            }
            // Sub-delegation gate: parent cert must have granted identity:delegate.
            if !next.scope.iter().any(|s| s == SCOPE_IDENTITY_DELEGATE) {
                return fail_with_status(
                    "delegation_not_authorized",
                    &format!(
                        "cert {} issued by a subject whose parent cert {} did not grant \"{}\"",
                        i,
                        i + 1,
                        SCOPE_IDENTITY_DELEGATE
                    ),
                );
            }
        }
    }

    // --- Liveness ---
    let challenge_age = now - bundle.challenge_at;
    if challenge_age < 0 || challenge_age > CHALLENGE_WINDOW_SECONDS {
        return invalid(
            "stale_challenge",
            &format!(
                "challenge is {} seconds old (max {})",
                challenge_age, CHALLENGE_WINDOW_SECONDS
            ),
        );
    }
    if let Err(err) = verify_challenge_signature_with_stream(
        &bundle.challenge,
        bundle.challenge_at,
        &bundle.session_context,
        &bundle.stream_id,
        bundle.stream_seq,
        &bundle.challenge_sig,
        &bundle.agent_pub_key,
    ) {
        return invalid(
            "bad_challenge_sig",
            &format!("challenge signature verification failed: {}", err),
        );
    }

    // --- Effective scope ---
    let scope_refs: Vec<&[String]> = bundle
        .delegations
        .iter()
        .map(|c| c.scope.as_slice())
        .collect();
    let effective = intersect_scopes(&scope_refs);

    if !opts.required_scope.is_empty() && !effective.iter().any(|s| s == &opts.required_scope) {
        return fail_with_status(
            "scope_denied",
            &format!(
                "required scope \"{}\" not in effective delegation scope",
                opts.required_scope
            ),
        );
    }

    VerifyResult {
        valid: true,
        identity_status: IdentityStatus::AuthorizedAgent,
        human_id,
        agent_id: bundle.agent_id.clone(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: effective,
        error_reason: String::new(),
    }
}

// ----------------------------------------------------------------------

fn hybrid_pub_key_equal(a: &HybridPublicKey, b: &HybridPublicKey) -> bool {
    a.ed25519 == b.ed25519 && a.ml_dsa_65 == b.ml_dsa_65
}

fn validate_hybrid_pubkey_lens(pub_key: &HybridPublicKey, label: &str) -> Option<String> {
    if pub_key.ed25519.len() != ED25519_PUBLIC_KEY_SIZE {
        return Some(format!(
            "{} Ed25519 public key has wrong length: {}",
            label,
            pub_key.ed25519.len()
        ));
    }
    if pub_key.ml_dsa_65.len() != MLDSA65_PUBLIC_KEY_SIZE {
        return Some(format!(
            "{} ML-DSA-65 public key has wrong length: {}",
            label,
            pub_key.ml_dsa_65.len()
        ));
    }
    None
}

fn invalid(reason: &str, msg: &str) -> VerifyResult {
    VerifyResult {
        valid: false,
        identity_status: IdentityStatus::Invalid,
        human_id: String::new(),
        agent_id: String::new(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: Vec::new(),
        error_reason: format!("{}: {}", reason, msg),
    }
}

/// fail_with_status is used when the failure maps to its own identity_status
/// (scope_denied, constraint_denied, constraint_unverifiable,
/// delegation_not_authorized). Unknown `status` strings fall back to Invalid
/// — the wire form for error_reason still reflects the intended status so
/// audits aren't lossy.
fn fail_with_status(status: &str, msg: &str) -> VerifyResult {
    let st = IdentityStatus::from_wire(status).unwrap_or(IdentityStatus::Invalid);
    VerifyResult {
        valid: false,
        identity_status: st,
        human_id: String::new(),
        agent_id: String::new(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: Vec::new(),
        error_reason: format!("{}: {}", status, msg),
    }
}

fn expired(human_id: &str, agent_id: &str) -> VerifyResult {
    VerifyResult {
        valid: false,
        identity_status: IdentityStatus::Expired,
        human_id: human_id.to_string(),
        agent_id: agent_id.to_string(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: Vec::new(),
        error_reason: "delegation certificate has expired".to_string(),
    }
}

fn revoked(human_id: &str, agent_id: &str) -> VerifyResult {
    VerifyResult {
        valid: false,
        identity_status: IdentityStatus::Revoked,
        human_id: human_id.to_string(),
        agent_id: agent_id.to_string(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: Vec::new(),
        error_reason: "delegation certificate has been revoked".to_string(),
    }
}

// ----------------------------------------------------------------------
// v1.1 transaction receipt verification
// ----------------------------------------------------------------------

/// Verify a TransactionReceipt: envelope checks, per-party bundle
/// verification, and party signature verification over the canonical signable.
pub fn verify_transaction_receipt(
    receipt: &TransactionReceipt,
    now: i64,
) -> TransactionReceiptResult {
    if receipt.version != PROTOCOL_VERSION {
        return receipt_fail(&format!(
            "version_mismatch: unsupported version {}",
            receipt.version
        ));
    }
    if receipt.transaction_id.is_empty() {
        return receipt_fail("missing_transaction_id: transaction_id must not be empty");
    }
    if receipt.terms_schema_uri.is_empty() {
        return receipt_fail("missing_terms_schema_uri: terms_schema_uri must not be empty");
    }
    if receipt.terms_canonical_json.is_empty() {
        return receipt_fail(
            "missing_terms_canonical_json: terms_canonical_json must not be empty",
        );
    }
    if receipt.parties.is_empty() {
        return receipt_fail("no_parties: receipt must list at least one party");
    }

    // Party IDs must be unique.
    let mut party_idx: HashMap<&str, usize> = HashMap::new();
    for (i, p) in receipt.parties.iter().enumerate() {
        if p.party_id.is_empty() {
            return receipt_fail(&format!("empty_party_id: party {} has no party_id", i));
        }
        if party_idx.contains_key(p.party_id.as_str()) {
            return receipt_fail(&format!(
                "duplicate_party_id: {:?} listed more than once",
                p.party_id
            ));
        }
        party_idx.insert(&p.party_id, i);
    }

    // Each listed party must have exactly one signature; every signature's
    // party_id must refer to a listed party.
    let mut sig_by_party: HashMap<&str, usize> = HashMap::new();
    for (i, s) in receipt.party_signatures.iter().enumerate() {
        if !party_idx.contains_key(s.party_id.as_str()) {
            return receipt_fail(&format!(
                "unknown_party_signature: signature {} references unknown party_id {:?}",
                i, s.party_id
            ));
        }
        if sig_by_party.contains_key(s.party_id.as_str()) {
            return receipt_fail(&format!(
                "duplicate_party_signature: party {:?} has multiple signatures",
                s.party_id
            ));
        }
        sig_by_party.insert(&s.party_id, i);
    }
    for p in &receipt.parties {
        if !sig_by_party.contains_key(p.party_id.as_str()) {
            return receipt_fail(&format!(
                "missing_party_signature: party {:?} has no signature",
                p.party_id
            ));
        }
    }

    // Canonical signable bytes.
    let signable = transaction_receipt_sign_bytes(receipt);

    let mut party_results = Vec::with_capacity(receipt.parties.len());
    for p in &receipt.parties {
        // Proof bundle's agent_id / agent_pub_key MUST match the party's.
        if p.proof_bundle.agent_id != p.agent_id {
            return receipt_fail_with_results(
                &format!(
                    "party_agent_id_mismatch: party {:?} proof_bundle.agent_id={:?} != party.agent_id={:?}",
                    p.party_id, p.proof_bundle.agent_id, p.agent_id
                ),
                party_results,
            );
        }
        if !hybrid_pub_key_equal(&p.proof_bundle.agent_pub_key, &p.agent_pub_key) {
            return receipt_fail_with_results(
                &format!(
                    "party_agent_key_mismatch: party {:?} proof_bundle.agent_pub_key != party.agent_pub_key",
                    p.party_id
                ),
                party_results,
            );
        }

        // Bundle verification.
        let bundle_opts = VerifyOptions {
            now: Some(now),
            ..VerifyOptions::default()
        };
        let r = verify_bundle(&p.proof_bundle, &bundle_opts);
        party_results.push(r.clone());
        if !r.valid {
            return receipt_fail_with_results(
                &format!(
                    "party_bundle_invalid: party {:?} status={} reason={}",
                    p.party_id,
                    r.identity_status.as_str(),
                    r.error_reason
                ),
                party_results,
            );
        }

        // Party signature check over the atomic signable.
        let sig_idx = sig_by_party[p.party_id.as_str()];
        let sig = &receipt.party_signatures[sig_idx].signature;
        if let Err(e) = verify_both(&signable, sig, &p.agent_pub_key) {
            return receipt_fail_with_results(
                &format!("party_signature_invalid: party {:?}: {}", p.party_id, e),
                party_results,
            );
        }
    }

    TransactionReceiptResult {
        valid: true,
        error_reason: String::new(),
        party_results,
    }
}

fn receipt_fail(reason: &str) -> TransactionReceiptResult {
    TransactionReceiptResult {
        valid: false,
        error_reason: reason.to_string(),
        party_results: Vec::new(),
    }
}

fn receipt_fail_with_results(
    reason: &str,
    party_results: Vec<VerifyResult>,
) -> TransactionReceiptResult {
    TransactionReceiptResult {
        valid: false,
        error_reason: reason.to_string(),
        party_results,
    }
}

// ----------------------------------------------------------------------
// v1.1 session cert cache (ROADMAP 2.3) streamed-turn verification
// ----------------------------------------------------------------------

/// Fast-path verifier for streamed turns that present a SessionToken in
/// place of the full cert chain. Checks HMAC, validity window, challenge
/// freshness, and hybrid challenge signature against token.agent_pub_key.
/// The chain is NOT re-verified — that's the point of the token.
#[allow(clippy::too_many_arguments)]
pub fn verify_streamed_turn(
    token: &SessionToken,
    session_secret: &[u8],
    challenge: &[u8],
    challenge_at: i64,
    challenge_sig: &HybridSignature,
    session_context: &[u8],
    stream_id: &[u8],
    stream_seq: i64,
    now: i64,
) -> VerifyResult {
    if let Err(e) = verify_session_token_e(token, session_secret, now) {
        return invalid("session_token_invalid", &e);
    }
    if challenge.is_empty() {
        return invalid("no_challenge", "streamed turn contains no challenge");
    }
    if !session_context.is_empty() && session_context.len() != 32 {
        return invalid(
            "invalid_session_context",
            &format!(
                "session_context must be 32 bytes, got {}",
                session_context.len()
            ),
        );
    }
    if !stream_id.is_empty() && stream_id.len() != 32 {
        return invalid(
            "invalid_stream_id",
            &format!("stream_id must be 32 bytes, got {}", stream_id.len()),
        );
    }
    if !stream_id.is_empty() && stream_seq < 1 {
        return invalid(
            "invalid_stream_seq",
            &format!("stream_seq must be >=1, got {}", stream_seq),
        );
    }
    let challenge_age = now - challenge_at;
    if challenge_age < 0 || challenge_age > CHALLENGE_WINDOW_SECONDS {
        return invalid(
            "stale_challenge",
            &format!(
                "challenge is {} seconds old (max {})",
                challenge_age, CHALLENGE_WINDOW_SECONDS
            ),
        );
    }
    if let Err(err) = verify_challenge_signature_with_stream(
        challenge,
        challenge_at,
        session_context,
        stream_id,
        stream_seq,
        challenge_sig,
        &token.agent_pub_key,
    ) {
        return invalid(
            "bad_challenge_sig",
            &format!("challenge signature verification failed: {}", err),
        );
    }
    VerifyResult {
        valid: true,
        identity_status: IdentityStatus::AuthorizedAgent,
        human_id: token.human_id.clone(),
        agent_id: token.agent_id.clone(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: token.granted_scope.clone(),
        error_reason: String::new(),
    }
}
