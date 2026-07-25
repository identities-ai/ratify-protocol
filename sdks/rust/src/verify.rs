//! Verify — the core verifier. Mirrors the Go reference verify.go exactly.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

use alloc::collections::BTreeMap;

use crate::challenge_store::UNKNOWN_CHALLENGE;
use crate::constraints::evaluate_constraints;

use crate::crypto::{
    transaction_receipt_sign_bytes, verify_both, verify_challenge_signature_with_stream,
    verify_delegation_signature_e, verify_session_token_e,
};
use crate::scope::{intersect_scopes, validate_scopes, SCOPE_IDENTITY_DELEGATE};
use crate::types::{
    DelegationCert, HybridPublicKey, HybridSignature, IdentityStatus, ProofBundle, SessionToken,
    StreamContext, TransactionReceipt, TransactionReceiptResult, VerifyOptions, VerifyResult,
    CHALLENGE_WINDOW_SECONDS, ED25519_PUBLIC_KEY_SIZE, MAX_DELEGATION_CHAIN_DEPTH,
    MLDSA65_PUBLIC_KEY_SIZE, PROTOCOL_VERSION,
};

/// `verify_bundle` is the entry point. Audit hook (SPEC §17.3) wraps the
/// inner verifier so it fires on every call — success AND failure — and its
/// errors are swallowed so auditing never alters the verdict.
pub fn verify_bundle(bundle: &ProofBundle, opts: &VerifyOptions) -> VerifyResult {
    let res = verify_bundle_inner(bundle, opts);
    if let Some(audit) = &opts.audit {
        audit.log_verification(&res, bundle);
    }
    res
}

fn verify_bundle_inner(bundle: &ProofBundle, opts: &VerifyOptions) -> VerifyResult {
    let now = opts.now.unwrap_or_else(|| {
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        }
        #[cfg(not(feature = "std"))]
        {
            // Without std, callers MUST supply opts.now.
            panic!("verify_bundle: opts.now must be set when std feature is disabled")
        }
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

    // --- Single-use challenge: locate WITHOUT consuming (SPEC §10) ---
    // An unknown, expired, already-consumed, or wrongly-bound challenge is
    // rejected before any signature work; the record is not touched, so a
    // forged presentation cannot burn a legitimate challenge. The store's
    // error is discarded: the public result always carries the canonical
    // UNKNOWN_CHALLENGE text so no store failure mode is distinguishable.
    if let Some(store) = &opts.challenge_store {
        if store
            .validate(&bundle.challenge, &opts.session_context, now)
            .is_err()
        {
            return invalid("unknown_challenge", UNKNOWN_CHALLENGE);
        }
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

    #[allow(deprecated)]
    let legacy_revoke = opts.is_revoked.as_ref();
    if opts.force_revocation_check && legacy_revoke.is_none() && opts.revocation.is_none() {
        return invalid(
            "force_revocation_no_callback",
            "force_revocation_check is true but neither is_revoked nor revocation provider is set",
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
        // Scope vocabulary validation (SPEC §9): every granted scope must be
        // canonical, a wildcard, or a custom: extension. Checked before any
        // scope arithmetic so invalid vocabulary can never reach the
        // effective-scope intersection.
        if let Some(scope_err) = validate_scopes(&cert.scope) {
            return fail_with_status("invalid_scope", &format!("cert {}: {}", i, scope_err));
        }
        if now > cert.expires_at {
            return expired(&human_id, &bundle.agent_id);
        }
        if now < cert.issued_at {
            return invalid("not_yet_valid", &format!("cert {} is not yet valid", i));
        }
        // Revocation: provider (SPEC §17.1) takes precedence over legacy closure.
        if let Some(provider) = &opts.revocation {
            match provider.is_revoked(&cert.cert_id) {
                Err(e) => {
                    return invalid(
                        "revocation_error",
                        &format!("cert {}: revocation lookup failed: {}", i, e),
                    )
                }
                Ok(true) => return revoked(&human_id, &bundle.agent_id),
                Ok(false) => {}
            }
        } else if let Some(check) = legacy_revoke {
            if check(&cert.cert_id) {
                return revoked(&human_id, &bundle.agent_id);
            }
        }
        if let Err(sig_err) = verify_delegation_signature_e(cert) {
            return invalid("bad_signature", &format!("cert {}: {}", i, sig_err));
        }
        // Constraint evaluation — each cert's first-class constraints must all
        // pass against the caller-supplied VerifierContext. Fail-closed.
        // With a challenge store in play, constraint evaluation is deferred
        // until after the challenge is consumed (SPEC §10): a
        // cryptographically valid presentation spends its challenge even
        // when a constraint subsequently denies it, so denial outcomes
        // cannot be probed with one liveness proof.
        if opts.challenge_store.is_none() {
            if let Some(failure) = evaluate_cert_constraints(cert, i, opts, now) {
                return failure;
            }
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
    if !(0..=CHALLENGE_WINDOW_SECONDS).contains(&challenge_age) {
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

    // --- Single-use challenge: atomic consume (SPEC §10) ---
    // Structure, chain, and challenge signature have all verified, so this
    // presentation is cryptographically the agent's. Consume the challenge
    // now — before authorization evaluation — so a later replay of the
    // same challenge fails even if this presentation is subsequently
    // denied.
    if let Some(store) = &opts.challenge_store {
        if store
            .consume(&bundle.challenge, &opts.session_context, now)
            .is_err()
        {
            return invalid("unknown_challenge", UNKNOWN_CHALLENGE);
        }
        // Deferred constraint evaluation (skipped in the per-cert loop
        // above when a store is present).
        for (i, cert) in bundle.delegations.iter().enumerate() {
            if let Some(failure) = evaluate_cert_constraints(cert, i, opts, now) {
                return failure;
            }
        }
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

    let mut result = VerifyResult {
        valid: true,
        identity_status: IdentityStatus::AuthorizedAgent,
        human_id: human_id.clone(),
        agent_id: bundle.agent_id.clone(),
        agent_name: String::new(),
        agent_type: String::new(),
        granted_scope: effective,
        error_reason: String::new(),
        anchor: None,
    };

    // --- Anchor resolution (SPEC §17.8) ---
    // Best-effort: populate anchor on the success result so downstream
    // AuditProviders observe an identity-bound receipt. Resolver errors are
    // non-fatal.
    if let Some(resolver) = &opts.anchor_resolver {
        if let Ok(Some(anchor)) = resolver.resolve_anchor(&human_id) {
            result.anchor = Some(anchor);
        }
    }

    // --- Advanced Policy Gating (SPEC §17.2 / §17.6) ---
    //
    // Fast path: if a PolicyVerdict is supplied AND verifies cleanly, skip
    // the live Policy provider entirely.
    if let (Some(verdict), Some(secret)) = (&opts.policy_verdict, &opts.policy_secret) {
        if !opts.required_scope.is_empty() {
            match crate::receipts::verifier_context_hash(&opts.context) {
                Err(e) => {
                    return invalid(
                        "policy_error",
                        &format!("verifier context hash failed: {}", e),
                    );
                }
                Ok(ctx_hash) => {
                    let v_err = crate::receipts::verify_policy_verdict(
                        verdict,
                        secret,
                        &bundle.agent_id,
                        &opts.required_scope,
                        &ctx_hash,
                        now,
                    );
                    match v_err {
                        Ok(()) => return result,
                        Err(e) if e.starts_with("policy_verdict_denied") => {
                            return fail_with_status(
                                "scope_denied",
                                "policy verdict (cached) denied access",
                            );
                        }
                        Err(_) => {
                            // stale verdict — fall through to live policy
                        }
                    }
                }
            }
        }
    }

    if let Some(policy) = &opts.policy {
        match policy.evaluate_policy(bundle, &opts.context) {
            Err(e) => {
                return invalid(
                    "policy_error",
                    &format!("advanced policy evaluation failed: {}", e),
                )
            }
            Ok(false) => {
                return fail_with_status(
                    "scope_denied",
                    "advanced policy evaluation denied access",
                )
            }
            Ok(true) => {}
        }
    }

    result
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

/// Run one cert's constraint evaluation and map a failure to its identity
/// status; None means the constraints passed.
fn evaluate_cert_constraints(
    cert: &DelegationCert,
    i: usize,
    opts: &VerifyOptions,
    now: i64,
) -> Option<VerifyResult> {
    let constraint_err =
        evaluate_constraints(cert, &opts.context, now, opts.constraint_evaluators.as_ref()).err()?;
    // Route constraint failures to the specific identity_status so audit
    // layers can distinguish unverifiable / unknown / denied.
    // Matches Go/TS/Python.
    let status = if constraint_err.contains("constraint_unverifiable") {
        "constraint_unverifiable"
    } else if constraint_err.contains("constraint_unknown") {
        "constraint_unknown"
    } else {
        "constraint_denied"
    };
    Some(fail_with_status(
        status,
        &format!("cert {}: {}", i, constraint_err),
    ))
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
        anchor: None,
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
        anchor: None,
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
        anchor: None,
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
        anchor: None,
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
    let mut party_idx: BTreeMap<&str, usize> = BTreeMap::new();
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
    let mut sig_by_party: BTreeMap<&str, usize> = BTreeMap::new();
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

/// The presentation-side inputs of one streamed turn: the fresh challenge
/// the agent signed and the bindings it signed it under (SPEC §6.4.2).
/// Presented values, distinct from the verifier-side expectations carried
/// in [`VerifyOptions`].
#[derive(Debug, Clone)]
pub struct StreamedTurn {
    pub challenge: Vec<u8>,
    pub challenge_at: i64,
    pub challenge_sig: HybridSignature,
    /// Presented session binding (empty = unbound; otherwise 32 bytes).
    pub session_context: Vec<u8>,
    /// Presented stream binding (empty = unbound; otherwise 32 bytes with
    /// `stream_seq >= 1`).
    pub stream_id: Vec<u8>,
    pub stream_seq: i64,
}

/// The verifier-side controls that apply to a streamed-turn presentation
/// (SPEC §5.13). Deliberately NOT the full [`VerifyOptions`]: a streamed
/// turn re-verifies liveness and bindings, not the chain, so revocation,
/// policy, constraint, audit, and anchor options have no field here and
/// can never be passed and silently ignored. Callers who need fresh
/// revocation or policy semantics — including high-value operations the
/// spec directs to `force_revocation_check` — MUST run full
/// `verify_bundle` instead.
#[derive(Default)]
pub struct StreamedVerifyOptions<'a> {
    /// Must be present in `token.granted_scope` for the turn to be valid;
    /// empty skips the check. The token stores the verified chain's
    /// effective scope lex-sorted for exactly this check.
    pub required_scope: String,
    /// Makes the per-turn challenge single-use: consulted (without
    /// consuming) after the session token's HMAC authenticates the
    /// presentation and before the per-turn hybrid challenge signature is
    /// verified; atomically consumed after that signature verifies —
    /// before the scope check. Store failures normalize to the canonical
    /// unknown_challenge result.
    pub challenge_store: Option<Box<dyn crate::challenge_store::ChallengeStore + 'a>>,
    /// Verifier-side session binding; when set, the turn's presented
    /// session_context must match byte-for-byte.
    pub session_context: Vec<u8>,
    /// Verifier-side stream state (stream_id match; stream_seq must be
    /// exactly last_seen_seq+1, else stream_seq_replay /
    /// stream_seq_skip).
    ///
    /// This is a caller-owned SNAPSHOT: the verifier only reads it and
    /// never advances it. Two concurrent turns carrying distinct valid
    /// challenges and the same stream_seq will BOTH verify against the
    /// same snapshot. Concurrency-safe sequence enforcement is the
    /// caller's responsibility: atomically compare-and-advance your
    /// tracked last-seen sequence to `turn.stream_seq` when (and only
    /// when) verification succeeds, and build the snapshot from that
    /// tracked state.
    pub stream: Option<StreamContext>,
    /// Clock override (unix seconds); `None` uses the system clock (std
    /// builds only — no_std callers MUST set it).
    pub now: Option<i64>,
}

/// Options-object form of the streamed fast path (SPEC §5.13): verifies
/// one turn against a previously issued SessionToken and enforces the
/// verifier-side controls in [`StreamedVerifyOptions`] — required scope
/// against the token's cached effective scope, single-use challenges, and
/// session/stream binding checks.
pub fn verify_streamed_turn_with_options(
    token: &SessionToken,
    session_secret: &[u8],
    turn: &StreamedTurn,
    opts: &StreamedVerifyOptions,
) -> VerifyResult {
    let now = opts.now.unwrap_or_else(|| {
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        }
        #[cfg(not(feature = "std"))]
        {
            // Without std, callers MUST supply opts.now.
            panic!("verify_streamed_turn_with_options: opts.now must be set when std feature is disabled")
        }
    });

    // --- Token authenticity and validity window ---
    // Deliberately FIRST, before the challenge store is consulted: the
    // HMAC is a cheap authenticated pre-check that stops unauthenticated
    // callers from probing the challenge store. This is the documented
    // SPEC §5.13 order — it differs from §10, where no equivalent cheap
    // authenticator exists ahead of the store lookup.
    if let Err(e) = verify_session_token_e(token, session_secret, now) {
        return invalid("session_token_invalid", &e);
    }

    // --- Basic structure ---
    if turn.challenge.is_empty() {
        return invalid("no_challenge", "streamed turn contains no challenge");
    }

    // --- Session context validation (mirrors SPEC §10 step 2) ---
    if !turn.session_context.is_empty() && turn.session_context.len() != 32 {
        return invalid(
            "invalid_session_context",
            &format!(
                "session_context must be 32 bytes, got {}",
                turn.session_context.len()
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
        if turn.session_context.is_empty() {
            return invalid(
                "missing_session_context",
                "verifier requires a session-bound challenge but turn has no session_context",
            );
        }
        if turn.session_context != opts.session_context {
            return invalid(
                "session_context_mismatch",
                "turn session_context does not match verifier context",
            );
        }
    } else if !turn.session_context.is_empty() {
        return invalid(
            "session_context_unverifiable",
            "turn has session_context but verifier did not provide one",
        );
    }

    // --- Single-use challenge: locate WITHOUT consuming ---
    // Before the per-turn hybrid challenge signature is verified, so a
    // forged turn cannot burn a pending challenge and unknown challenges
    // are rejected before the expensive signature check.
    if let Some(store) = &opts.challenge_store {
        if store
            .validate(&turn.challenge, &opts.session_context, now)
            .is_err()
        {
            return invalid("unknown_challenge", UNKNOWN_CHALLENGE);
        }
    }

    // --- Stream binding validation (mirrors SPEC §10 step 3) ---
    if !turn.stream_id.is_empty() && turn.stream_id.len() != 32 {
        return invalid(
            "invalid_stream_id",
            &format!("stream_id must be 32 bytes, got {}", turn.stream_id.len()),
        );
    }
    if turn.stream_id.is_empty() && turn.stream_seq != 0 {
        return invalid("invalid_stream_seq", "stream_seq set without stream_id");
    }
    if !turn.stream_id.is_empty() && turn.stream_seq < 1 {
        return invalid(
            "invalid_stream_seq",
            &format!("stream_seq must be >=1, got {}", turn.stream_seq),
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
        if turn.stream_id.is_empty() {
            return invalid(
                "missing_stream_context",
                "verifier requires a stream-bound challenge but turn has no stream_id",
            );
        }
        if turn.stream_id != stream.stream_id {
            return invalid(
                "stream_id_mismatch",
                "turn stream_id does not match verifier stream context",
            );
        }
        let expected = stream.last_seen_seq + 1;
        if turn.stream_seq <= stream.last_seen_seq {
            return invalid(
                "stream_seq_replay",
                &format!(
                    "stream_seq {} already seen (last={})",
                    turn.stream_seq, stream.last_seen_seq
                ),
            );
        }
        if turn.stream_seq != expected {
            return invalid(
                "stream_seq_skip",
                &format!("stream_seq {} skips expected {}", turn.stream_seq, expected),
            );
        }
    } else if !turn.stream_id.is_empty() {
        return invalid(
            "stream_context_unverifiable",
            "turn has stream_id but verifier did not provide a stream context",
        );
    }

    // --- Liveness (challenge freshness + hybrid signature) ---
    let challenge_age = now - turn.challenge_at;
    if !(0..=CHALLENGE_WINDOW_SECONDS).contains(&challenge_age) {
        return invalid(
            "stale_challenge",
            &format!(
                "challenge is {} seconds old (max {})",
                challenge_age, CHALLENGE_WINDOW_SECONDS
            ),
        );
    }
    if let Err(err) = verify_challenge_signature_with_stream(
        &turn.challenge,
        turn.challenge_at,
        &turn.session_context,
        &turn.stream_id,
        turn.stream_seq,
        &turn.challenge_sig,
        &token.agent_pub_key,
    ) {
        return invalid(
            "bad_challenge_sig",
            &format!("challenge signature verification failed: {}", err),
        );
    }

    // --- Single-use challenge: atomic consume ---
    // The signature has verified. Consume before the scope check so a
    // denied caller cannot probe authorization with one liveness proof.
    if let Some(store) = &opts.challenge_store {
        if store
            .consume(&turn.challenge, &opts.session_context, now)
            .is_err()
        {
            return invalid("unknown_challenge", UNKNOWN_CHALLENGE);
        }
    }

    // --- Required scope against the token's cached effective scope ---
    if !opts.required_scope.is_empty()
        && !token
            .granted_scope
            .iter()
            .any(|s| s == &opts.required_scope)
    {
        return fail_with_status(
            "scope_denied",
            &format!(
                "required scope \"{}\" not in session token granted scope",
                opts.required_scope
            ),
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
        anchor: None,
    }
}

/// Fast-path verifier for streamed turns that present a SessionToken in
/// place of the full cert chain. Checks HMAC, validity window, challenge
/// freshness, and hybrid challenge signature against token.agent_pub_key.
/// The chain is NOT re-verified — that's the point of the token.
///
/// Presentation checks only — this form cannot enforce a required scope,
/// single-use challenges, or verifier-side session/stream checks, so a
/// token holder passes it for any protected action.
#[deprecated(
    since = "1.0.0-alpha.15",
    note = "presentation checks only — cannot enforce scope, single-use, or verifier-side bindings; use verify_streamed_turn_with_options"
)]
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
    if !(0..=CHALLENGE_WINDOW_SECONDS).contains(&challenge_age) {
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
        anchor: None,
    }
}
