//! Post-claim local authorization and the ordered post-status stages
//! (SPEC-v2 §5.2, §6.3 to §6.7). Mirrors Go `authorization_v2.go` and
//! `evaluateConstraintV2` / `loadV2TimeZone` from `constraints_v2.go`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::audience::{evaluate_receiver_audience_inner, V2AudienceMembership};
use super::claim_store::{TokenState, V2EvaluationToken, V2RateReservationStore, V2StoreError};
use super::constraints::{
    is_registered_constraint_type_v2, parse_hhmm_v2, valid_iso4217_alpha_v2, ConstraintContextV2,
    ConstraintV2, CONSTRAINT_MAX_AMOUNT, CONSTRAINT_MAX_RATE, CONSTRAINT_RECEIVER_AUDIENCE,
    CONSTRAINT_RESOURCE_PATH, CONSTRAINT_TIME_WINDOW,
};
use super::context::V2Context;
use super::context_policy::{evaluate_proof_bundle_v2_context_policy, same_v2_context_policy, V2ContextPolicy};
use super::crypto::equal_keys;
use super::errors::{plain, V2Error, V2ErrorClass, V2Result};
use super::evaluator::{
    extension_params_json_v2, run_constraint_evaluator_v2, ConstraintEvaluationInputV2, ConstraintFailure,
};
use super::limits::{checked_add_v2, valid_v2_timestamp, V2_MAX_DELEGATION_LIFETIME_SECONDS, V2_MAX_TIMESTAMP_SECONDS};
use super::operation_context::protocol_claim_id_v2;
use super::preflight::{matches_expected_challenge_v2, ExpectedChallengeStateV2, ExpectedChallengeV2};
use super::rate_reservation::build_v2_rate_reservation_batch_inner;
use super::receipt::StatusEvidenceEntryV2;
use super::status::{V2CertificateStatusCheck, V2StatusAssessment};
use super::tzdb::{civil_from_unix, load_zone, unix_from_civil_utc, Zone, TZDB_VERSION};
use super::wire::{bundle_hash_v2, validate_required_scope_v2, validate_scopes_v2, verify_proof_bundle_v2_signatures, ProofBundleV2, MAX_SAFE};
use crate::resource_path::{normalize_resource_path, resource_path_matches};
use crate::scope::{intersect_scopes, SCOPE_IDENTITY_DELEGATE};
use crate::types::HybridPublicKey;

/// The IANA tzdata release embedded in this crate and used for every
/// `time_window` evaluation (SPEC-v2 §5.2; Go `TZDBVersionV2`). A verifier
/// configures the release it requires; any other configured value, or none,
/// makes every `time_window` constraint_unverifiable.
pub const TZDB_VERSION_V2: &str = TZDB_VERSION;

/// Verifier-owned inputs for the deterministic authorization checks that
/// follow a successful challenge claim. There is no caller-supplied
/// evaluation time: every time-sensitive check uses the claim store's
/// authoritative claim time sealed in `claim_token`. `future_skew_seconds`
/// must equal the value sealed at claim.
#[derive(Debug, Clone)]
pub struct V2LocalAuthorizationOptions {
    pub future_skew_seconds: i64,
    pub required_scope: String,
    pub trusted_root_id: String,
    pub trusted_root_key: HybridPublicKey,
    pub trust_configured: bool,
    pub context: ConstraintContextV2,
    /// The caller-configured IANA tzdata release required for `time_window`;
    /// it must equal [`TZDB_VERSION_V2`].
    pub tzdb_version: String,
    pub context_policy: Option<V2ContextPolicy>,
    pub expected_challenge: Option<ExpectedChallengeV2>,
    pub claim_token: Option<V2EvaluationToken>,
}

impl Default for V2LocalAuthorizationOptions {
    fn default() -> Self {
        V2LocalAuthorizationOptions {
            future_skew_seconds: 0,
            required_scope: String::new(),
            trusted_root_id: String::new(),
            trusted_root_key: HybridPublicKey {
                ed25519: Vec::new(),
                ml_dsa_65: Vec::new(),
            },
            trust_configured: false,
            context: ConstraintContextV2::default(),
            tzdb_version: String::new(),
            context_policy: None,
            expected_challenge: None,
            claim_token: None,
        }
    }
}

/// An intermediate result, not a terminal authorization decision. Callers
/// must still evaluate issuer status and any deferred checks before an
/// action can be allowed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2LocalAuthorizationAssessment {
    /// Copied from the sealed preflight state so a terminal receipt remains
    /// bound to the claimed proof after a mismatch.
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub agent_id: String,
    pub root_id: String,
    pub required_scope: String,
    pub delegation_digest: Vec<u8>,
    pub effective_scope: Vec<String>,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub status_assessment: String,
    pub delegation_valid_until: i64,
    pub local_time_valid_until: i64,
    pub extension_valid_until: i64,
    pub status_fresh_until: i64,
    pub audience_fresh_until: i64,
    pub status_evidence: Vec<StatusEvidenceEntryV2>,
    pub audience_evidence_digests: Vec<String>,
    pub rate_store_unavailable: bool,
    pub rate_admission_deferred: bool,
    pub status_checks: Vec<V2CertificateStatusCheck>,
    pub deferred: Vec<V2DeferredConstraint>,
    pub local_policy_failure: Option<V2LocalPolicyFailure>,
    pub status: String,
    pub reason: String,
    pub detail: String,
}

/// A pure local verdict that must not become terminal until every
/// authenticated chain CertificateRef has completed status evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2LocalPolicyFailure {
    pub status: String,
    pub reason: String,
    pub detail: String,
}

/// A constraint requiring the ordered status, membership, or
/// rate-reservation stage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2DeferredConstraint {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub issuer_id: String,
    pub cert_id: String,
    pub kind: String,
    pub canonical_json: Vec<u8>,
}

fn v2_local_assessment(status: &str, reason: &str, scope: Vec<String>, detail: &str) -> V2LocalAuthorizationAssessment {
    V2LocalAuthorizationAssessment {
        effective_scope: scope,
        context_assessment: "not_evaluated".into(),
        status: status.into(),
        reason: reason.into(),
        detail: detail.into(),
        ..Default::default()
    }
}

/// Go `v2InterruptedAssessment`.
pub(crate) fn v2_interrupted_assessment(detail: &str) -> V2LocalAuthorizationAssessment {
    v2_local_assessment("authorization_unverified", "evaluation_interrupted", Vec::new(), detail)
}

/// Go `EvaluateProofBundleV2LocalAuthorization`: trust-root binding,
/// delegation times, effective scope, and deterministic constraints. The
/// caller must invoke it only after preflight and atomic challenge claim. It
/// performs no status lookup, rate reservation, or other external call
/// (extension evaluators sealed at preflight are pure).
pub fn evaluate_proof_bundle_v2_local_authorization(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions,
) -> V2LocalAuthorizationAssessment {
    let (mut assessment, started) = evaluate_local_inner(bundle, opts);
    if let Some(token) = &opts.claim_token {
        let state = &token.state;
        assessment.bundle_hash = state.expected.bundle_hash.clone();
        assessment.issuer_ids = state.expected.issuer_ids.clone();
        if started && !assessment.status.is_empty() {
            let mut m = state.lock();
            m.evaluation_status = assessment.status.clone();
            m.evaluation_reason = assessment.reason.clone();
            if assessment.status == "pending_external_checks" {
                m.pending_assessment = Some(assessment.clone());
            }
            state.evaluation_complete.store(true, Ordering::SeqCst);
        }
    }
    assessment
}

fn evaluate_local_inner(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions,
) -> (V2LocalAuthorizationAssessment, bool) {
    let Some(token) = &opts.claim_token else {
        return (
            v2_local_assessment(
                "preflight_binding_mismatch",
                "claim_required",
                Vec::new(),
                "local authorization requires a successful atomic challenge claim",
            ),
            false,
        );
    };
    let state: &TokenState = &token.state;
    let expected: &ExpectedChallengeStateV2 = &state.expected;
    let claim_id = protocol_claim_id_v2(&expected.verifier_namespace, expected.replay_epoch, &expected.value);
    if claim_id.as_deref().ok() != Some(state.claim_id.as_str())
        || state.proof_digest != expected.bundle_hash
        || state.owner_token.len() != 32
    {
        return (
            v2_interrupted_assessment("local authorization state differs from successful preflight or atomic claim"),
            false,
        );
    }
    if state
        .used
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return (
            v2_local_assessment(
                "evaluation_in_progress",
                "claim_in_progress",
                Vec::new(),
                "the claim's single evaluation token has already been used",
            ),
            false,
        );
    }
    let a = evaluate_local_started(bundle, opts, state, expected);
    (a, true)
}

fn evaluate_local_started(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions,
    state: &TokenState,
    expected: &ExpectedChallengeStateV2,
) -> V2LocalAuthorizationAssessment {
    if !state.claim_time_valid {
        return v2_interrupted_assessment(
            "claim store returned an authoritative claim time outside the authenticated freshness bounds",
        );
    }
    if let Some(e) = &opts.expected_challenge {
        if !matches_expected_challenge_v2(e, expected) {
            return v2_interrupted_assessment(
                "local authorization challenge state differs from successful preflight or atomic claim",
            );
        }
    }
    let now = state.claimed_at;
    state.lock().evaluated_at = now;
    if opts.required_scope != state.required_scope || opts.future_skew_seconds != state.future_skew {
        return v2_interrupted_assessment("local authorization state differs from successful preflight or atomic claim");
    }
    if opts.required_scope != expected.required_scope {
        return v2_interrupted_assessment("required scope differs from the scope validated during preflight");
    }
    match bundle_hash_v2(bundle) {
        Ok(h) if h == state.proof_digest => {}
        _ => return v2_interrupted_assessment("proof bundle differs from the bundle validated during preflight"),
    }
    if bundle.challenge != expected.value
        || bundle.challenge_at != expected.issued_at
        || bundle.verifier_id != expected.verifier_id
    {
        return v2_interrupted_assessment("proof challenge differs from the challenge validated during preflight");
    }
    if let Err(e) = validate_required_scope_v2(&opts.required_scope) {
        return v2_interrupted_assessment(&format!(
            "required scope changed after successful preflight: {}",
            e.message
        ));
    }
    if verify_proof_bundle_v2_signatures(bundle).is_err() {
        return v2_interrupted_assessment("proof signature changed after successful preflight");
    }
    let Some(root) = bundle.delegations.last() else {
        return v2_local_assessment(
            "delegation_not_authorized",
            "not_delegated",
            Vec::new(),
            "proof has no delegation certificates",
        );
    };
    if !opts.trust_configured {
        return v2_local_assessment(
            "authorization_unverified",
            "trust_unavailable",
            Vec::new(),
            "caller-authenticated trust configuration is unavailable",
        );
    }
    if opts.trusted_root_id != root.issuer_id || !equal_keys(&opts.trusted_root_key, &root.issuer_pub_key) {
        return v2_local_assessment(
            "unauthorized",
            "unauthorized",
            Vec::new(),
            "delegation chain does not terminate at the configured trust root",
        );
    }
    for (i, cert) in bundle.delegations.iter().enumerate() {
        // Checked integer seconds: both timestamps inside the v2 domain, a
        // bounded lifetime, and issued_at no later than now + skew.
        let latest_issue = checked_add_v2(now, state.future_skew);
        let bad = !valid_v2_timestamp(cert.issued_at)
            || !valid_v2_timestamp(cert.expires_at)
            || cert.issued_at >= cert.expires_at
            || cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS
            || latest_issue.is_none_or(|latest| cert.issued_at > latest);
        if bad {
            return v2_local_assessment(
                "invalid",
                "proof_invalid",
                Vec::new(),
                &format!("delegation {i} has invalid time bounds"),
            );
        }
    }
    for (i, cert) in bundle.delegations.iter().enumerate() {
        if now >= cert.expires_at {
            return v2_local_assessment(
                "expired",
                "delegation_expired",
                Vec::new(),
                &format!("delegation {i} has expired"),
            );
        }
    }
    for (i, cert) in bundle.delegations.iter().enumerate() {
        if let Err(e) = validate_scopes_v2(&cert.scope) {
            return v2_local_assessment(
                "invalid_scope",
                "invalid_scope",
                Vec::new(),
                &format!("delegation {i}: {}", e.message),
            );
        }
    }
    for i in 0..bundle.delegations.len() {
        if let Some(parent) = bundle.delegations.get(i + 1) {
            if !parent.scope.iter().any(|s| s == SCOPE_IDENTITY_DELEGATE) {
                return v2_local_assessment(
                    "delegation_not_authorized",
                    "delegation_not_authorized",
                    Vec::new(),
                    &format!("parent delegation {} does not grant {SCOPE_IDENTITY_DELEGATE:?}", i + 1),
                );
            }
        }
    }
    let scope_lists: Vec<&[String]> = bundle.delegations.iter().map(|c| c.scope.as_slice()).collect();
    let effective = intersect_scopes(&scope_lists);
    let mut local_policy_failure: Option<V2LocalPolicyFailure> = None;
    if !effective.contains(&opts.required_scope) {
        local_policy_failure = Some(V2LocalPolicyFailure {
            status: "scope_denied".into(),
            reason: "scope_denied".into(),
            detail: format!(
                "required scope {:?} is not in the effective delegation scope",
                opts.required_scope
            ),
        });
    }
    if opts.context_policy.is_some()
        && !same_v2_context_policy(opts.context_policy.as_ref(), expected.context_policy.as_ref())
    {
        return v2_interrupted_assessment("context policy differs from the policy sealed during successful preflight");
    }
    let context_assessment = evaluate_proof_bundle_v2_context_policy(Some(bundle), expected.context_policy.as_ref());
    if context_assessment.status != "passed" && local_policy_failure.is_none() {
        local_policy_failure = Some(V2LocalPolicyFailure {
            status: context_assessment.status.clone(),
            reason: context_assessment.reason.clone(),
            detail: context_assessment.detail.clone(),
        });
    }
    let (deferred, constraint_status, mut constraint_failures, extension_valid_until) =
        evaluate_v2_local_constraints(bundle, opts, expected, now);
    if !constraint_status.is_empty() {
        constraint_failures.sort();
        let candidate = V2LocalPolicyFailure {
            status: constraint_status.clone(),
            reason: constraint_status,
            detail: constraint_failures.join("; "),
        };
        if local_policy_failure.is_none() {
            local_policy_failure = Some(candidate);
        }
    }
    let no_local_failure = local_policy_failure.is_none();
    let mut assessment = pending_v2_local_assessment(bundle, opts, effective, deferred, local_policy_failure);
    assessment.extension_valid_until = extension_valid_until;
    assessment.delegation_valid_until = bundle
        .delegations
        .iter()
        .map(|c| c.expires_at)
        .min()
        .unwrap_or_default();
    if no_local_failure {
        match local_time_window_valid_until_v2(bundle, &opts.tzdb_version, now) {
            Ok(h) => assessment.local_time_valid_until = h,
            Err(e) => {
                assessment.local_policy_failure = Some(V2LocalPolicyFailure {
                    status: "constraint_unverifiable".into(),
                    reason: "constraint_unverifiable".into(),
                    detail: e.message,
                });
            }
        }
    }
    assessment.context_assessment = context_assessment.assessment;
    assessment.context_policy_digest = context_assessment.policy_digest;
    assessment
}

fn pending_v2_local_assessment(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions,
    effective: Vec<String>,
    deferred: Vec<V2DeferredConstraint>,
    failure: Option<V2LocalPolicyFailure>,
) -> V2LocalAuthorizationAssessment {
    let mut a = v2_local_assessment(
        "pending_external_checks",
        "external_checks_required",
        effective,
        "local checks recorded; status and deferred authorization checks remain",
    );
    a.agent_id = bundle.agent_id.clone();
    a.root_id = opts.trusted_root_id.clone();
    a.required_scope = opts.required_scope.clone();
    a.delegation_digest = bundle.delegation_digest.clone();
    a.local_policy_failure = failure;
    a.status_checks = bundle
        .delegations
        .iter()
        .enumerate()
        .map(|(i, cert)| V2CertificateStatusCheck {
            delegation_index: i,
            issuer_id: cert.issuer_id.clone(),
            subject_id: cert.subject_id.clone(),
            cert_id: cert.cert_id.clone(),
        })
        .collect();
    a.deferred = deferred;
    a
}

/// Go `evaluateV2LocalConstraints`: every locally decidable constraint in
/// chain order. A registered v2 type uses its built-in rule; an extension
/// type uses the evaluator sealed for it at preflight; any other type is
/// constraint_unknown. Also returns the earliest extension pass horizon
/// (0 = none).
fn evaluate_v2_local_constraints(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions,
    sealed: &ExpectedChallengeStateV2,
    now: i64,
) -> (Vec<V2DeferredConstraint>, String, Vec<String>, i64) {
    let mut deferred = Vec::new();
    let mut constraint_status = String::new();
    let mut constraint_failures = Vec::new();
    let mut extension_horizon = 0i64;
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for (j, constraint) in cert.constraints.iter().enumerate() {
            if constraint.kind == CONSTRAINT_MAX_RATE || constraint.kind == CONSTRAINT_RECEIVER_AUDIENCE {
                match constraint.canonical_json() {
                    Ok(encoded) => deferred.push(V2DeferredConstraint {
                        delegation_index: i,
                        constraint_index: j,
                        issuer_id: cert.issuer_id.clone(),
                        cert_id: cert.cert_id.clone(),
                        kind: constraint.kind.clone(),
                        canonical_json: encoded,
                    }),
                    Err(e) => {
                        if constraint_precedence_v2("constraint_unverifiable") > constraint_precedence_v2(&constraint_status) {
                            constraint_status = "constraint_unverifiable".into();
                        }
                        constraint_failures.push(format!(
                            "delegation {i} constraint {j} cannot be encoded: {}",
                            e.message
                        ));
                    }
                }
                continue;
            }
            let result: Result<(), ConstraintFailure> = match sealed.evaluators.get(&constraint.kind) {
                Some(entry) if !is_registered_constraint_type_v2(&constraint.kind) => {
                    match extension_params_json_v2(constraint) {
                        Err(e) => Err(ConstraintFailure::Unverifiable(format!(
                            "{} params cannot be encoded: {}",
                            constraint.kind, e.message
                        ))),
                        Ok(params) => run_constraint_evaluator_v2(
                            entry,
                            sealed.evaluator_timeout,
                            ConstraintEvaluationInputV2 {
                                kind: constraint.kind.clone(),
                                params_json: params,
                                delegation_index: i,
                                constraint_index: j,
                                issuer_id: cert.issuer_id.clone(),
                                cert_id: cert.cert_id.clone(),
                                context: opts.context.clone(),
                                evaluation_time: now,
                            },
                        )
                        .map(|horizon| {
                            if horizon != 0 && (extension_horizon == 0 || horizon < extension_horizon) {
                                extension_horizon = horizon;
                            }
                        }),
                    }
                }
                _ => evaluate_constraint_v2(constraint, &opts.context, &opts.tzdb_version, now),
            };
            if let Err(failure) = result {
                let (status, message) = match failure {
                    ConstraintFailure::Denied(m) => ("constraint_denied", m),
                    ConstraintFailure::Unverifiable(m) => ("constraint_unverifiable", m),
                    ConstraintFailure::Unknown(m) => ("constraint_unknown", m),
                };
                if constraint_status.is_empty() || constraint_precedence_v2(status) > constraint_precedence_v2(&constraint_status) {
                    constraint_status = status.into();
                }
                constraint_failures.push(format!("delegation {i} constraint {j}: {message}"));
            }
        }
    }
    (deferred, constraint_status, constraint_failures, extension_horizon)
}

/// Go `loadV2TimeZone`: an IANA zone from the embedded, pinned database
/// after checking the configured database version.
fn load_v2_time_zone(configured_version: &str, tz: &str) -> Result<Arc<Zone>, String> {
    if configured_version.is_empty() {
        return Err("no tzdb_version is configured".into());
    }
    if configured_version != TZDB_VERSION_V2 {
        return Err(format!(
            "configured tzdb_version {configured_version:?} differs from the loaded IANA tzdata {TZDB_VERSION_V2}"
        ));
    }
    load_zone(tz).map_err(|e| e.message().to_string())
}

/// `now.In(loc)`: (UTC offset, end of the current zone period, local civil
/// date and clock).
struct LocalTime {
    offset: i64,
    zone_end: Option<i64>,
    year: i64,
    month: u32,
    day: u32,
    minute_of_day: i64,
}

fn local_time(zone: &Zone, now: i64) -> LocalTime {
    let info = zone.lookup(now);
    let (year, month, day, hour, minute, _) = civil_from_unix(now.wrapping_add(info.offset_seconds));
    LocalTime {
        offset: info.offset_seconds,
        zone_end: info.end,
        year,
        month,
        day,
        minute_of_day: i64::from(hour) * 60 + i64::from(minute),
    }
}

/// Go `evaluateConstraintV2`: one registered locally decidable constraint.
/// `max_rate` and `ratify.receiver_audience` are deferred stages and never
/// reach here.
pub(crate) fn evaluate_constraint_v2(
    c: &ConstraintV2,
    ctx: &ConstraintContextV2,
    tzdb_version: &str,
    now: i64,
) -> Result<(), ConstraintFailure> {
    use ConstraintFailure::*;
    match c.kind.as_str() {
        CONSTRAINT_RESOURCE_PATH => {
            // SPEC-v2 §5.2 order: the signed path_prefix is checked before
            // any request input.
            if !c.path_prefix.is_empty() {
                if let Err(e) = normalize_resource_path(&c.path_prefix) {
                    return Err(Denied(format!("malformed path_prefix: {e}")));
                }
            }
            if !ctx.has_resource || ctx.requested_resource_id.is_empty() {
                return Err(Unverifiable("no requested resource in context".into()));
            }
            if ctx.requested_resource_id != c.resource_id {
                return Err(Denied("requested resource does not match the authorized resource".into()));
            }
            if c.path_prefix.is_empty() {
                return Ok(());
            }
            if ctx.requested_path.is_empty() {
                return Err(Unverifiable("no requested path in context".into()));
            }
            if let Err(e) = normalize_resource_path(&ctx.requested_path) {
                return Err(Denied(format!("invalid requested path: {e}")));
            }
            if !resource_path_matches(&c.path_prefix, &ctx.requested_path) {
                return Err(Denied(format!(
                    "requested path {:?} is outside the authorized prefix {:?}",
                    ctx.requested_path, c.path_prefix
                )));
            }
            Ok(())
        }
        CONSTRAINT_TIME_WINDOW => {
            let zone = load_v2_time_zone(tzdb_version, &c.tz)
                .map_err(|e| Unverifiable(format!("time zone {:?} cannot be evaluated: {e}", c.tz)))?;
            let start = parse_hhmm_v2(&c.start).map_err(|e| Denied(e.message))?;
            let end = parse_hhmm_v2(&c.end).map_err(|e| Denied(e.message))?;
            let local = local_time(&zone, now);
            let cur = local.minute_of_day;
            let inside = if start <= end { (start..=end).contains(&cur) } else { cur >= start || cur <= end };
            if !inside {
                return Err(Denied(format!(
                    "current {:02}:{:02} is outside [{}, {}] {}",
                    cur / 60,
                    cur % 60,
                    c.start,
                    c.end,
                    zone.name()
                )));
            }
            Ok(())
        }
        CONSTRAINT_MAX_AMOUNT => {
            if !ctx.has_amount {
                return Err(Unverifiable("no requested amount in context".into()));
            }
            if ctx.requested_amount_micros < 0
                || ctx.requested_amount_micros > MAX_SAFE
                || !valid_iso4217_alpha_v2(&ctx.requested_currency)
            {
                return Err(Unverifiable(
                    "requested amount is not a nonnegative safe integer in ISO-4217 micro-units".into(),
                ));
            }
            if ctx.requested_currency != c.currency {
                return Err(Denied(format!(
                    "currency mismatch: requested {:?}, constraint {:?}",
                    ctx.requested_currency, c.currency
                )));
            }
            if ctx.requested_amount_micros > c.max_amount_micros {
                return Err(Denied(format!(
                    "amount {} exceeds max {} micro-units of {}",
                    ctx.requested_amount_micros, c.max_amount_micros, c.currency
                )));
            }
            Ok(())
        }
        CONSTRAINT_MAX_RATE | CONSTRAINT_RECEIVER_AUDIENCE => Err(Unverifiable(format!(
            "{} requires its dedicated post-status stage",
            c.kind
        ))),
        _ => Err(Unknown(format!("unknown constraint type: {}", c.kind))),
    }
}

/// Go `localTimeWindowValidUntilV2`: bound an allow at the end of each
/// currently accepted local minute window or the next time-zone offset
/// transition, whichever is first.
pub(crate) fn local_time_window_valid_until_v2(bundle: &ProofBundleV2, tzdb_version: &str, now: i64) -> V2Result<i64> {
    let mut horizon = 0i64;
    for cert in &bundle.delegations {
        for constraint in &cert.constraints {
            if constraint.kind != CONSTRAINT_TIME_WINDOW {
                continue;
            }
            let zone = load_v2_time_zone(tzdb_version, &constraint.tz).map_err(V2Error::plain)?;
            let start = parse_hhmm_v2(&constraint.start)?;
            let end = parse_hhmm_v2(&constraint.end)?;
            let local = local_time(&zone, now);
            let minute = local.minute_of_day;
            let inside = if start <= end { (start..=end).contains(&minute) } else { minute >= start || minute <= end };
            if !inside {
                return plain("time window is no longer current");
            }
            let day_offset = i64::from(start > end && minute >= start);
            let mut until = unix_from_civil_utc(
                local.year,
                local.month,
                i64::from(local.day) + day_offset,
                0,
                end + 1,
                0,
            )
            .wrapping_sub(local.offset);
            if let Some(zone_end) = local.zone_end {
                if zone_end < until {
                    until = zone_end;
                }
            }
            if until <= now {
                return plain("time window has no valid terminal horizon");
            }
            // A horizon past the timestamp domain is clamped to its upper
            // bound (SPEC-v2 §2.5, §5.2).
            let contribution = until.min(V2_MAX_TIMESTAMP_SECONDS);
            if horizon == 0 || contribution < horizon {
                horizon = contribution;
            }
        }
    }
    Ok(horizon)
}

/// Go `allowHorizonV2`.
pub(crate) fn allow_horizon_v2(a: &V2LocalAuthorizationAssessment) -> i64 {
    let mut horizon = a.delegation_valid_until.min(a.status_fresh_until);
    if a.audience_fresh_until > 0 {
        horizon = horizon.min(a.audience_fresh_until);
    }
    if a.local_time_valid_until > 0 {
        horizon = horizon.min(a.local_time_valid_until);
    }
    if a.extension_valid_until > 0 {
        horizon = horizon.min(a.extension_valid_until);
    }
    horizon.min(V2_MAX_TIMESTAMP_SECONDS)
}

/// Go `combinableWithAudienceV2`.
fn combinable_with_audience_v2(failure: Option<&V2LocalPolicyFailure>, deferred: &[V2DeferredConstraint]) -> bool {
    match failure {
        Some(f) if f.status == "constraint_unknown" || f.status == "constraint_unverifiable" => {
            deferred.iter().any(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
        }
        _ => false,
    }
}

/// Go `constraintPrecedenceV2`.
fn constraint_precedence_v2(status: &str) -> u8 {
    match status {
        "constraint_denied" => 3,
        "constraint_unknown" => 2,
        "constraint_unverifiable" => 1,
        _ => 0,
    }
}

/// Go `resolveClaimProofBundleV2AfterStatus`: complete the ordered
/// post-claim status stage for the sealed pending assessment. Internal:
/// status results reach a claim only through the authenticated evidence path
/// of SPEC-v2 §6.5.
pub(crate) fn resolve_claim_proof_bundle_v2_after_status(
    token: &V2EvaluationToken,
    aggregate: impl FnOnce(&[V2CertificateStatusCheck]) -> V2Result<V2StatusAssessment>,
) -> V2Result<V2LocalAuthorizationAssessment> {
    let state = &token.state;
    let mut m = state.lock();
    let pending = match &m.pending_assessment {
        Some(p)
            if state.evaluation_complete.load(Ordering::SeqCst)
                && m.evaluation_status == "pending_external_checks" =>
        {
            p.clone()
        }
        _ => return plain("v2 claim does not have a pending status assessment"),
    };
    let mut a = pending;
    if a.bundle_hash != state.expected.bundle_hash || a.required_scope != state.expected.required_scope {
        return plain("pending status assessment differs from its claimed proof");
    }
    let aggregated = aggregate(&a.status_checks)?;
    a.status_assessment = aggregated.assessment.clone();
    a.status_fresh_until = aggregated.fresh_until;
    a.status_evidence = aggregated.evidence.clone();
    match aggregated.assessment.as_str() {
        "revoked" => {
            a.status = "revoked".into();
            a.reason = "delegation_revoked".into();
            a.detail = "at least one delegation certificate is revoked".into();
        }
        "unavailable" => {
            a.status = "authorization_unverified".into();
            a.reason = "status_unavailable".into();
            a.detail = "one or more delegation certificate statuses are unavailable".into();
        }
        "stale" => {
            a.status = "authorization_unverified".into();
            a.reason = "status_stale".into();
            a.detail = "one or more delegation certificate statuses are stale".into();
        }
        "current" => {
            if a.local_policy_failure.is_some() && combinable_with_audience_v2(a.local_policy_failure.as_ref(), &a.deferred) {
                // SPEC-v2 §5.2, §6.4: a proven audience violation on another
                // link outranks a local unknown or unverifiable constraint,
                // so the audience stage still runs. Rate never follows.
                a.deferred.retain(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE);
                a.status = "pending_external_checks".into();
                a.reason = "deferred_policy_checks_required".into();
                a.detail = "status is current; audience must be aggregated with a pending local constraint result".into();
                m.pending_assessment = Some(a.clone());
                m.evaluation_status = a.status.clone();
                m.evaluation_reason = a.reason.clone();
                return Ok(a);
            } else if let Some(local) = a.local_policy_failure.clone() {
                a.status = local.status;
                a.reason = local.reason;
                a.detail = local.detail;
            } else if !a.deferred.is_empty() {
                a.status = "pending_external_checks".into();
                a.reason = "deferred_policy_checks_required".into();
                a.detail = "status is current; deferred audience or rate checks remain".into();
                m.pending_assessment = Some(a.clone());
                m.evaluation_status = a.status.clone();
                m.evaluation_reason = a.reason.clone();
                return Ok(a);
            } else {
                a.status = "authorized_agent".into();
                a.reason = "authorized".into();
                a.detail = "proof, status, and local authorization checks passed".into();
                m.allow_valid_until = allow_horizon_v2(&a);
            }
        }
        _ => return plain("v2 status aggregator returned an unknown assessment"),
    }
    m.evaluation_status = a.status.clone();
    m.evaluation_reason = a.reason.clone();
    m.pending_assessment = None;
    Ok(a)
}

/// Go `ResolveClaimProofBundleV2AfterAudience`: consume caller-authenticated,
/// complete membership results only after every certificate status is
/// current. Membership freshness is evaluated at the authoritative claim
/// time sealed in the token. Errors are `configuration_invalid` (Go returns
/// them unclassified; they mean the token is not in this stage or the sealed
/// state is inconsistent).
pub fn resolve_claim_proof_bundle_v2_after_audience(
    token: &V2EvaluationToken,
    memberships: &[V2AudienceMembership],
) -> V2Result<V2LocalAuthorizationAssessment> {
    resolve_after_audience_inner(token, memberships).map_err(|e| e.classify(V2ErrorClass::ConfigurationInvalid))
}

pub(crate) fn resolve_after_audience_inner(
    token: &V2EvaluationToken,
    memberships: &[V2AudienceMembership],
) -> V2Result<V2LocalAuthorizationAssessment> {
    let state = &token.state;
    let mut m = state.lock();
    let ok = match &m.pending_assessment {
        Some(p) => {
            state.evaluation_complete.load(Ordering::SeqCst)
                && m.evaluation_status == "pending_external_checks"
                && p.status_assessment == "current"
                && (p.local_policy_failure.is_none()
                    || combinable_with_audience_v2(p.local_policy_failure.as_ref(), &p.deferred))
        }
        None => false,
    };
    let Some(mut a) = m.pending_assessment.clone().filter(|_| ok) else {
        return plain("v2 claim does not have current status and pending audience checks");
    };
    if a.bundle_hash != state.expected.bundle_hash || a.required_scope != state.expected.required_scope {
        m.evaluation_status = "authorization_unverified".into();
        m.evaluation_reason = "evaluation_interrupted".into();
        m.pending_assessment = None;
        return plain("pending audience assessment differs from its claimed proof");
    }
    let result = match evaluate_receiver_audience_inner(
        &a.deferred,
        &state.expected.expected_receiver_id,
        memberships,
        m.evaluated_at,
        state.future_skew,
    ) {
        Ok(r) => r,
        Err(e) => {
            m.evaluation_status = "authorization_unverified".into();
            m.evaluation_reason = "evaluation_interrupted".into();
            m.pending_assessment = None;
            return Err(e);
        }
    };
    a.audience_evidence_digests = result.evidence_digests.clone();
    a.audience_fresh_until = result.fresh_until;
    if let Some(local) = a.local_policy_failure.clone() {
        // Aggregate independently of link order: denied, then unknown, then
        // unverifiable (SPEC-v2 §5.2).
        if result.status == "passed" || constraint_precedence_v2(&local.status) > constraint_precedence_v2(&result.status) {
            a.status = local.status;
            a.reason = local.reason;
            a.detail = local.detail;
        } else {
            a.status = result.status.clone();
            a.reason = result.status.clone();
            a.detail = "receiver audience did not authorize this receiver".into();
        }
        a.deferred = Vec::new();
        m.pending_assessment = None;
    } else if result.status != "passed" {
        a.status = result.status.clone();
        a.reason = result.status.clone();
        a.detail = "receiver audience did not authorize this receiver".into();
        m.pending_assessment = None;
    } else {
        a.deferred.retain(|d| d.kind != CONSTRAINT_RECEIVER_AUDIENCE);
        if a.deferred.is_empty() {
            a.status = "authorized_agent".into();
            a.reason = "authorized".into();
            a.detail = "proof, status, audience, and local authorization checks passed".into();
            m.allow_valid_until = allow_horizon_v2(&a);
            m.pending_assessment = None;
        } else {
            a.status = "pending_external_checks".into();
            a.reason = "rate_reservation_required".into();
            a.detail = "audience passed; rate reservation remains".into();
            m.pending_assessment = Some(a.clone());
        }
    }
    m.evaluation_status = a.status.clone();
    m.evaluation_reason = a.reason.clone();
    Ok(a)
}

/// Go `ResolveClaimProofBundleV2AfterRate`: the final external Protocol
/// constraint stage. The caller must finalize the returned terminal result
/// through the same claim store; an ambiguous store error never authorizes.
/// A rate store that panics is treated as unavailable. Errors are
/// `evaluation_cancelled` for a done context and `configuration_invalid`
/// otherwise (Go returns them unclassified).
pub fn resolve_claim_proof_bundle_v2_after_rate(
    ctx: &V2Context,
    store: Option<&dyn V2RateReservationStore>,
    token: &V2EvaluationToken,
) -> V2Result<V2LocalAuthorizationAssessment> {
    if ctx.is_done() {
        return Err(V2Error::new(V2ErrorClass::EvaluationCancelled, "v2 rate evaluation context is done"));
    }
    resolve_after_rate_inner(ctx, store, token).map_err(|e| e.classify(V2ErrorClass::ConfigurationInvalid))
}

pub(crate) fn resolve_after_rate_inner(
    ctx: &V2Context,
    store: Option<&dyn V2RateReservationStore>,
    token: &V2EvaluationToken,
) -> V2Result<V2LocalAuthorizationAssessment> {
    if ctx.is_done() {
        return plain("v2 rate evaluation context is done");
    }
    let state = &token.state;
    let mut m = state.lock();
    let ok = match &m.pending_assessment {
        Some(p) => {
            state.evaluation_complete.load(Ordering::SeqCst)
                && m.evaluation_status == "pending_external_checks"
                && p.status_assessment == "current"
                && p.local_policy_failure.is_none()
        }
        None => false,
    };
    let Some(mut a) = m.pending_assessment.clone().filter(|_| ok) else {
        return plain("v2 claim does not have current status and pending rate checks");
    };
    if a.bundle_hash != state.expected.bundle_hash
        || a.required_scope != state.expected.required_scope
        || state.rate_batch.is_empty()
    {
        m.evaluation_status = "authorization_unverified".into();
        m.evaluation_reason = "evaluation_interrupted".into();
        m.pending_assessment = None;
        return plain("pending rate assessment differs from its claimed proof");
    }
    if a.deferred.iter().any(|d| d.kind != CONSTRAINT_MAX_RATE) {
        return plain("audience or unknown checks remain before rate reservation");
    }
    let batch = match build_v2_rate_reservation_batch_inner(&a.deferred) {
        Ok(b) if b == state.rate_batch => b,
        _ => {
            m.evaluation_status = "authorization_unverified".into();
            m.evaluation_reason = "evaluation_interrupted".into();
            m.pending_assessment = None;
            return plain("pending rate checks differ from sealed signed batch");
        }
    };
    let result: Result<(), V2StoreError> = match store {
        None => Err(V2StoreError::Unavailable("v2 rate reservation store is unavailable".into())),
        Some(store) if store.rate_at_finalization_view().is_some() => {
            m.rate_at_finalization = true;
            a.rate_admission_deferred = true;
            Ok(())
        }
        Some(store) => {
            let owner = state.owner_token.clone();
            let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.reserve_v2_rate_batch(ctx, &state.claim_id, &owner, &a.bundle_hash, &batch)
            }));
            call.unwrap_or_else(|_| Err(V2StoreError::Unavailable("rate store panicked".into())))
        }
    };
    match result {
        Ok(()) => {
            a.status = "authorized_agent".into();
            a.reason = "authorized".into();
            a.detail = if m.rate_at_finalization {
                "proof, status, and audience passed; rate admission is deferred to durable finalization".into()
            } else {
                "proof, status, audience, and rate checks passed".into()
            };
            m.allow_valid_until = allow_horizon_v2(&a);
        }
        Err(V2StoreError::RateLimitExceeded) => {
            a.status = "constraint_denied".into();
            a.reason = "constraint_denied".into();
            a.detail = "signed rate limit has no remaining capacity".into();
        }
        Err(_) => {
            a.status = "constraint_unverifiable".into();
            a.reason = "constraint_unverifiable".into();
            a.detail = "rate reservation could not be verified".into();
            a.rate_store_unavailable = true;
        }
    }
    a.deferred = Vec::new();
    m.pending_assessment = None;
    m.evaluation_status = a.status.clone();
    m.evaluation_reason = a.reason.clone();
    Ok(a)
}

/// Go `interruptV2Evaluation`: turn the claim's evaluation into the terminal
/// indeterminate/evaluation_interrupted result. Any provisional rate
/// admission is abandoned because the result is not allow.
pub(crate) fn interrupt_v2_evaluation(token: &V2EvaluationToken) {
    let state = &token.state;
    let mut m = state.lock();
    m.evaluation_status = "authorization_unverified".into();
    m.evaluation_reason = "evaluation_interrupted".into();
    m.allow_valid_until = 0;
    m.rate_at_finalization = false;
    m.pending_assessment = None;
    state.evaluation_complete.store(true, Ordering::SeqCst);
}
