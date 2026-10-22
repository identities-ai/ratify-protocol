//! Extension constraint evaluator profiles (SPEC-v2 §5.2, Go
//! `constraint_evaluator_v2.go`).
//!
//! A verifier may register, in caller-authenticated configuration, an
//! evaluator profile for an exact extension constraint type. A profile is
//! identified by a digest over `{"profile":<id>,"type":<type>}`; the digest
//! names the profile identifier bound to the type and is not evidence that two
//! implementations behave alike. Neither a certificate nor a proof selects a
//! profile. The entries used by a chain are sealed with the challenge claim
//! and recorded in the receipt member `constraint_evaluators`.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use super::constraints::{
    params_map_cj, v2_integer_field, v2_string_field, ConstraintContextV2, ConstraintV2,
};
use super::context::V2Context;
use super::crypto::{sha384, valid_prefixed_digest};
use super::errors::{err, plain, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, parse_json, CJ, JV};
use super::limits::{V2_MAX_SAFE_INTEGER, V2_MAX_TIMESTAMP_SECONDS};
use super::wire::ProofBundleV2;

/// Type of the standard count profile.
pub const CONSTRAINT_MAX_COUNT_V2: &str = "com.ratifyprotocol.max_count";
/// Type of the standard exact-value profile.
pub const CONSTRAINT_ALLOWED_VALUES_V2: &str = "com.ratifyprotocol.allowed_values";
/// Versioned identifier of the standard count profile.
pub const PROFILE_MAX_COUNT_V2: &str = "com.ratifyprotocol.max_count/v1";
/// Versioned identifier of the standard exact-value profile.
pub const PROFILE_ALLOWED_VALUES_V2: &str = "com.ratifyprotocol.allowed_values/v1";
pub const MAX_CONSTRAINT_EVALUATORS_V2: usize = 32;
pub const MAX_EXTENSION_TYPE_BYTES_V2: usize = 128;
pub const MAX_PROFILE_ID_BYTES_V2: usize = 128;
pub const MAX_EXTENSION_CONTEXT_ENTRIES_V2: usize = 64;
pub const MAX_EXTENSION_CONTEXT_NAME_BYTES_V2: usize = 128;
pub const MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2: usize = 512;
pub const MAX_ALLOWED_VALUES_V2: usize = 64;
/// Upper bound on the configured evaluation timeout.
pub const MAX_CONSTRAINT_EVALUATOR_TIMEOUT_V2: Duration = Duration::from_secs(10);

const PROFILE_DIGEST_LABEL: &[u8] = b"ratify-protocol-constraint-profile-v2\0";

/// The canonical object whose digest identifies an evaluator profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintProfileDescriptorV2 {
    pub profile: String,
    pub kind: String,
}

/// One entry of a receipt's `constraint_evaluators` member and of a claim's
/// sealed evaluator snapshot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConstraintEvaluatorRefV2 {
    pub kind: String,
    pub profile_digest: String,
}

/// Everything an evaluator may read. It is a copy; `evaluation_time` is the
/// authoritative claim time `T_claim`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintEvaluationInputV2 {
    pub kind: String,
    /// The canonical params object, or `None` when absent.
    pub params_json: Option<Vec<u8>>,
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub issuer_id: String,
    pub cert_id: String,
    pub context: ConstraintContextV2,
    pub evaluation_time: i64,
}

/// An evaluator verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintOutcomeV2 {
    Pass,
    Denied,
    Unverifiable,
    /// Anything an implementation may return that is none of the three
    /// defined outcomes; the verifier treats it as unverifiable.
    Invalid,
}

/// An evaluator's answer. `valid_until` is an optional exclusive horizon for
/// a pass (0 = none); it must be later than the evaluation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintEvaluationResultV2 {
    pub outcome: ConstraintOutcomeV2,
    pub valid_until: i64,
    pub detail: String,
}

/// An evaluator's own failure (treated as unverifiable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintEvaluatorError(pub String);

impl fmt::Display for ConstraintEvaluatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConstraintEvaluatorError {}

/// A pure evaluator function: no I/O, clock, or randomness. An error, a
/// panic, a timeout, or an invalid result is unverifiable. The verifier stops
/// waiting at the registry timeout; an implementation must also return once
/// the context is done, or its thread outlives the call.
pub type ConstraintEvaluatorFnV2 = Arc<
    dyn Fn(&V2Context, &ConstraintEvaluationInputV2) -> Result<ConstraintEvaluationResultV2, ConstraintEvaluatorError>
        + Send
        + Sync,
>;

/// Binds one profile descriptor to its implementation.
#[derive(Clone)]
pub struct ConstraintEvaluatorRegistrationV2 {
    pub descriptor: ConstraintProfileDescriptorV2,
    pub evaluate: ConstraintEvaluatorFnV2,
}

impl fmt::Debug for ConstraintEvaluatorRegistrationV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConstraintEvaluatorRegistrationV2")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RegisteredEvaluator {
    pub(crate) reference: ConstraintEvaluatorRefV2,
    pub(crate) evaluate: ConstraintEvaluatorFnV2,
}

/// Caller-authenticated verifier configuration, immutable once built; only
/// [`ConstraintEvaluatorRegistryV2::new`] builds one.
#[derive(Clone)]
pub struct ConstraintEvaluatorRegistryV2 {
    timeout: Duration,
    entries: BTreeMap<String, RegisteredEvaluator>,
}

impl fmt::Debug for ConstraintEvaluatorRegistryV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConstraintEvaluatorRegistryV2")
            .field("timeout", &self.timeout)
            .field("refs", &self.refs())
            .finish()
    }
}

impl ConstraintEvaluatorRegistryV2 {
    /// Validate and freeze a registry. Every type must be a registrable
    /// extension type and appear once; every descriptor must name a valid
    /// versioned profile identifier; `timeout` must be in (0, 10 s]. A
    /// violation is `configuration_invalid`.
    pub fn new(
        timeout: Duration,
        registrations: Vec<ConstraintEvaluatorRegistrationV2>,
    ) -> V2Result<Self> {
        if timeout.is_zero() || timeout > MAX_CONSTRAINT_EVALUATOR_TIMEOUT_V2 {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                "v2 constraint evaluator timeout must be in (0, 10s]",
            );
        }
        if registrations.len() > MAX_CONSTRAINT_EVALUATORS_V2 {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                format!("v2 constraint evaluator registry holds at most {MAX_CONSTRAINT_EVALUATORS_V2} profiles"),
            );
        }
        let mut entries = BTreeMap::new();
        for registration in registrations {
            let digest = constraint_profile_digest_v2(&registration.descriptor)
                .map_err(|e| e.classify(V2ErrorClass::ConfigurationInvalid))?;
            let kind = registration.descriptor.kind.clone();
            if entries.contains_key(&kind) {
                return err(
                    V2ErrorClass::ConfigurationInvalid,
                    format!("v2 constraint type {kind:?} is registered more than once"),
                );
            }
            entries.insert(
                kind.clone(),
                RegisteredEvaluator {
                    reference: ConstraintEvaluatorRefV2 { kind, profile_digest: digest },
                    evaluate: registration.evaluate,
                },
            );
        }
        Ok(ConstraintEvaluatorRegistryV2 { timeout, entries })
    }

    /// The registered `{type, profile_digest}` pairs sorted by type.
    pub fn refs(&self) -> Vec<ConstraintEvaluatorRefV2> {
        self.entries.values().map(|e| e.reference.clone()).collect()
    }

    /// The configured evaluation timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// `"sha384:" || hex(SHA-384("ratify-protocol-constraint-profile-v2" || 0x00 ||
/// RatifyCanonicalJSON({"profile":profile,"type":type})))`.
pub fn constraint_profile_digest_v2(d: &ConstraintProfileDescriptorV2) -> V2Result<String> {
    if !valid_extension_type_v2(&d.kind) {
        return plain(format!("v2 constraint profile type {:?} is not a registrable extension type", d.kind));
    }
    if !valid_profile_id_v2(&d.profile) {
        return plain(format!("v2 constraint profile identifier {:?} is invalid", d.profile));
    }
    let body = canonical(&CJ::obj(vec![("profile", CJ::s(&d.profile)), ("type", CJ::s(&d.kind))]))?;
    Ok(format!("sha384:{}", hex::encode(sha384(&[PROFILE_DIGEST_LABEL, &body]))))
}

fn label_ok(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// 3 to 128 bytes of at least three `.`-separated labels of `[a-z0-9_-]`, not
/// in the reserved `ratify.` namespace.
pub fn valid_extension_type_v2(t: &str) -> bool {
    if t.is_empty() || t.len() > MAX_EXTENSION_TYPE_BYTES_V2 || t.starts_with("ratify.") {
        return false;
    }
    let labels: Vec<&str> = t.split('.').collect();
    labels.len() >= 3 && labels.iter().all(|l| label_ok(l))
}

/// `<name>/v<n>`, at most 128 bytes.
pub fn valid_profile_id_v2(id: &str) -> bool {
    if id.len() > MAX_PROFILE_ID_BYTES_V2 {
        return false;
    }
    let Some((name, version)) = id.split_once("/v") else {
        return false;
    };
    if name.is_empty() || version.is_empty() || version.starts_with('0') || version.contains('/') {
        return false;
    }
    version.bytes().all(|b| b.is_ascii_digit()) && name.split('.').all(label_ok)
}

/// 1 to 128 bytes of `[a-z0-9_.:-]`.
pub(crate) fn valid_extension_context_name_v2(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_EXTENSION_CONTEXT_NAME_BYTES_V2
        && name.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b':' | b'-')
        })
}

/// The supplied request context of SPEC-v2 §5.2, checked before claim
/// (`configuration_invalid` on failure; Go `validateV2RequestContext`).
pub fn validate_v2_request_context(c: &ConstraintContextV2) -> V2Result<()> {
    if c.has_amount {
        if c.requested_amount_micros < 0
            || c.requested_amount_micros > V2_MAX_SAFE_INTEGER
            || !super::constraints::valid_iso4217_alpha_v2(&c.requested_currency)
        {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                "v2 request amount must be 0..2^53-1 micro-units with a three-letter A-Z currency",
            );
        }
    } else if c.requested_amount_micros != 0 || !c.requested_currency.is_empty() {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 request amount and currency must be supplied together with has_amount",
        );
    }
    if c.has_resource {
        if c.requested_resource_id.len() > crate::types::MAX_IDENTIFIER_LENGTH_BYTES {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                "v2 requested resource ID must be at most 512 bytes",
            );
        }
    } else if !c.requested_resource_id.is_empty() || !c.requested_path.is_empty() {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 requested resource ID and path must be supplied with has_resource",
        );
    }
    validate_v2_extension_context(c)
}

/// The extension request context checked before claim.
pub(crate) fn validate_v2_extension_context(c: &ConstraintContextV2) -> V2Result<()> {
    if c.extension_counts.len() > MAX_EXTENSION_CONTEXT_ENTRIES_V2
        || c.extension_values.len() > MAX_EXTENSION_CONTEXT_ENTRIES_V2
    {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 extension request context holds at most 64 counts and 64 values",
        );
    }
    for (name, count) in &c.extension_counts {
        if !valid_extension_context_name_v2(name) || *count < 0 || *count > V2_MAX_SAFE_INTEGER {
            return err(V2ErrorClass::ConfigurationInvalid, format!("v2 extension count {name:?} is invalid"));
        }
    }
    for (name, value) in &c.extension_values {
        if !valid_extension_context_name_v2(name) || value.len() > MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2 {
            return err(V2ErrorClass::ConfigurationInvalid, format!("v2 extension value {name:?} is invalid"));
        }
    }
    Ok(())
}

/// The registry entries for the extension types present in the chain, keyed
/// by type, and their sorted refs.
pub(crate) fn snapshot_constraint_evaluators_v2(
    registry: Option<&ConstraintEvaluatorRegistryV2>,
    bundle: &ProofBundleV2,
) -> (BTreeMap<String, RegisteredEvaluator>, Vec<ConstraintEvaluatorRefV2>, Duration) {
    let Some(registry) = registry else {
        return (BTreeMap::new(), Vec::new(), Duration::ZERO);
    };
    let mut used = BTreeMap::new();
    for cert in &bundle.delegations {
        for constraint in &cert.constraints {
            if let Some(entry) = registry.entries.get(&constraint.kind) {
                used.insert(constraint.kind.clone(), entry.clone());
            }
        }
    }
    if used.is_empty() {
        return (used, Vec::new(), Duration::ZERO);
    }
    let refs = used.values().map(|e: &RegisteredEvaluator| e.reference.clone()).collect();
    (used, refs, registry.timeout)
}

/// A receipt or claim snapshot: every entry has a registrable type and a
/// `sha384:` digest, strictly sorted by type.
pub(crate) fn valid_constraint_evaluator_refs_v2(refs: &[ConstraintEvaluatorRefV2]) -> bool {
    refs.len() <= MAX_CONSTRAINT_EVALUATORS_V2
        && refs.iter().enumerate().all(|(i, r)| {
            valid_extension_type_v2(&r.kind)
                && valid_prefixed_digest(&r.profile_digest)
                && (i == 0 || refs[i - 1].kind.as_bytes() < r.kind.as_bytes())
        })
}

pub(crate) fn evaluator_refs_cj(refs: &[ConstraintEvaluatorRefV2]) -> CJ {
    CJ::Arr(
        refs.iter()
            .map(|r| CJ::obj(vec![("profile_digest", CJ::s(&r.profile_digest)), ("type", CJ::s(&r.kind))]))
            .collect(),
    )
}

/// The verdict of one constraint evaluation (Go's error model for
/// `evaluateConstraintV2`): pass is `Ok`, the rest are failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConstraintFailure {
    Denied(String),
    Unverifiable(String),
    Unknown(String),
}

/// Invoke one sealed evaluator under its timeout with panic containment and
/// map the answer: `Ok(horizon)` (0 = none) or a failure.
pub(crate) fn run_constraint_evaluator_v2(
    entry: &RegisteredEvaluator,
    timeout: Duration,
    input: ConstraintEvaluationInputV2,
) -> Result<i64, ConstraintFailure> {
    let (ctx, cancel) = V2Context::background().with_timeout(timeout);
    let (tx, rx) = mpsc::channel();
    let evaluate = entry.evaluate.clone();
    let kind = input.kind.clone();
    let evaluation_time = input.evaluation_time;
    let thread_ctx = ctx.clone();
    let spawned = std::thread::Builder::new()
        .name("ratify-v2-evaluator".into())
        .spawn(move || {
            let answer = catch_unwind(AssertUnwindSafe(|| evaluate(&thread_ctx, &input)));
            let _ = tx.send(answer.map_err(|_| ()));
        });
    if spawned.is_err() {
        return Err(ConstraintFailure::Unverifiable(format!("{kind} evaluator could not be started")));
    }
    let answer = rx.recv_timeout(timeout);
    cancel.cancel();
    let result = match answer {
        Err(_) => {
            return Err(ConstraintFailure::Unverifiable(format!(
                "{kind} evaluator did not answer within {timeout:?}"
            )))
        }
        Ok(Err(())) => return Err(ConstraintFailure::Unverifiable(format!("{kind} evaluator panicked"))),
        Ok(Ok(Err(e))) => return Err(ConstraintFailure::Unverifiable(format!("{kind} evaluator failed: {e}"))),
        Ok(Ok(Ok(result))) => result,
    };
    match result.outcome {
        ConstraintOutcomeV2::Pass => {
            if result.valid_until == 0 {
                return Ok(0);
            }
            if result.valid_until <= evaluation_time {
                return Err(ConstraintFailure::Unverifiable(format!(
                    "{kind} evaluator returned a pass horizon not after the evaluation time"
                )));
            }
            Ok(result.valid_until.min(V2_MAX_TIMESTAMP_SECONDS))
        }
        ConstraintOutcomeV2::Denied => {
            if result.valid_until != 0 {
                return Err(ConstraintFailure::Unverifiable(format!(
                    "{kind} evaluator returned a horizon with a denial"
                )));
            }
            Err(ConstraintFailure::Denied(format!("{kind} denied: {}", result.detail)))
        }
        ConstraintOutcomeV2::Unverifiable => {
            if result.valid_until != 0 {
                return Err(ConstraintFailure::Unverifiable(format!(
                    "{kind} evaluator returned a horizon with an unverifiable result"
                )));
            }
            Err(ConstraintFailure::Unverifiable(format!("{kind} unverifiable: {}", result.detail)))
        }
        ConstraintOutcomeV2::Invalid => Err(ConstraintFailure::Unverifiable(format!(
            "{kind} evaluator returned an invalid outcome"
        ))),
    }
}

/// The canonical params object of an extension constraint, or `None`.
pub(crate) fn extension_params_json_v2(c: &ConstraintV2) -> V2Result<Option<Vec<u8>>> {
    match &c.params {
        None => Ok(None),
        Some(params) => canonical(&params_map_cj(params)).map(Some),
    }
}

// ---------------------------------------------------------------------------
// Standard profiles (SPEC-v2 §5.2).

/// The standard count profile `com.ratifyprotocol.max_count/v1`.
pub fn standard_max_count_evaluator_v2() -> ConstraintEvaluatorRegistrationV2 {
    ConstraintEvaluatorRegistrationV2 {
        descriptor: ConstraintProfileDescriptorV2 {
            profile: PROFILE_MAX_COUNT_V2.into(),
            kind: CONSTRAINT_MAX_COUNT_V2.into(),
        },
        evaluate: Arc::new(|_, input| Ok(evaluate_max_count_v2(input))),
    }
}

/// The standard exact-value profile `com.ratifyprotocol.allowed_values/v1`.
pub fn standard_allowed_values_evaluator_v2() -> ConstraintEvaluatorRegistrationV2 {
    ConstraintEvaluatorRegistrationV2 {
        descriptor: ConstraintProfileDescriptorV2 {
            profile: PROFILE_ALLOWED_VALUES_V2.into(),
            kind: CONSTRAINT_ALLOWED_VALUES_V2.into(),
        },
        evaluate: Arc::new(|_, input| Ok(evaluate_allowed_values_v2(input))),
    }
}

fn outcome(outcome: ConstraintOutcomeV2, detail: impl Into<String>) -> ConstraintEvaluationResultV2 {
    ConstraintEvaluationResultV2 { outcome, valid_until: 0, detail: detail.into() }
}

/// The standard count profile applied to one input.
pub fn evaluate_max_count_v2(input: &ConstraintEvaluationInputV2) -> ConstraintEvaluationResultV2 {
    let (counter, max) = match decode_max_count_params_v2(input.params_json.as_deref()) {
        Ok(v) => v,
        Err(e) => return outcome(ConstraintOutcomeV2::Denied, e.message),
    };
    match input.context.extension_counts.get(&counter) {
        None => outcome(
            ConstraintOutcomeV2::Unverifiable,
            format!("no authenticated count {counter:?} in the request context"),
        ),
        Some(count) if *count > max => outcome(
            ConstraintOutcomeV2::Denied,
            format!("count {counter:?} is {count}, above the signed maximum {max}"),
        ),
        Some(_) => outcome(ConstraintOutcomeV2::Pass, ""),
    }
}

/// The standard exact-value profile applied to one input.
pub fn evaluate_allowed_values_v2(input: &ConstraintEvaluationInputV2) -> ConstraintEvaluationResultV2 {
    let (field, allowed) = match decode_allowed_values_params_v2(input.params_json.as_deref()) {
        Ok(v) => v,
        Err(e) => return outcome(ConstraintOutcomeV2::Denied, e.message),
    };
    match input.context.extension_values.get(&field) {
        None => outcome(
            ConstraintOutcomeV2::Unverifiable,
            format!("no authenticated value {field:?} in the request context"),
        ),
        Some(value) if !allowed.contains(value) => outcome(
            ConstraintOutcomeV2::Denied,
            format!("value of {field:?} is not an allowed value"),
        ),
        Some(_) => outcome(ConstraintOutcomeV2::Pass, ""),
    }
}

/// Strictly decode a params object with exactly the named members.
fn decode_standard_params_v2<'a>(
    data: Option<&[u8]>,
    members: &[&str],
    root: &'a mut Option<super::json::JNode>,
) -> V2Result<Vec<(&'a str, &'a super::json::JNode)>> {
    let Some(data) = data else {
        return plain("params are required");
    };
    let node = parse_json(data).map_err(|_| V2Error::plain("params must be one JSON object without duplicate members"))?;
    *root = Some(node);
    let Some(JV::Obj(fields)) = root.as_ref().map(|n| &n.v) else {
        return plain("params must be one JSON object without duplicate members");
    };
    if fields.len() != members.len() || !members.iter().all(|m| fields.iter().any(|(k, _)| k == m)) {
        return plain(format!("params must have exactly the members {members:?}"));
    }
    Ok(fields.iter().map(|(k, v)| (k.as_str(), v)).collect())
}

fn field<'a>(fields: &[(&str, &'a super::json::JNode)], name: &str) -> V2Result<&'a super::json::JNode> {
    fields
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
        .ok_or_else(|| V2Error::plain(format!("params member {name:?} is missing")))
}

fn decode_max_count_params_v2(data: Option<&[u8]>) -> V2Result<(String, i64)> {
    let mut root = None;
    let fields = decode_standard_params_v2(data, &["counter", "max"], &mut root)?;
    let counter = match v2_string_field(field(&fields, "counter")?) {
        Ok(c) if valid_extension_context_name_v2(&c) => c,
        _ => return plain("counter must be 1 to 128 bytes of [a-z0-9_.:-]"),
    };
    let max = match v2_integer_field(field(&fields, "max")?) {
        Ok(m) if m >= 0 => m,
        _ => return plain("max must be an integer in 0..2^53-1"),
    };
    Ok((counter, max))
}

fn decode_allowed_values_params_v2(data: Option<&[u8]>) -> V2Result<(String, Vec<String>)> {
    let mut root = None;
    let fields = decode_standard_params_v2(data, &["allowed", "field"], &mut root)?;
    let name = match v2_string_field(field(&fields, "field")?) {
        Ok(c) if valid_extension_context_name_v2(&c) => c,
        _ => return plain("field must be 1 to 128 bytes of [a-z0-9_.:-]"),
    };
    let JV::Arr(items) = &field(&fields, "allowed")?.v else {
        return plain("allowed must be an array of strings");
    };
    if items.is_empty() || items.len() > MAX_ALLOWED_VALUES_V2 {
        return plain("allowed must hold 1 to 64 strings");
    }
    let mut allowed: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        match v2_string_field(item) {
            Ok(v) if !v.is_empty() && v.len() <= MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2 && !allowed.contains(&v) => {
                allowed.push(v)
            }
            _ => return plain("allowed values must be unique strings of 1 to 512 bytes"),
        }
    }
    Ok((name, allowed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_profile_digests_match_the_spec_table() {
        let d = |p: &str, t: &str| {
            constraint_profile_digest_v2(&ConstraintProfileDescriptorV2 { profile: p.into(), kind: t.into() })
                .expect("digest")
        };
        assert_eq!(
            d(PROFILE_MAX_COUNT_V2, CONSTRAINT_MAX_COUNT_V2),
            "sha384:27e6c6b37856ce4eed4c0923641d45a59d06e138b38893d850f8f0f1356200286fdb2e2e8d36cc69e4b550f9b2443e2b"
        );
        assert_eq!(
            d(PROFILE_ALLOWED_VALUES_V2, CONSTRAINT_ALLOWED_VALUES_V2),
            "sha384:2c9b719e7477c342038f4900461db15c12d8d0d4131026cb4b820a3ee8e566e49d882a62c9846fa5047d606163bd8015"
        );
    }

    #[test]
    fn evaluator_panic_timeout_and_invalid_are_unverifiable() {
        let reg = |f: ConstraintEvaluatorFnV2| RegisteredEvaluator {
            reference: ConstraintEvaluatorRefV2 { kind: "a.b.c".into(), profile_digest: String::new() },
            evaluate: f,
        };
        let input = ConstraintEvaluationInputV2 {
            kind: "a.b.c".into(),
            params_json: None,
            delegation_index: 0,
            constraint_index: 0,
            issuer_id: String::new(),
            cert_id: String::new(),
            context: ConstraintContextV2::default(),
            evaluation_time: 100,
        };
        let panics = reg(Arc::new(|_, _| panic!("boom")));
        assert!(matches!(
            run_constraint_evaluator_v2(&panics, Duration::from_secs(1), input.clone()),
            Err(ConstraintFailure::Unverifiable(_))
        ));
        let slow = reg(Arc::new(|_, _| {
            std::thread::sleep(Duration::from_millis(300));
            Ok(outcome(ConstraintOutcomeV2::Pass, ""))
        }));
        assert!(matches!(
            run_constraint_evaluator_v2(&slow, Duration::from_millis(20), input.clone()),
            Err(ConstraintFailure::Unverifiable(_))
        ));
        let at_claim = reg(Arc::new(|_, _| {
            Ok(ConstraintEvaluationResultV2 { outcome: ConstraintOutcomeV2::Pass, valid_until: 100, detail: String::new() })
        }));
        assert!(run_constraint_evaluator_v2(&at_claim, Duration::from_secs(1), input.clone()).is_err());
        let invalid = reg(Arc::new(|_, _| Ok(outcome(ConstraintOutcomeV2::Invalid, ""))));
        assert!(run_constraint_evaluator_v2(&invalid, Duration::from_secs(1), input).is_err());
    }
}
