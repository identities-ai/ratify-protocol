//! Owned input and direct standard-profile evaluation at the mobile boundary.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ratify_protocol::v2::{
    self as core, ConstraintContextV2, ConstraintEvaluationInputV2, ConstraintEvaluationResultV2,
    ConstraintOutcomeV2, ConstraintProfileDescriptorV2, ConstraintEvaluatorRegistrationV2,
    ConstraintEvaluatorRegistryV2, ConstraintEvaluatorInvocationV2, ConstraintEvaluatorError,
};

use crate::error::FfiResult;
use crate::guard::{call, call_on, Poison};
use crate::store::FfiStoreContext;

#[derive(uniffi::Record, Clone)]
pub struct FfiConstraintContext {
    pub requested_amount_micros: i64,
    pub requested_currency: String,
    pub has_amount: bool,
    pub requested_resource_id: String,
    pub requested_path: String,
    pub has_resource: bool,
    pub extension_counts: std::collections::HashMap<String, i64>,
    pub extension_values: std::collections::HashMap<String, String>,
}

impl From<FfiConstraintContext> for ConstraintContextV2 {
    fn from(c: FfiConstraintContext) -> Self {
        Self {
            requested_amount_micros: c.requested_amount_micros,
            requested_currency: c.requested_currency,
            has_amount: c.has_amount,
            requested_resource_id: c.requested_resource_id,
            requested_path: c.requested_path,
            has_resource: c.has_resource,
            extension_counts: c.extension_counts.into_iter().collect::<BTreeMap<_, _>>(),
            extension_values: c.extension_values.into_iter().collect::<BTreeMap<_, _>>(),
        }
    }
}

impl From<ConstraintContextV2> for FfiConstraintContext {
    fn from(c: ConstraintContextV2) -> Self {
        Self {
            requested_amount_micros: c.requested_amount_micros,
            requested_currency: c.requested_currency,
            has_amount: c.has_amount,
            requested_resource_id: c.requested_resource_id,
            requested_path: c.requested_path,
            has_resource: c.has_resource,
            extension_counts: c.extension_counts.into_iter().collect(),
            extension_values: c.extension_values.into_iter().collect(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiConstraintEvaluationInput {
    pub kind: String,
    pub params_json: Option<Vec<u8>>,
    pub delegation_index: u64,
    pub constraint_index: u64,
    pub issuer_id: String,
    pub cert_id: String,
    pub context: FfiConstraintContext,
    pub evaluation_time: i64,
}

impl From<ConstraintEvaluationInputV2> for FfiConstraintEvaluationInput {
    fn from(i: ConstraintEvaluationInputV2) -> Self {
        Self {
            kind: i.kind,
            params_json: i.params_json,
            delegation_index: i.delegation_index as u64,
            constraint_index: i.constraint_index as u64,
            issuer_id: i.issuer_id,
            cert_id: i.cert_id,
            context: i.context.into(),
            evaluation_time: i.evaluation_time,
        }
    }
}

impl TryFrom<FfiConstraintEvaluationInput> for ConstraintEvaluationInputV2 {
    type Error = core::V2Error;

    fn try_from(i: FfiConstraintEvaluationInput) -> Result<Self, Self::Error> {
        let invalid = || {
            core::V2Error::new(
                core::V2ErrorClass::ConfigurationInvalid,
                "constraint index exceeds platform size",
            )
        };
        Ok(Self {
            kind: i.kind,
            params_json: i.params_json,
            delegation_index: usize::try_from(i.delegation_index).map_err(|_| invalid())?,
            constraint_index: usize::try_from(i.constraint_index).map_err(|_| invalid())?,
            issuer_id: i.issuer_id,
            cert_id: i.cert_id,
            context: i.context.into(),
            evaluation_time: i.evaluation_time,
        })
    }
}

#[derive(uniffi::Record)]
pub struct FfiConstraintEvaluationResult {
    pub outcome: String,
    pub valid_until: i64,
    pub detail: String,
}

impl From<ConstraintEvaluationResultV2> for FfiConstraintEvaluationResult {
    fn from(r: ConstraintEvaluationResultV2) -> Self {
        Self {
            outcome: match r.outcome {
                ConstraintOutcomeV2::Pass => "pass",
                ConstraintOutcomeV2::Denied => "denied",
                ConstraintOutcomeV2::Unverifiable => "unverifiable",
                ConstraintOutcomeV2::Invalid => "invalid",
            }
            .into(),
            valid_until: r.valid_until,
            detail: r.detail,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiEvaluatorError {
    #[error("{detail}")]
    Failed { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiEvaluatorError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { detail: e.reason }
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiConstraintEvaluator: Send + Sync {
    fn evaluate(&self, input: FfiConstraintEvaluationInput,
        context: Arc<FfiStoreContext>) -> Result<FfiConstraintEvaluationResult, FfiEvaluatorError>;
}

#[derive(uniffi::Record)]
pub struct FfiConstraintEvaluatorRegistration {
    pub profile: String,
    pub kind: String,
    pub evaluator: Arc<dyn FfiConstraintEvaluator>,
}

#[derive(uniffi::Object)]
pub struct FfiConstraintEvaluatorRegistry {
    pub(crate) poison: Poison,
    pub(crate) inner: ConstraintEvaluatorRegistryV2,
}

#[uniffi::export]
impl FfiConstraintEvaluatorRegistry {
    #[uniffi::constructor]
    pub fn new(timeout_millis: u64, registrations: Vec<FfiConstraintEvaluatorRegistration>) -> FfiResult<Arc<Self>> {
        call(|| {
            let registrations = registrations.into_iter().map(foreign_registration).collect();
            let inner = ConstraintEvaluatorRegistryV2::new_with_invocation(
                Duration::from_millis(timeout_millis), registrations, ConstraintEvaluatorInvocationV2::CallingThread)?;
            Ok(Arc::new(Self { poison: Poison::default(), inner }))
        })
    }

    pub fn refs(&self) -> FfiResult<Vec<crate::objects::FfiConstraintEvaluatorRef>> {
        call_on(&self.poison, || Ok(self.inner.refs().into_iter().map(|r| crate::objects::FfiConstraintEvaluatorRef {
            kind: r.kind, profile_digest: r.profile_digest,
        }).collect()))
    }
}

fn foreign_registration(r: FfiConstraintEvaluatorRegistration) -> ConstraintEvaluatorRegistrationV2 {
    let evaluator = r.evaluator;
    ConstraintEvaluatorRegistrationV2 {
        descriptor: ConstraintProfileDescriptorV2 { profile: r.profile, kind: r.kind },
        evaluate: Arc::new(move |ctx, input| {
            let result = evaluator.evaluate(input.clone().into(), FfiStoreContext::new(ctx))
                .map_err(|e| ConstraintEvaluatorError(e.to_string()))?;
            let outcome = match result.outcome.as_str() {
                "pass" => ConstraintOutcomeV2::Pass,
                "denied" => ConstraintOutcomeV2::Denied,
                "unverifiable" => ConstraintOutcomeV2::Unverifiable,
                _ => ConstraintOutcomeV2::Invalid,
            };
            Ok(ConstraintEvaluationResultV2 { outcome, valid_until: result.valid_until, detail: result.detail })
        }),
    }
}

#[uniffi::export]
pub fn ffi_validate_request_context(context: FfiConstraintContext) -> FfiResult<()> {
    call(|| Ok(core::validate_v2_request_context(&context.into())?))
}

#[uniffi::export]
pub fn ffi_constraint_profile_digest(profile: String, kind: String) -> FfiResult<String> {
    call(|| {
        Ok(core::constraint_profile_digest_v2(
            &ConstraintProfileDescriptorV2 { profile, kind },
        )?)
    })
}

#[uniffi::export]
pub fn ffi_evaluate_max_count(
    input: FfiConstraintEvaluationInput,
) -> FfiResult<FfiConstraintEvaluationResult> {
    call(|| Ok(core::evaluate_max_count_v2(&input.try_into()?).into()))
}

#[uniffi::export]
pub fn ffi_evaluate_allowed_values(
    input: FfiConstraintEvaluationInput,
) -> FfiResult<FfiConstraintEvaluationResult> {
    call(|| Ok(core::evaluate_allowed_values_v2(&input.try_into()?).into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Evaluator(AtomicUsize);
    impl FfiConstraintEvaluator for Evaluator {
        fn evaluate(&self, input: FfiConstraintEvaluationInput,
            context: Arc<FfiStoreContext>) -> Result<FfiConstraintEvaluationResult, FfiEvaluatorError> {
            assert_eq!(input.kind, "com.example.limit");
            assert_eq!(input.params_json, Some(br#"{"max":1}"#.to_vec()));
            assert!(!context.is_cancelled().unwrap());
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(FfiConstraintEvaluationResult { outcome: "pass".into(), valid_until: 42, detail: String::new() })
        }
    }

    struct FaultyEvaluator(&'static str);
    impl FfiConstraintEvaluator for FaultyEvaluator {
        fn evaluate(&self, _: FfiConstraintEvaluationInput,
            _: Arc<FfiStoreContext>) -> Result<FfiConstraintEvaluationResult, FfiEvaluatorError> {
            if self.0 == "error" {
                return Err(FfiEvaluatorError::Failed { detail: "failed".into() });
            }
            Ok(FfiConstraintEvaluationResult { outcome: self.0.into(), valid_until: 0, detail: String::new() })
        }
    }

    #[test]
    fn foreign_registration_preserves_input_and_callback_result() {
        let evaluator = Arc::new(Evaluator(AtomicUsize::new(0)));
        let registration = foreign_registration(FfiConstraintEvaluatorRegistration {
            profile: "com.example.limit/v1".into(), kind: "com.example.limit".into(), evaluator: evaluator.clone(),
        });
        let answer = (registration.evaluate)(&core::V2Context::background(), &ConstraintEvaluationInputV2 {
            kind: "com.example.limit".into(), params_json: Some(br#"{"max":1}"#.to_vec()),
            delegation_index: 0, constraint_index: 0, issuer_id: String::new(), cert_id: String::new(),
            context: ConstraintContextV2::default(), evaluation_time: 10,
        }).unwrap();
        assert_eq!(answer.outcome, ConstraintOutcomeV2::Pass);
        assert_eq!(answer.valid_until, 42);
        assert_eq!(evaluator.0.load(Ordering::SeqCst), 1);
        let registry = FfiConstraintEvaluatorRegistry::new(100, vec![FfiConstraintEvaluatorRegistration {
            profile: "com.example.limit/v1".into(), kind: "com.example.limit".into(), evaluator,
        }]).unwrap();
        assert_eq!(registry.inner.invocation(), ConstraintEvaluatorInvocationV2::CallingThread);
        assert_eq!(registry.refs().unwrap()[0].kind, "com.example.limit");
    }

    #[test]
    fn foreign_callback_error_and_unknown_outcome_fail_closed() {
        let input = ConstraintEvaluationInputV2 {
            kind: "com.example.limit".into(), params_json: None,
            delegation_index: 0, constraint_index: 0, issuer_id: String::new(), cert_id: String::new(),
            context: ConstraintContextV2::default(), evaluation_time: 10,
        };
        for (answer, expected) in [("error", None), ("unexpected", Some(ConstraintOutcomeV2::Invalid))] {
            let registration = foreign_registration(FfiConstraintEvaluatorRegistration {
                profile: "com.example.limit/v1".into(), kind: input.kind.clone(),
                evaluator: Arc::new(FaultyEvaluator(answer)),
            });
            let result = (registration.evaluate)(&core::V2Context::background(), &input);
            assert_eq!(result.ok().map(|r| r.outcome), expected);
        }
    }
}
