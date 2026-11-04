//! Owned input and direct standard-profile evaluation at the mobile boundary.

use std::collections::BTreeMap;

use ratify_protocol::v2::{
    self as core, ConstraintContextV2, ConstraintEvaluationInputV2, ConstraintEvaluationResultV2,
    ConstraintOutcomeV2, ConstraintProfileDescriptorV2,
};

use crate::error::FfiResult;
use crate::guard::call;

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
