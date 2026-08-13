use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::Engine;
use napi::{bindgen_prelude::AsyncTask, Env, Error, Result, Status, Task};
use napi_derive::napi;
use ratify_protocol::{
    decode_proof_bundle, verify_bundle, RevocationProvider, StreamContext, VerifierContext,
    VerifyOptions,
};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextInput {
    current_lat: Option<f64>,
    current_lon: Option<f64>,
    current_alt_m: Option<f64>,
    current_speed_mps: Option<f64>,
    requested_amount: Option<f64>,
    requested_currency: Option<String>,
    invocations_in_window_count: Option<i64>,
    requested_resource_id: Option<String>,
    requested_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamInput {
    stream_id: String,
    #[serde(default)]
    last_seen_seq: i64,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsInput {
    #[serde(default)]
    required_scope: String,
    now: Option<i64>,
    #[serde(default)]
    session_context: String,
    stream: Option<StreamInput>,
    #[serde(default)]
    context: ContextInput,
    #[serde(default)]
    revoked_cert_ids: BTreeSet<String>,
}

struct RevokedSet(BTreeSet<String>);

impl RevocationProvider for RevokedSet {
    fn is_revoked(&self, cert_id: &str) -> std::result::Result<bool, String> {
        Ok(self.0.contains(cert_id))
    }
}

fn b64(value: &str, field: &str) -> std::result::Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("invalid {field}: {e}"))
}

fn verify_inner(bundle_json: &str, options_json: &str) -> std::result::Result<String, String> {
    let bundle = decode_proof_bundle(bundle_json.as_bytes())?;
    let input: OptionsInput = serde_json::from_str(options_json)
        .map_err(|e| format!("invalid options: {e}"))?;
    let count = input.context.invocations_in_window_count;
    let context = VerifierContext {
        current_lat: input.context.current_lat,
        current_lon: input.context.current_lon,
        current_alt_m: input.context.current_alt_m,
        current_speed_mps: input.context.current_speed_mps,
        requested_amount: input.context.requested_amount,
        requested_currency: input.context.requested_currency,
        invocations_in_window: count.map(|n| {
            Box::new(move |_cert_id: &str, _window_s: i64| n)
                as Box<dyn Fn(&str, i64) -> i64>
        }),
        requested_resource_id: input.context.requested_resource_id,
        requested_path: input.context.requested_path,
    };
    let stream = input.stream.map(|s| -> std::result::Result<StreamContext, String> {
        Ok(StreamContext { stream_id: b64(&s.stream_id, "stream_id")?, last_seen_seq: s.last_seen_seq })
    }).transpose()?;
    let revocation = (!input.revoked_cert_ids.is_empty()).then(|| {
        Box::new(RevokedSet(input.revoked_cert_ids)) as Box<dyn RevocationProvider>
    });
    let options = VerifyOptions {
        required_scope: input.required_scope,
        now: input.now,
        session_context: if input.session_context.is_empty() { Vec::new() } else { b64(&input.session_context, "session_context")? },
        stream,
        context,
        revocation,
        ..VerifyOptions::default()
    };
    serde_json::to_string(&verify_bundle(&bundle, &options)).map_err(|e| e.to_string())
}

#[napi]
pub fn verify_bundle_json(bundle_json: String, options_json: String) -> Result<String> {
    match catch_unwind(AssertUnwindSafe(|| verify_inner(&bundle_json, &options_json))) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(Error::new(Status::InvalidArg, error)),
        Err(_) => Err(Error::new(Status::GenericFailure, "native verifier panicked")),
    }
}

pub struct VerifyTask {
    bundle_json: String,
    options_json: String,
}

impl Task for VerifyTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        verify_bundle_json(self.bundle_json.clone(), self.options_json.clone())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn verify_bundle_json_async(bundle_json: String, options_json: String) -> AsyncTask<VerifyTask> {
    AsyncTask::new(VerifyTask { bundle_json, options_json })
}
