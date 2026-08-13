use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::Engine;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use ratify_protocol::{
    decode_proof_bundle, verify_bundle, Constraint, DelegationCert, HybridPublicKey,
    HybridSignature, ProofBundle, RevocationProvider, StreamContext, VerifierContext, VerifyOptions,
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
    fn is_revoked(&self, cert_id: &str) -> Result<bool, String> {
        Ok(self.0.contains(cert_id))
    }
}

fn b64(value: &str, field: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("invalid {field}: {e}"))
}

fn verify_json_inner(bundle_json: &str, options_json: &str) -> Result<String, String> {
    let bundle = decode_proof_bundle(bundle_json.as_bytes())?;
    verify_inner(&bundle, options_json)
}

fn verify_inner(bundle: &ProofBundle, options_json: &str) -> Result<String, String> {
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
    let stream = input.stream.map(|s| -> Result<StreamContext, String> {
        Ok(StreamContext {
            stream_id: b64(&s.stream_id, "stream_id")?,
            last_seen_seq: s.last_seen_seq,
        })
    }).transpose()?;
    let revocation = (!input.revoked_cert_ids.is_empty()).then(|| {
        Box::new(RevokedSet(input.revoked_cert_ids)) as Box<dyn RevocationProvider>
    });
    let options = VerifyOptions {
        required_scope: input.required_scope,
        now: input.now,
        session_context: if input.session_context.is_empty() {
            Vec::new()
        } else {
            b64(&input.session_context, "session_context")?
        },
        stream,
        context,
        revocation,
        ..VerifyOptions::default()
    };
    serde_json::to_string(&verify_bundle(&bundle, &options)).map_err(|e| e.to_string())
}

fn public_key(value: &Bound<'_, PyAny>) -> PyResult<HybridPublicKey> {
    Ok(HybridPublicKey {
        ed25519: value.getattr("ed25519")?.extract()?,
        ml_dsa_65: value.getattr("ml_dsa_65")?.extract()?,
    })
}

fn signature(value: &Bound<'_, PyAny>) -> PyResult<HybridSignature> {
    Ok(HybridSignature {
        ed25519: value.getattr("ed25519")?.extract()?,
        ml_dsa_65: value.getattr("ml_dsa_65")?.extract()?,
    })
}

fn constraint(value: &Bound<'_, PyAny>) -> PyResult<Constraint> {
    let params = value.getattr("params")?;
    let params = if params.is_none() {
        None
    } else {
        let json = value.py().import("json")?.call_method1("dumps", (params,))?.extract::<String>()?;
        Some(serde_json::from_str(&json).map_err(|e| PyValueError::new_err(e.to_string()))?)
    };
    let path_prefix: String = value.getattr("path_prefix")?.extract()?;
    let points: Vec<Vec<f64>> = value.getattr("points")?.extract()?;
    let points = points
        .into_iter()
        .map(|p| p.try_into().map_err(|_| PyValueError::new_err("constraint point must contain two values")))
        .collect::<PyResult<Vec<[f64; 2]>>>()?;
    Ok(Constraint {
        count: value.getattr("count")?.extract()?,
        currency: value.getattr("currency")?.extract()?,
        end: value.getattr("end")?.extract()?,
        lat: value.getattr("lat")?.extract()?,
        lon: value.getattr("lon")?.extract()?,
        max_alt_m: value.getattr("max_alt_m")?.extract()?,
        max_amount: value.getattr("max_amount")?.extract()?,
        max_lat: value.getattr("max_lat")?.extract()?,
        max_lon: value.getattr("max_lon")?.extract()?,
        max_mps: value.getattr("max_mps")?.extract()?,
        min_alt_m: value.getattr("min_alt_m")?.extract()?,
        min_lat: value.getattr("min_lat")?.extract()?,
        min_lon: value.getattr("min_lon")?.extract()?,
        params,
        path_prefix: (!path_prefix.is_empty()).then_some(path_prefix),
        points,
        radius_m: value.getattr("radius_m")?.extract()?,
        resource_id: value.getattr("resource_id")?.extract()?,
        start: value.getattr("start")?.extract()?,
        tz: value.getattr("tz")?.extract()?,
        kind: value.getattr("type")?.extract()?,
        window_s: value.getattr("window_s")?.extract()?,
    })
}

fn bundle_from_py(value: &Bound<'_, PyAny>) -> PyResult<ProofBundle> {
    let mut delegations = Vec::new();
    for cert in value.getattr("delegations")?.try_iter()? {
        let cert = cert?;
        let mut constraints = Vec::new();
        for item in cert.getattr("constraints")?.try_iter()? {
            constraints.push(constraint(&item?)?);
        }
        delegations.push(DelegationCert {
            cert_id: cert.getattr("cert_id")?.extract()?,
            version: cert.getattr("version")?.extract()?,
            issuer_id: cert.getattr("issuer_id")?.extract()?,
            issuer_pub_key: public_key(&cert.getattr("issuer_pub_key")?)?,
            subject_id: cert.getattr("subject_id")?.extract()?,
            subject_pub_key: public_key(&cert.getattr("subject_pub_key")?)?,
            scope: cert.getattr("scope")?.extract()?,
            constraints,
            issued_at: cert.getattr("issued_at")?.extract()?,
            expires_at: cert.getattr("expires_at")?.extract()?,
            signature: signature(&cert.getattr("signature")?)?,
        });
    }
    Ok(ProofBundle {
        agent_id: value.getattr("agent_id")?.extract()?,
        agent_pub_key: public_key(&value.getattr("agent_pub_key")?)?,
        delegations,
        challenge: value.getattr("challenge")?.extract()?,
        challenge_at: value.getattr("challenge_at")?.extract()?,
        challenge_sig: signature(&value.getattr("challenge_sig")?)?,
        session_context: value.getattr("session_context")?.extract()?,
        stream_id: value.getattr("stream_id")?.extract()?,
        stream_seq: value.getattr("stream_seq")?.extract()?,
    })
}

#[pyfunction]
fn verify_bundle_json(bundle_json: &str, options_json: &str) -> PyResult<String> {
    match catch_unwind(AssertUnwindSafe(|| verify_json_inner(bundle_json, options_json))) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(PyValueError::new_err(error)),
        Err(_) => Err(PyValueError::new_err("native verifier panicked")),
    }
}

#[pyfunction]
fn verify_bundle_object(bundle: &Bound<'_, PyAny>, options_json: &str) -> PyResult<String> {
    match catch_unwind(AssertUnwindSafe(|| -> PyResult<String> {
        let bundle = bundle_from_py(bundle)?;
        verify_inner(&bundle, options_json).map_err(PyValueError::new_err)
    })) {
        Ok(result) => result,
        Err(_) => Err(PyValueError::new_err("native verifier panicked")),
    }
}

#[pymodule]
fn ratify_rust_accel(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_bundle_json, module)?)?;
    module.add_function(wrap_pyfunction!(verify_bundle_object, module)?)
}
