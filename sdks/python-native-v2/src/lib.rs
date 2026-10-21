//! Native deterministic key generation for the Ratify Protocol v2 Python SDK.
//!
//! A separate distribution and module (`ratify-protocol-native-v2` /
//! `ratify_protocol_native_v2`) from the v1 extension, so both install
//! together. It supplies key generation only; it is not a wire verifier.
//! `ratify_protocol_v2` checks `version()` at import time and rejects a
//! mismatched build.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ratify_protocol::crypto::hybrid_keypair_from_seeds;

/// Derive a hybrid keypair from two 32-byte seeds.
///
/// Returns `(ed25519_public, ml_dsa_65_public, ed25519_private,
/// ml_dsa_65_private)` as `bytes`. Both seeds are key material.
#[pyfunction]
fn hybrid_keypair_from_seeds_py(
    py: Python<'_>,
    ed_seed: &[u8],
    ml_seed: &[u8],
) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
    let ed_seed: [u8; 32] = ed_seed.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Ed25519 seed must be 32 bytes")
    })?;
    let ml_seed: [u8; 32] = ml_seed.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("ML-DSA-65 seed must be 32 bytes")
    })?;

    let (public, private) = hybrid_keypair_from_seeds(&ed_seed, &ml_seed);
    Ok((
        PyBytes::new(py, &public.ed25519).unbind(),
        PyBytes::new(py, &public.ml_dsa_65).unbind(),
        PyBytes::new(py, &private.ed25519).unbind(),
        PyBytes::new(py, &private.ml_dsa_65).unbind(),
    ))
}

/// Distribution version of this extension (Cargo form, e.g. 2.0.0-alpha.1).
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn ratify_protocol_native_v2(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hybrid_keypair_from_seeds_py, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
