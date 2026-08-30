//! Deterministic hybrid key generation for the Ratify Protocol Python SDK.
//!
//! This is a separate distribution (`ratify-protocol-native`) rather than part
//! of `ratify-protocol` on purpose: the Python SDK stays a pure-Python,
//! platform-independent package that installs anywhere, and this optional
//! extra adds the one entry it cannot implement in pure Python.
//!
//! Why an extension is needed at all: `pqcrypto`'s ML-DSA-65 binding calls
//! PQClean's `crypto_sign_keypair`, which reads the OS RNG and ignores any
//! caller-supplied seed. The only pure-Python ML-DSA implementations available
//! carry explicit warnings against cryptographic use, so the deterministic path
//! runs through the Ratify Rust core instead.
//!
//! Only key generation lives here. Signing and verification remain on
//! `pqcrypto` in the Python SDK, unchanged.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ratify_protocol::crypto::hybrid_keypair_from_seeds;

/// Derive a hybrid keypair from two 32-byte seeds.
///
/// Returns `(ed25519_public, ml_dsa_65_public, ed25519_private,
/// ml_dsa_65_private)` as `bytes`. Output is byte-identical to the Go, Rust,
/// TypeScript, and C SDKs for the same seeds.
///
/// Both seeds are key material. Anyone holding them holds the identity.
#[pyfunction]
fn hybrid_keypair_from_seeds_py(
    py: Python<'_>,
    ed_seed: &[u8],
    ml_seed: &[u8],
) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
    // Length is validated here as well as in the Python caller: this function
    // is importable directly, and a short seed must not reach the core.
    let ed_seed: [u8; 32] = ed_seed.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Ed25519 seed must be 32 bytes")
    })?;
    let ml_seed: [u8; 32] = ml_seed.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("ML-DSA-65 seed must be 32 bytes")
    })?;

    let (public, private) = hybrid_keypair_from_seeds(&ed_seed, &ml_seed);
    Ok((
        PyBytes::new_bound(py, &public.ed25519).unbind(),
        PyBytes::new_bound(py, &public.ml_dsa_65).unbind(),
        PyBytes::new_bound(py, &private.ed25519).unbind(),
        PyBytes::new_bound(py, &private.ml_dsa_65).unbind(),
    ))
}

/// Protocol version this extension was built against. The Python SDK checks it
/// so a stale extension reports a version mismatch instead of silently pairing
/// with an SDK it was not built for.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn ratify_protocol_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hybrid_keypair_from_seeds_py, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
