//! Native key generation, hybrid signing and hybrid verification for the
//! Ratify Protocol v2 Python SDK.
//!
//! A separate distribution and module (`ratify-protocol-native-v2` /
//! `ratify_protocol_native_v2`) from the v1 extension, so both install
//! together. `ratify_protocol_v2` signs only through this extension and checks
//! `version()` at import time, rejecting a mismatched build.
//!
//! Signing uses `ed25519-dalek` and the constant-time `fips204` ML-DSA-65
//! implementation, the same crates the Ratify Rust core depends on. The SDK
//! computes the 77-byte v2 signing message and the ML-DSA context; this module
//! checks that the two describe the same registered object type and signs
//! exactly those bytes. It is not a wire verifier: the SDK verifies every
//! signature returned here with its ordinary verifier before using it.
//!
//! Verification: `_verify_hybrid` checks one hybrid signature over an
//! SDK-computed transcript with the Rust core's strict v2 verifier (canonical
//! prime-order Ed25519 A and R, S < L, the cofactorless equation, and FIPS 204
//! ML-DSA-65 under the per-type context). It touches only public data. The
//! SDK uses it by default and keeps its pure-Python verifier as a fallback;
//! both must reach the same verdict on every shared vector.
//!
//! Key material: a `HybridSigningKey` holds the parsed private keys in Rust
//! memory and zeroizes them on drop. Constructing one from private-key bytes
//! copies those bytes in from Python; `private_key_bytes()` and
//! `hybrid_keypair_from_seeds_py` copy them out, because the SDK's
//! `HybridPrivateKey` is bytes-backed. Python `bytes` objects cannot be wiped,
//! so callers should keep their lifetime short.

use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ratify_protocol::crypto::hybrid_keypair_from_seeds;
use ratify_protocol::types::{HybridPublicKey, HybridSignature};
use ratify_protocol::v2::{verify_v2_message, V2ObjectType};
use zeroize::Zeroize;

const SIGNATURE_PREFIX: &[u8] = b"ratify-protocol-signature\0\x02";
const MESSAGE_LEN: usize = 77;
const CONTEXT_PREFIX: &str = "ratify-protocol/2/";
const MIN_OBJECT_TYPE: u16 = 0x0001;
const MAX_OBJECT_TYPE: u16 = 0x0009;

fn value_error(msg: &str) -> PyErr {
    PyValueError::new_err(msg.to_string())
}

/// Check that `message` is a v2 transcript for a registered object type and
/// that `context` is exactly that type's ML-DSA context; return the type.
fn check_transcript(message: &[u8], context: &[u8]) -> PyResult<V2ObjectType> {
    if message.len() != MESSAGE_LEN || !message.starts_with(SIGNATURE_PREFIX) {
        return Err(value_error(
            "message is not a 77-byte Ratify v2 signing transcript",
        ));
    }
    let code = u16::from_be_bytes([
        message[SIGNATURE_PREFIX.len()],
        message[SIGNATURE_PREFIX.len() + 1],
    ]);
    if !(MIN_OBJECT_TYPE..=MAX_OBJECT_TYPE).contains(&code) {
        return Err(value_error("message names an unsupported v2 object type"));
    }
    if context != format!("{CONTEXT_PREFIX}{code:04x}").as_bytes() {
        return Err(value_error(
            "ML-DSA context does not match the message object type",
        ));
    }
    V2ObjectType::from_code(code)
        .ok_or_else(|| value_error("message names an unsupported v2 object type"))
}

/// A hybrid (Ed25519 + ML-DSA-65) private key held in native memory.
#[pyclass(frozen, module = "ratify_protocol_native_v2")]
struct HybridSigningKey {
    ed25519: SigningKey,
    ml_dsa_65: ml_dsa_65::PrivateKey,
}

impl HybridSigningKey {
    fn from_parts(ed_seed: &[u8], ml_secret: &[u8]) -> PyResult<Self> {
        let mut seed: [u8; 32] = ed_seed
            .try_into()
            .map_err(|_| value_error("Ed25519 private key must be a 32-byte seed"))?;
        let mut secret: [u8; ml_dsa_65::SK_LEN] = ml_secret
            .try_into()
            .map_err(|_| value_error("ML-DSA-65 private key must be 4032 bytes"))?;
        let ed25519 = SigningKey::from_bytes(&seed);
        seed.zeroize();
        // try_from_bytes takes the array by value; the copy left here is wiped.
        let parsed = ml_dsa_65::PrivateKey::try_from_bytes(secret);
        secret.zeroize();
        let ml_dsa_65 = parsed.map_err(|_| value_error("ML-DSA-65 private key is malformed"))?;
        Ok(Self { ed25519, ml_dsa_65 })
    }
}

#[pymethods]
impl HybridSigningKey {
    /// Load a key from a 32-byte Ed25519 seed and a 4032-byte ML-DSA-65
    /// secret key (the SDK's `HybridPrivateKey` layout).
    #[staticmethod]
    fn from_private_bytes(ed25519: &[u8], ml_dsa_65: &[u8]) -> PyResult<Self> {
        Self::from_parts(ed25519, ml_dsa_65)
    }

    /// Derive a key from two 32-byte seeds (Go `HybridKeypairFromSeeds`).
    #[staticmethod]
    fn from_seeds(ed_seed: &[u8], ml_seed: &[u8]) -> PyResult<Self> {
        let ed_seed: [u8; 32] = ed_seed
            .try_into()
            .map_err(|_| value_error("Ed25519 seed must be 32 bytes"))?;
        let ml_seed: [u8; 32] = ml_seed
            .try_into()
            .map_err(|_| value_error("ML-DSA-65 seed must be 32 bytes"))?;
        // HybridPrivateKey wipes both components when it is dropped.
        let (_, private) = hybrid_keypair_from_seeds(&ed_seed, &ml_seed);
        Self::from_parts(private.ed25519(), private.ml_dsa_65())
    }

    /// Return `(ed25519_public, ml_dsa_65_public)`.
    fn public_key(&self, py: Python<'_>) -> (Py<PyBytes>, Py<PyBytes>) {
        let ml_pub = self.ml_dsa_65.get_public_key().into_bytes();
        (
            PyBytes::new(py, &self.ed25519.verifying_key().to_bytes()).unbind(),
            PyBytes::new(py, &ml_pub).unbind(),
        )
    }

    /// Copy the private key out as `(ed25519_seed, ml_dsa_65_secret)` bytes.
    fn private_key_bytes(&self, py: Python<'_>) -> (Py<PyBytes>, Py<PyBytes>) {
        let mut seed = self.ed25519.to_bytes();
        let mut secret = self.ml_dsa_65.clone().into_bytes();
        let out = (
            PyBytes::new(py, &seed).unbind(),
            PyBytes::new(py, &secret).unbind(),
        );
        seed.zeroize();
        secret.zeroize();
        out
    }

    /// Internal to `ratify_protocol_v2`: sign an SDK-computed v2 transcript
    /// with both components. It is not public API. The SDK's typed signing
    /// functions are the only supported callers; they compute the message
    /// and context and verify every returned signature. The name is
    /// underscored and the SDK never re-exports it, but a compiled module
    /// cannot hide a method from code running in the same interpreter, so a
    /// caller that already holds a `HybridSigningKey` (and therefore the key
    /// bytes) can still reach it. It signs only registered v2 transcripts.
    ///
    /// Returns `(ed25519_signature, ml_dsa_65_signature)`. ML-DSA-65 signing is
    /// hedged with fresh OS randomness. `deterministic_for_test_vectors=True`
    /// uses the FIPS 204 deterministic variant (all-zero `rnd`), which is how
    /// the shared test vectors are generated; it exists for conformance tests
    /// and must not be used for production signatures.
    #[pyo3(name = "_sign", signature = (message, context, *, deterministic_for_test_vectors = false))]
    fn sign(
        &self,
        py: Python<'_>,
        message: &[u8],
        context: &[u8],
        deterministic_for_test_vectors: bool,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        check_transcript(message, context)?;
        let ed_sig = self.ed25519.sign(message).to_bytes();
        let ml_sig = if deterministic_for_test_vectors {
            self.ml_dsa_65
                .try_sign_with_seed(&[0u8; 32], message, context)
        } else {
            self.ml_dsa_65.try_sign(message, context)
        }
        .map_err(|e| PyRuntimeError::new_err(format!("ML-DSA-65 signing failed: {e}")))?;
        Ok((
            PyBytes::new(py, &ed_sig).unbind(),
            PyBytes::new(py, &ml_sig).unbind(),
        ))
    }

    fn __repr__(&self) -> &'static str {
        "<HybridSigningKey>"
    }
}

/// Derive a hybrid keypair from two 32-byte seeds.
///
/// Returns `(ed25519_public, ml_dsa_65_public, ed25519_private,
/// ml_dsa_65_private)` as `bytes`. Both seeds are key material.
/// Ed25519 public, ML-DSA-65 public, Ed25519 private, ML-DSA-65 private.
type KeypairBytes = (Py<PyBytes>, Py<PyBytes>, Py<PyBytes>, Py<PyBytes>);

#[pyfunction]
fn hybrid_keypair_from_seeds_py(
    py: Python<'_>,
    ed_seed: &[u8],
    ml_seed: &[u8],
) -> PyResult<KeypairBytes> {
    let ed_seed: [u8; 32] = ed_seed
        .try_into()
        .map_err(|_| value_error("Ed25519 seed must be 32 bytes"))?;
    let ml_seed: [u8; 32] = ml_seed
        .try_into()
        .map_err(|_| value_error("ML-DSA-65 seed must be 32 bytes"))?;

    // HybridPrivateKey wipes both components when it is dropped.
    let (public, private) = hybrid_keypair_from_seeds(&ed_seed, &ml_seed);
    Ok((
        PyBytes::new(py, &public.ed25519).unbind(),
        PyBytes::new(py, &public.ml_dsa_65).unbind(),
        PyBytes::new(py, private.ed25519()).unbind(),
        PyBytes::new(py, private.ml_dsa_65()).unbind(),
    ))
}

/// Internal to `ratify_protocol_v2`: strictly verify one hybrid signature
/// over an SDK-computed 77-byte v2 transcript `message` and its ML-DSA
/// `context`, under the complete public key. Not public API; the SDK's
/// verifiers are the supported callers. Returns `None` when both components
/// verify and raises `ValueError` otherwise (a malformed transcript or
/// context, a wrong component length, a non-canonical or small-order point,
/// a non-canonical scalar, or a failed Ed25519 or ML-DSA-65 check). The GIL
/// is released while the signature is checked.
#[pyfunction]
#[pyo3(name = "_verify_hybrid")]
fn verify_hybrid(
    py: Python<'_>,
    message: &[u8],
    context: &[u8],
    ed25519_public: &[u8],
    ml_dsa_65_public: &[u8],
    ed25519_signature: &[u8],
    ml_dsa_65_signature: &[u8],
) -> PyResult<()> {
    let object_type = check_transcript(message, context)?;
    let public_key = HybridPublicKey {
        ed25519: ed25519_public.to_vec(),
        ml_dsa_65: ml_dsa_65_public.to_vec(),
    };
    let signature = HybridSignature {
        ed25519: ed25519_signature.to_vec(),
        ml_dsa_65: ml_dsa_65_signature.to_vec(),
    };
    let message = message.to_vec();
    py.detach(|| verify_v2_message(object_type, &message, &signature, &public_key))
        .map_err(|e| PyValueError::new_err(e.message))
}

/// Distribution version of this extension (Cargo form, e.g. 2.0.0-beta.1).
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn ratify_protocol_native_v2(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<HybridSigningKey>()?;
    m.add_function(wrap_pyfunction!(hybrid_keypair_from_seeds_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_hybrid, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
