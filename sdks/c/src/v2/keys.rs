//! Hybrid key pairs for Protocol v2: generation from seeds or from the
//! operating-system random source, public keys, and key IDs (SPEC-v2 §2.3).

use std::os::raw::c_char;
use std::sync::atomic::AtomicBool;

use ratify_protocol::v2::{key_id_v2, V2ErrorClass};
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPrivateKey, HybridPublicKey};
use zeroize::Zeroizing;

use super::marshal::{public_key_json, to_bytes};
use super::{
    bytes, flag, handle, null_arg, poisonable, run, run_h, write_string, AbiResult, Failure,
    RatifyV2Code, RatifyV2PublicKey,
};

/// An opaque hybrid Ed25519 + ML-DSA-65 key pair. Create it with
/// `ratify_v2_keypair_from_seeds` or `ratify_v2_keypair_generate`; release it
/// with `ratify_v2_keypair_free`, which wipes the private key. It is used by
/// one thread at a time; the library reads it during a signing call and never
/// retains or copies it.
pub struct RatifyV2KeyPair {
    pub(crate) poisoned: AtomicBool,
    pub(crate) private: HybridPrivateKey,
    pub(crate) public: HybridPublicKey,
    pub(crate) key_id: String,
}

poisonable!(RatifyV2KeyPair);

impl RatifyV2KeyPair {
    pub(crate) fn from_seeds(ed: &[u8; 32], ml: &[u8; 32]) -> AbiResult<Self> {
        let (public, private) = hybrid_keypair_from_seeds(ed, ml);
        let key_id = key_id_v2(&public)?;
        Ok(RatifyV2KeyPair {
            poisoned: AtomicBool::new(false),
            private,
            public,
            key_id,
        })
    }
}

/// A copy of a caller seed, wiped when it goes out of scope.
fn seed(ptr: *const u8, name: &str) -> AbiResult<Zeroizing<[u8; 32]>> {
    // SAFETY: the caller supplies 32 readable bytes (documented).
    if ptr.is_null() {
        return Err(null_arg(name));
    }
    let b = unsafe { bytes(ptr, 32, name)? };
    let mut s = Zeroizing::new([0u8; 32]);
    s.copy_from_slice(b);
    Ok(s)
}

/// Derive a key pair from a 32-byte Ed25519 seed and a 32-byte ML-DSA-65
/// seed (FIPS 204 `KeyGen_internal(ξ)`), the derivation every SDK and the
/// `keys.json` fixtures use. Seeds are copied; the caller may wipe them after
/// the call. On success `*out` is a new handle.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_keypair_from_seeds(
    ed25519_seed: *const u8,
    ml_dsa_65_seed: *const u8,
    out: *mut *mut RatifyV2KeyPair,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let ed = seed(ed25519_seed, "ed25519_seed")?;
            let ml = seed(ml_dsa_65_seed, "ml_dsa_65_seed")?;
            let kp = RatifyV2KeyPair::from_seeds(&ed, &ml)?;
            *out = Box::into_raw(Box::new(kp));
            Ok(())
        },
    )
}

/// Generate a fresh key pair from the operating-system random source (or the
/// custom entropy source of a `custom-entropy` build). When
/// `ed25519_seed_out` / `ml_dsa_65_seed_out` are non-NULL, the 32-byte seeds
/// are written there so the caller can persist or export the key; pass NULL to
/// keep them inside the library.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_keypair_generate(
    out: *mut *mut RatifyV2KeyPair,
    ed25519_seed_out: *mut u8,
    ml_dsa_65_seed_out: *mut u8,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            crate::guard::clear_ptr(out);
            crate::guard::clear_bytes(ed25519_seed_out, 32);
            crate::guard::clear_bytes(ml_dsa_65_seed_out, 32);
        },
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            // Generated seeds are wiped on every exit path.
            let mut ed = Zeroizing::new([0u8; 32]);
            let mut ml = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(ed.as_mut())
                .and_then(|_| getrandom::getrandom(ml.as_mut()))
                .map_err(|e| {
                    Failure::new(
                        RatifyV2Code::RatifyV2ErrInternal,
                        format!("random source failed: {e}"),
                    )
                })?;
            let kp = RatifyV2KeyPair::from_seeds(&ed, &ml)?;
            if !ed25519_seed_out.is_null() {
                std::ptr::copy_nonoverlapping(ed.as_ptr(), ed25519_seed_out, 32);
            }
            if !ml_dsa_65_seed_out.is_null() {
                std::ptr::copy_nonoverlapping(ml.as_ptr(), ml_dsa_65_seed_out, 32);
            }
            *out = Box::into_raw(Box::new(kp));
            Ok(())
        },
    )
}

/// Release a key pair. NULL is a no-op. The private key is wiped and dropped
/// from library memory.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_keypair_free(kp: *mut RatifyV2KeyPair) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !kp.is_null() {
                drop(Box::from_raw(kp));
            }
        },
    )
}

/// Write the complete public key of `kp` into `*out`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_keypair_public_key(
    kp: *const RatifyV2KeyPair,
    out: *mut RatifyV2PublicKey,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(kp)],
        || {},
        || RatifyV2PublicKey::write(out, &handle(kp, "keypair")?.public),
    )
}

/// Write the 64-character `key_id_v2` of `kp` plus NUL into `out`
/// (`out_len` >= `RATIFY_V2_KEY_ID_BUF_LEN`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_keypair_key_id(
    kp: *const RatifyV2KeyPair,
    out: *mut c_char,
    out_len: usize,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(kp)],
        || crate::guard::clear_cstr(out, out_len),
        || write_cstr_buf(out, out_len, &handle(kp, "keypair")?.key_id),
    )
}

pub(crate) fn write_cstr_buf(out: *mut c_char, out_len: usize, s: &str) -> AbiResult<()> {
    if out.is_null() {
        return Err(null_arg("out"));
    }
    if out_len < s.len() + 1 {
        return Err(super::bad_arg(format!(
            "out_len {out_len} is too small; need {}",
            s.len() + 1
        )));
    }
    // SAFETY: out has at least out_len writable bytes (caller contract).
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), out as *mut u8, s.len());
        *out.add(s.len()) = 0;
    }
    Ok(())
}

/// Compute `key_id_v2` of a complete public key (SPEC-v2 §2.3) into `out`
/// (`out_len` >= 65).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_public_key_id(
    key: *const RatifyV2PublicKey,
    out: *mut c_char,
    out_len: usize,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_cstr(out, out_len),
        || {
            let key = key.as_ref().ok_or_else(|| null_arg("key"))?;
            let id =
                key_id_v2(&key.as_hybrid()).map_err(|e| e.classify(V2ErrorClass::Malformed))?;
            write_cstr_buf(out, out_len, &id)
        },
    )
}

/// Encode a public key as the wire JSON object
/// `{"ed25519":"<b64>","ml_dsa_65":"<b64>"}` (for request and context JSON).
/// Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_public_key_to_json(
    key: *const RatifyV2PublicKey,
    out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let key = key.as_ref().ok_or_else(|| null_arg("key"))?;
            let text =
                String::from_utf8(to_bytes(&public_key_json(&key.as_hybrid()))).unwrap_or_default();
            write_string(out, &text)
        },
    )
}
