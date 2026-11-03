//! Panic containment and handle poisoning at the FFI boundary.
//!
//! Every exported function and method runs its body through [`call`] (free
//! functions) or [`call_on`] (methods on a handle). A Rust panic is caught
//! here and returned as `FfiError::Internal { kind: "panic" }`; it never
//! reaches UniFFI's own panic path, whose Swift form traps in non-throwing
//! functions. A panic inside a method also poisons that handle: every later
//! call on it returns `Internal { kind: "poisoned" }` (the C ABI rule).
//!
//! Every export is fallible (`FfiResult`), so the generated Swift never uses
//! `try!` and the generated Kotlin always routes failures through the
//! hand-written error mapper.
//!
//! The `test-hooks` feature compiles a one-shot panic injection point into
//! every guarded body, armed by the plain C symbol
//! `ratify_ffi_test_arm_panic` (not a UniFFI export, so the generated
//! bindings are identical with and without the feature). Never enable it in
//! a shipped build.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{FfiError, FfiResult};

/// Whether a panic left a handle unusable.
#[derive(Default)]
pub(crate) struct Poison(AtomicBool);

pub(crate) const PANIC_MESSAGE: &str = "a panic was caught at the FFI boundary";

fn contained<T>(body: impl FnOnce() -> FfiResult<T>) -> Result<FfiResult<T>, ()> {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(feature = "test-hooks")]
        test_hooks::fire();
        body()
    }));
    match outcome {
        Ok(r) => Ok(r),
        Err(payload) => {
            // Dropping the payload can itself panic; never let that unwind.
            if let Err(again) = catch_unwind(AssertUnwindSafe(move || drop(payload))) {
                std::mem::forget(again);
            }
            Err(())
        }
    }
}

impl Poison {
    pub(crate) fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub(crate) fn poisoned() -> FfiError {
    FfiError::Internal {
        kind: "poisoned".into(),
        detail: "this handle is unusable after a panic".into(),
    }
}

fn panicked() -> FfiError {
    FfiError::Internal {
        kind: "panic".into(),
        detail: PANIC_MESSAGE.into(),
    }
}

/// Guard a free function.
pub(crate) fn call<T>(body: impl FnOnce() -> FfiResult<T>) -> FfiResult<T> {
    contained(body).unwrap_or_else(|()| Err(panicked()))
}

/// Guard a method on a handle: refuse a poisoned handle, and poison it when
/// its body panics.
pub(crate) fn call_on<T>(poison: &Poison, body: impl FnOnce() -> FfiResult<T>) -> FfiResult<T> {
    if poison.0.load(Ordering::SeqCst) {
        return Err(FfiError::Internal {
            kind: "poisoned".into(),
            detail: "this handle is unusable after a panic".into(),
        });
    }
    contained(body).unwrap_or_else(|()| {
        poison.0.store(true, Ordering::SeqCst);
        Err(panicked())
    })
}

/// Guard a free function that receives SDK key handles: refuse it if any of
/// them is poisoned, and poison every one of them when its body panics.
pub(crate) fn call_with<T>(
    handles: &[&Poison],
    body: impl FnOnce() -> FfiResult<T>,
) -> FfiResult<T> {
    if handles.iter().any(|p| p.is_set()) {
        return Err(poisoned());
    }
    contained(body).unwrap_or_else(|()| {
        for p in handles {
            p.0.store(true, Ordering::SeqCst);
        }
        Err(panicked())
    })
}

#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::sync::atomic::{AtomicBool, Ordering};

    static ARMED: AtomicBool = AtomicBool::new(false);

    /// Make the next guarded call panic inside its guard (test builds only).
    #[no_mangle]
    pub extern "C" fn ratify_ffi_test_arm_panic() {
        ARMED.store(true, Ordering::SeqCst);
    }

    /// An emulated external signing provider (test builds only): signs `M`
    /// with Ed25519 and `M` with ML-DSA-65 under `ctx` (direct mode), from
    /// the two 32-byte seeds, the way an HSM or KMS outside the SDK would.
    /// Writes 64 + 3309 bytes and returns 0, or returns -1.
    ///
    /// # Safety
    /// Pointers must be valid for the stated lengths.
    #[no_mangle]
    pub unsafe extern "C" fn ratify_ffi_test_provider_sign(
        ed_seed: *const u8,
        ml_seed: *const u8,
        msg: *const u8,
        msg_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        out_ed: *mut u8,
        out_ml: *mut u8,
    ) -> i32 {
        use ed25519_dalek::Signer as _;
        use fips204::traits::{SerDes, Signer as _};
        let r = std::panic::catch_unwind(|| {
            let ed: [u8; 32] = std::slice::from_raw_parts(ed_seed, 32).try_into().ok()?;
            let ml: [u8; 32] = std::slice::from_raw_parts(ml_seed, 32).try_into().ok()?;
            let m = std::slice::from_raw_parts(msg, msg_len);
            let c = std::slice::from_raw_parts(ctx, ctx_len);
            let (_, private) = ratify_protocol::hybrid_keypair_from_seeds(&ed, &ml);
            let es = ed25519_dalek::SigningKey::from_bytes(&ed)
                .sign(m)
                .to_bytes();
            let sk: [u8; fips204::ml_dsa_65::SK_LEN] = private.ml_dsa_65().try_into().ok()?;
            let ms = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk)
                .ok()?
                .try_sign(m, c)
                .ok()?;
            std::ptr::copy_nonoverlapping(es.as_ptr(), out_ed, 64);
            std::ptr::copy_nonoverlapping(ms.as_ptr(), out_ml, ms.len());
            Some(())
        });
        if matches!(r, Ok(Some(()))) {
            0
        } else {
            -1
        }
    }

    pub(super) fn fire() {
        if ARMED.swap(false, Ordering::SeqCst) {
            panic!("injected test panic");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_becomes_internal_and_poisons_only_its_handle() {
        let p = Poison::default();
        let r: FfiResult<()> = call_on(&p, || panic!("boom"));
        assert!(matches!(r, Err(FfiError::Internal { ref kind, .. }) if kind == "panic"));
        let again: FfiResult<i32> = call_on(&p, || Ok(1));
        assert!(matches!(again, Err(FfiError::Internal { ref kind, .. }) if kind == "poisoned"));
        let other = Poison::default();
        assert_eq!(call_on(&other, || Ok(2)).ok(), Some(2));
        let (a, b) = (Poison::default(), Poison::default());
        let r: FfiResult<()> = call_with(&[&a, &b], || panic!("boom"));
        assert!(matches!(r, Err(FfiError::Internal { ref kind, .. }) if kind == "panic"));
        assert!(
            a.is_set() && b.is_set(),
            "every participating handle is poisoned"
        );
        let refused: FfiResult<i32> = call_with(&[&Poison::default(), &a], || Ok(1));
        assert!(matches!(refused, Err(FfiError::Internal { ref kind, .. }) if kind == "poisoned"));
        let free: FfiResult<()> = call(|| panic!("boom"));
        assert!(matches!(free, Err(FfiError::Internal { ref kind, .. }) if kind == "panic"));
        assert_eq!(call(|| Ok(3)).ok(), Some(3));
    }
}
