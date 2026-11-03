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

#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::sync::atomic::{AtomicBool, Ordering};

    static ARMED: AtomicBool = AtomicBool::new(false);

    /// Make the next guarded call panic inside its guard (test builds only).
    #[no_mangle]
    pub extern "C" fn ratify_ffi_test_arm_panic() {
        ARMED.store(true, Ordering::SeqCst);
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
        let free: FfiResult<()> = call(|| panic!("boom"));
        assert!(matches!(free, Err(FfiError::Internal { ref kind, .. }) if kind == "panic"));
        assert_eq!(call(|| Ok(3)).ok(), Some(3));
    }
}
