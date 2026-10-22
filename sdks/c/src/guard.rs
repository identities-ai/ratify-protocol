//! Panic containment at the C ABI boundary.
//!
//! Every exported `extern "C"` function runs its body through one of the
//! guards below, so a Rust panic is caught before it reaches the caller. A
//! caught panic returns the function's documented internal-error value
//! (`RatifyErrInternal`, `RatifyV2ErrInternal`, NULL, or a fail-closed
//! integer), writes a diagnostic to `err_out` when the function has one, and
//! first resets every output parameter to a defined state (NULL handle,
//! zeroed fixed-size buffer, empty string, zero flag) so a caller never sees
//! output that was partly written before the panic.
//!
//! `tests/panic_containment.rs` checks that every exported function goes
//! through one of these guards; a new export that skips them fails that test.
//!
//! ## Unwind safety
//!
//! The guards wrap bodies in `AssertUnwindSafe`. That is sound here because a
//! guarded body's only state that outlives a caught panic is:
//!
//! - output parameters, which the panic path resets before returning;
//! - caller-owned handles, which every export reads through `*const` except
//!   the `*_free` functions (which consume the handle) and the challenge
//!   store, whose records sit behind a `Mutex`: a panic while it is held
//!   poisons the lock, so later calls on that store fail closed with the
//!   internal-error status rather than observing a half-updated record set.
//!
//! The library holds no other mutable global state (the optional
//! custom-entropy callback is a single atomic store).

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{set_err, RatifyStatus};

/// Diagnostic written to `err_out` when a panic is caught.
pub(crate) const PANIC_MESSAGE: &str = "internal error: a panic was caught at the C ABI boundary";

/// Run `body`, converting a panic into `on_panic()`. Nothing unwinds out of
/// this function: the panic payload is dropped under its own `catch_unwind`
/// and leaked if dropping it panics again.
pub(crate) fn ffi_guard<R>(on_panic: impl FnOnce() -> R, body: impl FnOnce() -> R) -> R {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(feature = "panic-test-hook")]
        test_hook::fire(test_hook::BEFORE_BODY);
        let r = body();
        #[cfg(feature = "panic-test-hook")]
        test_hook::fire(test_hook::AFTER_BODY);
        r
    }));
    match outcome {
        Ok(r) => r,
        Err(payload) => {
            if let Err(again) = catch_unwind(AssertUnwindSafe(move || drop(payload))) {
                std::mem::forget(again);
            }
            on_panic()
        }
    }
}

/// Guard for functions returning `RatifyStatus`: a panic runs `reset`, writes
/// the diagnostic, and returns `RatifyErrInternal`.
pub(crate) fn guard_status(
    err_out: *mut *mut c_char,
    reset: impl FnOnce(),
    body: impl FnOnce() -> RatifyStatus,
) -> RatifyStatus {
    ffi_guard(
        || {
            reset();
            set_err(err_out, PANIC_MESSAGE);
            RatifyStatus::RatifyErrInternal
        },
        body,
    )
}

/// Guard for functions returning an owned pointer: a panic returns NULL and
/// writes the diagnostic when `err_out` is non-NULL (pass NULL when the
/// function has no `err_out`).
pub(crate) fn guard_ptr<T>(err_out: *mut *mut c_char, body: impl FnOnce() -> *mut T) -> *mut T {
    ffi_guard(
        || {
            set_err(err_out, PANIC_MESSAGE);
            std::ptr::null_mut()
        },
        body,
    )
}

/// Set a handle or string output to NULL. No-op when `out` is NULL.
pub(crate) unsafe fn clear_ptr<T>(out: *mut *mut T) {
    if !out.is_null() {
        *out = std::ptr::null_mut();
    }
}

/// Set a scalar output (validity flag, timestamp) to zero. No-op when NULL.
pub(crate) unsafe fn clear_val<T: Default>(out: *mut T) {
    if !out.is_null() {
        *out = T::default();
    }
}

/// Zero `len` bytes of a caller buffer. No-op when `out` is NULL.
pub(crate) unsafe fn clear_bytes(out: *mut u8, len: usize) {
    if !out.is_null() {
        std::ptr::write_bytes(out, 0, len);
    }
}

/// Make a caller string buffer the empty string. No-op when `out` is NULL or
/// its capacity is zero.
pub(crate) unsafe fn clear_cstr(out: *mut c_char, cap: usize) {
    if !out.is_null() && cap > 0 {
        *out = 0;
    }
}

/// Test-only panic injection, compiled only with the `panic-test-hook`
/// feature (never in a release build). Arms a one-shot panic on the current
/// thread either before the guarded body runs or after it has returned (that
/// is, after it has written its outputs), so tests can check the panic path
/// of a real export.
#[cfg(feature = "panic-test-hook")]
pub mod test_hook {
    use std::cell::Cell;

    pub(crate) const BEFORE_BODY: u8 = 1;
    pub(crate) const AFTER_BODY: u8 = 2;

    thread_local! {
        static ARMED: Cell<u8> = const { Cell::new(0) };
    }

    /// Panic at the start of the next guarded export called on this thread.
    pub fn arm_before_body() {
        ARMED.with(|a| a.set(BEFORE_BODY));
    }

    /// Panic in the next guarded export called on this thread after its body
    /// has returned, that is, after it has written its outputs.
    pub fn arm_after_body() {
        ARMED.with(|a| a.set(AFTER_BODY));
    }

    pub(crate) fn fire(point: u8) {
        if ARMED.with(|a| a.get()) == point {
            ARMED.with(|a| a.set(0));
            panic!("ratify panic-test-hook: injected panic");
        }
    }
}
