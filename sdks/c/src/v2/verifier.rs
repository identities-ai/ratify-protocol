//! The stateful live verifier (SPEC-v2 §6), the claim stage, the committed
//! outcome and release (§6.9), lease-expiry recovery (§7.5), challenge
//! issuance (§7.3), and composed transaction-receipt verification (§5.7).

use std::os::raw::c_char;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use ratify_protocol::v2::*;

use super::callbacks::*;
use super::marshal::{
    claim_json, expected_challenge_json, issue_request, status_keys, status_policy, to_bytes,
    transaction_result_json, verify_request, Obj,
};
use super::{
    bytes, class_code, clear_buffer, cstr, flag, handle, json_bytes, null_arg, poisonable, run,
    run_h, run_value, set_success_note, write_buffer, write_opt_buffer, write_opt_val,
    write_string, write_val, AbiResult, RatifyV2Buffer, RatifyV2PublicKey, RatifyV2Slice,
};

/// Where a verification stopped (SPEC-v2 §2.7).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2Stage {
    RatifyV2StageNone = 0,
    /// A pre-claim failure; nothing was consumed.
    RatifyV2StagePreflight = 1,
    /// The claim already existed; the result is not disclosed.
    RatifyV2StageReplay = 2,
    /// The claim exists and nothing was committed.
    RatifyV2StageEvaluating = 3,
    /// A terminal result was committed; it is NOT actionable.
    RatifyV2StageCommitted = 4,
}

/// The result of `ratify_v2_verify_proof_bundle`. It deliberately carries no
/// decision. `error_code` is the class of a preflight or evaluating outcome
/// (0 otherwise); `disposition` is a `RatifyV2Disposition` (0 for preflight).
#[repr(C)]
pub struct RatifyV2VerifyOutcome {
    pub stage: i32,
    pub error_code: i32,
    pub disposition: i32,
}

/// The opaque, non-actionable committed outcome: the handoff from a
/// committed verification to publication and `ratify_v2_release_decision`.
/// Only the library creates it; release it with `ratify_v2_committed_free`.
pub struct RatifyV2Committed {
    pub(crate) poisoned: AtomicBool,
    pub(crate) inner: CommittedV2Outcome,
}

/// The opaque released decision (SPEC-v2 §6.9): the only actionable value of
/// this ABI. `ratify_v2_release_decision` is its only constructor; every
/// accessor returns a copy. Gate a side effect only on
/// `ratify_v2_released_allowed`. Release it with `ratify_v2_released_free`.
pub struct RatifyV2Released {
    pub(crate) poisoned: AtomicBool,
    pub(crate) inner: Arc<V2ReleasedDecision>,
}

poisonable!(RatifyV2Committed, RatifyV2Released);

fn disposition_code(d: Option<V2ClaimDisposition>) -> i32 {
    (match d {
        None => RatifyV2Disposition::RatifyV2DispositionNone,
        Some(V2ClaimDisposition::Created) => RatifyV2Disposition::RatifyV2DispositionCreated,
        Some(V2ClaimDisposition::InProgress) => RatifyV2Disposition::RatifyV2DispositionInProgress,
        Some(V2ClaimDisposition::TerminalReplay) => {
            RatifyV2Disposition::RatifyV2DispositionTerminalReplay
        }
    }) as i32
}

fn stage_code(s: V2VerifyStage) -> i32 {
    (match s {
        V2VerifyStage::Preflight => RatifyV2Stage::RatifyV2StagePreflight,
        V2VerifyStage::Replay => RatifyV2Stage::RatifyV2StageReplay,
        V2VerifyStage::Evaluating => RatifyV2Stage::RatifyV2StageEvaluating,
        V2VerifyStage::Committed => RatifyV2Stage::RatifyV2StageCommitted,
    }) as i32
}

unsafe fn request(ptr: *const u8, len: usize) -> AbiResult<V2VerifyRequest> {
    let v = json_bytes(ptr, len, "request_json")?;
    Ok(verify_request(&v)??)
}

/// Run the live v2 decision path (SPEC-v2 §6) in the specified order.
///
/// - `bundle`: the proof bundle wire bytes.
/// - `request_json`: `{"required_scope", "verifier_namespace",
///   "replay_epoch", "now", "max_challenge_age_seconds",
///   "future_skew_seconds", "tzdb_version", "status_keys": {"<issuer>":
///   {"epoch", "public_key"}}, "status_policy": {...}, "expected_challenge":
///   {...}|null, "context_policy": {...}|null, "context": {...}}`. `now` is
///   used only for the pre-claim freshness check; every post-claim time
///   comes from the claim store's clock. A null `context_policy` means none
///   is configured, so the result can never be allow.
/// - `evaluators`: the extension evaluator registry, or NULL for none.
/// - `callbacks`: the providers and stores (`claim_store` is required).
///
/// Returns 0 when the verification ran: `*outcome` then says where it
/// stopped, and the last-error message carries the diagnostic of a
/// preflight or evaluating outcome. A committed outcome is written to
/// `*committed_out` (NULL otherwise); it is not an authorization. When
/// `claim_record_out` is non-NULL the claim record (the
/// `RatifyV2ClaimView.record` encoding) is written there whenever a claim
/// exists. A malformed request or evaluator registry fails the call itself
/// (`bad_argument` or its class) without running the verifier. A callback
/// returning `RatifyV2ErrCancelled` after the claim yields
/// `evaluation_cancelled` and commits nothing; the receiver-binding hook
/// returning it cancels before the claim, so the outcome is a preflight
/// `evaluation_cancelled` and nothing is consumed (SPEC-v2 §6.11).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verify_proof_bundle(
    bundle: *const u8,
    bundle_len: usize,
    request_json: *const u8,
    request_json_len: usize,
    evaluators: *const RatifyV2EvaluatorConfig,
    callbacks: *const RatifyV2VerifyCallbacks,
    outcome: *mut RatifyV2VerifyOutcome,
    claim_record_out: *mut RatifyV2Buffer,
    committed_out: *mut *mut RatifyV2Committed,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            if !outcome.is_null() {
                *outcome = RatifyV2VerifyOutcome {
                    stage: 0,
                    error_code: 0,
                    disposition: 0,
                };
            }
            clear_buffer(claim_record_out);
            crate::guard::clear_ptr(committed_out);
        },
        || {
            if outcome.is_null() {
                return Err(null_arg("outcome"));
            }
            if committed_out.is_null() {
                return Err(null_arg("committed_out"));
            }
            *committed_out = std::ptr::null_mut();
            clear_buffer(claim_record_out);
            let mut req = request(request_json, request_json_len)?;
            req.bundle = bytes(bundle, bundle_len, "bundle")?.to_vec();
            req.constraint_evaluators = evaluator_registry(evaluators)?;
            let (ctx, cancel) = V2Context::background().with_cancel();
            let deps = build_callbacks(callbacks, &Cancel(cancel));
            let mut result = verify_proof_bundle_v2(&ctx, &req, &deps.callbacks);
            // The receiver-binding hook is the only callback before the
            // claim; its cancellation is the caller's cancellation there.
            if result.stage == V2VerifyStage::Preflight
                && result.error_class == Some(V2ErrorClass::ReceiverBindingRejected)
                && ctx.is_done()
            {
                let e = V2Error::new(
                    V2ErrorClass::EvaluationCancelled,
                    "v2 verification cancelled before the claim: context done",
                );
                result.error_class = Some(e.class);
                result.error = Some(e);
            }
            *outcome = RatifyV2VerifyOutcome {
                stage: stage_code(result.stage),
                error_code: result.error_class.map_or(0, |c| class_code(c) as i32),
                disposition: disposition_code(result.disposition),
            };
            if let Some(e) = &result.error {
                set_success_note(&format!("{}: {}", e.class, e.message));
            }
            if !result.claim.claim_id.is_empty() {
                write_opt_buffer(claim_record_out, claim_json(&result.claim))?;
            }
            if let Some(c) = result.committed {
                *committed_out = Box::into_raw(Box::new(RatifyV2Committed {
                    poisoned: AtomicBool::new(false),
                    inner: c,
                }));
            }
            Ok(())
        },
    )
}

/// The claim stage alone: pre-claim checks (`request_json` as for
/// `ratify_v2_verify_proof_bundle`; a context policy is required) then the
/// atomic claim at `now`. The evaluator capability is never exposed, so a
/// created claim stays in progress until lease-expiry recovery. Returns 0
/// with `*disposition_out` and the claim ID, or the failure class.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_claim_proof_bundle(
    bundle: *const u8,
    bundle_len: usize,
    request_json: *const u8,
    request_json_len: usize,
    claim_store: *const RatifyV2ClaimStoreCallbacks,
    disposition_out: *mut i32,
    claim_id_out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            crate::guard::clear_val(disposition_out);
            crate::guard::clear_ptr(claim_id_out);
        },
        || {
            let cb = claim_store
                .as_ref()
                .ok_or_else(|| null_arg("claim_store"))?;
            let req = request(request_json, request_json_len)?;
            let b = decode_proof_bundle_v2(bytes(bundle, bundle_len, "bundle")?)?;
            let pre = preflight_proof_bundle_v2(
                &b,
                req.expected.as_ref(),
                req.context_policy.as_ref(),
                &req.required_scope,
                &req.verifier_namespace,
                req.replay_epoch,
                req.now,
                req.max_challenge_age_seconds,
                req.future_skew_seconds,
            )?;
            let (ctx, cancel) = V2Context::background().with_cancel();
            let store = CClaimStore {
                cb: *cb,
                cancel: Cancel(cancel),
            };
            let (claim, disposition, _token) = claim_proof_bundle_v2(
                &ctx,
                &store,
                &b,
                &pre,
                &req.verifier_namespace,
                req.replay_epoch,
                req.now,
            )?;
            write_val(disposition_out, disposition_code(Some(disposition)))?;
            write_string(claim_id_out, &claim.claim_id)
        },
    )
}

/// Lease-expiry recovery (SPEC-v2 §7.5): load an interrupted claim after its
/// lease expired and commit the canonical `indeterminate /
/// evaluation_interrupted` result built from its recorded progress. On
/// success `*committed_out` is the committed outcome.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_recover_interrupted_claim(
    claim_store: *const RatifyV2ClaimStoreCallbacks,
    claim_id: *const c_char,
    committed_out: *mut *mut RatifyV2Committed,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(committed_out),
        || {
            let cb = claim_store
                .as_ref()
                .ok_or_else(|| null_arg("claim_store"))?;
            if committed_out.is_null() {
                return Err(null_arg("committed_out"));
            }
            let (ctx, cancel) = V2Context::background().with_cancel();
            let store = CClaimStore {
                cb: *cb,
                cancel: Cancel(cancel),
            };
            let c = recover_interrupted_claim_v2(&ctx, &store, cstr(claim_id, "claim_id")?)?;
            *committed_out = Box::into_raw(Box::new(RatifyV2Committed {
                poisoned: AtomicBool::new(false),
                inner: c,
            }));
            Ok(())
        },
    )
}

/// Release a committed outcome. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_committed_free(c: *mut RatifyV2Committed) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !c.is_null() {
                drop(Box::from_raw(c));
            }
        },
    )
}

/// The claim ID of a committed outcome (free with `ratify_v2_string_free`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_committed_claim_id(
    c: *const RatifyV2Committed,
    out: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(c)],
        || crate::guard::clear_ptr(out),
        || write_string(out, &handle(c, "committed")?.inner.claim_id()),
    )
}

/// A copy of the sealed receipt outbox body. It is evidence for publication,
/// not an authorization.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_committed_receipt_body(
    c: *const RatifyV2Committed,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(c)],
        || clear_buffer(out),
        || write_buffer(out, handle(c, "committed")?.inner.receipt_body()),
    )
}

/// `ReceiptOutboxDigest` of the committed body (free with
/// `ratify_v2_string_free`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_committed_receipt_body_digest(
    c: *const RatifyV2Committed,
    out: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(c)],
        || crate::guard::clear_ptr(out),
        || write_string(out, &handle(c, "committed")?.inner.receipt_body_digest()),
    )
}

/// The sealed exclusive challenge deadline.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_committed_challenge_expires_at(
    c: *const RatifyV2Committed,
    out: *mut i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(c)],
        || crate::guard::clear_val(out),
        || write_val(out, handle(c, "committed")?.inner.challenge_expires_at()),
    )
}

/// The sealed exclusive allow horizon: `*has_horizon` is 1 only for an
/// allow; `*horizon` is 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_committed_allow_horizon(
    c: *const RatifyV2Committed,
    has_horizon: *mut i32,
    horizon: *mut i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(c)],
        || {
            crate::guard::clear_val(has_horizon);
            crate::guard::clear_val(horizon);
        },
        || {
            let h = handle(c, "committed")?.inner.allow_horizon();
            write_val(has_horizon, i32::from(h.is_some()))?;
            write_val(horizon, h.unwrap_or(0))
        },
    )
}

/// Release outcome classes (§6.9).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2ReleaseStatus {
    RatifyV2ReleaseNone = 0,
    RatifyV2ReleaseReleased = 1,
    RatifyV2ReleasePending = 2,
    RatifyV2ReleaseWithheld = 3,
    RatifyV2ReleaseRejected = 4,
}

/// Run the release steps of SPEC-v2 §6.9 for a committed outcome.
/// `signed_receipt` is the publisher's signed receipt wire; pass a slice with
/// a NULL `ptr` when it has not been appended yet. `verifier_key` and
/// `log_id` are caller-authenticated configuration. Returns 0 with
/// `*status_out` (a `RatifyV2ReleaseStatus`) and `*reason_out` (empty only
/// when released; free with `ratify_v2_string_free`); `*released_out` is a
/// new released-decision handle exactly when the status is released.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_release_decision(
    committed: *const RatifyV2Committed,
    signed_receipt: RatifyV2Slice,
    verifier_key: *const RatifyV2PublicKey,
    log_id: *const c_char,
    release_store: *const RatifyV2ReleaseStoreCallbacks,
    checkpoint: *const RatifyV2CheckpointCallbacks,
    status_out: *mut i32,
    reason_out: *mut *mut c_char,
    released_out: *mut *mut RatifyV2Released,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(committed)],
        || {
            crate::guard::clear_val(status_out);
            crate::guard::clear_ptr(reason_out);
            crate::guard::clear_ptr(released_out);
        },
        || {
            let c = handle(committed, "committed")?;
            let key = verifier_key
                .as_ref()
                .ok_or_else(|| null_arg("verifier_key"))?
                .as_hybrid();
            let log = cstr(log_id, "log_id")?;
            let store_cb = release_store
                .as_ref()
                .ok_or_else(|| null_arg("release_store"))?;
            let checkpoint_cb = checkpoint.as_ref().ok_or_else(|| null_arg("checkpoint"))?;
            if status_out.is_null() || reason_out.is_null() || released_out.is_null() {
                return Err(null_arg("release outputs"));
            }
            let receipt = if signed_receipt.ptr.is_null() {
                None
            } else {
                Some(signed_receipt.bytes("signed_receipt")?.to_vec())
            };
            let (ctx, cancel) = V2Context::background().with_cancel();
            let cancel = Cancel(cancel);
            let store = CReleaseStore {
                cb: *store_cb,
                cancel: cancel.clone(),
            };
            let cp = CCheckpoint {
                cb: *checkpoint_cb,
                cancel,
            };
            let result = release_v2_decision(
                &ctx,
                &c.inner,
                receipt.as_deref(),
                V2ReleaseConfig {
                    verifier_public_key: &key,
                    log_id: log,
                    claim_store: &store,
                    checkpoint: &cp,
                },
            );
            let status = match result.status {
                V2ReleaseStatus::Released => RatifyV2ReleaseStatus::RatifyV2ReleaseReleased,
                V2ReleaseStatus::Pending => RatifyV2ReleaseStatus::RatifyV2ReleasePending,
                V2ReleaseStatus::Withheld => RatifyV2ReleaseStatus::RatifyV2ReleaseWithheld,
                V2ReleaseStatus::Rejected => RatifyV2ReleaseStatus::RatifyV2ReleaseRejected,
            } as i32;
            write_string(reason_out, &result.reason)?;
            *status_out = status;
            if let Some(d) = result.into_decision() {
                *released_out = Box::into_raw(Box::new(RatifyV2Released {
                    poisoned: AtomicBool::new(false),
                    inner: Arc::new(d),
                }));
            }
            Ok(())
        },
    )
}

/// The spelling of a `RatifyV2ReleaseStatus` ("released", "pending",
/// "withheld", "rejected", or "unknown"). Static — do NOT free.
#[no_mangle]
pub extern "C" fn ratify_v2_release_status_str(status: i32) -> *const c_char {
    crate::guard::ffi_guard(
        || c"unknown".as_ptr(),
        || {
            (match status {
                1 => c"released",
                2 => c"pending",
                3 => c"withheld",
                4 => c"rejected",
                _ => c"unknown",
            })
            .as_ptr()
        },
    )
}

/// Release a released decision. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_released_free(d: *mut RatifyV2Released) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !d.is_null() {
                drop(Box::from_raw(d));
            }
        },
    )
}

/// Which string field `ratify_v2_released_string` returns.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2ReleasedField {
    RatifyV2ReleasedClaimId = 1,
    /// "allow", "deny", or "indeterminate". Never gate a side effect on it;
    /// use `ratify_v2_released_allowed`.
    RatifyV2ReleasedDecision = 2,
    RatifyV2ReleasedReason = 3,
    RatifyV2ReleasedIdentityStatus = 4,
}

/// A copy of a released decision's string field (free with
/// `ratify_v2_string_free`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_released_string(
    d: *const RatifyV2Released,
    field: i32,
    out: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || crate::guard::clear_ptr(out),
        || {
            let d = &handle(d, "released")?.inner;
            let value = match field {
                1 => d.claim_id(),
                2 => d.decision(),
                3 => d.reason(),
                4 => d.identity_status(),
                other => {
                    return Err(super::bad_arg(format!(
                        "released field {other} is not defined"
                    )))
                }
            };
            write_string(out, &value)
        },
    )
}

/// A copy of the released granted scope as a JSON array of strings.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_released_granted_scope(
    d: *const RatifyV2Released,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || clear_buffer(out),
        || {
            let scope = handle(d, "released")?.inner.granted_scope();
            write_buffer(out, to_bytes(&serde_json::Value::from(scope)))
        },
    )
}

/// A copy of the signed receipt wire verified during release.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_released_receipt(
    d: *const RatifyV2Released,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || clear_buffer(out),
        || write_buffer(out, handle(d, "released")?.inner.receipt_wire()),
    )
}

/// The release time, the sealed challenge deadline, and the sealed allow
/// horizon (`*has_allow_horizon` is 1 only for an allow). Any output pointer
/// may be NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_released_times(
    d: *const RatifyV2Released,
    release_time: *mut i64,
    challenge_expires_at: *mut i64,
    has_allow_horizon: *mut i32,
    allow_horizon: *mut i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || {
            crate::guard::clear_val(release_time);
            crate::guard::clear_val(challenge_expires_at);
            crate::guard::clear_val(has_allow_horizon);
            crate::guard::clear_val(allow_horizon);
        },
        || {
            let d = &handle(d, "released")?.inner;
            write_opt_val(release_time, d.release_time());
            write_opt_val(challenge_expires_at, d.challenge_expires_at());
            write_opt_val(has_allow_horizon, i32::from(d.allow_horizon().is_some()));
            write_opt_val(allow_horizon, d.allow_horizon().unwrap_or(0));
            Ok(())
        },
    )
}

/// Whether a released allow may be acted on now: 1 only when the released
/// decision is an allow and the receiver's authoritative clock reads before
/// both sealed exclusive deadlines. Any other case, a clock failure, a
/// regression, a NULL argument, a poisoned handle, or a panic is 0
/// (fail-closed). Call it immediately before the side effect.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_released_allowed(
    d: *const RatifyV2Released,
    clock: *const RatifyV2ClockCallbacks,
) -> i32 {
    run_value(&[flag(d)], 0, || {
        let (Some(d), Some(clock)) = (d.as_ref(), clock.as_ref()) else {
            return 0;
        };
        let (ctx, cancel) = V2Context::background().with_cancel();
        let c = CClock {
            cb: *clock,
            cancel: Cancel(cancel),
        };
        i32::from(d.inner.allowed(&ctx, &c))
    })
}

/// Issue a fresh challenge (SPEC-v2 §7.3): validate `request_json`
/// (`{"verifier_namespace", "replay_epoch", "verifier_id",
/// "lifetime_seconds", "expected_agent_id"?, "expected_agent_public_key"?,
/// "expected_receiver_id"?, "expected_session_context_b64"?}`), read the
/// authoritative clock, draw 32 random bytes (from `random` when non-NULL,
/// else the OS), persist the complete record, and only then return it as
/// ExpectedChallenge JSON.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_issue_challenge(
    request_json: *const u8,
    request_json_len: usize,
    clock: *const RatifyV2ClockCallbacks,
    issuance_store: *const RatifyV2IssuanceStoreCallbacks,
    random: *const RatifyV2RandomCallbacks,
    expected_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(expected_out),
        || {
            let req = issue_request(&json_bytes(request_json, request_json_len, "request_json")?)?;
            let clock = clock.as_ref().ok_or_else(|| null_arg("clock"))?;
            let store = issuance_store
                .as_ref()
                .ok_or_else(|| null_arg("issuance_store"))?;
            let (ctx, cancel) = V2Context::background().with_cancel();
            let cancel = Cancel(cancel);
            let issuer = V2ChallengeIssuer {
                clock: Arc::new(CClock {
                    cb: *clock,
                    cancel: cancel.clone(),
                }),
                store: Arc::new(CIssuance { cb: *store, cancel }),
                random: random
                    .as_ref()
                    .map(|r| Arc::new(Mutex::new(CRandom(*r))) as V2RandomSource),
            };
            let expected = issuer.issue_challenge_v2(&ctx, &req)?;
            write_buffer(expected_out, to_bytes(&expected_challenge_json(&expected)))
        },
    )
}

/// Load the authenticated ExpectedChallenge for a presented 32-byte
/// challenge from the issuance store (as ExpectedChallenge JSON).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_load_expected_challenge(
    issuance_store: *const RatifyV2IssuanceStoreCallbacks,
    verifier_namespace: *const c_char,
    replay_epoch: i64,
    challenge: *const u8,
    challenge_len: usize,
    expected_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(expected_out),
        || {
            let store = issuance_store
                .as_ref()
                .ok_or_else(|| null_arg("issuance_store"))?;
            let (ctx, cancel) = V2Context::background().with_cancel();
            let store = CIssuance {
                cb: *store,
                cancel: Cancel(cancel),
            };
            let expected = load_expected_challenge_v2(
                &ctx,
                &store,
                cstr(verifier_namespace, "verifier_namespace")?,
                replay_epoch,
                bytes(challenge, challenge_len, "challenge")?,
            )?;
            write_buffer(expected_out, to_bytes(&expected_challenge_json(&expected)))
        },
    )
}

/// Composed transaction-receipt verification (SPEC-v2 §5.7). `config_json`
/// is `{"status_keys": {...}, "status_policy": {...}}` (the verification
/// request schema). `trust`, `status_evidence`, and `status_journal` may be
/// NULL (unavailable). The result JSON is `{"transaction_id", "actionable":
/// false, "parties": [{"party_id", "agent_id", "required_scope",
/// "trust_assessment", "delegation_assessment", "delegation_expires_at",
/// "status_assessment", "scope_assessment", "freshness",
/// "status_evidence_digests": [...]}]}`; it is evidence, never an
/// authorization.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verify_transaction_receipt(
    receipt: *const u8,
    receipt_len: usize,
    now: i64,
    future_skew_seconds: i64,
    config_json: *const u8,
    config_json_len: usize,
    trust: *const RatifyV2TrustCallbacks,
    status_evidence: *const RatifyV2StatusEvidenceCallbacks,
    status_journal: *const RatifyV2JournalStoreCallbacks,
    result_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(result_out),
        || {
            let config = json_bytes(config_json, config_json_len, "config_json")?;
            let o = Obj::new(&config, "config", &["status_keys", "status_policy"])?;
            let (ctx, cancel) = V2Context::background().with_cancel();
            let cancel = Cancel(cancel);
            let sources = TransactionVerifySourcesV2 {
                trust: trust.as_ref().map(|t| trust_provider(*t, cancel.clone())),
                status_evidence: status_evidence
                    .as_ref()
                    .map(|s| status_provider(*s, cancel.clone())),
                status_journal: status_journal.as_ref().map(|j| {
                    Arc::new(CJournal {
                        cb: *j,
                        cancel: cancel.clone(),
                    }) as Arc<dyn SecurityJournalStoreV2>
                }),
                status_keys: status_keys(o.raw("status_keys"))?,
                status_policy: match o.raw("status_policy") {
                    Some(p) => status_policy(p)?,
                    None => RevocationStatusPolicyV2::default(),
                },
            };
            let result = verify_transaction_receipt_v2(
                &ctx,
                &TransactionVerifyRequestV2 {
                    receipt: bytes(receipt, receipt_len, "receipt")?.to_vec(),
                    now,
                    future_skew_seconds,
                },
                &sources,
            )?;
            write_buffer(result_out, to_bytes(&transaction_result_json(&result)))
        },
    )
}
