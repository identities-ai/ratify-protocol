//! TEST/REFERENCE ONLY (`test-reference` feature): the in-memory reference
//! implementations of the Part B stores and of the single-device offline and
//! dual-root profile components, exported behind the C callback interfaces.
//!
//! Each handle hands out callback structs whose functions forward to the
//! Rust reference implementation, so a conformance runner drives every
//! store and provider through exactly the callback path a C deployment
//! uses. None of this is durable, rollback-resistant, or safe for
//! production; a shipped build never enables the feature.

use std::cell::RefCell;
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use ratify_protocol::v2::reference::*;
use ratify_protocol::v2::*;
use serde_json::Value;

use super::callbacks::*;
use super::keys::RatifyV2KeyPair;
use super::marshal::{
    claim_from_json, claim_json, expected_challenge, expected_challenge_json, progress_from_json,
    progress_json, public_key, to_bytes, Obj,
};
use super::verifier::RatifyV2Released;
use super::{
    bad_arg, bytes, class_code, clear_buffer, cstr, flag, handle, json_bytes, null_arg, poisonable,
    run, run_h, store_failure, write_buffer, write_val, AbiResult, RatifyV2Buffer, RatifyV2Code,
    RatifyV2Slice,
};

// ---------------------------------------------------------------------------
// Bridge plumbing

/// What a bridge forwards to. Each method runs `f` with the target when the
/// bridge serves that interface and returns whether it did.
trait Target: Send + Sync {
    fn claim(&self, _f: &mut dyn FnMut(&dyn ClaimStoreV2)) -> bool {
        false
    }
    fn release(&self, _f: &mut dyn FnMut(&dyn V2ReleaseClaimStore)) -> bool {
        false
    }
    fn checkpoint(&self, _f: &mut dyn FnMut(&dyn V2ReceiptCheckpoint)) -> bool {
        false
    }
    fn clock(&self, _f: &mut dyn FnMut(&dyn V2AuthoritativeClock)) -> bool {
        false
    }
    fn journal(&self, _f: &mut dyn FnMut(&dyn SecurityJournalStoreV2)) -> bool {
        false
    }
    fn issuance(&self, _f: &mut dyn FnMut(&dyn V2ChallengeIssuanceStore)) -> bool {
        false
    }
}

/// The `user` pointer of every reference callback.
struct Bridge {
    target: Box<dyn Target>,
}

thread_local! {
    /// Buffers a reference callback returns: they live until the next
    /// reference callback on this thread, after the adapter copied them.
    static SCRATCH: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

fn scratch_bytes(b: Vec<u8>) -> RatifyV2Slice {
    SCRATCH.with(|s| {
        let mut s = s.borrow_mut();
        s.push(b);
        RatifyV2Slice::of(s.last().map(Vec::as_slice).unwrap_or(&[]))
    })
}

fn scratch_str(text: &str) -> *const c_char {
    let mut b = text.replace('\0', "").into_bytes();
    b.push(0);
    scratch_bytes(b).ptr as *const c_char
}

/// Enter a reference callback: clear the scratch, contain panics.
fn enter(user: *mut c_void, f: impl FnOnce(&Bridge) -> i32) -> i32 {
    SCRATCH.with(|s| s.borrow_mut().clear());
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `user` is the Bridge a reference handle handed out.
        match unsafe { (user as *const Bridge).as_ref() } {
            Some(b) => f(b),
            None => RatifyV2Code::RatifyV2ErrNullPointer as i32,
        }
    }))
    .unwrap_or(RatifyV2Code::RatifyV2ErrInternal as i32)
}

fn ctx() -> V2Context {
    V2Context::background()
}

fn store_code(e: V2StoreError) -> i32 {
    store_failure(e).code as i32
}

fn not_served() -> i32 {
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}

unsafe extern "C" fn br_now(user: *mut c_void, out: *mut i64) -> i32 {
    enter(user, |b| {
        let mut code = not_served();
        b.target.clock(&mut |c| {
            code = match c.authoritative_time_v2(&ctx()) {
                Ok(t) => {
                    if !out.is_null() {
                        *out = t;
                    }
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_claim(
    user: *mut c_void,
    view: *const RatifyV2ClaimView,
    out: *mut RatifyV2ClaimResult,
) -> i32 {
    enter(user, |b| {
        let Some(view) = view.as_ref() else {
            return RatifyV2Code::RatifyV2ErrNullPointer as i32;
        };
        let claim = match claim_from_json(&slice_vec(view.record)) {
            Ok(c) => c,
            Err(_) => return RatifyV2Code::RatifyV2Malformed as i32,
        };
        let mut code = not_served();
        b.target.claim(&mut |s| {
            code = match s.claim_v2(&ctx(), claim.clone()) {
                Ok(r) => {
                    *out = RatifyV2ClaimResult {
                        disposition: match r.disposition {
                            V2ClaimDisposition::Created => 1,
                            V2ClaimDisposition::InProgress => 2,
                            V2ClaimDisposition::TerminalReplay => 3,
                        },
                        claimed_at: r.claimed_at,
                        owner_token: scratch_bytes(r.owner_token),
                    };
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_finalize(
    user: *mut c_void,
    claim_id: *const c_char,
    owner_token: RatifyV2Slice,
    terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    allow_valid_until: i64,
    committed: *mut i32,
) -> i32 {
    enter(user, |b| {
        let id = owned(claim_id);
        let (token, terminal, body) =
            (slice_vec(owner_token), slice_vec(terminal), slice_vec(body));
        let mut code = not_served();
        b.target.claim(&mut |s| {
            code =
                match s.finalize_v2_claim(&ctx(), &id, &token, &terminal, &body, allow_valid_until)
                {
                    Ok(c) => {
                        *committed = i32::from(c);
                        0
                    }
                    Err(e) => store_code(e),
                }
        });
        code
    })
}

unsafe extern "C" fn br_progress(
    user: *mut c_void,
    claim_id: *const c_char,
    owner_token: RatifyV2Slice,
    progress: RatifyV2Slice,
) -> i32 {
    enter(user, |b| {
        let id = owned(claim_id);
        let token = slice_vec(owner_token);
        let progress = match progress_from_json(&slice_vec(progress)) {
            Ok(p) => p,
            Err(_) => return RatifyV2Code::RatifyV2Malformed as i32,
        };
        let mut code = not_served();
        b.target.claim(&mut |s| {
            code = match s.record_v2_evaluation_progress(&ctx(), &id, &token, progress.clone()) {
                Ok(()) => 0,
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_load_interrupted(
    user: *mut c_void,
    claim_id: *const c_char,
    out: *mut RatifyV2InterruptedClaim,
) -> i32 {
    enter(user, |b| {
        let id = owned(claim_id);
        let mut code = not_served();
        b.target.claim(&mut |s| {
            code = match s.load_v2_interrupted_claim(&ctx(), &id) {
                Ok(c) => {
                    *out = RatifyV2InterruptedClaim {
                        record: scratch_bytes(claim_json(&c.claim)),
                        claimed_at: c.claimed_at,
                        progress: scratch_bytes(progress_json(&c.progress)),
                    };
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_recover(
    user: *mut c_void,
    claim_id: *const c_char,
    terminal: RatifyV2Slice,
    body: RatifyV2Slice,
    committed: *mut i32,
) -> i32 {
    enter(user, |b| {
        let id = owned(claim_id);
        let (terminal, body) = (slice_vec(terminal), slice_vec(body));
        let mut code = not_served();
        b.target.claim(&mut |s| {
            code = match s.recover_interrupted_v2_claim(&ctx(), &id, &terminal, &body) {
                Ok(c) => {
                    *committed = i32::from(c);
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_reserve(
    _user: *mut c_void,
    _claim_id: *const c_char,
    _owner_token: RatifyV2Slice,
    _bundle_hash: *const c_char,
    _batch: *const RatifyV2RateReservation,
    _len: usize,
) -> i32 {
    // The reference store admits rate only at finalization.
    RatifyV2Code::RatifyV2StoreUnavailable as i32
}

unsafe extern "C" fn br_load_terminal(
    user: *mut c_void,
    claim_id: *const c_char,
    out: *mut RatifyV2TerminalClaim,
) -> i32 {
    enter(user, |b| {
        let id = owned(claim_id);
        let mut code = not_served();
        b.target.release(&mut |s| {
            code = match s.load_v2_terminal_claim(&ctx(), &id) {
                Ok(r) => {
                    let release = r.release.clone().unwrap_or_default();
                    *out = RatifyV2TerminalClaim {
                        terminal: i32::from(r.terminal),
                        receipt_outbox_digest: scratch_str(&r.receipt_outbox_digest),
                        challenge_expires_at: r.challenge_expires_at,
                        allow_horizon: r.allow_horizon,
                        finalized_at: r.finalized_at,
                        receipt_abandoned: i32::from(r.receipt_abandoned),
                        has_release: i32::from(r.release.is_some()),
                        release_claim_id: scratch_str(&release.claim_id),
                        release_entry_hash: scratch_bytes(release.entry_hash),
                        release_ack_timestamp: release.ack_timestamp,
                    };
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_record_release(
    user: *mut c_void,
    record: *const RatifyV2ReleaseRecord,
) -> i32 {
    enter(user, |b| {
        let Some(r) = record.as_ref() else {
            return RatifyV2Code::RatifyV2ErrNullPointer as i32;
        };
        let rec = V2ReleaseRecord {
            claim_id: owned(r.claim_id),
            entry_hash: slice_vec(r.entry_hash),
            ack_timestamp: r.ack_timestamp,
        };
        let mut code = not_served();
        b.target.release(&mut |s| {
            code = match s.record_v2_release(&ctx(), rec.clone()) {
                Ok(()) => 0,
                Err(e) => store_code(e),
            }
        });
        code
    })
}

fn write_ack(out: *mut RatifyV2Acknowledgement, a: V2CheckpointAcknowledgement) {
    // SAFETY: out is the adapter's output struct.
    unsafe {
        *out = RatifyV2Acknowledgement {
            log_id: scratch_str(&a.log_id),
            sequence: a.sequence,
            entry_hash: scratch_bytes(a.entry_hash),
            timestamp: a.timestamp,
        }
    };
}

unsafe extern "C" fn br_acknowledge(
    user: *mut c_void,
    log_id: *const c_char,
    sequence: i64,
    previous: RatifyV2Slice,
    entry: RatifyV2Slice,
    out: *mut RatifyV2Acknowledgement,
) -> i32 {
    enter(user, |b| {
        let log = owned(log_id);
        let (previous, entry) = (slice_vec(previous), slice_vec(entry));
        let mut code = not_served();
        b.target.checkpoint(&mut |c| {
            code = match c.acknowledge_v2_receipt(&ctx(), &log, sequence, &previous, &entry) {
                Ok(a) => {
                    write_ack(out, a);
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_get_ack(
    user: *mut c_void,
    log_id: *const c_char,
    sequence: i64,
    out: *mut RatifyV2Acknowledgement,
) -> i32 {
    enter(user, |b| {
        let log = owned(log_id);
        let mut code = not_served();
        b.target.checkpoint(&mut |c| {
            code = match c.get_v2_acknowledgement(&ctx(), &log, sequence) {
                Ok(a) => {
                    write_ack(out, a);
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_journal_load(user: *mut c_void, out: *mut RatifyV2JournalSnapshot) -> i32 {
    enter(user, |b| {
        let mut code = not_served();
        b.target.journal(&mut |j| {
            code = match j.load(&ctx()).and_then(|(journal, head)| {
                Ok((export_security_journal_snapshot_v2(&journal)?, head))
            }) {
                Ok((snapshot, head)) => {
                    *out = RatifyV2JournalSnapshot {
                        snapshot: scratch_bytes(snapshot),
                        generation: head.generation,
                        digest: scratch_str(&head.digest),
                    };
                    0
                }
                Err(e) => class_code(e.class) as i32,
            }
        });
        code
    })
}

unsafe extern "C" fn br_journal_cas(
    user: *mut c_void,
    expected_generation: u64,
    expected_digest: *const c_char,
    next: *const RatifyV2JournalSnapshot,
) -> i32 {
    enter(user, |b| {
        let Some(next) = next.as_ref() else {
            return RatifyV2Code::RatifyV2ErrNullPointer as i32;
        };
        let expected = SecurityJournalHeadV2 {
            generation: expected_generation,
            digest: owned(expected_digest),
        };
        let head = SecurityJournalHeadV2 {
            generation: next.generation,
            digest: owned(next.digest),
        };
        let journal = match import_security_journal_snapshot_v2(&slice_vec(next.snapshot), &head) {
            Ok(j) => j,
            Err(e) => return class_code(e.class) as i32,
        };
        let mut code = not_served();
        b.target.journal(&mut |j| {
            code = match j.compare_and_swap(&ctx(), &expected, &journal) {
                Ok(()) => 0,
                Err(SecurityJournalStoreErrorV2::Conflict) => {
                    RatifyV2Code::RatifyV2StoreJournalConflict as i32
                }
                Err(SecurityJournalStoreErrorV2::Failed(e)) => class_code(e.class) as i32,
            }
        });
        code
    })
}

unsafe extern "C" fn br_issuance_persist(
    user: *mut c_void,
    _namespace: *const c_char,
    _epoch: i64,
    _digest: RatifyV2Slice,
    record: RatifyV2Slice,
) -> i32 {
    enter(user, |b| {
        let rec = match super::strict_json(&slice_vec(record))
            .ok()
            .and_then(|v| expected_challenge(&v).ok())
        {
            Some(r) => r,
            None => return RatifyV2Code::RatifyV2Malformed as i32,
        };
        let mut code = not_served();
        b.target.issuance(&mut |s| {
            code = match s.persist_v2_challenge(&ctx(), rec.clone()) {
                Ok(()) => 0,
                Err(e) => store_code(e),
            }
        });
        code
    })
}

unsafe extern "C" fn br_issuance_load(
    user: *mut c_void,
    namespace: *const c_char,
    epoch: i64,
    digest: RatifyV2Slice,
    out: *mut RatifyV2Slice,
) -> i32 {
    enter(user, |b| {
        let ns = owned(namespace);
        let digest = slice_vec(digest);
        let mut code = not_served();
        b.target.issuance(&mut |s| {
            code = match s.load_v2_challenge(&ctx(), &ns, epoch, &digest) {
                Ok(r) => {
                    *out = scratch_bytes(to_bytes(&expected_challenge_json(&r)));
                    0
                }
                Err(e) => store_code(e),
            }
        });
        code
    })
}

fn bridge_ptr(b: &Bridge) -> *mut c_void {
    b as *const Bridge as *mut c_void
}

fn claim_callbacks(b: &Bridge, rate_at_finalization: bool) -> RatifyV2ClaimStoreCallbacks {
    RatifyV2ClaimStoreCallbacks {
        user: bridge_ptr(b),
        rate_at_finalization: i32::from(rate_at_finalization),
        now: Some(br_now),
        claim: Some(br_claim),
        finalize: Some(br_finalize),
        record_progress: Some(br_progress),
        load_interrupted: Some(br_load_interrupted),
        recover: Some(br_recover),
    }
}

fn journal_callbacks(b: &Bridge) -> RatifyV2JournalStoreCallbacks {
    RatifyV2JournalStoreCallbacks {
        user: bridge_ptr(b),
        load: Some(br_journal_load),
        compare_and_swap: Some(br_journal_cas),
    }
}

fn checkpoint_callbacks(b: &Bridge) -> RatifyV2CheckpointCallbacks {
    RatifyV2CheckpointCallbacks {
        user: bridge_ptr(b),
        acknowledge: Some(br_acknowledge),
        get: Some(br_get_ack),
    }
}

// ---------------------------------------------------------------------------
// Reference Part B store

struct StoreTarget(Arc<Store>);

impl Target for StoreTarget {
    fn claim(&self, f: &mut dyn FnMut(&dyn ClaimStoreV2)) -> bool {
        f(self.0.as_ref());
        true
    }
    fn release(&self, f: &mut dyn FnMut(&dyn V2ReleaseClaimStore)) -> bool {
        f(self.0.as_ref());
        true
    }
    fn checkpoint(&self, f: &mut dyn FnMut(&dyn V2ReceiptCheckpoint)) -> bool {
        f(self.0.as_ref());
        true
    }
    fn clock(&self, f: &mut dyn FnMut(&dyn V2AuthoritativeClock)) -> bool {
        f(self.0.as_ref());
        true
    }
}

/// TEST ONLY: the in-memory reference Part B store (claim store with stream
/// sequence and progress, authoritative clock, receipt outbox and publisher,
/// checkpoint). The handle must outlive every callback struct taken from it.
pub struct RatifyV2RefStore {
    pub(crate) poisoned: AtomicBool,
    store: Arc<Store>,
    bridge: Box<Bridge>,
}

poisonable!(RatifyV2RefStore);

fn ref_store(store: Arc<Store>) -> *mut RatifyV2RefStore {
    Box::into_raw(Box::new(RatifyV2RefStore {
        poisoned: AtomicBool::new(false),
        bridge: Box::new(Bridge {
            target: Box::new(StoreTarget(Arc::clone(&store))),
        }),
        store,
    }))
}

/// TEST ONLY: a new reference store at time `now` with evaluator leases of
/// `lease_seconds`, receipt log `log_id` (32 hex), signing receipts with
/// `verifier_key`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_new(
    now: i64,
    lease_seconds: i64,
    log_id: *const c_char,
    verifier_key: *const RatifyV2KeyPair,
    out: *mut *mut RatifyV2RefStore,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let kp = handle(verifier_key, "verifier_key")?;
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let store = Store::new(now, lease_seconds, cstr(log_id, "log_id")?, &kp.private)?;
            *out = ref_store(Arc::new(store));
            Ok(())
        },
    )
}

/// TEST ONLY: release a reference store handle. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_free(s: *mut RatifyV2RefStore) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !s.is_null() {
                drop(Box::from_raw(s));
            }
        },
    )
}

/// TEST ONLY: an exact copy of the store state (a restore of a backup).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_clone(
    s: *const RatifyV2RefStore,
    out: *mut *mut RatifyV2RefStore,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || crate::guard::clear_ptr(out),
        || {
            let s = handle(s, "store")?;
            if out.is_null() {
                return Err(null_arg("out"));
            }
            *out = ref_store(Arc::new(s.store.clone_store()));
            Ok(())
        },
    )
}

/// TEST ONLY: store controls. `control` selects: 1 set time to `value`;
/// 2 set acknowledgement withheld (`value` != 0); 3 set signer failure
/// (`value` != 0).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_control(
    s: *const RatifyV2RefStore,
    control: i32,
    value: i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || {},
        || {
            let s = handle(s, "store")?;
            match control {
                1 => s.store.set_time(value),
                2 => s.store.set_acknowledgement_withheld(value != 0),
                3 => s.store.set_signer_failure(value != 0),
                other => return Err(bad_arg(format!("store control {other} is not defined"))),
            }
            Ok(())
        },
    )
}

/// TEST ONLY: the store's current clock value (without a reading).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_time(
    s: *const RatifyV2RefStore,
    out: *mut i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || crate::guard::clear_val(out),
        || write_val(out, handle(s, "store")?.store.now()),
    )
}

/// TEST ONLY: plant a release record for a claim (models a forged or stale
/// primary-storage record), or flip one byte of its sealed terminal result
/// (`corrupt` != 0).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_tamper(
    s: *const RatifyV2RefStore,
    claim_id: *const c_char,
    corrupt: i32,
    ack_timestamp: i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || {},
        || {
            let s = handle(s, "store")?;
            let id = cstr(claim_id, "claim_id")?;
            if corrupt != 0 {
                s.store.corrupt_sealed_state_test_only(id);
            } else {
                s.store.plant_release_test_only(id, ack_timestamp);
            }
            Ok(())
        },
    )
}

/// TEST ONLY: abandon every unpublished receipt and freeze the log; writes
/// the abandoned claim IDs as a JSON array.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_abandon(
    s: *const RatifyV2RefStore,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || clear_buffer(out),
        || {
            let ids = handle(s, "store")?.store.abandon_pending_receipts();
            write_buffer(out, to_bytes(&Value::from(ids)))
        },
    )
}

/// TEST ONLY: the receipt publisher (§7.7): sign and append the committed
/// body of `claim_id`, or return the receipt already appended. On a store
/// refusal `*refusal_out` names it ("head_of_line_blocked",
/// "signer_unavailable", "log_frozen", or "other"; static) and the call
/// returns `RatifyV2StoreUnavailable`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_publish(
    s: *const RatifyV2RefStore,
    claim_id: *const c_char,
    body: *const u8,
    body_len: usize,
    wire_out: *mut RatifyV2Buffer,
    refusal_out: *mut *const c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || {
            clear_buffer(wire_out);
            crate::guard::clear_ptr(refusal_out as *mut *mut c_char);
        },
        || {
            let s = handle(s, "store")?;
            match s.store.publish_v2_receipt(
                &ctx(),
                cstr(claim_id, "claim_id")?,
                bytes(body, body_len, "body")?,
            ) {
                Ok(wire) => write_buffer(wire_out, wire),
                Err(e) => {
                    if !refusal_out.is_null() {
                        *refusal_out = match &e {
                            V2StoreError::Unavailable(m)
                                if m == store::ERR_HEAD_OF_LINE_BLOCKED =>
                            {
                                c"head_of_line_blocked"
                            }
                            V2StoreError::Unavailable(m) if m == store::ERR_SIGNER_UNAVAILABLE => {
                                c"signer_unavailable"
                            }
                            V2StoreError::Unavailable(m) if m == store::ERR_LOG_FROZEN => {
                                c"log_frozen"
                            }
                            _ => c"other",
                        }
                        .as_ptr();
                    }
                    Err(store_failure(e))
                }
            }
        },
    )
}

/// TEST ONLY: callback structs serving this store. Any output pointer may be
/// NULL. With `rate_at_finalization` non-zero the store admits `max_rate`
/// at finalization (it then stays in that mode) and the claim-store and
/// rate callbacks report it.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_store_callbacks(
    s: *const RatifyV2RefStore,
    rate_at_finalization: i32,
    claim_out: *mut RatifyV2ClaimStoreCallbacks,
    rate_out: *mut RatifyV2RateCallbacks,
    release_out: *mut RatifyV2ReleaseStoreCallbacks,
    checkpoint_out: *mut RatifyV2CheckpointCallbacks,
    clock_out: *mut RatifyV2ClockCallbacks,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || {},
        || {
            let s = handle(s, "store")?;
            let b = s.bridge.as_ref();
            if rate_at_finalization != 0 {
                let _view = s.store.with_rate_at_finalization();
            }
            if !claim_out.is_null() {
                *claim_out = claim_callbacks(b, rate_at_finalization != 0);
            }
            if !rate_out.is_null() {
                *rate_out = RatifyV2RateCallbacks {
                    user: bridge_ptr(b),
                    rate_at_finalization: i32::from(rate_at_finalization != 0),
                    reserve: Some(br_reserve),
                };
            }
            if !release_out.is_null() {
                *release_out = RatifyV2ReleaseStoreCallbacks {
                    user: bridge_ptr(b),
                    now: Some(br_now),
                    load_terminal: Some(br_load_terminal),
                    record_release: Some(br_record_release),
                };
            }
            if !checkpoint_out.is_null() {
                *checkpoint_out = checkpoint_callbacks(b);
            }
            if !clock_out.is_null() {
                *clock_out = RatifyV2ClockCallbacks {
                    user: bridge_ptr(b),
                    now: Some(br_now),
                };
            }
            Ok(())
        },
    )
}

// ---------------------------------------------------------------------------
// Reference journal store

struct JournalTarget(Arc<JournalStore>);

impl Target for JournalTarget {
    fn journal(&self, f: &mut dyn FnMut(&dyn SecurityJournalStoreV2)) -> bool {
        f(self.0.as_ref());
        true
    }
}

/// TEST ONLY: the reference anchored `SecurityJournalV2` store.
pub struct RatifyV2RefJournal {
    pub(crate) poisoned: AtomicBool,
    journal: Arc<JournalStore>,
    bridge: Box<Bridge>,
}

poisonable!(RatifyV2RefJournal);

/// TEST ONLY: a reference journal store anchored at genesis.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_journal_new(out: *mut *mut RatifyV2RefJournal) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let journal = Arc::new(JournalStore::new()?);
            *out = Box::into_raw(Box::new(RatifyV2RefJournal {
                poisoned: AtomicBool::new(false),
                bridge: Box::new(Bridge {
                    target: Box::new(JournalTarget(Arc::clone(&journal))),
                }),
                journal,
            }));
            Ok(())
        },
    )
}

/// TEST ONLY: release a reference journal. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_journal_free(j: *mut RatifyV2RefJournal) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !j.is_null() {
                drop(Box::from_raw(j));
            }
        },
    )
}

/// TEST ONLY: the journal callbacks and the anchored head (any output may
/// be NULL; free the digest with `ratify_v2_string_free`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_journal_callbacks(
    j: *const RatifyV2RefJournal,
    callbacks_out: *mut RatifyV2JournalStoreCallbacks,
    generation_out: *mut u64,
    digest_out: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(j)],
        || crate::guard::clear_ptr(digest_out),
        || {
            let j = handle(j, "journal")?;
            if !callbacks_out.is_null() {
                *callbacks_out = journal_callbacks(&j.bridge);
            }
            let head = j.journal.head();
            super::write_opt_val(generation_out, head.generation);
            super::write_opt_string(digest_out, &head.digest)
        },
    )
}

// ---------------------------------------------------------------------------
// Reference challenge issuance store

struct IssuanceTarget(Arc<TestOnlyChallengeIssuanceStore>);

impl Target for IssuanceTarget {
    fn issuance(&self, f: &mut dyn FnMut(&dyn V2ChallengeIssuanceStore)) -> bool {
        f(self.0.as_ref());
        true
    }
}

/// TEST ONLY: the reference challenge issuance store.
pub struct RatifyV2RefIssuance {
    pub(crate) poisoned: AtomicBool,
    store: Arc<TestOnlyChallengeIssuanceStore>,
    bridge: Box<Bridge>,
}

poisonable!(RatifyV2RefIssuance);

/// TEST ONLY: a new, empty reference issuance store.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_issuance_new(out: *mut *mut RatifyV2RefIssuance) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let store = Arc::new(TestOnlyChallengeIssuanceStore::new());
            *out = Box::into_raw(Box::new(RatifyV2RefIssuance {
                poisoned: AtomicBool::new(false),
                bridge: Box::new(Bridge {
                    target: Box::new(IssuanceTarget(Arc::clone(&store))),
                }),
                store,
            }));
            Ok(())
        },
    )
}

/// TEST ONLY: release a reference issuance store. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_issuance_free(s: *mut RatifyV2RefIssuance) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !s.is_null() {
                drop(Box::from_raw(s));
            }
        },
    )
}

/// TEST ONLY: callbacks, record count, and a persist fault for the next
/// persist (`fault`: 0 none, 1 fail before commit, 2 fail after commit; -1
/// leaves it unchanged). Any output may be NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_issuance_control(
    s: *const RatifyV2RefIssuance,
    fault: i32,
    callbacks_out: *mut RatifyV2IssuanceStoreCallbacks,
    records_out: *mut i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(s)],
        || {},
        || {
            let s = handle(s, "issuance")?;
            match fault {
                -1 => {}
                0 => s.store.fail_next_persist(PersistFault::Ok),
                1 => s.store.fail_next_persist(PersistFault::FailBeforeCommit),
                2 => s.store.fail_next_persist(PersistFault::FailAfterCommit),
                other => return Err(bad_arg(format!("persist fault {other} is not defined"))),
            }
            if !callbacks_out.is_null() {
                *callbacks_out = RatifyV2IssuanceStoreCallbacks {
                    user: bridge_ptr(&s.bridge),
                    persist: Some(br_issuance_persist),
                    load: Some(br_issuance_load),
                };
            }
            super::write_opt_val(records_out, s.store.len() as i64);
            Ok(())
        },
    )
}

// ---------------------------------------------------------------------------
// Single-device offline profile (§7.13)

struct DeviceClock(Arc<Mutex<Arc<Store>>>);

impl V2AuthoritativeClock for DeviceClock {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        let store = self.0.lock().unwrap_or_else(|p| p.into_inner()).clone();
        store.authoritative_time_v2(ctx)
    }
}

struct DeviceParts {
    component: Arc<DeviceComponentTestOnly>,
    primary: DevicePrimaryTestOnly,
    checkpoint: Arc<DeviceCheckpointTestOnly>,
    uplink: DeviceUplinkTestOnly,
}

struct DeviceTarget(Arc<Mutex<Option<DeviceParts>>>);

impl Target for DeviceTarget {
    fn checkpoint(&self, f: &mut dyn FnMut(&dyn V2ReceiptCheckpoint)) -> bool {
        let checkpoint = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|d| Arc::clone(&d.checkpoint));
        match checkpoint {
            Some(c) => {
                f(c.as_ref());
                true
            }
            None => false,
        }
    }
    fn journal(&self, f: &mut dyn FnMut(&dyn SecurityJournalStoreV2)) -> bool {
        let parts = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match parts.as_ref() {
            Some(d) => {
                f(&d.primary.journal);
                true
            }
            None => false,
        }
    }
}

/// TEST ONLY: one single-device offline profile device (component, primary,
/// checkpoint, uplink).
pub struct RatifyV2RefDevice {
    pub(crate) poisoned: AtomicBool,
    slot: Arc<Mutex<Arc<Store>>>,
    parts: Arc<Mutex<Option<DeviceParts>>>,
    bridge: Box<Bridge>,
}

/// TEST ONLY: a copy of a device primary (a backup).
pub struct RatifyV2RefPrimary {
    pub(crate) poisoned: AtomicBool,
    primary: DevicePrimaryTestOnly,
}

poisonable!(RatifyV2RefDevice, RatifyV2RefPrimary);

fn bind_device(
    primary: DevicePrimaryTestOnly,
    component: Arc<DeviceComponentTestOnly>,
) -> AbiResult<DeviceParts> {
    let checkpoint = Arc::new(DeviceCheckpointTestOnly::new(
        &primary,
        component.clone(),
        &component.public_key(),
    )?);
    let uplink = DeviceUplinkTestOnly::new(checkpoint.clone());
    Ok(DeviceParts {
        component,
        primary,
        checkpoint,
        uplink,
    })
}

impl RatifyV2RefDevice {
    fn with<R>(&self, f: impl FnOnce(&DeviceParts) -> AbiResult<R>) -> AbiResult<R> {
        let parts = self.parts.lock().unwrap_or_else(|p| p.into_inner());
        f(parts
            .as_ref()
            .ok_or_else(|| bad_arg("device has no bound primary"))?)
    }
}

/// TEST ONLY: provision a device whose primary wraps `store`, whose
/// component has a 32-byte seed and room for `capacity` acknowledgements,
/// and which serves `replay_epoch`. The store must withhold
/// self-acknowledgement.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_new(
    store: *const RatifyV2RefStore,
    component_seed: *const u8,
    component_seed_len: usize,
    capacity: u64,
    replay_epoch: i64,
    out: *mut *mut RatifyV2RefDevice,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(store)],
        || crate::guard::clear_ptr(out),
        || {
            let s = handle(store, "store")?;
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let slot = Arc::new(Mutex::new(Arc::clone(&s.store)));
            let component = Arc::new(DeviceComponentTestOnly::new(
                bytes(component_seed, component_seed_len, "component_seed")?,
                capacity as usize,
                Arc::new(DeviceClock(Arc::clone(&slot))),
            )?);
            let primary = DevicePrimaryTestOnly::new(Arc::clone(&s.store), replay_epoch)?;
            let parts = bind_device(primary, component)?;
            parts.checkpoint.provision()?;
            let parts = Arc::new(Mutex::new(Some(parts)));
            *out = Box::into_raw(Box::new(RatifyV2RefDevice {
                poisoned: AtomicBool::new(false),
                slot,
                bridge: Box::new(Bridge {
                    target: Box::new(DeviceTarget(Arc::clone(&parts))),
                }),
                parts,
            }));
            Ok(())
        },
    )
}

/// TEST ONLY: release a device. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_free(d: *mut RatifyV2RefDevice) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !d.is_null() {
                drop(Box::from_raw(d));
            }
        },
    )
}

/// TEST ONLY: release a primary copy. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_primary_free(p: *mut RatifyV2RefPrimary) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !p.is_null() {
                drop(Box::from_raw(p));
            }
        },
    )
}

/// TEST ONLY: the device checkpoint and the primary's journal callbacks.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_callbacks(
    d: *const RatifyV2RefDevice,
    checkpoint_out: *mut RatifyV2CheckpointCallbacks,
    journal_out: *mut RatifyV2JournalStoreCallbacks,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || {},
        || {
            let d = handle(d, "device")?;
            if !checkpoint_out.is_null() {
                *checkpoint_out = checkpoint_callbacks(&d.bridge);
            }
            if !journal_out.is_null() {
                *journal_out = journal_callbacks(&d.bridge);
            }
            Ok(())
        },
    )
}

fn device_error_name(e: Option<&DeviceErrorTestOnly>) -> &'static std::ffi::CStr {
    match e {
        None => c"",
        Some(DeviceErrorTestOnly::PowerLoss) => c"power_loss",
        Some(DeviceErrorTestOnly::StorageFull) => c"storage_full",
        Some(DeviceErrorTestOnly::StateMismatch) => c"state_mismatch",
        Some(DeviceErrorTestOnly::Frozen) => c"frozen",
        Some(DeviceErrorTestOnly::Store(e)) if e.class() == Some(V2ErrorClass::ClockRegressed) => {
            c"clock_regressed"
        }
        Some(_) => c"unexpected",
    }
}

/// TEST ONLY: device operations. `op`: 1 power loss before the component
/// commits; 2 power loss after it commits; 3 submit pending entries
/// (`*json_out` = acknowledged sequences); 4 resubmit `sequence`
/// (`*value_out` = acknowledgement time); 5 startup (`*name_out` = status);
/// 6 upload (`*json_out` = uploaded sequences). `*name_out` is the device
/// error name ("" when none) for ops 3 and 4. Static names — do NOT free.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_op(
    d: *const RatifyV2RefDevice,
    op: i32,
    sequence: i64,
    json_out: *mut RatifyV2Buffer,
    value_out: *mut i64,
    name_out: *mut *const c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || {
            clear_buffer(json_out);
            crate::guard::clear_val(value_out);
            crate::guard::clear_ptr(name_out as *mut *mut c_char);
        },
        || {
            let d = handle(d, "device")?;
            let set_name = |n: &'static std::ffi::CStr| {
                if !name_out.is_null() {
                    *name_out = n.as_ptr();
                }
            };
            d.with(|p| {
                match op {
                    1 => p.component.set_power_loss(DevicePowerLoss::BeforeCommit),
                    2 => p.component.set_power_loss(DevicePowerLoss::AfterCommit),
                    3 => {
                        let (acked, err) = p.checkpoint.submit_pending(&ctx());
                        set_name(device_error_name(err.as_ref()));
                        super::write_opt_buffer(json_out, to_bytes(&Value::from(acked)))?;
                    }
                    4 => {
                        let r = p.checkpoint.resubmit(&ctx(), sequence);
                        set_name(device_error_name(r.as_ref().err()));
                        if let Ok(ack) = r {
                            super::write_opt_val(value_out, ack.timestamp);
                        }
                    }
                    5 => {
                        let status = p.checkpoint.startup();
                        set_name(match status.as_str() {
                            "ready" => c"ready",
                            "primary_behind" => c"primary_behind",
                            "state_digest_mismatch" => c"state_digest_mismatch",
                            "checkpoint_frozen" => c"checkpoint_frozen",
                            _ => c"unexpected",
                        });
                    }
                    6 => {
                        let got = p.uplink.upload(&ctx());
                        super::write_opt_buffer(json_out, to_bytes(&Value::from(got)))?;
                    }
                    other => return Err(bad_arg(format!("device op {other} is not defined"))),
                }
                Ok(())
            })
        },
    )
}

/// TEST ONLY: copy the device's complete primary state (a backup).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_snapshot(
    d: *const RatifyV2RefDevice,
    out: *mut *mut RatifyV2RefPrimary,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d)],
        || crate::guard::clear_ptr(out),
        || {
            let d = handle(d, "device")?;
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let primary = d.with(|p| Ok(p.primary.clone_primary()))?;
            *out = Box::into_raw(Box::new(RatifyV2RefPrimary {
                poisoned: AtomicBool::new(false),
                primary,
            }));
            Ok(())
        },
    )
}

/// TEST ONLY: restore a primary copy onto the device: the device keeps its
/// component and security clock time; `*store_out` is a new handle for the
/// restored primary store, which replaces the previous one.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_restore(
    d: *const RatifyV2RefDevice,
    snapshot: *const RatifyV2RefPrimary,
    store_out: *mut *mut RatifyV2RefStore,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(d), flag(snapshot)],
        || crate::guard::clear_ptr(store_out),
        || {
            let d = handle(d, "device")?;
            let snap = handle(snapshot, "snapshot")?;
            if store_out.is_null() {
                return Err(null_arg("store_out"));
            }
            let mut parts = d.parts.lock().unwrap_or_else(|p| p.into_inner());
            let current = parts
                .take()
                .ok_or_else(|| bad_arg("device has no bound primary"))?;
            let now = d.slot.lock().unwrap_or_else(|p| p.into_inner()).now();
            let primary = snap.primary.clone_primary();
            let store = Arc::clone(&primary.store);
            *d.slot.lock().unwrap_or_else(|p| p.into_inner()) = Arc::clone(&store);
            store.set_time(now);
            *parts = Some(bind_device(primary, current.component)?);
            *store_out = ref_store(store);
            Ok(())
        },
    )
}

/// TEST ONLY: the single-device complete-state projection (SPEC-v2 §7.13)
/// of a primary loaded from `state_json` (the record encodings of
/// `testvectors/v2/device-state.json` `state`). `*out` is a JSON object of
/// strings: `<member>_canonical_json` for `claims`, `streams`,
/// `rate_counters`, `receipt_log`, and `issuance_records`;
/// `projection_canonical_json`; `complete_state_digest_hex`; and
/// `anchoring_digest_hex`, the digest the loaded primary anchors to its
/// checkpoint, which must equal the projection digest.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_device_state_projection(
    state_json: *const u8,
    state_json_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let state = bytes(state_json, state_json_len, "state_json")?;
            let primary = DevicePrimaryTestOnly::from_records_test_only(state)?;
            let p = primary.projection_test_only()?;
            let anchoring = primary.complete_state_digest_test_only()?;
            let text = |b: &[u8]| {
                String::from_utf8(b.to_vec()).map_err(|_| bad_arg("projection member is not UTF-8"))
            };
            let mut o = serde_json::Map::new();
            for (member, b) in [
                ("claims", &p.claims),
                ("streams", &p.streams),
                ("rate_counters", &p.rate_counters),
                ("receipt_log", &p.receipt_log),
                ("issuance_records", &p.issuance_records),
                ("projection", &p.projection),
            ] {
                o.insert(format!("{member}_canonical_json"), text(b)?.into());
            }
            o.insert(
                "complete_state_digest_hex".into(),
                hex_lower(&p.complete_state_digest).into(),
            );
            o.insert("anchoring_digest_hex".into(), hex_lower(&anchoring).into());
            write_buffer(out, to_bytes(&Value::Object(o)))
        },
    )
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Dual-root composition profile (§7.14)

/// TEST ONLY: the dual-root application approval ledger.
pub struct RatifyV2RefLedger {
    pub(crate) poisoned: AtomicBool,
    ledger: ApprovalLedgerTestOnly,
}

poisonable!(RatifyV2RefLedger);

fn ledger_error_name(r: &Result<(), ApprovalErrorTestOnly>) -> *const c_char {
    match r {
        Ok(()) => c"".as_ptr(),
        Err(e) => static_name(e.as_str()),
    }
}

fn static_name(s: &'static str) -> *const c_char {
    // Every ApprovalErrorTestOnly spelling, NUL-terminated.
    const NAMES: &[&std::ffi::CStr] = &[
        c"not_released",
        c"action_mismatch",
        c"root_mismatch",
        c"slot_filled",
        c"approval_reused",
        c"incomplete",
        c"expired",
        c"already_executed",
        c"approval_set_invalid",
        c"approval_set_unknown",
        c"approval_set_already_exists",
        c"invalid_slot",
    ];
    NAMES
        .iter()
        .find(|n| n.to_str() == Ok(s))
        .map_or(c"unexpected".as_ptr(), |n| n.as_ptr())
}

/// TEST ONLY: a new, empty ledger.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_ledger_new(out: *mut *mut RatifyV2RefLedger) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            *out = Box::into_raw(Box::new(RatifyV2RefLedger {
                poisoned: AtomicBool::new(false),
                ledger: ApprovalLedgerTestOnly::new(),
            }));
            Ok(())
        },
    )
}

/// TEST ONLY: release a ledger. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_ledger_free(l: *mut RatifyV2RefLedger) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !l.is_null() {
                drop(Box::from_raw(l));
            }
        },
    )
}

/// TEST ONLY: open an approval set `{"approval_set_id", "verifier_id",
/// "workspace_id", "session_id", "agent_public_key", "required_scope",
/// "request_hash_b64", "root_keys": [<key>, <key>]}`. `*error_out` is the
/// ledger error name ("" on success; static).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_ledger_open(
    l: *const RatifyV2RefLedger,
    set_json: *const u8,
    set_json_len: usize,
    error_out: *mut *const c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(l)],
        || {},
        || {
            let l = handle(l, "ledger")?;
            let v = json_bytes(set_json, set_json_len, "set_json")?;
            let o = Obj::new(
                &v,
                "approval set",
                &[
                    "approval_set_id",
                    "verifier_id",
                    "workspace_id",
                    "session_id",
                    "agent_public_key",
                    "required_scope",
                    "request_hash_b64",
                    "root_keys",
                ],
            )?;
            let roots = o.array("root_keys")?;
            if roots.len() != 2 {
                return Err(bad_arg("root_keys must hold two keys"));
            }
            let set = ApprovalSetTestOnly {
                approval_set_id: o.str("approval_set_id")?,
                verifier_id: o.str("verifier_id")?,
                workspace_id: o.str("workspace_id")?,
                session_id: o.str("session_id")?,
                agent_public_key: o.key("agent_public_key")?,
                required_scope: o.str("required_scope")?,
                request_hash: o.b64("request_hash_b64")?,
                roots: [
                    public_key(roots[0], "root_keys[0]")?,
                    public_key(roots[1], "root_keys[1]")?,
                ],
            };
            write_val(error_out, ledger_error_name(&l.ledger.open(set)))
        },
    )
}

/// TEST ONLY: record a released decision (NULL = none) and the exact proof
/// bundle it verified in `slot`; `*complete_out` is 1 when both slots are
/// filled.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_ledger_record(
    l: *const RatifyV2RefLedger,
    set_id: *const c_char,
    slot: u64,
    decision: *const RatifyV2Released,
    bundle: *const u8,
    bundle_len: usize,
    complete_out: *mut i32,
    error_out: *mut *const c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(l), flag(decision)],
        || crate::guard::clear_val(complete_out),
        || {
            let l = handle(l, "ledger")?;
            let d = decision.as_ref().map(|d| &d.inner);
            let r = l.ledger.record_approval(
                cstr(set_id, "set_id")?,
                slot as usize,
                d,
                bytes(bundle, bundle_len, "bundle")?,
            );
            write_val(complete_out, i32::from(*r.as_ref().unwrap_or(&false)))?;
            write_val(error_out, ledger_error_name(&r.map(|_| ())))
        },
    )
}

/// TEST ONLY: execute an approval set at the receiver's authoritative clock.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_ref_ledger_execute(
    l: *const RatifyV2RefLedger,
    set_id: *const c_char,
    clock: *const RatifyV2ClockCallbacks,
    error_out: *mut *const c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(l)],
        || {},
        || {
            let l = handle(l, "ledger")?;
            let clock = clock.as_ref().ok_or_else(|| null_arg("clock"))?;
            let (c, cancel) = V2Context::background().with_cancel();
            let clock = CClock {
                cb: *clock,
                cancel: Cancel(cancel),
            };
            write_val(
                error_out,
                ledger_error_name(&l.ledger.execute(&c, cstr(set_id, "set_id")?, &clock)),
            )
        },
    )
}
