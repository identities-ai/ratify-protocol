//! Protocol state machines: the status reducer (SPEC-v2 §5.4), the
//! `SecurityJournalV2` operations and snapshots (§6.6), the status publisher
//! (§5.4), the rotation journal (§5.5), witness and receipt log heads (§5.6,
//! §5.8), and archival verification (§6.10).

use std::os::raw::c_char;
use std::sync::atomic::AtomicBool;

use ratify_protocol::v2::*;
use ratify_protocol::HybridPublicKey;
use serde_json::{json, Value};

use super::callbacks::{CJournal, Cancel, RatifyV2JournalStoreCallbacks};
use super::keys::RatifyV2KeyPair;
use super::marshal::{
    archival_json, receipt_head, rotation_journal_json, status_result_json, status_state_json,
    to_bytes, witness_head, Obj,
};
use super::sign::{build, finish, Built, RatifyV2ExternalSigner};
use super::{
    bad_arg, bytes, clear_buffer, cstr, flag, handle, json_bytes, null_arg, poisonable, run, run_h,
    write_buffer, write_val, AbiResult, RatifyV2Buffer, RatifyV2PublicKey,
};

/// The caller-authenticated revocation status policy (§2.5 bounds).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2StatusPolicy {
    pub max_list_lifetime_seconds: i64,
    pub max_status_age_seconds: i64,
    pub clock_skew_seconds: i64,
}

impl RatifyV2StatusPolicy {
    fn to_rust(self) -> RevocationStatusPolicyV2 {
        RevocationStatusPolicyV2 {
            max_list_lifetime_seconds: self.max_list_lifetime_seconds,
            max_status_age_seconds: self.max_status_age_seconds,
            clock_skew_seconds: self.clock_skew_seconds,
        }
    }
}

unsafe fn policy_arg(p: *const RatifyV2StatusPolicy) -> AbiResult<RevocationStatusPolicyV2> {
    p.as_ref()
        .map(|p| p.to_rust())
        .ok_or_else(|| null_arg("policy"))
}

unsafe fn key_arg(k: *const RatifyV2PublicKey, name: &str) -> AbiResult<HybridPublicKey> {
    k.as_ref()
        .map(RatifyV2PublicKey::as_hybrid)
        .ok_or_else(|| null_arg(name))
}

// ---------------------------------------------------------------------------
// Status reducer

/// One issuer's rollback-protected status reducer state (§5.4). An apply
/// replaces the state only when it succeeds. Applies and epoch transitions
/// are serialized on the handle: each reads, applies, and replaces the state
/// under one lock, so concurrent updates never overwrite each other. Release
/// with `ratify_v2_status_state_free`.
pub struct RatifyV2StatusState {
    pub(crate) poisoned: AtomicBool,
    pub(crate) inner: std::sync::Mutex<RevocationStatusStateV2>,
}

poisonable!(RatifyV2StatusState);

impl RatifyV2StatusState {
    fn get(&self) -> RevocationStatusStateV2 {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Read, transition, and replace the state under one lock. The state is
    /// replaced only when `f` succeeds, and no other update can interleave
    /// between the read and the replacement.
    fn update(
        &self,
        f: impl FnOnce(&RevocationStatusStateV2) -> AbiResult<RevocationStatusStateV2>,
    ) -> AbiResult<()> {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let next = f(&guard)?;
        *guard = next;
        Ok(())
    }
}

/// A new, empty reducer state.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_state_new(out: *mut *mut RatifyV2StatusState) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            *out = Box::into_raw(Box::new(RatifyV2StatusState {
                poisoned: AtomicBool::new(false),
                inner: std::sync::Mutex::new(RevocationStatusStateV2::default()),
            }));
            Ok(())
        },
    )
}

/// Release a reducer state. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_state_free(s: *mut RatifyV2StatusState) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !s.is_null() {
                drop(Box::from_raw(s));
            }
        },
    )
}

/// Apply a signed revocation list (`kind` 3) or push (`kind` 5) for
/// `issuer_id` under the authenticated status key at `status_key_epoch`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_state_apply(
    state: *const RatifyV2StatusState,
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    issuer_id: *const c_char,
    status_key_epoch: u64,
    status_key: *const RatifyV2PublicKey,
    policy: *const RatifyV2StatusPolicy,
    now: i64,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(state)],
        || {},
        || {
            let st = handle(state, "state")?;
            let wire = bytes(wire, wire_len, "wire")?;
            let issuer = cstr(issuer_id, "issuer_id")?;
            let key = key_arg(status_key, "status_key")?;
            let pol = policy_arg(policy)?;
            match kind {
                3 => {
                    let list = decode_revocation_list_v2(wire)?;
                    st.update(|current| {
                        Ok(apply_revocation_list_v2(
                            current,
                            &list,
                            issuer,
                            status_key_epoch,
                            &key,
                            &pol,
                            now,
                        )?)
                    })
                }
                5 => {
                    let push = decode_revocation_push_v2(wire)?;
                    st.update(|current| {
                        Ok(apply_revocation_push_v2(
                            current,
                            &push,
                            issuer,
                            status_key_epoch,
                            &key,
                            &pol,
                            now,
                        )?)
                    })
                }
                other => Err(bad_arg(format!("status object kind {other} is not 3 or 5"))),
            }
        },
    )
}

/// Transition the issuer's status key to `next_epoch` / `next_status_key`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_state_transition_epoch(
    state: *const RatifyV2StatusState,
    issuer_id: *const c_char,
    next_epoch: u64,
    next_status_key: *const RatifyV2PublicKey,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(state)],
        || {},
        || {
            let st = handle(state, "state")?;
            let issuer = cstr(issuer_id, "issuer_id")?;
            let key = key_arg(next_status_key, "next_status_key")?;
            st.update(|current| {
                Ok(transition_revocation_status_epoch_v2(
                    current, issuer, next_epoch, &key,
                )?)
            })
        },
    )
}

/// The status of one certificate at `now`: JSON `{"status": "not_revoked" |
/// "revoked" | "indeterminate", "reason": "" | "unavailable" | "stale",
/// "evidence": [...], "fresh_until"}`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_state_query(
    state: *const RatifyV2StatusState,
    issuer_id: *const c_char,
    cert_id: *const c_char,
    status_key_epoch: u64,
    status_key: *const RatifyV2PublicKey,
    policy: *const RatifyV2StatusPolicy,
    now: i64,
    result_out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(state)],
        || clear_buffer(result_out),
        || {
            let st = handle(state, "state")?;
            let r = revocation_status_for_cert_v2(
                &st.get(),
                cstr(issuer_id, "issuer_id")?,
                cstr(cert_id, "cert_id")?,
                status_key_epoch,
                &key_arg(status_key, "status_key")?,
                &policy_arg(policy)?,
                now,
            )?;
            write_buffer(result_out, to_bytes(&status_result_json(&r)))
        },
    )
}

/// A JSON view of the reducer state (`has_floor`, `floor`,
/// `accepted_cert_ids`, `deny_union_cert_ids`, `max_observed_sequence`,
/// `fork_sequence`, `reconciliation_required`,
/// `future_dated_object_observed`, and the status key fields).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_state_json(
    state: *const RatifyV2StatusState,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(state)],
        || clear_buffer(out),
        || {
            write_buffer(
                out,
                to_bytes(&status_state_json(&handle(state, "state")?.get())),
            )
        },
    )
}

// ---------------------------------------------------------------------------
// Security journal (§6.6)

fn journal(cb: *const RatifyV2JournalStoreCallbacks) -> AbiResult<(V2Context, CJournal)> {
    // SAFETY: a non-NULL pointer refers to caller storage for this call.
    let cb = unsafe { cb.as_ref() }.ok_or_else(|| null_arg("journal"))?;
    let (ctx, cancel) = V2Context::background().with_cancel();
    Ok((
        ctx,
        CJournal {
            cb: *cb,
            cancel: Cancel(cancel),
        },
    ))
}

/// Permanently bind a key to a role in the anchored journal. `role` is one of
/// `"delegation"`, `"rotation"`, `"verifier"`, `"witness"`, `"receiver"`,
/// `"issuer"`, or `"other"`. A status key is bound with
/// `ratify_v2_journal_configure_status_key`, which also records its issuer
/// and epoch; `"status"` is rejected here.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_record_key_role(
    journal_store: *const RatifyV2JournalStoreCallbacks,
    role: *const c_char,
    key: *const RatifyV2PublicKey,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let (ctx, j) = journal(journal_store)?;
            record_security_key_role_v2(&ctx, &j, cstr(role, "role")?, &key_arg(key, "key")?)?;
            Ok(())
        },
    )
}

/// Configure an issuer's status key at `epoch` in the anchored journal.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_configure_status_key(
    journal_store: *const RatifyV2JournalStoreCallbacks,
    issuer_id: *const c_char,
    epoch: u64,
    key: *const RatifyV2PublicKey,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let (ctx, j) = journal(journal_store)?;
            configure_status_key_epoch_v2(
                &ctx,
                &j,
                cstr(issuer_id, "issuer_id")?,
                epoch,
                &key_arg(key, "key")?,
            )?;
            Ok(())
        },
    )
}

/// Apply a signed revocation list (`kind` 3) or push (5) to the anchored
/// journal (load, reduce, compare-and-swap with one bounded retry).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_apply(
    journal_store: *const RatifyV2JournalStoreCallbacks,
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    issuer_id: *const c_char,
    status_key_epoch: u64,
    status_key: *const RatifyV2PublicKey,
    policy: *const RatifyV2StatusPolicy,
    now: i64,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {},
        || {
            let (ctx, j) = journal(journal_store)?;
            let wire = bytes(wire, wire_len, "wire")?;
            let issuer = cstr(issuer_id, "issuer_id")?;
            let key = key_arg(status_key, "status_key")?;
            let pol = policy_arg(policy)?;
            match kind {
                3 => apply_revocation_list_to_journal_v2(
                    &ctx,
                    &j,
                    &decode_revocation_list_v2(wire)?,
                    issuer,
                    status_key_epoch,
                    &key,
                    &pol,
                    now,
                )?,
                5 => apply_revocation_push_to_journal_v2(
                    &ctx,
                    &j,
                    &decode_revocation_push_v2(wire)?,
                    issuer,
                    status_key_epoch,
                    &key,
                    &pol,
                    now,
                )?,
                other => return Err(bad_arg(format!("status object kind {other} is not 3 or 5"))),
            };
            Ok(())
        },
    )
}

/// The status of one certificate from the anchored journal (result JSON as
/// `ratify_v2_status_state_query`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_status(
    journal_store: *const RatifyV2JournalStoreCallbacks,
    issuer_id: *const c_char,
    cert_id: *const c_char,
    status_key_epoch: u64,
    status_key: *const RatifyV2PublicKey,
    policy: *const RatifyV2StatusPolicy,
    now: i64,
    result_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(result_out),
        || {
            let (ctx, j) = journal(journal_store)?;
            let r = revocation_status_from_journal_v2(
                &ctx,
                &j,
                cstr(issuer_id, "issuer_id")?,
                cstr(cert_id, "cert_id")?,
                status_key_epoch,
                &key_arg(status_key, "status_key")?,
                &policy_arg(policy)?,
                now,
            )?;
            write_buffer(result_out, to_bytes(&status_result_json(&r)))
        },
    )
}

fn snapshot_head_json(j: &SecurityJournalV2) -> Value {
    json!({
        "version": j.version,
        "generation": j.generation,
        "previous_digest": j.previous_digest,
        "digest": j.digest,
    })
}

/// The canonical genesis snapshot; `*generation_out` and `*digest_out` are
/// its head (free the digest with `ratify_v2_string_free`). A new anchored
/// journal store starts here.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_genesis(
    snapshot_out: *mut RatifyV2Buffer,
    generation_out: *mut u64,
    digest_out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            clear_buffer(snapshot_out);
            crate::guard::clear_val(generation_out);
            crate::guard::clear_ptr(digest_out);
        },
        || {
            let g = empty_security_journal_v2();
            write_val(generation_out, g.generation)?;
            super::write_string(digest_out, &g.digest)?;
            write_buffer(snapshot_out, export_security_journal_snapshot_v2(&g)?)
        },
    )
}

/// Import a snapshot against an anchored head (every structural, digest, and
/// invariant check). On success, `*head_out` (when non-NULL) is the JSON
/// `{"version", "generation", "previous_digest", "digest"}`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_import(
    snapshot: *const u8,
    snapshot_len: usize,
    generation: u64,
    digest: *const c_char,
    head_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(head_out),
        || {
            let head = SecurityJournalHeadV2 {
                generation,
                digest: cstr(digest, "digest")?.to_string(),
            };
            let j = import_security_journal_snapshot_v2(
                bytes(snapshot, snapshot_len, "snapshot")?,
                &head,
            )?;
            super::write_opt_buffer(head_out, to_bytes(&snapshot_head_json(&j)))
        },
    )
}

/// Migrate a version 1 journal record (Go JSON encoding) to the version 2
/// logical snapshot. Writes the snapshot and its head JSON.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_migrate(
    legacy_record: *const u8,
    legacy_record_len: usize,
    snapshot_out: *mut RatifyV2Buffer,
    head_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            clear_buffer(snapshot_out);
            clear_buffer(head_out);
        },
        || {
            let legacy = decode_security_journal_json_v2(bytes(
                legacy_record,
                legacy_record_len,
                "legacy_record",
            )?)?;
            let migrated = migrate_security_journal_v2(&legacy)?;
            write_buffer(
                snapshot_out,
                export_security_journal_snapshot_v2(&migrated)?,
            )?;
            write_buffer(head_out, to_bytes(&snapshot_head_json(&migrated)))
        },
    )
}

/// Re-encode a journal record in the version 1 JSON encoding; with
/// `clear_digest` non-zero the digest member is emptied first (the version 1
/// digest input).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_journal_legacy_encode(
    record: *const u8,
    record_len: usize,
    clear_digest: i32,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let mut j = decode_security_journal_json_v2(bytes(record, record_len, "record")?)?;
            if clear_digest != 0 {
                j.digest = String::new();
            }
            write_buffer(out, encode_security_journal_json_v2(&j)?)
        },
    )
}

// ---------------------------------------------------------------------------
// Status publisher (§5.4)

/// Publisher operations.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2PublishOp {
    RatifyV2PublishGenesis = 1,
    RatifyV2PublishHeartbeat = 2,
    RatifyV2PublishRevoke = 3,
}

fn publisher_state(v: &Value) -> AbiResult<V2StatusPublisherState> {
    let o = Obj::new(
        v,
        "publisher state",
        &[
            "issuer_id",
            "status_key_id",
            "sequence",
            "updated_at",
            "revoked",
        ],
    )?;
    Ok(V2StatusPublisherState {
        issuer_id: o.str("issuer_id")?,
        status_key_id: o.str("status_key_id")?,
        sequence: o.i64("sequence")?,
        updated_at: o.i64("updated_at")?,
        revoked: o.strings("revoked")?,
    })
}

fn publisher_state_json(s: &V2StatusPublisherState) -> Value {
    json!({
        "issuer_id": s.issuer_id,
        "status_key_id": s.status_key_id,
        "sequence": s.sequence,
        "updated_at": s.updated_at,
        "revoked": s.revoked,
    })
}

/// One status publisher transition for the issuer whose complete key is
/// `issuer_key`. The publisher is constructed from the authenticated role
/// configuration in `journal_store` (a status key outside it is refused with
/// `configuration_invalid`) and signs with exactly one of `local` (the
/// status key pair held by the library, signed only through the typed
/// revocation signers) or `external`; both apply the same refusals.
/// `state_json` is the publisher state JSON (`{"issuer_id",
/// "status_key_id", "sequence", "updated_at", "revoked"}`) returned by the
/// previous transition (ignored for genesis); `cert_ids_json` is a JSON
/// array (revoke only). Writes the signed list, the signed push (empty
/// unless revoking), and the next state; persist the state before
/// publishing the objects.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_status_publish(
    op: i32,
    journal_store: *const RatifyV2JournalStoreCallbacks,
    issuer_key: *const RatifyV2PublicKey,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    lifetime_seconds: i64,
    state_json: *const u8,
    state_json_len: usize,
    cert_ids_json: *const u8,
    cert_ids_json_len: usize,
    at: i64,
    list_out: *mut RatifyV2Buffer,
    push_out: *mut RatifyV2Buffer,
    state_out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || {
            clear_buffer(list_out);
            clear_buffer(push_out);
            clear_buffer(state_out);
        },
        || {
            let (ctx, j) = journal(journal_store)?;
            let issuer = key_arg(issuer_key, "issuer_key")?;
            let state = if op == RatifyV2PublishOp::RatifyV2PublishGenesis as i32 {
                V2StatusPublisherState::default()
            } else {
                publisher_state(&json_bytes(state_json, state_json_len, "state_json")?)?
            };
            let ids: Vec<String> = if op == RatifyV2PublishOp::RatifyV2PublishRevoke as i32 {
                let v = json_bytes(cert_ids_json, cert_ids_json_len, "cert_ids_json")?;
                v.as_array()
                    .ok_or_else(|| bad_arg("cert_ids_json must be an array"))?
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| bad_arg("cert ids must be strings"))
                    })
                    .collect::<AbiResult<_>>()?
            } else {
                Vec::new()
            };
            if !(1..=3).contains(&op) {
                return Err(bad_arg(format!("publish op {op} is not defined")));
            }
            let (_sctx, cancel) = V2Context::background().with_cancel();
            let publisher = match build(local, external, "status", &cancel)? {
                Built::Local(key) => {
                    new_v2_status_publisher_with_key(&ctx, &j, &issuer, key, lifetime_seconds)?
                }
                Built::External(signer) => new_v2_status_publisher(
                    &ctx,
                    &j,
                    &issuer,
                    std::sync::Arc::new(signer),
                    lifetime_seconds,
                )?,
            };
            let result = match op {
                1 => publisher.genesis(&ctx, at),
                2 => publisher.heartbeat(&ctx, &state, at),
                _ => publisher.revoke(&ctx, &state, &ids, at),
            };
            let p = finish(result, &[])?;
            write_buffer(list_out, encode_revocation_list_v2(&p.list)?)?;
            match &p.push {
                Some(push) => write_buffer(push_out, encode_revocation_push_v2(push)?)?,
                None => clear_buffer(push_out),
            }
            write_buffer(state_out, to_bytes(&publisher_state_json(&p.state)))
        },
    )
}

// ---------------------------------------------------------------------------
// Rotation journal (§5.5)

/// The AcceptRotation journal of one authority and role. Release with
/// `ratify_v2_rotation_journal_free`.
pub struct RatifyV2RotationJournal {
    pub(crate) poisoned: AtomicBool,
    pub(crate) inner: std::sync::Mutex<KeyRotationV2Journal>,
}

poisonable!(RatifyV2RotationJournal);

/// Start a rotation journal from a caller-authenticated genesis key.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_rotation_journal_new(
    authority_id: *const c_char,
    recovery_epoch: i64,
    role: *const c_char,
    genesis_key: *const RatifyV2PublicKey,
    out: *mut *mut RatifyV2RotationJournal,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let j = new_key_rotation_v2_journal(
                cstr(authority_id, "authority_id")?,
                recovery_epoch,
                cstr(role, "role")?,
                &key_arg(genesis_key, "genesis_key")?,
            )?;
            *out = Box::into_raw(Box::new(RatifyV2RotationJournal {
                poisoned: AtomicBool::new(false),
                inner: std::sync::Mutex::new(j),
            }));
            Ok(())
        },
    )
}

/// Release a rotation journal. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_rotation_journal_free(j: *mut RatifyV2RotationJournal) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !j.is_null() {
                drop(Box::from_raw(j));
            }
        },
    )
}

/// Log append results.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2LogResult {
    RatifyV2LogNone = 0,
    /// The next valid entry; persist the new head atomically.
    RatifyV2LogAppended = 1,
    /// An exact accepted body at an accepted sequence; state unchanged.
    RatifyV2LogReplay = 2,
}

fn log_result(r: WitnessEntryV2Result) -> i32 {
    (match r {
        WitnessEntryV2Result::Appended => RatifyV2LogResult::RatifyV2LogAppended,
        WitnessEntryV2Result::Replay => RatifyV2LogResult::RatifyV2LogReplay,
    }) as i32
}

/// Accept a rotation statement at `now`. The journal always takes the
/// returned state (a fork freezes it even though the call fails with
/// `rotation_fork`). `*result_out` is `RatifyV2LogResult` on success.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_rotation_journal_accept(
    journal_handle: *const RatifyV2RotationJournal,
    wire: *const u8,
    wire_len: usize,
    now: i64,
    future_skew_seconds: i64,
    result_out: *mut i32,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(journal_handle)],
        || crate::guard::clear_val(result_out),
        || {
            let h = handle(journal_handle, "journal")?;
            let stmt = decode_key_rotation_statement_v2(bytes(wire, wire_len, "wire")?)?;
            let mut j = h.inner.lock().unwrap_or_else(|p| p.into_inner());
            let (next, result) =
                accept_key_rotation_statement_v2(&stmt, &j, now, future_skew_seconds);
            *j = next;
            write_val(result_out, log_result(result?))
        },
    )
}

/// Recover the authority to a new recovery epoch and genesis key.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_rotation_journal_recover(
    journal_handle: *const RatifyV2RotationJournal,
    new_recovery_epoch: i64,
    new_genesis_key: *const RatifyV2PublicKey,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(journal_handle)],
        || {},
        || {
            let h = handle(journal_handle, "journal")?;
            let mut j = h.inner.lock().unwrap_or_else(|p| p.into_inner());
            *j = recover_key_rotation_v2(
                &j,
                new_recovery_epoch,
                &key_arg(new_genesis_key, "new_genesis_key")?,
            )?;
            Ok(())
        },
    )
}

/// The journal state JSON: `{"authority_id", "recovery_epoch", "role",
/// "sequence", "head_hash_b64", "current_key", "used_key_ids", "frozen",
/// "accepted_count"}`. Its rotation-state members are the
/// `"rotation_state"` schema of `ratify_v2_verify_object`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_rotation_journal_state(
    journal_handle: *const RatifyV2RotationJournal,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(journal_handle)],
        || clear_buffer(out),
        || {
            let h = handle(journal_handle, "journal")?;
            let j = h.inner.lock().unwrap_or_else(|p| p.into_inner());
            write_buffer(out, to_bytes(&rotation_journal_json(&j)))
        },
    )
}

// ---------------------------------------------------------------------------
// Witness and receipt logs (§5.6, §5.8)

/// Verify a witness entry against a caller-authenticated log head
/// (`head_json` as in `ratify_v2_verify_object`) and witness key. On success
/// `*result_out` is appended or replay and, when non-NULL, `*digest_out` is
/// the entry's StatementBodyDigest (the next `head_hash`). The caller
/// persists the new head after an append and freezes it after `log_fork`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_witness_entry_append(
    wire: *const u8,
    wire_len: usize,
    head_json: *const u8,
    head_json_len: usize,
    witness_key: *const RatifyV2PublicKey,
    result_out: *mut i32,
    digest_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            crate::guard::clear_val(result_out);
            clear_buffer(digest_out);
        },
        || {
            let e = decode_witness_entry_v2(bytes(wire, wire_len, "wire")?)?;
            let head = witness_head(&json_bytes(head_json, head_json_len, "head_json")?)?;
            let r = verify_witness_entry_v2(&e, &head, &key_arg(witness_key, "witness_key")?)?;
            write_val(result_out, log_result(r))?;
            super::write_opt_buffer(digest_out, witness_entry_v2_digest(&e)?)
        },
    )
}

/// Verify a verification receipt against a caller-authenticated verifier
/// key and receipt-log head; outputs as `ratify_v2_witness_entry_append`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verification_receipt_append(
    wire: *const u8,
    wire_len: usize,
    head_json: *const u8,
    head_json_len: usize,
    verifier_key: *const RatifyV2PublicKey,
    result_out: *mut i32,
    digest_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            crate::guard::clear_val(result_out);
            clear_buffer(digest_out);
        },
        || {
            let r = decode_verification_receipt_v2(bytes(wire, wire_len, "wire")?)?;
            let head = receipt_head(&json_bytes(head_json, head_json_len, "head_json")?)?;
            let result =
                verify_verification_receipt_v2(&r, &key_arg(verifier_key, "verifier_key")?, &head)?;
            write_val(result_out, log_result(result))?;
            super::write_opt_buffer(digest_out, verification_receipt_v2_digest(&r)?)
        },
    )
}

// ---------------------------------------------------------------------------
// Archival verification (§6.10)

/// Archival verification of a stored object (SPEC-v2 §6.10). It proves
/// signatures and structure only: the result is labelled
/// `freshness_unverified` and is never actionable.
///
/// - `kind` 2 (proof bundle): always returns 0 and writes `{"actionable",
///   "agent_id", "assessment", "bundle_hash", "error_class", "issuer_ids"}`
///   (the language-neutral result; `error_class` is null on success).
/// - kinds 1, 4, 7: no key needed.
/// - kinds 3, 5: `issuer_id` and `key` (the status key).
/// - kinds 6, 8: `key` (the witness or verifier key).
///
/// Other kinds write `{"object_type_code", "freshness", "actionable",
/// "digest", "signer_key_ids"}` and fail with the object's class.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_archival_verify(
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    issuer_id: *const c_char,
    key: *const RatifyV2PublicKey,
    result_out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(result_out),
        || {
            let data = bytes(wire, wire_len, "wire")?;
            let r = match kind {
                2 => {
                    return write_buffer(
                        result_out,
                        verify_archival_proof_bundle_v2(data).to_json()?,
                    )
                }
                1 => verify_archival_delegation_cert_v2(data)?,
                3 => verify_archival_revocation_list_v2(
                    data,
                    cstr(issuer_id, "issuer_id")?,
                    &key_arg(key, "key")?,
                )?,
                4 => verify_archival_key_rotation_statement_v2(data)?,
                5 => verify_archival_revocation_push_v2(
                    data,
                    cstr(issuer_id, "issuer_id")?,
                    &key_arg(key, "key")?,
                )?,
                6 => verify_archival_witness_entry_v2(data, &key_arg(key, "key")?)?,
                7 => verify_archival_transaction_receipt_v2(data)?,
                8 => verify_archival_verification_receipt_v2(data, &key_arg(key, "key")?)?,
                other => return Err(bad_arg(format!("archival kind {other} is not defined"))),
            };
            write_buffer(result_out, to_bytes(&archival_json(&r)))
        },
    )
}
