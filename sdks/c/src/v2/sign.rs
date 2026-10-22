//! Typed signing for every v2 signed object (SPEC-v2 §3.2), with either a
//! library key pair or an external signer supplied as C callbacks.
//!
//! No function here signs caller-selected bytes, codes, contexts, or prehash
//! modes: each takes a typed object, validates it and applies its issuer
//! duties before any signer method runs, computes the signable projection,
//! `M`, the ML-DSA context (and μ for an external-μ signer) itself, and
//! verifies every returned signature before producing an object.

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use ratify_protocol::v2::*;
use ratify_protocol::{base64_std_decode, HybridPublicKey, HybridSignature};
use serde_json::{json, Map, Value};

use super::keys::RatifyV2KeyPair;
use super::marshal::{b64, public_key, receipt_head, to_bytes, Obj};
use super::{
    bad_arg, bytes, clear_buffer, cstr, flag, json_bytes, null_arg, run_h, write_buffer, AbiResult,
    Failure, RatifyV2Buffer, RatifyV2Code, RatifyV2PublicKey, RatifyV2Signature, RatifyV2Slice,
};

/// How an external signer receives the ML-DSA-65 input.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2SignerMode {
    /// The provider signs `message` (`M`) under `ml_dsa_context` (FIPS 204
    /// pure ML-DSA with a context string).
    RatifyV2SignerDirect = 1,
    /// The provider signs the 64-byte `ml_dsa_mu` (external μ).
    RatifyV2SignerExternalMu = 2,
}

/// What an external signer receives for one typed statement. Every byte is
/// computed by the library and valid only until the callback returns.
/// Ed25519 always signs `message`.
#[repr(C)]
pub struct RatifyV2SignRequest {
    /// `RatifyV2SignerMode`.
    pub mode: i32,
    /// The 77-byte transcript `M`.
    pub message: RatifyV2Slice,
    /// The 22-byte ML-DSA context in direct mode; empty in external-μ mode.
    pub ml_dsa_context: RatifyV2Slice,
    /// The 64-byte μ in external-μ mode; empty in direct mode.
    pub ml_dsa_mu: RatifyV2Slice,
    /// The complete key the provider must sign under; a provider holding any
    /// other key must refuse.
    pub public_key: *const RatifyV2PublicKey,
    /// `key_id_v2` of `public_key`, NUL-terminated.
    pub key_id: *const c_char,
}

/// Reports the signer's complete public key. Return 0, or a negative code
/// (`RatifyV2ErrCancelled` cancels signing).
pub type RatifyV2SignerPublicKeyFn =
    Option<unsafe extern "C" fn(user: *mut c_void, out: *mut RatifyV2PublicKey) -> i32>;

/// Signs one request. Write both components and their lengths into `*out`
/// and return 0; return `RatifyV2ErrCancelled` to cancel, or any other
/// non-zero code to refuse. The library verifies the result before use.
pub type RatifyV2SignerSignFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        request: *const RatifyV2SignRequest,
        out: *mut RatifyV2Signature,
    ) -> i32,
>;

/// An external signer (HSM, KMS, remote service). `mode` is declared when the
/// signer is bound and never changes. The callbacks run on the calling thread
/// during the signing call and are never retained after it returns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2ExternalSigner {
    pub user: *mut c_void,
    /// `RatifyV2SignerMode`; any other value is refused before any callback.
    pub mode: i32,
    pub public_key: RatifyV2SignerPublicKeyFn,
    pub sign: RatifyV2SignerSignFn,
}

/// The external signer as a [`SignerV2`]. It records why a callback failed so
/// the export can report cancellation exactly.
pub(crate) struct CSigner {
    cb: RatifyV2ExternalSigner,
    mode: SignerModeV2,
    cancel: V2CancelHandle,
    key: Mutex<Option<HybridPublicKey>>,
    cancelled: Mutex<bool>,
}

// SAFETY: the callbacks run only on the thread that made the signing call;
// the adapter never leaves that call.
unsafe impl Send for CSigner {}
unsafe impl Sync for CSigner {}

impl SignerV2 for CSigner {
    fn public_key_v2(&self) -> HybridPublicKey {
        let mut cached = self.key.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(k) = cached.as_ref() {
            return k.clone();
        }
        let empty = HybridPublicKey {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        };
        let Some(f) = self.cb.public_key else {
            return empty;
        };
        let mut out = RatifyV2PublicKey {
            ed25519: [0; 32],
            ml_dsa_65: [0; 1952],
        };
        // SAFETY: the caller supplied a valid callback and user pointer.
        let code = unsafe { f(self.cb.user, &mut out) };
        if code != 0 {
            if code == RatifyV2Code::RatifyV2ErrCancelled as i32 {
                *self.cancelled.lock().unwrap_or_else(|p| p.into_inner()) = true;
                self.cancel.cancel();
            }
            return empty;
        }
        let key = out.as_hybrid();
        *cached = Some(key.clone());
        key
    }

    fn mode_v2(&self) -> SignerModeV2 {
        self.mode
    }

    fn sign_v2(&self, ctx: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature> {
        if ctx.is_done() {
            return Err(V2SignError::Cancelled);
        }
        let Some(f) = self.cb.sign else {
            return Err(V2SignError::Provider(
                "external signer has no sign callback".into(),
            ));
        };
        let mut key = RatifyV2PublicKey {
            ed25519: [0; 32],
            ml_dsa_65: [0; 1952],
        };
        if request.public_key.ed25519.len() == 32 && request.public_key.ml_dsa_65.len() == 1952 {
            key.ed25519.copy_from_slice(&request.public_key.ed25519);
            key.ml_dsa_65.copy_from_slice(&request.public_key.ml_dsa_65);
        }
        let key_id = CString::new(request.key_id.clone()).unwrap_or_default();
        let empty: &[u8] = &[];
        let view = RatifyV2SignRequest {
            mode: match request.mode {
                SignerModeV2::Direct => RatifyV2SignerMode::RatifyV2SignerDirect as i32,
                SignerModeV2::ExternalMu => RatifyV2SignerMode::RatifyV2SignerExternalMu as i32,
            },
            message: RatifyV2Slice::of(&request.message),
            ml_dsa_context: RatifyV2Slice::of(request.ml_dsa_context.as_deref().unwrap_or(empty)),
            ml_dsa_mu: RatifyV2Slice::of(request.ml_dsa_mu.as_deref().unwrap_or(empty)),
            public_key: &key,
            key_id: key_id.as_ptr(),
        };
        let mut out = RatifyV2Signature::zeroed();
        // SAFETY: the caller supplied a valid callback and user pointer; the
        // view's buffers outlive the call.
        let code = unsafe { f(self.cb.user, &view, &mut out) };
        if code == RatifyV2Code::RatifyV2ErrCancelled as i32 {
            *self.cancelled.lock().unwrap_or_else(|p| p.into_inner()) = true;
            self.cancel.cancel();
            return Err(V2SignError::Cancelled);
        }
        if code != 0 {
            return Err(V2SignError::Provider(format!(
                "external signer refused ({})",
                super::code_str(code)
            )));
        }
        if out.ed25519_len > 64 || out.ml_dsa_65_len > 3309 {
            return Err(V2SignError::Provider(
                "external signer reported an oversized component".into(),
            ));
        }
        Ok(out.as_hybrid())
    }
}

/// One selected signer: a library key pair or an external signer.
pub(crate) enum Built {
    Local(LocalSignerV2),
    External(CSigner),
}

impl Built {
    pub(crate) fn signer(&self) -> &dyn SignerV2 {
        match self {
            Built::Local(s) => s,
            Built::External(s) => s,
        }
    }

    pub(crate) fn cancelled(&self) -> bool {
        match self {
            Built::Local(_) => false,
            Built::External(s) => *s.cancelled.lock().unwrap_or_else(|p| p.into_inner()),
        }
    }
}

/// Select the signer of one slot: exactly one of `local` and `external` must
/// be non-NULL. External signers share `cancel`.
pub(crate) unsafe fn build(
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    name: &str,
    cancel: &V2CancelHandle,
) -> AbiResult<Built> {
    match (local.as_ref(), external.as_ref()) {
        (Some(kp), None) => Ok(Built::Local(LocalSignerV2::new(&kp.private)?)),
        (None, Some(ext)) => {
            let mode = match ext.mode {
                1 => SignerModeV2::Direct,
                2 => SignerModeV2::ExternalMu,
                other => {
                    return Err(Failure::new(
                        RatifyV2Code::RatifyV2SignUnsupportedMode,
                        format!("{name}: external signer mode {other} is not supported"),
                    ))
                }
            };
            Ok(Built::External(CSigner {
                cb: *ext,
                mode,
                cancel: cancel.clone(),
                key: Mutex::new(None),
                cancelled: Mutex::new(false),
            }))
        }
        (None, None) => Err(null_arg(&format!("{name} signer (local or external)"))),
        (Some(_), Some(_)) => Err(bad_arg(format!(
            "{name}: pass either a local key pair or an external signer, not both"
        ))),
    }
}

/// Map a signing result, reporting a signer cancellation as
/// `RatifyV2ErrCancelled`.
pub(crate) fn finish<R>(result: V2SignResult<R>, built: &[&Built]) -> AbiResult<R> {
    match result {
        Err(e) if built.iter().any(|b| b.cancelled()) => Err(Failure::new(
            RatifyV2Code::RatifyV2ErrCancelled,
            format!("signer cancelled: {e}"),
        )),
        other => Ok(other?),
    }
}

/// Run `f` with the one signer the caller selected.
pub(crate) unsafe fn with_signer<R>(
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    name: &str,
    f: impl FnOnce(&V2Context, &dyn SignerV2) -> V2SignResult<R>,
) -> AbiResult<R> {
    let (ctx, cancel) = V2Context::background().with_cancel();
    let built = build(local, external, name, &cancel)?;
    finish(f(&ctx, built.signer()), &[&built])
}

/// Run `f` with two signers (rotation: old key, new key).
unsafe fn with_two_signers<R>(
    first: (*const RatifyV2KeyPair, *const RatifyV2ExternalSigner),
    second: (*const RatifyV2KeyPair, *const RatifyV2ExternalSigner),
    f: impl FnOnce(&V2Context, &dyn SignerV2, &dyn SignerV2) -> V2SignResult<R>,
) -> AbiResult<R> {
    let (ctx, cancel) = V2Context::background().with_cancel();
    let a = build(first.0, first.1, "old", &cancel)?;
    let b = build(second.0, second.1, "new", &cancel)?;
    finish(f(&ctx, a.signer(), b.signer()), &[&a, &b])
}

fn placeholder_sig() -> Value {
    json!({"ed25519": b64(&[0u8; 64]), "ml_dsa_65": b64(&[0u8; 3309])})
}

/// Parse an object for signing: signature members that are absent are filled
/// with a well-formed placeholder (their values are replaced by signing),
/// then the object is canonicalized for the strict decoder.
unsafe fn signing_input(
    ptr: *const u8,
    len: usize,
    sig_fields: &[&str],
    extra: &[(&str, Value)],
) -> AbiResult<Vec<u8>> {
    let mut v = json_bytes(ptr, len, "object")?;
    let m = v
        .as_object_mut()
        .ok_or_else(|| bad_arg("object must be a JSON object"))?;
    for f in sig_fields {
        m.entry(f.to_string()).or_insert_with(placeholder_sig);
    }
    for (k, x) in extra {
        m.entry(k.to_string()).or_insert_with(|| x.clone());
    }
    Ok(canonical_json_v2(&to_bytes(&v))?)
}

fn key_arg(k: *const RatifyV2PublicKey, name: &str) -> AbiResult<HybridPublicKey> {
    // SAFETY: a non-NULL key points to caller storage.
    unsafe { k.as_ref() }
        .map(RatifyV2PublicKey::as_hybrid)
        .ok_or_else(|| null_arg(name))
}

/// Sign a delegation certificate (code 0x0001) with the issuer key. `object`
/// is the certificate wire JSON; an absent `signature` is allowed. Issuer
/// duties (§5.1, §5.2) are checked before any signer method runs and refuse
/// with `RatifyV2SignIssuerDuty`. On success `*out` is the canonical signed
/// certificate.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_delegation_certificate(
    object: *const u8,
    object_len: usize,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let cert = decode_delegation_cert_v2(&signing_input(
                object,
                object_len,
                &["signature"],
                &[],
            )?)?;
            let signed = with_signer(local, external, "issuer", |ctx, s| {
                sign_delegation_cert_v2_with_signer(ctx, &cert, s)
            })?;
            write_buffer(out, encode_delegation_cert_v2(&signed)?)
        },
    )
}

/// Sign a proof bundle's challenge presentation (code 0x0002) with the agent
/// key. `delegation_digest` and `challenge_sig` may be absent; the digest is
/// recomputed. The embedded certificates must already be signed.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_proof_bundle(
    object: *const u8,
    object_len: usize,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let wire = signing_input(
                object,
                object_len,
                &["challenge_sig"],
                &[("delegation_digest", json!(b64(&[0u8; 48])))],
            )?;
            let bundle = decode_proof_bundle_v2(&wire)?;
            let signed = with_signer(local, external, "agent", |ctx, s| {
                sign_proof_bundle_v2_with_signer(ctx, &bundle, s)
            })?;
            write_buffer(out, encode_proof_bundle_v2(&signed)?)
        },
    )
}

/// Sign a revocation list (code 0x0003) with the status key bound to
/// `bound_issuer_id` by caller-authenticated configuration; the signer's key
/// must equal `bound_status_key`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_revocation_list(
    object: *const u8,
    object_len: usize,
    bound_issuer_id: *const c_char,
    bound_status_key: *const RatifyV2PublicKey,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let list = decode_revocation_list_v2(&signing_input(
                object,
                object_len,
                &["signature"],
                &[],
            )?)?;
            let issuer = cstr(bound_issuer_id, "bound_issuer_id")?;
            let key = key_arg(bound_status_key, "bound_status_key")?;
            let signed = with_signer(local, external, "status", |ctx, s| {
                sign_revocation_list_v2_with_signer(ctx, &list, issuer, &key, s)
            })?;
            write_buffer(out, encode_revocation_list_v2(&signed)?)
        },
    )
}

/// Sign a revocation push (code 0x0005); see
/// `ratify_v2_sign_revocation_list`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_revocation_push(
    object: *const u8,
    object_len: usize,
    bound_issuer_id: *const c_char,
    bound_status_key: *const RatifyV2PublicKey,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let push = decode_revocation_push_v2(&signing_input(
                object,
                object_len,
                &["signature"],
                &[],
            )?)?;
            let issuer = cstr(bound_issuer_id, "bound_issuer_id")?;
            let key = key_arg(bound_status_key, "bound_status_key")?;
            let signed = with_signer(local, external, "status", |ctx, s| {
                sign_revocation_push_v2_with_signer(ctx, &push, issuer, &key, s)
            })?;
            write_buffer(out, encode_revocation_push_v2(&signed)?)
        },
    )
}

/// Sign a key-rotation statement under both codes: 0x0004 with the current
/// (old) key and 0x0009 with the new key. Each signer slot takes exactly one
/// of a local key pair or an external signer.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_key_rotation_statement(
    object: *const u8,
    object_len: usize,
    old_local: *const RatifyV2KeyPair,
    old_external: *const RatifyV2ExternalSigner,
    new_local: *const RatifyV2KeyPair,
    new_external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(old_local), flag(new_local)],
        || clear_buffer(out),
        || {
            let stmt = decode_key_rotation_statement_v2(&signing_input(
                object,
                object_len,
                &["old_signature", "new_signature"],
                &[],
            )?)?;
            let signed = with_two_signers(
                (old_local, old_external),
                (new_local, new_external),
                |ctx, a, b| sign_key_rotation_statement_v2_with_signers(ctx, &stmt, a, b),
            )?;
            write_buffer(out, encode_key_rotation_statement_v2(&signed)?)
        },
    )
}

/// Sign a witness entry (code 0x0006) with the named witness key.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_witness_entry(
    object: *const u8,
    object_len: usize,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let entry =
                decode_witness_entry_v2(&signing_input(object, object_len, &["signature"], &[])?)?;
            let signed = with_signer(local, external, "witness", |ctx, s| {
                sign_witness_entry_v2_with_signer(ctx, &entry, s)
            })?;
            write_buffer(out, encode_witness_entry_v2(&signed)?)
        },
    )
}

/// Sign a complete verification receipt (code 0x0008) with the verifier key.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_verification_receipt(
    object: *const u8,
    object_len: usize,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let r = decode_verification_receipt_v2(&signing_input(
                object,
                object_len,
                &["signature"],
                &[],
            )?)?;
            let signed = with_signer(local, external, "verifier", |ctx, s| {
                sign_verification_receipt_v2_with_signer(ctx, &r, s)
            })?;
            write_buffer(out, encode_verification_receipt_v2(&signed)?)
        },
    )
}

/// Bind a sealed receipt outbox body to the next position of a receipt log
/// (`head_json`, the receipt-log head schema of `ratify_v2_verify_object`) and
/// sign it with the verifier key: the receipt publisher's operation (§7.7).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_prepared_verification_receipt(
    body: *const u8,
    body_len: usize,
    head_json: *const u8,
    head_json_len: usize,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let body = bytes(body, body_len, "body")?;
            let head = receipt_head(&json_bytes(head_json, head_json_len, "head_json")?)?;
            let signed = with_signer(local, external, "verifier", |ctx, s| {
                sign_prepared_verification_receipt_v2_with_signer(ctx, body, &head, s)
            })?;
            write_buffer(out, encode_verification_receipt_v2(&signed)?)
        },
    )
}

/// Parse a transaction receipt whose party signature set may be incomplete.
fn transaction_template(v: &Value) -> AbiResult<TransactionReceiptV2> {
    let o = Obj::new(
        v,
        "transaction receipt",
        &[
            "version",
            "transaction_id",
            "created_at",
            "terms_schema_uri",
            "terms_canonical_json",
            "parties",
            "party_signatures",
        ],
    )?;
    let mut parties = Vec::new();
    for p in o.array("parties")? {
        let po = Obj::new(
            p,
            "party",
            &[
                "party_id",
                "role",
                "agent_id",
                "agent_pub_key",
                "verifier_id",
                "workspace_id",
                "session_id",
                "invocation_id",
                "required_scope",
                "proof_bundle_hash",
                "proof_bundle",
            ],
        )?;
        let bundle = match po.raw("proof_bundle") {
            Some(b) => Some(decode_proof_bundle_v2(&canonical_json_v2(&to_bytes(b))?)?),
            None => None,
        };
        parties.push(TransactionReceiptPartyV2 {
            party_id: po.str("party_id")?,
            role: po.str("role")?,
            agent_id: po.str("agent_id")?,
            agent_pub_key: public_key(
                po.raw("agent_pub_key").unwrap_or(&Value::Null),
                "agent_pub_key",
            )?,
            verifier_id: po.str("verifier_id")?,
            workspace_id: po.str("workspace_id")?,
            session_id: po.str("session_id")?,
            invocation_id: po.str("invocation_id")?,
            required_scope: po.str("required_scope")?,
            proof_bundle_hash: po.str("proof_bundle_hash")?,
            proof_bundle: bundle,
        });
    }
    let mut sigs = Vec::new();
    for s in o.array("party_signatures")? {
        let so = Obj::new(s, "party signature", &["party_id", "signature"])?;
        let sig = so.raw("signature").unwrap_or(&Value::Null);
        let sig = Obj::new(sig, "signature", &["ed25519", "ml_dsa_65"])?;
        sigs.push(TransactionReceiptSignatureV2 {
            party_id: so.str("party_id")?,
            signature: HybridSignature {
                ed25519: sig.b64("ed25519")?,
                ml_dsa_65: sig.b64("ml_dsa_65")?,
            },
        });
    }
    let terms = o.str("terms_canonical_json")?;
    Ok(TransactionReceiptV2 {
        version: o.i64("version")?,
        transaction_id: o.str("transaction_id")?,
        created_at: o.i64("created_at")?,
        terms_schema_uri: o.str("terms_schema_uri")?,
        terms_canonical_json: base64_std_decode(&terms)
            .map_err(|e| bad_arg(format!("terms_canonical_json: {e}")))?,
        parties,
        party_signatures: sigs,
    })
}

/// Sign the shared transaction statement (code 0x0007) as party `party_id`
/// with that party's agent key. `object` is the transaction receipt JSON
/// whose `party_signatures` may be incomplete (each party signs separately).
/// On success `*out` is the same receipt with this party's signature added
/// (replacing any earlier one) in canonical form; once every party has
/// signed, it is the canonical receipt wire.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_sign_transaction_receipt_party(
    object: *const u8,
    object_len: usize,
    party_id: *const c_char,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || clear_buffer(out),
        || {
            let mut v = json_bytes(object, object_len, "object")?;
            let r = transaction_template(&v)?;
            let party = cstr(party_id, "party_id")?;
            let sig = with_signer(local, external, "party", |ctx, s| {
                sign_transaction_receipt_party_v2_with_signer(ctx, &r, party, s)
            })?;
            let m = v
                .as_object_mut()
                .ok_or_else(|| bad_arg("object must be a JSON object"))?;
            let mut sigs: Vec<Value> = match m.remove("party_signatures") {
                Some(Value::Array(a)) => a,
                _ => Vec::new(),
            };
            sigs.retain(|s| s.get("party_id").and_then(Value::as_str) != Some(party));
            let mut entry = Map::new();
            entry.insert("party_id".into(), json!(party));
            entry.insert(
            "signature".into(),
            json!({"ed25519": b64(&sig.signature.ed25519), "ml_dsa_65": b64(&sig.signature.ml_dsa_65)}),
        );
            sigs.push(Value::Object(entry));
            sigs.sort_by(|a, b| {
                let pa = a.get("party_id").and_then(Value::as_str).unwrap_or("");
                let pb = b.get("party_id").and_then(Value::as_str).unwrap_or("");
                pa.as_bytes().cmp(pb.as_bytes())
            });
            m.insert("party_signatures".into(), Value::Array(sigs));
            write_buffer(out, canonical_json_v2(&to_bytes(&v))?)
        },
    )
}

impl Built {
    /// The signer as a shared trait object (for APIs that hold a signer for
    /// the duration of one call).
    pub(crate) fn into_arc(self) -> std::sync::Arc<dyn SignerV2> {
        match self {
            Built::Local(s) => std::sync::Arc::new(s),
            Built::External(s) => std::sync::Arc::new(s),
        }
    }
}
