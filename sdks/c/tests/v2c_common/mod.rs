//! Shared harness for the C-ABI conformance runners (`tests/v2c_*.rs`).
//!
//! Every Protocol operation goes through the `extern "C"` functions of
//! `ratify_c`; nothing here calls the Rust `ratify-protocol` crate. JSON,
//! base64, and hex handling is harness plumbing for corpus data. Scripted
//! providers and stores are implemented as C callbacks (`extern "C"`
//! trampolines over Rust closures) so every scenario crosses the callback
//! interface exactly as a C deployment does.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_c::*;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Corpus

pub fn sdk_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn corpus_dir() -> PathBuf {
    sdk_dir().join("../../testvectors/v2")
}

pub fn load(name: &str) -> Value {
    let p = corpus_dir().join(name);
    let data = std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

pub fn b64(v: &Value) -> Vec<u8> {
    STANDARD
        .decode(
            v.as_str()
                .unwrap_or_else(|| panic!("expected base64 string, got {v}")),
        )
        .expect("base64")
}

pub fn enc(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// Zero-value accessors (absent or null is the zero value).
pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}
pub fn i(v: &Value) -> i64 {
    v.as_i64().unwrap_or_default()
}
pub fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_default()
}
pub fn b(v: &Value) -> bool {
    v.as_bool().unwrap_or_default()
}
pub fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

/// The README row for a corpus file.
pub fn readme_line(file: &str) -> String {
    let readme = std::fs::read_to_string(corpus_dir().join("README.md")).expect("README");
    readme
        .lines()
        .find(|l| l.starts_with(&format!("| `{file}`")))
        .unwrap_or_else(|| panic!("README has no row for {file}"))
        .to_string()
}

// ---------------------------------------------------------------------------
// ABI results

/// An ABI failure: the code, its stable spelling, and the diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub code: i32,
    pub class: String,
    pub message: String,
}

pub type R<T> = Result<T, Fail>;

pub fn class(code: i32) -> String {
    unsafe { CStr::from_ptr(ratify_v2_error_class_str(code)) }
        .to_str()
        .unwrap()
        .to_string()
}

pub fn last_error() -> String {
    unsafe { CStr::from_ptr(ratify_v2_last_error_message()) }
        .to_string_lossy()
        .into_owned()
}

/// Map a return code to a result, capturing the thread-local diagnostic.
pub fn check(code: i32) -> R<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Fail {
            code,
            class: class(code),
            message: last_error(),
        })
    }
}

/// "ok" or the class spelling of a result.
pub fn class_of<T>(r: &R<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(f) => f.class.clone(),
    }
}

pub fn empty_buf() -> RatifyV2Buffer {
    RatifyV2Buffer {
        ptr: ptr::null_mut(),
        len: 0,
    }
}

/// Take ownership of a library buffer.
pub fn take(b: RatifyV2Buffer) -> Vec<u8> {
    let v = if b.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    };
    unsafe { ratify_v2_buffer_free(b) };
    v
}

/// Call a buffer-producing export.
pub fn buf(f: impl FnOnce(*mut RatifyV2Buffer) -> i32) -> R<Vec<u8>> {
    let mut out = empty_buf();
    let code = f(&mut out);
    let data = take(out);
    check(code).map(|_| data)
}

/// Take ownership of a library string.
pub fn take_str(p: *mut c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { ratify_v2_string_free(p) };
    s
}

/// Call a string-producing export.
pub fn string(f: impl FnOnce(*mut *mut c_char) -> i32) -> R<String> {
    let mut out: *mut c_char = ptr::null_mut();
    let code = f(&mut out);
    let s = take_str(out);
    check(code).map(|_| s)
}

pub fn cs(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

/// A non-NULL pointer for possibly-empty input (the ABI rejects NULL).
pub fn ptr_of(b: &[u8]) -> *const u8 {
    if b.is_empty() {
        [0u8].as_ptr()
    } else {
        b.as_ptr()
    }
}

pub fn slice(b: &[u8]) -> RatifyV2Slice {
    RatifyV2Slice {
        ptr: ptr_of(b),
        len: b.len(),
    }
}

pub fn null_slice() -> RatifyV2Slice {
    RatifyV2Slice {
        ptr: ptr::null(),
        len: 0,
    }
}

pub fn json_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

pub fn parse(b: &[u8]) -> Value {
    serde_json::from_slice(b)
        .unwrap_or_else(|e| panic!("library JSON: {e}: {}", String::from_utf8_lossy(b)))
}

// ---------------------------------------------------------------------------
// Keys

pub fn zero_key() -> RatifyV2PublicKey {
    RatifyV2PublicKey {
        ed25519: [0; 32],
        ml_dsa_65: [0; 1952],
    }
}

/// A public key struct from `{"ed25519","ml_dsa_65"}` JSON (exact lengths).
pub fn key_struct(v: &Value) -> RatifyV2PublicKey {
    let mut k = zero_key();
    let (ed, ml) = (b64(&v["ed25519"]), b64(&v["ml_dsa_65"]));
    assert_eq!((ed.len(), ml.len()), (32, 1952), "key component lengths");
    k.ed25519.copy_from_slice(&ed);
    k.ml_dsa_65.copy_from_slice(&ml);
    k
}

pub fn key_json(k: &RatifyV2PublicKey) -> Value {
    json!({"ed25519": enc(&k.ed25519), "ml_dsa_65": enc(&k.ml_dsa_65)})
}

/// A library key pair handle.
pub struct Kp(pub *mut RatifyV2KeyPair);

unsafe impl Send for Kp {}
unsafe impl Sync for Kp {}

impl Kp {
    pub fn from_seeds(ed: &[u8], ml: &[u8]) -> Kp {
        assert_eq!((ed.len(), ml.len()), (32, 32));
        let mut out = ptr::null_mut();
        check(unsafe { ratify_v2_keypair_from_seeds(ed.as_ptr(), ml.as_ptr(), &mut out) })
            .expect("keypair");
        Kp(out)
    }

    /// A fresh key pair and its seeds.
    pub fn generate() -> (Kp, [u8; 32], [u8; 32]) {
        let mut out = ptr::null_mut();
        let (mut ed, mut ml) = ([0u8; 32], [0u8; 32]);
        check(unsafe { ratify_v2_keypair_generate(&mut out, ed.as_mut_ptr(), ml.as_mut_ptr()) })
            .expect("generate");
        (Kp(out), ed, ml)
    }

    pub fn public(&self) -> RatifyV2PublicKey {
        let mut k = zero_key();
        check(unsafe { ratify_v2_keypair_public_key(self.0, &mut k) }).expect("public key");
        k
    }

    pub fn id(&self) -> String {
        let mut out = [0 as c_char; RATIFY_V2_KEY_ID_BUF_LEN];
        check(unsafe { ratify_v2_keypair_key_id(self.0, out.as_mut_ptr(), out.len()) })
            .expect("key id");
        unsafe { CStr::from_ptr(out.as_ptr()) }
            .to_str()
            .unwrap()
            .to_string()
    }
}

impl Drop for Kp {
    fn drop(&mut self) {
        unsafe { ratify_v2_keypair_free(self.0) };
    }
}

pub fn key_id_of(k: &RatifyV2PublicKey) -> R<String> {
    let mut out = [0 as c_char; RATIFY_V2_KEY_ID_BUF_LEN];
    check(unsafe { ratify_v2_public_key_id(k, out.as_mut_ptr(), out.len()) })?;
    Ok(unsafe { CStr::from_ptr(out.as_ptr()) }
        .to_str()
        .unwrap()
        .to_string())
}

/// The keys.json fixture, every key derived through the ABI from its seeds.
pub struct Fixture {
    pub kp: BTreeMap<String, Kp>,
    pub public: BTreeMap<String, RatifyV2PublicKey>,
    pub id: BTreeMap<String, String>,
}

impl Fixture {
    pub fn load() -> Fixture {
        let keys = load("keys.json");
        let mut fx = Fixture {
            kp: BTreeMap::new(),
            public: BTreeMap::new(),
            id: BTreeMap::new(),
        };
        for k in arr(&keys["keys"]) {
            let kp = Kp::from_seeds(
                &hex::decode(s(&k["ed25519_seed_hex"])).unwrap(),
                &hex::decode(s(&k["ml_dsa_65_seed_hex"])).unwrap(),
            );
            let name = s(&k["name"]);
            fx.public.insert(name.clone(), kp.public());
            fx.id.insert(name.clone(), kp.id());
            fx.kp.insert(name, kp);
        }
        fx
    }

    pub fn key(&self, name: &str) -> RatifyV2PublicKey {
        *self
            .public
            .get(name)
            .unwrap_or_else(|| panic!("unknown fixture key {name}"))
    }

    pub fn kp(&self, name: &str) -> &Kp {
        self.kp
            .get(name)
            .unwrap_or_else(|| panic!("unknown fixture key {name}"))
    }

    /// The key as wire JSON (zero key JSON for an unknown name).
    pub fn key_json(&self, name: &str) -> Value {
        self.public.get(name).map(key_json).unwrap_or(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Object helpers

pub fn kind_code(kind: &str) -> i32 {
    match kind {
        "delegation_certificate" => 1,
        "proof_bundle" => 2,
        "revocation_list" => 3,
        "key_rotation_statement" => 4,
        "revocation_push" => 5,
        "witness_entry" => 6,
        "transaction_receipt" => 7,
        "verification_receipt" => 8,
        "verification_receipt_body" => 100,
        "status_evidence_batch" => 101,
        "checkpoint_acknowledgement" => 102,
        other => panic!("unknown kind {other}"),
    }
}

/// Strict decode and canonical re-encode through the ABI.
pub fn canonicalize(kind: i32, wire: &[u8]) -> R<Vec<u8>> {
    buf(|o| unsafe { ratify_v2_object_decode(kind, ptr_of(wire), wire.len(), o) })
}

pub fn signable(code: u32, wire: &[u8]) -> R<Vec<u8>> {
    buf(|o| unsafe { ratify_v2_signable_bytes(code, ptr_of(wire), wire.len(), o) })
}

pub fn message(code: u32, signable: &[u8]) -> R<Vec<u8>> {
    buf(|o| unsafe { ratify_v2_signing_message(code, ptr_of(signable), signable.len(), o) })
}

pub fn context(code: u32) -> R<Vec<u8>> {
    buf(|o| unsafe { ratify_v2_mldsa_context(code, o) })
}

pub fn mu(key: &RatifyV2PublicKey, code: u32, m: &[u8]) -> R<Vec<u8>> {
    buf(|o| unsafe { ratify_v2_external_mu(key, code, ptr_of(m), m.len(), o) })
}

pub fn verify_statement(
    code: u32,
    signable: &[u8],
    ed: &[u8],
    ml: &[u8],
    key: &RatifyV2PublicKey,
) -> R<()> {
    check(unsafe {
        ratify_v2_verify_statement(
            code,
            ptr_of(signable),
            signable.len(),
            slice(ed),
            slice(ml),
            key,
        )
    })
}

pub fn canonical_json(data: &[u8]) -> R<Vec<u8>> {
    buf(|o| unsafe { ratify_v2_canonical_json(ptr_of(data), data.len(), o) })
}

/// Canonical JSON of a harness value, through the ABI.
pub fn canon(v: &Value) -> Vec<u8> {
    canonical_json(&json_bytes(v)).expect("canonical json")
}

/// The verify-context JSON the ABI takes, with fixture key names resolved.
pub fn verify_context(vc: &Value, fx: &Fixture) -> Option<CString> {
    let obj = vc.as_object()?;
    if obj.is_empty() {
        return None;
    }
    let mut v = vc.clone();
    for f in ["status_key", "witness_key", "verifier_key"] {
        if let Some(name) = v.get(f).and_then(Value::as_str).map(str::to_owned) {
            v[f] = fx.key_json(&name);
        }
    }
    if let Some(name) = v
        .get("rotation_state")
        .and_then(|r| r.get("current_key"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        v["rotation_state"]["current_key"] = fx.key_json(&name);
    }
    Some(CString::new(v.to_string()).unwrap())
}

/// The per-kind decode-and-verify procedure of object-negatives.json.
pub fn verify_object(fx: &Fixture, kind: &str, wire: &[u8], bundle: &[u8], vc: &Value) -> R<()> {
    let ctx = verify_context(vc, fx);
    let code = unsafe {
        if kind == "receipt_bundle_binding" {
            ratify_v2_receipt_bundle_binding_check(
                ptr_of(wire),
                wire.len(),
                ptr_of(bundle),
                bundle.len(),
                ptr::null_mut(),
            )
        } else {
            ratify_v2_verify_object(
                kind_code(kind),
                ptr_of(wire),
                wire.len(),
                ctx.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                ptr::null_mut(),
            )
        }
    };
    check(code)
}

// ---------------------------------------------------------------------------
// Tally

/// Per-row pass/total counts; fails on any mismatch.
#[derive(Default)]
pub struct Tally {
    rows: BTreeMap<String, (usize, usize)>,
    failures: Vec<String>,
}

impl Tally {
    pub fn check(&mut self, row: &str, name: &str, ok: bool, detail: impl FnOnce() -> String) {
        let e = self.rows.entry(row.to_string()).or_default();
        e.1 += 1;
        if ok {
            e.0 += 1;
        } else {
            self.failures.push(format!("[{row}] {name}: {}", detail()));
        }
    }

    pub fn total(&self, row: &str) -> usize {
        self.rows.get(row).map_or(0, |r| r.1)
    }

    /// Fail on any mismatch; require each listed row to have run exactly the
    /// stated number of checks (computed from the corpus, never hard-coded).
    pub fn finish(self, exact_rows: &[(&str, usize)]) {
        for (row, (pass, total)) in &self.rows {
            println!("C-ABI COVERAGE {row}: {pass}/{total}");
        }
        for (row, want) in exact_rows {
            let total = self.rows.get(*row).map_or(0, |r| r.1);
            assert_eq!(total, *want, "{row}: ran {total} checks, expected {want}");
            assert!(*want > 0, "{row}: no checks ran");
        }
        assert!(
            self.failures.is_empty(),
            "{} failure(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Callback plumbing: Rust closures behind C function pointers

/// Copy a C string a callback received.
pub unsafe fn cstr_in(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

pub unsafe fn slice_in(s: RatifyV2Slice) -> Vec<u8> {
    if s.ptr.is_null() || s.len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(s.ptr, s.len).to_vec()
    }
}

/// Owned output storage a callback hands back by pointer: it lives in the
/// provider until the next call, after the library copied it.
#[derive(Default)]
pub struct Keep {
    bytes: Mutex<Vec<Vec<u8>>>,
    strings: Mutex<Vec<CString>>,
}

impl Keep {
    pub fn bytes(&self, b: Vec<u8>) -> RatifyV2Slice {
        let mut v = self.bytes.lock().unwrap();
        v.push(b);
        let last = v.last().unwrap();
        RatifyV2Slice {
            ptr: if last.is_empty() {
                ptr::null()
            } else {
                last.as_ptr()
            },
            len: last.len(),
        }
    }

    pub fn str(&self, s: &str) -> *const c_char {
        let mut v = self.strings.lock().unwrap();
        v.push(CString::new(s.replace('\0', "")).unwrap());
        v.last().unwrap().as_ptr()
    }
}

/// One certificate of a chain as the trust callback saw it.
#[derive(Debug, Clone)]
pub struct ChainCert {
    pub cert_id: String,
    pub issuer_id: String,
    pub subject_id: String,
}

pub type TrustFn =
    dyn Fn(&[ChainCert]) -> Result<(i32, Option<RatifyV2PublicKey>), i32> + Send + Sync;

/// A trust provider implemented by a Rust closure.
pub struct Trust(pub Box<TrustFn>);

unsafe extern "C" fn trust_tramp(
    user: *mut c_void,
    chain: *const RatifyV2CertView,
    len: usize,
    outcome: *mut i32,
    root: *mut RatifyV2PublicKey,
) -> i32 {
    let t = &*(user as *const Trust);
    let certs: Vec<ChainCert> = std::slice::from_raw_parts(chain, len)
        .iter()
        .map(|c| ChainCert {
            cert_id: cstr_in(c.cert_id),
            issuer_id: cstr_in(c.issuer_id),
            subject_id: cstr_in(c.subject_id),
        })
        .collect();
    match (t.0)(&certs) {
        Ok((o, k)) => {
            *outcome = o;
            if let Some(k) = k {
                *root = k;
            }
            0
        }
        Err(code) => code,
    }
}

impl Trust {
    pub fn callbacks(&self) -> RatifyV2TrustCallbacks {
        RatifyV2TrustCallbacks {
            user: self as *const Trust as *mut c_void,
            resolve: Some(trust_tramp),
        }
    }
}

/// What a status callback was asked.
#[derive(Debug, Clone)]
pub struct StatusReq {
    pub issuer_id: String,
    pub status_key_epoch: u64,
    pub status_key_id: String,
    pub refs: Vec<(String, String)>,
}

pub type StatusFn = dyn Fn(&StatusReq) -> Result<Vec<(u16, Vec<u8>)>, i32> + Send + Sync;

/// A status evidence provider implemented by a Rust closure.
pub struct Status {
    pub f: Box<StatusFn>,
    keep: Keep,
    objects: Mutex<Vec<RatifyV2StatusObject>>,
}

unsafe impl Send for Status {}
unsafe impl Sync for Status {}

impl Status {
    pub fn new(f: Box<StatusFn>) -> Status {
        Status {
            f,
            keep: Keep::default(),
            objects: Mutex::new(Vec::new()),
        }
    }

    pub fn callbacks(&self) -> RatifyV2StatusEvidenceCallbacks {
        RatifyV2StatusEvidenceCallbacks {
            user: self as *const Status as *mut c_void,
            fetch: Some(status_tramp),
        }
    }
}

unsafe extern "C" fn status_tramp(
    user: *mut c_void,
    req: *const RatifyV2StatusRequest,
    out: *mut RatifyV2StatusBatch,
) -> i32 {
    let st = &*(user as *const Status);
    let r = &*req;
    let refs = if r.refs_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(r.refs, r.refs_len)
            .iter()
            .map(|x| (cstr_in(x.issuer_id), cstr_in(x.cert_id)))
            .collect()
    };
    let q = StatusReq {
        issuer_id: cstr_in(r.issuer_id),
        status_key_epoch: r.status_key_epoch,
        status_key_id: cstr_in(r.status_key_id),
        refs,
    };
    match (st.f)(&q) {
        Ok(objs) => {
            let mut keep = st.objects.lock().unwrap();
            keep.clear();
            for (code, wire) in objs {
                let wire = st.keep.bytes(wire);
                keep.push(RatifyV2StatusObject {
                    object_type: code,
                    wire,
                });
            }
            *out = RatifyV2StatusBatch {
                objects: if keep.is_empty() {
                    ptr::null()
                } else {
                    keep.as_ptr()
                },
                count: keep.len(),
            };
            0
        }
        Err(code) => code,
    }
}

/// One audience membership answer.
#[derive(Debug, Clone, Default)]
pub struct Membership {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub receiver_id: String,
    pub trust_domain_ids: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub evidence_digest: String,
}

pub type AudienceFn = dyn Fn(&str) -> Result<Vec<Membership>, i32> + Send + Sync;

/// An audience provider implemented by a Rust closure (given the receiver).
pub struct Audience {
    pub f: Box<AudienceFn>,
    keep: Keep,
    out: Mutex<(Vec<RatifyV2AudienceMembership>, Vec<Vec<*const c_char>>)>,
}

unsafe impl Send for Audience {}
unsafe impl Sync for Audience {}

impl Audience {
    pub fn new(f: Box<AudienceFn>) -> Audience {
        Audience {
            f,
            keep: Keep::default(),
            out: Mutex::new((Vec::new(), Vec::new())),
        }
    }

    pub fn callbacks(&self) -> RatifyV2AudienceCallbacks {
        RatifyV2AudienceCallbacks {
            user: self as *const Audience as *mut c_void,
            lookup: Some(audience_tramp),
        }
    }
}

unsafe extern "C" fn audience_tramp(
    user: *mut c_void,
    _deferred: *const RatifyV2DeferredConstraint,
    _len: usize,
    receiver: *const c_char,
    out: *mut RatifyV2AudienceResult,
) -> i32 {
    let a = &*(user as *const Audience);
    match (a.f)(&cstr_in(receiver)) {
        Ok(ms) => {
            let mut keep = a.out.lock().unwrap();
            keep.0.clear();
            keep.1.clear();
            for m in &ms {
                keep.1
                    .push(m.trust_domain_ids.iter().map(|d| a.keep.str(d)).collect());
            }
            for (n, m) in ms.iter().enumerate() {
                let domains = &keep.1[n];
                let view = RatifyV2AudienceMembership {
                    delegation_index: m.delegation_index,
                    constraint_index: m.constraint_index,
                    receiver_id: a.keep.str(&m.receiver_id),
                    trust_domain_ids: if domains.is_empty() {
                        ptr::null()
                    } else {
                        domains.as_ptr()
                    },
                    trust_domain_ids_len: domains.len(),
                    issued_at: m.issued_at,
                    expires_at: m.expires_at,
                    evidence_digest: a.keep.str(&m.evidence_digest),
                };
                keep.0.push(view);
            }
            *out = RatifyV2AudienceResult {
                memberships: if keep.0.is_empty() {
                    ptr::null()
                } else {
                    keep.0.as_ptr()
                },
                count: keep.0.len(),
            };
            0
        }
        Err(code) => code,
    }
}

/// A rate reservation as a store saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rate {
    pub issuer_id: String,
    pub cert_id: String,
    pub window_s: i64,
    pub limit: i64,
}

pub unsafe fn rates_in(p: *const RatifyV2RateReservation, n: usize) -> Vec<Rate> {
    if n == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(p, n)
        .iter()
        .map(|r| Rate {
            issuer_id: cstr_in(r.issuer_id),
            cert_id: cstr_in(r.cert_id),
            window_s: r.window_s,
            limit: r.limit,
        })
        .collect()
}

pub type ReserveFn = dyn Fn(&[Rate]) -> i32 + Send + Sync;

/// A rate store implemented by a Rust closure.
pub struct RateStore(pub Box<ReserveFn>);

unsafe extern "C" fn reserve_tramp(
    user: *mut c_void,
    _claim_id: *const c_char,
    _token: RatifyV2Slice,
    _hash: *const c_char,
    batch: *const RatifyV2RateReservation,
    len: usize,
) -> i32 {
    let r = &*(user as *const RateStore);
    (r.0)(&rates_in(batch, len))
}

impl RateStore {
    pub fn callbacks(&self) -> RatifyV2RateCallbacks {
        RatifyV2RateCallbacks {
            user: self as *const RateStore as *mut c_void,
            rate_at_finalization: 0,
            reserve: Some(reserve_tramp),
        }
    }
}

pub type BindingFn = dyn Fn() -> i32 + Send + Sync;

/// A receiver-binding hook implemented by a Rust closure.
pub struct Binding(pub Box<BindingFn>);

unsafe extern "C" fn binding_tramp(
    user: *mut c_void,
    _bundle: RatifyV2Slice,
    _expected: RatifyV2Slice,
) -> i32 {
    ((*(user as *const Binding)).0)()
}

impl Binding {
    pub fn callbacks(&self) -> RatifyV2ReceiverBindingCallbacks {
        RatifyV2ReceiverBindingCallbacks {
            user: self as *const Binding as *mut c_void,
            check: Some(binding_tramp),
        }
    }
}

pub type NowFn = dyn Fn() -> Result<i64, i32> + Send + Sync;

/// A clock implemented by a Rust closure.
pub struct Clock(pub Box<NowFn>);

unsafe extern "C" fn clock_tramp(user: *mut c_void, out: *mut i64) -> i32 {
    match ((*(user as *const Clock)).0)() {
        Ok(t) => {
            *out = t;
            0
        }
        Err(c) => c,
    }
}

impl Clock {
    pub fn fixed(t: i64) -> Clock {
        Clock(Box::new(move || Ok(t)))
    }

    pub fn callbacks(&self) -> RatifyV2ClockCallbacks {
        RatifyV2ClockCallbacks {
            user: self as *const Clock as *mut c_void,
            now: Some(clock_tramp),
        }
    }
}

/// A journal store that forwards to another journal callback struct with
/// scripted failure modes (the ordering corpus's modal journal store).
pub struct ModalJournal {
    pub inner: RatifyV2JournalStoreCallbacks,
    pub mode: String,
    pub cas_calls: Mutex<usize>,
    keep: Keep,
}

unsafe impl Send for ModalJournal {}
unsafe impl Sync for ModalJournal {}

impl ModalJournal {
    pub fn new(inner: RatifyV2JournalStoreCallbacks, mode: &str) -> ModalJournal {
        ModalJournal {
            inner,
            mode: mode.to_string(),
            cas_calls: Mutex::new(0),
            keep: Keep::default(),
        }
    }

    pub fn callbacks(&self) -> RatifyV2JournalStoreCallbacks {
        RatifyV2JournalStoreCallbacks {
            user: self as *const ModalJournal as *mut c_void,
            load: Some(modal_load),
            compare_and_swap: Some(modal_cas),
        }
    }
}

unsafe extern "C" fn modal_load(user: *mut c_void, out: *mut RatifyV2JournalSnapshot) -> i32 {
    let m = &*(user as *const ModalJournal);
    match m.mode.as_str() {
        "load_error" => RatifyV2Code::RatifyV2StatusObjectRejected as i32,
        "unanchored" => {
            let code = (m.inner.load.unwrap())(m.inner.user, out);
            if code == 0 {
                (*out).digest = m.keep.str(&"e".repeat(96));
            }
            code
        }
        _ => (m.inner.load.unwrap())(m.inner.user, out),
    }
}

unsafe extern "C" fn modal_cas(
    user: *mut c_void,
    generation: u64,
    digest: *const c_char,
    next: *const RatifyV2JournalSnapshot,
) -> i32 {
    let m = &*(user as *const ModalJournal);
    let calls = {
        let mut c = m.cas_calls.lock().unwrap();
        *c += 1;
        *c
    };
    if m.mode == "cas_conflict" || (m.mode == "cas_conflict_once" && calls % 2 == 1) {
        return RatifyV2Code::RatifyV2StoreJournalConflict as i32;
    }
    (m.inner.compare_and_swap.unwrap())(m.inner.user, generation, digest, next)
}

// ---------------------------------------------------------------------------
// Reference stores (test-reference feature)

/// The reference Part B store.
pub struct RefStore(pub *mut RatifyV2RefStore);

unsafe impl Send for RefStore {}
unsafe impl Sync for RefStore {}

impl RefStore {
    pub fn new(now: i64, lease: i64, log_id: &str, verifier: &Kp) -> RefStore {
        let mut out = ptr::null_mut();
        let log = cs(log_id);
        check(unsafe { ratify_v2_ref_store_new(now, lease, log.as_ptr(), verifier.0, &mut out) })
            .expect("ref store");
        RefStore(out)
    }

    pub fn clone_store(&self) -> RefStore {
        let mut out = ptr::null_mut();
        check(unsafe { ratify_v2_ref_store_clone(self.0, &mut out) }).expect("clone");
        RefStore(out)
    }

    pub fn set_time(&self, t: i64) {
        check(unsafe { ratify_v2_ref_store_control(self.0, 1, t) }).unwrap();
    }

    pub fn set_ack_withheld(&self, w: bool) {
        check(unsafe { ratify_v2_ref_store_control(self.0, 2, i64::from(w)) }).unwrap();
    }

    pub fn set_signer_failure(&self, f: bool) {
        check(unsafe { ratify_v2_ref_store_control(self.0, 3, i64::from(f)) }).unwrap();
    }

    pub fn now(&self) -> i64 {
        let mut t = 0;
        check(unsafe { ratify_v2_ref_store_time(self.0, &mut t) }).unwrap();
        t
    }

    pub fn claim(&self, rate_at_finalization: bool) -> RatifyV2ClaimStoreCallbacks {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2ClaimStoreCallbacks>() };
        check(unsafe {
            ratify_v2_ref_store_callbacks(
                self.0,
                i32::from(rate_at_finalization),
                &mut c,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })
        .unwrap();
        c
    }

    pub fn rate(&self) -> RatifyV2RateCallbacks {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2RateCallbacks>() };
        check(unsafe {
            ratify_v2_ref_store_callbacks(
                self.0,
                1,
                ptr::null_mut(),
                &mut c,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })
        .unwrap();
        c
    }

    pub fn release(&self) -> RatifyV2ReleaseStoreCallbacks {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2ReleaseStoreCallbacks>() };
        check(unsafe {
            ratify_v2_ref_store_callbacks(
                self.0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut c,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })
        .unwrap();
        c
    }

    pub fn checkpoint(&self) -> RatifyV2CheckpointCallbacks {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2CheckpointCallbacks>() };
        check(unsafe {
            ratify_v2_ref_store_callbacks(
                self.0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut c,
                ptr::null_mut(),
            )
        })
        .unwrap();
        c
    }

    pub fn clock(&self) -> RatifyV2ClockCallbacks {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2ClockCallbacks>() };
        check(unsafe {
            ratify_v2_ref_store_callbacks(
                self.0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut c,
            )
        })
        .unwrap();
        c
    }

    /// Publish; on refusal returns the refusal name.
    pub fn publish(&self, claim_id: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        let id = cs(claim_id);
        let mut out = empty_buf();
        let mut refusal: *const c_char = ptr::null();
        let code = unsafe {
            ratify_v2_ref_store_publish(
                self.0,
                id.as_ptr(),
                ptr_of(body),
                body.len(),
                &mut out,
                &mut refusal,
            )
        };
        let wire = take(out);
        if code == 0 {
            Ok(wire)
        } else {
            Err(unsafe { cstr_in(refusal) })
        }
    }

    pub fn abandon(&self) -> Vec<String> {
        let v = parse(&buf(|o| unsafe { ratify_v2_ref_store_abandon(self.0, o) }).unwrap());
        arr(&v).iter().map(s).collect()
    }

    pub fn plant_release(&self, claim_id: &str, t: i64) {
        let id = cs(claim_id);
        check(unsafe { ratify_v2_ref_store_tamper(self.0, id.as_ptr(), 0, t) }).unwrap();
    }

    pub fn corrupt(&self, claim_id: &str) {
        let id = cs(claim_id);
        check(unsafe { ratify_v2_ref_store_tamper(self.0, id.as_ptr(), 1, 0) }).unwrap();
    }
}

impl Drop for RefStore {
    fn drop(&mut self) {
        unsafe { ratify_v2_ref_store_free(self.0) };
    }
}

/// The reference anchored journal store.
pub struct RefJournal(pub *mut RatifyV2RefJournal);

unsafe impl Send for RefJournal {}
unsafe impl Sync for RefJournal {}

impl RefJournal {
    pub fn new() -> RefJournal {
        let mut out = ptr::null_mut();
        check(unsafe { ratify_v2_ref_journal_new(&mut out) }).expect("journal");
        RefJournal(out)
    }

    pub fn callbacks(&self) -> RatifyV2JournalStoreCallbacks {
        let mut c = unsafe { std::mem::zeroed::<RatifyV2JournalStoreCallbacks>() };
        check(unsafe {
            ratify_v2_ref_journal_callbacks(self.0, &mut c, ptr::null_mut(), ptr::null_mut())
        })
        .unwrap();
        c
    }

    pub fn head(&self) -> (u64, String) {
        let mut g = 0;
        let d = string(|o| unsafe {
            ratify_v2_ref_journal_callbacks(self.0, ptr::null_mut(), &mut g, o)
        })
        .unwrap();
        (g, d)
    }
}

impl Drop for RefJournal {
    fn drop(&mut self) {
        unsafe { ratify_v2_ref_journal_free(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Verification request and journal population from corpus inputs

pub fn status_policy_struct(v: &Value) -> RatifyV2StatusPolicy {
    RatifyV2StatusPolicy {
        max_list_lifetime_seconds: i(&v["max_list_lifetime_seconds"]),
        max_status_age_seconds: i(&v["max_status_age_seconds"]),
        clock_skew_seconds: i(&v["clock_skew_seconds"]),
    }
}

/// The ABI `status_keys` member (`{"<issuer>": {"epoch", "public_key"}}`)
/// from corpus status keys (which also carry an informational key ID).
pub fn status_keys_json(v: &Value) -> Value {
    let mut m = Map::new();
    for (issuer, k) in v.as_object().cloned().unwrap_or_default() {
        m.insert(
            issuer,
            json!({"epoch": k["epoch"], "public_key": k["public_key"]}),
        );
    }
    Value::Object(m)
}

/// The ABI request JSON for verifier-ordering style inputs.
pub fn request_json(inputs: &Value) -> Value {
    let mut r = Map::new();
    r.insert("required_scope".into(), inputs["required_scope"].clone());
    r.insert(
        "verifier_namespace".into(),
        inputs["configured_namespace"].clone(),
    );
    r.insert(
        "replay_epoch".into(),
        inputs["configured_replay_epoch"].clone(),
    );
    r.insert("now".into(), inputs["now"].clone());
    r.insert(
        "max_challenge_age_seconds".into(),
        inputs["max_challenge_age_seconds"].clone(),
    );
    r.insert(
        "future_skew_seconds".into(),
        inputs["future_skew_seconds"].clone(),
    );
    r.insert("tzdb_version".into(), inputs["tzdb_version"].clone());
    r.insert(
        "status_keys".into(),
        status_keys_json(&inputs["status_keys"]),
    );
    r.insert("status_policy".into(), inputs["status_policy"].clone());
    let e = &inputs["expected_challenge"];
    if !e.is_null() {
        let mut exp = Map::new();
        for k in [
            "value_b64",
            "issued_at",
            "expires_at",
            "verifier_namespace",
            "replay_epoch",
            "verifier_id",
        ] {
            exp.insert(k.into(), e[k].clone());
        }
        if !e["expected_agent_id"].is_null() {
            exp.insert("expected_agent_id".into(), e["expected_agent_id"].clone());
            if !e["expected_agent_public_key"].is_null() {
                exp.insert(
                    "expected_agent_public_key".into(),
                    e["expected_agent_public_key"].clone(),
                );
            }
        }
        for k in ["expected_receiver_id", "expected_session_context_b64"] {
            if !e[k].is_null() {
                exp.insert(k.into(), e[k].clone());
            }
        }
        r.insert("expected_challenge".into(), Value::Object(exp));
    }
    let p = &inputs["context_policy"];
    if !p.is_null() {
        r.insert(
            "context_policy".into(),
            json!({
                "profile": p["profile"],
                "require_bound": p["require_bound"],
                "required_fields": p["required_fields"],
                "expected_session_context_b64": p["expected_session_context_b64"],
            }),
        );
    }
    let c = &inputs["request_context"];
    if !c.is_null() {
        r.insert("context".into(), c.clone());
    }
    Value::Object(r)
}

/// Configure every status key and apply every preload object through the
/// journal callbacks (Go `v2PopulateStatusJournal`).
pub fn populate_status_journal(journal: &RatifyV2JournalStoreCallbacks, inputs: &Value) {
    let keys = inputs["status_keys"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let policy = status_policy_struct(&inputs["status_policy"]);
    for (issuer, key) in &keys {
        let id = cs(issuer);
        let k = key_struct(&key["public_key"]);
        check(unsafe {
            ratify_v2_journal_configure_status_key(journal, id.as_ptr(), u(&key["epoch"]), &k)
        })
        .unwrap_or_else(|e| panic!("configure status key for {issuer}: {e:?}"));
    }
    for p in arr(&inputs["journal"]["preload"]) {
        let issuer = s(&p["issuer_id"]);
        let key = &keys[&issuer];
        let k = key_struct(&key["public_key"]);
        let wire = b64(&p["wire_b64"]);
        let id = cs(&issuer);
        check(unsafe {
            ratify_v2_journal_apply(
                journal,
                u(&p["object_type_code"]) as i32,
                ptr_of(&wire),
                wire.len(),
                id.as_ptr(),
                u(&key["epoch"]),
                &k,
                &policy,
                i(&p["now"]),
            )
        })
        .unwrap_or_else(|e| panic!("preload: {e:?}"));
    }
}

pub fn evidence_json(v: &Value) -> Value {
    json!({
        "issuer_id": s(&v["issuer_id"]),
        "status_key_id": s(&v["status_key_id"]),
        "sequence": i(&v["sequence"]),
        "object_type_code": u(&v["object_type_code"]),
        "digest": s(&v["digest"]),
    })
}

// ---------------------------------------------------------------------------
// Scripted verification setup (Go `v2BuildVerifyRequest`)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The number of times every callback ran.
#[derive(Default, Debug)]
pub struct Counts {
    pub receiver_binding: AtomicUsize,
    pub claim: AtomicUsize,
    pub trust: AtomicUsize,
    pub status: AtomicUsize,
    pub audience: AtomicUsize,
    pub rate: AtomicUsize,
    pub finalize: AtomicUsize,
    pub progress: AtomicUsize,
    pub evaluator: AtomicUsize,
}

pub const COUNT_NAMES: [&str; 9] = [
    "receiver_binding",
    "claim",
    "trust",
    "status",
    "audience",
    "rate",
    "finalize",
    "progress",
    "evaluator",
];

impl Counts {
    pub fn get(&self, name: &str) -> &AtomicUsize {
        match name {
            "receiver_binding" => &self.receiver_binding,
            "claim" => &self.claim,
            "trust" => &self.trust,
            "status" => &self.status,
            "audience" => &self.audience,
            "rate" => &self.rate,
            "finalize" => &self.finalize,
            "progress" => &self.progress,
            "evaluator" => &self.evaluator,
            other => panic!("unknown count {other}"),
        }
    }

    pub fn bump(&self, name: &str) {
        self.get(name).fetch_add(1, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> BTreeMap<&'static str, usize> {
        COUNT_NAMES
            .iter()
            .map(|n| (*n, self.get(n).load(Ordering::SeqCst)))
            .collect()
    }

    pub fn expected(v: &Value) -> BTreeMap<&'static str, usize> {
        COUNT_NAMES
            .iter()
            .map(|n| (*n, u(&v[*n]) as usize))
            .collect()
    }
}

/// One scripted evaluator: its descriptor and behaviour.
pub struct Evaluator {
    pub kind: CString,
    pub profile: CString,
    pub implementation: String,
    pub valid_until: i64,
    pub counts: Arc<Counts>,
    pub detail: CString,
}

thread_local! {
    /// Evaluator callbacks that ran on this thread. SPEC-v2 §1.3 requires a
    /// C evaluator to run on the thread that made the ABI call.
    pub static EVALUATOR_CALLS_ON_THIS_THREAD: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

unsafe extern "C" fn evaluator_tramp(
    user: *mut c_void,
    call: *const RatifyV2EvaluatorCall,
    input: *const RatifyV2EvaluationInput,
    out: *mut RatifyV2EvaluationResult,
) -> i32 {
    let e = &*(user as *const Evaluator);
    e.counts.bump("evaluator");
    EVALUATOR_CALLS_ON_THIS_THREAD.with(|c| c.set(c.get() + 1));
    let set = |outcome: i32, valid_until: i64| {
        *out = RatifyV2EvaluationResult {
            outcome,
            valid_until,
            detail: e.detail.as_ptr(),
        };
    };
    match e.implementation.as_str() {
        "fault:error" => return RatifyV2Code::RatifyV2StoreUnavailable as i32,
        "fault:panic" => {
            // A C evaluator cannot unwind; a crash-like failure is a refusal.
            return RatifyV2Code::RatifyV2ErrInternal as i32;
        }
        "fault:timeout" => {
            while ratify_v2_evaluator_call_expired(call) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            set(1, 0);
        }
        "test:late_pass" => {
            // Ignores the call handle and answers pass only after the 1000 ms
            // registry deadline (`Setup::evaluator_config`).
            std::thread::sleep(std::time::Duration::from_millis(1100));
            set(1, 0);
        }
        "fault:invalid_outcome" => set(99, 0),
        "fault:pass_until" => set(1, e.valid_until),
        profile => {
            // A standard profile, run through the ABI on the input it was given.
            let inp = &*input;
            let mut v = Map::new();
            v.insert("type".into(), json!(cstr_in(inp.constraint_type)));
            if inp.has_params != 0 {
                v.insert("params".into(), parse(&slice_in(inp.params_json)));
            }
            v.insert("delegation_index".into(), json!(inp.delegation_index));
            v.insert("constraint_index".into(), json!(inp.constraint_index));
            v.insert("issuer_id".into(), json!(cstr_in(inp.issuer_id)));
            v.insert("cert_id".into(), json!(cstr_in(inp.cert_id)));
            v.insert("context".into(), parse(&slice_in(inp.request_context_json)));
            v.insert("evaluation_time".into(), json!(inp.evaluation_time));
            let input_json = json_bytes(&Value::Object(v));
            let p = cs(profile);
            let (mut outcome, mut until) = (0i32, 0i64);
            let code = ratify_v2_evaluate_standard_profile(
                p.as_ptr(),
                input_json.as_ptr(),
                input_json.len(),
                &mut outcome,
                &mut until,
                ptr::null_mut(),
            );
            if code != 0 {
                return code;
            }
            set(outcome, until);
        }
    }
    0
}

/// Everything one scripted verification needs; boxed so the callback
/// pointers into it stay valid.
pub struct Setup {
    pub request: Vec<u8>,
    pub trust: Option<Trust>,
    pub status: Status,
    pub audience: Audience,
    pub journal: Option<(RefJournal, ModalJournal)>,
    pub binding: Option<Binding>,
    pub rate: Option<RateStore>,
    pub rate_batch: Arc<Mutex<Vec<Rate>>>,
    pub evaluators: Vec<Evaluator>,
    pub registrations: Vec<RatifyV2EvaluatorRegistration>,
    pub has_evaluators: bool,
    // callback structs the pointers in `callbacks()` refer to
    trust_cb: Option<RatifyV2TrustCallbacks>,
    status_cb: Option<RatifyV2StatusEvidenceCallbacks>,
    audience_cb: Option<RatifyV2AudienceCallbacks>,
    journal_cb: Option<RatifyV2JournalStoreCallbacks>,
    binding_cb: Option<RatifyV2ReceiverBindingCallbacks>,
    rate_cb: Option<RatifyV2RateCallbacks>,
    pub claim_cb: Option<RatifyV2ClaimStoreCallbacks>,
}

unsafe impl Send for Setup {}
unsafe impl Sync for Setup {}

impl Setup {
    /// Build the scripted providers of one ordering-style vector. With
    /// `builtin_standard`, standard profiles use the library's built-in
    /// implementations (their calls are then not counted).
    pub fn build(inputs: &Value, counts: &Arc<Counts>, builtin_standard: bool) -> Box<Setup> {
        let trust = {
            let counts = Arc::clone(counts);
            let t = inputs["trust"].clone();
            Some(Trust(Box::new(move |_chain: &[ChainCert]| {
                counts.bump("trust");
                if t.is_null() {
                    return Ok((RatifyV2TrustOutcome::RatifyV2TrustUnavailable as i32, None));
                }
                match s(&t["mode"]).as_str() {
                    "error" => return Err(RatifyV2Code::RatifyV2StoreUnavailable as i32),
                    "panic" => return Err(RatifyV2Code::RatifyV2ErrInternal as i32),
                    _ => {}
                }
                let outcome = match s(&t["outcome"]).as_str() {
                    "trusted" => 1,
                    "untrusted" => 2,
                    "unavailable" => 3,
                    "ambiguous" => 4,
                    other => panic!("unknown trust outcome {other}"),
                };
                let key =
                    (!t["root_public_key"].is_null()).then(|| key_struct(&t["root_public_key"]));
                Ok((outcome, key))
            })))
        };
        let status = {
            let counts = Arc::clone(counts);
            let evidence = inputs["status_evidence"].clone();
            Status::new(Box::new(move |r: &StatusReq| {
                counts.bump("status");
                let script = &evidence[&r.issuer_id];
                if script.is_null() {
                    return Ok(Vec::new());
                }
                match s(&script["mode"]).as_str() {
                    "error" => return Err(RatifyV2Code::RatifyV2StoreUnavailable as i32),
                    "panic" => return Err(RatifyV2Code::RatifyV2ErrInternal as i32),
                    _ => {}
                }
                Ok(arr(&script["objects"])
                    .iter()
                    .map(|o| (u(&o["object_type_code"]) as u16, b64(&o["wire_b64"])))
                    .collect())
            }))
        };
        let audience = {
            let counts = Arc::clone(counts);
            let mode = s(&inputs["audience_mode"]);
            let memberships: Vec<Membership> = arr(&inputs["audience_memberships"])
                .iter()
                .map(|m| Membership {
                    delegation_index: u(&m["delegation_index"]) as usize,
                    constraint_index: u(&m["constraint_index"]) as usize,
                    receiver_id: s(&m["receiver_id"]),
                    trust_domain_ids: arr(&m["trust_domain_ids"]).iter().map(s).collect(),
                    issued_at: i(&m["issued_at"]),
                    expires_at: i(&m["expires_at"]),
                    evidence_digest: s(&m["evidence_digest"]),
                })
                .collect();
            Audience::new(Box::new(move |_r: &str| {
                counts.bump("audience");
                match mode.as_str() {
                    "error" => Err(RatifyV2Code::RatifyV2StoreUnavailable as i32),
                    "panic" => Err(RatifyV2Code::RatifyV2ErrInternal as i32),
                    _ => Ok(memberships.clone()),
                }
            }))
        };
        let journal_mode = s(&inputs["journal"]["mode"]);
        let journal = (journal_mode != "absent").then(|| {
            let inner = RefJournal::new();
            populate_status_journal(&inner.callbacks(), inputs);
            let modal = ModalJournal::new(inner.callbacks(), &journal_mode);
            (inner, modal)
        });
        let hook = s(&inputs["receiver_binding_hook"]);
        let binding = (hook == "accept" || hook == "reject").then(|| {
            let counts = Arc::clone(counts);
            Binding(Box::new(move || {
                counts.bump("receiver_binding");
                if hook == "reject" {
                    1
                } else {
                    0
                }
            }))
        });
        let rate_batch = Arc::new(Mutex::new(Vec::new()));
        let rate_mode = s(&inputs["rate"]);
        let rate = (rate_mode != "absent" && !rate_mode.is_empty()).then(|| {
            let (counts, batch) = (Arc::clone(counts), Arc::clone(&rate_batch));
            RateStore(Box::new(move |b: &[Rate]| {
                counts.bump("rate");
                *batch.lock().unwrap() = b.to_vec();
                match rate_mode.as_str() {
                    "reserve" => 0,
                    "exceeded" => RatifyV2Code::RatifyV2StoreRateLimitExceeded as i32,
                    "panic" => RatifyV2Code::RatifyV2ErrInternal as i32,
                    _ => RatifyV2Code::RatifyV2StoreUnavailable as i32,
                }
            }))
        });
        let evaluators: Vec<Evaluator> = arr(&inputs["constraint_evaluators"])
            .iter()
            .map(|e| Evaluator {
                kind: cs(&s(&e["type"])),
                profile: cs(&s(&e["profile"])),
                implementation: s(&e["implementation"]),
                valid_until: i(&e["valid_until"]),
                counts: Arc::clone(counts),
                detail: cs(""),
            })
            .collect();
        let mut setup = Box::new(Setup {
            request: json_bytes(&request_json(inputs)),
            trust,
            status,
            audience,
            journal,
            binding,
            rate,
            rate_batch,
            has_evaluators: !evaluators.is_empty(),
            evaluators,
            registrations: Vec::new(),
            trust_cb: None,
            status_cb: None,
            audience_cb: None,
            journal_cb: None,
            binding_cb: None,
            rate_cb: None,
            claim_cb: None,
        });
        let regs: Vec<RatifyV2EvaluatorRegistration> = setup
            .evaluators
            .iter()
            .map(|e| {
                let implementation = match (builtin_standard, e.implementation.as_str()) {
                    (true, "com.ratifyprotocol.max_count/v1") => 1,
                    (true, "com.ratifyprotocol.allowed_values/v1") => 2,
                    _ => 0,
                };
                RatifyV2EvaluatorRegistration {
                    constraint_type: e.kind.as_ptr(),
                    profile: e.profile.as_ptr(),
                    implementation,
                    evaluate: Some(evaluator_tramp),
                    user: e as *const Evaluator as *mut c_void,
                }
            })
            .collect();
        setup.registrations = regs;
        setup.trust_cb = setup.trust.as_ref().map(Trust::callbacks);
        setup.status_cb = Some(setup.status.callbacks());
        setup.audience_cb = Some(setup.audience.callbacks());
        setup.journal_cb = setup.journal.as_ref().map(|(_, m)| m.callbacks());
        setup.binding_cb = setup.binding.as_ref().map(Binding::callbacks);
        setup.rate_cb = setup.rate.as_ref().map(RateStore::callbacks);
        setup
    }

    /// Replace the rate store (e.g. the reference store's admission view).
    pub fn set_rate(&mut self, rate: RatifyV2RateCallbacks) {
        self.rate_cb = Some(rate);
    }

    /// Wrap the status provider (e.g. to run a step mid-lookup).
    pub fn set_status(&mut self, cb: RatifyV2StatusEvidenceCallbacks) {
        self.status_cb = Some(cb);
    }

    pub fn status_callbacks(&self) -> RatifyV2StatusEvidenceCallbacks {
        self.status_cb.unwrap()
    }

    pub fn evaluator_config(&self) -> RatifyV2EvaluatorConfig {
        RatifyV2EvaluatorConfig {
            timeout_ms: 1000,
            registrations: if self.registrations.is_empty() {
                ptr::null()
            } else {
                self.registrations.as_ptr()
            },
            count: self.registrations.len(),
        }
    }

    fn opt<T>(o: &Option<T>) -> *const T {
        o.as_ref().map_or(ptr::null(), |x| x as *const T)
    }

    pub fn callbacks(&self) -> RatifyV2VerifyCallbacks {
        RatifyV2VerifyCallbacks {
            claim_store: Self::opt(&self.claim_cb),
            trust: Self::opt(&self.trust_cb),
            status_evidence: Self::opt(&self.status_cb),
            status_journal: Self::opt(&self.journal_cb),
            audience: Self::opt(&self.audience_cb),
            rate: Self::opt(&self.rate_cb),
            receiver_binding: Self::opt(&self.binding_cb),
        }
    }

    /// The trust callbacks, or NULL when the vector has no trust provider.
    pub fn trust_ptr(&self) -> *const RatifyV2TrustCallbacks {
        Self::opt(&self.trust_cb)
    }

    pub fn status_ptr(&self) -> *const RatifyV2StatusEvidenceCallbacks {
        Self::opt(&self.status_cb)
    }

    pub fn journal_ptr(&self) -> *const RatifyV2JournalStoreCallbacks {
        Self::opt(&self.journal_cb)
    }
}

/// A verification outcome read back through the ABI.
pub struct Outcome {
    pub stage: String,
    pub class: String,
    pub disposition: String,
    pub message: String,
    pub claim_record: Vec<u8>,
    pub committed: Option<Committed>,
}

pub fn stage_name(code: i32) -> &'static str {
    match code {
        1 => "preflight",
        2 => "replay",
        3 => "evaluating",
        4 => "committed",
        _ => "",
    }
}

pub fn disposition_name(code: i32) -> &'static str {
    match code {
        1 => "created",
        2 => "in_progress",
        3 => "terminal_replay",
        _ => "",
    }
}

/// Run `ratify_v2_verify_proof_bundle` on a setup.
pub fn verify(setup: &Setup, bundle: &[u8]) -> R<Outcome> {
    let config = setup.evaluator_config();
    let cb = setup.callbacks();
    let mut outcome = RatifyV2VerifyOutcome {
        stage: 0,
        error_code: 0,
        disposition: 0,
    };
    let mut record = empty_buf();
    let mut committed: *mut RatifyV2Committed = ptr::null_mut();
    let code = unsafe {
        ratify_v2_verify_proof_bundle(
            ptr_of(bundle),
            bundle.len(),
            setup.request.as_ptr(),
            setup.request.len(),
            if setup.has_evaluators {
                &config
            } else {
                ptr::null()
            },
            &cb,
            &mut outcome,
            &mut record,
            &mut committed,
        )
    };
    let message = last_error();
    let claim_record = take(record);
    check(code)?;
    Ok(Outcome {
        stage: stage_name(outcome.stage).into(),
        class: if outcome.error_code == 0 {
            String::new()
        } else {
            class(outcome.error_code)
        },
        disposition: disposition_name(outcome.disposition).into(),
        message,
        claim_record,
        committed: (!committed.is_null()).then_some(Committed(committed)),
    })
}

/// A committed outcome handle.
pub struct Committed(pub *mut RatifyV2Committed);

unsafe impl Send for Committed {}
unsafe impl Sync for Committed {}

impl Committed {
    pub fn claim_id(&self) -> String {
        string(|o| unsafe { ratify_v2_committed_claim_id(self.0, o) }).unwrap()
    }
    pub fn body(&self) -> Vec<u8> {
        buf(|o| unsafe { ratify_v2_committed_receipt_body(self.0, o) }).unwrap()
    }
    pub fn body_digest(&self) -> String {
        string(|o| unsafe { ratify_v2_committed_receipt_body_digest(self.0, o) }).unwrap()
    }
    pub fn allow_horizon(&self) -> Option<i64> {
        let (mut has, mut h) = (0, 0);
        check(unsafe { ratify_v2_committed_allow_horizon(self.0, &mut has, &mut h) }).unwrap();
        (has != 0).then_some(h)
    }
    pub fn expires_at(&self) -> i64 {
        let mut t = 0;
        check(unsafe { ratify_v2_committed_challenge_expires_at(self.0, &mut t) }).unwrap();
        t
    }
}

impl Drop for Committed {
    fn drop(&mut self) {
        unsafe { ratify_v2_committed_free(self.0) };
    }
}

/// The decoded receipt body JSON of a committed outcome (strictly checked
/// through the ABI first).
pub fn body_json(body: &[u8]) -> Value {
    canonicalize(100, body).expect("receipt body decodes");
    parse(body)
}
