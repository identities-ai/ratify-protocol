//! Ratify Protocol v1 types.
//!
//! Every public key and every signature is a hybrid pair: one Ed25519
//! component and one ML-DSA-65 (FIPS 204) component. Both must verify.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec, vec::Vec};

use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: i32 = 1;
pub const MAX_DELEGATION_CHAIN_DEPTH: usize = 3;
pub const CHALLENGE_WINDOW_SECONDS: i64 = 300;

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

/// Ed25519 + ML-DSA-65 public key pair.
///
/// Canonical JSON form (keys in lex order):
/// `{"ed25519":"<base64-32-bytes>","ml_dsa_65":"<base64-1952-bytes>"}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    #[serde(with = "crate::canonical::base64_bytes")]
    pub ed25519: Vec<u8>, // 32 bytes
    #[serde(with = "crate::canonical::base64_bytes")]
    pub ml_dsa_65: Vec<u8>, // 1952 bytes
}

/// Ed25519 + ML-DSA-65 signature pair over the same canonical bytes.
///
/// Both components MUST verify for the signature to be accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    #[serde(with = "crate::canonical::base64_bytes")]
    pub ed25519: Vec<u8>, // 64 bytes
    #[serde(with = "crate::canonical::base64_bytes")]
    pub ml_dsa_65: Vec<u8>, // 3309 bytes
}

/// Both component private keys. Never serialized to the wire.
#[derive(Debug, Clone)]
pub struct HybridPrivateKey {
    pub ed25519: Vec<u8>,   // 32-byte seed
    pub ml_dsa_65: Vec<u8>, // ML-DSA-65 secret key bytes
}

/// Optional external binding for higher-assurance identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    #[serde(rename = "type")]
    pub anchor_type: String,
    pub provider: String,
    pub reference: String,
    pub verified_at: i64,
}

/// Master identity for a human (or tenant admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanRoot {
    pub id: String,
    pub public_key: HybridPublicKey,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchors: Option<Vec<Anchor>>,
}

/// An AI agent's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: String,
    pub public_key: HybridPublicKey,
    pub name: String,
    pub agent_type: String,
    pub created_at: i64,
}

/// Signed authorization from a principal to an agent.
///
/// `scope` answers *what* the agent may do. `constraints` answer *where /
/// when / how much* — first-class bounds evaluated at verify time against a
/// caller-supplied VerifierContext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCert {
    pub cert_id: String,
    pub version: i32,
    pub issuer_id: String,
    pub issuer_pub_key: HybridPublicKey,
    pub subject_id: String,
    pub subject_pub_key: HybridPublicKey,
    pub scope: Vec<String>,
    /// Always present in canonical JSON (`[]` when empty) so canonical bytes
    /// are deterministic across issuers.
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: HybridSignature,
}

/// First-class bound on when/where/how much an agent may exercise its scopes.
///
/// Wire format is a tagged JSON object. `type` discriminates the kind;
/// remaining fields are kind-specific. Unknown `type` values MUST be
/// rejected by conformant verifiers (fail-closed).
///
// Fields are declared in alphabetical JSON-key order so serde's default
// struct serialization order produces canonical bytes that match the Go
// reference and the other SDKs' lex-sorted output (SPEC §6.2). Do not
// reorder — cross-SDK byte identicality depends on this.
//
// Serialization is custom (see impl Serialize below) to emit the
// canonical per-kind shape rather than the default "skip if zero"
// behavior. This closes the v1 zero-as-absence ambiguity: a geo_circle at
// lat=0, lon=0 now emits lat:0, lon:0 explicitly instead of omitting them.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Constraint {
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub end: String,
    #[serde(default)]
    pub lat: f64,
    #[serde(default)]
    pub lon: f64,
    #[serde(default)]
    pub max_alt_m: f64,
    #[serde(default)]
    pub max_amount: f64,
    #[serde(default)]
    pub max_lat: f64,
    #[serde(default)]
    pub max_lon: f64,
    #[serde(default)]
    pub max_mps: f64,
    #[serde(default)]
    pub min_alt_m: f64,
    #[serde(default)]
    pub min_lat: f64,
    #[serde(default)]
    pub min_lon: f64,
    #[serde(default)]
    pub points: Vec<[f64; 2]>,
    #[serde(default)]
    pub radius_m: f64,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub tz: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub window_s: i64,
}

// Custom Serialize for Constraint — emits the canonical per-kind shape.
// Mirrors Go's Constraint.MarshalJSON and TS canonicalConstraintDict.
// Keys are emitted in alphabetical order, matching the other SDKs.
impl Serialize for Constraint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Count fields up front so serde's map writer knows the length.
        // Doing this the verbose way rather than with serialize_struct
        // because the per-kind shape is dynamic, not a fixed struct.
        let entries: Vec<(&'static str, FieldValue)> = match self.kind.as_str() {
            "geo_circle" => vec![
                ("lat", FieldValue::F64(self.lat)),
                ("lon", FieldValue::F64(self.lon)),
                ("radius_m", FieldValue::F64(self.radius_m)),
                ("type", FieldValue::Str(self.kind.clone())),
            ],
            "geo_polygon" => vec![
                ("points", FieldValue::Points(self.points.clone())),
                ("type", FieldValue::Str(self.kind.clone())),
            ],
            "geo_bbox" => {
                let mut v = vec![
                    ("max_lat", FieldValue::F64(self.max_lat)),
                    ("max_lon", FieldValue::F64(self.max_lon)),
                    ("min_lat", FieldValue::F64(self.min_lat)),
                    ("min_lon", FieldValue::F64(self.min_lon)),
                ];
                if self.min_alt_m != 0.0 || self.max_alt_m != 0.0 {
                    // Insert altitude pair alphabetically: max_alt_m < max_lat.
                    v.insert(0, ("max_alt_m", FieldValue::F64(self.max_alt_m)));
                    // min_alt_m < min_lat → insert after max_lon (index 2).
                    v.insert(3, ("min_alt_m", FieldValue::F64(self.min_alt_m)));
                }
                v.push(("type", FieldValue::Str(self.kind.clone())));
                v
            }
            "time_window" => vec![
                ("end", FieldValue::Str(self.end.clone())),
                ("start", FieldValue::Str(self.start.clone())),
                ("type", FieldValue::Str(self.kind.clone())),
                ("tz", FieldValue::Str(self.tz.clone())),
            ],
            "max_speed_mps" => vec![
                ("max_mps", FieldValue::F64(self.max_mps)),
                ("type", FieldValue::Str(self.kind.clone())),
            ],
            "max_amount" => vec![
                ("currency", FieldValue::Str(self.currency.clone())),
                ("max_amount", FieldValue::F64(self.max_amount)),
                ("type", FieldValue::Str(self.kind.clone())),
            ],
            "max_rate" => vec![
                ("count", FieldValue::I64(self.count)),
                ("type", FieldValue::Str(self.kind.clone())),
                ("window_s", FieldValue::I64(self.window_s)),
            ],
            // Unknown kind: emit only the tag. Verifier returns constraint_unknown.
            _ => vec![("type", FieldValue::Str(self.kind.clone()))],
        };
        let mut m = serializer.serialize_map(Some(entries.len()))?;
        for (k, v) in entries {
            match v {
                FieldValue::F64(x) => m.serialize_entry(k, &x)?,
                FieldValue::I64(x) => m.serialize_entry(k, &x)?,
                FieldValue::Str(x) => m.serialize_entry(k, &x)?,
                FieldValue::Points(x) => m.serialize_entry(k, &x)?,
            }
        }
        m.end()
    }
}

// Small sum type so the serialize impl can carry mixed-type values in one
// vector. Kept private to this module.
enum FieldValue {
    F64(f64),
    I64(i64),
    Str(String),
    Points(Vec<[f64; 2]>),
}

/// Application-supplied inputs for evaluating first-class constraints.
/// A cert bearing a constraint whose required context field is absent will
/// be rejected with `constraint_unverifiable` (fail-closed).
#[derive(Default)]
pub struct VerifierContext<'a> {
    pub current_lat: Option<f64>,
    pub current_lon: Option<f64>,
    pub current_alt_m: Option<f64>,
    pub current_speed_mps: Option<f64>,
    pub requested_amount: Option<f64>,
    pub requested_currency: Option<String>,
    /// (cert_id, window_s) -> invocation count
    pub invocations_in_window: Option<Box<dyn Fn(&str, i64) -> i64 + 'a>>,
}

/// Proof an agent presents to a verifier.
///
/// v1.1 optional stream binding: when `stream_id` and `stream_seq` are set,
/// the bundle is "stream-bound" — it belongs to an ordered sequence of
/// interactions sharing a stream_id. Both are signed into the challenge bytes
/// (SPEC §6.4.2) so replay, reorder, or omission within the stream invalidate
/// the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub delegations: Vec<DelegationCert>,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub challenge: Vec<u8>,
    pub challenge_at: i64,
    pub challenge_sig: HybridSignature,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::canonical::base64_bytes"
    )]
    pub session_context: Vec<u8>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::canonical::base64_bytes"
    )]
    pub stream_id: Vec<u8>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub stream_seq: i64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// Identity status values in a VerifyResult (SPEC §5.9). Granular failure
/// statuses (scope_denied, constraint_denied, etc) let callers route on the
/// enum directly — they do not have to parse error_reason text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    VerifiedHuman,
    AuthorizedAgent,
    Expired,
    Revoked,
    ScopeDenied,
    ConstraintDenied,
    ConstraintUnverifiable,
    ConstraintUnknown,
    DelegationNotAuthorized,
    Invalid,
    Unauthorized,
}

impl IdentityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifiedHuman => "verified_human",
            Self::AuthorizedAgent => "authorized_agent",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::ScopeDenied => "scope_denied",
            Self::ConstraintDenied => "constraint_denied",
            Self::ConstraintUnverifiable => "constraint_unverifiable",
            Self::ConstraintUnknown => "constraint_unknown",
            Self::DelegationNotAuthorized => "delegation_not_authorized",
            Self::Invalid => "invalid",
            Self::Unauthorized => "unauthorized",
        }
    }

    /// Parse the snake_case wire form back into the enum. Returns None if
    /// the input is not a known status; callers should fail-closed.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "verified_human" => Self::VerifiedHuman,
            "authorized_agent" => Self::AuthorizedAgent,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            "scope_denied" => Self::ScopeDenied,
            "constraint_denied" => Self::ConstraintDenied,
            "constraint_unverifiable" => Self::ConstraintUnverifiable,
            "constraint_unknown" => Self::ConstraintUnknown,
            "delegation_not_authorized" => Self::DelegationNotAuthorized,
            "invalid" => Self::Invalid,
            "unauthorized" => Self::Unauthorized,
            _ => return None,
        })
    }
}

/// Deterministic output of `verify_bundle`. Always check `valid` first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub identity_status: IdentityStatus,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub human_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub agent_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub agent_name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub agent_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub granted_scope: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error_reason: String,
    /// Resolved external-identity binding for `human_id`, populated when
    /// `VerifyOptions.anchor_resolver` is set on a successful verification.
    /// Lets downstream `AuditProvider`s record an unforgeable chain from
    /// verification event → identity attestation. (SPEC §17.8)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub anchor: Option<Anchor>,
}

/// Signed list of revoked cert IDs, served by the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    pub issuer_id: String,
    pub updated_at: i64,
    pub revoked_certs: Vec<String>,
    pub signature: HybridSignature,
}

/// v1.1 signed push notification of newly revoked cert IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationPush {
    pub issuer_id: String,
    pub seq_no: i64,
    pub entries: Vec<String>,
    pub pushed_at: i64,
    pub signature: HybridSignature,
}

/// v1.1 element in a hash-chain append-only witness log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEntry {
    #[serde(with = "crate::canonical::base64_bytes")]
    pub prev_hash: Vec<u8>,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub entry_data: Vec<u8>,
    pub timestamp: i64,
    pub witness_id: String,
    pub signature: HybridSignature,
}

/// v1.1 verifier-issued credential that caches a verified chain. MAC =
/// HMAC-SHA256(session_secret, session_token_sign_bytes(token)). The session
/// secret is private to the verifier and never leaves its trust boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub version: i32,
    pub session_id: String,
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub human_id: String,
    pub granted_scope: Vec<String>,
    pub issued_at: i64,
    pub valid_until: i64,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub chain_hash: Vec<u8>,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub mac: Vec<u8>,
}

/// v1.1 canonical envelope for a multi-party, atomic transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub version: i32,
    pub transaction_id: String,
    pub created_at: i64,
    pub terms_schema_uri: String,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub terms_canonical_json: Vec<u8>,
    pub parties: Vec<ReceiptParty>,
    pub party_signatures: Vec<ReceiptPartySignature>,
}

/// One party to a TransactionReceipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptParty {
    pub party_id: String,
    pub role: String,
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub proof_bundle: ProofBundle,
}

/// Hybrid signature by a party over the canonical receipt signable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPartySignature {
    pub party_id: String,
    pub signature: HybridSignature,
}

/// Outcome of verify_transaction_receipt.
pub struct TransactionReceiptResult {
    pub valid: bool,
    pub error_reason: String,
    pub party_results: Vec<VerifyResult>,
}

/// Signed continuity statement from an old root key to a new root key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationStatement {
    pub version: i32,
    pub old_id: String,
    pub old_pub_key: HybridPublicKey,
    pub new_id: String,
    pub new_pub_key: HybridPublicKey,
    pub rotated_at: i64,
    pub reason: String,
    pub signature_old: HybridSignature,
    pub signature_new: HybridSignature,
}

/// Verifier state tracked per stream_id for v1.1 stream-bound bundles.
///
/// `last_seen_seq` is the highest sequence number the verifier has already
/// accepted for `stream_id`; zero means no turns accepted yet, so the first
/// valid bundle must carry `stream_seq == 1`.
#[derive(Debug, Clone, Default)]
pub struct StreamContext {
    pub stream_id: Vec<u8>,
    pub last_seen_seq: i64,
}

/// Pluggable provider for revocation state (SPEC §17.1).
///
/// Implementations return `Ok(true)` for revoked, `Ok(false)` for live, and
/// `Err(...)` to surface a lookup failure. A provider error is fail-closed:
/// the bundle is rejected with `error_reason="revocation_error: ..."` —
/// SDKs MUST NOT treat a lookup failure as "not revoked." On the verifier's
/// hot path; implementations should be O(1) at call time.
pub trait RevocationProvider {
    fn is_revoked(&self, cert_id: &str) -> Result<bool, String>;
}

/// Pluggable evaluator for verifier-local policy (SPEC §17.2).
///
/// Evaluated AFTER all cryptographic, temporal, revocation, constraint, and
/// scope-intersection checks pass. `Ok(true)` allows; `Ok(false)` denies with
/// `scope_denied`; `Err(...)` fails closed with `policy_error`.
pub trait PolicyProvider {
    fn evaluate_policy(
        &self,
        bundle: &ProofBundle,
        context: &VerifierContext,
    ) -> Result<bool, String>;
}

/// Pluggable audit-receipt persistence (SPEC §17.3).
///
/// Invoked on every `verify_bundle` call (success AND failure). Errors are
/// swallowed — auditing MUST NOT alter the verdict.
pub trait AuditProvider {
    fn log_verification(&self, result: &VerifyResult, bundle: &ProofBundle);
}

/// Pluggable evaluator for extension constraint types (SPEC §17.7).
///
/// Built-in types (geo_*, time_window, max_*) are evaluated by the SDK
/// directly; an evaluator is consulted only for types the SDK does not
/// natively understand. Returning `Ok(true)` allows; `Ok(false)` denies as
/// `constraint_denied`; `Err("constraint_unverifiable: ...")` routes to
/// `constraint_unverifiable`; other `Err(...)` denies with the wrapped
/// reason.
pub trait ConstraintEvaluator {
    fn evaluate(
        &self,
        constraint: &Constraint,
        cert_id: &str,
        context: &VerifierContext,
        now: i64,
    ) -> Result<(), String>;
}

/// Resolves a verified `human_id` to its external-identity binding
/// (SPEC §17.8). Errors are non-fatal: the verifier MUST NOT fail the bundle
/// because the resolver errored — it silently leaves `VerifyResult.anchor`
/// `None` and continues.
pub trait AnchorResolver {
    fn resolve_anchor(&self, human_id: &str) -> Result<Option<Anchor>, String>;
}

/// HMAC-bound cached policy decision (SPEC §17.6). The policy equivalent
/// of `SessionToken`: issued once by a commercial policy backend, accepted
/// locally by the verifier for the rest of `valid_until` without re-calling
/// the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub version: i32,
    pub verdict_id: String,
    pub agent_id: String,
    pub scope: String,
    pub allow: bool,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub context_hash: Vec<u8>, // 32 bytes
    pub issued_at: i64,
    pub valid_until: i64,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub mac: Vec<u8>, // 32 bytes — HMAC-SHA256
}

/// Verifier-signed attestation that a specific ProofBundle was verified at
/// a specific moment with a specific outcome (SPEC §17.5).
///
/// Receipts chain by `prev_hash` (SHA-256 of previous receipt's canonical
/// signable bytes) so a missing or backdated entry is detectable. Genesis
/// uses 32 zero bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub version: i32,
    pub verifier_id: String,
    pub verifier_pub: HybridPublicKey,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub bundle_hash: Vec<u8>, // 32 bytes
    pub decision: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub human_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub agent_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub granted_scope: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error_reason: String,
    pub verified_at: i64,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub prev_hash: Vec<u8>, // 32 bytes; zeros for genesis
    pub signature: HybridSignature,
}

/// Options passed to `verify_bundle`.
pub struct VerifyOptions<'a> {
    /// Required scope; empty string skips scope checking.
    pub required_scope: String,
    /// Legacy v1 revocation closure.
    ///
    /// **Deprecated:** Use `revocation` (SPEC §17.1) instead. The closure
    /// has no way to surface lookup failures; `revocation` returns
    /// `Result<bool, String>` and fails closed on error. Slated for removal
    /// in v1.0.0-beta.1. When both fields are set, `revocation` wins.
    #[deprecated(since = "1.0.0-alpha.7", note = "use `revocation` (SPEC §17.1) instead")]
    pub is_revoked: Option<Box<dyn Fn(&str) -> bool + 'a>>,
    /// Pluggable revocation provider (SPEC §17.1). Takes precedence over
    /// `is_revoked`. A provider error fails the bundle as `revocation_error`.
    pub revocation: Option<Box<dyn RevocationProvider + 'a>>,
    /// Force a fresh revocation check for high-stakes endpoints. The SDK
    /// cannot fetch revocation state itself; callers must provide is_revoked
    /// or a revocation provider when this is true.
    pub force_revocation_check: bool,
    /// Override current time (unix seconds); None = SystemTime::now().
    pub now: Option<i64>,
    /// Optional verifier-reconstructed 32-byte v1.1 session context.
    pub session_context: Vec<u8>,
    /// Optional verifier-tracked v1.1 stream context.
    pub stream: Option<StreamContext>,
    /// Application inputs for evaluating first-class constraints. Default is
    /// empty; constraint-bearing certs fail closed if required context is
    /// absent.
    pub context: VerifierContext<'a>,
    /// Advanced verifier-local policy evaluator (SPEC §17.2). Evaluated after
    /// all cryptographic checks pass. Deny → `scope_denied`; provider error →
    /// `policy_error`.
    pub policy: Option<Box<dyn PolicyProvider + 'a>>,
    /// Audit-receipt persistence hook (SPEC §17.3). Invoked on every Verify
    /// (success AND failure). Provider errors are swallowed — auditing cannot
    /// alter the verdict.
    pub audit: Option<Box<dyn AuditProvider + 'a>>,
    /// Per-Verify registry of extension constraint evaluators (SPEC §17.7).
    /// Built-in types are evaluated by the SDK directly; the registry is
    /// only consulted for unknown types.
    pub constraint_evaluators:
        Option<alloc::collections::BTreeMap<String, Box<dyn ConstraintEvaluator + 'a>>>,
    /// Fast-path cached policy decision (SPEC §17.6). When present and
    /// valid (MAC matches `policy_secret`, within window, agent/scope/
    /// context_hash matches), the verifier skips the live `policy` hook.
    /// Stale verdicts fall back to live policy.
    pub policy_verdict: Option<PolicyVerdict>,
    /// HMAC secret used to verify `policy_verdict.mac`.
    pub policy_secret: Option<Vec<u8>>,
    /// Anchor resolver (SPEC §17.8). When set on a Valid=true verification,
    /// the verifier populates `VerifyResult.anchor`. Resolver errors are
    /// non-fatal.
    pub anchor_resolver: Option<Box<dyn AnchorResolver + 'a>>,
}

impl<'a> Default for VerifyOptions<'a> {
    fn default() -> Self {
        // The Default impl must initialize the deprecated field for backwards
        // compatibility. Suppressing the warning is intentional and isolated
        // to this single construction site.
        #[allow(deprecated)]
        Self {
            required_scope: String::new(),
            is_revoked: None,
            revocation: None,
            force_revocation_check: false,
            now: None,
            session_context: Vec::new(),
            stream: None,
            context: VerifierContext::default(),
            policy: None,
            audit: None,
            constraint_evaluators: None,
            policy_verdict: None,
            policy_secret: None,
            anchor_resolver: None,
        }
    }
}
