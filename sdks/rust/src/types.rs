//! Ratify Protocol v1 types.
//!
//! Every public key and every signature is a hybrid pair: one Ed25519
//! component and one ML-DSA-65 (FIPS 204) component. Both must verify.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, string::ToString, vec, vec::Vec};

use alloc::collections::BTreeMap;
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer, Serialize};
use core::fmt;

pub const PROTOCOL_VERSION: i32 = 1;

/// The `expires_at` value that means "no expiry (until revoked)":
/// 4070908799 = 2099-12-31 23:59:59 UTC. `DelegationCert.expires_at` is a
/// required i64 with no null representation, so open-ended delegations carry
/// this sentinel in the signed bytes. Conformant implementations MUST treat
/// a cert with `expires_at == NO_EXPIRY_SENTINEL` as "no expiry (until
/// revoked)" in display and policy evaluation — NOT as a literal 2099
/// expiry. Verification is unchanged: the sentinel is a future timestamp, so
/// the temporal check passes; revocation is the sole termination mechanism
/// for such certs. See SPEC §5.7.
pub const NO_EXPIRY_SENTINEL: i64 = 4070908799;
/// Maximum number of certs in a delegation chain. A wire-determinism and
/// denial-of-service bound, not cryptography (SPEC §5.1); raised from 3 to 8
/// in v1.0.0-alpha.16 for multi-hop agent topologies.
pub const MAX_DELEGATION_CHAIN_DEPTH: usize = 8;
pub const CHALLENGE_WINDOW_SECONDS: i64 = 300;

// Input bounds (SPEC §5.1). The depth ceiling alone does not bound parsing or
// intersection work; these limits do. Violations route to the existing
// `invalid` status with a descriptive error_reason — no new status.

/// Bounds the encoded size of a ProofBundle. Wire decoders enforce it BEFORE
/// parsing; an oversized payload is rejected without ever being parsed.
pub const MAX_PROOF_BUNDLE_BYTES: usize = 131072; // 128 KiB
/// Bounds `len(DelegationCert.scope)`.
pub const MAX_SCOPES_PER_CERT: usize = 128;
/// Bounds `len(DelegationCert.constraints)`.
pub const MAX_CONSTRAINTS_PER_CERT: usize = 32;
/// Bounds the UTF-8 byte length of a single scope.
pub const MAX_SCOPE_LENGTH_BYTES: usize = 256;
/// Bounds `resource_path`'s `resource_id` (SPEC §5.1).
pub const MAX_IDENTIFIER_LENGTH_BYTES: usize = 512;
/// Bounds `AgentIdentity.name` (UTF-8 bytes), enforced at construction.
pub const MAX_AGENT_NAME_LENGTH_BYTES: usize = 256;
/// Bounds JSON container nesting in wire documents, enforced during parse.
pub const MAX_JSON_NESTING_DEPTH: usize = 16;

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

/// Ed25519 + ML-DSA-65 public key pair.
///
/// Canonical JSON form (keys in lex order):
/// `{"ed25519":"<base64-32-bytes>","ml_dsa_65":"<base64-1952-bytes>"}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    #[serde(
        serialize_with = "crate::canonical::wire_int::serialize",
        deserialize_with = "crate::canonical::wire_int::deserialize"
    )]
    pub issued_at: i64,
    #[serde(
        serialize_with = "crate::canonical::wire_int::serialize",
        deserialize_with = "crate::canonical::wire_int::deserialize"
    )]
    pub expires_at: i64,
    pub signature: HybridSignature,
}

impl DelegationCert {
    /// Reports whether the cert carries [`NO_EXPIRY_SENTINEL`], meaning "no
    /// expiry (until revoked)". Callers rendering expiry to users or applying
    /// lifetime policy caps MUST branch on this rather than treating the
    /// sentinel as a real 2099 timestamp.
    pub fn is_no_expiry(&self) -> bool {
        self.expires_at == NO_EXPIRY_SENTINEL
    }
}

/// Extension-constraint parameter value under the restricted value model
/// (SPEC §5.7.1): null, booleans, strings, safe integers (|n| ≤ 2^53−1), and
/// arrays/objects of these. Floats and non-integer numbers are prohibited;
/// integers beyond the safe range travel as decimal strings. Object keys are
/// held in a `BTreeMap` so canonical serialization emits them in byte-lex
/// order (RFC 8785) with no extra sort.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamsValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<ParamsValue>),
    Object(BTreeMap<String, ParamsValue>),
}

impl Serialize for ParamsValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ParamsValue::Null => serializer.serialize_unit(),
            ParamsValue::Bool(b) => serializer.serialize_bool(*b),
            ParamsValue::Int(n) => {
                if !crate::canonical::wire_int::in_domain(*n) {
                    return Err(serde::ser::Error::custom(
                        "params integer exceeds the safe-integer range; carry it as a decimal string",
                    ));
                }
                serializer.serialize_i64(*n)
            }
            ParamsValue::Str(s) => serializer.serialize_str(s),
            ParamsValue::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            ParamsValue::Object(map) => {
                // BTreeMap iterates in sorted key order → canonical.
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}

struct ParamsValueVisitor;

impl<'de> Visitor<'de> for ParamsValueVisitor {
    type Value = ParamsValue;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a restricted params value (null, bool, string, safe integer, array, or object)")
    }

    fn visit_bool<E: DeError>(self, v: bool) -> Result<Self::Value, E> {
        Ok(ParamsValue::Bool(v))
    }
    fn visit_i64<E: DeError>(self, v: i64) -> Result<Self::Value, E> {
        Ok(ParamsValue::Int(v))
    }
    fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
        if v > i64::MAX as u64 {
            return Err(E::custom(
                "params integer exceeds the safe-integer range; carry it as a decimal string",
            ));
        }
        Ok(ParamsValue::Int(v as i64))
    }
    fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
        // JSON numbers reach here as f64. Integral values within the safe
        // range are wire integers; anything else is outside the value model.
        if !v.is_finite() || v.fract() != 0.0 {
            return Err(E::custom(
                "params values must be safe integers, not floats (carry non-integers as strings)",
            ));
        }
        let max = crate::canonical::wire_int::MAX_SAFE_INTEGER as f64;
        if v.abs() > max {
            return Err(E::custom(
                "params integer exceeds the safe-integer range; carry it as a decimal string",
            ));
        }
        Ok(ParamsValue::Int(v as i64))
    }
    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(ParamsValue::Str(v.to_string()))
    }
    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        Ok(ParamsValue::Str(v))
    }
    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(ParamsValue::Null)
    }
    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(ParamsValue::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(item) = seq.next_element()? {
            out.push(item);
        }
        Ok(ParamsValue::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out: BTreeMap<String, ParamsValue> = BTreeMap::new();
        while let Some((k, v)) = map.next_entry::<String, ParamsValue>()? {
            if out.insert(k, v).is_some() {
                // Duplicate object keys are prohibited (SPEC §5.7.1).
                return Err(A::Error::custom("params contains a duplicate object key"));
            }
        }
        Ok(ParamsValue::Object(out))
    }
}

impl<'de> Deserialize<'de> for ParamsValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ParamsValueVisitor)
    }
}

/// Reports whether `t` is one of the canonical v1 constraint kinds
/// (SPEC §5.7.2). `params` is permitted only on non-canonical types.
pub fn is_canonical_constraint_type(t: &str) -> bool {
    matches!(
        t,
        "geo_circle"
            | "geo_polygon"
            | "geo_bbox"
            | "time_window"
            | "max_speed_mps"
            | "max_amount"
            | "max_rate"
            | "resource_path"
    )
}

// Deserialize helper for `path_prefix`: presence is load-bearing (SPEC
// §5.7.3). Serde only invokes a `deserialize_with` when the key is PRESENT,
// so an ABSENT field falls through to `#[serde(default)]` = None (whole
// resource). A present `null`, present `""`, or non-string value reaches
// this function and is REJECTED — a malformed path restriction must never
// silently widen into whole-resource authority.
fn de_path_prefix<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // `String::deserialize` rejects `null` and non-strings by type.
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Err(D::Error::custom(
            "constraint path_prefix must not be empty or null; omit the field to authorize the entire resource",
        ));
    }
    Ok(Some(s))
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
// Constraint deserializes THROUGH `ConstraintWire` (serde `try_from`) so
// cross-field wire invariants are enforced at the deserialize boundary — for
// direct `Constraint` decoding and for cert/bundle decoding alike, matching
// Go's `Constraint.UnmarshalJSON`. A `resource_id` on a `resource_path` that
// is absent, empty, null, or non-string is rejected here; strict wire
// acceptance does not differ by SDK. (`null`/non-string already fail as type
// errors against the `String` field; the `try_from` also closes absent and
// empty.)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConstraintWire {
    #[serde(default, deserialize_with = "crate::canonical::wire_int::deserialize")]
    count: i64,
    #[serde(default)]
    currency: String,
    #[serde(default)]
    end: String,
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    #[serde(default)]
    max_alt_m: f64,
    #[serde(default)]
    max_amount: f64,
    #[serde(default)]
    max_lat: f64,
    #[serde(default)]
    max_lon: f64,
    #[serde(default)]
    max_mps: f64,
    #[serde(default)]
    min_alt_m: f64,
    #[serde(default)]
    min_lat: f64,
    #[serde(default)]
    min_lon: f64,
    #[serde(default)]
    params: Option<BTreeMap<String, ParamsValue>>,
    #[serde(default, deserialize_with = "de_path_prefix")]
    path_prefix: Option<String>,
    #[serde(default)]
    points: Vec<[f64; 2]>,
    #[serde(default)]
    radius_m: f64,
    #[serde(default)]
    resource_id: String,
    #[serde(default)]
    start: String,
    #[serde(default)]
    tz: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, deserialize_with = "crate::canonical::wire_int::deserialize")]
    window_s: i64,
}

impl TryFrom<ConstraintWire> for Constraint {
    type Error = String;
    fn try_from(w: ConstraintWire) -> Result<Self, Self::Error> {
        if w.kind == "resource_path" && w.resource_id.is_empty() {
            return Err(
                "resource_path constraint requires a non-empty resource_id".into(),
            );
        }
        Ok(Constraint {
            count: w.count,
            currency: w.currency,
            end: w.end,
            lat: w.lat,
            lon: w.lon,
            max_alt_m: w.max_alt_m,
            max_amount: w.max_amount,
            max_lat: w.max_lat,
            max_lon: w.max_lon,
            max_mps: w.max_mps,
            min_alt_m: w.min_alt_m,
            min_lat: w.min_lat,
            min_lon: w.min_lon,
            params: w.params,
            path_prefix: w.path_prefix,
            points: w.points,
            radius_m: w.radius_m,
            resource_id: w.resource_id,
            start: w.start,
            tz: w.tz,
            kind: w.kind,
            window_s: w.window_s,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(try_from = "ConstraintWire")]
pub struct Constraint {
    pub count: i64,
    pub currency: String,
    pub end: String,
    pub lat: f64,
    pub lon: f64,
    pub max_alt_m: f64,
    pub max_amount: f64,
    pub max_lat: f64,
    pub max_lon: f64,
    pub max_mps: f64,
    pub min_alt_m: f64,
    pub min_lat: f64,
    pub min_lon: f64,
    /// Extension-constraint parameters (SPEC §5.7.1). Permitted ONLY on
    /// non-canonical types under the restricted value model. Canonical types
    /// carrying params are rejected at encode/issue/decode.
    pub params: Option<BTreeMap<String, ParamsValue>>,
    /// Optionally narrows a `resource_path` constraint to a path at or below
    /// it under segment-boundary matching (SPEC §5.7.3). Absence (`None`) —
    /// never the empty string — is the sole encoding of "entire resource".
    pub path_prefix: Option<String>,
    pub points: Vec<[f64; 2]>,
    pub radius_m: f64,
    /// Names the resource a `resource_path` constraint binds to. Opaque
    /// UTF-8; compared byte-for-byte, never dereferenced or normalized.
    pub resource_id: String,
    pub start: String,
    pub tz: String,
    pub kind: String,
    pub window_s: i64,
}

// Custom Serialize for Constraint — emits the canonical per-kind shape.
// Mirrors Go's Constraint.MarshalJSON and TS canonicalConstraintDict.
// Keys are emitted in alphabetical order, matching the other SDKs.
impl Serialize for Constraint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // params is permitted only on non-canonical types (SPEC §5.7.1).
        if self.params.is_some() && is_canonical_constraint_type(&self.kind) {
            return Err(serde::ser::Error::custom(format!(
                "canonical constraint type \"{}\" must not carry params",
                self.kind
            )));
        }
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
            "resource_path" => {
                // keys: path_prefix (only when present), resource_id, type.
                // Absence — not "" — is the sole encoding of whole-resource
                // authorization (SPEC §5.7.3).
                if self.resource_id.is_empty() {
                    return Err(serde::ser::Error::custom(
                        "resource_path constraint requires a non-empty resource_id",
                    ));
                }
                let mut v = Vec::new();
                if let Some(prefix) = &self.path_prefix {
                    v.push(("path_prefix", FieldValue::Str(prefix.clone())));
                }
                v.push(("resource_id", FieldValue::Str(self.resource_id.clone())));
                v.push(("type", FieldValue::Str(self.kind.clone())));
                v
            }
            // Extension kind — emit params (when present) plus the tag
            // (SPEC §5.7.1). "params" sorts before "type". Verifier without a
            // registered evaluator returns constraint_unknown on this shape.
            _ => {
                let mut v = Vec::new();
                if let Some(params) = &self.params {
                    v.push(("params", FieldValue::Params(params.clone())));
                }
                v.push(("type", FieldValue::Str(self.kind.clone())));
                v
            }
        };
        let mut m = serializer.serialize_map(Some(entries.len()))?;
        for (k, v) in entries {
            match v {
                FieldValue::F64(x) => m.serialize_entry(k, &x)?,
                FieldValue::I64(x) => {
                    // Encoder side of the wire integer domain (SPEC §6.2).
                    if !crate::canonical::wire_int::in_domain(x) {
                        return Err(serde::ser::Error::custom(
                            "integer outside the safe-integer range [-(2^53-1), 2^53-1]",
                        ));
                    }
                    m.serialize_entry(k, &x)?
                }
                FieldValue::Str(x) => m.serialize_entry(k, &x)?,
                FieldValue::Points(x) => m.serialize_entry(k, &x)?,
                FieldValue::Params(x) => m.serialize_entry(k, &x)?,
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
    Params(BTreeMap<String, ParamsValue>),
}

/// Callback answering "how many invocations of this cert in this window?"
/// — (cert_id, window_s) -> count. Used by rate-limit constraints.
pub type InvocationCounter<'a> = Box<dyn Fn(&str, i64) -> i64 + 'a>;

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
    pub invocations_in_window: Option<InvocationCounter<'a>>,
    /// The resource the operation targets (SPEC §5.16). Required by
    /// `resource_path`; `None` (or empty) → `constraint_unverifiable`.
    /// Compared byte-exactly against the constraint's `resource_id`.
    pub requested_resource_id: Option<String>,
    /// The path the operation targets, following the logical path model of
    /// §5.7.3. Callers MUST apply every decoding/normalization step (URL
    /// decode, Unicode NFC, case folding, separator conversion) BEFORE
    /// populating this; the verifier never transforms it.
    pub requested_path: Option<String>,
}

/// Proof an agent presents to a verifier.
///
/// v1.1 optional stream binding: when `stream_id` and `stream_seq` are set,
/// the bundle is "stream-bound" — it belongs to an ordered sequence of
/// interactions sharing a stream_id. Both are signed into the challenge bytes
/// (SPEC §6.4.2) so replay, reorder, or omission within the stream invalidate
/// the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub delegations: Vec<DelegationCert>,
    #[serde(with = "crate::canonical::base64_bytes")]
    pub challenge: Vec<u8>,
    #[serde(
        serialize_with = "crate::canonical::wire_int::serialize",
        deserialize_with = "crate::canonical::wire_int::deserialize"
    )]
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
    #[serde(
        default,
        skip_serializing_if = "is_zero_i64",
        serialize_with = "crate::canonical::wire_int::serialize",
        deserialize_with = "crate::canonical::wire_int::deserialize"
    )]
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
    /// A cert in the chain grants a scope that is not canonical, not a
    /// wildcard, and not a `custom:` extension (SPEC §9). Fail-closed —
    /// vocabulary outside the protocol is rejected as malformed rather than
    /// silently intersected.
    InvalidScope,
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
            Self::InvalidScope => "invalid_scope",
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
            "invalid_scope" => Self::InvalidScope,
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
#[serde(deny_unknown_fields)]
pub struct SessionToken {
    pub version: i32,
    pub session_id: String,
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub human_id: String,
    pub granted_scope: Vec<String>,
    #[serde(
        serialize_with = "crate::canonical::wire_int::serialize",
        deserialize_with = "crate::canonical::wire_int::deserialize"
    )]
    pub issued_at: i64,
    #[serde(
        serialize_with = "crate::canonical::wire_int::serialize",
        deserialize_with = "crate::canonical::wire_int::deserialize"
    )]
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
    // Slated for removal in v1.0.0-beta.1 — not worth a public type alias.
    #[allow(clippy::type_complexity)]
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
    /// Single-use tracking for verifier-issued challenges (SPEC §10). When
    /// set, the store is consulted (without consuming) before any signature
    /// work, and the challenge is atomically consumed after the structural,
    /// chain, and challenge-signature checks pass — before authorization
    /// evaluation. A forged or malformed presentation never consumes a
    /// challenge; a cryptographically valid presentation does, even if
    /// authorization is subsequently denied. When a store is in use,
    /// constraint evaluation is deferred until after consumption. The
    /// store's session binding is checked against `session_context`.
    pub challenge_store: Option<Box<dyn crate::challenge_store::ChallengeStore + 'a>>,
}

// Not derived: this manual impl exists to isolate the #[allow(deprecated)]
// initialization of `is_revoked` to a single construction site. Deriving
// would spread the deprecation suppression to the whole struct.
#[allow(clippy::derivable_impls)]
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
            challenge_store: None,
        }
    }
}
