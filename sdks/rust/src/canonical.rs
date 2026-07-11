//! Canonical JSON serialization per Ratify Protocol SPEC §6.
//!
//! Every implementation MUST produce byte-identical output for the same
//! input or signatures will not verify across languages.
//!
//! Rules:
//!   - Object members in lex order (byte order on UTF-8), RECURSIVELY.
//!   - No whitespace between tokens. No trailing newline.
//!   - UTF-8 encoding.
//!   - Integers as shortest decimal.
//!   - Byte arrays as base64-standard strings with padding.
//!   - '<', '>', '&' pass through unmodified.
//!   - U+2028 / U+2029 escape as \\u2028 / \\u2029 (matches Go behavior).
//!   - Minimum string escaping per RFC 8259.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Canonical JSON-encode a serde_json::Value.
///
/// Available with the `std` feature only (requires `serde_json`).
#[cfg(feature = "std")]
pub fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    let mut out = String::new();
    encode_value(value, &mut out);
    out.into_bytes()
}

#[cfg(feature = "std")]
fn encode_value(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&encode_number(n)),
        Value::String(s) => encode_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_value(item, out);
            }
            out.push(']');
        }
        Value::Object(obj) => {
            // Collect keys and sort lex-order.
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            out.push('{');
            let mut first = true;
            for k in keys {
                let val = &obj[k];
                // Skip nulls — matches Go's omitempty for optional fields.
                if val.is_null() {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                encode_string(k, out);
                out.push(':');
                encode_value(val, out);
                first = false;
            }
            out.push('}');
        }
    }
}

// encode_number reproduces the Go / TS / Python policy: integers and
// integer-valued floats serialize as shortest decimal integer (no "500.0"),
// non-integer floats serialize via their default textual representation.
// Without this, serde_json's f64 default emits "500.0" where the other
// implementations emit "500", breaking cross-SDK byte identicality.
#[cfg(feature = "std")]
fn encode_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 {
            // Whole-number f64 → integer form.
            return (f as i64).to_string();
        }
        return f.to_string();
    }
    n.to_string()
}

fn encode_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            // Everything else passes through unmodified (NO HTML escape).
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Standard base64 encode with padding.
pub fn base64_std_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Standard base64 decode.
pub fn base64_std_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

/// Lowercase hex.
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Lower- or upper-case hex.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

// ---------------------------------------------------------------------------
// Low-level canonical-JSON helpers (no serde_json::Value intermediary)
//
// These write directly into a &mut String and are the building blocks for
// the no_std signing-bytes functions in crypto.rs and receipts.rs.
// ---------------------------------------------------------------------------

/// Write a canonical-JSON string (with escaping) into `out`.
pub fn encode_str(s: &str, out: &mut String) {
    encode_string(s, out);
}

/// Write a canonical-JSON i64 (shortest decimal) into `out`.
pub fn encode_i64(n: i64, out: &mut String) {
    out.push_str(&n.to_string());
}

/// Write a canonical-JSON i32 into `out`.
pub fn encode_i32(n: i32, out: &mut String) {
    out.push_str(&n.to_string());
}

/// Write a canonical-JSON f64 following the Ratify integer-valued rule:
/// whole-number f64s emit as shortest decimal integer; others as-is.
pub fn encode_f64(n: f64, out: &mut String) {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e15 {
        out.push_str(&(n as i64).to_string());
    } else {
        out.push_str(&n.to_string());
    }
}

/// Write a canonical-JSON bool into `out`.
pub fn encode_bool(b: bool, out: &mut String) {
    out.push_str(if b { "true" } else { "false" });
}

/// Write a base64-standard-encoded byte slice as a canonical-JSON string.
pub fn encode_bytes_b64(b: &[u8], out: &mut String) {
    let s = base64_std_encode(b);
    encode_string(&s, out);
}

/// Write a canonical-JSON array of strings into `out`.
pub fn encode_str_array(arr: &[String], out: &mut String) {
    out.push('[');
    for (i, s) in arr.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_string(s, out);
    }
    out.push(']');
}

/// Write a canonical-JSON array of [f64; 2] pairs (geo polygon points).
pub fn encode_points_array(pts: &[[f64; 2]], out: &mut String) {
    out.push('[');
    for (i, pt) in pts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        encode_f64(pt[0], out);
        out.push(',');
        encode_f64(pt[1], out);
        out.push(']');
    }
    out.push(']');
}

/// Write a canonical Constraint object into `out`, matching the per-kind
/// shape emitted by Constraint's Serialize impl (alphabetical keys).
pub fn encode_constraint(c: &crate::types::Constraint, out: &mut String) {
    match c.kind.as_str() {
        "geo_circle" => {
            // keys: lat, lon, radius_m, type
            out.push('{');
            out.push_str("\"lat\":");  encode_f64(c.lat, out);
            out.push_str(",\"lon\":");  encode_f64(c.lon, out);
            out.push_str(",\"radius_m\":");  encode_f64(c.radius_m, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push('}');
        }
        "geo_polygon" => {
            // keys: points, type
            out.push('{');
            out.push_str("\"points\":");  encode_points_array(&c.points, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push('}');
        }
        "geo_bbox" => {
            // base keys: max_lat, max_lon, min_lat, min_lon, type
            // optional altitude keys (alphabetical insert): max_alt_m < max_lat, min_alt_m < min_lat
            out.push('{');
            let has_alt = c.min_alt_m != 0.0 || c.max_alt_m != 0.0;
            if has_alt {
                out.push_str("\"max_alt_m\":");  encode_f64(c.max_alt_m, out);
                out.push(',');
            }
            out.push_str("\"max_lat\":");  encode_f64(c.max_lat, out);
            out.push_str(",\"max_lon\":");  encode_f64(c.max_lon, out);
            if has_alt {
                out.push_str(",\"min_alt_m\":");  encode_f64(c.min_alt_m, out);
            }
            out.push_str(",\"min_lat\":");  encode_f64(c.min_lat, out);
            out.push_str(",\"min_lon\":");  encode_f64(c.min_lon, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push('}');
        }
        "time_window" => {
            // keys: end, start, type, tz
            out.push('{');
            out.push_str("\"end\":");  encode_string(&c.end, out);
            out.push_str(",\"start\":");  encode_string(&c.start, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push_str(",\"tz\":");  encode_string(&c.tz, out);
            out.push('}');
        }
        "max_speed_mps" => {
            // keys: max_mps, type
            out.push('{');
            out.push_str("\"max_mps\":");  encode_f64(c.max_mps, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push('}');
        }
        "max_amount" => {
            // keys: currency, max_amount, type
            out.push('{');
            out.push_str("\"currency\":");  encode_string(&c.currency, out);
            out.push_str(",\"max_amount\":");  encode_f64(c.max_amount, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push('}');
        }
        "max_rate" => {
            // keys: count, type, window_s
            out.push('{');
            out.push_str("\"count\":");  encode_i64(c.count, out);
            out.push_str(",\"type\":");  encode_string(&c.kind, out);
            out.push_str(",\"window_s\":");  encode_i64(c.window_s, out);
            out.push('}');
        }
        // Unknown kind: emit only the type tag, matching the Serialize impl.
        _ => {
            out.push('{');
            out.push_str("\"type\":");  encode_string(&c.kind, out);
            out.push('}');
        }
    }
}

/// Write a canonical-JSON array of Constraint objects.
pub fn encode_constraints(cs: &[crate::types::Constraint], out: &mut String) {
    out.push('[');
    for (i, c) in cs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_constraint(c, out);
    }
    out.push(']');
}

/// Write a canonical HybridPublicKey object: `{"ed25519":"...","ml_dsa_65":"..."}`.
/// Keys are already in lex order: "ed25519" < "ml_dsa_65".
pub fn encode_hybrid_pub_key(pk: &crate::types::HybridPublicKey, out: &mut String) {
    out.push('{');
    out.push_str("\"ed25519\":");  encode_bytes_b64(&pk.ed25519, out);
    out.push_str(",\"ml_dsa_65\":");  encode_bytes_b64(&pk.ml_dsa_65, out);
    out.push('}');
}

/// Write a canonical HybridSignature object: `{"ed25519":"...","ml_dsa_65":"..."}`.
pub fn encode_hybrid_sig(sig: &crate::types::HybridSignature, out: &mut String) {
    out.push('{');
    out.push_str("\"ed25519\":");  encode_bytes_b64(&sig.ed25519, out);
    out.push_str(",\"ml_dsa_65\":");  encode_bytes_b64(&sig.ml_dsa_65, out);
    out.push('}');
}

/// serde helper to (de)serialize Vec<u8> as base64-standard strings.
pub mod base64_bytes {
    #[cfg(not(feature = "std"))]
    use alloc::{format, string::String, vec::Vec};
    use super::{base64_std_decode, base64_std_encode};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64_std_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64_std_decode(&s).map_err(|e| D::Error::custom(format!("base64 decode: {e}")))
    }
}
