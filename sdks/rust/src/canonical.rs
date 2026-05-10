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

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

/// Canonical JSON-encode a serde_json::Value.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    encode_value(value, &mut out);
    out.into_bytes()
}

fn encode_value(v: &Value, out: &mut String) {
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

/// serde helper to (de)serialize Vec<u8> as base64-standard strings.
pub mod base64_bytes {
    use super::{base64_std_decode, base64_std_encode};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
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
