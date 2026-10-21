//! Strict wire JSON for Protocol v2.
//!
//! The parser enforces the Go reference's `checkWireJSONV2` rules in one pass:
//! valid UTF-8, no unpaired UTF-16 surrogate escapes, no duplicate object keys
//! (compared after unescaping), integer tokens inside the safe-integer range,
//! no negative zero, bounded container nesting, and no trailing data. Every
//! node records its byte span so callers can hash exact embedded bytes.
//!
//! Field access mirrors Go `encoding/json` decoding into structs with
//! `DisallowUnknownFields`: an absent or `null` member yields the zero value,
//! while a wrong JSON type is an error. Required/non-null checks are applied
//! separately by [`Obj::require`], exactly where Go calls `requireV2Fields`.

use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::errors::{plain, V2Error, V2Result};
use crate::canonical::wire_int::MAX_SAFE_INTEGER;
use crate::types::{HybridPublicKey, HybridSignature, MAX_JSON_NESTING_DEPTH};

/// Protocol byte-field member names (Go `wireByteFields`), checked at any depth.
const WIRE_BYTE_FIELDS: &[&str] = &[
    "bundle_hash",
    "chain_hash",
    "challenge",
    "context_hash",
    "ed25519",
    "entry_data",
    "mac",
    "ml_dsa_65",
    "prev_hash",
    "session_context",
    "stream_id",
    "terms_canonical_json",
];

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JV {
    Null,
    Bool(bool),
    /// Raw number token text.
    Num(String),
    Str(String),
    Arr(Vec<JNode>),
    Obj(Vec<(String, JNode)>),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JNode {
    pub v: JV,
    pub start: usize,
    pub end: usize,
}

impl JNode {
    pub(crate) fn is_null(&self) -> bool {
        matches!(self.v, JV::Null)
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> V2Result<JNode> {
        self.ws();
        let start = self.i;
        let Some(&c) = self.s.get(self.i) else {
            return plain("wire: invalid JSON: unexpected end of input");
        };
        let v = match c {
            b'{' => {
                if depth >= MAX_JSON_NESTING_DEPTH {
                    return plain("wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH");
                }
                self.i += 1;
                let mut fields: Vec<(String, JNode)> = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        if self.s.get(self.i) != Some(&b'"') {
                            return plain("wire: invalid JSON: expected object key");
                        }
                        let key = self.string()?;
                        if fields.iter().any(|(k, _)| *k == key) {
                            return plain(format!("wire: duplicate key {key:?} in JSON object"));
                        }
                        self.ws();
                        if self.s.get(self.i) != Some(&b':') {
                            return plain("wire: invalid JSON: expected ':'");
                        }
                        self.i += 1;
                        let value = self.value(depth + 1)?;
                        fields.push((key, value));
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return plain("wire: invalid JSON: expected ',' or '}'"),
                        }
                    }
                }
                JV::Obj(fields)
            }
            b'[' => {
                if depth >= MAX_JSON_NESTING_DEPTH {
                    return plain("wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH");
                }
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        items.push(self.value(depth + 1)?);
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return plain("wire: invalid JSON: expected ',' or ']'"),
                        }
                    }
                }
                JV::Arr(items)
            }
            b'"' => JV::Str(self.string()?),
            b't' => self.literal(b"true", JV::Bool(true))?,
            b'f' => self.literal(b"false", JV::Bool(false))?,
            b'n' => self.literal(b"null", JV::Null)?,
            b'-' | b'0'..=b'9' => JV::Num(self.number()?),
            _ => return plain("wire: invalid JSON: unexpected character"),
        };
        Ok(JNode {
            v,
            start,
            end: self.i,
        })
    }

    fn literal(&mut self, text: &[u8], v: JV) -> V2Result<JV> {
        if self.s[self.i..].starts_with(text) {
            self.i += text.len();
            Ok(v)
        } else {
            plain("wire: invalid JSON literal")
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> V2Result<String> {
        let start = self.i;
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return plain("wire: invalid JSON number"),
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return plain("wire: invalid JSON number");
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return plain("wire: invalid JSON number");
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).expect("ascii number");
        // Go: reject a "-" token whose value parses to zero (-0, -0.0, -0e5,
        // and underflow such as -1e-400). Ordinary negatives like -0.5 pass.
        if text.starts_with('-') && text.parse::<f64>() == Ok(0.0) {
            return plain("wire: negative zero is not a canonical number");
        }
        if !text.contains(['.', 'e', 'E']) {
            match text.parse::<i64>() {
                Ok(n) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) => {}
                _ => {
                    return plain(format!(
                        "wire: integer {text} outside the safe-integer range [-(2^53-1), 2^53-1]"
                    ))
                }
            }
        }
        Ok(text.to_string())
    }

    fn hex4(&mut self) -> V2Result<u32> {
        let Some(chunk) = self.s.get(self.i..self.i + 4) else {
            return plain("wire: invalid JSON escape");
        };
        let text =
            std::str::from_utf8(chunk).map_err(|_| V2Error::plain("wire: invalid JSON escape"))?;
        let v = u32::from_str_radix(text, 16)
            .map_err(|_| V2Error::plain("wire: invalid JSON escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> V2Result<String> {
        // Caller guarantees the opening quote.
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(&c) = self.s.get(self.i) else {
                return plain("wire: invalid JSON: unterminated string");
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let Some(&e) = self.s.get(self.i) else {
                        return plain("wire: invalid JSON escape");
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return plain("wire: unpaired UTF-16 surrogate escape");
                                }
                                self.i += 2;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return plain("wire: unpaired UTF-16 surrogate escape");
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&first) {
                                return plain("wire: unpaired UTF-16 surrogate escape");
                            } else {
                                first
                            };
                            out.push(
                                char::from_u32(code)
                                    .ok_or_else(|| V2Error::plain("wire: invalid JSON escape"))?,
                            );
                        }
                        _ => return plain("wire: invalid JSON escape"),
                    }
                }
                0x00..=0x1f => return plain("wire: invalid JSON: control character in string"),
                _ => {
                    // Copy one complete UTF-8 scalar (input is validated UTF-8).
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    out.push_str(
                        std::str::from_utf8(&self.s[self.i..self.i + len])
                            .expect("validated UTF-8"),
                    );
                    self.i += len;
                }
            }
        }
    }
}

/// Parse untrusted wire JSON under the strict v2 rules and check canonical
/// base64 in byte fields. `top_byte` adds v2-only top-level byte fields and
/// `top_text` exempts top-level members that are text in this schema.
pub(crate) fn parse_wire(data: &[u8], top_byte: &[&str], top_text: &[&str]) -> V2Result<JNode> {
    let root = parse_json(data)?;
    check_byte_fields(&root, 0, top_byte, top_text)?;
    Ok(root)
}

/// Parse strict JSON without byte-field checks.
pub(crate) fn parse_json(data: &[u8]) -> V2Result<JNode> {
    if std::str::from_utf8(data).is_err() {
        return plain("wire: invalid UTF-8");
    }
    let mut p = Parser { s: data, i: 0 };
    let root = p.value(0)?;
    p.ws();
    if p.i != data.len() {
        return plain("wire: trailing data after JSON document");
    }
    Ok(root)
}

fn check_byte_fields(
    node: &JNode,
    depth: usize,
    top_byte: &[&str],
    top_text: &[&str],
) -> V2Result<()> {
    match &node.v {
        JV::Obj(fields) => {
            let d = depth + 1;
            for (k, v) in fields {
                if let JV::Str(s) = &v.v {
                    let wire = WIRE_BYTE_FIELDS.contains(&k.as_str())
                        && !(d == 1 && top_text.contains(&k.as_str()));
                    if wire || (d == 1 && top_byte.contains(&k.as_str())) {
                        check_canonical_base64(k, s)?;
                    }
                }
                check_byte_fields(v, d, top_byte, top_text)?;
            }
            Ok(())
        }
        JV::Arr(items) => {
            for item in items {
                check_byte_fields(item, depth + 1, top_byte, top_text)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_canonical_base64(key: &str, s: &str) -> V2Result<()> {
    match STANDARD.decode(s) {
        Ok(decoded) if STANDARD.encode(&decoded) == s => Ok(()),
        _ => plain(format!(
            "wire: field {key:?}: malformed or non-canonical base64"
        )),
    }
}

/// Decode canonical standard base64.
pub(crate) fn b64_decode(s: &str) -> V2Result<Vec<u8>> {
    match STANDARD.decode(s) {
        Ok(decoded) if STANDARD.encode(&decoded) == s => Ok(decoded),
        _ => plain("wire: malformed or non-canonical base64"),
    }
}

/// Object view with Go-struct decoding semantics.
pub(crate) struct Obj<'a> {
    pub fields: &'a [(String, JNode)],
}

pub(crate) fn obj(node: &JNode) -> V2Result<Obj<'_>> {
    match &node.v {
        JV::Obj(fields) => Ok(Obj { fields }),
        _ => plain("wire: expected a JSON object"),
    }
}

impl<'a> Obj<'a> {
    pub(crate) fn get(&self, key: &str) -> Option<&'a JNode> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Go `requireV2Fields`: every name present and non-null unless nullable.
    pub(crate) fn require(&self, names: &[&str], nullable: &[&str]) -> V2Result<()> {
        for name in names {
            match self.get(name) {
                None => return plain(format!("wire v2: required field {name:?} is missing")),
                Some(v) if v.is_null() && !nullable.contains(name) => {
                    return plain(format!("wire v2: required field {name:?} must not be null"))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Go `DisallowUnknownFields`: reject any member outside `allowed`.
    pub(crate) fn only(&self, allowed: &[&str]) -> V2Result<()> {
        for (k, _) in self.fields {
            if !allowed.contains(&k.as_str()) {
                return plain(format!("wire: unknown field {k:?}"));
            }
        }
        Ok(())
    }

    fn present(&self, key: &str) -> Option<&'a JNode> {
        self.get(key).filter(|v| !v.is_null())
    }

    pub(crate) fn str(&self, key: &str) -> V2Result<String> {
        match self.present(key) {
            None => Ok(String::new()),
            Some(v) => as_str(v),
        }
    }

    pub(crate) fn opt_str(&self, key: &str) -> V2Result<Option<String>> {
        match self.present(key) {
            None => Ok(None),
            Some(v) => as_str(v).map(Some),
        }
    }

    pub(crate) fn i64(&self, key: &str) -> V2Result<i64> {
        match self.present(key) {
            None => Ok(0),
            Some(v) => as_i64(v),
        }
    }

    pub(crate) fn opt_i64(&self, key: &str) -> V2Result<Option<i64>> {
        match self.present(key) {
            None => Ok(None),
            Some(v) => as_i64(v).map(Some),
        }
    }

    pub(crate) fn u16(&self, key: &str) -> V2Result<u16> {
        let n = self.i64(key)?;
        u16::try_from(n).map_err(|_| V2Error::plain(format!("wire: {key} out of range")))
    }

    pub(crate) fn bytes(&self, key: &str) -> V2Result<Vec<u8>> {
        match self.present(key) {
            None => Ok(Vec::new()),
            Some(v) => b64_decode(&as_str(v)?),
        }
    }

    pub(crate) fn opt_bytes(&self, key: &str) -> V2Result<Option<Vec<u8>>> {
        match self.present(key) {
            None => Ok(None),
            Some(v) => b64_decode(&as_str(v)?).map(Some),
        }
    }

    pub(crate) fn str_array(&self, key: &str) -> V2Result<Vec<String>> {
        match self.present(key) {
            None => Ok(Vec::new()),
            Some(v) => match &v.v {
                // Go decodes a null element of []string as "".
                JV::Arr(items) => items
                    .iter()
                    .map(|i| {
                        if i.is_null() {
                            Ok(String::new())
                        } else {
                            as_str(i)
                        }
                    })
                    .collect(),
                _ => plain(format!("wire: {key} must be an array of strings")),
            },
        }
    }

    pub(crate) fn array(&self, key: &str) -> V2Result<&'a [JNode]> {
        match self.present(key) {
            None => Ok(&[]),
            Some(v) => match &v.v {
                JV::Arr(items) => Ok(items),
                _ => plain(format!("wire: {key} must be an array")),
            },
        }
    }

    pub(crate) fn pub_key(&self, key: &str) -> V2Result<HybridPublicKey> {
        let (ed25519, ml_dsa_65) = self.pair(key)?;
        Ok(HybridPublicKey { ed25519, ml_dsa_65 })
    }

    pub(crate) fn sig(&self, key: &str) -> V2Result<HybridSignature> {
        let (ed25519, ml_dsa_65) = self.pair(key)?;
        Ok(HybridSignature { ed25519, ml_dsa_65 })
    }

    fn pair(&self, key: &str) -> V2Result<(Vec<u8>, Vec<u8>)> {
        match self.present(key) {
            None => Ok((Vec::new(), Vec::new())),
            Some(v) => {
                let o = obj(v)?;
                o.only(&["ed25519", "ml_dsa_65"])?;
                Ok((o.bytes("ed25519")?, o.bytes("ml_dsa_65")?))
            }
        }
    }
}

pub(crate) fn as_str(v: &JNode) -> V2Result<String> {
    match &v.v {
        JV::Str(s) => Ok(s.clone()),
        _ => plain("wire: expected a JSON string"),
    }
}

pub(crate) fn as_i64(v: &JNode) -> V2Result<i64> {
    match &v.v {
        JV::Num(t) if !t.contains(['.', 'e', 'E']) => t
            .parse::<i64>()
            .map_err(|_| V2Error::plain("wire: integer out of range")),
        _ => plain("wire: expected a JSON integer"),
    }
}

/// Canonical JSON output value. Object keys are sorted by UTF-8 bytes on write.
#[derive(Debug, Clone)]
pub(crate) enum CJ {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    /// Pre-encoded canonical JSON (constraints, embedded objects).
    Raw(String),
    Arr(Vec<CJ>),
    Obj(Vec<(String, CJ)>),
}

impl CJ {
    pub(crate) fn obj(fields: Vec<(&str, CJ)>) -> CJ {
        CJ::Obj(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    pub(crate) fn s(value: &str) -> CJ {
        CJ::Str(value.to_string())
    }

    pub(crate) fn strs(values: &[String]) -> CJ {
        CJ::Arr(values.iter().map(|v| CJ::Str(v.clone())).collect())
    }

    pub(crate) fn key(k: &HybridPublicKey) -> CJ {
        CJ::obj(vec![
            ("ed25519", CJ::Bytes(k.ed25519.clone())),
            ("ml_dsa_65", CJ::Bytes(k.ml_dsa_65.clone())),
        ])
    }

    pub(crate) fn sig(s: &HybridSignature) -> CJ {
        CJ::obj(vec![
            ("ed25519", CJ::Bytes(s.ed25519.clone())),
            ("ml_dsa_65", CJ::Bytes(s.ml_dsa_65.clone())),
        ])
    }
}

/// RatifyCanonicalJSON (SPEC §6) of `value`. Integers outside the
/// safe-integer range are an error, never emitted.
pub(crate) fn canonical(value: &CJ) -> V2Result<Vec<u8>> {
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write(value: &CJ, out: &mut String) -> V2Result<()> {
    match value {
        CJ::Null => out.push_str("null"),
        CJ::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        CJ::Int(n) => {
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(n) {
                return plain(format!(
                    "canonical JSON: integer {n} outside the safe-integer range [-(2^53-1), 2^53-1]"
                ));
            }
            out.push_str(&n.to_string());
        }
        CJ::Str(s) => crate::canonical::encode_str(s, out),
        CJ::Bytes(b) => crate::canonical::encode_str(&STANDARD.encode(b), out),
        CJ::Raw(r) => out.push_str(r),
        CJ::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        CJ::Obj(fields) => {
            let mut sorted: Vec<&(String, CJ)> = fields.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                crate::canonical::encode_str(k, out);
                out.push(':');
                write(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Re-encode a parsed node canonically (numbers keep their token text).
pub(crate) fn node_to_cj(node: &JNode) -> CJ {
    match &node.v {
        JV::Null => CJ::Null,
        JV::Bool(b) => CJ::Bool(*b),
        JV::Num(t) => CJ::Raw(t.clone()),
        JV::Str(s) => CJ::Str(s.clone()),
        JV::Arr(items) => CJ::Arr(items.iter().map(node_to_cj).collect()),
        JV::Obj(fields) => CJ::Obj(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), node_to_cj(v)))
                .collect(),
        ),
    }
}

/// Re-encode arbitrary strict JSON as RatifyCanonicalJSON, preserving
/// explicit `null` members (unlike the v1 `canonical_json` helper).
pub fn canonical_json_v2(data: &[u8]) -> V2Result<Vec<u8>> {
    canonical(&node_to_cj(&parse_json(data)?))
}

#[cfg(test)]
mod tests {
    use super::parse_json;

    #[test]
    fn negative_zero_values_are_rejected_but_negative_floats_decode() {
        for bad in ["-0", "-0.0", "-0e5", "-0E0", "-0.000", "-1e-400"] {
            let doc = format!("{{\"a\":{bad}}}");
            assert!(
                parse_json(doc.as_bytes()).is_err(),
                "{bad} must be rejected"
            );
        }
        for good in ["-0.5", "-122.4194", "-1e-3", "0", "0.0", "-1"] {
            let doc = format!("{{\"a\":{good}}}");
            assert!(parse_json(doc.as_bytes()).is_ok(), "{good} must decode");
        }
    }
}
