//! The restricted argument value model and its canonical form (Go
//! `verifyclient/mcp/arguments.go`).

use std::collections::BTreeMap;

use super::{McpError, MAX_ARGUMENT_DEPTH, MAX_SAFE_INTEGER};

/// Parse the JSON text of `params.arguments` under the restricted value
/// model and return its canonical bytes. The model allows objects with
/// unique keys, strings, integers in the safe range (no fraction, exponent,
/// or negative zero), booleans, and arrays, nested at most
/// [`MAX_ARGUMENT_DEPTH`] deep. Strings and keys must be valid UTF-8 without
/// control characters (U+0000 to U+001F, U+007F to U+009F), U+2028, U+2029,
/// or unpaired surrogate escapes. Empty input, JSON whitespace, and the
/// literal `null` mean the empty object.
///
/// Canonical form: object keys sorted by their UTF-8 bytes, no insignificant
/// whitespace, strings with only `"` and `\` escaped, integers in decimal.
pub fn canonical_arguments(raw: impl AsRef<[u8]>) -> Result<Vec<u8>, McpError> {
    let raw = raw.as_ref();
    let trimmed = trim_space(raw);
    if trimmed.is_empty() || trimmed == b"null" {
        return Ok(b"{}".to_vec());
    }
    let mut p = Parser { input: raw, pos: 0 };
    p.space();
    if p.peek() != Some(b'{') {
        return Err(McpError::InvalidArguments);
    }
    let v = p.value(0)?;
    p.space();
    if p.pos != raw.len() {
        return Err(McpError::InvalidArguments);
    }
    let mut out = Vec::new();
    write_value(&mut out, &v);
    Ok(out)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim_space(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !is_space(*c)).unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !is_space(*c))
        .map_or(start, |i| i + 1);
    &b[start..end]
}

enum Value {
    // String ordering is UTF-8 byte ordering, the canonical key order.
    Object(BTreeMap<String, Value>),
    Array(Vec<Value>),
    String(String),
    Integer(i64),
    Bool(bool),
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

const INVALID: Result<Value, McpError> = Err(McpError::InvalidArguments);

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn space(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> bool {
        if self.input[self.pos..].starts_with(word) {
            self.pos += word.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, McpError> {
        if depth > MAX_ARGUMENT_DEPTH {
            return INVALID;
        }
        self.space();
        let Some(c) = self.peek() else {
            return INVALID;
        };
        match c {
            b'{' => {
                self.pos += 1;
                let mut members = BTreeMap::new();
                self.space();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                loop {
                    self.space();
                    let key = self.string()?;
                    if members.contains_key(&key) {
                        return INVALID;
                    }
                    self.space();
                    if self.peek() != Some(b':') {
                        return INVALID;
                    }
                    self.pos += 1;
                    let child = self.value(depth + 1)?;
                    members.insert(key, child);
                    self.space();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Value::Object(members));
                        }
                        _ => return INVALID,
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.space();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.space();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Value::Array(items));
                        }
                        _ => return INVALID,
                    }
                }
            }
            b'"' => self.string().map(Value::String),
            b't' if self.literal(b"true") => Ok(Value::Bool(true)),
            b'f' if self.literal(b"false") => Ok(Value::Bool(false)),
            b'-' | b'0'..=b'9' => self.number(),
            _ => INVALID,
        }
    }

    /// Only the JSON integer grammar `-?(0|[1-9][0-9]*)`, in the safe range.
    fn number(&mut self) -> Result<Value, McpError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return INVALID,
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return INVALID;
        }
        let text = &self.input[start..self.pos];
        if text == b"-0" || text.len() > 17 {
            return INVALID;
        }
        // The text is ASCII digits with an optional sign, at most 17 bytes.
        let n: i64 = std::str::from_utf8(text)
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or(McpError::InvalidArguments)?;
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) {
            return INVALID;
        }
        Ok(Value::Integer(n))
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.input.get(self.pos..self.pos + 4)?;
        let mut r = 0u32;
        for c in digits {
            r = (r << 4) | (*c as char).to_digit(16)?;
        }
        self.pos += 4;
        Some(r)
    }

    fn string(&mut self) -> Result<String, McpError> {
        if self.peek() != Some(b'"') {
            return Err(McpError::InvalidArguments);
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or(McpError::InvalidArguments)?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let e = self.peek().ok_or(McpError::InvalidArguments)?;
                    self.pos += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e as char),
                        b'u' => {
                            let mut r = self.hex4().ok_or(McpError::InvalidArguments)?;
                            if (0xd800..=0xdfff).contains(&r) {
                                if r >= 0xdc00 || !self.literal(b"\\u") {
                                    return Err(McpError::InvalidArguments);
                                }
                                let low = self.hex4().ok_or(McpError::InvalidArguments)?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(McpError::InvalidArguments);
                                }
                                r = 0x10000 + ((r - 0xd800) << 10) + (low - 0xdc00);
                            }
                            let ch = char::from_u32(r).ok_or(McpError::InvalidArguments)?;
                            if !allowed(ch) {
                                return Err(McpError::InvalidArguments);
                            }
                            out.push(ch);
                        }
                        // \b \f \n \r \t decode to control characters, which
                        // the model refuses; any other escape is not JSON.
                        _ => return Err(McpError::InvalidArguments),
                    }
                }
                _ => {
                    let ch = self.utf8_char().ok_or(McpError::InvalidArguments)?;
                    if !allowed(ch) {
                        return Err(McpError::InvalidArguments);
                    }
                    out.push(ch);
                }
            }
        }
    }

    /// Decode one UTF-8 character, refusing invalid, overlong, and
    /// surrogate encodings.
    fn utf8_char(&mut self) -> Option<char> {
        let width = match self.peek()? {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return None,
        };
        let bytes = self.input.get(self.pos..self.pos + width)?;
        let ch = std::str::from_utf8(bytes).ok()?.chars().next()?;
        self.pos += width;
        Some(ch)
    }
}

fn allowed(c: char) -> bool {
    let r = c as u32;
    !(r < 0x20 || (0x7f..=0x9f).contains(&r) || r == 0x2028 || r == 0x2029)
}

fn write_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Object(members) => {
            out.push(b'{');
            for (i, (k, child)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                write_value(out, child);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item);
            }
            out.push(b']');
        }
        Value::String(s) => write_string(out, s),
        Value::Integer(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for b in s.bytes() {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b'"');
}
