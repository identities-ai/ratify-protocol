//! Resource-bound authority — the `resource_path` constraint's path model,
//! segment-boundary matching, and the extension-constraint params value model
//! (SPEC §5.7.1, §5.7.3). Mirrors Go's `resource_path.go` byte-for-byte.
//!
//! Paths are absolute logical POSIX-style paths: they name a location inside
//! the resource's own namespace, not filesystem paths on any machine. The
//! verifier compares bytes exactly — no Unicode normalization, no percent
//! decoding, no case folding. Issuers and adapters pre-normalize (NFC) and
//! pre-decode BEFORE constructing constraints and verifier context; nothing
//! transforms a path after verification.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

use crate::canonical::wire_int::MAX_SAFE_INTEGER;
use crate::types::{
    is_canonical_constraint_type, Constraint, ParamsValue, MAX_IDENTIFIER_LENGTH_BYTES,
    MAX_JSON_NESTING_DEPTH,
};

/// Validate `p` against the logical path model (SPEC §5.7.3) and return its
/// comparison form: at most one trailing `/` trimmed, except for the root
/// path `/` itself. Returns `Err` when `p` is not a valid logical path:
///
///   - must begin with `/` (`/` is the only separator)
///   - no NUL byte, no backslash (rejected, never translated)
///   - no `.` or `..` segment (rejected outright, never resolved)
///   - no empty interior segment (`/a//b` is invalid; `/` is valid)
///
/// `%` is an ordinary literal byte: the path model has no percent-encoding.
pub fn normalize_resource_path(p: &str) -> Result<String, String> {
    if p.is_empty() {
        return Err("path is empty".to_string());
    }
    if !p.starts_with('/') {
        return Err("path must begin with '/'".to_string());
    }
    if p.as_bytes().contains(&0x00) {
        return Err("path contains a NUL byte".to_string());
    }
    if p.contains('\\') {
        return Err("path contains a backslash; '/' is the only separator".to_string());
    }
    if p == "/" {
        return Ok("/".to_string());
    }
    // Trim at most one trailing slash before segment validation: "/docs/" ≡
    // "/docs", while "/docs//" leaves an empty interior segment and is invalid.
    let trimmed = p.strip_suffix('/').unwrap_or(p);
    for seg in trimmed[1..].split('/') {
        match seg {
            "" => return Err("path contains an empty segment".to_string()),
            "." | ".." => {
                return Err(
                    "path contains a dot-segment; dot-segments are rejected, never resolved"
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    Ok(trimmed.to_string())
}

/// Report whether `requested_path` is at or below `path_prefix` under
/// segment-boundary prefix matching (SPEC §5.7.3). This is NOT glob matching
/// and NOT plain string-prefix matching: `/src` matches `/src` and
/// `/src/a.ts`, never `/src-old/a.ts` or `/srcx`.
pub fn resource_path_matches(path_prefix: &str, requested_path: &str) -> bool {
    let prefix = match normalize_resource_path(path_prefix) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let path = match normalize_resource_path(requested_path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if prefix == "/" {
        // The root prefix matches every valid path.
        return true;
    }
    if path == prefix {
        return true;
    }
    path.starts_with(&format!("{}/", prefix))
}

/// Report whether two prefixes are comparable under the prefix relation (one
/// at or below the other). An absent prefix orders as `/` (SPEC §5.7.3).
fn resource_paths_nested(a: &str, b: &str) -> bool {
    let a = if a.is_empty() { "/" } else { a };
    let b = if b.is_empty() { "/" } else { b };
    resource_path_matches(a, b) || resource_path_matches(b, a)
}

/// Enforce the issuance rule of SPEC §5.7.3: a certificate's `resource_path`
/// constraints must be jointly satisfiable. Rejects constraint sets naming
/// different `resource_id`s, and same-resource sets whose prefixes do not
/// form a nested chain under the prefix relation. Individual constraints are
/// also validated (non-empty `resource_id` within `MAX_IDENTIFIER_LENGTH_BYTES`;
/// well-formed `path_prefix`).
///
/// Decoders do NOT call this — wire compatibility is not conditioned on
/// issuance hygiene; verification denies unsatisfiable sets fail-closed.
pub fn validate_resource_constraints(constraints: &[Constraint]) -> Result<(), String> {
    let mut resource_id: Option<&str> = None;
    let mut prefixes: Vec<&str> = Vec::new();
    for (i, c) in constraints.iter().enumerate() {
        if c.kind != "resource_path" {
            continue;
        }
        if c.resource_id.is_empty() {
            return Err(format!(
                "constraint[{}]: resource_path requires a non-empty resource_id",
                i
            ));
        }
        if c.resource_id.len() > MAX_IDENTIFIER_LENGTH_BYTES {
            return Err(format!(
                "constraint[{}]: resource_id is {} bytes, exceeding MAX_IDENTIFIER_LENGTH_BYTES ({})",
                i,
                c.resource_id.len(),
                MAX_IDENTIFIER_LENGTH_BYTES
            ));
        }
        let this_prefix = c.path_prefix.as_deref().unwrap_or("");
        if !this_prefix.is_empty() {
            if let Err(e) = normalize_resource_path(this_prefix) {
                return Err(format!("constraint[{}]: invalid path_prefix: {}", i, e));
            }
        }
        match resource_id {
            None => resource_id = Some(&c.resource_id),
            Some(rid) if c.resource_id != rid => {
                return Err(format!(
                    "constraint[{}]: certificate carries resource_path constraints naming different resource_ids — jointly unsatisfiable (SPEC §5.7.3); issue separate certificates",
                    i
                ));
            }
            _ => {}
        }
        for prev in &prefixes {
            if !resource_paths_nested(prev, this_prefix) {
                return Err(format!(
                    "constraint[{}]: same-resource path_prefix values \"{}\" and \"{}\" do not nest — jointly unsatisfiable (SPEC §5.7.3); narrow to one prefix or issue separate certificates",
                    i, prev, this_prefix
                ));
            }
        }
        prefixes.push(this_prefix);
    }
    Ok(())
}

/// Enforce the extension-constraint params value model (SPEC §5.7.1): null,
/// booleans, strings, safe integers (|n| ≤ 2^53−1), and arrays/objects of
/// these. `depth` is the container nesting already consumed; nesting beyond
/// `MAX_JSON_NESTING_DEPTH` is rejected.
///
/// The [`ParamsValue`] type cannot represent floats or raw bytes, so the
/// remaining checks are the safe-integer bound and the nesting depth.
pub fn validate_params_value(v: &ParamsValue, depth: usize) -> Result<(), String> {
    if depth > MAX_JSON_NESTING_DEPTH {
        return Err(format!(
            "params nesting exceeds MAX_JSON_NESTING_DEPTH ({})",
            MAX_JSON_NESTING_DEPTH
        ));
    }
    match v {
        ParamsValue::Null | ParamsValue::Bool(_) | ParamsValue::Str(_) => Ok(()),
        ParamsValue::Int(n) => {
            if *n > MAX_SAFE_INTEGER || *n < -MAX_SAFE_INTEGER {
                return Err(
                    "params integer exceeds the safe-integer range; carry it as a decimal string"
                        .to_string(),
                );
            }
            Ok(())
        }
        ParamsValue::Array(items) => {
            for item in items {
                validate_params_value(item, depth + 1)?;
            }
            Ok(())
        }
        ParamsValue::Object(map) => {
            for item in map.values() {
                validate_params_value(item, depth + 1)?;
            }
            Ok(())
        }
    }
}

/// Validate a constraint's `params` field against the value model and the
/// canonical-type restriction (SPEC §5.7.1). Shared by issuance and decode.
pub fn validate_constraint_params(c: &Constraint) -> Result<(), String> {
    if let Some(params) = &c.params {
        if is_canonical_constraint_type(&c.kind) {
            return Err(format!(
                "canonical constraint type \"{}\" must not carry params",
                c.kind
            ));
        }
        // The params object is the depth-0 container (Go: ValidateParamsValue
        // on the map iterates its values at depth+1), so values start at 1.
        for value in params.values() {
            validate_params_value(value, 1)?;
        }
    }
    Ok(())
}
