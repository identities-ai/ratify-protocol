//! Canonical JSON (SPEC-v2 Annex A) and the scope vocabulary rules.

use std::collections::HashMap;

use ratify_protocol::v2::{canonical_json_v2, validate_scopes_v2};

use crate::error::FfiResult;

/// The canonical form of a JSON text, or the strict-decode rejection.
#[uniffi::export]
pub fn ffi_canonical_json(data: Vec<u8>) -> FfiResult<Vec<u8>> {
    Ok(canonical_json_v2(&data)?)
}

#[uniffi::export]
pub fn ffi_validate_scopes(scopes: Vec<String>) -> FfiResult<()> {
    Ok(validate_scopes_v2(&scopes)?)
}

#[uniffi::export]
pub fn ffi_scope_vocabulary() -> Vec<String> {
    ratify_protocol::vocabulary()
        .into_iter()
        .map(String::from)
        .collect()
}

#[uniffi::export]
pub fn ffi_scope_wildcards() -> HashMap<String, Vec<String>> {
    ratify_protocol::scope_wildcards()
        .into_iter()
        .map(|(w, list)| (w.to_string(), list.iter().map(|s| s.to_string()).collect()))
        .collect()
}

#[uniffi::export]
pub fn ffi_is_sensitive_scope(scope: String) -> bool {
    ratify_protocol::is_sensitive(&scope)
}

#[uniffi::export]
pub fn ffi_expand_scopes(scopes: Vec<String>) -> Vec<String> {
    ratify_protocol::expand_scopes(&scopes)
}

#[uniffi::export]
pub fn ffi_intersect_scopes(lists: Vec<Vec<String>>) -> Vec<String> {
    let refs: Vec<&[String]> = lists.iter().map(Vec::as_slice).collect();
    ratify_protocol::intersect_scopes(&refs)
}
