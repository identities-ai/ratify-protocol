//! The console's client configuration (Go `verifyclient/mcp/config.go`).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{Map, Value};

use super::super::wire::{decode_delegation_cert_v2, DelegationCertV2};
use super::{McpError, MAX_SAFE_INTEGER};

/// The configuration the console shows when an agent is connected: the
/// pinned endpoint and audience, the verifier and workspace, the connection,
/// and the delegation chain ending at the agent key.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub endpoint: String,
    pub audience: String,
    pub verifier_id: String,
    pub workspace_id: String,
    pub connection_id: String,
    /// The decoded certificates, root side first; the last one is issued to
    /// the agent key.
    pub delegations: Vec<DelegationCertV2>,
}

/// Parse the console's client configuration: either the `client_config`
/// object itself or a JSON object that carries it under `client_config` (the
/// console's connect response). Fields other than the six below are
/// ignored, so a signer configuration file that also holds a key reference
/// parses too.
///
/// - `endpoint`: `https://` and a lowercase host name with an optional port,
///   nothing else (no path, query, fragment, credentials, or trailing slash)
/// - `audience`: exactly the endpoint followed by `/mcp`
/// - `verifier_id`: 64 lowercase hex characters
/// - `workspace_id`, `connection_id`: lowercase UUIDs
/// - `delegations`: a non-empty array of canonical standard base64 strings,
///   each a SPEC-v2 delegation certificate, root side first, each issued to
///   the issuer of the next (subject ID and complete public key)
pub fn parse_client_config(data: impl AsRef<[u8]>) -> Result<ClientConfig, McpError> {
    let mut top = json_object(data.as_ref()).ok_or(McpError::InvalidConfig)?;
    if let Some(Value::Object(inner)) = top.get("client_config") {
        top = inner.clone();
    }
    let field = |name: &str| json_string(&top, name).ok_or(McpError::InvalidConfig);
    let endpoint = field("endpoint")?;
    let audience = field("audience")?;
    let verifier_id = field("verifier_id")?;
    let workspace_id = field("workspace_id")?;
    let connection_id = field("connection_id")?;
    if !valid_endpoint(&endpoint, &audience)
        || !is_hex64(&verifier_id)
        || !is_uuid(&workspace_id)
        || !is_uuid(&connection_id)
    {
        return Err(McpError::InvalidConfig);
    }
    let items = match top.get("delegations") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => return Err(McpError::InvalidConfig),
    };
    let mut delegations = Vec::with_capacity(items.len());
    for item in items {
        let text = item.as_str().ok_or(McpError::InvalidConfig)?;
        let wire = decode_std_base64(text).ok_or(McpError::InvalidConfig)?;
        delegations.push(decode_delegation_cert_v2(&wire).map_err(|_| McpError::InvalidConfig)?);
    }
    // Root side first: each certificate is issued to the next one's issuer.
    for pair in delegations.windows(2) {
        let (parent, child) = (&pair[0], &pair[1]);
        if parent.subject_id != child.issuer_id
            || parent.subject_pub_key.ed25519 != child.issuer_pub_key.ed25519
            || parent.subject_pub_key.ml_dsa_65 != child.issuer_pub_key.ml_dsa_65
        {
            return Err(McpError::InvalidConfig);
        }
    }
    Ok(ClientConfig {
        endpoint,
        audience,
        verifier_id,
        workspace_id,
        connection_id,
        delegations,
    })
}

/// A JSON object, or `None` for anything else (including `null`).
pub(crate) fn json_object(data: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice(data).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// A member that is a JSON string (`null` is not a string).
pub(crate) fn json_string(m: &Map<String, Value>, name: &str) -> Option<String> {
    m.get(name)?.as_str().map(str::to_string)
}

/// A member that is a JSON integer (no fraction, exponent, boolean, or
/// string) in the safe range.
pub(crate) fn json_integer(m: &Map<String, Value>, name: &str) -> Option<i64> {
    let n = m.get(name)?.as_number()?;
    let v = n.as_i64()?;
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER)
        .contains(&v)
        .then_some(v)
}

/// `^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$` and the
/// audience is exactly the endpoint followed by `/mcp`.
pub(crate) fn valid_endpoint(endpoint: &str, audience: &str) -> bool {
    endpoint_grammar(endpoint) && audience.strip_suffix("/mcp") == Some(endpoint)
}

fn endpoint_grammar(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let host_ok = match (host.as_bytes().first(), host.as_bytes().last()) {
        (Some(&first), Some(&last)) => {
            alnum(first) && alnum(last) && host.bytes().all(|c| alnum(c) || c == b'.' || c == b'-')
        }
        _ => false,
    };
    let port_ok = match port {
        None => true,
        Some(p) => {
            (1..=5).contains(&p.len())
                && p.bytes().all(|c| c.is_ascii_digit())
                && !p.starts_with('0')
        }
    };
    host_ok && port_ok
}

fn lower_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(lower_hex)
}

pub(crate) fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                lower_hex(c)
            }
        })
}

/// Canonical padded standard base64 only: the text must be exactly what
/// encoding the decoded bytes produces.
pub(crate) fn decode_std_base64(s: &str) -> Option<Vec<u8>> {
    let b = STANDARD.decode(s).ok()?;
    (STANDARD.encode(&b) == s).then_some(b)
}
