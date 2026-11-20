//! Preview: the client side of the Ratify Verify MCP server. It signs the
//! delegated-authority proof each tool call carries, answers the console's
//! connect challenge with a proof of possession of the agent key, and parses
//! the configuration the console hands out (Go `verifyclient/mcp`).
//!
//! This module talks to the managed Ratify Verify service. It is not part of
//! SPEC-v2 conformance, and its API may change before it is declared stable.
//! Every hash is the normative SPEC-v2 operation and session context
//! construction; this module only decides which values go in.
//!
//! Nothing here signs caller-chosen bytes. A tool-call proof is a SPEC-v2
//! challenge presentation whose session context the signer recomputes from
//! the call it was asked to make and the pinned configuration, never from a
//! hash the server supplies. Shared vectors: `testvectors/v2/mcp`.

use std::fmt;

use sha2::{Digest, Sha256};

use super::errors::{V2Error, V2SignError};
use super::operation_context::{
    build_session_context_v2, operation_context_v2_hash, OperationContextV2, SessionContextV2Inputs,
};

mod arguments;
mod config;
mod connect;
mod toolcall;

pub use arguments::canonical_arguments;
pub use config::{parse_client_config, ClientConfig};
pub use connect::{
    parse_connect_token, prove_possession, prove_possession_with_signer, ConnectToken,
    PossessionProof,
};
pub use toolcall::{
    sign_tool_call, sign_tool_call_with_signer, Challenge, ProofEnvelope, ToolCall,
};

/// The receiver-configuration action of every tool operation.
pub const ACTION: &str = "mcp.tools/call";
/// The `params._meta` key that carries the proof envelope.
pub const PROOF_META_KEY: &str = "com.ratifyprotocol/proof";
/// The MCP revision the hosted endpoint speaks.
pub const PROTOCOL_VERSION: &str = "2026-07-28";
/// The least lifetime, in seconds by the signer's clock, a challenge must
/// have left for the signer to sign it.
pub const MIN_CHALLENGE_SECONDS_LEFT: i64 = 10;
/// Separates the connect proof of possession from every per-call session
/// context.
pub const CONNECT_POSSESSION_DOMAIN: &str = "ratify-verify-mcp/connect-possession/v1";
/// Starts the one-line connect challenge the console issues to the owner or
/// admin connecting an agent.
pub const CONNECT_TOKEN_PREFIX: &str = "ratify-mcp-connect-1.";
/// Bounds a connect token, in bytes.
pub const MAX_CONNECT_TOKEN_LENGTH: usize = 4096;
/// The deepest nesting a tool argument value may have: the arguments object
/// is depth 0 and each enclosing object or array adds one.
pub const MAX_ARGUMENT_DEPTH: usize = 4;

pub(crate) const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// One hosted tool and the exact custom scope it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tool {
    pub name: &'static str,
    pub scope: &'static str,
}

/// The hosted tools, in a fixed order.
pub const TOOLS: &[Tool] = &[
    Tool {
        name: "get_metrics",
        scope: "custom:verify.metrics:read",
    },
    Tool {
        name: "list_decisions",
        scope: "custom:verify.decisions:read",
    },
    Tool {
        name: "get_decision",
        scope: "custom:verify.decisions:read",
    },
    Tool {
        name: "list_events",
        scope: "custom:verify.events:read",
    },
    Tool {
        name: "list_agents",
        scope: "custom:verify.agents:read",
    },
    Tool {
        name: "list_evidence",
        scope: "custom:verify.evidence:read",
    },
    Tool {
        name: "get_evidence_package",
        scope: "custom:verify.evidence:read",
    },
];

/// The scope a tool requires, or `None` for a tool [`TOOLS`] does not name.
pub fn tool_scope(name: &str) -> Option<&'static str> {
    TOOLS.iter().find(|t| t.name == name).map(|t| t.scope)
}

/// A refusal of the MCP signer. Messages never carry key material, proofs,
/// or argument values.
#[derive(Debug, Clone)]
pub enum McpError {
    /// The tool is unknown, or its arguments are not a JSON object under the
    /// restricted value model. Nothing is signed for such a call.
    InvalidArguments,
    /// The console configuration is missing a field or a field has the wrong
    /// form.
    InvalidConfig,
    /// The challenge response does not match the pinned configuration or the
    /// call, or expires too soon. Nothing is signed.
    ChallengeRefused,
    /// The text is not a well-formed connect token from the console.
    InvalidConnectToken,
    /// The last delegation certificate of the configuration is not issued to
    /// the signing agent key.
    AgentNotDelegated,
    /// A SPEC-v2 construction refused its inputs.
    Protocol(V2Error),
    /// Signing the proof bundle failed.
    Signing(V2SignError),
}

impl fmt::Display for McpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpError::InvalidArguments => f.write_str("mcp: invalid tool arguments"),
            McpError::InvalidConfig => f.write_str("mcp: invalid client configuration"),
            McpError::ChallengeRefused => f.write_str("mcp: challenge refused"),
            McpError::InvalidConnectToken => {
                f.write_str("mcp: not a ratify-mcp-connect-1 token from the console")
            }
            McpError::AgentNotDelegated => {
                f.write_str("mcp: the last delegation certificate is not issued to this agent key")
            }
            McpError::Protocol(e) => write!(f, "mcp: {e}"),
            McpError::Signing(e) => write!(f, "mcp: {e}"),
        }
    }
}

impl std::error::Error for McpError {}

impl From<V2Error> for McpError {
    fn from(e: V2Error) -> Self {
        McpError::Protocol(e)
    }
}

impl From<V2SignError> for McpError {
    fn from(e: V2SignError) -> Self {
        McpError::Signing(e)
    }
}

/// SHA-256 of the canonical argument bytes.
pub fn payload_digest(canonical_arguments: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical_arguments).into()
}

/// The `sha256:<lowercase hex>` form the challenge request carries.
pub fn payload_digest_text(digest: &[u8]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// The SPEC-v2 operation context of one tool call: the tool's scope, the
/// operation `mcp.tools/call:<tool>`, the connection ID as resource, the
/// endpoint audience as requested path, and the 32-byte argument digest.
/// An unknown tool is [`McpError::InvalidArguments`].
pub fn request_hash(
    tool: &str,
    connection_id: &str,
    audience: &str,
    payload_digest: &[u8],
) -> Result<Vec<u8>, McpError> {
    let scope = tool_scope(tool).ok_or(McpError::InvalidArguments)?;
    Ok(operation_context_v2_hash(&OperationContextV2 {
        required_scope: scope.to_string(),
        operation: format!("{ACTION}:{tool}"),
        resource_id: connection_id.to_string(),
        requested_path: audience.to_string(),
        payload_digest: payload_digest.to_vec(),
    })?)
}

/// The SPEC-v2 session context a tool-call proof signs. The session ID is
/// the connection ID.
pub fn session_context(
    verifier_id: &str,
    workspace_id: &str,
    agent_id: &str,
    connection_id: &str,
    invocation_id: &str,
    request_hash: &[u8],
) -> Result<Vec<u8>, McpError> {
    Ok(build_session_context_v2(&SessionContextV2Inputs {
        verifier_id: verifier_id.to_string(),
        workspace_id: workspace_id.to_string(),
        agent_id: agent_id.to_string(),
        session_id: connection_id.to_string(),
        invocation_id: invocation_id.to_string(),
        request_hash: request_hash.to_vec(),
    })?)
}

/// The 32-byte session context of the connect proof of possession: SHA-256
/// of [`CONNECT_POSSESSION_DOMAIN`] followed by the workspace ID, receiver
/// ID, audience, challenge ID, and agent key ID, each prefixed with its
/// 8-byte big-endian length.
pub fn connect_possession_context(
    workspace_id: &str,
    receiver_id: &str,
    audience: &str,
    challenge_id: &str,
    agent_id: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONNECT_POSSESSION_DOMAIN.as_bytes());
    for field in [workspace_id, receiver_id, audience, challenge_id, agent_id] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.finalize().into()
}
