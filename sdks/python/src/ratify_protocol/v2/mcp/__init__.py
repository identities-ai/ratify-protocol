"""Ratify Verify MCP signer (preview).

The client side of the Ratify Verify MCP server: sign the delegated-authority
proof each tool call carries, answer the console's connect challenge with a
proof of possession of the agent key, and parse the console's client
configuration. This module talks to the managed Verify service; it is not
part of SPEC-v2 conformance, and its API may change while it is a preview.

Library use::

    from ratify_protocol.v2 import mcp

    config = mcp.parse_client_config(open("config.json", "rb").read())
    call = mcp.new_tool_call("get_metrics", {})
    body = config.challenge_request(call)          # POST <endpoint>/challenge
    challenge = config.check_challenge(call.tool, response_body, int(time.time()))
    envelope = mcp.sign_tool_call(config, agent_key, call, challenge)
    # tools/call params._meta[mcp.PROOF_META_KEY] = envelope.to_dict()

:class:`ratify_protocol.v2.mcp.signer.Signer` does the HTTPS round trips for
you, and the ``ratify-mcp-signer`` command (``pip install
"ratify-protocol[protocol-v2,mcp-signer]"``) runs it as a stdio MCP server.
Signing runs in the native v2 extension.
"""
from .binding import (
    ACTION,
    CONNECT_POSSESSION_DOMAIN,
    MAX_ARGUMENT_DEPTH,
    MIN_CHALLENGE_SECONDS_LEFT,
    PROOF_META_KEY,
    PROTOCOL_VERSION,
    TOOLS,
    canonical_arguments,
    connect_possession_context,
    payload_digest,
    payload_digest_text,
    request_hash,
    session_context,
    tool_scope,
)
from .config import ClientConfig, parse_client_config
from .connect import (
    CONNECT_TOKEN_PREFIX,
    MAX_CONNECT_TOKEN_LENGTH,
    ConnectToken,
    PossessionProof,
    parse_connect_token,
    prove_possession,
    prove_possession_with_signer,
)
from .errors import (
    ChallengeRefusedError,
    InvalidArgumentsError,
    InvalidConfigError,
    InvalidConnectTokenError,
    McpSignerError,
)
from .toolcall import (
    Challenge,
    ProofEnvelope,
    ToolCall,
    check_challenge,
    new_tool_call,
    sign_tool_call,
    sign_tool_call_with_signer,
)

__all__ = [
    "ACTION", "CONNECT_POSSESSION_DOMAIN", "CONNECT_TOKEN_PREFIX", "MAX_ARGUMENT_DEPTH", "MAX_CONNECT_TOKEN_LENGTH",
    "MIN_CHALLENGE_SECONDS_LEFT", "PROOF_META_KEY", "PROTOCOL_VERSION", "TOOLS",
    "Challenge", "ChallengeRefusedError", "ClientConfig", "ConnectToken", "InvalidArgumentsError",
    "InvalidConfigError", "InvalidConnectTokenError", "McpSignerError", "PossessionProof", "ProofEnvelope", "ToolCall",
    "canonical_arguments", "check_challenge", "connect_possession_context", "new_tool_call", "parse_client_config",
    "parse_connect_token", "payload_digest", "payload_digest_text", "prove_possession", "prove_possession_with_signer",
    "request_hash", "session_context", "sign_tool_call", "sign_tool_call_with_signer", "tool_scope",
]
