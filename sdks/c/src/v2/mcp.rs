//! Preview: the client of the managed Ratify Verify MCP service
//! (`ratify_v2_mcp_*`), over `ratify_protocol::v2::mcp`. It signs the
//! delegated-authority proof each tool call carries, answers the console's
//! connect challenge with a proof of possession of the agent key, and parses
//! the configuration the console hands out. It is not part of SPEC-v2
//! conformance, and this surface may change before it is declared stable.
//!
//! Refusals specific to the signer have their own negative codes
//! (`RatifyV2McpInvalidArguments` .. `RatifyV2McpAgentNotDelegated`); a
//! SPEC-v2 construction or signing failure reports its SPEC-v2 §2.7 class.
//! Diagnostics never carry key material, proofs, or argument values.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::AtomicBool;

use ratify_protocol::v2::mcp::{
    self, canonical_arguments, connect_possession_context, parse_client_config,
    parse_connect_token, payload_digest, payload_digest_text, prove_possession,
    prove_possession_with_signer, request_hash, session_context, sign_tool_call,
    sign_tool_call_with_signer, Challenge, ClientConfig, McpError, ToolCall,
};
use ratify_protocol::v2::V2Context;
use serde_json::{json, Value};

use super::keys::RatifyV2KeyPair;
use super::marshal::{b64, to_bytes};
use super::sign::{build, Built, RatifyV2ExternalSigner};
use super::{
    bytes, clear_buffer, cstr, flag, handle, null_arg, poisonable, run, run_h, write_buffer,
    write_opt_string, write_string, AbiResult, Failure, RatifyV2Buffer, RatifyV2Code,
};

/// A parsed console client configuration. Create it with
/// `ratify_v2_mcp_client_config_parse`; release it with
/// `ratify_v2_mcp_client_config_free`. Read-only after creation.
pub struct RatifyV2McpClientConfig {
    pub(crate) poisoned: AtomicBool,
    pub(crate) inner: ClientConfig,
}

/// A challenge response `ratify_v2_mcp_check_challenge` accepted. It signs
/// only a call to the tool, and under the configuration (verifier,
/// workspace, connection), it was checked for. Release it with
/// `ratify_v2_mcp_challenge_free`.
pub struct RatifyV2McpChallenge {
    pub(crate) poisoned: AtomicBool,
    pub(crate) inner: Challenge,
}

poisonable!(RatifyV2McpClientConfig, RatifyV2McpChallenge);

fn mcp_failure(e: McpError) -> Failure {
    use RatifyV2Code::*;
    let message = e.to_string();
    let code = match e {
        McpError::InvalidArguments => RatifyV2McpInvalidArguments,
        McpError::InvalidConfig => RatifyV2McpInvalidConfig,
        McpError::ChallengeRefused => RatifyV2McpChallengeRefused,
        McpError::InvalidConnectToken => RatifyV2McpInvalidConnectToken,
        McpError::AgentNotDelegated => RatifyV2McpAgentNotDelegated,
        McpError::Protocol(inner) => return inner.into(),
        McpError::Signing(inner) => return inner.into(),
    };
    Failure::new(code, message)
}

fn text(v: &Value) -> String {
    String::from_utf8(to_bytes(v)).unwrap_or_default()
}

/// A connect token argument. Text that is not UTF-8 is not a connect token.
unsafe fn token_arg<'a>(p: *const c_char) -> AbiResult<&'a str> {
    if p.is_null() {
        return Err(null_arg("token"));
    }
    std::str::from_utf8(CStr::from_ptr(p).to_bytes())
        .map_err(|_| mcp_failure(McpError::InvalidConnectToken))
}

/// Sign with the one signer the caller selected, reporting a signer
/// cancellation as `RatifyV2EvaluationCancelled`.
unsafe fn with_mcp_signer<R>(
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    local_fn: impl FnOnce(&ratify_protocol::HybridPrivateKey) -> Result<R, McpError>,
    external_fn: impl FnOnce(&V2Context, &dyn ratify_protocol::v2::SignerV2) -> Result<R, McpError>,
) -> AbiResult<R> {
    let (ctx, cancel) = V2Context::background().with_cancel();
    let built = build(local, external, "agent", &cancel)?;
    let result = match &built {
        Built::Local(key) => local_fn(key),
        Built::External(signer) => external_fn(&ctx, signer),
    };
    match result {
        Ok(r) => Ok(r),
        Err(e) if built.cancelled() => Err(Failure::new(
            RatifyV2Code::RatifyV2EvaluationCancelled,
            format!("signer cancelled: {e}"),
        )),
        Err(e) => Err(mcp_failure(e)),
    }
}

/// Write the signer constants and the hosted tool table as JSON:
/// `{"action","proof_meta_key","protocol_version","min_challenge_seconds_left",
/// "connect_possession_domain","connect_token_prefix","max_connect_token_length",
/// "max_argument_depth","tools":[{"name","scope"}, ...]}` (tools in their
/// fixed order). Free `*out` with `ratify_v2_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_constants_json(out: *mut *mut c_char) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out),
        || {
            let tools: Vec<Value> = mcp::TOOLS
                .iter()
                .map(|t| json!({"name": t.name, "scope": t.scope}))
                .collect();
            let v = json!({
                "action": mcp::ACTION,
                "proof_meta_key": mcp::PROOF_META_KEY,
                "protocol_version": mcp::PROTOCOL_VERSION,
                "min_challenge_seconds_left": mcp::MIN_CHALLENGE_SECONDS_LEFT,
                "connect_possession_domain": mcp::CONNECT_POSSESSION_DOMAIN,
                "connect_token_prefix": mcp::CONNECT_TOKEN_PREFIX,
                "max_connect_token_length": mcp::MAX_CONNECT_TOKEN_LENGTH,
                "max_argument_depth": mcp::MAX_ARGUMENT_DEPTH,
                "tools": tools,
            });
            write_string(out, &text(&v))
        },
    )
}

/// Parse the JSON text of `params.arguments` under the restricted value
/// model and write its canonical bytes (send them as `params.arguments`).
/// Empty input, JSON whitespace, and `null` mean `{}`. Refused input is
/// `RatifyV2McpInvalidArguments`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_canonical_arguments(
    arguments: *const u8,
    arguments_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let canonical = canonical_arguments(bytes(arguments, arguments_len, "arguments")?)
                .map_err(mcp_failure)?;
            write_buffer(out, canonical)
        },
    )
}

/// SHA-256 of canonical argument bytes into `*digest_out` (32 bytes); when
/// `text_out` is non-NULL, also the `sha256:<lowercase hex>` text (free it
/// with `ratify_v2_string_free`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_payload_digest(
    canonical_arguments: *const u8,
    canonical_arguments_len: usize,
    digest_out: *mut RatifyV2Buffer,
    text_out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            clear_buffer(digest_out);
            crate::guard::clear_ptr(text_out);
        },
        || {
            let digest = payload_digest(bytes(
                canonical_arguments,
                canonical_arguments_len,
                "canonical_arguments",
            )?);
            if digest_out.is_null() {
                return Err(null_arg("digest_out"));
            }
            write_opt_string(text_out, &payload_digest_text(&digest))?;
            write_buffer(digest_out, digest.to_vec())
        },
    )
}

/// The SPEC-v2 operation context (32 bytes) of one tool call: the tool's
/// scope, operation `mcp.tools/call:<tool>`, `connection_id` as resource,
/// `audience` as requested path, and the 32-byte payload digest. An unknown
/// tool is `RatifyV2McpInvalidArguments`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_request_hash(
    tool: *const c_char,
    connection_id: *const c_char,
    audience: *const c_char,
    payload_digest: *const u8,
    payload_digest_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let h = request_hash(
                cstr(tool, "tool")?,
                cstr(connection_id, "connection_id")?,
                cstr(audience, "audience")?,
                bytes(payload_digest, payload_digest_len, "payload_digest")?,
            )
            .map_err(mcp_failure)?;
            write_buffer(out, h)
        },
    )
}

/// The SPEC-v2 session context (32 bytes) a tool-call proof signs; the
/// session ID is `connection_id`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_session_context(
    verifier_id: *const c_char,
    workspace_id: *const c_char,
    agent_id: *const c_char,
    connection_id: *const c_char,
    invocation_id: *const c_char,
    request_hash: *const u8,
    request_hash_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let h = session_context(
                cstr(verifier_id, "verifier_id")?,
                cstr(workspace_id, "workspace_id")?,
                cstr(agent_id, "agent_id")?,
                cstr(connection_id, "connection_id")?,
                cstr(invocation_id, "invocation_id")?,
                bytes(request_hash, request_hash_len, "request_hash")?,
            )
            .map_err(mcp_failure)?;
            write_buffer(out, h)
        },
    )
}

/// The 32-byte session context of the connect proof of possession: SHA-256
/// of the connect possession domain followed by each field with its 8-byte
/// big-endian length.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_connect_possession_context(
    workspace_id: *const c_char,
    receiver_id: *const c_char,
    audience: *const c_char,
    challenge_id: *const c_char,
    agent_id: *const c_char,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || clear_buffer(out),
        || {
            let h = connect_possession_context(
                cstr(workspace_id, "workspace_id")?,
                cstr(receiver_id, "receiver_id")?,
                cstr(audience, "audience")?,
                cstr(challenge_id, "challenge_id")?,
                cstr(agent_id, "agent_id")?,
            );
            write_buffer(out, h.to_vec())
        },
    )
}

/// Parse the console's client configuration (the `client_config` object, or
/// an object carrying it under `client_config`; unknown fields are ignored).
/// On success `*out` is a new handle. When `fields_json_out` is non-NULL it
/// receives `{"endpoint","audience","verifier_id","workspace_id",
/// "connection_id","delegation_cert_ids":[...]}` (certificates root side
/// first, each issued to the next one's issuer). A refused configuration is
/// `RatifyV2McpInvalidConfig`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_client_config_parse(
    config: *const u8,
    config_len: usize,
    out: *mut *mut RatifyV2McpClientConfig,
    fields_json_out: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || {
            crate::guard::clear_ptr(out);
            crate::guard::clear_ptr(fields_json_out);
        },
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let cfg =
                parse_client_config(bytes(config, config_len, "config")?).map_err(mcp_failure)?;
            let ids: Vec<&str> = cfg.delegations.iter().map(|d| d.cert_id.as_str()).collect();
            let fields = json!({
                "endpoint": cfg.endpoint,
                "audience": cfg.audience,
                "verifier_id": cfg.verifier_id,
                "workspace_id": cfg.workspace_id,
                "connection_id": cfg.connection_id,
                "delegation_cert_ids": ids,
            });
            write_opt_string(fields_json_out, &text(&fields))?;
            *out = Box::into_raw(Box::new(RatifyV2McpClientConfig {
                poisoned: AtomicBool::new(false),
                inner: cfg,
            }));
            Ok(())
        },
    )
}

/// Release a client configuration. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_client_config_free(config: *mut RatifyV2McpClientConfig) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !config.is_null() {
                drop(Box::from_raw(config));
            }
        },
    )
}

/// The exact JSON body of `POST <endpoint>/challenge` for a call to `tool`
/// with `arguments` (JSON text, canonicalized first):
/// `{"connection_id":...,"tool":...,"payload_digest":"sha256:..."}`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_challenge_request(
    config: *const RatifyV2McpClientConfig,
    tool: *const c_char,
    arguments: *const u8,
    arguments_len: usize,
    out: *mut RatifyV2Buffer,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(config)],
        || clear_buffer(out),
        || {
            let cfg = &handle(config, "config")?.inner;
            let call = ToolCall::new(
                cstr(tool, "tool")?,
                bytes(arguments, arguments_len, "arguments")?,
            )
            .map_err(mcp_failure)?;
            write_buffer(out, cfg.challenge_request(&call).map_err(mcp_failure)?)
        },
    )
}

/// Accept the JSON response of `POST <endpoint>/challenge` for `tool` at
/// `now` (Unix seconds), or refuse it with `RatifyV2McpChallengeRefused`.
/// The response must be valid UTF-8 JSON; unknown fields, including any hash
/// the server supplies, are ignored. On success `*out` is a new handle that
/// signs only a call to `tool` under `config`. When
/// `fields_json_out` is non-NULL it receives `{"tool","invocation_id",
/// "challenge" (standard base64),"issued_at","expires_at"}`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_check_challenge(
    config: *const RatifyV2McpClientConfig,
    tool: *const c_char,
    response: *const u8,
    response_len: usize,
    now: i64,
    out: *mut *mut RatifyV2McpChallenge,
    fields_json_out: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(config)],
        || {
            crate::guard::clear_ptr(out);
            crate::guard::clear_ptr(fields_json_out);
        },
        || {
            if out.is_null() {
                return Err(null_arg("out"));
            }
            let cfg = &handle(config, "config")?.inner;
            let ch = cfg
                .check_challenge(
                    cstr(tool, "tool")?,
                    bytes(response, response_len, "response")?,
                    now,
                )
                .map_err(mcp_failure)?;
            let fields = json!({
                "tool": ch.tool(),
                "invocation_id": ch.invocation_id(),
                "challenge": b64(ch.challenge()),
                "issued_at": ch.issued_at(),
                "expires_at": ch.expires_at(),
            });
            write_opt_string(fields_json_out, &text(&fields))?;
            *out = Box::into_raw(Box::new(RatifyV2McpChallenge {
                poisoned: AtomicBool::new(false),
                inner: ch,
            }));
            Ok(())
        },
    )
}

/// Release a checked challenge. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_challenge_free(challenge: *mut RatifyV2McpChallenge) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !challenge.is_null() {
                drop(Box::from_raw(challenge));
            }
        },
    )
}

/// Sign the proof for a call to `tool` with `arguments` (JSON text) under a
/// checked `challenge`, with exactly one of a library key pair (`local`) or
/// an external signer. `*envelope_json_out` receives the
/// `params._meta["com.ratifyprotocol/proof"]` value
/// `{"connection_id","invocation_id","challenge","bundle"}` (free with
/// `ratify_v2_string_free`). A challenge checked for another tool or under
/// another verifier, workspace or connection is `RatifyV2McpChallengeRefused`;
/// a key the last delegation is not issued to is
/// `RatifyV2McpAgentNotDelegated`. The bundle carries the configuration's
/// delegations leaf first.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_sign_tool_call(
    config: *const RatifyV2McpClientConfig,
    tool: *const c_char,
    arguments: *const u8,
    arguments_len: usize,
    challenge: *const RatifyV2McpChallenge,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    envelope_json_out: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(config), flag(challenge), flag(local)],
        || crate::guard::clear_ptr(envelope_json_out),
        || {
            if envelope_json_out.is_null() {
                return Err(null_arg("envelope_json_out"));
            }
            let cfg = &handle(config, "config")?.inner;
            let ch = &handle(challenge, "challenge")?.inner;
            let call = ToolCall::new(
                cstr(tool, "tool")?,
                bytes(arguments, arguments_len, "arguments")?,
            )
            .map_err(mcp_failure)?;
            let env = with_mcp_signer(
                local,
                external,
                |k| sign_tool_call(cfg, k, &call, ch),
                |ctx, s| sign_tool_call_with_signer(ctx, cfg, s, &call, ch),
            )?;
            let v = serde_json::to_value(&env).map_err(|e| {
                Failure::new(RatifyV2Code::RatifyV2ErrInternal, format!("envelope: {e}"))
            })?;
            write_string(envelope_json_out, &text(&v))
        },
    )
}

/// Parse a console connect token. `*out_json` receives `{"challenge_id",
/// "challenge" (standard base64),"issued_at","workspace_id","receiver_id",
/// "audience","verifier_id"}`. A refused token is
/// `RatifyV2McpInvalidConnectToken`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_parse_connect_token(
    token: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    run(
        std::ptr::null_mut(),
        || crate::guard::clear_ptr(out_json),
        || {
            if out_json.is_null() {
                return Err(null_arg("out_json"));
            }
            let t = parse_connect_token(token_arg(token)?).map_err(mcp_failure)?;
            let v = json!({
                "challenge_id": t.challenge_id,
                "challenge": b64(&t.challenge),
                "issued_at": t.issued_at,
                "workspace_id": t.workspace_id,
                "receiver_id": t.receiver_id,
                "audience": t.audience,
                "verifier_id": t.verifier_id,
            });
            write_string(out_json, &text(&v))
        },
    )
}

/// Answer a connect token with a proof of possession of the agent key
/// (exactly one of `local` or `external`). `*out_json` receives
/// `{"connect_challenge_id","possession_proof"}` (the proof bundle wire in
/// standard base64). Never contacts the network.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_mcp_prove_possession(
    token: *const c_char,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
    out_json: *mut *mut c_char,
) -> i32 {
    run_h(
        std::ptr::null_mut(),
        &[flag(local)],
        || crate::guard::clear_ptr(out_json),
        || {
            if out_json.is_null() {
                return Err(null_arg("out_json"));
            }
            let token = token_arg(token)?;
            let proof = with_mcp_signer(
                local,
                external,
                |k| prove_possession(token, k),
                |ctx, s| prove_possession_with_signer(ctx, token, s),
            )?;
            let v = serde_json::to_value(&proof).map_err(|e| {
                Failure::new(RatifyV2Code::RatifyV2ErrInternal, format!("proof: {e}"))
            })?;
            write_string(out_json, &text(&v))
        },
    )
}
