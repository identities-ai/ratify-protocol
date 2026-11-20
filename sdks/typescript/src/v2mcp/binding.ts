// Binding of the Verify MCP signer (Preview): the tool table and the values
// each tool-call proof signs. Every hash is the normative SPEC-v2 operation
// and session context construction; this module only decides which values
// go in.

import { sha256 } from "@noble/hashes/sha2";

import { hexOf, uint64BE, utf8 } from "../json_v2.js";
import { buildSessionContextV2, operationContextV2Hash } from "../operation_context_v2.js";
import { InvalidArgumentsError } from "./errors.js";

/** The receiver-configuration action of every tool operation. Preview. */
export const ACTION = "mcp.tools/call";
/** The params._meta key that carries the proof envelope. Preview. */
export const PROOF_META_KEY = "com.ratifyprotocol/proof";
/** The MCP revision the hosted endpoint speaks. Preview. */
export const PROTOCOL_VERSION = "2026-07-28";
/** The least lifetime, in seconds by the signer's clock, a challenge must have left to be signed. Preview. */
export const MIN_CHALLENGE_SECONDS_LEFT = 10;
/** Separates the connect proof of possession from every per-call session context. Preview. */
export const CONNECT_POSSESSION_DOMAIN = "ratify-verify-mcp/connect-possession/v1";

/** One hosted tool and the exact custom scope it requires. Preview. */
export interface McpTool {
  readonly name: string;
  readonly scope: string;
}

/** The hosted tools in a fixed order. Preview. */
export const TOOLS: readonly McpTool[] = Object.freeze([
  { name: "get_metrics", scope: "custom:verify.metrics:read" },
  { name: "list_decisions", scope: "custom:verify.decisions:read" },
  { name: "get_decision", scope: "custom:verify.decisions:read" },
  { name: "list_events", scope: "custom:verify.events:read" },
  { name: "list_agents", scope: "custom:verify.agents:read" },
  { name: "list_evidence", scope: "custom:verify.evidence:read" },
  { name: "get_evidence_package", scope: "custom:verify.evidence:read" },
].map((t) => Object.freeze(t)));

/** The scope a hosted tool requires, or null for an unknown tool. Preview. */
export function toolScope(name: string): string | null {
  for (const t of TOOLS) {
    if (t.name === name) return t.scope;
  }
  return null;
}

/** SHA-256 of the canonical argument bytes. Preview. */
export function payloadDigest(canonicalArguments: Uint8Array): Uint8Array {
  return sha256(canonicalArguments);
}

/** The sha256:<lowercase hex> form the challenge request carries. Preview. */
export function payloadDigestText(digest: Uint8Array): string {
  return "sha256:" + hexOf(digest);
}

/**
 * Preview. The SPEC-v2 operation context of one tool call: the tool's
 * scope, the operation "mcp.tools/call:<tool>", the connection ID as
 * resource, the endpoint audience as requested path, and the raw 32-byte
 * argument digest. Throws InvalidArgumentsError for an unknown tool.
 */
export function requestHash(tool: string, connectionID: string, audience: string, digest: Uint8Array): Uint8Array {
  const scope = toolScope(tool);
  if (scope === null) throw new InvalidArgumentsError("mcp: unknown tool");
  return operationContextV2Hash({
    required_scope: scope,
    operation: `${ACTION}:${tool}`,
    resource_id: connectionID,
    requested_path: audience,
    payload_digest: digest,
  });
}

/** The SPEC-v2 session context a tool-call proof signs; the session ID is the connection ID. Preview. */
export function sessionContext(
  verifierID: string,
  workspaceID: string,
  agentID: string,
  connectionID: string,
  invocationID: string,
  requestHashBytes: Uint8Array,
): Uint8Array {
  return buildSessionContextV2({
    verifier_id: verifierID,
    workspace_id: workspaceID,
    agent_id: agentID,
    session_id: connectionID,
    invocation_id: invocationID,
    request_hash: requestHashBytes,
  });
}

/**
 * Preview. The 32-byte session context of the connect proof of possession:
 * SHA-256 of CONNECT_POSSESSION_DOMAIN followed by the workspace ID,
 * receiver ID, audience, challenge ID, and agent key ID, each prefixed with
 * the 8-byte big-endian length of its UTF-8 bytes.
 */
export function connectPossessionContext(
  workspaceID: string,
  receiverID: string,
  audience: string,
  challengeID: string,
  agentID: string,
): Uint8Array {
  const h = sha256.create();
  h.update(utf8(CONNECT_POSSESSION_DOMAIN));
  for (const field of [workspaceID, receiverID, audience, challengeID, agentID]) {
    const bytes = utf8(field);
    h.update(uint64BE(bytes.length));
    h.update(bytes);
  }
  return h.digest();
}
