// Ratify Verify MCP signer (`@identities-ai/ratify-protocol/v2/mcp`). Preview.
//
// The client side of the managed Ratify Verify MCP service: it signs the
// delegated-authority proof each tool call carries, answers the console's
// connect challenge with a proof of possession of the agent key, and parses
// the configuration the console hands out. It is not part of SPEC-v2
// conformance, and its API may change while it is a preview. Every hash is
// the normative SPEC-v2 operation and session context construction.
//
//   const config = parseClientConfig(configJSON);
//   const call = newToolCall("get_metrics", "{}");
//   const body = challengeRequest(config, call);       // POST <endpoint>/challenge
//   const challenge = checkChallenge(config, call.tool, responseBody, Math.floor(Date.now() / 1000));
//   const envelope = await signToolCall(config, agentKey, call, challenge);
//   // tools/call params._meta[PROOF_META_KEY] = envelope

export {
  McpSignerError,
  InvalidArgumentsError,
  InvalidConfigError,
  ChallengeRefusedError,
  InvalidConnectTokenError,
} from "./v2mcp/errors.js";
export { MAX_ARGUMENT_DEPTH, canonicalArguments } from "./v2mcp/arguments.js";
export {
  ACTION,
  PROOF_META_KEY,
  PROTOCOL_VERSION,
  MIN_CHALLENGE_SECONDS_LEFT,
  CONNECT_POSSESSION_DOMAIN,
  TOOLS,
  toolScope,
  payloadDigest,
  payloadDigestText,
  requestHash,
  sessionContext,
  connectPossessionContext,
  type McpTool,
} from "./v2mcp/binding.js";
export { parseClientConfig, type ClientConfig } from "./v2mcp/config.js";
export {
  newToolCall,
  challengeRequest,
  checkChallenge,
  signToolCall,
  signToolCallWithSigner,
  type Challenge,
  type ToolCall,
  type ProofEnvelope,
} from "./v2mcp/toolcall.js";
export {
  CONNECT_TOKEN_PREFIX,
  MAX_CONNECT_TOKEN_LENGTH,
  parseConnectToken,
  provePossession,
  provePossessionWithSigner,
  type ConnectToken,
  type PossessionProof,
} from "./v2mcp/connect.js";
