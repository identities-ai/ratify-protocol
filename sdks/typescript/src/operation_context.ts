// Operation-context and session-context canonical constructions
// (SPEC §6.4.9). Both are raw binary, domain-separated, and
// length-prefixed — NOT JSON. Length prefixes exist because raw
// concatenation is ambiguous ("ab"||"c" equals "a"||"bc"); domain tags
// exist so a hash computed for one construction can never collide with
// the other.

import { sha256 } from "@noble/hashes/sha2";

const OPERATION_CONTEXT_DOMAIN_TAG = "ratify/operation-context/v1";
const SESSION_CONTEXT_DOMAIN_TAG = "ratify/session-context/v1";

/**
 * The inputs that identify one specific action a presentation authorizes
 * (SPEC §6.4.9). Which fields are populated is deployment-defined —
 * absent fields encode as zero-length and the construction stays
 * well-defined.
 */
export interface OperationContext {
  /** Scope the action requires (e.g. "files:write"). */
  required_scope?: string;
  /** Action/operation type (e.g. "git.push", "tool.invoke"). */
  operation?: string;
  /** Target resource identity. */
  resource_id?: string;
  /** Path within the resource. */
  requested_path?: string;
  /**
   * Absent/empty, or exactly 32 bytes: the SHA-256 of the canonical
   * request payload, where one exists.
   */
  payload_digest?: Uint8Array;
}

/**
 * The inputs that identify the session a presentation belongs to, plus
 * the request_hash binding the specific operation (SPEC §6.4.9). The
 * Middleware Custody Profile (SPEC §15.2.1) requires all of them; other
 * deployments populate what they have.
 */
export interface SessionContextInputs {
  /**
   * The verifier's identity (e.g. its public key ID). Including it makes
   * cross-verifier challenge forwarding detectable at the cryptographic
   * layer (SPEC §15.1).
   */
  verifier_id?: string;
  /** The deployment's workspace/tenant identifier. */
  workspace_id?: string;
  /** The presenting agent's identity. */
  agent_id?: string;
  /** The session identifier. */
  session_id?: string;
  /** The specific invocation within the session. */
  invocation_id?: string;
  /**
   * Exactly 32 bytes — the operationContextHash of the action being
   * authorized. A deployment with no operation-specific inputs derives
   * it from an all-empty operation context. Binding the session but not
   * the operation would let an intermediary attach a valid proof to the
   * wrong action inside the right session.
   */
  request_hash: Uint8Array;
}

// Append big-endian uint64 length || field bytes.
function lengthPrefixed(chunks: Uint8Array[], field: Uint8Array): void {
  const prefix = new Uint8Array(8);
  new DataView(prefix.buffer).setBigUint64(0, BigInt(field.length));
  chunks.push(prefix, field);
}

function utf8(s: string | undefined): Uint8Array {
  return new TextEncoder().encode(s ?? "");
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/**
 * The SPEC §6.4.9 operation-context preimage: the domain tag followed by
 * every field length-prefixed, in canonical order. Throws if
 * payload_digest is neither absent/empty nor exactly 32 bytes.
 */
export function operationContextBytes(ctx: OperationContext): Uint8Array {
  const digest = ctx.payload_digest ?? new Uint8Array(0);
  if (digest.length !== 0 && digest.length !== 32) {
    throw new Error(`payload digest must be empty or 32 bytes, got ${digest.length}`);
  }
  const chunks: Uint8Array[] = [utf8(OPERATION_CONTEXT_DOMAIN_TAG)];
  lengthPrefixed(chunks, utf8(ctx.required_scope));
  lengthPrefixed(chunks, utf8(ctx.operation));
  lengthPrefixed(chunks, utf8(ctx.resource_id));
  lengthPrefixed(chunks, utf8(ctx.requested_path));
  lengthPrefixed(chunks, digest);
  return concat(chunks);
}

/**
 * The 32-byte request_hash: SHA-256 over the SPEC §6.4.9
 * operation-context bytes.
 */
export function operationContextHash(ctx: OperationContext): Uint8Array {
  return sha256(operationContextBytes(ctx));
}

/**
 * The SPEC §6.4.9 session-context preimage: the domain tag followed by
 * every field length-prefixed, in canonical order. Throws unless
 * request_hash is exactly 32 bytes — use operationContextHash to derive
 * it, over an all-empty operation context when the deployment has no
 * operation-specific inputs.
 */
export function sessionContextBytes(inputs: SessionContextInputs): Uint8Array {
  if (inputs.request_hash.length !== 32) {
    throw new Error(`request hash must be exactly 32 bytes, got ${inputs.request_hash.length}`);
  }
  const chunks: Uint8Array[] = [utf8(SESSION_CONTEXT_DOMAIN_TAG)];
  lengthPrefixed(chunks, utf8(inputs.verifier_id));
  lengthPrefixed(chunks, utf8(inputs.workspace_id));
  lengthPrefixed(chunks, utf8(inputs.agent_id));
  lengthPrefixed(chunks, utf8(inputs.session_id));
  lengthPrefixed(chunks, utf8(inputs.invocation_id));
  lengthPrefixed(chunks, inputs.request_hash);
  return concat(chunks);
}

/**
 * The 32-byte session_context: SHA-256 over the SPEC §6.4.9
 * session-context bytes — what a session-bound deployment passes as
 * VerifyOptions.session_context (and what the agent side includes in the
 * challenge signing bytes, SPEC §6.4.2). Verification receipts and audit
 * records bind this hash, never the preimage.
 */
export function buildSessionContext(inputs: SessionContextInputs): Uint8Array {
  return sha256(sessionContextBytes(inputs));
}
