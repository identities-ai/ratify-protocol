// Ratify Protocol v2 operation and session context constructions (SPEC-v2 §2.2).
// These functions intentionally use v2 domain tags and leave the v1 API unchanged.

import { sha256 } from "@noble/hashes/sha2";
import { validateRequiredScopeV2 } from "./scope_v2.js";
import { classified, v2Errorf } from "./errors_v2.js";

const OPERATION_CONTEXT_V2_DOMAIN_TAG = "ratify/operation-context/v2";
const SESSION_CONTEXT_V2_DOMAIN_TAG = "ratify/session-context/v2";
const KEY_ID_PATTERN = /^[0-9a-f]{64}$/;
const WORKSPACE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface OperationContextV2 {
  required_scope: string;
  operation?: string;
  resource_id?: string;
  requested_path?: string;
  /** Absent or exactly 32 raw SHA-256 bytes. */
  payload_digest?: Uint8Array;
}

export interface SessionContextV2Inputs {
  verifier_id: string;
  workspace_id: string;
  agent_id: string;
  session_id: string;
  invocation_id: string;
  /** Exactly 32 raw SHA-256 bytes from operationContextV2Hash. */
  request_hash: Uint8Array;
}

function encodeText(name: string, value: string | undefined): Uint8Array {
  const text = value ?? "";
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error(`${name} is not well-formed Unicode`);
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error(`${name} is not well-formed Unicode`);
    }
  }
  return new TextEncoder().encode(text);
}

function appendLengthPrefixed(chunks: Uint8Array[], field: Uint8Array): void {
  const prefix = new Uint8Array(8);
  new DataView(prefix.buffer).setBigUint64(0, BigInt(field.length));
  chunks.push(prefix, field);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function operationContextV2Bytes(ctx: OperationContextV2): Uint8Array {
  return classified("configuration_invalid", () => {
    if (validateRequiredScopeV2(ctx.required_scope ?? "") !== null) {
      throw v2Errorf("invalid_required_scope", "required scope must be one canonical scope or one exact custom: scope");
    }
    const digest = ctx.payload_digest ?? new Uint8Array(0);
    if (digest.length !== 0 && digest.length !== 32) {
      throw new Error(`payload digest must be empty or 32 bytes, got ${digest.length}`);
    }
    const chunks: Uint8Array[] = [new TextEncoder().encode(OPERATION_CONTEXT_V2_DOMAIN_TAG)];
    appendLengthPrefixed(chunks, encodeText("required scope", ctx.required_scope));
    appendLengthPrefixed(chunks, encodeText("operation", ctx.operation));
    appendLengthPrefixed(chunks, encodeText("resource id", ctx.resource_id));
    appendLengthPrefixed(chunks, encodeText("requested path", ctx.requested_path));
    appendLengthPrefixed(chunks, digest);
    return concat(chunks);
  });
}

export function operationContextV2Hash(ctx: OperationContextV2): Uint8Array {
  return sha256(operationContextV2Bytes(ctx));
}

export function sessionContextV2Bytes(inputs: SessionContextV2Inputs): Uint8Array {
  return classified("configuration_invalid", () => {
    if (!KEY_ID_PATTERN.test(inputs.verifier_id)) {
      throw new Error("verifier ID must be 64 lowercase hexadecimal characters");
    }
    if (!WORKSPACE_ID_PATTERN.test(inputs.workspace_id)) {
      throw new Error("workspace ID must be a canonical lowercase UUID");
    }
    if (!KEY_ID_PATTERN.test(inputs.agent_id)) {
      throw new Error("agent ID must be 64 lowercase hexadecimal characters");
    }
    if (inputs.request_hash.length !== 32) {
      throw new Error(`request hash must be 32 bytes, got ${inputs.request_hash.length}`);
    }
    const chunks: Uint8Array[] = [new TextEncoder().encode(SESSION_CONTEXT_V2_DOMAIN_TAG)];
    appendLengthPrefixed(chunks, encodeText("verifier ID", inputs.verifier_id));
    appendLengthPrefixed(chunks, encodeText("workspace ID", inputs.workspace_id));
    appendLengthPrefixed(chunks, encodeText("agent ID", inputs.agent_id));
    appendLengthPrefixed(chunks, encodeText("session ID", inputs.session_id));
    appendLengthPrefixed(chunks, encodeText("invocation ID", inputs.invocation_id));
    appendLengthPrefixed(chunks, inputs.request_hash);
    return concat(chunks);
  });
}

export function buildSessionContextV2(inputs: SessionContextV2Inputs): Uint8Array {
  return sha256(sessionContextV2Bytes(inputs));
}
