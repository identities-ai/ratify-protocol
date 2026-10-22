// testvectors/v2/operation-session-context.json: the operation and session
// context encodings (SPEC-v2 §2.4), the fixed Verify context policy and its
// digest (§6.12), and the managed Verify API payload-digest representation
// (§7.12).

import { test } from "node:test";
import assert from "node:assert/strict";

import { newV2ContextPolicy } from "../../src/context_policy_v2.js";
import { buildSessionContextV2, operationContextV2Hash } from "../../src/operation_context_v2.js";
import { validateRequiredScopeV2 } from "../../src/scope_v2.js";
import { hex, load, toHex, type Any } from "./helpers.js";

const f = load("operation-session-context.json");

/**
 * The Verify API text form of a payload digest (Go DecodePayloadDigest):
 * null is absent; otherwise exactly "sha256:" and 64 lowercase hex digits.
 * Protocol SDKs need only the raw form; this harness decodes the API form.
 */
function decodeVerifyAPIPayloadDigest(encoded: string | null): Uint8Array | null {
  if (encoded === null) return null;
  if (!/^sha256:[0-9a-f]{64}$/.test(encoded)) throw new Error("payload digest must be sha256: followed by 64 lowercase hexadecimal characters");
  return hex(encoded.slice(7));
}

const session = (requestHash: Uint8Array) => buildSessionContextV2({
  verifier_id: f.input.verifier_id, workspace_id: f.input.workspace_id, agent_id: f.input.agent_id,
  session_id: f.input.session_id, invocation_id: f.input.invocation_id, request_hash: requestHash,
});

test("operation-session-context.json: context policy digest", () => {
  const p = f.context_policy;
  assert.equal(p.version, 1);
  const policy = newV2ContextPolicy(p.profile, p.require_bound, p.required_fields, new Uint8Array(32));
  assert.equal(policy.digest, f.context_policy_digest);
});

test("operation-session-context.json: session context known answer", () => {
  assert.equal(toHex(session(hex(f.input.request_hash_hex))), f.expected_session_context_hex);
});

test("operation-session-context.json: operation request hash with and without payload digest", () => {
  const op = f.operation_input;
  const requestHash = operationContextV2Hash({
    required_scope: op.required_scope, operation: op.operation, resource_id: op.resource_id,
    requested_path: op.requested_path, payload_digest: hex(op.payload_digest_hex),
  });
  assert.equal(toHex(requestHash), f.expected_request_hash_hex);
  const e = f.empty_payload_operation_input;
  assert.equal(e.payload_digest_hex, null);
  const emptyHash = operationContextV2Hash({ required_scope: e.required_scope, operation: e.operation, resource_id: e.resource_id, requested_path: e.requested_path });
  assert.equal(toHex(emptyHash), f.expected_empty_request_hash_hex);
  assert.equal(toHex(session(emptyHash)), f.expected_empty_session_context_hex);
});

test("operation-session-context.json: invalid required scopes are rejected", () => {
  assert.ok(f.invalid_required_scopes.length > 0);
  for (const scope of f.invalid_required_scopes as string[]) {
    assert.notEqual(validateRequiredScopeV2(scope), null, `${JSON.stringify(scope)} accepted as a required scope`);
    assert.throws(() => operationContextV2Hash({ required_scope: scope }), /required scope/, JSON.stringify(scope));
  }
  // An exact custom: scope is requestable (SPEC-v2 §2.4).
  assert.equal(validateRequiredScopeV2("custom:invoice:read"), null);
});

test("operation-session-context.json: Verify API payload digest representation", () => {
  const api = f.verify_api_operation_input;
  const digest = decodeVerifyAPIPayloadDigest(api.payload_digest)!;
  const requestHash = operationContextV2Hash({
    required_scope: api.required_scope, operation: api.operation, resource_id: api.resource_id,
    requested_path: api.requested_path, payload_digest: digest,
  });
  assert.equal(toHex(requestHash), f.expected_verify_api_request_hash_hex);
  for (const c of f.verify_api_payload_digest_decode_cases as Any[]) {
    let got: Uint8Array | null = null;
    let ok = true;
    try {
      got = decodeVerifyAPIPayloadDigest(c.encoded);
    } catch {
      ok = false;
    }
    assert.equal(ok, c.valid, c.name);
    if (ok) assert.equal(got === null ? "" : toHex(got), c.expected_hex, c.name);
  }
});
