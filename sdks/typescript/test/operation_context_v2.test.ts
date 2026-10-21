// Protocol v2 context functions must match the shared Go-generated vectors.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildSessionContextV2,
  operationContextV2Hash,
  type OperationContextV2,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "..", "..", "testvectors", "v2", "operation-session-context.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  input: {
    verifier_id: string;
    workspace_id: string;
    agent_id: string;
    session_id: string;
    invocation_id: string;
    request_hash_hex: string;
  };
  expected_session_context_hex: string;
  operation_input: {
    required_scope: string;
    operation: string;
    resource_id: string;
    requested_path: string;
    payload_digest_hex: string;
  };
  expected_request_hash_hex: string;
  empty_payload_operation_input: Omit<OperationContextV2, "payload_digest"> & { payload_digest_hex: null };
  expected_empty_request_hash_hex: string;
  expected_empty_session_context_hex: string;
  invalid_required_scopes: string[];
};

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex = (value: string): Uint8Array =>
  new Uint8Array(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);

test("Protocol v2 operation and session contexts match shared vectors", () => {
  const operation = fixture.operation_input;
  const context: OperationContextV2 = {
    required_scope: operation.required_scope,
    operation: operation.operation,
    resource_id: operation.resource_id,
    requested_path: operation.requested_path,
    payload_digest: fromHex(operation.payload_digest_hex),
  };
  const requestHash = operationContextV2Hash(context);
  assert.equal(hex(requestHash), fixture.expected_request_hash_hex);
  assert.equal(
    hex(
      buildSessionContextV2({
        verifier_id: fixture.input.verifier_id,
        workspace_id: fixture.input.workspace_id,
        agent_id: fixture.input.agent_id,
        session_id: fixture.input.session_id,
        invocation_id: fixture.input.invocation_id,
        request_hash: fromHex(fixture.input.request_hash_hex),
      }),
    ),
    fixture.expected_session_context_hex,
  );

  const emptyPayload = fixture.empty_payload_operation_input;
  const emptyRequestHash = operationContextV2Hash({
    required_scope: emptyPayload.required_scope,
    operation: emptyPayload.operation,
    resource_id: emptyPayload.resource_id,
    requested_path: emptyPayload.requested_path,
  });
  assert.equal(hex(emptyRequestHash), fixture.expected_empty_request_hash_hex);
  assert.equal(
    hex(
      buildSessionContextV2({
        verifier_id: fixture.input.verifier_id,
        workspace_id: fixture.input.workspace_id,
        agent_id: fixture.input.agent_id,
        session_id: fixture.input.session_id,
        invocation_id: fixture.input.invocation_id,
        request_hash: emptyRequestHash,
      }),
    ),
    fixture.expected_empty_session_context_hex,
  );
});

test("Protocol v2 context rejects malformed digests, identifiers, and Unicode", () => {
  assert.throws(() => operationContextV2Hash({ required_scope: "data:read", payload_digest: new Uint8Array(31) }), /payload digest/);
  assert.throws(() => operationContextV2Hash({ required_scope: "data:read", operation: "\ud800" }), /well-formed Unicode/);
  const validRequestHash = operationContextV2Hash({ required_scope: "data:read" });
  assert.throws(
    () => buildSessionContextV2({ ...fixture.input, request_hash: validRequestHash, verifier_id: "A".repeat(64) }),
    /verifier ID/,
  );
  assert.throws(
    () => buildSessionContextV2({ ...fixture.input, request_hash: validRequestHash, verifier_id: "a".repeat(32) }),
    /verifier ID/,
  );
  assert.throws(
    () => buildSessionContextV2({ ...fixture.input, request_hash: validRequestHash, agent_id: "a".repeat(32) }),
    /agent ID/,
  );
  assert.throws(
    () => buildSessionContextV2({ ...fixture.input, request_hash: validRequestHash, workspace_id: "not-a-uuid" }),
    /workspace ID/,
  );
  assert.throws(
    () => buildSessionContextV2({ ...fixture.input, request_hash: new Uint8Array(31) }),
    /request hash/,
  );
});

test("Protocol v2 operation context rejects noncanonical required scopes", () => {
  for (const required_scope of fixture.invalid_required_scopes) {
    assert.throws(() => operationContextV2Hash({ required_scope }), /required scope/);
  }
});
