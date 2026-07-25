// Operation-context / session-context construction tests (SPEC §6.4.9).
// The known-answer hex values are duplicated across all five SDK test
// suites so the implementations provably produce byte-identical hashes.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  operationContextHash,
  buildSessionContext,
  type OperationContext,
} from "../src/index.js";

const KAT_EMPTY_OPERATION_HASH =
  "d135e239f4a5a5a0ad6385b204d6c81f3c10e6b2f5debfa3cc8079488970f82f";
const KAT_FULL_OPERATION_HASH =
  "6b70b5f404f61624ab2379fee2756639d8629141ecb3593b53e5a22346e0c3e5";
const KAT_SESSION_CONTEXT =
  "788c692b5dafae52dd896eb5f7580f61d42b8c7a2abeed4d4eea9dcd4d7d4dfd";

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const fullOperation: OperationContext = {
  required_scope: "files:write",
  operation: "git.push",
  resource_id: "git:github.com/acme/api",
  requested_path: "/src/handlers",
  payload_digest: new Uint8Array(32).fill(0xab),
};

test("operation context: known answers match the Go reference", () => {
  assert.equal(hex(operationContextHash({})), KAT_EMPTY_OPERATION_HASH);
  assert.equal(hex(operationContextHash(fullOperation)), KAT_FULL_OPERATION_HASH);

  const session = buildSessionContext({
    verifier_id: "verifier-1",
    workspace_id: "ws-42",
    agent_id: "agent-7",
    session_id: "sess-9",
    invocation_id: "inv-3",
    request_hash: operationContextHash(fullOperation),
  });
  assert.equal(session.length, 32);
  assert.equal(hex(session), KAT_SESSION_CONTEXT);
});

test("operation context: length prefixing disambiguates shifted boundaries", () => {
  const a = operationContextHash({ operation: "ab", resource_id: "c" });
  const b = operationContextHash({ operation: "a", resource_id: "bc" });
  assert.notEqual(hex(a), hex(b));
});

test("operation context: domain separation between the two constructions", () => {
  const opHash = operationContextHash({});
  const session = buildSessionContext({ request_hash: opHash });
  assert.notEqual(hex(opHash), hex(session));
});

test("operation context: ill-formed Unicode is rejected, not replaced", () => {
  // JS strings are UTF-16; TextEncoder would silently turn a lone
  // surrogate into U+FFFD, colliding with a literal replacement
  // character. §6.4.9 requires rejection instead.
  const loneHigh = "\ud800x";
  const loneLow = "x\udc00";
  for (const bad of [loneHigh, loneLow]) {
    assert.throws(() => operationContextHash({ required_scope: bad }), /well-formed Unicode/);
    assert.throws(() => operationContextHash({ operation: bad }), /well-formed Unicode/);
    assert.throws(() => operationContextHash({ resource_id: bad }), /well-formed Unicode/);
    assert.throws(() => operationContextHash({ requested_path: bad }), /well-formed Unicode/);
    const requestHash = operationContextHash({});
    for (const sessionField of [
      { verifier_id: bad },
      { workspace_id: bad },
      { agent_id: bad },
      { session_id: bad },
      { invocation_id: bad },
    ]) {
      assert.throws(
        () => buildSessionContext({ ...sessionField, request_hash: requestHash }),
        /well-formed Unicode/,
      );
    }
  }
  // A valid surrogate PAIR (astral character) is fine.
  const astral = "\u{1F600}";
  assert.equal(operationContextHash({ operation: astral }).length, 32);
});

test("operation context: input validation", () => {
  assert.throws(() => operationContextHash({ payload_digest: new Uint8Array(5) }), /payload digest/);
  assert.throws(
    () => buildSessionContext({ request_hash: new Uint8Array(16) }),
    /request hash/,
  );
});

test("operation context: every field is load-bearing", () => {
  const base = hex(operationContextHash(fullOperation));
  const mutations: OperationContext[] = [
    { ...fullOperation, required_scope: "files:read" },
    { ...fullOperation, operation: "git.pull" },
    { ...fullOperation, resource_id: "git:github.com/acme/api2" },
    { ...fullOperation, requested_path: "/src" },
    { ...fullOperation, payload_digest: new Uint8Array(32).fill(0xac) },
  ];
  for (const m of mutations) {
    assert.notEqual(hex(operationContextHash(m)), base);
  }

  const requestHash = operationContextHash(fullOperation);
  const sessionBase = {
    verifier_id: "verifier-1",
    workspace_id: "ws-42",
    agent_id: "agent-7",
    session_id: "sess-9",
    invocation_id: "inv-3",
    request_hash: requestHash,
  };
  const sessionBaseHex = hex(buildSessionContext(sessionBase));
  const sessionMutations = [
    { ...sessionBase, verifier_id: "verifier-2" },
    { ...sessionBase, workspace_id: "ws-43" },
    { ...sessionBase, agent_id: "agent-8" },
    { ...sessionBase, session_id: "sess-10" },
    { ...sessionBase, invocation_id: "inv-4" },
    { ...sessionBase, request_hash: operationContextHash({ operation: "other" }) },
  ];
  for (const m of sessionMutations) {
    assert.notEqual(hex(buildSessionContext(m)), sessionBaseHex);
  }
});
