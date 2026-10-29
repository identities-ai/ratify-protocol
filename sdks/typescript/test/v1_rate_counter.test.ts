// v1 max_rate (SPEC §5.6): the invocation counter is the only input that can
// deny an otherwise valid bundle on rate grounds. A counter that cannot
// answer (a negative count, for example a database error mapped to -1) must
// fail closed, never read as "no invocations yet". Mirrors the Rust
// sdks/rust/tests/v1_rate_counter.rs.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateAgent,
  generateHumanRoot,
  issueDelegation,
  signChallenge,
  verifyBundle,
  type DelegationCert,
  type ProofBundle,
  type VerifyResult,
} from "../src/index.js";

const NOW = 1_800_000_000;

async function rateLimitedBundle(): Promise<ProofBundle> {
  const { root, privateKey: rootPriv } = await generateHumanRoot();
  const { agent, privateKey: agentPriv } = await generateAgent("rate-agent", "custom");
  const cert: DelegationCert = {
    cert_id: "rate-cert", version: 1, issuer_id: root.id, issuer_pub_key: root.public_key,
    subject_id: agent.id, subject_pub_key: agent.public_key, scope: ["meeting:attend"],
    constraints: [{ type: "max_rate", count: 1, window_s: 60 }],
    issued_at: NOW - 10, expires_at: NOW + 3600,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  await issueDelegation(cert, rootPriv);
  const challenge = new Uint8Array(32).fill(7);
  return {
    agent_id: agent.id, agent_pub_key: agent.public_key, delegations: [cert],
    challenge, challenge_at: NOW, challenge_sig: await signChallenge(challenge, NOW, agentPriv),
  };
}

async function verifyWithCount(count: number): Promise<VerifyResult> {
  return verifyBundle(await rateLimitedBundle(), {
    required_scope: "meeting:attend", now: NOW, context: { invocations_in_window: () => count },
  });
}

test("v1 max_rate: a count below the limit allows", async () => {
  const r = await verifyWithCount(0);
  assert.ok(r.valid, r.error_reason);
});

test("v1 max_rate: a count at the limit denies", async () => {
  const r = await verifyWithCount(1);
  assert.equal(r.valid, false);
  assert.equal(r.identity_status, "constraint_denied");
});

test("v1 max_rate: a negative count fails closed as constraint_unverifiable", async () => {
  for (const count of [-1, Number.MIN_SAFE_INTEGER, Number.NaN]) {
    const r = await verifyWithCount(count);
    assert.equal(r.valid, false, `count ${count} must not allow`);
    assert.equal(r.identity_status, "constraint_unverifiable", `count ${count}: ${r.error_reason}`);
  }
});
