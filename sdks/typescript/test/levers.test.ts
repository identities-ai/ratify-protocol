// Tests for the SPEC §17.5–§17.8 levers introduced in alpha.7.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PROTOCOL_VERSION,
  SCOPE_MEETING_ATTEND,
  bundleHash,
  generateAgent,
  generateChallenge,
  generateHumanRoot,
  issueDelegation,
  issuePolicyVerdict,
  issueVerificationReceipt,
  receiptHash,
  signChallenge,
  verifierContextHash,
  verifyBundle,
  verifyPolicyVerdict,
  verifyVerificationReceipt,
  type Anchor,
  type AnchorResolver,
  type Constraint,
  type ConstraintEvaluator,
  type DelegationCert,
  type ProofBundle,
  type VerifierContext,
  type VerifyResult,
} from "../src/index.js";

async function goodBundle(): Promise<{ bundle: ProofBundle; certID: string; humanID: string }> {
  const { root, privateKey: rootPriv } = await generateHumanRoot();
  const { agent, privateKey: agentPriv } = await generateAgent("L Bot", "custom");
  const now = Math.floor(Date.now() / 1000);
  const cert: DelegationCert = {
    cert_id: "lever-cert",
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.public_key,
    subject_id: agent.id,
    subject_pub_key: agent.public_key,
    scope: [SCOPE_MEETING_ATTEND],
    issued_at: now,
    expires_at: now + 86400,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  await issueDelegation(cert, rootPriv);
  const challenge = generateChallenge();
  const sig = await signChallenge(challenge, now, agentPriv);
  return {
    bundle: {
      agent_id: agent.id,
      agent_pub_key: agent.public_key,
      delegations: [cert],
      challenge,
      challenge_at: now,
      challenge_sig: sig,
    },
    certID: cert.cert_id,
    humanID: root.id,
  };
}

// ---------------------------------------------------------------------------
// Lever 1: VerificationReceipt
// ---------------------------------------------------------------------------

test("verification receipt round-trip", async () => {
  const { bundle } = await goodBundle();
  const { agent: v, privateKey: vPriv } = await generateAgent("v", "verifier");
  const result = await verifyBundle(bundle, {});
  const r = await issueVerificationReceipt(
    bundle, result, v.id, v.public_key, vPriv, null, Math.floor(Date.now() / 1000),
  );
  const err = await verifyVerificationReceipt(r);
  assert.equal(err, null);
  assert.equal(r.decision, "authorized_agent");
});

test("verification receipt detects tampering", async () => {
  const { bundle } = await goodBundle();
  const { agent: v, privateKey: vPriv } = await generateAgent("v", "verifier");
  const result = await verifyBundle(bundle, {});
  const r = await issueVerificationReceipt(
    bundle, result, v.id, v.public_key, vPriv, null, Math.floor(Date.now() / 1000),
  );
  r.decision = "revoked";
  const err = await verifyVerificationReceipt(r);
  assert.notEqual(err, null);
});

test("verification receipt detects bundle substitution", async () => {
  const { bundle: b1 } = await goodBundle();
  const { bundle: b2 } = await goodBundle();
  const { agent: v, privateKey: vPriv } = await generateAgent("v", "verifier");
  const result = await verifyBundle(b1, {});
  const r = await issueVerificationReceipt(
    b1, result, v.id, v.public_key, vPriv, null, Math.floor(Date.now() / 1000),
  );
  r.bundle_hash = bundleHash(b2);
  const err = await verifyVerificationReceipt(r);
  assert.notEqual(err, null);
});

test("verification receipt chain linkage", async () => {
  const { bundle } = await goodBundle();
  const { agent: v, privateKey: vPriv } = await generateAgent("v", "verifier");
  const result = await verifyBundle(bundle, {});
  const r1 = await issueVerificationReceipt(
    bundle, result, v.id, v.public_key, vPriv, null, Math.floor(Date.now() / 1000),
  );
  const prev = receiptHash(r1);
  const r2 = await issueVerificationReceipt(
    bundle, result, v.id, v.public_key, vPriv, prev, Math.floor(Date.now() / 1000),
  );
  assert.deepEqual(r2.prev_hash, prev);
  // Tampering r1 changes its hash — chain pointer in r2 would no longer match.
  r1.decision = "tampered";
  const prevAfter = receiptHash(r1);
  assert.notDeepEqual(prev, prevAfter);
});

test("bundleHash deterministic", async () => {
  const { bundle } = await goodBundle();
  assert.deepEqual(bundleHash(bundle), bundleHash(bundle));
  assert.equal(bundleHash(bundle).length, 32);
});

// ---------------------------------------------------------------------------
// Lever 2: PolicyVerdict
// ---------------------------------------------------------------------------

const SECRET = new Uint8Array(32).fill(0x33);

test("policy verdict round-trip", () => {
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const v = issuePolicyVerdict("vid", "agent-A", "meeting:attend", true, ctx, now, now + 3600, SECRET);
  assert.equal(verifyPolicyVerdict(v, SECRET, "agent-A", "meeting:attend", ctx, now), null);
});

test("policy verdict deny returns policy_verdict_denied", () => {
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const v = issuePolicyVerdict("v", "a", "s", false, ctx, now, now + 3600, SECRET);
  const err = verifyPolicyVerdict(v, SECRET, "a", "s", ctx, now);
  assert.match(err ?? "", /policy_verdict_denied/);
});

test("policy verdict wrong secret rejected", () => {
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const v = issuePolicyVerdict("v", "a", "s", true, ctx, now, now + 3600, SECRET);
  const wrong = new Uint8Array(32).fill(0x44);
  assert.notEqual(verifyPolicyVerdict(v, wrong, "a", "s", ctx, now), null);
});

test("policy verdict context_hash mismatch", () => {
  const now = Math.floor(Date.now() / 1000);
  const ctxA = verifierContextHash({ current_lat: 37, current_lon: -122 });
  const ctxB = verifierContextHash({ current_lat: 51.5, current_lon: -0.1 });
  const v = issuePolicyVerdict("v", "a", "s", true, ctxA, now, now + 3600, SECRET);
  assert.notEqual(verifyPolicyVerdict(v, SECRET, "a", "s", ctxB, now), null);
});

test("policy verdict expired", () => {
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const v = issuePolicyVerdict("v", "a", "s", true, ctx, now - 7200, now - 3600, SECRET);
  assert.notEqual(verifyPolicyVerdict(v, SECRET, "a", "s", ctx, now), null);
});

test("policy verdict fast-path skips live policy", async () => {
  const { bundle } = await goodBundle();
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const verdict = issuePolicyVerdict(
    "vid", bundle.agent_id, "meeting:attend", true, ctx, now - 60, now + 3600, SECRET,
  );
  let liveCalls = 0;
  const res = await verifyBundle(bundle, {
    required_scope: "meeting:attend",
    policy: {
      async evaluatePolicy() {
        liveCalls += 1;
        return false; // would deny
      },
    },
    policy_verdict: verdict,
    policy_secret: SECRET,
  });
  assert.equal(res.valid, true, res.error_reason);
  assert.equal(liveCalls, 0);
});

test("policy verdict fast-path: cached deny", async () => {
  const { bundle } = await goodBundle();
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const verdict = issuePolicyVerdict(
    "vid", bundle.agent_id, "meeting:attend", false, ctx, now - 60, now + 3600, SECRET,
  );
  let liveCalls = 0;
  const res = await verifyBundle(bundle, {
    required_scope: "meeting:attend",
    policy: { async evaluatePolicy() { liveCalls += 1; return true; } },
    policy_verdict: verdict,
    policy_secret: SECRET,
  });
  assert.equal(res.valid, false);
  assert.equal(res.identity_status, "scope_denied");
  assert.equal(liveCalls, 0);
});

test("policy verdict falls back to live policy when stale", async () => {
  const { bundle } = await goodBundle();
  const now = Math.floor(Date.now() / 1000);
  const ctx = verifierContextHash({});
  const expired = issuePolicyVerdict(
    "vid", bundle.agent_id, "meeting:attend", true, ctx, now - 7200, now - 3600, SECRET,
  );
  let liveCalls = 0;
  const res = await verifyBundle(bundle, {
    required_scope: "meeting:attend",
    policy: { async evaluatePolicy() { liveCalls += 1; return true; } },
    policy_verdict: expired,
    policy_secret: SECRET,
  });
  assert.equal(res.valid, true, res.error_reason);
  assert.equal(liveCalls, 1);
});

// ---------------------------------------------------------------------------
// Lever 3: ConstraintEvaluator
// ---------------------------------------------------------------------------

async function bundleWithCustomConstraint(type: string): Promise<ProofBundle> {
  const { root, privateKey: rootPriv } = await generateHumanRoot();
  const { agent, privateKey: agentPriv } = await generateAgent("C Bot", "custom");
  const now = Math.floor(Date.now() / 1000);
  const cert: DelegationCert = {
    cert_id: "custom-cert",
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.public_key,
    subject_id: agent.id,
    subject_pub_key: agent.public_key,
    scope: [SCOPE_MEETING_ATTEND],
    constraints: [{ type } as Constraint],
    issued_at: now,
    expires_at: now + 3600,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  await issueDelegation(cert, rootPriv);
  const challenge = generateChallenge();
  const sig = await signChallenge(challenge, now, agentPriv);
  return {
    agent_id: agent.id,
    agent_pub_key: agent.public_key,
    delegations: [cert],
    challenge,
    challenge_at: now,
    challenge_sig: sig,
  };
}

test("constraint evaluator: unknown type fails closed", async () => {
  const bundle = await bundleWithCustomConstraint("verify.max_concurrent_sessions");
  const res = await verifyBundle(bundle, {});
  assert.equal(res.valid, false);
  assert.equal(res.identity_status, "constraint_unknown");
});

test("constraint evaluator: registered allow", async () => {
  const bundle = await bundleWithCustomConstraint("verify.max_concurrent_sessions");
  const ev: ConstraintEvaluator = { async evaluate() { return true; } };
  const res = await verifyBundle(bundle, {
    constraint_evaluators: { "verify.max_concurrent_sessions": ev },
  });
  assert.equal(res.valid, true, res.error_reason);
});

test("constraint evaluator: registered deny", async () => {
  const bundle = await bundleWithCustomConstraint("verify.max_concurrent_sessions");
  const ev: ConstraintEvaluator = { async evaluate() { return false; } };
  const res = await verifyBundle(bundle, {
    constraint_evaluators: { "verify.max_concurrent_sessions": ev },
  });
  assert.equal(res.valid, false);
  assert.equal(res.identity_status, "constraint_denied");
});

test("constraint evaluator: unverifiable routes correctly", async () => {
  const bundle = await bundleWithCustomConstraint("verify.needs_context");
  const ev: ConstraintEvaluator = { async evaluate() { return "unverifiable"; } };
  const res = await verifyBundle(bundle, {
    constraint_evaluators: { "verify.needs_context": ev },
  });
  assert.equal(res.valid, false);
  assert.equal(res.identity_status, "constraint_unverifiable");
});

// ---------------------------------------------------------------------------
// Lever 4: AnchorResolver
// ---------------------------------------------------------------------------

test("anchor resolver populates result", async () => {
  const { bundle, humanID } = await goodBundle();
  const anchor: Anchor = {
    type: "enterprise_sso",
    provider: "okta",
    reference: "opaque",
    verified_at: 1000,
  };
  const resolver: AnchorResolver = {
    async resolveAnchor(id) {
      return id === humanID ? anchor : null;
    },
  };
  const res = await verifyBundle(bundle, { anchor_resolver: resolver });
  assert.equal(res.valid, true, res.error_reason);
  assert.equal(res.anchor?.provider, "okta");
});

test("anchor resolver error is non-fatal", async () => {
  const { bundle } = await goodBundle();
  const resolver: AnchorResolver = {
    async resolveAnchor() { throw new Error("directory down"); },
  };
  const res = await verifyBundle(bundle, { anchor_resolver: resolver });
  assert.equal(res.valid, true, res.error_reason);
  assert.equal(res.anchor, undefined);
});

// Cross-SDK byte-equivalence is covered by cross_sdk.test.ts which loads
// the canonical fixture file testvectors/v1/cross_sdk_vectors.json.

test("audit observes anchor", async () => {
  const { bundle, humanID } = await goodBundle();
  const anchor: Anchor = {
    type: "email", provider: "google", reference: "h:abc", verified_at: 100,
  };
  const logged: VerifyResult[] = [];
  const res = await verifyBundle(bundle, {
    anchor_resolver: { async resolveAnchor(id) { return id === humanID ? anchor : null; } },
    audit: { async logVerification(r) { logged.push(r); } },
  });
  assert.equal(res.valid, true);
  assert.equal(logged.length, 1);
  assert.equal(logged[0]!.anchor?.provider, "google");
});
