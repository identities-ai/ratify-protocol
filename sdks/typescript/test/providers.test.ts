// Tests for the Provider interfaces defined in SPEC §17. The fixture is a
// freshly minted single-cert ProofBundle that verifies cleanly with no
// options — each test then configures one provider hook at a time and
// asserts the verifier's behaviour matches the spec.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PROTOCOL_VERSION,
  SCOPE_MEETING_ATTEND,
  generateAgent,
  generateChallenge,
  generateHumanRoot,
  issueDelegation,
  signChallenge,
  verifyBundle,
  type AuditProvider,
  type DelegationCert,
  type PolicyProvider,
  type ProofBundle,
  type RevocationProvider,
  type VerifyResult,
} from "../src/index.js";

async function goodBundle(): Promise<{ bundle: ProofBundle; certID: string }> {
  const { root, privateKey: rootPriv } = await generateHumanRoot();
  const { agent, privateKey: agentPriv } = await generateAgent("Provider Bot", "custom");
  const now = Math.floor(Date.now() / 1000);
  const cert: DelegationCert = {
    cert_id: "provider-cert-001",
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
  };
}

// ---------------------------------------------------------------------------
// RevocationProvider — SPEC §17.1
// ---------------------------------------------------------------------------

class FakeRevocation implements RevocationProvider {
  calls = 0;
  constructor(
    private readonly revoked: Record<string, boolean> = {},
    private readonly err: Error | null = null,
  ) {}
  async isRevoked(certID: string): Promise<[boolean, Error | null]> {
    this.calls += 1;
    if (this.err) return [false, this.err];
    return [Boolean(this.revoked[certID]), null];
  }
}

test("revocation provider — revoked", async () => {
  const { bundle, certID } = await goodBundle();
  const provider = new FakeRevocation({ [certID]: true });
  const res = await verifyBundle(bundle, { revocation: provider });
  assert.equal(res.valid, false);
  assert.equal(res.identity_status, "revoked");
  assert.equal(provider.calls, 1);
});

test("revocation provider — not revoked", async () => {
  const { bundle } = await goodBundle();
  const provider = new FakeRevocation();
  const res = await verifyBundle(bundle, { revocation: provider });
  assert.equal(res.valid, true, res.error_reason);
});

test("revocation provider — lookup error fails closed", async () => {
  const { bundle } = await goodBundle();
  const provider = new FakeRevocation({}, new Error("upstream timeout"));
  const res = await verifyBundle(bundle, { revocation: provider });
  assert.equal(res.valid, false);
  assert.ok(
    res.error_reason.includes("revocation_error"),
    `error_reason=${res.error_reason}`,
  );
});

test("revocation provider takes precedence over legacy closure", async () => {
  const { bundle, certID } = await goodBundle();
  const provider = new FakeRevocation({ [certID]: true });
  let closureCalls = 0;
  const res = await verifyBundle(bundle, {
    revocation: provider,
    is_revoked: (_id: string) => {
      closureCalls += 1;
      return false;
    },
  });
  assert.equal(res.valid, false);
  assert.equal(closureCalls, 0, "legacy closure must not be invoked");
});

test("force_revocation_check accepts a provider", async () => {
  const { bundle } = await goodBundle();
  const provider = new FakeRevocation();
  const res = await verifyBundle(bundle, {
    revocation: provider,
    force_revocation_check: true,
  });
  assert.equal(res.valid, true, res.error_reason);
});

// ---------------------------------------------------------------------------
// PolicyProvider — SPEC §17.2
// ---------------------------------------------------------------------------

class FakePolicy implements PolicyProvider {
  calls = 0;
  constructor(
    private readonly allow: boolean = true,
    private readonly raises: Error | null = null,
  ) {}
  async evaluatePolicy(): Promise<boolean> {
    this.calls += 1;
    if (this.raises) throw this.raises;
    return this.allow;
  }
}

test("policy provider — allow", async () => {
  const { bundle } = await goodBundle();
  const policy = new FakePolicy(true);
  const res = await verifyBundle(bundle, { policy });
  assert.equal(res.valid, true, res.error_reason);
  assert.equal(policy.calls, 1);
});

test("policy provider — deny → scope_denied", async () => {
  const { bundle } = await goodBundle();
  const policy = new FakePolicy(false);
  const res = await verifyBundle(bundle, { policy });
  assert.equal(res.valid, false);
  assert.equal(res.identity_status, "scope_denied");
});

test("policy provider — exception fails closed", async () => {
  const { bundle } = await goodBundle();
  const policy = new FakePolicy(true, new Error("opa eval crashed"));
  const res = await verifyBundle(bundle, { policy });
  assert.equal(res.valid, false);
  assert.ok(
    res.error_reason.includes("policy_error"),
    `error_reason=${res.error_reason}`,
  );
});

test("policy provider only runs after crypto checks", async () => {
  const { bundle } = await goodBundle();
  bundle.challenge = new TextEncoder().encode("tampered");
  const policy = new FakePolicy(true);
  const res = await verifyBundle(bundle, { policy });
  assert.equal(res.valid, false);
  assert.equal(policy.calls, 0, "policy must not run when crypto fails");
});

// ---------------------------------------------------------------------------
// AuditProvider — SPEC §17.3
// ---------------------------------------------------------------------------

class FakeAudit implements AuditProvider {
  results: VerifyResult[] = [];
  constructor(private readonly raises: Error | null = null) {}
  async logVerification(result: VerifyResult, _bundle: ProofBundle): Promise<void> {
    this.results.push(result);
    if (this.raises) throw this.raises;
  }
}

test("audit provider logs success", async () => {
  const { bundle } = await goodBundle();
  const audit = new FakeAudit();
  const res = await verifyBundle(bundle, { audit });
  assert.equal(res.valid, true, res.error_reason);
  assert.equal(audit.results.length, 1);
  assert.equal(audit.results[0]!.valid, true);
});

test("audit provider logs failure", async () => {
  const { bundle } = await goodBundle();
  bundle.challenge = new TextEncoder().encode("tampered");
  const audit = new FakeAudit();
  const res = await verifyBundle(bundle, { audit });
  assert.equal(res.valid, false);
  assert.equal(audit.results.length, 1);
  assert.equal(audit.results[0]!.valid, false);
});

test("audit provider exceptions do not alter the verdict", async () => {
  const { bundle } = await goodBundle();
  const audit = new FakeAudit(new Error("audit store offline"));
  const res = await verifyBundle(bundle, { audit });
  assert.equal(res.valid, true, "audit exception must not flip verdict");
});
