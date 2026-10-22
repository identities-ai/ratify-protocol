// Protocol v2 authority boundary for the GitHub Copilot reference.
// DEVELOPMENT ONLY: the receiver runs on the SDK's in-memory reference stores.
import assert from "node:assert/strict";
import test from "node:test";
import {
  hybridKeypairFromSeeds,
  keyIDV2,
  signDelegationCertV2,
  type DelegationCertV2,
} from "@identities-ai/ratify-protocol/v2";
import { createDemoAuthority, presentAuthority, type DemoAuthority } from "../src/authority.js";
import { ALLOWED_PATH, CERT_ID, RESOURCE_ID } from "../src/constants.js";
import { ProtectedDeployReceiver } from "../src/receiver.js";
import type { DeployRequest } from "../src/request.js";
import { DemoStatusFeed } from "../src/status-feed.js";

const staging: DeployRequest = {
  repository: "identities-ai/copilot-authority-demo",
  service: "payments",
  environment: "staging",
  artifact_digest: "sha256:approved",
  invocation_id: "test-invocation-1",
};

const now = () => Math.floor(Date.now() / 1000);
const unsigned = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) };

async function receiverFor(authority: DemoAuthority, pinnedRoot = authority.root.publicKey) {
  const feed = await DemoStatusFeed.create(authority, now());
  const receiver = await ProtectedDeployReceiver.create({
    trustedRoot: { publicKey: pinnedRoot },
    statusKey: authority.status.publicKey,
    expectedAgent: authority.agent.publicKey,
    statusFeed: (at) => feed.current(at),
  });
  return { receiver, feed };
}

async function present(receiver: ProtectedDeployReceiver, authority: DemoAuthority, request: DeployRequest, delegation?: DelegationCertV2) {
  const issued = await receiver.challenge(request);
  return presentAuthority({ ...authority, delegation: delegation ?? authority.delegation }, {
    value: new Uint8Array(Buffer.from(issued.challenge, "base64")),
    challengeAt: issued.challenge_at,
    verifierID: issued.verifier_id,
    sessionContext: new Uint8Array(Buffer.from(issued.session_context, "base64")),
  });
}

async function setup() {
  const authority = await createDemoAuthority();
  const { receiver, feed } = await receiverFor(authority);
  const proof = await present(receiver, authority, staging);
  return { authority, receiver, feed, proof };
}

test("a released allow for the exact custom scope invokes the protected handler exactly once", async () => {
  const { receiver, proof } = await setup();
  const result = await receiver.deploy(staging, proof);
  assert.equal(result.allowed, true, result.reason);
  assert.equal(result.reason, "authorized");
  assert.equal(result.handler_invocations, 1);
  assert.equal(result.receipt?.scope, "custom:github:deploy");
  assert.equal(result.receipt?.resource, "git:github.com/identities-ai/copilot-authority-demo");
  assert.equal(result.receipt?.path, ALLOWED_PATH);
  // Released only after a signed receipt was published and acknowledged.
  assert.equal(result.verification_receipt?.log_sequence, 1);
  assert.equal(result.verification_receipt?.decision, "allow");
});

test("production is a different operation than the one challenged and invokes nothing", async () => {
  const { receiver, proof } = await setup();
  const result = await receiver.deploy({ ...staging, environment: "production" }, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /session_context_mismatch/);
  assert.equal(result.handler_invocations, 0);
  // Nothing was consumed: the original request still releases.
  assert.equal((await receiver.deploy(staging, proof)).allowed, true);
});

test("production challenged honestly is outside the delegated path and denies with a signed receipt", async () => {
  const { authority, receiver } = await setup();
  const request = { ...staging, environment: "production" };
  const result = await receiver.deploy(request, await present(receiver, authority, request));
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^deny: constraint_denied$/);
  assert.equal(result.verification_receipt?.decision, "deny");
  assert.equal(result.handler_invocations, 0);
});

test("changing the artifact after challenge issuance invalidates the operation binding", async () => {
  const { receiver, proof } = await setup();
  const result = await receiver.deploy({ ...staging, artifact_digest: "sha256:changed" }, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /session_context_mismatch/);
  assert.equal(result.handler_invocations, 0);
});

test("another repository is outside the delegated Git resource and invokes nothing", async () => {
  const { authority, receiver } = await setup();
  const request = { ...staging, repository: "attacker/other-repository" };
  const result = await receiver.deploy(request, await present(receiver, authority, request));
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^deny: constraint_denied$/);
  assert.equal(result.handler_invocations, 0);
});

test("a non-canonical repository spelling is refused rather than normalized", async () => {
  const { receiver } = await setup();
  for (const repository of ["Identities-AI/copilot-authority-demo", "identities-ai/copilot-authority-demo.git", "https://github.com/identities-ai/copilot-authority-demo"]) {
    await assert.rejects(receiver.challenge({ ...staging, repository }), /canonical lowercase owner\/repo/);
  }
});

test("a proof is single-use and a replay is rejected before evaluation", async () => {
  const { receiver, proof } = await setup();
  assert.equal((await receiver.deploy(staging, proof)).allowed, true);
  const replay = await receiver.deploy(staging, proof);
  assert.equal(replay.allowed, false);
  assert.match(replay.reason, /^replay:/);
  assert.equal(replay.handler_invocations, 1);
});

test("a signed revocation from the principal's status publisher denies before the handler", async () => {
  const { authority, receiver, feed } = await setup();
  await feed.revoke(CERT_ID, now() + 1);
  const proof = await present(receiver, authority, { ...staging, invocation_id: "after-revoke" });
  const result = await receiver.deploy({ ...staging, invocation_id: "after-revoke" }, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^deny: delegation_revoked$/);
  assert.equal(result.handler_invocations, 0);
});

test("status signed by a key other than the pinned status key cannot allow", async () => {
  const authority = await createDemoAuthority();
  const impostor = { ...authority, status: await hybridKeypairFromSeeds(new Uint8Array(32).fill(51), new Uint8Array(32).fill(52)) };
  const forged = await DemoStatusFeed.create(impostor, now());
  const receiver = await ProtectedDeployReceiver.create({
    trustedRoot: { publicKey: authority.root.publicKey },
    statusKey: authority.status.publicKey,
    expectedAgent: authority.agent.publicKey,
    statusFeed: (at) => forged.current(at),
  });
  const result = await receiver.deploy(staging, await present(receiver, authority, staging));
  assert.equal(result.allowed, false);
  assert.equal(result.handler_invocations, 0);
});

test("a delegation for a different custom scope does not grant custom:github:deploy", async () => {
  const { authority, receiver } = await setup();
  const other = await signDelegationCertV2({
    ...authority.delegation,
    cert_id: "other-scope",
    scope: ["custom:github:deploy-preview"],
    signature: unsigned,
  }, authority.root);
  const result = await receiver.deploy(staging, await present(receiver, authority, staging, other));
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^deny: scope_denied$/);
  assert.equal(result.handler_invocations, 0);
});

test("a cryptographically valid proof from an untrusted root invokes nothing", async () => {
  const authority = await createDemoAuthority();
  const untrusted = await hybridKeypairFromSeeds(new Uint8Array(32).fill(41), new Uint8Array(32).fill(42));
  const { receiver } = await receiverFor(authority, untrusted.publicKey);
  const result = await receiver.deploy(staging, await present(receiver, authority, staging));
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^deny: unauthorized$/);
  assert.equal(result.handler_invocations, 0);
});

test("a root ID claimed by a different key is rejected before any state is consumed", async () => {
  const { authority, receiver } = await setup();
  const attacker = await hybridKeypairFromSeeds(new Uint8Array(32).fill(31), new Uint8Array(32).fill(32));
  const attackerID = keyIDV2(attacker.publicKey);
  // The SDK signer refuses to sign a certificate whose issuer ID is not the
  // ID of its issuer key, so an attacker has to forge the wire by hand.
  await assert.rejects(signDelegationCertV2({
    ...authority.delegation, issuer_pub_key: attacker.publicKey, signature: unsigned,
  }, attacker), /key ID does not match/);
  const own = await signDelegationCertV2({
    ...authority.delegation, issuer_id: attackerID, issuer_pub_key: attacker.publicKey, signature: unsigned,
  }, attacker);
  const honest = await present(receiver, authority, staging, own);
  const forged = new TextEncoder().encode(new TextDecoder().decode(honest).replaceAll(attackerID, authority.rootID));
  assert.notDeepEqual(forged, honest);
  const result = await receiver.deploy(staging, forged);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^preflight:/);
  assert.equal(result.handler_invocations, 0);
  // Rejected before claim: the challenge is still live for an honest proof.
  const genuine = await receiver.deploy(staging, await present(receiver, authority, staging));
  assert.equal(genuine.allowed, true, genuine.reason);
});

test("receiver configuration rejects a root ID that does not match its pinned key", async () => {
  const authority = await createDemoAuthority();
  await assert.rejects(
    ProtectedDeployReceiver.create({
      trustedRoot: { id: "0".repeat(64), publicKey: authority.root.publicKey },
      statusKey: authority.status.publicKey,
      expectedAgent: authority.agent.publicKey,
      statusFeed: async () => [],
    }),
    /trusted root ID does not match its public key/,
  );
  assert.equal(keyIDV2(authority.root.publicKey), authority.rootID);
});
