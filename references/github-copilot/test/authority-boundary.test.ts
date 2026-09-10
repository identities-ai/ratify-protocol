import assert from "node:assert/strict";
import test from "node:test";
import {
  PROTOCOL_VERSION,
  base64StandardDecode,
  deriveID,
  hybridKeypairFromSeeds,
  issueDelegation,
} from "@identities-ai/ratify-protocol";
import { createDemoAuthority, presentAuthority } from "../src/authority.js";
import { CERT_ID } from "../src/constants.js";
import { ProtectedDeployReceiver } from "../src/receiver.js";

const staging = {
  repository: "identities-ai/copilot-authority-demo",
  service: "payments",
  environment: "staging",
  artifact_digest: "sha256:approved",
  invocation_id: "test-invocation-1",
};

async function setup() {
  const authority = await createDemoAuthority();
  const receiver = new ProtectedDeployReceiver({
    id: authority.root.id,
    publicKey: authority.root.public_key,
  }, authority.agent.id);
  const issued = await receiver.challenge(staging);
  const proof = await presentAuthority(
    authority,
    base64StandardDecode(issued.challenge),
    base64StandardDecode(issued.session_context),
  );
  return { authority, receiver, proof };
}

test("valid bounded authority invokes the protected handler exactly once", async () => {
  const { receiver, proof } = await setup();
  const result = await receiver.deploy(staging, proof);
  assert.equal(result.allowed, true);
  assert.equal(result.handler_invocations, 1);
  assert.equal(result.receipt?.path, "/services/payments/environments/staging");
});

test("production is outside the delegated resource path and invokes nothing", async () => {
  const { receiver, proof } = await setup();
  const result = await receiver.deploy({ ...staging, environment: "production" }, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /session_context_mismatch/);
  assert.equal(result.handler_invocations, 0);
});

test("changing the artifact after challenge issuance invalidates operation binding", async () => {
  const { receiver, proof } = await setup();
  const result = await receiver.deploy({ ...staging, artifact_digest: "sha256:changed" }, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /session_context_mismatch/);
  assert.equal(result.handler_invocations, 0);
});

test("another repository is outside the delegated resource and invokes nothing", async () => {
  const authority = await createDemoAuthority();
  const receiver = new ProtectedDeployReceiver({
    id: authority.root.id,
    publicKey: authority.root.public_key,
  }, authority.agent.id);
  const request = { ...staging, repository: "attacker/other-repository" };
  const issued = await receiver.challenge(request);
  const proof = await presentAuthority(
    authority,
    base64StandardDecode(issued.challenge),
    base64StandardDecode(issued.session_context),
  );
  const result = await receiver.deploy(request, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /constraint_denied/);
  assert.equal(result.handler_invocations, 0);
});

test("a proof is single-use and cannot replay the protected action", async () => {
  const { receiver, proof } = await setup();
  assert.equal((await receiver.deploy(staging, proof)).allowed, true);
  const replay = await receiver.deploy(staging, proof);
  assert.equal(replay.allowed, false);
  assert.match(replay.reason, /unknown_challenge/);
  assert.equal(replay.handler_invocations, 1);
});

test("revocation is checked fresh before the protected handler", async () => {
  const { receiver, proof } = await setup();
  receiver.revoke(CERT_ID);
  const result = await receiver.deploy(staging, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /^revoked:/);
  assert.equal(result.handler_invocations, 0);
});

test("a cryptographically valid proof from an untrusted root invokes nothing", async () => {
  const authority = await createDemoAuthority();
  const untrusted = await hybridKeypairFromSeeds(new Uint8Array(32).fill(41), new Uint8Array(32).fill(42));
  const receiver = new ProtectedDeployReceiver({
    id: deriveID(untrusted.publicKey),
    publicKey: untrusted.publicKey,
  }, authority.agent.id);
  const issued = await receiver.challenge(staging);
  const proof = await presentAuthority(
    authority,
    base64StandardDecode(issued.challenge),
    base64StandardDecode(issued.session_context),
  );
  const result = await receiver.deploy(staging, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /untrusted_root/);
  assert.equal(result.handler_invocations, 0);
});

test("a root ID spoofed by a different key invokes nothing", async () => {
  const authority = await createDemoAuthority();
  const receiver = new ProtectedDeployReceiver({
    id: authority.root.id,
    publicKey: authority.root.public_key,
  }, authority.agent.id);
  const attacker = await hybridKeypairFromSeeds(new Uint8Array(32).fill(31), new Uint8Array(32).fill(32));
  const spoofedDelegation = {
    ...authority.delegation,
    version: PROTOCOL_VERSION,
    issuer_id: authority.root.id,
    issuer_pub_key: attacker.publicKey,
    signature: { ed25519: new Uint8Array(), ml_dsa_65: new Uint8Array() },
  };
  await issueDelegation(spoofedDelegation, attacker.privateKey);
  const issued = await receiver.challenge(staging);
  const proof = await presentAuthority(
    { ...authority, delegation: spoofedDelegation },
    base64StandardDecode(issued.challenge),
    base64StandardDecode(issued.session_context),
  );

  const result = await receiver.deploy(staging, proof);
  assert.equal(result.allowed, false);
  assert.match(result.reason, /untrusted_root/);
  assert.equal(result.handler_invocations, 0);
});

test("receiver configuration rejects a root ID that does not match its pinned key", async () => {
  const authority = await createDemoAuthority();
  assert.throws(
    () => new ProtectedDeployReceiver({
      id: "h1_mismatched_configuration",
      publicKey: authority.root.public_key,
    }, authority.agent.id),
    /trusted root ID does not match its public key/,
  );
});
