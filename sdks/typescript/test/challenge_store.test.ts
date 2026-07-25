// ChallengeStore tests — store semantics plus the locked consumption order
// in verifyBundle (SPEC §10): a challenge is consumed after the structural,
// chain, and challenge-signature checks pass and before authorization
// evaluation, so a forged presentation never spends a challenge and a
// cryptographically valid presentation spends it even when denied.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateHumanRoot,
  generateAgent,
  issueDelegation,
  signChallenge,
  verifyBundle,
  MemoryChallengeStore,
  UNKNOWN_CHALLENGE,
  PROTOCOL_VERSION,
  SCOPE_MEETING_ATTEND,
  SCOPE_TRANSACT_PURCHASE,
  SCOPE_FILES_WRITE,
  type Constraint,
  type DelegationCert,
  type ProofBundle,
} from "../src/index.js";

const NOW = () => Math.floor(Date.now() / 1000);

// ----- Store semantics -----

test("challenge store: issue then consume", async () => {
  const store = new MemoryChallengeStore(16);
  const { challenge, expires_at } = await store.issue(undefined, 300);
  assert.equal(challenge.length, 32);
  const until = expires_at - NOW();
  assert.ok(until >= 290 && until <= 310, `expiry ${until}s out, want ~300`);
  assert.equal(await store.validate(challenge, undefined, NOW()), null);
  assert.equal(await store.consume(challenge, undefined, NOW()), null);
});

test("challenge store: double consume fails", async () => {
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
  assert.equal(await store.consume(challenge, undefined, NOW()), null);
  assert.equal(await store.consume(challenge, undefined, NOW()), UNKNOWN_CHALLENGE);
  assert.equal(await store.validate(challenge, undefined, NOW()), UNKNOWN_CHALLENGE);
});

test("challenge store: expiry", async () => {
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
  const later = NOW() + 360;
  assert.equal(await store.validate(challenge, undefined, later), UNKNOWN_CHALLENGE);
  assert.equal(await store.consume(challenge, undefined, later), UNKNOWN_CHALLENGE);
});

test("challenge store: never-issued challenge", async () => {
  const store = new MemoryChallengeStore(16);
  assert.equal(
    await store.consume(new Uint8Array(32), undefined, NOW()),
    UNKNOWN_CHALLENGE,
  );
});

test("challenge store: wrong session context does not consume", async () => {
  const store = new MemoryChallengeStore(16);
  const ctx = new Uint8Array(32);
  ctx[0] = 1;
  const { challenge } = await store.issue(ctx, 300);

  const other = new Uint8Array(32);
  other[0] = 2;
  assert.equal(await store.consume(challenge, other, NOW()), UNKNOWN_CHALLENGE);
  assert.equal(await store.consume(challenge, undefined, NOW()), UNKNOWN_CHALLENGE);
  // The legitimate record survived both wrong-context presentations.
  assert.equal(await store.consume(challenge, ctx, NOW()), null);
});

test("challenge store: capacity cap", async () => {
  const store = new MemoryChallengeStore(2);
  await store.issue(undefined, 60);
  await store.issue(undefined, 60);
  await assert.rejects(() => store.issue(undefined, 60), /challenge store full/);
});

test("challenge store: repeated consume attempts yield exactly one success", async () => {
  // JS is single-threaded, so CAS is exercised as N racing consume calls:
  // exactly one may succeed.
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
  const results = await Promise.all(
    Array.from({ length: 64 }, () => store.consume(challenge, undefined, NOW())),
  );
  assert.equal(results.filter((r) => r === null).length, 1);
});

// ----- verifyBundle integration: the locked consumption order -----

async function storeBundle(
  scope: string[],
  constraints: Constraint[] = [],
): Promise<{ bundle: ProofBundle; store: MemoryChallengeStore }> {
  const { root, privateKey: rootPriv } = await generateHumanRoot();
  const { agent, privateKey: agentPriv } = await generateAgent("Store Bot", "custom");
  const now = NOW();
  const cert: DelegationCert = {
    cert_id: "store-cert-001",
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.public_key,
    subject_id: agent.id,
    subject_pub_key: agent.public_key,
    scope,
    constraints,
    issued_at: now,
    expires_at: now + 86400,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  await issueDelegation(cert, rootPriv);
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
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
    store,
  };
}

const UNKNOWN_REASON = `unknown_challenge: ${UNKNOWN_CHALLENGE}`;

test("verify with store: replay is rejected", async () => {
  const { bundle, store } = await storeBundle([SCOPE_MEETING_ATTEND]);
  const opts = { required_scope: SCOPE_MEETING_ATTEND, challenge_store: store };

  const first = await verifyBundle(bundle, opts);
  assert.equal(first.valid, true, first.error_reason);

  const replay = await verifyBundle(bundle, opts);
  assert.equal(replay.valid, false);
  assert.equal(replay.identity_status, "invalid");
  assert.equal(replay.error_reason, UNKNOWN_REASON);
});

test("verify with store: bad signature does not consume", async () => {
  const { bundle, store } = await storeBundle([SCOPE_MEETING_ATTEND]);
  const opts = { required_scope: SCOPE_MEETING_ATTEND, challenge_store: store };

  const forgedSig = bundle.challenge_sig.ed25519.slice();
  forgedSig[0]! ^= 0xff;
  const forged: ProofBundle = {
    ...bundle,
    challenge_sig: { ...bundle.challenge_sig, ed25519: forgedSig },
  };
  const res = await verifyBundle(forged, opts);
  assert.equal(res.valid, false);
  assert.match(res.error_reason ?? "", /^bad_challenge_sig/);

  // The legitimate presentation still succeeds afterwards.
  const legit = await verifyBundle(bundle, opts);
  assert.equal(legit.valid, true, legit.error_reason);
});

test("verify with store: scope-denied still consumes", async () => {
  const { bundle, store } = await storeBundle([SCOPE_MEETING_ATTEND]);
  const denied = await verifyBundle(bundle, {
    required_scope: SCOPE_FILES_WRITE,
    challenge_store: store,
  });
  assert.equal(denied.valid, false);
  assert.equal(denied.identity_status, "scope_denied");

  // Retrying with the correct scope fails: the challenge is spent.
  const retry = await verifyBundle(bundle, {
    required_scope: SCOPE_MEETING_ATTEND,
    challenge_store: store,
  });
  assert.equal(retry.error_reason, UNKNOWN_REASON);
});

test("verify with store: constraint-denied still consumes", async () => {
  const { bundle, store } = await storeBundle(
    [SCOPE_TRANSACT_PURCHASE],
    [{ type: "max_amount", max_amount: 100, currency: "USD" }],
  );
  const denied = await verifyBundle(bundle, {
    required_scope: SCOPE_TRANSACT_PURCHASE,
    challenge_store: store,
    context: { requested_amount: 500, requested_currency: "USD" },
  });
  assert.equal(denied.valid, false);
  assert.equal(denied.identity_status, "constraint_denied");

  // Constraint denial happened AFTER consumption: the challenge is spent.
  const retry = await verifyBundle(bundle, {
    required_scope: SCOPE_TRANSACT_PURCHASE,
    challenge_store: store,
    context: { requested_amount: 50, requested_currency: "USD" },
  });
  assert.equal(retry.error_reason, UNKNOWN_REASON);
});

test("verify with store: unknown challenge rejected before crypto", async () => {
  const { bundle, store } = await storeBundle([SCOPE_MEETING_ATTEND]);
  const otherStore = new MemoryChallengeStore(16);
  const res = await verifyBundle(bundle, { challenge_store: otherStore });
  assert.equal(res.error_reason, UNKNOWN_REASON);
  // The bundle's own store still holds the unconsumed record.
  assert.equal(await store.validate(bundle.challenge, undefined, NOW()), null);
});
