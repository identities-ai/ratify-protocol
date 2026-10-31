// SDK-owned private key lifetime (SPEC-v2 §9.3: zero key material after each
// signing operation where the runtime allows). Every typed key-pair signer
// copies the private key into an internal signer; these tests observe those
// copies through an internal hook and require them to be all zeros once the
// call settles, on success and on refusal. They also require a disposed
// status publisher to zero its retained key and refuse to sign.

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { keyIDV2, type HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeKeyRotationStatementV2, signKeyRotationStatementV2 } from "../../src/key_rotation_v2.js";
import { decodeDelegationCertV2, signDelegationCertV2, verifyDelegationCertV2Signature, type DelegationCertV2 } from "../../src/protocol_v2_wire.js";
import { configureStatusKeyEpochV2, recordSecurityKeyRoleV2 } from "../../src/security_journal_v2.js";
import { setLocalSignerBuffersObserverForTestingV2 } from "../../src/signer_v2.js";
import { newV2StatusPublisherWithKey } from "../../src/status_publisher_v2.js";
import { JournalStoreTestOnly } from "../../src/v2reference/journal.js";
import { type Any, corpusKeyPairs, load } from "./helpers.js";

const allZero = (b: Uint8Array) => b.length > 0 && b.every((x) => x === 0);

/** Records the private-key buffers of every local signer the SDK creates. */
function observeSignerBuffers(): Uint8Array[][] {
  const seen: Uint8Array[][] = [];
  setLocalSignerBuffersObserverForTestingV2((buffers) => seen.push([...buffers]));
  return seen;
}

afterEach(() => setLocalSignerBuffersObserverForTestingV2(null));

async function delegationFixture(): Promise<{ cert: DelegationCertV2; issuer: HybridKeyPairV2 }> {
  const objects = load("objects.json").objects as Any[];
  const obj = objects.find((o) => o.kind === "delegation_certificate")!;
  const cert = decodeDelegationCertV2(new Uint8Array(Buffer.from(obj.wire_b64, "base64")));
  const keys = await corpusKeyPairs();
  const issuer = [...keys.values()].find((k) => keyIDV2(k.publicKey) === cert.issuer_id)!;
  assert.ok(issuer, "fixture issuer key");
  return { cert, issuer };
}

test("typed key-pair signing zeroes the SDK's private key copies after a successful call", async () => {
  const { cert, issuer } = await delegationFixture();
  const before = [Uint8Array.from(issuer.privateKey.ed25519), Uint8Array.from(issuer.privateKey.ml_dsa_65)];
  const seen = observeSignerBuffers();
  const signed = await signDelegationCertV2(cert, issuer);
  await verifyDelegationCertV2Signature(signed);
  assert.equal(seen.length, 1, "exactly one SDK-owned signer");
  for (const buf of seen[0]!) assert.ok(allZero(buf), "an SDK-owned private key copy survived signing");
  // Only SDK-owned copies are wiped; the caller's key pair is left alone.
  assert.deepEqual([issuer.privateKey.ed25519, issuer.privateKey.ml_dsa_65], before);
});

test("typed key-pair signing zeroes the SDK's private key copies when signing is refused", async () => {
  const { cert, issuer } = await delegationFixture();
  const seen = observeSignerBuffers();
  // The issuer ID no longer matches the key, so the signer is created and
  // then the call is refused before a signature exists.
  const bad = { ...cert, issuer_id: "0".repeat(64) };
  await assert.rejects(signDelegationCertV2(bad, issuer));
  assert.equal(seen.length, 1, "the refusal happened after the signer was created");
  for (const buf of seen[0]!) assert.ok(allZero(buf), "an SDK-owned private key copy survived a refused call");
});

test("key rotation signing zeroes both SDK-owned key copies, and the old one when the new key is invalid", async () => {
  const objects = load("objects.json").objects as Any[];
  const obj = objects.find((o) => o.kind === "key_rotation_statement")!;
  const stmt = decodeKeyRotationStatementV2(new Uint8Array(Buffer.from(obj.wire_b64, "base64")));
  const keys = [...(await corpusKeyPairs()).values()];
  const oldKey = keys.find((k) => keyIDV2(k.publicKey) === stmt.old_key_id)!;
  const newKey = keys.find((k) => keyIDV2(k.publicKey) === stmt.new_key_id)!;
  assert.ok(oldKey && newKey, "fixture rotation keys");

  let seen = observeSignerBuffers();
  await signKeyRotationStatementV2(stmt, oldKey, newKey);
  assert.equal(seen.length, 2, "one SDK-owned signer per key");
  for (const buf of seen.flat()) assert.ok(allZero(buf), "a rotation key copy survived signing");

  seen = observeSignerBuffers();
  const brokenNew: HybridKeyPairV2 = { publicKey: newKey.publicKey, privateKey: { ed25519: newKey.privateKey.ed25519, ml_dsa_65: new Uint8Array(4032) } };
  await assert.rejects(signKeyRotationStatementV2(stmt, oldKey, brokenNew));
  assert.equal(seen.length, 1, "only the old signer was created");
  for (const buf of seen[0]!) assert.ok(allZero(buf), "the old key copy survived a refused rotation");
});

async function publisherFixture(): Promise<{ journal: JournalStoreTestOnly; issuerKey: Any; status: HybridKeyPairV2; lifetime: number; at: number }> {
  const f = load("status-publisher.json");
  const sc = (f.scenarios as Any[]).find((s) => s.publisher !== "refused" && s.status_configured_for && s.steps?.[0]?.op === "genesis")!;
  assert.ok(sc, "an accepted publisher scenario with a genesis step");
  const keys = await corpusKeyPairs();
  const journal = new JournalStoreTestOnly();
  for (const rk of sc.role_keys ?? []) await recordSecurityKeyRoleV2(journal, rk.role, keys.get(rk.key)!.publicKey);
  const status = keys.get(sc.status_key)!;
  await configureStatusKeyEpochV2(journal, keyIDV2(keys.get(sc.status_configured_for)!.publicKey), 1, status.publicKey);
  return { journal, issuerKey: keys.get(sc.issuer)!.publicKey, status, lifetime: sc.lifetime_seconds, at: sc.steps[0].at };
}

test("a disposed status publisher zeroes its retained key and refuses to sign", async () => {
  const fx = await publisherFixture();
  const seen = observeSignerBuffers();
  const publisher = await newV2StatusPublisherWithKey(fx.journal, fx.issuerKey, fx.status, fx.lifetime);
  assert.equal(seen.length, 1);
  // The publisher keeps its copy live for its lifetime, so it can sign.
  assert.ok(!seen[0]!.some(allZero), "a live publisher must hold its key");
  const g = await publisher.genesis(fx.at);
  assert.equal(publisher.disposed, false);
  publisher.dispose();
  assert.equal(publisher.disposed, true);
  for (const buf of seen[0]!) assert.ok(allZero(buf), "dispose() left the status key copy in memory");
  for (const op of [() => publisher.genesis(fx.at + 1), () => publisher.heartbeat(g.state, fx.at + 1), () => publisher.revoke(g.state, ["c"], fx.at + 1)]) {
    await assert.rejects(op(), (err) => v2ErrorClassOf(err) === "configuration_invalid");
  }
  publisher.dispose(); // idempotent
});

test("Symbol.dispose retires the status publisher like dispose()", async () => {
  const fx = await publisherFixture();
  const seen = observeSignerBuffers();
  const publisher = await newV2StatusPublisherWithKey(fx.journal, fx.issuerKey, fx.status, fx.lifetime);
  publisher[Symbol.dispose]();
  for (const buf of seen[0]!) assert.ok(allZero(buf));
  await assert.rejects(publisher.genesis(fx.at), (err) => v2ErrorClassOf(err) === "configuration_invalid");
});

test("a refused in-process status publisher zeroes its key copy before returning", async () => {
  const fx = await publisherFixture();
  const seen = observeSignerBuffers();
  // An empty journal is not the authenticated role configuration.
  await assert.rejects(newV2StatusPublisherWithKey(new JournalStoreTestOnly(), fx.issuerKey, fx.status, fx.lifetime),
    (err) => v2ErrorClassOf(err) === "configuration_invalid");
  assert.equal(seen.length, 1);
  for (const buf of seen[0]!) assert.ok(allZero(buf));
});
