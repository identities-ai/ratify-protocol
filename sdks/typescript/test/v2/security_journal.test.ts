// testvectors/v2/security-journal.json: SecurityJournalV2 snapshot known
// answers, transitions, alpha migration, and import negatives (SPEC-v2 §6.6),
// plus property, concurrency, and issuer-isolation tests for the journal.

import { test } from "node:test";
import assert from "node:assert/strict";
import { sha384 } from "@noble/hashes/sha2";
import fc from "fast-check";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeRevocationListV2, signRevocationListV2 } from "../../src/protocol_v2_wire.js";
import {
  ErrSecurityJournalConflictV2,
  applyRevocationListToJournalV2,
  applyRevocationPushToJournalV2,
  configureStatusKeyEpochV2,
  emptySecurityJournalV2,
  recordSecurityKeyRoleV2,
  registerKeyRoleV2,
  revocationStatusFromJournalV2,
  type SecurityJournalV2,
} from "../../src/security_journal_v2.js";
import {
  decodeLegacySecurityJournalV1,
  exportSecurityJournalSnapshotV2,
  importSecurityJournalSnapshotV2,
  legacySecurityJournalDigestInputV1,
  legacySecurityJournalDigestV1,
  migrateSecurityJournalV2,
  sameSecurityJournalContentV2,
  securityJournalSnapshotDigestV2,
} from "../../src/security_journal_snapshot_v2.js";
import { JournalStoreTestOnly } from "../../src/v2reference/journal.js";
import { decodeRevocationPushV2 } from "../../src/protocol_v2_wire.js";
import { type Any, corpusKeyPairs, eqBytes, load, pubOf, toHex, unb64 } from "./helpers.js";

const f = load("security-journal.json");
const policyOf = (p: Any) => ({ maxListLifetimeSeconds: p.max_list_lifetime_seconds, maxStatusAgeSeconds: p.max_status_age_seconds, clockSkewSeconds: p.clock_skew_seconds });

test("security-journal.json: genesis snapshot and digest", () => {
  const genesis = emptySecurityJournalV2();
  const snapshot = exportSecurityJournalSnapshotV2(genesis);
  assert.equal(new TextDecoder().decode(snapshot), f.genesis_snapshot);
  assert.equal(genesis.digest, f.genesis_digest);
  assert.equal(securityJournalSnapshotDigestV2(snapshot), f.genesis_digest);
});

for (const sc of f.scenarios as Any[]) {
  test(`security-journal.json: scenario ${sc.name}`, async () => {
    const store = new JournalStoreTestOnly();
    for (const [i, step] of (sc.steps as Any[]).entries()) {
      const before = store.head();
      const key = pubOf(step.key.public_key);
      let stepErr: unknown = null;
      try {
        switch (step.op) {
          case "record_key_role":
            await recordSecurityKeyRoleV2(store, step.role, key);
            break;
          case "configure_status_key_epoch":
            await configureStatusKeyEpochV2(store, step.issuer_id, step.epoch, key);
            break;
          case "apply_revocation_list":
            await applyRevocationListToJournalV2(store, decodeRevocationListV2(unb64(step.wire_b64)), step.issuer_id, step.epoch, key, policyOf(step.policy), step.now);
            break;
          case "apply_revocation_push":
            await applyRevocationPushToJournalV2(store, decodeRevocationPushV2(unb64(step.wire_b64)), step.issuer_id, step.epoch, key, policyOf(step.policy), step.now);
            break;
          default:
            assert.fail(`unknown op ${step.op}`);
        }
      } catch (err) {
        stepErr = err;
      }
      assert.equal(stepErr !== null, step.expect_rejected === true, `step ${i} ${step.op}: error ${stepErr}`);
      const head = store.head();
      const changed = head.generation !== before.generation || head.digest !== before.digest;
      assert.equal(changed, step.expect_changed, `step ${i} ${step.op}: changed`);
      assert.deepEqual(head, step.expect_head, `step ${i} ${step.op}: head`);
      const { journal } = await store.load();
      const got = exportSecurityJournalSnapshotV2(journal);
      const want = unb64(step.expect_snapshot_b64);
      assert.ok(eqBytes(got, want), `step ${i} ${step.op}: snapshot\n got ${new TextDecoder().decode(got)}\nwant ${new TextDecoder().decode(want)}`);
      assert.equal(securityJournalSnapshotDigestV2(got), head.digest);
    }
  });
}

test("security-journal.json: alpha version 1 migration", () => {
  const m = f.migration;
  const input = unb64(m.legacy_digest_input_b64);
  assert.equal(toHex(sha384(input)), m.legacy_digest, "legacy digest is SHA-384 of its input");
  const legacy = decodeLegacySecurityJournalV1(unb64(m.legacy_record_b64));
  assert.ok(eqBytes(legacySecurityJournalDigestInputV1(legacy), input), "reproduced legacy digest input");
  assert.equal(legacySecurityJournalDigestV1(legacy), m.legacy_digest);
  const migrated = migrateSecurityJournalV2(legacy);
  const snapshot = exportSecurityJournalSnapshotV2(migrated);
  assert.equal(migrated.generation, m.expect_head.generation);
  assert.equal(migrated.digest, m.expect_head.digest);
  assert.equal(migrated.previousDigest, m.expect_previous_digest);
  assert.ok(eqBytes(snapshot, unb64(m.expect_snapshot_b64)));
  assert.ok(sameSecurityJournalContentV2(legacy, migrated));
  assert.throws(() => migrateSecurityJournalV2(migrated), "a version 2 record is not migrated again");
  const tampered = decodeLegacySecurityJournalV1(unb64(m.tampered_legacy_record_b64));
  assert.throws(() => migrateSecurityJournalV2(tampered), "a tampered legacy record is refused");
});

for (const n of f.import_negatives as Any[]) {
  test(`security-journal.json: import negative ${n.name}`, () => {
    let cls = "";
    try {
      importSecurityJournalSnapshotV2(unb64(n.snapshot_b64), n.head);
    } catch (err) {
      cls = v2ErrorClassOf(err);
    }
    assert.equal(cls, n.expect_error_class);
  });
}

test("security journal: export/import round trip and refusals", async () => {
  const keys = await corpusKeyPairs();
  const status = keys.get("status_root")!;
  const store = new JournalStoreTestOnly();
  const issuerID = "d".repeat(64);
  await configureStatusKeyEpochV2(store, issuerID, 1, status.publicKey);
  const list = await signRevocationListV2({ version: 2, issuer_id: issuerID, updated_at: 99, next_update: 120, sequence: 1, revoked: [{ cert_id: "known" }], signature: { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) } }, issuerID, status.publicKey, status);
  const journal = await applyRevocationListToJournalV2(store, list, issuerID, 1, status.publicKey, { maxListLifetimeSeconds: 100, maxStatusAgeSeconds: 50, clockSkewSeconds: 0 }, 100);
  const snapshot = exportSecurityJournalSnapshotV2(journal);
  const head = { generation: journal.generation, digest: journal.digest };
  assert.ok(eqBytes(exportSecurityJournalSnapshotV2(importSecurityJournalSnapshotV2(snapshot, head)), snapshot));
  assert.throws(() => importSecurityJournalSnapshotV2(snapshot, { generation: head.generation + 1, digest: head.digest }));
  const spaced = new Uint8Array([0x20, ...snapshot]);
  assert.throws(() => importSecurityJournalSnapshotV2(spaced, { generation: head.generation, digest: securityJournalSnapshotDigestV2(spaced) }));
});

test("security journal: legacy record built in memory migrates and a tampered one does not", async () => {
  const keys = await corpusKeyPairs();
  const legacy: SecurityJournalV2 = { version: 1, generation: 0, previousDigest: "", digest: "", statusByIssuer: new Map(), keyRoleHistory: [], statusKeyHistory: [] };
  registerKeyRoleV2(legacy, "verifier", keys.get("verifier")!.publicKey);
  legacy.generation = 1;
  legacy.previousDigest = "a".repeat(96);
  legacy.digest = legacySecurityJournalDigestV1(legacy);
  const migrated = migrateSecurityJournalV2(legacy);
  assert.equal(migrated.version, 2);
  assert.equal(migrated.generation, 2);
  assert.equal(migrated.previousDigest, legacy.digest);
  assert.throws(() => migrateSecurityJournalV2({ ...legacy, generation: 5 }));
});

test("security journal: import never crashes and fails closed as malformed (property)", () => {
  const genesis = exportSecurityJournalSnapshotV2(emptySecurityJournalV2());
  const text = new TextDecoder().decode(genesis);
  fc.assert(fc.property(
    fc.oneof(
      fc.uint8Array({ maxLength: 512 }),
      fc.string({ maxLength: 300 }).map((s) => new TextEncoder().encode(s)),
      fc.tuple(fc.nat(text.length), fc.string({ maxLength: 8 })).map(([i, s]) => new TextEncoder().encode(text.slice(0, i) + s + text.slice(i))),
    ),
    (data) => {
      try {
        const journal = importSecurityJournalSnapshotV2(data, { generation: 0, digest: securityJournalSnapshotDigestV2(data) });
        assert.ok(eqBytes(exportSecurityJournalSnapshotV2(journal), data), "an accepted snapshot re-exports byte for byte");
      } catch (err) {
        assert.ok(["malformed", "log_state_mismatch"].includes(v2ErrorClassOf(err)), `class ${v2ErrorClassOf(err)}`);
      }
    },
  ), { numRuns: 400 });
});

test("security journal: concurrent compare-and-swap admits exactly one writer per head", async () => {
  const keys = await corpusKeyPairs();
  const store = new JournalStoreTestOnly();
  const names = ["root", "intermediate", "agent", "verifier", "witness"].filter((n) => keys.has(n));
  const results = await Promise.allSettled(names.map((n) => recordSecurityKeyRoleV2(store, "other", keys.get(n)!.publicKey)));
  const ok = results.filter((r) => r.status === "fulfilled").length;
  const conflicts = results.filter((r) => r.status === "rejected" && (r.reason === ErrSecurityJournalConflictV2 || String(r.reason).includes("compare-and-swap conflict"))).length;
  assert.ok(ok >= 1, "at least one writer commits");
  assert.equal(ok + conflicts, names.length, "every other writer sees a conflict, never a lost update");
  const { journal } = await store.load();
  assert.equal(journal.generation, ok, "one generation per committed writer");
  assert.equal(journal.keyRoleHistory.length, ok);
});

test("security journal: the same cert_id under two issuers keeps isolated status", async () => {
  const keys = await corpusKeyPairs();
  const statusA = keys.get("status_root")!;
  const statusB = keys.get("status_intermediate")!;
  const issuerA = "a".repeat(64);
  const issuerB = "b".repeat(64);
  const store = new JournalStoreTestOnly();
  await configureStatusKeyEpochV2(store, issuerA, 1, statusA.publicKey);
  await configureStatusKeyEpochV2(store, issuerB, 1, statusB.publicKey);
  const policy = { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 0 };
  const placeholder = { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) };
  const listA = await signRevocationListV2({ version: 2, issuer_id: issuerA, updated_at: 1000, next_update: 2000, sequence: 1, revoked: [{ cert_id: "shared" }], signature: placeholder }, issuerA, statusA.publicKey, statusA);
  const listB = await signRevocationListV2({ version: 2, issuer_id: issuerB, updated_at: 1000, next_update: 2000, sequence: 1, revoked: [], signature: placeholder }, issuerB, statusB.publicKey, statusB);
  await applyRevocationListToJournalV2(store, listA, issuerA, 1, statusA.publicKey, policy, 1001);
  await applyRevocationListToJournalV2(store, listB, issuerB, 1, statusB.publicKey, policy, 1001);
  const a = await revocationStatusFromJournalV2(store, issuerA, "shared", 1, statusA.publicKey, policy, 1002);
  const b = await revocationStatusFromJournalV2(store, issuerB, "shared", 1, statusB.publicKey, policy, 1002);
  assert.equal(a.status, "revoked");
  assert.equal(b.status, "not_revoked");
  await assert.rejects(applyRevocationListToJournalV2(store, listA, issuerB, 1, statusB.publicKey, policy, 1003), "issuer A's list cannot apply under issuer B");
  assert.equal((await revocationStatusFromJournalV2(store, issuerB, "shared", 1, statusB.publicKey, policy, 1003)).status, "not_revoked");
});
