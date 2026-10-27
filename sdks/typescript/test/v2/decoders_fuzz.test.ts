// Property tests for every v2 decoder (SPEC-v2 §8.1 item 2). Arbitrary
// bytes, arbitrary JSON, and mutated valid encodings must either decode or
// fail with a closed §2.7 class (never unclassified), within a time bound;
// inputs past a byte limit fail at the size gate before parsing. The
// SecurityJournalV2 snapshot importer has its own property at the end.

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { decodeV2CheckpointAcknowledgement, encodeV2CheckpointAcknowledgement, MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2 } from "../../src/checkpoint_ack_v2.js";
import { V2_ERROR_CLASSES, v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeKeyRotationStatementV2 } from "../../src/key_rotation_v2.js";
import * as limits from "../../src/limits_v2.js";
import { decodeDelegationCertV2, decodeProofBundleV2, decodeRevocationListV2, decodeRevocationPushV2 } from "../../src/protocol_v2_wire.js";
import { decodeTransactionReceiptV2 } from "../../src/transaction_receipt_v2.js";
import { decodeVerificationReceiptBodyV2, decodeVerificationReceiptV2, verificationReceiptV2Body } from "../../src/verification_receipt_v2.js";
import { decodeWitnessEntryV2 } from "../../src/witness_v2.js";
import { exportSecurityJournalSnapshotV2, importSecurityJournalSnapshotV2, MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES, securityJournalSnapshotDigestV2 } from "../../src/security_journal_snapshot_v2.js";
import { load, unb64, type Any } from "./helpers.js";

type Decoder = (b: Uint8Array) => unknown;

const objects = load("objects.json");
const wireOf = (kind: string): Uint8Array => unb64(objects.objects.find((o: Any) => o.kind === kind).wire_b64);
const receiptWire = wireOf("verification_receipt");

const ackSample = encodeV2CheckpointAcknowledgement({ logID: "c".repeat(32), sequence: 7, entryHash: new Uint8Array(48).fill(9), timestamp: 1800000000 });

async function batchDecoder(): Promise<Decoder> {
  const mod = (await import("../../src/status_batch_v2.js")) as Any;
  assert.equal(typeof mod.decodeV2StatusEvidenceBatch, "function");
  return mod.decodeV2StatusEvidenceBatch;
}

interface Target {
  name: string;
  decode: Decoder;
  limit: number;
  sample: Uint8Array;
  /** Classes a mutated encoding may produce; the pure decoders allow only these. */
  allowed: ReadonlySet<string>;
  runs: number;
}

const STRUCTURAL = new Set(["malformed", "key_id_mismatch"]);
const ANY_CLASS = new Set<string>(V2_ERROR_CLASSES);

async function targets(): Promise<Target[]> {
  const listWire = wireOf("revocation_list");
  return [
    { name: "delegation certificate", decode: decodeDelegationCertV2, limit: limits.MAX_DELEGATION_CERT_BYTES_V2, sample: wireOf("delegation_certificate"), allowed: STRUCTURAL, runs: 150 },
    { name: "proof bundle", decode: decodeProofBundleV2, limit: limits.MAX_PROOF_BUNDLE_BYTES_V2, sample: wireOf("proof_bundle"), allowed: STRUCTURAL, runs: 100 },
    { name: "revocation list", decode: decodeRevocationListV2, limit: limits.MAX_REVOCATION_LIST_BYTES_V2, sample: listWire, allowed: STRUCTURAL, runs: 200 },
    { name: "revocation push", decode: decodeRevocationPushV2, limit: limits.MAX_REVOCATION_PUSH_BYTES_V2, sample: wireOf("revocation_push"), allowed: STRUCTURAL, runs: 200 },
    { name: "key rotation statement", decode: decodeKeyRotationStatementV2, limit: limits.MAX_KEY_ROTATION_STATEMENT_BYTES_V2, sample: wireOf("key_rotation_statement"), allowed: STRUCTURAL, runs: 150 },
    { name: "witness entry", decode: decodeWitnessEntryV2, limit: limits.MAX_WITNESS_ENTRY_BYTES_V2, sample: wireOf("witness_entry"), allowed: STRUCTURAL, runs: 200 },
    { name: "verification receipt", decode: decodeVerificationReceiptV2, limit: limits.MAX_VERIFICATION_RECEIPT_BYTES_V2, sample: receiptWire, allowed: STRUCTURAL, runs: 200 },
    { name: "verification receipt body", decode: decodeVerificationReceiptBodyV2, limit: limits.MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2,
      sample: verificationReceiptV2Body(decodeVerificationReceiptV2(receiptWire)), allowed: STRUCTURAL, runs: 200 },
    // Transaction receipt decode verifies embedded bundles and party
    // signatures, so a mutation may surface any closed class.
    { name: "transaction receipt", decode: decodeTransactionReceiptV2, limit: limits.MAX_TRANSACTION_RECEIPT_BYTES_V2, sample: wireOf("transaction_receipt"), allowed: ANY_CLASS, runs: 25 },
    { name: "checkpoint acknowledgement", decode: decodeV2CheckpointAcknowledgement, limit: MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2, sample: ackSample, allowed: new Set(["malformed"]), runs: 300 },
    { name: "status evidence batch", decode: await batchDecoder(), limit: limits.MAX_STATUS_EVIDENCE_BATCH_BYTES_V2,
      sample: new TextEncoder().encode(`[{"object":${new TextDecoder().decode(listWire)},"object_type_code":3}]`), allowed: STRUCTURAL, runs: 100 },
  ];
}

/** Decodes and returns "" on success or the class; fails on unclassified, non-Error throws, or slowness. */
async function outcome(t: Target, data: Uint8Array): Promise<string> {
  const start = performance.now();
  let cls = "";
  try {
    await t.decode(data);
  } catch (err) {
    assert.ok(err instanceof Error, `${t.name}: threw a non-Error`);
    cls = v2ErrorClassOf(err);
    assert.ok(cls !== "" && cls !== "unclassified", `${t.name}: unclassified failure: ${err.message}`);
    assert.ok(ANY_CLASS.has(cls), `${t.name}: class ${cls} is outside the closed list`);
  }
  assert.ok(performance.now() - start < 5000, `${t.name}: decode took too long`);
  return cls;
}

const mutation = (len: number) =>
  fc.oneof(
    fc.record({ op: fc.constant("flip" as const), at: fc.nat(len - 1), bit: fc.nat(7) }),
    fc.record({ op: fc.constant("set" as const), at: fc.nat(len - 1), byte: fc.constantFrom(0x22, 0x5c, 0x2c, 0x7b, 0x7d, 0x5b, 0x5d, 0x30, 0x2d, 0x2e, 0x65, 0x20, 0x00, 0xff, 0xc3) }),
    fc.record({ op: fc.constant("insert" as const), at: fc.nat(len), bytes: fc.uint8Array({ minLength: 1, maxLength: 8 }) }),
    fc.record({ op: fc.constant("delete" as const), at: fc.nat(len - 1), count: fc.integer({ min: 1, max: 16 }) }),
    fc.record({ op: fc.constant("truncate" as const), at: fc.nat(len) }),
  );

function applyMutations(sample: Uint8Array, ms: Any[]): Uint8Array {
  let out = Uint8Array.from(sample);
  for (const m of ms) {
    const at = Math.min(m.at, Math.max(out.length - 1, 0));
    switch (m.op) {
      case "flip": if (out.length) out[at] = out[at]! ^ (1 << m.bit); break;
      case "set": if (out.length) out[at] = m.byte; break;
      case "insert": out = Uint8Array.from([...out.subarray(0, m.at), ...m.bytes, ...out.subarray(m.at)]); break;
      case "delete": out = Uint8Array.from([...out.subarray(0, at), ...out.subarray(at + m.count)]); break;
      case "truncate": out = out.subarray(0, m.at); break;
    }
  }
  return out;
}

test("decoders: arbitrary bytes and arbitrary JSON fail closed with a v2 class", async (t) => {
  for (const target of await targets()) {
    await t.test(target.name, async () => {
      await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 512 }), async (data) => {
        await outcome(target, data);
      }), { numRuns: 300 });
      await fc.assert(fc.asyncProperty(fc.jsonValue({ maxDepth: 6 }), async (value) => {
        await outcome(target, new TextEncoder().encode(JSON.stringify(value)));
      }), { numRuns: 300 });
      // The deep-nesting and huge-number shapes are rejected, never parsed into memory.
      const deep = "[".repeat(10000) + "]".repeat(10000);
      assert.equal(await outcome(target, new TextEncoder().encode(deep)), "malformed");
      assert.equal(await outcome(target, new TextEncoder().encode(`{"version":${"9".repeat(400)}}`)), "malformed");
    });
  }
});

test("decoders: mutated valid encodings fail closed or still decode", async (t) => {
  for (const target of await targets()) {
    await t.test(target.name, async () => {
      assert.equal(await outcome(target, target.sample), "", `${target.name}: the sample must decode`);
      await fc.assert(fc.asyncProperty(fc.array(mutation(target.sample.length), { minLength: 1, maxLength: 3 }), async (ms) => {
        const cls = await outcome(target, applyMutations(target.sample, ms));
        if (cls !== "") assert.ok(target.allowed.has(cls), `${target.name}: unexpected class ${cls}`);
      }), { numRuns: target.runs });
    });
  }
});

test("decoders: an input one byte past its limit fails at the size gate before parsing", async (t) => {
  for (const target of await targets()) {
    await t.test(target.name, async () => {
      // Not JSON at all: only the size gate can reject it quickly and with its message.
      const over = new Uint8Array(target.limit + 1).fill(0x7b);
      let message = "";
      try {
        await target.decode(over);
      } catch (err) {
        message = (err as Error).message;
        assert.equal(v2ErrorClassOf(err), "malformed");
      }
      assert.match(message, /rejected before parsing/);
    });
  }
});

test("checkpoint acknowledgement: canonical round trip and strictness", () => {
  fc.assert(fc.property(
    fc.hexaString({ minLength: 32, maxLength: 32 }).map((s) => s.toLowerCase()),
    fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER }),
    fc.uint8Array({ minLength: 48, maxLength: 48 }),
    fc.integer({ min: 0, max: 253402300799 }),
    (logID, sequence, entryHash, timestamp) => {
      const ack = { logID, sequence, entryHash, timestamp };
      const wire = encodeV2CheckpointAcknowledgement(ack);
      assert.ok(wire.length <= MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2);
      const back = decodeV2CheckpointAcknowledgement(wire);
      assert.deepEqual({ ...back, entryHash: [...back.entryHash] }, { ...ack, entryHash: [...entryHash] });
      // A whitespace variant of the same value is not the canonical encoding.
      const spaced = new TextEncoder().encode(" " + new TextDecoder().decode(wire));
      assert.throws(() => decodeV2CheckpointAcknowledgement(spaced), (e: unknown) => v2ErrorClassOf(e) === "malformed");
    },
  ), { numRuns: 200 });
  const bad = [
    { logID: "C".repeat(32), sequence: 1, entryHash: new Uint8Array(48), timestamp: 0 },
    { logID: "c".repeat(32), sequence: 0, entryHash: new Uint8Array(48), timestamp: 0 },
    { logID: "c".repeat(32), sequence: 1, entryHash: new Uint8Array(47), timestamp: 0 },
    { logID: "c".repeat(32), sequence: 1, entryHash: new Uint8Array(48), timestamp: 253402300800 },
    { logID: "c".repeat(32), sequence: 1, entryHash: new Uint8Array(48), timestamp: -1 },
  ];
  for (const ack of bad) assert.throws(() => encodeV2CheckpointAcknowledgement(ack), (e: unknown) => v2ErrorClassOf(e) === "malformed");
  const text = new TextDecoder().decode(ackSample);
  for (const variant of [
    text.replace('"sequence":7', '"sequence":7.0'),
    text.replace('"sequence":7', '"sequence":-0'),
    text.replace('"log_id"', '"Log_id"'),
    text.replace("}", ',"extra":1}'),
    text.replace('"timestamp":1800000000', '"timestamp":"1800000000"'),
  ]) {
    assert.throws(() => decodeV2CheckpointAcknowledgement(new TextEncoder().encode(variant)), (e: unknown) => v2ErrorClassOf(e) === "malformed", variant);
  }
});

// The SecurityJournalV2 snapshot importer (SPEC-v2 §8.1 item 2). The head is
// derived from the input, so most failures reach the decoder itself; an
// import that succeeds must re-export the identical bytes.
test("security journal snapshot: arbitrary and mutated input imports exactly or fails closed", async () => {
  const journal = load("security-journal.json");
  const sample = unb64(journal.scenarios.find((s: Any) => s.name === "status_reducer_transitions").steps[8].expect_snapshot_b64);
  const generation = JSON.parse(new TextDecoder().decode(sample)).generation as number;
  const target: Target = {
    name: "security journal snapshot",
    decode: (b) => {
      // An oversized snapshot is refused on its size before any digest is
      // compared, so the test does not hash it (hashing 64 MiB would make
      // the decode timing measure the test, not the decoder).
      const digest = b.length > MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES ? "" : securityJournalSnapshotDigestV2(b);
      const got = importSecurityJournalSnapshotV2(b, { generation, digest });
      assert.deepEqual(exportSecurityJournalSnapshotV2(got), b, "an imported snapshot must re-export identically");
      return got;
    },
    limit: MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES, sample, allowed: new Set(["malformed", "log_state_mismatch"]), runs: 300,
  };
  assert.equal(await outcome(target, sample), "", "the sample must import");
  await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 512 }), async (data) => {
    const cls = await outcome(target, data);
    if (cls !== "") assert.ok(target.allowed.has(cls), `unexpected class ${cls}`);
  }), { numRuns: 300 });
  await fc.assert(fc.asyncProperty(fc.jsonValue({ maxDepth: 6 }), async (value) => {
    const cls = await outcome(target, new TextEncoder().encode(JSON.stringify(value)));
    if (cls !== "") assert.ok(target.allowed.has(cls), `unexpected class ${cls}`);
  }), { numRuns: 300 });
  await fc.assert(fc.asyncProperty(fc.array(mutation(sample.length), { minLength: 1, maxLength: 3 }), async (ms) => {
    const cls = await outcome(target, applyMutations(sample, ms));
    if (cls !== "") assert.ok(target.allowed.has(cls), `unexpected class ${cls}`);
  }), { numRuns: target.runs });
  assert.equal(await outcome(target, new TextEncoder().encode("[".repeat(10000) + "]".repeat(10000))), "malformed");
  assert.equal(await outcome(target, new Uint8Array(target.limit + 1).fill(0x7b)), "malformed");
});
