// testvectors/v2/hedged-signatures.json: hedged ML-DSA-65 variants of the
// objects.json statements must verify, keep identical projections and body
// digests, and an accepted body re-signed with new bytes is a replay.

import { test } from "node:test";
import assert from "node:assert/strict";

import { decodeKeyRotationStatementV2, keyRotationStatementV2Digest } from "../../src/key_rotation_v2.js";
import { decodeVerificationReceiptV2, verificationReceiptV2Digest, verifyVerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { decodeWitnessEntryV2, verifyWitnessEntryV2, witnessEntryV2Digest } from "../../src/witness_v2.js";
import { corpusKeyPairs, eqBytes, load, unb64, type Any } from "./helpers.js";
import { pubByName, projection, receiptHead, reencode, verifyObject, witnessHead, type KeyMap } from "./object_procedures.js";

const file = load("hedged-signatures.json");

async function checkHedgedIdempotency(keys: KeyMap, kind: string, vc: Any, deterministic: Uint8Array, hedged: Uint8Array): Promise<void> {
  switch (kind) {
    case "witness_entry": {
      const first = decodeWitnessEntryV2(deterministic);
      const again = decodeWitnessEntryV2(hedged);
      const digest = witnessEntryV2Digest(first);
      assert.ok(eqBytes(digest, witnessEntryV2Digest(again)), "hedged witness entry has a different body digest");
      const head = witnessHead(vc.head);
      head.sequence = first.sequence;
      head.headHash = digest;
      head.acceptedDigests = new Map([[first.sequence, digest]]);
      assert.equal(await verifyWitnessEntryV2(again, head, pubByName(keys, vc.witness_key)), "replay");
      return;
    }
    case "verification_receipt": {
      const first = decodeVerificationReceiptV2(deterministic);
      const again = decodeVerificationReceiptV2(hedged);
      const digest = verificationReceiptV2Digest(first);
      assert.ok(eqBytes(digest, verificationReceiptV2Digest(again)), "hedged receipt has a different body digest");
      const head = receiptHead(vc.head);
      head.sequence = first.sequence;
      head.headHash = digest;
      head.acceptedDigests = new Map([[first.sequence, digest]]);
      assert.equal(await verifyVerificationReceiptV2(again, pubByName(keys, vc.verifier_key), head), "replay");
      return;
    }
    case "key_rotation_statement": {
      const a = keyRotationStatementV2Digest(decodeKeyRotationStatementV2(deterministic));
      const b = keyRotationStatementV2Digest(decodeKeyRotationStatementV2(hedged));
      assert.ok(eqBytes(a, b), "hedged rotation statement has a different body digest");
    }
  }
}

test("hedged-signatures.json: every hedged variant", async (t) => {
  const keys = await corpusKeyPairs();
  const kinds = new Set<string>();
  assert.equal(file.objects.length, 10);
  for (const o of file.objects as Any[]) {
    kinds.add(o.kind);
    await t.test(o.name, async () => {
      const deterministic = unb64(o.deterministic_wire_b64);
      assert.ok(o.hedged_wire_b64.length >= 2 && o.resigned_fields.length > 0, "need two hedged variants and a re-signed field");
      const seen: Uint8Array[] = [deterministic];
      for (let i = 0; i < o.hedged_wire_b64.length; i++) {
        const wire = unb64(o.hedged_wire_b64[i]);
        for (const prior of seen) assert.ok(!eqBytes(prior, wire), `variant ${i} repeats an earlier signature`);
        seen.push(wire);
        assert.ok(eqBytes(await reencode(o.kind, wire), wire), `variant ${i} does not re-encode identically`);
        await verifyObject(keys, o.kind, wire, null, o.verify);
        for (const field of o.resigned_fields) {
          assert.ok(eqBytes(await projection(wire, field), await projection(deterministic, field)), `variant ${i}: ${field} projection differs`);
        }
        await checkHedgedIdempotency(keys, o.kind, o.verify, deterministic, wire);
      }
    });
  }
  for (const kind of ["delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement", "witness_entry", "transaction_receipt", "verification_receipt"]) {
    assert.ok(kinds.has(kind), `hedged-signatures.json has no ${kind}`);
  }
});
