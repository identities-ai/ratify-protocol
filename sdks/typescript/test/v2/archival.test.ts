// Archival verification (SPEC-v2 §6.10): signature-only results for every
// stored object, always freshness_unverified and never actionable.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  encodeArchivalProofBundleResultV2,
  verifyArchivalDelegationCertV2,
  verifyArchivalKeyRotationStatementV2,
  verifyArchivalProofBundleV2,
  verifyArchivalRevocationListV2,
  verifyArchivalRevocationPushV2,
  verifyArchivalTransactionReceiptV2,
  verifyArchivalVerificationReceiptV2,
  verifyArchivalWitnessEntryV2,
} from "../../src/archival_v2.js";
import { deriveKeyIDV2 } from "../../src/crypto_v2.js";
import { classOfAsync, corpusKeyPairs, load, unb64, type Any } from "./helpers.js";

const objects = load("objects.json");
const negatives = load("object-negatives.json");
const obj = (name: string): Any => objects.objects.find((o: Any) => o.name === name);
const digestOf = (o: Any, name: string) => o.digests[name];

test("archival: every object kind verifies with its digest and signers", async () => {
  const keys = await corpusKeyPairs();
  const id = (name: string) => deriveKeyIDV2(keys.get(name)!.publicKey);

  const cert = await verifyArchivalDelegationCertV2(unb64(obj("delegation_root_to_intermediate").wire_b64));
  assert.deepEqual(cert, { object_type_code: 1, freshness: "freshness_unverified", actionable: false, digest: "", signer_key_ids: [id("root")] });

  const listObj = obj("revocation_list");
  const list = await verifyArchivalRevocationListV2(unb64(listObj.wire_b64), listObj.verify.bound_issuer_id, keys.get("status_root")!.publicKey);
  assert.deepEqual(list, { object_type_code: 3, freshness: "freshness_unverified", actionable: false, digest: digestOf(listObj, "status_evidence_digest"), signer_key_ids: [id("status_root")] });

  const pushObj = obj("revocation_push");
  const push = await verifyArchivalRevocationPushV2(unb64(pushObj.wire_b64), pushObj.verify.bound_issuer_id, keys.get("status_root")!.publicKey);
  assert.equal(push.digest, digestOf(pushObj, "status_evidence_digest"));
  assert.equal(push.object_type_code, 5);

  const rot = await verifyArchivalKeyRotationStatementV2(unb64(obj("key_rotation_genesis").wire_b64));
  assert.equal(rot.digest, "sha384:" + digestOf(obj("key_rotation_genesis"), "statement_body_digest_hex"));
  assert.deepEqual(rot.signer_key_ids, [id("rotation_genesis"), id("rotation_second")]);

  const wit = await verifyArchivalWitnessEntryV2(unb64(obj("witness_entry_genesis").wire_b64), keys.get("witness")!.publicKey);
  assert.equal(wit.digest, "sha384:" + digestOf(obj("witness_entry_genesis"), "statement_body_digest_hex"));
  assert.deepEqual(wit.signer_key_ids, [id("witness")]);

  const rec = await verifyArchivalVerificationReceiptV2(unb64(obj("verification_receipt_allow_genesis").wire_b64), keys.get("verifier")!.publicKey);
  assert.equal(rec.digest, "sha384:" + digestOf(obj("verification_receipt_allow_genesis"), "statement_body_digest_hex"));
  assert.equal(rec.object_type_code, 8);

  const tx = await verifyArchivalTransactionReceiptV2(unb64(obj("transaction_receipt_two_parties").wire_b64));
  assert.deepEqual(tx, { object_type_code: 7, freshness: "freshness_unverified", actionable: false, digest: "", signer_key_ids: [id("agent"), id("party_b_agent")] });
  for (const r of [cert, list, push, rot, wit, rec, tx]) assert.ok(!("decision" in r), "archival results carry no decision");
});

test("archival: wrong caller keys fail with their class", async () => {
  const keys = await corpusKeyPairs();
  assert.equal(await classOfAsync(() => verifyArchivalWitnessEntryV2(unb64(obj("witness_entry_genesis").wire_b64), keys.get("verifier")!.publicKey)), "key_id_mismatch");
  assert.equal(await classOfAsync(() => verifyArchivalVerificationReceiptV2(unb64(obj("verification_receipt_allow_genesis").wire_b64), keys.get("witness")!.publicKey)), "key_id_mismatch");
  const listObj = obj("revocation_list");
  assert.equal(await classOfAsync(() => verifyArchivalRevocationListV2(unb64(listObj.wire_b64), listObj.verify.bound_issuer_id, keys.get("root")!.publicKey)), "invalid_signature");
  assert.equal(await classOfAsync(() => verifyArchivalRevocationListV2(unb64(listObj.wire_b64), "0".repeat(64), keys.get("status_root")!.publicKey)), "status_key_binding_mismatch");
});

test("archival: proof bundle result and every proof-bundle negative class", async () => {
  const okObj = obj("proof_bundle_two_link_bound_context");
  const ok = await verifyArchivalProofBundleV2(unb64(okObj.wire_b64));
  assert.equal(ok.error_class, null);
  assert.equal(ok.bundle_hash, digestOf(okObj, "bundle_hash_v2"));
  assert.equal(ok.actionable, false);
  assert.equal(ok.issuer_ids.length, 2);
  const json = JSON.parse(new TextDecoder().decode(encodeArchivalProofBundleResultV2(ok)));
  assert.deepEqual(Object.keys(json), ["actionable", "agent_id", "assessment", "bundle_hash", "error_class", "issuer_ids"]);
  assert.equal(json.error_class, null);
  assert.equal(json.assessment, "freshness_unverified");
  let n = 0;
  for (const v of negatives.vectors as Any[]) {
    if (v.kind !== "proof_bundle") continue;
    n++;
    const r = await verifyArchivalProofBundleV2(unb64(v.wire_b64));
    assert.equal(r.error_class, v.expected_error_class, v.name);
    assert.equal(r.actionable, false);
  }
  assert.ok(n > 0);
});

// testvectors/v2/archival.json: the exact result (or error class) for every
// signed object kind (Go TestV2ConformanceArchival).
const archival = load("archival.json");
const ARCHIVAL_KINDS = ["proof_bundle", "delegation_certificate", "revocation_list", "revocation_push", "key_rotation_statement", "witness_entry", "verification_receipt", "transaction_receipt"];

test("archival.json: corpus shape", () => {
  assert.equal(archival.cases.length, 19);
  assert.deepEqual([...new Set((archival.cases as Any[]).map((c) => c.kind))].sort(), [...ARCHIVAL_KINDS].sort());
});

for (const c of archival.cases as Any[]) {
  test(`archival.json: ${c.name}`, async () => {
    const keys = await corpusKeyPairs();
    const pub = (name: string) => keys.get(name)!.publicKey;
    const wire = unb64(c.wire_b64);
    const run = async (): Promise<unknown> => {
      switch (c.kind) {
        case "proof_bundle": return verifyArchivalProofBundleV2(wire);
        case "delegation_certificate": return verifyArchivalDelegationCertV2(wire);
        case "revocation_list": return verifyArchivalRevocationListV2(wire, c.verify.issuer_id, pub(c.verify.status_key));
        case "revocation_push": return verifyArchivalRevocationPushV2(wire, c.verify.issuer_id, pub(c.verify.status_key));
        case "key_rotation_statement": return verifyArchivalKeyRotationStatementV2(wire);
        case "witness_entry": return verifyArchivalWitnessEntryV2(wire, pub(c.verify.witness_key));
        case "verification_receipt": return verifyArchivalVerificationReceiptV2(wire, pub(c.verify.verifier_key));
        case "transaction_receipt": return verifyArchivalTransactionReceiptV2(wire);
        default: throw new Error(`unknown kind ${c.kind}`);
      }
    };
    if (c.expected_error_class) {
      assert.equal(await classOfAsync(run), c.expected_error_class);
      return;
    }
    assert.deepEqual(JSON.parse(JSON.stringify(await run())), c.expected);
  });
}
