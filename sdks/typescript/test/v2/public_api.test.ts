// Public v2 API invariants (SPEC-v2 §1.3, §3.2, §6.9): no export signs
// caller-selected bytes, codes or contexts; the committed outcome exposes no
// decision; the released decision cannot be forged or mutated through its
// accessors.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as v2 from "../../src/v2.js";
import * as root from "../../src/index.js";
import { CommittedV2Outcome, V2ReleasedDecision, releaseV2Decision } from "../../src/release_v2.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import { corpusKeyPairs, load } from "./helpers.js";

const clock = (now: number) => ({ authoritativeTimeV2: async () => now });

test("public API: no raw statement signer is exported", () => {
  for (const surface of [v2, root] as Record<string, unknown>[]) {
    for (const name of Object.keys(surface)) {
      assert.ok(!/^signV2Statement/i.test(name), `raw signer exported: ${name}`);
      assert.ok(!/WithKeyPair$/.test(name), `raw signer exported: ${name}`);
    }
    for (const forbidden of ["signV2Statement", "signV2StatementWithSigner", "signV2StatementWithKeyPair", "runV2StatusStage", "resolveClaimProofBundleV2AfterStatus", "aggregateCertificateStatusV2"]) {
      assert.equal(forbidden in surface, false, `${forbidden} must not be exported`);
    }
  }
  assert.equal(typeof v2.keyIDV2, "function", "key_id_v2 is exported");
  assert.equal(typeof v2.verifyProofBundleV2, "function");
  assert.equal(typeof v2.releaseV2Decision, "function");
});

test("released decision: a forged instance is never actionable", async () => {
  const forged = Object.create(V2ReleasedDecision.prototype) as V2ReleasedDecision;
  assert.equal(await forged.allowed(clock(1800000000)), false);
  assert.equal(forged.decision(), "");
  assert.equal(forged.allowHorizon(), null);
  const parsed = Object.assign(Object.create(V2ReleasedDecision.prototype), JSON.parse('{"decision":"allow","allowHorizon":9999999999}')) as V2ReleasedDecision;
  assert.equal(await parsed.allowed(clock(1800000000)), false);
  assert.throws(() => forged.receipt());
});

test("committed outcome: exposes no decision and a forged one is rejected by release", async () => {
  const keys = await corpusKeyPairs();
  const committedKeys = Object.getOwnPropertyNames(CommittedV2Outcome.prototype).sort();
  assert.deepEqual(committedKeys, ["allowHorizon", "challengeExpiresAt", "claimID", "constructor", "receiptBody", "receiptBodyDigest"].sort());
  const forged = Object.create(CommittedV2Outcome.prototype) as CommittedV2Outcome;
  const store = new StoreTestOnly(1800000000, 60, "0123456789abcdef0123456789abcdef", keys.get("verifier")!);
  const result = await releaseV2Decision(forged, null, { verifierPublicKey: keys.get("verifier")!.publicKey, logID: "0123456789abcdef0123456789abcdef", claimStore: store, checkpoint: store });
  assert.deepEqual([result.status, result.reason, result.decision], ["rejected", "release_state_mismatch", null]);
});

test("package: ./v2 subpath and the 2.0.0-alpha.1 line", () => {
  const pkg = JSON.parse(JSON.stringify(load("../../sdks/typescript/package.json")));
  assert.equal(pkg.version, "2.0.0-alpha.1");
  assert.equal(pkg.exports["./v2"].import, "./dist/v2.js");
  assert.equal(pkg.exports["./v2/reference"].import, "./dist/v2reference.js");
});
