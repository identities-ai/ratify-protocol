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
  // The prototype is frozen, so Object.assign cannot even shadow an accessor;
  // defining own properties directly still yields nothing actionable.
  assert.throws(() => Object.assign(Object.create(V2ReleasedDecision.prototype), JSON.parse('{"decision":"allow","allowHorizon":9999999999}')), TypeError);
  const parsed = Object.create(V2ReleasedDecision.prototype, Object.getOwnPropertyDescriptors(JSON.parse('{"decision":"allow","allowHorizon":9999999999}'))) as V2ReleasedDecision;
  assert.equal(await parsed.allowed(clock(1800000000)), false);
  assert.throws(() => forged.receipt());
});

test("public API: no local signer is exported", () => {
  // A local SignerV2 would sign any well-formed message under any context
  // its holder chose (SPEC-v2 §3.2). In-process keys sign only through the
  // typed key-pair functions.
  for (const surface of [v2, root] as Record<string, unknown>[]) {
    for (const name of Object.keys(surface)) {
      assert.ok(!/LocalSigner/i.test(name), `local signer exported: ${name}`);
    }
  }
  assert.equal(typeof v2.newV2StatusPublisherWithKey, "function");
});

test("released decision: package consumers cannot construct an actionable instance", async () => {
  const now = clock(1800000000);
  for (const surface of [v2, root] as unknown as { V2ReleasedDecision: typeof V2ReleasedDecision }[]) {
    const Cls = surface.V2ReleasedDecision as unknown as Record<string, unknown> & (new (...args: unknown[]) => V2ReleasedDecision);
    assert.equal(Cls, V2ReleasedDecision);
    // The former public static factory and any other static entry are gone.
    assert.equal(Cls.release, undefined);
    assert.equal(Cls.create, undefined);
    assert.deepEqual(Object.getOwnPropertyNames(Cls).filter((n) => !["length", "name", "prototype"].includes(n)), []);
    // The constructor throws without the module-private token, with any argument.
    for (const arg of [undefined, null, {}, Symbol("v2 released decision"), Symbol.for("v2 released decision")]) {
      assert.throws(() => new Cls(arg), TypeError);
      assert.throws(() => Reflect.construct(Cls, [arg]), TypeError);
    }
    // Subclassing still runs the throwing constructor.
    assert.throws(() => new (class extends (Cls as new (...a: unknown[]) => object) {})(), TypeError);
    // The class and its prototype are frozen: no accessor can be replaced.
    assert.ok(Object.isFrozen(Cls) && Object.isFrozen(Cls.prototype));
    assert.throws(() => { (Cls.prototype as Record<string, unknown>).allowed = async () => true; }, TypeError);
    assert.throws(() => { Cls.release = () => ({}); }, TypeError);
    // Objects that only look like a released decision are never actionable.
    const fields = { claimID: "c", decision: "allow", receiptWire: new Uint8Array([1]), allowHorizon: 9999999999, challengeExpiresAt: 9999999999 };
    const bare = Object.create(Cls.prototype) as V2ReleasedDecision;
    assert.equal(await bare.allowed(now), false);
    assert.equal(bare.decision(), "");
    assert.equal(bare.allowHorizon(), null);
    assert.throws(() => bare.receipt());
    const forged = [
      bare,
      Object.create(Cls.prototype, Object.getOwnPropertyDescriptors(fields)),
      Object.setPrototypeOf({ ...fields }, Cls.prototype),
      Object.setPrototypeOf(structuredClone(fields), Cls.prototype),
    ] as V2ReleasedDecision[];
    for (const f of forged) assert.equal(await f.allowed(now), false);
    // Calling an accessor with a forged receiver does not help either.
    assert.equal(await V2ReleasedDecision.prototype.allowed.call(fields as unknown as V2ReleasedDecision, now), false);
  }
});

test("committed outcome: package consumers cannot construct one", () => {
  const Cls = v2.CommittedV2Outcome as unknown as Record<string, unknown> & (new (...args: unknown[]) => CommittedV2Outcome);
  assert.equal(Cls.create, undefined);
  assert.throws(() => new Cls(), TypeError);
  assert.throws(() => new Cls(Symbol("v2 committed outcome")), TypeError);
  assert.ok(Object.isFrozen(Cls) && Object.isFrozen(Cls.prototype));
  assert.equal("newCommittedV2Outcome" in v2, false);
  assert.equal("newCommittedV2Outcome" in root, false);
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

test("package: ./v2 subpath and the v2 release line", () => {
  const pkg = JSON.parse(JSON.stringify(load("../../sdks/typescript/package.json")));
  // Any 2.x version: scripts/release.sh bumps package.json, so pinning one
  // exact prerelease here would fail the release gate on every bump.
  assert.match(pkg.version, /^2\.\d+\.\d+(-(alpha|beta|rc)\.\d+)?$/);
  assert.equal(pkg.exports["./v2"].import, "./dist/v2.js");
  assert.equal(pkg.exports["./v2/reference"].import, "./dist/v2reference.js");
});
