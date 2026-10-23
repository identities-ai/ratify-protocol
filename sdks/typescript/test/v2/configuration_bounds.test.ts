// Configuration bounds and wire rules tightened before the beta, mirroring Go
// TestVerifyKeyRotationStatementV2ClockConfigurationBounds,
// TestRevokedCertIDLengthBoundV2,
// TestDecodeTransactionReceiptV2DecodesBundleBeforeHash,
// TestVerifyProofBundleV2ConfigurationRejectedAtStepTwo and
// TestValidateProofBundleV2PreflightReplayEpochBound, plus the classified
// key-ID error of deriveKeyIDV2.

import { test } from "node:test";
import assert from "node:assert/strict";

import { V2_MAX_TIMESTAMP_SECONDS } from "../../src/clock_bounds_v2.js";
import { deriveKeyIDV2 } from "../../src/crypto_v2.js";
import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeKeyRotationStatementV2, verifyKeyRotationStatementV2 } from "../../src/key_rotation_v2.js";
import {
  decodeProofBundleV2,
  decodeRevocationListV2,
  decodeRevocationPushV2,
  encodeRevocationListV2,
  encodeRevocationPushV2,
} from "../../src/protocol_v2_wire.js";
import { decodeTransactionReceiptV2 } from "../../src/transaction_receipt_v2.js";
import { MAX_IDENTIFIER_LENGTH_BYTES } from "../../src/types.js";
import { verifyProofBundleV2, type V2VerifyRequest } from "../../src/verify_v2.js";
import { validateProofBundleV2Preflight } from "../../src/verify_v2_preflight.js";
import { corpusKeyPairs, load, unb64 } from "./helpers.js";
import { rotationState } from "./object_procedures.js";

const objects = load("objects.json");
const obj = (name: string) => objects.objects.find((o: { name: string }) => o.name === name);
const lifecycle = load("lifecycle-scenarios.json");
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const bytes = (s: string) => new TextEncoder().encode(s);

const classOf = async (fn: () => unknown): Promise<string> => {
  try {
    await fn();
    return "";
  } catch (err) {
    return v2ErrorClassOf(err);
  }
};

// SPEC-v2 §2.5: rotation verification applies the configured bounds to the
// caller's clock inputs. A skew of 301 must not admit what 300 rejects.
test("rotation verification: clock configuration bounds", async () => {
  const keys = await corpusKeyPairs();
  const o = obj("key_rotation_genesis");
  const wire = unb64(o.wire_b64);
  const state = () => rotationState(o.verify.rotation_state, keys);
  const stmt = decodeKeyRotationStatementV2(wire);
  const latest = Math.max(stmt.issued_at, stmt.not_before);
  const cases: [number, number, string][] = [
    [latest - 301, 301, "configuration_invalid"],
    [latest - 301, 300, "rotation_future_dated"],
    [o.verify.now, -1, "configuration_invalid"],
    [-1, 5, "configuration_invalid"],
    [V2_MAX_TIMESTAMP_SECONDS + 1, 5, "configuration_invalid"],
    [o.verify.now, 86400, "configuration_invalid"],
    [latest - 1, 0, "rotation_future_dated"],
    [latest, 0, ""],
    [V2_MAX_TIMESTAMP_SECONDS, 0, ""],
  ];
  for (const [now, skew, want] of cases) {
    assert.equal(await classOf(() => verifyKeyRotationStatementV2(decodeKeyRotationStatementV2(wire), state(), now, skew)), want, `now ${now} skew ${skew}`);
  }
});

// SPEC-v2 §2.6: every cert_id, including a revoked reference in a list or a
// push, is at most MAX_IDENTIFIER_LENGTH_BYTES UTF-8 bytes.
test("revocation list and push: revoked cert_id length bound", () => {
  const listWire = text(unb64(obj("revocation_list").wire_b64));
  const pushWire = text(unb64(obj("revocation_push").wire_b64));
  const withID = (wire: string, id: string) => bytes(wire.replace(/"revoked":\[[^\]]*\]/, `"revoked":[{"cert_id":${JSON.stringify(id)}}]`));
  for (const [id, ok] of [
    ["a".repeat(MAX_IDENTIFIER_LENGTH_BYTES), true],
    ["a".repeat(MAX_IDENTIFIER_LENGTH_BYTES + 1), false],
    ["é".repeat(MAX_IDENTIFIER_LENGTH_BYTES / 2), true],
    ["é".repeat(MAX_IDENTIFIER_LENGTH_BYTES / 2) + "a", false],
  ] as const) {
    const list = withID(listWire, id);
    const push = withID(pushWire, id);
    assert.notEqual(text(list), listWire);
    assert.notEqual(text(push), pushWire);
    const results: Record<string, () => unknown> = {
      "decode list": () => decodeRevocationListV2(list),
      "decode push": () => decodeRevocationPushV2(push),
      "encode list": () => encodeRevocationListV2({ ...decodeRevocationListV2(unb64(obj("revocation_list").wire_b64)), revoked: [{ cert_id: id }] }),
      "encode push": () => encodeRevocationPushV2({ ...decodeRevocationPushV2(unb64(obj("revocation_push").wire_b64)), revoked: [{ cert_id: id }] }),
    };
    for (const [name, fn] of Object.entries(results)) {
      let cls = "";
      try {
        fn();
      } catch (err) {
        cls = v2ErrorClassOf(err);
      }
      assert.equal(cls, ok ? "" : "malformed", `${name} with a ${bytes(id).length}-byte cert_id`);
    }
  }
});

// SPEC-v2 §2.1, §5.7: a nested bundle that does not strictly decode, or is
// not canonical, is malformed even though its hash no longer matches.
test("transaction receipt: a nested bundle is decoded before its hash is compared", async () => {
  const wire = text(unb64(obj("transaction_receipt_two_parties").wire_b64));
  const edits: Record<string, (w: string) => string> = {
    "challenge_at as a string": (w) => w.replace(/"challenge_at":(\d+)/, '"challenge_at":"$1"'),
    "whitespace in the bundle": (w) => w.replace('"proof_bundle":{', '"proof_bundle":{ '),
  };
  for (const [name, edit] of Object.entries(edits)) {
    const mutated = edit(wire);
    assert.notEqual(mutated, wire, `${name}: fixture did not change`);
    assert.equal(await classOf(() => decodeTransactionReceiptV2(bytes(mutated))), "malformed", name);
  }
});

// SPEC-v2 §2.5, §6.1 and §6.2 step 2: configuration that is out of bounds or
// internally inconsistent is configuration_invalid before any later pre-claim
// step and before the claim store is consulted.
test("verify: inconsistent skew, replay epoch and session context are rejected at step 2", async () => {
  const request = lifecycle.requests.A;
  const base = (): V2VerifyRequest => ({
    bundle: unb64(lifecycle.bundles_b64[request.bundle]), expected: null, contextPolicy: null, requiredScope: "", verifierNamespace: "ns",
    replayEpoch: 0, now: 1800000000, maxChallengeAgeSeconds: 60, futureSkewSeconds: 5,
    statusPolicy: { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 5 },
  });
  const expectedWith = (session: Uint8Array) => ({
    value: new Uint8Array(32), issuedAt: 0, expiresAt: 1, verifierNamespace: "ns", replayEpoch: 0, verifierID: "", expectedSessionContext: session,
  });
  // Without the fault each request stops later (expected challenge missing),
  // so the class proves where the check runs.
  const cases: Record<string, (r: V2VerifyRequest) => void> = {
    "status skew below future skew": (r) => (r.statusPolicy.clockSkewSeconds = 0),
    "status skew above future skew": (r) => (r.futureSkewSeconds = 0),
    "replay epoch above 2^53-1": (r) => (r.replayEpoch = 2 ** 53),
    "replay epoch negative": (r) => (r.replayEpoch = -1),
    "31-byte expected session context without a policy": (r) => (r.expected = expectedWith(new Uint8Array(31))),
    "empty expected session context without a policy": (r) => (r.expected = expectedWith(new Uint8Array(0))),
  };
  let claims = 0;
  const claimStore = new Proxy({}, { get: () => () => { claims++; throw new Error("claim store consulted"); } });
  const untouched = await verifyProofBundleV2(base(), { claimStore: claimStore as never });
  assert.deepEqual([untouched.stage, untouched.errorClass, claims], ["preflight", "expected_challenge_unavailable", 0]);
  for (const [name, edit] of Object.entries(cases)) {
    const req = base();
    edit(req);
    const outcome = await verifyProofBundleV2(req, { claimStore: claimStore as never });
    assert.deepEqual([outcome.stage, outcome.errorClass, claims], ["preflight", "configuration_invalid", 0], name);
  }
});

// The standalone preflight applies the same §6.2 step 2 bound on the
// configured replay epoch, so a caller that runs preflight itself sees
// configuration_invalid, not stale_replay_epoch.
test("preflight: configured replay epoch bound", async () => {
  const bundle = decodeProofBundleV2(unb64(lifecycle.bundles_b64[lifecycle.requests.A.bundle]));
  for (const epoch of [-1, 2 ** 53]) {
    const expected = { value: new Uint8Array(32), issuedAt: 0, expiresAt: 1, verifierNamespace: "ns", replayEpoch: epoch, verifierID: "" };
    assert.equal(await classOf(() => validateProofBundleV2Preflight(bundle, expected, "data:read", "ns", epoch, 1800000000, 60, 5)),
      "configuration_invalid", `epoch ${epoch}`);
  }
});

// SPEC-v2 §2.7: every public v2 API error is classified. A key with a wrong
// component length is malformed.
test("deriveKeyIDV2: a bad key length is a classified malformed error", async () => {
  const key = (await corpusKeyPairs()).get("agent")!.publicKey;
  for (const bad of [
    { ed25519: key.ed25519.subarray(0, 31), ml_dsa_65: key.ml_dsa_65 },
    { ed25519: key.ed25519, ml_dsa_65: key.ml_dsa_65.subarray(0, 1951) },
    null,
  ]) {
    assert.equal(await classOf(() => deriveKeyIDV2(bad as never)), "malformed");
  }
});
