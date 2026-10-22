// The cross-SDK verification procedure of testvectors/v2/README.md
// "cross-sdk/": key derivation, required coverage, the objects.json positive
// procedure for every object (hedged signatures are verified, never compared
// with anything but the wire object), and the verifier and release scenarios.

import assert from "node:assert/strict";

import { deriveID } from "../../src/crypto.js";
import { deriveKeyIDV2, type HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { isRegisteredConstraintTypeV2 } from "../../src/constraints_v2.js";
import { decodeDelegationCertV2 } from "../../src/protocol_v2_wire.js";
import { releaseV2Decision } from "../../src/release_v2.js";
import { TZDB_VERSION_V2 } from "../../src/tzdb_v2.js";
import { decodeVerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import { type Any, b64, deriveKeys, unb64 } from "./helpers.js";
import { checkPositiveObject } from "./object_procedures.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";

export const CROSS_SDK_KEY_NAMES = [
  "root", "intermediate", "agent", "verifier", "status_root", "status_intermediate",
  "witness", "party_b_root", "party_b_agent", "rotation_genesis", "rotation_second",
];

export const CROSS_SDK_KINDS = [
  "delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement",
  "witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding",
];

const TOP_LEVEL = ["version", "description", "sdk", "sdk_version", "generator", "kind_object_type_codes", "keys", "objects"];
const SCENARIO_MEMBERS = ["scenario_configuration", "scenarios"];

/** The scenarios every cross-SDK fixture contains (SPEC-v2 §8.1). */
export const CROSS_SCENARIO_NAMES = ["allow_released", "deny_revoked_released", "indeterminate_status_unavailable_released", "allow_withheld_past_horizon"];

/** The fixed scenario_configuration of every cross-SDK fixture. */
export const CROSS_SCENARIO_CONFIGURATION = {
  verifier_namespace: "verify-test", replay_epoch: 3, verifier_key: "verifier", receipt_log_id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
  lease_seconds: 30, max_challenge_age_seconds: 300, future_skew_seconds: 5,
  status_policy: { max_list_lifetime_seconds: 7200, max_status_age_seconds: 3660, clock_skew_seconds: 5 }, tzdb_version: TZDB_VERSION_V2,
};

const pubJSON = (k: HybridKeyPairV2) => ({ ed25519: b64(k.publicKey.ed25519), ml_dsa_65: b64(k.publicKey.ml_dsa_65) });

/**
 * Runs one scenario through this SDK's live verifier, reference store and
 * release gate: verify at verify_time, publish at publish_time, and release
 * at release_time with releaseReceipt (the receipt just published when
 * null). Returns the observed expectation in the fixture schema.
 */
export async function replayCrossScenario(cfg: Any, sc: Any, keys: Map<string, HybridKeyPairV2>, releaseReceipt: Uint8Array | null): Promise<Any> {
  const key = (name: string) => {
    const k = keys.get(name);
    assert.ok(k, `key ${name} is not in the fixture`);
    return k;
  };
  const statusKeys: Record<string, Any> = {};
  for (const [issuer, k] of Object.entries<Any>(sc.status_keys)) statusKeys[issuer] = { epoch: k.epoch, public_key: pubJSON(key(k.key)) };
  const statusEvidence: Record<string, Any> = {};
  for (const [issuer, objects] of Object.entries<Any>(sc.status_evidence)) statusEvidence[issuer] = { mode: "ok", objects };
  const inputs = {
    required_scope: sc.required_scope, expected_challenge: sc.expected_challenge, context_policy: sc.context_policy,
    configured_namespace: cfg.verifier_namespace, configured_replay_epoch: cfg.replay_epoch, now: sc.verify_time,
    max_challenge_age_seconds: cfg.max_challenge_age_seconds, future_skew_seconds: cfg.future_skew_seconds, tzdb_version: cfg.tzdb_version,
    receiver_binding_hook: "absent", status_keys: statusKeys, status_policy: cfg.status_policy, journal: { mode: "anchored" },
    audience_mode: "ok", rate: "absent", trust: { mode: "ok", outcome: "trusted", root_public_key: pubJSON(key(sc.trust_root_key)) },
    status_evidence: statusEvidence,
  };
  const verifier = key(cfg.verifier_key);
  const store = new StoreTestOnly(sc.verify_time, cfg.lease_seconds, cfg.receipt_log_id, verifier);
  const { req, cb } = await buildVerifyRequest(inputs, unb64(sc.bundle_b64), zeroCounts());
  const outcome = await verifyProofBundleV2(req, { ...cb, claimStore: store });
  assert.equal(outcome.stage, "committed", `stage (${outcome.errorClass}: ${outcome.error?.message})`);
  const c = outcome.committed!;
  store.setTime(sc.publish_time);
  const published = await store.publishV2Receipt(c.claimID(), c.receiptBody());
  store.setTime(sc.release_time);
  const result = await releaseV2Decision(c, releaseReceipt ?? published, {
    verifierPublicKey: verifier.publicKey, logID: cfg.receipt_log_id, claimStore: store, checkpoint: store,
  });
  return {
    receipt_body_b64: b64(c.receiptBody()), allow_horizon: c.allowHorizon(), signed_receipt_b64: b64(published),
    release: {
      status: result.status, reason: result.reason === "" ? null : result.reason,
      decision: result.decision ? result.decision.decision() : null, release_time: result.decision ? result.decision.releaseTime() : null,
    },
  };
}

/**
 * Replays every scenario of a fixture, releasing with the producer's signed
 * receipt, and requires the same receipt outbox body, allow horizon and
 * release result. Returns the number of scenarios.
 */
export async function verifyCrossScenarios(f: Any): Promise<number> {
  const keys = await deriveKeys(f.keys);
  assert.deepEqual(f.scenario_configuration, CROSS_SCENARIO_CONFIGURATION, "scenario_configuration differs from the fixed values");
  const seen = new Set<string>();
  for (const sc of f.scenarios) {
    seen.add(sc.name);
    try {
      const got = await replayCrossScenario(f.scenario_configuration, sc, keys, unb64(sc.expected.signed_receipt_b64));
      assert.equal(got.receipt_body_b64, sc.expected.receipt_body_b64, "receipt outbox body");
      assert.equal(got.allow_horizon, sc.expected.allow_horizon, "allow horizon");
      assert.deepEqual(got.release, sc.expected.release, "release result");
    } catch (err) {
      throw new Error(`${f.sdk}.json scenario ${sc.name}: ${(err as Error).message}`, { cause: err });
    }
  }
  for (const name of CROSS_SCENARIO_NAMES) assert.ok(seen.has(name), `${f.sdk}.json: missing scenario ${name}`);
  return f.scenarios.length;
}

/** True when a fixture carries the verifier and release scenarios. */
export const hasCrossScenarios = (f: Any): boolean => f.scenario_configuration !== undefined || f.scenarios !== undefined;

/** Verifies one parsed cross-SDK fixture; sdk must equal the file name. Returns the number of objects. */
export async function verifyCrossSDKFixture(f: Any, sdk: string): Promise<number> {
  const members = hasCrossScenarios(f) ? [...TOP_LEVEL, ...SCENARIO_MEMBERS] : TOP_LEVEL;
  assert.deepEqual(Object.keys(f).sort(), [...members].sort(), "top-level members");
  assert.equal(f.version, 2);
  assert.equal(f.sdk, sdk, "sdk must equal the file name");
  assert.ok(typeof f.sdk_version === "string" && f.sdk_version !== "" && typeof f.generator === "string" && f.generator !== "");
  const names = new Set<string>();
  for (const k of f.keys) {
    assert.ok(!names.has(k.name), `duplicate key ${k.name}`);
    names.add(k.name);
  }
  for (const name of CROSS_SDK_KEY_NAMES) assert.ok(names.has(name), `missing key ${name}`);
  const keys = await deriveKeys(f.keys);
  for (const k of f.keys) {
    const pub = keys.get(k.name)!.publicKey;
    assert.equal(b64(pub.ed25519), k.public_key.ed25519, `${k.name}: seeds do not derive the Ed25519 key`);
    assert.equal(b64(pub.ml_dsa_65), k.public_key.ml_dsa_65, `${k.name}: seeds do not derive the ML-DSA-65 key`);
    assert.equal(deriveKeyIDV2(pub), k.key_id_v2, `${k.name}: key_id_v2`);
    assert.equal(deriveID(pub), k.v1_key_id_128, `${k.name}: v1_key_id_128`);
  }
  const kinds = new Set<string>();
  const codes = new Set<number>();
  let everyConstraint = false;
  let evaluators = false;
  for (const o of f.objects) {
    kinds.add(o.kind);
    try {
      for (const code of await checkPositiveObject(keys, o, { deterministic: false })) codes.add(code);
    } catch (err) {
      throw new Error(`${sdk}.json ${o.name}: ${(err as Error).message}`, { cause: err });
    }
    if (o.kind === "delegation_certificate") {
      const types = new Set((decodeDelegationCertV2(unb64(o.wire_b64)).constraints ?? []).map((c) => c.type));
      const extension = [...types].some((t) => !isRegisteredConstraintTypeV2(t));
      everyConstraint ||= extension && ["max_rate", "ratify.receiver_audience", "resource_path", "time_window", "max_amount"].every((t) => types.has(t));
    }
    if (o.kind === "verification_receipt") {
      evaluators ||= (decodeVerificationReceiptV2(unb64(o.wire_b64)).constraint_evaluators ?? []).length > 0;
    }
  }
  for (const kind of CROSS_SDK_KINDS) assert.ok(kinds.has(kind), `no ${kind} object`);
  for (let code = 1; code <= 9; code++) assert.ok(codes.has(code), `no signature for object_type_code ${code}`);
  assert.ok(everyConstraint, "no delegation certificate with every registered constraint type and an extension type");
  assert.ok(evaluators, "no verification receipt with constraint_evaluators");
  return f.objects.length;
}

export type { Any };
