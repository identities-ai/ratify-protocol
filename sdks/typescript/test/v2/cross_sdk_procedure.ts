// The cross-SDK verification procedure of testvectors/v2/README.md
// "cross-sdk/": key derivation, required coverage, and the objects.json
// positive procedure for every object (hedged signatures are verified, never
// compared with anything but the wire object).

import assert from "node:assert/strict";

import { deriveID } from "../../src/crypto.js";
import { deriveKeyIDV2 } from "../../src/crypto_v2.js";
import { isRegisteredConstraintTypeV2 } from "../../src/constraints_v2.js";
import { decodeDelegationCertV2 } from "../../src/protocol_v2_wire.js";
import { decodeVerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { type Any, b64, deriveKeys, unb64 } from "./helpers.js";
import { checkPositiveObject } from "./object_procedures.js";

export const CROSS_SDK_KEY_NAMES = [
  "root", "intermediate", "agent", "verifier", "status_root", "status_intermediate",
  "witness", "party_b_root", "party_b_agent", "rotation_genesis", "rotation_second",
];

export const CROSS_SDK_KINDS = [
  "delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement",
  "witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding",
];

const TOP_LEVEL = ["version", "description", "sdk", "sdk_version", "generator", "kind_object_type_codes", "keys", "objects"];

/** Verifies one parsed cross-SDK fixture; sdk must equal the file name. Returns the number of objects. */
export async function verifyCrossSDKFixture(f: Any, sdk: string): Promise<number> {
  assert.deepEqual(Object.keys(f).sort(), [...TOP_LEVEL].sort(), "top-level members");
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
