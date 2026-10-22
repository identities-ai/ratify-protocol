// testvectors/v2/keys.json: deterministic fixture keys, full 256-bit v2 key
// IDs, the v1 128-bit ID of the same key, and invalid v2 key IDs that MUST be
// rejected wherever a v2 key ID is required (SPEC-v2 §2.3, §8.1).

import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "@noble/hashes/sha2";

import { deriveID } from "../../src/crypto.js";
import { deriveKeyIDV2 } from "../../src/crypto_v2.js";
import { canonicalJSONV2, gAny, parseJSONV2 } from "../../src/json_v2.js";
import { decodeProofBundleV2, validV2ID } from "../../src/protocol_v2_wire.js";
import { keyIDV2 } from "../../src/signer_v2.js";
import { decodeWitnessEntryV2 } from "../../src/witness_v2.js";
import { classOf, corpusKeyPairs, eqBytes, load, pubOf, toHex, unb64, type Any } from "./helpers.js";

const f = load("keys.json");
const objects = load("objects.json");

function setTopLevelString(wire: Uint8Array, field: string, value: string): Uint8Array {
  const obj = gAny(parseJSONV2(wire)) as Record<string, unknown>;
  obj[field] = value;
  return canonicalJSONV2(obj);
}

test("keys.json: seeds derive the pinned keys and key IDs", async () => {
  const pairs = await corpusKeyPairs();
  assert.equal(f.keys.length, 18);
  for (const k of f.keys as Any[]) {
    const p = pairs.get(k.name)!;
    assert.ok(eqBytes(p.publicKey.ed25519, unb64(k.public_key.ed25519)), `${k.name} Ed25519`);
    assert.ok(eqBytes(p.publicKey.ml_dsa_65, unb64(k.public_key.ml_dsa_65)), `${k.name} ML-DSA-65`);
    const independent = toHex(sha256(new Uint8Array([...new TextEncoder().encode("ratify-key-id-v2\0"), ...p.publicKey.ed25519, ...p.publicKey.ml_dsa_65])));
    assert.equal(independent, k.key_id_v2, `${k.name} independent key ID`);
    assert.equal(keyIDV2(pubOf(k.public_key)), k.key_id_v2, `${k.name} keyIDV2`);
    assert.equal(deriveKeyIDV2(pubOf(k.public_key)), k.key_id_v2);
    assert.equal(k.key_id_v2.length, 64);
    const v1 = deriveID(pubOf(k.public_key));
    assert.equal(v1, k.v1_key_id_128, `${k.name} v1 ID`);
    assert.notEqual(v1, k.key_id_v2.slice(0, 32), `${k.name}: v1 ID aliases the v2 prefix`);
    assert.equal(validV2ID(v1), false);
  }
});

test("keys.json: keyIDV2 rejects incomplete keys as malformed", async () => {
  const p = (await corpusKeyPairs()).get("root")!.publicKey;
  assert.equal(classOf(() => keyIDV2({ ed25519: p.ed25519.subarray(1), ml_dsa_65: p.ml_dsa_65 })), "malformed");
  assert.equal(classOf(() => keyIDV2({ ed25519: p.ed25519, ml_dsa_65: p.ml_dsa_65.subarray(1) })), "malformed");
});

test("keys.json: invalid v2 key IDs are rejected where a v2 key ID is required", () => {
  const bundleWire = unb64(objects.objects.find((o: Any) => o.kind === "proof_bundle").wire_b64);
  const witnessWire = unb64(objects.objects.find((o: Any) => o.kind === "witness_entry").wire_b64);
  assert.equal(f.invalid_v2_key_ids.length, 6);
  for (const bad of f.invalid_v2_key_ids as Any[]) {
    assert.equal(validV2ID(bad.value), false, bad.name);
    assert.equal(classOf(() => decodeProofBundleV2(setTopLevelString(bundleWire, "verifier_id", bad.value))), bad.expected_error_class, `${bad.name} as verifier_id`);
    assert.equal(classOf(() => decodeProofBundleV2(setTopLevelString(bundleWire, "agent_id", bad.value))), bad.expected_error_class, `${bad.name} as agent_id`);
    assert.equal(classOf(() => decodeWitnessEntryV2(setTopLevelString(witnessWire, "witness_id", bad.value))), bad.expected_error_class, `${bad.name} as witness_id`);
  }
});
