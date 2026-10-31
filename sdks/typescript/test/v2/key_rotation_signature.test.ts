// testvectors/v2/key-rotation-signature.json: genesis and continuation
// rotation statements, signable bytes, contexts, deterministic signatures,
// body digests, and wire bytes.

import { test } from "node:test";
import assert from "node:assert/strict";

import { hybridKeypairFromSeeds } from "../../src/crypto.js";
import { V2_OBJECT_TYPE, v2MLDSAContext } from "../../src/crypto_v2.js";
import { base64Encode, hexOf } from "../../src/json_v2.js";
import {
  acceptKeyRotationStatementV2,
  decodeKeyRotationStatementV2,
  encodeKeyRotationStatementV2,
  keyRotationStatementV2Digest,
  keyRotationStatementV2SignBytes,
  newKeyRotationV2Journal,
  signKeyRotationStatementV2,
  type KeyRotationStatementV2,
  type KeyRotationV2Journal,
} from "../../src/key_rotation_v2.js";
import { eqBytes, hex, load, unb64 } from "./helpers.js";

const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);

test("key-rotation-signature.json: genesis and continuation", async () => {
  const f = load("key-rotation-signature.json");
  assert.equal(f.version, 2);
  assert.equal(f.object_type_code, 4);
  assert.ok(f.continuation && f.continuation.sequence === 2, "vector lacks a sequence-2 continuation");
  let journal: KeyRotationV2Journal | null = null;
  let priorDigest: string | null = null;
  for (const v of [f, f.continuation]) {
    const oldPair = await hybridKeypairFromSeeds(hex(v.old_key_seeds.ed25519), hex(v.old_key_seeds.ml_dsa_65));
    const newPair = await hybridKeypairFromSeeds(hex(v.new_key_seeds.ed25519), hex(v.new_key_seeds.ml_dsa_65));
    assert.ok(eqBytes(oldPair.publicKey.ml_dsa_65, unb64(v.old_key.ml_dsa_65)) && eqBytes(newPair.publicKey.ed25519, unb64(v.new_key.ed25519)), "seed-derived keys");
    const stmt: KeyRotationStatementV2 = {
      version: v.version, authority_id: v.authority_id, recovery_epoch: v.recovery_epoch, role: v.role, sequence: v.sequence,
      previous_statement_hash: unb64(v.previous_statement_hash), old_key: oldPair.publicKey, new_key: newPair.publicKey,
      old_key_id: v.old_key_id, new_key_id: v.new_key_id, issued_at: v.issued_at, not_before: v.not_before,
      old_signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }, new_signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
    };
    assert.equal(utf8(keyRotationStatementV2SignBytes(stmt)), utf8(unb64(v.signable_bytes)), "signable bytes");
    assert.equal(utf8(v2MLDSAContext(V2_OBJECT_TYPE.keyRotationAuthorization)), v.old_mldsa_context);
    assert.equal(utf8(v2MLDSAContext(V2_OBJECT_TYPE.keyRotationProofOfPossession)), v.new_mldsa_context);
    const signed = await signKeyRotationStatementV2(stmt, oldPair, newPair, { deterministic: true });
    assert.equal(base64Encode(signed.old_signature.ed25519), v.old_signature.ed25519, "old Ed25519 signature");
    assert.equal(base64Encode(signed.old_signature.ml_dsa_65), v.old_signature.ml_dsa_65, "old ML-DSA signature");
    assert.equal(base64Encode(signed.new_signature.ed25519), v.new_signature.ed25519, "new Ed25519 signature");
    assert.equal(base64Encode(signed.new_signature.ml_dsa_65), v.new_signature.ml_dsa_65, "new ML-DSA signature");
    assert.equal(hexOf(keyRotationStatementV2Digest(signed)), v.statement_body_digest, "statement body digest");
    const wire = unb64(v.wire);
    const decoded = decodeKeyRotationStatementV2(wire);
    assert.ok(eqBytes(encodeKeyRotationStatementV2(decoded), wire), "wire is canonical and stable");
    assert.ok(eqBytes(encodeKeyRotationStatementV2(signed), wire), "signed statement encodes to the vector wire");
    if (priorDigest !== null) assert.equal(hexOf(decoded.previous_statement_hash), priorDigest, "continuation links to the genesis digest");
    if (journal === null) journal = newKeyRotationV2Journal(v.authority_id, v.recovery_epoch, v.role, oldPair.publicKey);
    const out = await acceptKeyRotationStatementV2(decoded, journal, Math.max(v.issued_at, v.not_before), 0);
    assert.equal(out.error, undefined, out.error?.message);
    assert.equal(out.result, "appended");
    journal = out.journal;
    priorDigest = v.statement_body_digest;
  }
});
