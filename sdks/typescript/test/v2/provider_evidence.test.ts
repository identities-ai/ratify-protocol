// testvectors/v2/provider-evidence/<platform>-<provider>.json: every device
// evidence record present. Each record's key must issue its certificate,
// prove possession in its rotation, and sign its revocation list, and every
// object must re-encode to its wire bytes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { verifyV2Statement } from "../../src/crypto_v2.js";
import {
  V2_OBJECT_TYPE,
  decodeDelegationCertV2,
  decodeKeyRotationStatementV2,
  decodeRevocationListV2,
  encodeDelegationCertV2,
  encodeKeyRotationStatementV2,
  encodeRevocationListV2,
  keyIDV2,
  keyRotationStatementV2SignBytes,
  verifyDelegationCertV2Signature,
  verifyRevocationListV2Signature,
} from "../../src/v2.js";
import { type Any, VECTOR_DIR, classOfAsync, eqBytes, pubOf, unb64 } from "./helpers.js";

const dir = join(VECTOR_DIR, "provider-evidence");
const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();

test("provider-evidence: the directory holds at least one record", () => {
  assert.ok(files.length > 0, "provider-evidence/ has no records");
});

for (const name of files) {
  test(`provider-evidence: ${name} verifies`, async () => {
    const r: Any = JSON.parse(readFileSync(join(dir, name), "utf8"));
    let checks = 0;
    const check = (ok: boolean, what: string) => {
      assert.ok(ok, `${name}: ${what}`);
      checks++;
    };
    check(name === `${r.platform}-${r.provider}.json`, "file name matches platform and provider");
    check(r.version === 1, "version");
    const key = pubOf(r.public_key);
    const id: string = r.key_id_v2;
    check(keyIDV2(key) === id, "key ID of public_key");
    const keyEq = (k: { ed25519: Uint8Array; ml_dsa_65: Uint8Array }) => eqBytes(k.ed25519, key.ed25519) && eqBytes(k.ml_dsa_65, key.ml_dsa_65);

    const kinds: string[] = [];
    for (const o of r.objects as Any[]) {
      const wire = unb64(o.wire_b64);
      kinds.push(o.kind);
      switch (o.kind) {
        case "delegation_certificate": {
          const c = decodeDelegationCertV2(wire);
          check(eqBytes(encodeDelegationCertV2(c), wire), "certificate re-encodes to its wire");
          check(await classOfAsync(() => verifyDelegationCertV2Signature(c)) === "", "certificate signature");
          check(keyEq(c.issuer_pub_key) && c.issuer_id === id, "certificate issuer is the evidence key");
          const ml = new Uint8Array(c.signature.ml_dsa_65);
          ml[0]! ^= 1;
          const bad = { ...c, signature: { ...c.signature, ml_dsa_65: ml } };
          check(await classOfAsync(() => verifyDelegationCertV2Signature(bad)) === "invalid_signature", "flipped ML-DSA-65 signature byte is refused");
          break;
        }
        case "key_rotation_statement": {
          const s = decodeKeyRotationStatementV2(wire);
          check(eqBytes(encodeKeyRotationStatementV2(s), wire), "rotation re-encodes to its wire");
          check(keyEq(s.new_key), "rotation new key is the evidence key");
          const signable = keyRotationStatementV2SignBytes(s);
          assert.equal(V2_OBJECT_TYPE.keyRotationAuthorization, 0x0004);
          assert.equal(V2_OBJECT_TYPE.keyRotationProofOfPossession, 0x0009);
          check(await classOfAsync(() => verifyV2Statement(V2_OBJECT_TYPE.keyRotationAuthorization, signable, s.old_signature, s.old_key)) === "", "rotation old signature");
          check(await classOfAsync(() => verifyV2Statement(V2_OBJECT_TYPE.keyRotationProofOfPossession, signable, s.new_signature, s.new_key)) === "", "rotation new signature");
          break;
        }
        case "revocation_list": {
          const l = decodeRevocationListV2(wire);
          check(eqBytes(encodeRevocationListV2(l), wire), "revocation list re-encodes to its wire");
          check(await classOfAsync(() => verifyRevocationListV2Signature(l, id, key)) === "", "revocation list signature");
          break;
        }
        default:
          assert.fail(`${name}: unknown kind ${o.kind}`);
      }
    }
    assert.deepEqual(kinds.sort(), ["delegation_certificate", "key_rotation_statement", "revocation_list"], `${name}: object kinds`);
    assert.equal(checks, 13, `${name}: ${checks} checks ran`);
  });
}
