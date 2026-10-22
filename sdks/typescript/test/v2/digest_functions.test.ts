// testvectors/v2/digest-functions.json: StatementBodyDigest and
// StatusEvidenceDigest over explicit object type codes (SPEC-v2 §4; Go
// TestV2ConformanceDigestFunctions), plus the strictness of the revocation
// list and push signable bodies (Go TestStatementBodyDigestV2RevocationBodies).

import { test } from "node:test";
import assert from "node:assert/strict";
import { sha384 } from "@noble/hashes/sha2";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { canonicalJSONV2, hexOf } from "../../src/json_v2.js";
import { statementBodyDigestV2 } from "../../src/key_rotation_v2.js";
import { decodeRevocationListV2, revocationListV2SignBytes, revocationPushV2SignBytes, statusEvidenceDigestV2 } from "../../src/protocol_v2_wire.js";
import { type Any, eqBytes, load, unb64 } from "./helpers.js";

const file = load("digest-functions.json");
const noSig = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) };

test("digest-functions.json: corpus shape", () => {
  assert.equal(file.cases.length, 16);
});

for (const c of file.cases as Any[]) {
  test(`digest-functions.json: ${c.name}`, () => {
    const input = unb64(c.input_b64);
    let digest: Uint8Array | null = null;
    let cls = "";
    try {
      switch (c.function) {
        case "statement_body_digest":
          digest = statementBodyDigestV2(c.object_type_code, input);
          break;
        case "status_evidence_digest":
          digest = statusEvidenceDigestV2(c.object_type_code, decodeRevocationListV2(input));
          break;
        default:
          throw new Error(`unknown function ${c.function}`);
      }
    } catch (err) {
      cls = v2ErrorClassOf(err);
    }
    if (c.expected_error_class) {
      assert.equal(digest, null);
      assert.equal(cls, c.expected_error_class);
      return;
    }
    assert.equal(cls, "");
    assert.equal(`sha384:${hexOf(digest!)}`, c.expected_digest);
  });
}

test("statementBodyDigestV2: revocation list and push bodies are exactly the signable projection", () => {
  const issuer = "ab".repeat(32);
  const listBody = revocationListV2SignBytes({ version: 2, issuer_id: issuer, updated_at: 100, next_update: 200, sequence: 2, revoked: [{ cert_id: "c1" }, { cert_id: "c2" }], signature: noSig });
  const pushBody = revocationPushV2SignBytes({ version: 2, issuer_id: issuer, sequence: 3, pushed_at: 150, revoked: [{ cert_id: "c3" }], signature: noSig });
  const enc = new TextEncoder();
  for (const [code, body, otherBody] of [[0x0003, listBody, pushBody], [0x0005, pushBody, listBody]] as const) {
    const independent = sha384(new Uint8Array([...enc.encode("ratify-protocol-statement-body-v2\0"), code >> 8, code & 0xff, ...body]));
    assert.ok(eqBytes(statementBodyDigestV2(code, body), independent), `0x${code.toString(16)} labelled transcript`);
    const malformed = (b: Uint8Array): string => {
      try {
        statementBodyDigestV2(code, b);
        return "";
      } catch (err) {
        return v2ErrorClassOf(err);
      }
    };
    assert.equal(malformed(otherBody), "malformed", "the other status object's body");
    const fields = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
    const variants: Record<string, Uint8Array> = {
      "signature field": canonicalJSONV2({ ...fields, signature: { ed25519: "", ml_dsa_65: "" } }),
      "unknown field": canonicalJSONV2({ ...fields, extra: 1 }),
      "noncanonical JSON": new Uint8Array([...body, 0x20]),
      "null revoked": canonicalJSONV2({ ...fields, revoked: null }),
    };
    for (const [name, b] of Object.entries(variants)) assert.equal(malformed(b), "malformed", `0x${code.toString(16)} ${name}`);
  }
  for (const code of [0x0000, 0x0001, 0x0002, 0x0007, 0x0009, 0x000a, 0xffff]) {
    assert.throws(() => statementBodyDigestV2(code, listBody), (err) => v2ErrorClassOf(err) === "unsupported_object_type");
  }
});
