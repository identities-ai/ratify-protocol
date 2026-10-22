// testvectors/v2/annex-a.json (SPEC-v2-ANNEX-A.md): the v1 clauses Protocol
// v2 incorporates, pinned by digest and locked by behavior. Port of
// annex_a_v2_test.go.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";

import { canonicalJSONV2, checkWireJSONV2, gAny, type JNode } from "../../src/json_v2.js";
import { expandScopes, intersectScopes, isSensitive, scopeWildcards, vocabulary } from "../../src/scope.js";
import { expandScopesV2, intersectScopesV2, validateScopesV2 } from "../../src/scope_v2.js";
import { validateCanonicalTransactionTermsV2 } from "../../src/transaction_receipt_v2.js";
import { VECTOR_DIR, eqBytes, load, toHex, unb64, type Any } from "./helpers.js";

const f = load("annex-a.json");

/** SPEC-v2 §2.1 strict decode over the Annex A value model. */
function annexStrictDecode(data: Uint8Array): unknown {
  const root = checkWireJSONV2(data);
  const walk = (n: JNode): void => {
    if (n.k === "num") {
      if (n.raw === "-0" || /[.eE]/.test(n.raw)) throw new Error("non-integer JSON numbers are not permitted");
      const v = BigInt(n.raw);
      if (v > 9007199254740991n || v < -9007199254740991n) throw new Error("JSON integer is outside the safe-integer range");
    } else if (n.k === "arr") n.a.forEach(walk);
    else if (n.k === "obj") for (const v of n.m.values()) walk(v);
  };
  walk(root);
  return gAny(root);
}

const accepts = (fn: () => unknown): boolean => {
  try {
    fn();
    return true;
  } catch {
    return false;
  }
};

test("annex-a.json: copied v1 clauses are pinned", () => {
  const annex = readFileSync(join(VECTOR_DIR, "..", "..", "SPEC-v2-ANNEX-A.md"), "utf8");
  const lines = annex.split("\n");
  assert.equal(f.clauses.length, 3);
  for (const c of f.clauses) {
    const begin = lines.indexOf(`<!-- annex-a:begin ${c.id} -->`);
    const end = lines.indexOf(`<!-- annex-a:end ${c.id} -->`);
    assert.ok(begin >= 0 && end > begin + 1, `${c.id}: markers missing`);
    const block = new TextEncoder().encode(lines.slice(begin + 1, end).join("\n"));
    assert.equal(block.length, c.bytes, `${c.id} bytes`);
    assert.equal(toHex(sha256(block)), c.sha256, `${c.id} sha256`);
    assert.ok(annex.includes("`" + c.sha256 + "`"), `${c.id}: digest not stated in the annex table`);
  }
});

test("annex-a.json: vector counts", () => {
  assert.ok(f.canonical_json.length > 0 && f.strict_decode_rejections.length > 0);
});

for (const v of f.canonical_json) {
  test(`annex-a.json: canonical_json/${v.name}`, () => {
    const input = unb64(v.input_b64);
    const got = canonicalJSONV2(annexStrictDecode(input));
    assert.equal(new TextDecoder().decode(got), v.canonical);
    assert.doesNotThrow(() => validateCanonicalTransactionTermsV2(new TextEncoder().encode(v.canonical)));
    const isCanonical = accepts(() => validateCanonicalTransactionTermsV2(input));
    assert.equal(isCanonical, v.input_is_canonical);
    assert.equal(isCanonical, eqBytes(input, got));
  });
}

for (const v of f.strict_decode_rejections) {
  test(`annex-a.json: reject/${v.name}`, () => {
    const input = unb64(v.input_b64);
    assert.equal(accepts(() => annexStrictDecode(input)), false, `accepted ${new TextDecoder().decode(input)}`);
    assert.equal(v.error_class, "malformed");
  });
}

test("annex-a.json: scope vocabulary, sensitivity, and wildcards", () => {
  assert.deepEqual([...vocabulary()], f.vocabulary.canonical);
  const sensitive: string[] = [];
  for (const s of f.vocabulary.canonical) {
    if (isSensitive(s)) sensitive.push(s);
    assert.equal(validateScopesV2([s]), null, `canonical ${s} rejected`);
  }
  assert.deepEqual(sensitive, f.vocabulary.sensitive);
  const wildcards = scopeWildcards();
  assert.equal(Object.keys(wildcards).length, Object.keys(f.vocabulary.wildcards).length);
  for (const [w, want] of Object.entries(f.vocabulary.wildcards) as [string, string[]][]) {
    assert.deepEqual(expandScopes([w]), want, `${w} expansion`);
    assert.deepEqual(expandScopesV2([w]), want, `${w} v2 expansion`);
    for (const s of want) assert.equal(isSensitive(s), false, `${w} expands to sensitive ${s}`);
  }
});

for (const v of f.scope_validation as Any[]) {
  test(`annex-a.json: scope_validation/${v.name}`, () => {
    assert.equal(validateScopesV2(v.scopes) === null, v.valid);
  });
}
for (const v of f.scope_expansion as Any[]) {
  test(`annex-a.json: scope_expansion/${v.name}`, () => {
    assert.deepEqual(expandScopes(v.scopes), v.expanded);
    assert.deepEqual(expandScopesV2(v.scopes), v.expanded);
  });
}
for (const v of f.scope_intersection as Any[]) {
  test(`annex-a.json: scope_intersection/${v.name}`, () => {
    assert.deepEqual(intersectScopes(...v.lists), v.effective);
    assert.deepEqual(intersectScopesV2(v.lists), v.effective);
  });
}
