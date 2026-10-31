// testvectors/v2/objects.json: positive objects of every code. Each must
// re-encode byte-identically, verify, reproduce every transcript and digest,
// and (deterministic fixtures) re-sign to the exact signature bytes.

import { test } from "node:test";
import assert from "node:assert/strict";

import { corpusKeyPairs, load, type Any } from "./helpers.js";
import { checkPositiveObject } from "./object_procedures.js";

const file = load("objects.json");

test("objects.json: every positive object", async (t) => {
  const keys = await corpusKeyPairs();
  const seenCodes = new Set<number>();
  const kinds = new Set<string>();
  assert.equal(file.objects.length, 13);
  for (const o of file.objects as Any[]) {
    kinds.add(o.kind);
    await t.test(o.name, async () => {
      for (const code of await checkPositiveObject(keys, o, { deterministic: true })) seenCodes.add(code);
    });
  }
  for (let code = 1; code <= 9; code++) assert.ok(seenCodes.has(code), `objects.json has no signature for object_type_code ${code}`);
  for (const kind of Object.keys(file.kind_object_type_codes)) assert.ok(kinds.has(kind), `no positive ${kind}`);
});
