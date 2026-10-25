// testvectors/v2/object-negatives.json: every single-fault negative must be
// rejected with exactly its language-neutral error class.

import { test } from "node:test";
import assert from "node:assert/strict";

import { classOfAsync, corpusKeyPairs, load, unb64, type Any } from "./helpers.js";
import { OBJECT_KINDS, verifyObject } from "./object_procedures.js";

const file = load("object-negatives.json");

test("object-negatives.json: every vector rejected with its class", async (t) => {
  const keys = await corpusKeyPairs();
  const kinds = new Map<string, number>();
  assert.equal(file.vectors.length, 433);
  for (const v of file.vectors as Any[]) {
    kinds.set(v.kind, (kinds.get(v.kind) ?? 0) + 1);
    await t.test(v.name, async () => {
      const bundle = v.bundle_b64 ? unb64(v.bundle_b64) : null;
      const got = await classOfAsync(() => verifyObject(keys, v.kind, unb64(v.wire_b64), bundle, v.verify));
      assert.notEqual(got, "", `accepted; want ${v.expected_error_class} (${v.mutation})`);
      assert.equal(got, v.expected_error_class, v.mutation);
    });
  }
  for (const kind of OBJECT_KINDS) assert.ok((kinds.get(kind) ?? 0) > 0, `no negative vectors for ${kind}`);
  for (const kind of Object.keys(file.procedure_by_kind)) assert.ok(kinds.has(kind), `procedure ${kind} has no vector`);
});
