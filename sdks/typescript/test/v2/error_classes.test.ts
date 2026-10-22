// The closed v2 error-class set must equal the SPEC-v2 §2.7 table exactly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { V2_ERROR_CLASSES, V2Error, v2ErrorClassOf } from "../../src/errors_v2.js";
import { VECTOR_DIR } from "./helpers.js";

function specClasses(): string[] {
  const spec = readFileSync(join(VECTOR_DIR, "..", "..", "SPEC-v2.md"), "utf8");
  const start = spec.indexOf("### 2.7 Error classes");
  const end = spec.indexOf("## 3.", start);
  assert.ok(start > 0 && end > start, "SPEC-v2 §2.7 not found");
  const section = spec.slice(start, end);
  const classes: string[] = [];
  for (const line of section.split("\n")) {
    if (!line.startsWith("| `")) continue;
    const first = line.split("|")[1]!;
    for (const m of first.matchAll(/`([a-z_]+)`/g)) classes.push(m[1]!);
  }
  const count = /The list has (\d+) classes\./.exec(section);
  assert.ok(count, "class count sentence not found");
  assert.equal(classes.length, Number(count[1]), "table rows disagree with the stated count");
  return classes;
}

test("V2_ERROR_CLASSES equals the SPEC-v2 §2.7 table (49 classes)", () => {
  const spec = specClasses();
  assert.equal(spec.length, 49);
  assert.equal(new Set(spec).size, spec.length, "duplicate class in the spec table");
  assert.deepEqual([...V2_ERROR_CLASSES].sort(), [...spec].sort());
});

test("v2ErrorClassOf never invents a class", () => {
  assert.equal(v2ErrorClassOf(null), "");
  assert.equal(v2ErrorClassOf(new Error("plain")), "unclassified");
  for (const cls of V2_ERROR_CLASSES) assert.equal(v2ErrorClassOf(new Error("wrapped", { cause: new V2Error(cls, "x") })), cls);
});
