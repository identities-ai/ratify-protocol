// The fast paths taken on multi-megabyte receipt values must give exactly the
// bytes of the general paths: a different canonical string or digest would
// change what a receipt signs or how it is judged canonical (SPEC-v2 §2.1).

import { test } from "node:test";
import assert from "node:assert/strict";
import { sha384 } from "@noble/hashes/sha2";

import { encodeGoString } from "../../src/json_v2.js";
import { sha384V2 } from "../../src/sha384_v2.js";

// Appending a quote forces the per-character loop; the result must be the
// fast-path encoding with the escaped quote added.
function viaLoop(s: string, escapeHTML: boolean): string {
  const forced = encodeGoString(s + '"', escapeHTML);
  assert.ok(forced.endsWith('\\""'));
  return forced.slice(0, -3) + '"';
}

test("encodeGoString: no-escape fast path equals the escaping loop for every code unit", () => {
  for (const escapeHTML of [false, true]) {
    for (let c = 0; c <= 0xffff; c++) {
      const s = "a" + String.fromCharCode(c) + "z";
      assert.equal(encodeGoString(s, escapeHTML), viaLoop(s, escapeHTML), `U+${c.toString(16)} escapeHTML=${escapeHTML}`);
    }
    for (const s of ["", "😀", "\ud83d", "\ude00x", "<a&b>", "  ", "x".repeat(1 << 20)]) {
      assert.equal(encodeGoString(s, escapeHTML), viaLoop(s, escapeHTML));
    }
  }
});

test("sha384V2 equals the portable SHA-384", () => {
  const lengths = [0, 1, 111, 112, 127, 128, 129, 1000, 1 << 16, 5 * 1024 * 1024];
  for (const n of lengths) {
    const data = new Uint8Array(n);
    for (let i = 0; i < n; i++) data[i] = (i * 31 + 7) & 0xff;
    assert.deepEqual(sha384V2(data), sha384(data), `length ${n}`);
  }
  const view = new Uint8Array(new Uint8Array(64).fill(9).buffer, 8, 40);
  assert.deepEqual(sha384V2(view), sha384(view));
});
