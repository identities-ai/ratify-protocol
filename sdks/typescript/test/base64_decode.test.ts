// base64StandardDecode takes a fallback path wherever Buffer is undefined:
// browsers, Deno without node compatibility, and edge runtimes. That path is
// where the padding strip lives, so these tests stub Buffer out to reach it.
//
// Stripping trailing padding with /=+$/ backtracks polynomially: an input of
// many '=' followed by a character that is not the end of the string costs
// O(n^2). The decoder is exported and its input is not always size-checked
// before it is called, so the strip scans backwards instead.

import { test } from "node:test";
import assert from "node:assert/strict";

import { base64StandardDecode, base64StandardEncode } from "../src/canonical.js";

/** Run fn with globalThis.Buffer removed, so the fallback decoder is used. */
function withoutBuffer<T>(fn: () => T): T {
  const saved = (globalThis as { Buffer?: unknown }).Buffer;
  delete (globalThis as { Buffer?: unknown }).Buffer;
  try {
    return fn();
  } finally {
    (globalThis as { Buffer?: unknown }).Buffer = saved;
  }
}

test("fallback round-trips with and without padding", () => {
  withoutBuffer(() => {
    for (const n of [0, 1, 2, 3, 4, 5, 31, 32, 33]) {
      const bytes = new Uint8Array(n).map((_, i) => (i * 37) & 0xff);
      const padded = base64StandardEncode(bytes);
      assert.deepEqual(base64StandardDecode(padded), bytes);
      assert.deepEqual(base64StandardDecode(padded.replace(/=+$/, "")), bytes);
    }
  });
});

test("fallback strips only trailing padding", () => {
  // '=' is not in the alphabet, so an interior one must be rejected rather
  // than silently ignored.
  withoutBuffer(() => {
    assert.throws(() => base64StandardDecode("QQ=Q"), /invalid base64 char/);
  });
});

test("fallback does not backtrack on adversarial padding", () => {
  // Against /=+$/ this input costs roughly n^2. Scanning backwards rejects it
  // on the first non-alphabet character in linear time.
  withoutBuffer(() => {
    const n = 200_000;
    const hostile = "=".repeat(n) + "!";
    const started = Date.now();
    assert.throws(() => base64StandardDecode(hostile), /invalid base64 char/);
    const elapsed = Date.now() - started;
    assert.ok(
      elapsed < 1_000,
      `decoding ${n} padding characters took ${elapsed}ms, which suggests the ` +
        `padding strip is backtracking rather than scanning`,
    );
  });
});

test("fallback decodes a string of only padding to nothing", () => {
  withoutBuffer(() => {
    assert.deepEqual(base64StandardDecode("=".repeat(100_000)), new Uint8Array(0));
  });
});
