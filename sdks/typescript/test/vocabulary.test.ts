// Vocabulary parity tests — the public scope vocabulary accessors must
// match the Go reference's Vocabulary(): 54 canonical scopes, sorted
// lexicographically, returned as defensive copies.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  expandScopes,
  isSensitive,
  scopeWildcards,
  validateScopes,
  vocabulary,
  SCOPE_PRESENCE_REPRESENT,
} from "../src/index.js";

test("vocabulary: 54 entries, sorted, all canonical", () => {
  const v = vocabulary();
  assert.equal(v.length, 54, "canonical vocabulary size drift");
  assert.deepEqual([...v], [...v].sort(), "vocabulary must be lex-sorted");
  assert.equal(new Set(v).size, v.length, "vocabulary must not contain duplicates");
  assert.ok(v.includes(SCOPE_PRESENCE_REPRESENT));
  // Every entry is a valid canonical scope.
  assert.equal(validateScopes([...v]), null);
});

test("vocabulary: returns a fresh frozen copy", () => {
  const v = vocabulary();
  assert.ok(Object.isFrozen(v));
  assert.notEqual(v, vocabulary(), "each call must return a fresh array");
});

test("scopeWildcards: expansions are non-sensitive members of the vocabulary", () => {
  const wildcards = scopeWildcards();
  const vocab = new Set(vocabulary());
  const keys = Object.keys(wildcards);
  assert.equal(keys.length, 14, "wildcard count drift");
  for (const [wildcard, children] of Object.entries(wildcards)) {
    assert.ok(wildcard.endsWith(":*"), `wildcard ${wildcard} must end with ":*"`);
    assert.ok(children.length > 0, `wildcard ${wildcard} must expand to something`);
    for (const c of children) {
      assert.ok(vocab.has(c), `${wildcard} expands to unknown scope ${c}`);
      assert.equal(isSensitive(c), false, `${wildcard} must not expand to sensitive ${c}`);
    }
    // The map agrees with expandScopes.
    assert.deepEqual(expandScopes([wildcard]), [...children].sort());
  }
});

test("scopeWildcards: returns fresh frozen copies", () => {
  const w = scopeWildcards();
  assert.ok(Object.isFrozen(w));
  assert.ok(Object.isFrozen(w["meeting:*"]));
  assert.notEqual(w, scopeWildcards(), "each call must return a fresh map");
});
