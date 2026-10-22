// Fails when testvectors/v2 holds a file (or directory) that no runner in
// test/v2 consumes, or when a listed runner is missing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VECTOR_DIR } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));

/** Corpus entry -> the runner test file that consumes it. */
const RUNNERS: Record<string, string> = {
  "README.md": "corpus_files.test.ts",
  "derive-external-mu.py": "delegation_signature.test.ts",
  "keys.json": "keys.test.ts",
  "objects.json": "objects.test.ts",
  "object-negatives.json": "object_negatives.test.ts",
  "verifier-ordering.json": "verifier_ordering.test.ts",
  "status-sequences.json": "status_sequences.test.ts",
  "log-sequences.json": "log_sequences.test.ts",
  "rotation-sequences.json": "rotation_sequences.test.ts",
  "key-rotation-signature.json": "key_rotation_signature.test.ts",
  "delegation-signature.json": "delegation_signature.test.ts",
  "operation-session-context.json": "operation_session_context.test.ts",
  "challenge-claim.json": "challenge_claim.test.ts",
  "security-journal.json": "security_journal.test.ts",
  "lifecycle-scenarios.json": "lifecycle_scenarios.test.ts",
  "transaction-verification.json": "transaction_verification.test.ts",
  "limits.json": "limits.test.ts",
  "hedged-signatures.json": "hedged_signatures.test.ts",
  "annex-a.json": "annex_a.test.ts",
  "issuer-duties.json": "issuer_duties.test.ts",
  "challenge-issuance.json": "challenge_issuance.test.ts",
  "status-publisher.json": "status_publisher.test.ts",
  "evaluator-profiles.json": "evaluator_profiles.test.ts",
  "device-state.json": "device_state.test.ts",
  "archival.json": "archival.test.ts",
  "external-signer.json": "external_signer.test.ts",
  "digest-functions.json": "digest_functions.test.ts",
  "cross-sdk": "cross_sdk_v2.test.ts",
};

test("v2 corpus: every entry in testvectors/v2 is consumed by a runner", () => {
  const entries = readdirSync(VECTOR_DIR);
  const unknown = entries.filter((f) => !(f in RUNNERS));
  assert.deepEqual(unknown, [], `unconsumed corpus entries: ${unknown.join(", ")}`);
  for (const [entry, runner] of Object.entries(RUNNERS)) {
    assert.ok(entries.includes(entry), `expected corpus entry ${entry} is missing`);
    assert.ok(existsSync(join(here, runner)), `runner ${runner} for ${entry} is missing`);
  }
});
