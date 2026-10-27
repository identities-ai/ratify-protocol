// testvectors/v2/limits.json: every per-object byte limit and count limit at
// the limit and one past it, and the timestamp domain. The size gate is the
// first check: an over-limit input fails with the named limit before parsing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeKeyRotationStatementV2 } from "../../src/key_rotation_v2.js";
import * as limits from "../../src/limits_v2.js";
import { V2_MAX_TIMESTAMP_SECONDS } from "../../src/clock_bounds_v2.js";
import { base64DecodeCanonical } from "../../src/json_v2.js";
import { bundleHashV2, decodeDelegationCertV2, decodeProofBundleV2, decodeRevocationListV2, decodeRevocationPushV2, signProofBundleV2 } from "../../src/protocol_v2_wire.js";
import {
  decodeTransactionReceiptV2, encodeTransactionReceiptV2, signTransactionReceiptPartyV2, transactionContextHashV2, transactionPartyRequestHashV2,
} from "../../src/transaction_receipt_v2.js";
import { buildSessionContextV2 } from "../../src/operation_context_v2.js";
import { decodeVerificationReceiptBodyV2, decodeVerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { decodeWitnessEntryV2 } from "../../src/witness_v2.js";
import { MAX_DELEGATION_CHAIN_DEPTH, MAX_IDENTIFIER_LENGTH_BYTES } from "../../src/types.js";
import { corpusKeyPairs, load, unb64, type Any } from "./helpers.js";

const file = load("limits.json");

/** Go v2vectors.BuildLimitBytes. */
export function buildLimitBytes(c: Any): Uint8Array {
  const b64 = (s: string) => new Uint8Array(Buffer.from(s ?? "", "base64"));
  const enc = new TextEncoder();
  switch (c.method) {
    case "inline":
      return b64(c.wire_b64);
    case "pad": {
      const base = b64(c.base_b64);
      assert.ok(base.length > 0, "pad: invalid base");
      const out = new Uint8Array(base.length + (c.pad_count ?? 0));
      out.set(base.subarray(0, base.length - 1));
      out.fill(0x20, base.length - 1, base.length - 1 + (c.pad_count ?? 0));
      out[out.length - 1] = base[base.length - 1]!;
      return out;
    }
    case "repeat_items": {
      const parts: Uint8Array[] = [b64(c.prefix_b64)];
      for (let i = 0; i < c.count; i++) {
        parts.push(enc.encode((i > 0 ? "," : "") + c.item_prefix + String(i).padStart(c.item_index_digits, "0") + c.item_suffix));
      }
      parts.push(b64(c.suffix_b64));
      return Buffer.concat(parts);
    }
    case "repeat_bytes": {
      const item = b64(c.item_b64);
      const parts: Uint8Array[] = [b64(c.prefix_b64)];
      for (let i = 0; i < c.count; i++) parts.push(item);
      parts.push(b64(c.suffix_b64));
      return Buffer.concat(parts);
    }
    case "repeat_item": {
      const item = b64(c.item_b64);
      const parts: Uint8Array[] = [b64(c.prefix_b64)];
      for (let i = 0; i < c.count; i++) {
        if (i > 0) parts.push(enc.encode(","));
        parts.push(item);
      }
      parts.push(b64(c.suffix_b64));
      return Buffer.concat(parts);
    }
  }
  assert.fail(`unknown construction method ${c.method}`);
}

async function decodeBatch(b: Uint8Array): Promise<unknown> {
  // The status evidence batch decoder lives in status_batch_v2.ts.
  const mod = (await import("../../src/status_batch_v2.js")) as Any;
  assert.equal(typeof mod.decodeV2StatusEvidenceBatch, "function", "decodeV2StatusEvidenceBatch is not exported");
  return mod.decodeV2StatusEvidenceBatch(b);
}

const CONSTANTS: Record<string, number> = {
  MAX_DELEGATION_CERT_BYTES_V2: limits.MAX_DELEGATION_CERT_BYTES_V2,
  MAX_DELEGATION_CHAIN_DEPTH,
  MAX_IDENTIFIER_LENGTH_BYTES,
  MAX_KEY_ROTATION_STATEMENT_BYTES_V2: limits.MAX_KEY_ROTATION_STATEMENT_BYTES_V2,
  MAX_PROOF_BUNDLE_BYTES_V2: limits.MAX_PROOF_BUNDLE_BYTES_V2,
  MAX_REVOCATION_LIST_BYTES_V2: limits.MAX_REVOCATION_LIST_BYTES_V2,
  MAX_REVOCATION_LIST_REFS_V2: limits.MAX_REVOCATION_LIST_REFS_V2,
  MAX_REVOCATION_PUSH_BYTES_V2: limits.MAX_REVOCATION_PUSH_BYTES_V2,
  MAX_REVOCATION_PUSH_REFS_V2: limits.MAX_REVOCATION_PUSH_REFS_V2,
  MAX_STATUS_EVIDENCE_BATCH_BYTES_V2: limits.MAX_STATUS_EVIDENCE_BATCH_BYTES_V2,
  MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2: limits.MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2,
  MAX_TIMESTAMP_SECONDS_V2: V2_MAX_TIMESTAMP_SECONDS,
  MAX_TRANSACTION_RECEIPT_BYTES_V2: limits.MAX_TRANSACTION_RECEIPT_BYTES_V2,
  MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2: limits.MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2,
  MAX_VERIFICATION_RECEIPT_BYTES_V2: limits.MAX_VERIFICATION_RECEIPT_BYTES_V2,
  MAX_WITNESS_ENTRY_BYTES_V2: limits.MAX_WITNESS_ENTRY_BYTES_V2,
  MAX_WITNESS_ENTRY_DATA_BYTES_V2: limits.MAX_WITNESS_ENTRY_DATA_BYTES_V2,
};

test("limits.json: SDK constants equal the limits table", () => {
  assert.deepEqual(Object.keys(file.limits).sort(), Object.keys(CONSTANTS).sort());
  for (const [name, value] of Object.entries(file.limits)) assert.equal(CONSTANTS[name], value, name);
});

test("limits.json: byte, count and timestamp boundaries", async (t) => {
  const decoders: Record<string, (b: Uint8Array) => unknown> = {
    delegation_certificate: decodeDelegationCertV2,
    proof_bundle: decodeProofBundleV2,
    key_rotation_statement: decodeKeyRotationStatementV2,
    revocation_list: decodeRevocationListV2,
    revocation_push: decodeRevocationPushV2,
    witness_entry: decodeWitnessEntryV2,
    verification_receipt: decodeVerificationReceiptV2,
    verification_receipt_body: decodeVerificationReceiptBodyV2,
    transaction_receipt: decodeTransactionReceiptV2,
    status_evidence_batch: decodeBatch,
  };
  assert.equal(file.vectors.length, 80);
  for (const kind of Object.keys(file.procedure_by_kind)) assert.ok(kind in decoders, `no decoder for ${kind}`);
  for (const v of file.vectors as Any[]) {
    await t.test(v.name, async () => {
      assert.equal(file.limits[v.limit], v.limit_value, `limit ${v.limit} disagrees with the table`);
      const data = buildLimitBytes(v.construction);
      assert.equal(data.length, v.length, "constructed length");
      assert.equal(createHash("sha256").update(data).digest("hex"), v.sha256_hex, "constructed digest");
      const decode = decoders[v.kind];
      assert.ok(decode, `no decoder for ${v.kind}`);
      let err: unknown = null;
      try {
        await decode(data);
      } catch (e) {
        err = e;
      }
      if (v.expected === "accept") {
        assert.equal(err, null, `at-limit input rejected: ${(err as Error)?.message}`);
      } else {
        assert.equal(v.expected, "reject");
        assert.ok(err !== null, "input accepted");
        assert.equal(v2ErrorClassOf(err), v.expected_error_class, (err as Error).message);
      }
      const message = err instanceof Error ? err.message : "";
      const gateFailed = message.includes(`exceeds ${v.limit} (`) && message.includes("rejected before parsing");
      assert.equal(gateFailed, v.size_gate === "fail", `size gate ${v.size_gate}, error ${message}`);
    });
  }
});

test("limits: a valid transaction receipt near MAX_TRANSACTION_RECEIPT_BYTES_V2 decodes", async () => {
  // SPEC-v2 §2.6 admits a transaction receipt up to 5 MiB, so a byte field
  // holding most of that budget is valid. The canonical base64 check must
  // stay linear in the field length; a backtracking pattern exhausted the
  // stack at about 4.47 million characters and made this receipt malformed.
  const keys = await corpusKeyPairs();
  const signers = new Map([["party-a", keys.get("agent")!], ["party-b", keys.get("party_b_agent")!]]);
  const objects = load("objects.json").objects as Any[];
  const base = await decodeTransactionReceiptV2(unb64(objects.find((o) => o.name === "transaction_receipt_two_parties").wire_b64));
  const build = async (n: number): Promise<Uint8Array> => {
    const r = { ...base, terms_canonical_json: new TextEncoder().encode(`{"pad":"${"y".repeat(n)}"}`) };
    const transactionHash = transactionContextHashV2(r);
    r.parties = await Promise.all(base.parties.map(async (p) => {
      const session_context = buildSessionContextV2({
        verifier_id: p.verifier_id, workspace_id: p.workspace_id, agent_id: p.agent_id, session_id: p.session_id,
        invocation_id: p.invocation_id, request_hash: transactionPartyRequestHashV2(transactionHash, p.required_scope),
      });
      const proof_bundle = await signProofBundleV2({ ...p.proof_bundle, session_context } as Parameters<typeof signProofBundleV2>[0], signers.get(p.party_id)!, { deterministic: true });
      return { ...p, proof_bundle, proof_bundle_hash: bundleHashV2(proof_bundle) };
    }));
    r.party_signatures = await Promise.all(r.parties.map((p) => signTransactionReceiptPartyV2(r, p.party_id, signers.get(p.party_id)!, { deterministic: true })));
    return encodeTransactionReceiptV2(r);
  };
  const overhead = (await build(0)).length;
  const limit = limits.MAX_TRANSACTION_RECEIPT_BYTES_V2;
  const n = Math.floor((limit - overhead) / 4) * 3;
  const wire = await build(n);
  assert.ok(wire.length <= limit && wire.length > limit - 4, `receipt is ${wire.length} bytes`);
  const decoded = await decodeTransactionReceiptV2(wire);
  assert.equal(decoded.terms_canonical_json.length, n + 10);
});

test("limits: the canonical base64 check keeps its padded-alphabet shape", () => {
  // The linear check replaced a pattern; it accepts and rejects exactly the
  // same shapes (SPEC-v2 §2.1).
  for (const ok of ["", "AA==", "AAA=", "AAAA", "+/+/", "QUJD"]) assert.ok(base64DecodeCanonical(ok) !== null, ok);
  for (const bad of ["A", "AA=", "A===", "====", "AA=A", "AB==CD==", "AAA-", "AAA_", "AA\n=", "QUI=QUI=", "AB=="]) {
    assert.equal(base64DecodeCanonical(bad), null, JSON.stringify(bad));
  }
});
