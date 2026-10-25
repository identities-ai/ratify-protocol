// Shared helpers for the Protocol v2 corpus runners (testvectors/v2).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { protocolClaimIDFromDigestV2 } from "../../src/challenge_claim_v2.js";
import { hybridKeypairFromSeeds } from "../../src/crypto.js";
import type { HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { base64Encode } from "../../src/json_v2.js";
import { v2ErrorClassOf } from "../../src/errors_v2.js";
import type { HybridPublicKey } from "../../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const VECTOR_DIR = join(__dirname, "..", "..", "..", "..", "testvectors", "v2");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Any = any;

export const load = (name: string): Any => JSON.parse(readFileSync(join(VECTOR_DIR, name), "utf8"));

export const unb64 = (s: string): Uint8Array => {
  const out = new Uint8Array(Buffer.from(s, "base64"));
  assert.equal(base64Encode(out), s, `non-canonical base64 in vector: ${s.slice(0, 20)}`);
  return out;
};
export const b64 = (b: Uint8Array): string => base64Encode(b);
export const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
export const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
export const eqBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
export const pubOf = (o: { ed25519: string; ml_dsa_65: string }): HybridPublicKey => ({ ed25519: unb64(o.ed25519), ml_dsa_65: unb64(o.ml_dsa_65) });

/** Derives every key of a keys.json-shaped list from its seeds. */
export async function deriveKeys(keys: Any[]): Promise<Map<string, HybridKeyPairV2>> {
  const out = new Map<string, HybridKeyPairV2>();
  for (const k of keys) {
    const { publicKey, privateKey } = await hybridKeypairFromSeeds(hex(k.ed25519_seed_hex), hex(k.ml_dsa_65_seed_hex));
    out.set(k.name, { publicKey, privateKey });
  }
  return out;
}

let corpusKeys: Promise<Map<string, HybridKeyPairV2>> | null = null;
/** The keys of testvectors/v2/keys.json, derived from their seeds. */
export function corpusKeyPairs(): Promise<Map<string, HybridKeyPairV2>> {
  corpusKeys ??= deriveKeys(load("keys.json").keys);
  return corpusKeys;
}

/** The thrown error's v2 class, or "" when fn succeeds. */
export function classOf(fn: () => unknown): string {
  try {
    fn();
    return "";
  } catch (err) {
    return v2ErrorClassOf(err);
  }
}

export async function classOfAsync(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "";
  } catch (err) {
    return v2ErrorClassOf(err);
  }
}

/**
 * A hand-built test claim with the claim ID derived from its replay key
 * (SPEC-v2 §2.4); the reference store refuses any other ID (§7.3).
 */
export function keyedClaim<T extends { claimID: string; namespace: string; replayEpoch: number; challengeDigest: string }>(claim: T): T {
  const digest = Uint8Array.from(claim.challengeDigest.slice("sha384:".length).match(/../g)!, (h) => parseInt(h, 16));
  return { ...claim, claimID: protocolClaimIDFromDigestV2(claim.namespace, claim.replayEpoch, digest) };
}
