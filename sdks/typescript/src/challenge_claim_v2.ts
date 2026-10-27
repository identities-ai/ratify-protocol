// Protocol v2 replay identifiers are separate from v1 challenge-store keys.
import { sha256, sha384 } from "@noble/hashes/sha2";
import { classified, v2Classify, v2Errorf } from "./errors_v2.js";
import type { V2ChallengeClaim } from "./claim_store_v2.js";

const encoder = new TextEncoder();
const claimDigestTag = encoder.encode("ratify-protocol-challenge-claim-v2\0");
const claimIDTag = encoder.encode("ratify-protocol-claim-id-v2\0");

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function uint64BE(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value);
  return bytes;
}

export function challengeClaimDigestV2(challenge: Uint8Array): Uint8Array {
  return classified("malformed", () => {
    if (!(challenge instanceof Uint8Array) || challenge.length !== 32) {
      throw new Error("v2 challenge claim requires exactly 32 challenge bytes");
    }
    return sha384(concat(claimDigestTag, challenge));
  });
}

function validateNamespaceEpoch(verifierNamespace: string, replayEpoch: number): void {
  if (typeof verifierNamespace !== "string" || !verifierNamespace ||
      !/^(?:[^\uD800-\uDFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF])+$/.test(verifierNamespace)) {
    throw new Error("v2 verifier namespace must be non-empty well-formed Unicode");
  }
  if (!Number.isSafeInteger(replayEpoch) || replayEpoch < 0) {
    throw new Error("v2 replay epoch must be an unsigned safe integer");
  }
}

export function protocolClaimIDV2(verifierNamespace: string, replayEpoch: number, challenge: Uint8Array): string {
  return classified("configuration_invalid", () => {
    validateNamespaceEpoch(verifierNamespace, replayEpoch);
    let digest: Uint8Array;
    try {
      digest = challengeClaimDigestV2(challenge);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    return protocolClaimIDFromDigestV2(verifierNamespace, replayEpoch, digest);
  });
}

export function protocolClaimIDFromDigestV2(verifierNamespace: string, replayEpoch: number, claimDigest: Uint8Array): string {
  return classified("configuration_invalid", () => {
    validateNamespaceEpoch(verifierNamespace, replayEpoch);
    if (!(claimDigest instanceof Uint8Array) || claimDigest.length !== 48) {
      throw v2Errorf("malformed", "v2 challenge claim digest must be exactly 48 bytes");
    }
    const namespace = encoder.encode(verifierNamespace);
    const digest = sha256(concat(
      claimIDTag,
      uint64BE(BigInt(namespace.length)),
      namespace,
      uint64BE(BigInt(replayEpoch)),
      claimDigest,
    ));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  });
}

/**
 * @internal Whether the claim ID is the stable claim ID of the claim's
 * (namespace, replay_epoch, ChallengeClaimDigest) key (SPEC-v2 §2.4, §7.3).
 * A claim store is keyed by claim ID, so a supplied ID that is not derived
 * from that key could create a second claim for one challenge.
 */
export function claimIDMatchesKeyV2(claim: V2ChallengeClaim | null | undefined): boolean {
  const match = /^sha384:([0-9a-f]{96})$/.exec(typeof claim?.challengeDigest === "string" ? claim.challengeDigest : "");
  if (!claim || !match) return false;
  const digest = Uint8Array.from(match[1]!.match(/../g)!, (h) => parseInt(h, 16));
  try {
    return protocolClaimIDFromDigestV2(claim.namespace, claim.replayEpoch, digest) === claim.claimID;
  } catch {
    return false;
  }
}
