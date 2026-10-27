import { sha384 as nobleSha384 } from "@noble/hashes/sha2";

// SHA-384 over inputs of up to MAX_TRANSACTION_RECEIPT_BYTES_V2 (a
// transaction receipt's signable bytes and terms). Node's native hash is
// used when the runtime provides it, without a static node:crypto import, and
// @noble/hashes otherwise; both return the same FIPS 180-4 digest.
type NodeCrypto = { createHash(algorithm: "sha384"): { update(data: Uint8Array): { digest(): Uint8Array } } };
const nodeCrypto = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process?.getBuiltinModule?.("node:crypto") as
  | NodeCrypto
  | undefined;

export function sha384V2(data: Uint8Array): Uint8Array {
  if (nodeCrypto === undefined) return nobleSha384(data);
  return new Uint8Array(nodeCrypto.createHash("sha384").update(data).digest());
}
