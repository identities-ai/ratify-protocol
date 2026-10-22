import { Point, getPublicKeyAsync as getEd25519PublicKeyAsync, verifyAsync as verifyEd25519Async } from "@noble/ed25519";
import { sha256, sha384 } from "@noble/hashes/sha2";
import { shake256 } from "@noble/hashes/sha3";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { v2Errorf } from "./errors_v2.js";
import type { HybridPublicKey, HybridSignature } from "./types.js";

const KEY_ID_V2_DOMAIN = new TextEncoder().encode("ratify-key-id-v2\0");
const SIGNATURE_V2_DOMAIN = new TextEncoder().encode("ratify-protocol-signature\0\x02");
const ML_DSA_V2_CERT_CONTEXT = new TextEncoder().encode("ratify-protocol/2/0001");
const ED25519_ORDER_LE = new Uint8Array([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]);

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hasCanonicalNonIdentityPrimeOrder(encoded: Uint8Array): boolean {
  if (encoded.length !== 32) return false;
  try {
    const point = Point.fromBytes(encoded, false);
    return point.toBytes().every((byte, index) => byte === encoded[index]) && !point.is0() && point.isTorsionFree();
  } catch {
    return false;
  }
}

function hasCanonicalScalar(encoded: Uint8Array): boolean {
  if (encoded.length !== ED25519_ORDER_LE.length) return false;
  for (let i = encoded.length - 1; i >= 0; i--) {
    const value = encoded[i]!;
    const orderByte = ED25519_ORDER_LE[i]!;
    if (value !== orderByte) return value < orderByte;
  }
  return false;
}

/** Derives a full 256-bit Protocol v2 key ID. v1 DeriveID remains unchanged. */
export function deriveKeyIDV2(publicKey: HybridPublicKey): string {
  if (!publicKey || !(publicKey.ed25519 instanceof Uint8Array) ||
      !(publicKey.ml_dsa_65 instanceof Uint8Array) ||
      publicKey.ed25519.length !== 32 || publicKey.ml_dsa_65.length !== 1952) {
    throw new Error("v2 hybrid public key has invalid component length");
  }
  return encodeHex(sha256(concatBytes(KEY_ID_V2_DOMAIN, publicKey.ed25519, publicKey.ml_dsa_65)));
}

function signingMessageV2Delegation(signableBytes: Uint8Array): Uint8Array {
  const code = new Uint8Array([0x00, 0x01]);
  return concatBytes(SIGNATURE_V2_DOMAIN, code, sha384(signableBytes));
}

/**
 * Verifies the v2 delegation-certificate signature pair over the caller's
 * canonical signable projection. The object code and ML-DSA context are fixed.
 * This low-level primitive does not parse or validate a certificate schema.
 */
export async function verifyV2DelegationCertificateSignature(
  signableBytes: Uint8Array,
  signature: HybridSignature,
  issuerPublicKey: HybridPublicKey,
): Promise<boolean> {
  try {
    if (!signature || !issuerPublicKey ||
        !(signature.ed25519 instanceof Uint8Array) || !(signature.ml_dsa_65 instanceof Uint8Array) ||
        !(issuerPublicKey.ed25519 instanceof Uint8Array) || !(issuerPublicKey.ml_dsa_65 instanceof Uint8Array) ||
        !(signableBytes instanceof Uint8Array)) return false;
    if (issuerPublicKey.ed25519.length !== 32 || issuerPublicKey.ml_dsa_65.length !== 1952) return false;
    if (signature.ed25519.length !== 64 || signature.ml_dsa_65.length !== 3309) return false;

    const r = signature.ed25519.subarray(0, 32);
    const s = signature.ed25519.subarray(32);
    if (!hasCanonicalNonIdentityPrimeOrder(issuerPublicKey.ed25519) ||
        !hasCanonicalNonIdentityPrimeOrder(r) || !hasCanonicalScalar(s)) return false;

    const message = signingMessageV2Delegation(signableBytes);
    const edValid = await verifyEd25519Async(signature.ed25519, message, issuerPublicKey.ed25519, { zip215: false });
    if (!edValid) return false;
    return ml_dsa65.verify(signature.ml_dsa_65, message, issuerPublicKey.ml_dsa_65, { context: ML_DSA_V2_CERT_CONTEXT });
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Generic typed v2 statements (Go crypto_v2.go). The object code is closed:
// callers cannot pick an ML-DSA context independently of the schema.

/** Registered Protocol v2 object type codes (SPEC-v2 §4). */
export const V2_OBJECT_TYPE = {
  delegationCertificate: 0x0001,
  challengePresentation: 0x0002,
  revocationList: 0x0003,
  keyRotationAuthorization: 0x0004,
  revocationPush: 0x0005,
  witnessEntry: 0x0006,
  transactionPartyStatement: 0x0007,
  verificationReceipt: 0x0008,
  keyRotationProofOfPossession: 0x0009,
} as const;

export function validV2ObjectType(code: number): boolean {
  return Number.isInteger(code) && code >= 0x0001 && code <= 0x0009;
}

/** M = "ratify-protocol-signature" || 0x00 || 0x02 || u16be(code) || SHA-384(signable). */
export function v2SigningMessage(code: number, signable: Uint8Array): Uint8Array {
  if (!validV2ObjectType(code)) throw new Error(`unsupported v2 object type: ${code.toString(16).padStart(4, "0")}`);
  return concatBytes(SIGNATURE_V2_DOMAIN, new Uint8Array([(code >> 8) & 0xff, code & 0xff]), sha384(signable));
}

/** FIPS 204 context "ratify-protocol/2/" || lowercase hex4(code). */
export function v2MLDSAContext(code: number): Uint8Array {
  if (!validV2ObjectType(code)) throw new Error(`unsupported v2 object type: ${code.toString(16).padStart(4, "0")}`);
  return new TextEncoder().encode(`ratify-protocol/2/${code.toString(16).padStart(4, "0")}`);
}

/** A hybrid key pair. The public key must belong to the private key. */
export interface HybridKeyPairV2 {
  publicKey: HybridPublicKey;
  privateKey: { ed25519: Uint8Array; ml_dsa_65: Uint8Array };
}

const ML_DSA_65_SECRET_KEY_SIZE = 4032;

/**
 * Checks that a key pair is complete and internally consistent: the Ed25519
 * public key derives from the seed, and the ML-DSA-65 secret key's embedded
 * tr equals SHAKE256(public key, 64) (FIPS 204 §7.2 skEncode layout).
 */
export async function validateHybridKeyPairV2(pair: HybridKeyPairV2): Promise<void> {
  const priv = pair?.privateKey;
  const pub = pair?.publicKey;
  if (!priv || !pub || !(priv.ed25519 instanceof Uint8Array) || !(priv.ml_dsa_65 instanceof Uint8Array) ||
      priv.ed25519.length !== 32 || priv.ml_dsa_65.length !== ML_DSA_65_SECRET_KEY_SIZE ||
      !(pub.ed25519 instanceof Uint8Array) || !(pub.ml_dsa_65 instanceof Uint8Array) ||
      pub.ed25519.length !== 32 || pub.ml_dsa_65.length !== 1952) {
    throw new Error("incomplete hybrid private key");
  }
  const edPublic = await getEd25519PublicKeyAsync(priv.ed25519);
  if (!edPublic.every((b, i) => b === pub.ed25519[i])) {
    throw new Error("Ed25519 private key seed and public component do not match");
  }
  const tr = shake256(pub.ml_dsa_65, { dkLen: 64 });
  const embedded = priv.ml_dsa_65.subarray(64, 128);
  if (!tr.every((b, i) => b === embedded[i])) {
    throw new Error("ML-DSA-65 private key and public component do not match");
  }
}

export interface V2SignOptions {
  /**
   * Deterministic ML-DSA-65 signing (no hedging randomness). Used to
   * reproduce published vectors; production signing is hedged by default.
   */
  deterministic?: boolean;
}

/** Go keyIDV2: an unclassified error on a wrong component length. */
export function keyIDV2(pub: HybridPublicKey): string {
  if (!pub || !(pub.ed25519 instanceof Uint8Array) || pub.ed25519.length !== 32) {
    throw new Error(`Ed25519 public key wrong length: ${pub?.ed25519?.length ?? 0}`);
  }
  if (!(pub.ml_dsa_65 instanceof Uint8Array) || pub.ml_dsa_65.length !== 1952) {
    throw new Error(`ML-DSA-65 public key wrong length: ${pub.ml_dsa_65?.length ?? 0}`);
  }
  return deriveKeyIDV2(pub);
}

/**
 * Classified v2 verification (Go verifyV2Statement): an unregistered code is
 * unsupported_object_type and every other failure is invalid_signature.
 */
export async function verifyV2Statement(code: number, signable: Uint8Array, sig: HybridSignature, pub: HybridPublicKey): Promise<void> {
  if (!validV2ObjectType(code)) {
    throw v2Errorf("unsupported_object_type", `unsupported v2 object type: ${code.toString(16).padStart(4, "0")}`);
  }
  const reason = await verifyV2StatementReason(code, signable, sig, pub);
  if (reason !== null) throw v2Errorf("invalid_signature", reason);
}

/**
 * Strict hybrid AND verification for one typed statement. Returns null on
 * success, otherwise a reason. The object code must be registered.
 */
export async function verifyV2StatementReason(
  code: number,
  signable: Uint8Array,
  sig: HybridSignature,
  pub: HybridPublicKey,
): Promise<string | null> {
  try {
    if (!pub || !(pub.ed25519 instanceof Uint8Array) || !(pub.ml_dsa_65 instanceof Uint8Array) ||
        pub.ed25519.length !== 32 || pub.ml_dsa_65.length !== 1952) {
      return "hybrid public key has invalid component length";
    }
    if (!sig || !(sig.ed25519 instanceof Uint8Array) || !(sig.ml_dsa_65 instanceof Uint8Array) ||
        sig.ed25519.length !== 64 || sig.ml_dsa_65.length !== 3309) {
      return "hybrid signature has invalid component length";
    }
    if (!hasCanonicalNonIdentityPrimeOrder(pub.ed25519) || !hasCanonicalNonIdentityPrimeOrder(sig.ed25519.subarray(0, 32))) {
      return "Ed25519 v2 public key or R component is not a canonical non-identity prime-order point";
    }
    if (!hasCanonicalScalar(sig.ed25519.subarray(32))) return "Ed25519 v2 S component is not a canonical scalar";
    const message = v2SigningMessage(code, signable);
    const context = v2MLDSAContext(code);
    if (!(await verifyEd25519Async(sig.ed25519, message, pub.ed25519, { zip215: false }))) {
      return "Ed25519 v2 signature invalid";
    }
    if (!ml_dsa65.verify(sig.ml_dsa_65, message, pub.ml_dsa_65, { context })) return "ML-DSA-65 v2 signature invalid";
    return null;
  } catch (err) {
    return `v2 signature verification failed: ${(err as Error)?.message ?? err}`;
  }
}
