// Protocol v2 typed signing and the external signer interface (SPEC-v2 §3.2;
// Go signer_v2.go). There is deliberately no exported function that signs
// caller-selected bytes, codes, or contexts: every signature is produced by
// a typed object signer that computes M and the ML-DSA context itself.

import { signAsync as signEd25519Async } from "@noble/ed25519";
import { shake256 } from "@noble/hashes/sha3";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  keyIDV2 as keyIDV2Unclassified,
  v2MLDSAContext,
  v2SigningMessage,
  validateHybridKeyPairV2,
  verifyV2Statement,
  type HybridKeyPairV2,
} from "./crypto_v2.js";
import { classifiedAsync, v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import { concatBytes } from "./json_v2.js";
import type { HybridPublicKey, HybridSignature } from "./types.js";

/**
 * Returns the Protocol v2 key ID of a complete hybrid public key (SPEC-v2
 * §2.3): lowercase_hex(SHA-256("ratify-key-id-v2" || 0x00 || ed25519 ||
 * ml_dsa_65)). Throws the malformed class unless both components have their
 * exact lengths.
 */
export function keyIDV2(pub: HybridPublicKey): string {
  try {
    return keyIDV2Unclassified(pub);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
}

/** Which ML-DSA-65 input an external signer receives. */
export const SIGNER_MODE_DIRECT_V2 = 1;
export const SIGNER_MODE_EXTERNAL_MU_V2 = 2;
export type SignerModeV2 = typeof SIGNER_MODE_DIRECT_V2 | typeof SIGNER_MODE_EXTERNAL_MU_V2;

/**
 * Everything an external signer receives for one typed v2 statement. The
 * SDK computes every field; the provider never receives the object or its
 * type code and never chooses a context or message. Ed25519 always signs
 * `message`.
 */
export interface SignRequestV2 {
  readonly mode: SignerModeV2;
  /** The 77-byte M. */
  readonly message: Uint8Array;
  /** The 22-byte FIPS 204 context in direct mode; null in external-mu mode. */
  readonly mlDsaContext: Uint8Array | null;
  /** The 64-byte external mu in external-mu mode; null in direct mode. */
  readonly mlDsaMu: Uint8Array | null;
  /** The complete key the provider must sign under; any other key must refuse. */
  readonly publicKey: HybridPublicKey;
  readonly keyId: string;
}

/** Options for one signing call. An aborted signal fails signing. */
export interface SignOptionsV2 {
  signal?: AbortSignal;
}

/**
 * An external signing provider (SPEC-v2 §3.2). The SDK never trusts its
 * output: every returned signature is verified with the ordinary v2 verifier
 * under the bound key before use. ML-DSA-65 signing may be hedged, so a
 * retry may return different valid bytes; idempotency compares
 * StatementBodyDigest, never signature bytes. No claim is made about any
 * particular HSM or KMS.
 */
export interface SignerV2 {
  /** The complete hybrid public key the provider signs under. Stable. */
  publicKeyV2(): HybridPublicKey;
  /** The ML-DSA-65 input mode the provider implements. */
  modeV2(): SignerModeV2;
  /** Signs one SDK-prepared request. */
  signV2(req: SignRequestV2, signal?: AbortSignal): Promise<HybridSignature>;
}

/** Options for an in-process signer. */
export interface LocalSignerOptionsV2 {
  /**
   * Deterministic ML-DSA-65 (no hedging randomness), for reproducing fixed
   * test vectors only. Production signing is hedged.
   */
  deterministic?: boolean;
}

const localSigners = new WeakSet<object>();

class LocalSignerV2 implements SignerV2 {
  readonly #pair: HybridKeyPairV2;
  readonly #deterministic: boolean;
  constructor(pair: HybridKeyPairV2, deterministic: boolean) {
    this.#pair = {
      publicKey: { ed25519: Uint8Array.from(pair.publicKey.ed25519), ml_dsa_65: Uint8Array.from(pair.publicKey.ml_dsa_65) },
      privateKey: { ed25519: Uint8Array.from(pair.privateKey.ed25519), ml_dsa_65: Uint8Array.from(pair.privateKey.ml_dsa_65) },
    };
    this.#deterministic = deterministic;
    localSigners.add(this);
  }
  publicKeyV2(): HybridPublicKey {
    return { ed25519: Uint8Array.from(this.#pair.publicKey.ed25519), ml_dsa_65: Uint8Array.from(this.#pair.publicKey.ml_dsa_65) };
  }
  modeV2(): SignerModeV2 {
    return SIGNER_MODE_DIRECT_V2;
  }
  async signV2(req: SignRequestV2, signal?: AbortSignal): Promise<HybridSignature> {
    if (signal?.aborted) throw v2Classify("evaluation_cancelled", signal.reason ?? new Error("signing cancelled"));
    if (req.mode !== SIGNER_MODE_DIRECT_V2 || req.message.length !== V2_SIGNING_MESSAGE_SIZE || !req.mlDsaContext || req.mlDsaContext.length === 0) {
      throw new Error("local v2 signer supports only direct-mode requests");
    }
    const ed25519 = await signEd25519Async(req.message, this.#pair.privateKey.ed25519);
    const ml_dsa_65 = ml_dsa65.sign(req.message, this.#pair.privateKey.ml_dsa_65, this.#deterministic
      ? { context: req.mlDsaContext, extraEntropy: false }
      : { context: req.mlDsaContext });
    return { ed25519, ml_dsa_65 };
  }
  async validate(): Promise<void> {
    await validateHybridKeyPairV2(this.#pair);
  }
}

/** A direct-mode SignerV2 backed by an in-process hybrid key pair. */
export async function newLocalSignerV2(pair: HybridKeyPairV2, opts: LocalSignerOptionsV2 = {}): Promise<SignerV2> {
  return classifiedAsync("configuration_invalid", async () => {
    await validateHybridKeyPairV2(pair);
    return new LocalSignerV2(pair, opts.deterministic === true);
  });
}

/**
 * Internal: signs one typed statement with an in-process key pair through
 * the same verified signer path. Used only by typed object signers; never
 * exported from the package entry points.
 */
export async function signV2StatementWithKeyPair(
  objectType: number,
  signable: Uint8Array,
  pair: HybridKeyPairV2,
  opts: { deterministic?: boolean } = {},
): Promise<HybridSignature> {
  const signer = await newLocalSignerV2(pair, { deterministic: opts.deterministic });
  return signV2StatementWithSigner(objectType, signable, signer, await signerPublicKeyV2(signer));
}

/** len("ratify-protocol-signature\x00\x02") + 2 + 48. */
export const V2_SIGNING_MESSAGE_SIZE = 77;

/**
 * The complete public key a signer signs under (Go signerPublicKeyV2). A
 * local signer's key pair is validated first; an external signer's key must
 * have exact component lengths.
 */
export async function signerPublicKeyV2(signer: SignerV2 | null | undefined): Promise<HybridPublicKey> {
  if (!signer) throw v2Errorf("configuration_invalid", "v2 signer is required");
  if (localSigners.has(signer)) await (signer as LocalSignerV2).validate();
  const pub = signer.publicKeyV2();
  try {
    keyIDV2Unclassified(pub);
  } catch (err) {
    throw v2Errorf("configuration_invalid", `v2 signer public key: ${(err as Error).message}`, err);
  }
  return { ed25519: Uint8Array.from(pub.ed25519), ml_dsa_65: Uint8Array.from(pub.ml_dsa_65) };
}

/** FIPS 204 external mu: SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64), tr = SHAKE256(pk, 64). */
export function externalMuV2(mlPub: Uint8Array, mlContext: Uint8Array, message: Uint8Array): Uint8Array {
  const tr = shake256(mlPub, { dkLen: 64 });
  return shake256(concatBytes(tr, new Uint8Array([0x00, mlContext.length]), mlContext, message), { dkLen: 64 });
}

function aborted(signal: AbortSignal | undefined): Error | null {
  if (!signal?.aborted) return null;
  return signal.reason instanceof Error ? signal.reason : new Error("v2 signing cancelled");
}

/**
 * Prepares the typed request, calls the signer, and verifies the returned
 * signature under pub before returning it (Go signV2StatementWithSigner).
 * Internal to the typed object signers; never exported from the package.
 */
export async function signV2StatementWithSigner(
  objectType: number,
  signable: Uint8Array,
  signer: SignerV2,
  pub: HybridPublicKey,
  opts: SignOptionsV2 = {},
): Promise<HybridSignature> {
  const before = aborted(opts.signal);
  if (before) throw v2Classify("evaluation_cancelled", before);
  const message = v2SigningMessage(objectType, signable);
  const mlContext = v2MLDSAContext(objectType);
  const keyId = keyIDV2Unclassified(pub);
  const mode = signer.modeV2();
  let req: SignRequestV2;
  const publicKey = { ed25519: Uint8Array.from(pub.ed25519), ml_dsa_65: Uint8Array.from(pub.ml_dsa_65) };
  if (mode === SIGNER_MODE_DIRECT_V2) {
    req = { mode, message, mlDsaContext: mlContext, mlDsaMu: null, publicKey, keyId };
  } else if (mode === SIGNER_MODE_EXTERNAL_MU_V2) {
    req = { mode, message, mlDsaContext: null, mlDsaMu: externalMuV2(pub.ml_dsa_65, mlContext, message), publicKey, keyId };
  } else {
    throw v2Errorf("configuration_invalid", `v2 signer reports an unsupported mode ${String(mode)}`);
  }
  let signature: HybridSignature;
  try {
    signature = await signer.signV2(req, opts.signal);
  } catch (err) {
    throw v2Classify("configuration_invalid", wrapError("v2 signer", err));
  }
  const after = aborted(opts.signal);
  if (after) throw v2Classify("evaluation_cancelled", after);
  if (!signature || !(signature.ed25519 instanceof Uint8Array) || !(signature.ml_dsa_65 instanceof Uint8Array)) {
    throw v2Errorf("invalid_signature", "v2 signer returned a signature that does not verify: missing component");
  }
  const copy: HybridSignature = { ed25519: Uint8Array.from(signature.ed25519), ml_dsa_65: Uint8Array.from(signature.ml_dsa_65) };
  try {
    await verifyV2Statement(objectType, signable, copy, pub);
  } catch (err) {
    throw v2Errorf("invalid_signature", `v2 signer returned a signature that does not verify: ${(err as Error).message}`, err);
  }
  return copy;
}
