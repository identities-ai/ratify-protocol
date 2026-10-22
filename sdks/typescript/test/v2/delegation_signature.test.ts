// testvectors/v2/delegation-signature.json and derive-external-mu.py: the
// signing transcript M, the ML-DSA context, FIPS 204 external-mu tr and mu,
// deterministic hybrid signatures, and common negative mutations (SPEC-v2
// §3.1). Also exercises the external signer interface (§3.2) in direct and
// external-mu modes against the same key.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { sha384 } from "@noble/hashes/sha2";
import { shake256 } from "@noble/hashes/sha3";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { hybridKeypairFromSeeds } from "../../src/crypto.js";
import { deriveKeyIDV2, v2MLDSAContext, v2SigningMessage, verifyV2Statement } from "../../src/crypto_v2.js";
import { concatBytes } from "../../src/json_v2.js";
import { decodeDelegationCertV2, encodeDelegationCertV2, signDelegationCertV2WithSigner, verifyDelegationCertV2Signature, type DelegationCertV2 } from "../../src/protocol_v2_wire.js";
import {
  SIGNER_MODE_DIRECT_V2,
  SIGNER_MODE_EXTERNAL_MU_V2,
  externalMuV2,
  keyIDV2,
  newLocalSignerV2,
  type SignRequestV2,
  type SignerModeV2,
  type SignerV2,
} from "../../src/signer_v2.js";
import type { HybridPublicKey, HybridSignature } from "../../src/types.js";
import { VECTOR_DIR, classOfAsync, corpusKeyPairs, eqBytes, load, pubOf, unb64 } from "./helpers.js";

const f = load("delegation-signature.json");
const signable = unb64(f.signable_bytes);
const message = unb64(f.message);
const context = unb64(f.mldsa_context);
const key = pubOf(f.issuer_public_key);
const sig: HybridSignature = { ed25519: unb64(f.signature.ed25519), ml_dsa_65: unb64(f.signature.ml_dsa_65) };

test("delegation-signature.json: transcript, context, and key ID", () => {
  assert.equal(f.version, 2);
  assert.equal(f.object_type_code, 1);
  assert.ok(eqBytes(message, concatBytes(new TextEncoder().encode("ratify-protocol-signature\0\x02"), new Uint8Array([0, 1]), sha384(signable))));
  assert.ok(eqBytes(v2SigningMessage(f.object_type_code, signable), message));
  assert.equal(message.length, 77);
  assert.ok(eqBytes(v2MLDSAContext(1), context));
  assert.equal(new TextDecoder().decode(context), "ratify-protocol/2/0001");
  assert.ok(eqBytes(v2MLDSAContext(2), unb64(f.alternate_mldsa_context)));
  assert.equal(deriveKeyIDV2(key), f.key_id_v2);
  assert.equal(keyIDV2(key), f.key_id_v2);
});

test("derive-external-mu.py: tr and mu recomputed from the fixture", () => {
  // The script recomputes tr = SHAKE256(pk, 64) and
  // mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64); this runner does
  // the same computation and the SDK helper must agree.
  const script = join(VECTOR_DIR, "derive-external-mu.py");
  assert.ok(existsSync(script));
  assert.match(readFileSync(script, "utf8"), /shake_256/);
  const tr = shake256(key.ml_dsa_65, { dkLen: 64 });
  const mu = shake256(concatBytes(tr, new Uint8Array([0x00, context.length]), context, message), { dkLen: 64 });
  assert.ok(eqBytes(tr, unb64(f.mldsa_tr)));
  assert.ok(eqBytes(mu, unb64(f.mldsa_mu)));
  assert.ok(eqBytes(externalMuV2(key.ml_dsa_65, context, message), mu));
  assert.equal(ml_dsa65.internal.verify(sig.ml_dsa_65, mu, key.ml_dsa_65, { externalMu: true }), true);
});

test("delegation-signature.json: deterministic signatures reproduce from seeds", async () => {
  const edSeed = unb64(f.issuer_seeds.ed25519);
  const mlSeed = unb64(f.issuer_seeds.ml_dsa_65);
  assert.ok(eqBytes(await getPublicKeyAsync(edSeed), key.ed25519));
  const mlKeys = ml_dsa65.keygen(mlSeed);
  assert.ok(eqBytes(mlKeys.publicKey, key.ml_dsa_65));
  assert.ok(eqBytes(await signAsync(message, edSeed), sig.ed25519));
  assert.ok(eqBytes(ml_dsa65.sign(message, mlKeys.secretKey, { context, extraEntropy: false }), sig.ml_dsa_65));
  const mu = unb64(f.mldsa_mu);
  assert.ok(eqBytes(ml_dsa65.internal.sign(mu, mlKeys.secretKey, { externalMu: true, extraEntropy: false }), sig.ml_dsa_65));
});

test("delegation-signature.json: typed verification and negative mutations", async () => {
  await verifyV2Statement(1, signable, sig, key);
  assert.equal(await classOfAsync(() => verifyV2Statement(2, signable, sig, key)), "invalid_signature");
  for (const code of [0x0000, 0x000a, 0xffff]) {
    assert.equal(await classOfAsync(() => verifyV2Statement(code, signable, sig, key)), "unsupported_object_type");
  }
  const m = f.negative_mutations;
  assert.deepEqual([...m.targets].sort(), ["issuer_public_key.ed25519", "issuer_public_key.ml_dsa_65", "signable_bytes", "signature.ed25519", "signature.ml_dsa_65"]);
  for (const target of m.targets as string[]) {
    const s = signable.slice();
    const g = { ed25519: sig.ed25519.slice(), ml_dsa_65: sig.ml_dsa_65.slice() };
    const k = { ed25519: key.ed25519.slice(), ml_dsa_65: key.ml_dsa_65.slice() };
    const flip = (b: Uint8Array) => {
      b[0] = b[0]! ^ m.xor_mask;
    };
    if (target === "signable_bytes") flip(s);
    else if (target === "signature.ed25519") flip(g.ed25519);
    else if (target === "signature.ml_dsa_65") flip(g.ml_dsa_65);
    else if (target === "issuer_public_key.ed25519") flip(k.ed25519);
    else flip(k.ml_dsa_65);
    assert.equal(await classOfAsync(() => verifyV2Statement(1, s, g, k)), "invalid_signature", target);
  }
});

// ---------------------------------------------------------------------------
// External signer interface (SPEC-v2 §3.2).

interface ExternalOptions {
  mode: SignerModeV2;
  publicKey?: HybridPublicKey;
  corrupt?: "ed25519" | "ml_dsa_65" | "missing";
  fail?: boolean;
  requests?: SignRequestV2[];
}

async function externalSigner(seedName: string, opts: ExternalOptions): Promise<SignerV2> {
  const k = (await corpusKeyPairs()).get(seedName)!;
  const { privateKey, publicKey } = k;
  return {
    publicKeyV2: () => opts.publicKey ?? publicKey,
    modeV2: () => opts.mode,
    async signV2(req: SignRequestV2): Promise<HybridSignature> {
      opts.requests?.push(req);
      if (opts.fail) throw new Error("provider unavailable");
      const ed25519 = await signAsync(req.message, privateKey.ed25519);
      const ml_dsa_65 = req.mode === SIGNER_MODE_EXTERNAL_MU_V2
        ? ml_dsa65.internal.sign(req.mlDsaMu!, privateKey.ml_dsa_65, { externalMu: true })
        : ml_dsa65.sign(req.message, privateKey.ml_dsa_65, { context: req.mlDsaContext! });
      if (opts.corrupt === "ed25519") ed25519[1] = ed25519[1]! ^ 1;
      if (opts.corrupt === "ml_dsa_65") ml_dsa_65[1] = ml_dsa_65[1]! ^ 1;
      if (opts.corrupt === "missing") return { ed25519, ml_dsa_65: new Uint8Array(0) };
      return { ed25519, ml_dsa_65 };
    },
  };
}

async function unsignedCert(): Promise<DelegationCertV2> {
  const keys = await corpusKeyPairs();
  const issuer = keys.get("root")!.publicKey;
  const subject = keys.get("agent")!.publicKey;
  return {
    version: 2, cert_id: "external-signer-cert", issuer_id: keyIDV2(issuer), issuer_pub_key: issuer,
    subject_id: keyIDV2(subject), subject_pub_key: subject, scope: ["data:read"], constraints: [],
    issued_at: 1_800_000_000, expires_at: 1_800_086_400,
    signature: { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) },
  };
}

test("external signer: direct and external-mu modes produce verifying certificates", async () => {
  for (const mode of [SIGNER_MODE_DIRECT_V2, SIGNER_MODE_EXTERNAL_MU_V2] as SignerModeV2[]) {
    const requests: SignRequestV2[] = [];
    const signer = await externalSigner("root", { mode, requests });
    const signed = await signDelegationCertV2WithSigner(await unsignedCert(), signer);
    await verifyDelegationCertV2Signature(decodeDelegationCertV2(encodeDelegationCertV2(signed)));
    assert.equal(requests.length, 1);
    const req = requests[0]!;
    assert.equal(req.message.length, 77);
    assert.equal(req.keyId, signed.issuer_id);
    if (mode === SIGNER_MODE_DIRECT_V2) {
      assert.equal(new TextDecoder().decode(req.mlDsaContext!), "ratify-protocol/2/0001");
      assert.equal(req.mlDsaMu, null);
    } else {
      assert.equal(req.mlDsaContext, null);
      assert.ok(eqBytes(req.mlDsaMu!, externalMuV2(signed.issuer_pub_key.ml_dsa_65, v2MLDSAContext(1), req.message)));
    }
  }
});

test("external signer: invalid components, key mismatch, provider errors, and cancellation fail signing", async () => {
  const cert = await unsignedCert();
  for (const corrupt of ["ed25519", "ml_dsa_65", "missing"] as const) {
    await assert.rejects(signDelegationCertV2WithSigner(cert, await externalSigner("root", { mode: SIGNER_MODE_EXTERNAL_MU_V2, corrupt })), /does not verify/, corrupt);
  }
  const other = (await corpusKeyPairs()).get("intermediate")!.publicKey;
  const requests: SignRequestV2[] = [];
  await assert.rejects(signDelegationCertV2WithSigner(cert, await externalSigner("root", { mode: SIGNER_MODE_DIRECT_V2, publicKey: other, requests })), /does not match/);
  assert.equal(requests.length, 0, "a key-binding mismatch never calls the provider");
  await assert.rejects(signDelegationCertV2WithSigner(cert, await externalSigner("root", { mode: SIGNER_MODE_DIRECT_V2, fail: true })), /provider unavailable/);
  await assert.rejects(signDelegationCertV2WithSigner(cert, await externalSigner("root", { mode: 7 as SignerModeV2 })), /unsupported mode/);
  const controller = new AbortController();
  controller.abort();
  const before: SignRequestV2[] = [];
  await assert.rejects(signDelegationCertV2WithSigner(cert, await externalSigner("root", { mode: SIGNER_MODE_DIRECT_V2, requests: before }), { signal: controller.signal }));
  assert.equal(before.length, 0);
});

test("external signer: hedged local signing yields different valid bytes over the same body", async () => {
  const pair = (await corpusKeyPairs()).get("root")!;
  const cert = await unsignedCert();
  const a = await signDelegationCertV2WithSigner(cert, await newLocalSignerV2(pair));
  const b = await signDelegationCertV2WithSigner(cert, await newLocalSignerV2(pair));
  assert.ok(!eqBytes(a.signature.ml_dsa_65, b.signature.ml_dsa_65));
  const d1 = await signDelegationCertV2WithSigner(cert, await newLocalSignerV2(pair, { deterministic: true }));
  const d2 = await signDelegationCertV2WithSigner(cert, await newLocalSignerV2(pair, { deterministic: true }));
  assert.ok(eqBytes(d1.signature.ml_dsa_65, d2.signature.ml_dsa_65));
  const seeds = load("keys.json").keys.find((k: { name: string }) => k.name === "root");
  const again = await hybridKeypairFromSeeds(Buffer.from(seeds.ed25519_seed_hex, "hex"), Buffer.from(seeds.ml_dsa_65_seed_hex, "hex"));
  assert.ok(eqBytes(again.publicKey.ed25519, pair.publicKey.ed25519));
});
