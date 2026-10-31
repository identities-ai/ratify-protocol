import { CURVE, Point, getPublicKeyAsync, signAsync, utils, verifyAsync } from "@noble/ed25519";
import { sha384, sha512 } from "@noble/hashes/sha2";
import { shake256 } from "@noble/hashes/sha3";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { readFile } from "node:fs/promises";
import { canonicalJSON } from "../src/canonical.js";
import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeyIDV2, verifyV2DelegationCertificateSignature } from "../src/index.js";
import type { HybridPublicKey, HybridSignature } from "../src/types.js";

const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const signable = new TextEncoder().encode('{"cert_id":"typescript-v2-kat","version":2}');

function littleEndian(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function littleEndianInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

async function makeRelaxedMixedOrderSignature(
  seed: Uint8Array,
  message: Uint8Array,
  torsion: Point,
  mixInto: "public key" | "R" | "none",
): Promise<{ publicKey: Uint8Array; signature: Uint8Array }> {
  const extended = await utils.getExtendedPublicKeyAsync(seed);
  const r = littleEndianInteger(sha512(concatBytes(extended.prefix, message))) % CURVE.n;
  const publicPoint = mixInto === "public key" ? extended.point.add(torsion) : extended.point;
  const baseRPoint = Point.BASE.multiply(r);
  const rPoint = mixInto === "R" ? baseRPoint.add(torsion) : baseRPoint;
  const publicKey = publicPoint.toBytes();
  const encodedR = rPoint.toBytes();
  const challenge = littleEndianInteger(sha512(concatBytes(encodedR, publicKey, message))) % CURVE.n;
  const scalar = (r + challenge * extended.scalar) % CURVE.n;
  return { publicKey, signature: concatBytes(encodedR, littleEndian(scalar, 32)) };
}

interface DelegationSignatureVector {
  version: number;
  object_type_code: number;
  key_id_v2: string;
  signable_bytes: string;
  message: string;
  mldsa_context: string;
  mldsa_tr: string;
  mldsa_mu: string;
  alternate_mldsa_context: string;
  issuer_seeds: { ed25519: string; ml_dsa_65: string };
  negative_mutations: { xor_mask: number; targets: string[] };
  issuer_public_key: { ed25519: string; ml_dsa_65: string };
  signature: { ed25519: string; ml_dsa_65: string };
}

const sharedVector = JSON.parse(await readFile(
  new URL("../../../testvectors/v2/delegation-signature.json", import.meta.url), "utf8",
)) as DelegationSignatureVector;

test("shared v2 signature vector verifies across SDK implementations", async () => {
  const decode = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "base64"));
  assert.equal(sharedVector.version, 2);
  assert.equal(sharedVector.object_type_code, 1);
  const signableBytes = decode(sharedVector.signable_bytes);
  assert.deepEqual(signableBytes, canonicalJSON(JSON.parse(new TextDecoder().decode(signableBytes))));
  const prefix = new TextEncoder().encode("ratify-protocol-signature");
  const expectedMessage = concatBytes(prefix, new Uint8Array([0, 2, 0, 1]), sha384(signableBytes));
  assert.deepEqual(decode(sharedVector.message), expectedMessage);
  assert.deepEqual(decode(sharedVector.mldsa_context), new TextEncoder().encode("ratify-protocol/2/0001"));
  const publicKey: HybridPublicKey = {
    ed25519: decode(sharedVector.issuer_public_key.ed25519),
    ml_dsa_65: decode(sharedVector.issuer_public_key.ml_dsa_65),
  };
  const signature: HybridSignature = {
    ed25519: decode(sharedVector.signature.ed25519),
    ml_dsa_65: decode(sharedVector.signature.ml_dsa_65),
  };
  const context = decode(sharedVector.mldsa_context);
  const message = decode(sharedVector.message);
  assert.equal(publicKey.ml_dsa_65.length, 1952);
  assert.equal(context.length, 22);
  assert.equal(message.length, 77);
  const tr = shake256(publicKey.ml_dsa_65, { dkLen: 64 });
  const mu = shake256(concatBytes(tr, new Uint8Array([0, context.length]), context, message), { dkLen: 64 });
  assert.deepEqual(tr, decode(sharedVector.mldsa_tr));
  assert.deepEqual(mu, decode(sharedVector.mldsa_mu));
  assert.equal(ml_dsa65.internal.verify(signature.ml_dsa_65, mu, publicKey.ml_dsa_65, { externalMu: true }), true);
  const edSeed = decode(sharedVector.issuer_seeds.ed25519);
  const mlSeed = decode(sharedVector.issuer_seeds.ml_dsa_65);
  const generatedMLDSA = await ml_dsa65.keygen(mlSeed);
  assert.deepEqual(ml_dsa65.internal.sign(mu, generatedMLDSA.secretKey, {
    externalMu: true, extraEntropy: false,
  }), signature.ml_dsa_65);
  const mutatedMu = mu.slice();
  mutatedMu[0] ^= 1;
  assert.equal(ml_dsa65.internal.verify(signature.ml_dsa_65, mutatedMu, publicKey.ml_dsa_65, { externalMu: true }), false);
  for (const wrongContext of [decode(sharedVector.alternate_mldsa_context), new Uint8Array()]) {
    const wrongMu = shake256(concatBytes(tr, new Uint8Array([0, wrongContext.length]), wrongContext, message), { dkLen: 64 });
    assert.equal(ml_dsa65.internal.verify(signature.ml_dsa_65, wrongMu, publicKey.ml_dsa_65, { externalMu: true }), false);
  }
  assert.deepEqual(await getPublicKeyAsync(edSeed), publicKey.ed25519);
  assert.deepEqual(generatedMLDSA.publicKey, publicKey.ml_dsa_65);
  assert.equal(deriveKeyIDV2(publicKey), sharedVector.key_id_v2);
  assert.deepEqual(await signAsync(decode(sharedVector.message), edSeed), signature.ed25519);
  assert.deepEqual(await ml_dsa65.sign(decode(sharedVector.message), generatedMLDSA.secretKey, {
    context: decode(sharedVector.mldsa_context),
    extraEntropy: false,
  }), signature.ml_dsa_65);
  assert.equal(await verifyV2DelegationCertificateSignature(signableBytes, signature, publicKey), true);
  const wrongContextSignature = {
    ...signature,
    ml_dsa_65: await ml_dsa65.sign(decode(sharedVector.message), generatedMLDSA.secretKey, {
      context: decode(sharedVector.alternate_mldsa_context),
      extraEntropy: false,
    }),
  };
  assert.equal(await verifyV2DelegationCertificateSignature(signableBytes, wrongContextSignature, publicKey), false);
  assert.deepEqual([...sharedVector.negative_mutations.targets].sort(), [
    "signable_bytes", "signature.ed25519", "signature.ml_dsa_65",
    "issuer_public_key.ed25519", "issuer_public_key.ml_dsa_65",
  ].sort());
  for (const target of sharedVector.negative_mutations.targets) {
    const mutatedSignable = signableBytes.slice();
    const mutatedSignature = {
      ed25519: signature.ed25519.slice(),
      ml_dsa_65: signature.ml_dsa_65.slice(),
    };
    const mutatedPublicKey = {
      ed25519: publicKey.ed25519.slice(),
      ml_dsa_65: publicKey.ml_dsa_65.slice(),
    };
    switch (target) {
      case "signable_bytes":
        mutatedSignable[0] ^= sharedVector.negative_mutations.xor_mask;
        break;
      case "signature.ed25519":
        mutatedSignature.ed25519[0] ^= sharedVector.negative_mutations.xor_mask;
        break;
      case "signature.ml_dsa_65":
        mutatedSignature.ml_dsa_65[0] ^= sharedVector.negative_mutations.xor_mask;
        break;
      case "issuer_public_key.ed25519":
        mutatedPublicKey.ed25519[0] ^= sharedVector.negative_mutations.xor_mask;
        break;
      case "issuer_public_key.ml_dsa_65":
        mutatedPublicKey.ml_dsa_65[0] ^= sharedVector.negative_mutations.xor_mask;
        break;
      default:
        assert.fail(`unknown shared vector mutation target ${target}`);
    }
    assert.equal(await verifyV2DelegationCertificateSignature(mutatedSignable, mutatedSignature, mutatedPublicKey), false,
      `accepted shared vector mutation ${target}`);
  }
});

test("v2 key ID matches the Go known answer and uses all 256 digest bits", async () => {
  const edSeed = new Uint8Array(32);
  edSeed[0] = 1;
  const mlSeed = new Uint8Array(32);
  mlSeed[0] = 2;
  const mlPair = await ml_dsa65.keygen(mlSeed);
  const publicKey: HybridPublicKey = {
    ed25519: await getPublicKeyAsync(edSeed),
    ml_dsa_65: mlPair.publicKey,
  };
  assert.equal(deriveKeyIDV2(publicKey), "31e31007b20edf49d044f5413f952d94e3d95f51a3cd85f131aa5856ef0bfa2f");
  assert.equal(deriveKeyIDV2(publicKey).length, 64);
  assert.throws(() => deriveKeyIDV2({ ...publicKey, ed25519: publicKey.ed25519.slice(1) }));
  assert.throws(() => deriveKeyIDV2({ ...publicKey, ml_dsa_65: publicKey.ml_dsa_65.slice(1) }));
  assert.throws(() => deriveKeyIDV2(null as unknown as HybridPublicKey),
    /v2 hybrid public key has invalid component length/);
  assert.throws(() => deriveKeyIDV2({ ...publicKey, ed25519: Array.from(publicKey.ed25519) } as unknown as HybridPublicKey),
    /v2 hybrid public key has invalid component length/);
});

test("v2 delegation verifier requires strict Ed25519 and both hybrid components", async () => {
  const edSeed = new Uint8Array(32);
  edSeed[0] = 3;
  const mlSeed = new Uint8Array(32);
  mlSeed[0] = 4;
  const mlPair = await ml_dsa65.keygen(mlSeed);
  const publicKey: HybridPublicKey = {
    ed25519: await getPublicKeyAsync(edSeed),
    ml_dsa_65: mlPair.publicKey,
  };
  const message = concatBytes(
    new TextEncoder().encode("ratify-protocol-signature\0\x02"),
    new Uint8Array([0, 1]),
    sha384(signable),
  );
  const signature: HybridSignature = {
    ed25519: await signAsync(message, edSeed),
    ml_dsa_65: await ml_dsa65.sign(message, mlPair.secretKey, {
      context: new TextEncoder().encode("ratify-protocol/2/0001"),
      extraEntropy: false,
    }),
  };
  assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, publicKey), true);
  const wrongContextSignature: HybridSignature = {
    ...signature,
    ml_dsa_65: await ml_dsa65.sign(message, mlPair.secretKey, {
      context: new TextEncoder().encode("ratify-protocol/2/0002"),
      extraEntropy: false,
    }),
  };
  assert.equal(await verifyV2DelegationCertificateSignature(signable, wrongContextSignature, publicKey), false);
  assert.equal(await verifyV2DelegationCertificateSignature(
    signable,
    null as unknown as HybridSignature,
    publicKey,
  ), false);
  assert.equal(await verifyV2DelegationCertificateSignature(
    signable,
    { ...signature, ed25519: Array.from(signature.ed25519) } as unknown as HybridSignature,
    publicKey,
  ), false);
  assert.equal(await verifyV2DelegationCertificateSignature(
    signable,
    { ...signature, ed25519: new Uint8ClampedArray(signature.ed25519) } as unknown as HybridSignature,
    publicKey,
  ), false);
  assert.equal(await verifyV2DelegationCertificateSignature(
    signable,
    signature,
    null as unknown as HybridPublicKey,
  ), false);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, {
    ...publicKey,
    ed25519: publicKey.ed25519.slice(1),
  }), false);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, {
    ...publicKey,
    ml_dsa_65: publicKey.ml_dsa_65.slice(1),
  }), false);
  const throwingSignature = Object.defineProperty({}, "ed25519", {
    get() { throw new Error("malformed signature getter"); },
  });
  assert.equal(await verifyV2DelegationCertificateSignature(
    signable,
    throwingSignature as HybridSignature,
    publicKey,
  ), false);
  assert.equal(await verifyV2DelegationCertificateSignature(
    undefined as unknown as Uint8Array,
    signature,
    publicKey,
  ), false);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, {
    ...signature,
    ed25519: signature.ed25519.slice(1),
  }, publicKey), false);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, {
    ...signature,
    ml_dsa_65: signature.ml_dsa_65.slice(1),
  }, publicKey), false);

  const changedSignable = concatBytes(signable, new Uint8Array([0x20]));
  assert.equal(await verifyV2DelegationCertificateSignature(changedSignable, signature, publicKey), false);

  const badMLDSA = { ...signature, ml_dsa_65: signature.ml_dsa_65.slice() };
  badMLDSA.ml_dsa_65[0] ^= 1;
  assert.equal(await verifyV2DelegationCertificateSignature(signable, badMLDSA, publicKey), false);

  const identity = new Uint8Array(32);
  identity[0] = 1;
  const badR = { ...signature, ed25519: signature.ed25519.slice() };
  badR.ed25519.set(identity, 0);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, badR, publicKey), false);

  const orderTwoEncoding = new Uint8Array(32).fill(0xff);
  orderTwoEncoding[0] = 0xec;
  orderTwoEncoding[31] = 0x7f;
  const orderTwo = Point.fromBytes(orderTwoEncoding, false);
  const keyPoint = Point.fromBytes(publicKey.ed25519, false);
  const mixedOrderR = keyPoint.add(orderTwo).toBytes();
  assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, {
    ...publicKey,
    ed25519: mixedOrderR,
  }), false);
  const badMixedR = { ...signature, ed25519: signature.ed25519.slice() };
  badMixedR.ed25519.set(mixedOrderR, 0);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, badMixedR, publicKey), false);

  // Noble verifies with the cofactored equation, so the added low-order
  // component is erased by multiplying by eight. Ratify must reject these
  // signatures before reaching that equation.
  const baseline = await makeRelaxedMixedOrderSignature(edSeed, message, orderTwo, "none");
  assert.deepEqual(baseline.signature, signature.ed25519, "test signer must reproduce ordinary Ed25519 signatures");
  for (const mixInto of ["public key", "R"] as const) {
    const malformed = await makeRelaxedMixedOrderSignature(edSeed, message, orderTwo, mixInto);
    const relaxedAccepted = await verifyAsync(
      malformed.signature,
      message,
      malformed.publicKey,
      { zip215: true },
    );
    assert.equal(relaxedAccepted, true, `fixture must pass relaxed Ed25519 when torsion is mixed into ${mixInto}`);
    assert.equal(await verifyV2DelegationCertificateSignature(signable, {
      ed25519: malformed.signature,
      ml_dsa_65: signature.ml_dsa_65,
    }, {
      ed25519: malformed.publicKey,
      ml_dsa_65: publicKey.ml_dsa_65,
    }), false, `v2 must reject mixed-order ${mixInto}`);
  }

  const badS = { ...signature, ed25519: signature.ed25519.slice() };
  badS.ed25519.set(new Uint8Array([
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  ]), 32);
  assert.equal(await verifyV2DelegationCertificateSignature(signable, badS, publicKey), false);
  badS.ed25519[32] = 0xee; // L + 1 in little-endian form.
  assert.equal(await verifyV2DelegationCertificateSignature(signable, badS, publicKey), false);

  const identityKey = { ...publicKey, ed25519: identity };
  assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, identityKey), false);

  const torsionEncodings = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  ];
  for (const encoded of torsionEncodings) {
    const point = Uint8Array.from(Buffer.from(encoded, "hex"));
    assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, {
      ...publicKey,
      ed25519: point,
    }), false, `accepted torsion public key ${encoded}`);
    const torsionR = { ...signature, ed25519: signature.ed25519.slice() };
    torsionR.ed25519.set(point, 0);
    assert.equal(await verifyV2DelegationCertificateSignature(signable, torsionR, publicKey), false,
      `accepted torsion R ${encoded}`);
  }

  const nonCanonicalYEqualsP = new Uint8Array(32).fill(0xff);
  nonCanonicalYEqualsP[0] = 0xed;
  nonCanonicalYEqualsP[31] = 0x7f;
  assert.throws(() => Point.fromBytes(nonCanonicalYEqualsP, false));
  const negativeZero = new Uint8Array(32);
  negativeZero[0] = 1;
  negativeZero[31] = 0x80;
  for (const [name, invalidPoint] of [["y=p", nonCanonicalYEqualsP], ["negative zero", negativeZero]] as const) {
    assert.equal(await verifyV2DelegationCertificateSignature(signable, signature, {
      ...publicKey,
      ed25519: invalidPoint,
    }), false, `accepted ${name} public key`);
    const invalidR = { ...signature, ed25519: signature.ed25519.slice() };
    invalidR.ed25519.set(invalidPoint, 0);
    assert.equal(await verifyV2DelegationCertificateSignature(signable, invalidR, publicKey), false,
      `accepted ${name} R point`);
  }
});
