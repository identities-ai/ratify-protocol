// The external signer interface (SPEC-v2 §3.2): direct and external-mu
// modes, verify-before-use, key binding, cancellation, and provider errors.
// The external-mu provider is emulated in software; no HSM or KMS is claimed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { signAsync as signEd25519Async } from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { v2MLDSAContext, v2SigningMessage, type HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { base64Encode } from "../../src/json_v2.js";
import { decodeKeyRotationStatementV2, encodeKeyRotationStatementV2, signKeyRotationStatementV2WithSigners } from "../../src/key_rotation_v2.js";
import {
  decodeDelegationCertV2,
  decodeProofBundleV2,
  decodeRevocationListV2,
  decodeRevocationPushV2,
  delegationCertV2SignBytes,
  encodeDelegationCertV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  encodeRevocationPushV2,
  signDelegationCertV2WithSigner,
  signProofBundleV2WithSigner,
  signRevocationListV2WithSigner,
  signRevocationPushV2WithSigner,
  verifyDelegationCertV2Signature,
  type DelegationCertV2,
} from "../../src/protocol_v2_wire.js";
import { decodeTransactionReceiptV2, encodeTransactionReceiptV2, signTransactionReceiptPartyV2WithSigner } from "../../src/transaction_receipt_v2.js";
import { decodeVerificationReceiptV2, encodeVerificationReceiptV2, signVerificationReceiptV2WithSigner } from "../../src/verification_receipt_v2.js";
import { decodeWitnessEntryV2, encodeWitnessEntryV2, signWitnessEntryV2WithSigner } from "../../src/witness_v2.js";
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
import { corpusKeyPairs, eqBytes, load, unb64, type Any } from "./helpers.js";

/** A software external-mu provider: it sees only M (Ed25519) and mu (ML-DSA). */
class ExternalMuSigner implements SignerV2 {
  requests: SignRequestV2[] = [];
  constructor(private readonly pair: HybridKeyPairV2, private readonly deterministic = false) {}
  publicKeyV2(): HybridPublicKey {
    return this.pair.publicKey;
  }
  modeV2(): SignerModeV2 {
    return SIGNER_MODE_EXTERNAL_MU_V2;
  }
  async signV2(req: SignRequestV2): Promise<HybridSignature> {
    this.requests.push(req);
    assert.equal(req.mode, SIGNER_MODE_EXTERNAL_MU_V2);
    assert.ok(req.mlDsaMu && req.mlDsaMu.length === 64 && req.mlDsaContext === null);
    const ed25519 = await signEd25519Async(req.message, this.pair.privateKey.ed25519);
    const ml_dsa_65 = ml_dsa65.internal.sign(req.mlDsaMu, this.pair.privateKey.ml_dsa_65, {
      externalMu: true, ...(this.deterministic ? { extraEntropy: false } : {}),
    });
    return { ed25519, ml_dsa_65 };
  }
}

/** Wraps a signer and lets a test rewrite its answer or report a key. */
class ScriptedSigner implements SignerV2 {
  calls = { publicKey: 0, mode: 0, sign: 0 };
  requests: SignRequestV2[] = [];
  constructor(
    private readonly inner: SignerV2,
    private readonly script: {
      publicKey?: HybridPublicKey;
      mode?: SignerModeV2;
      rewrite?: (sig: HybridSignature) => HybridSignature;
      fail?: Error;
      onSign?: () => void;
    } = {},
  ) {}
  publicKeyV2(): HybridPublicKey {
    this.calls.publicKey++;
    return this.script.publicKey ?? this.inner.publicKeyV2();
  }
  modeV2(): SignerModeV2 {
    this.calls.mode++;
    return this.script.mode ?? this.inner.modeV2();
  }
  async signV2(req: SignRequestV2, signal?: AbortSignal): Promise<HybridSignature> {
    this.calls.sign++;
    this.requests.push(req);
    this.script.onSign?.();
    if (this.script.fail) throw this.script.fail;
    const sig = await this.inner.signV2(req, signal);
    return this.script.rewrite ? this.script.rewrite(sig) : sig;
  }
}

const objects = load("objects.json");
const certObject: Any = objects.objects.find((o: Any) => o.name === "delegation_root_to_intermediate");

async function fixture(): Promise<{ cert: DelegationCertV2; issuer: HybridKeyPairV2; other: HybridKeyPairV2; pinned: Any }> {
  const keys = await corpusKeyPairs();
  const cert = decodeDelegationCertV2(unb64(certObject.wire_b64));
  const pinned = certObject.signatures[0];
  const issuer = keys.get(pinned.signer)!;
  const other = [...keys.entries()].find(([name]) => name !== pinned.signer)![1];
  return { cert, issuer, other, pinned };
}

async function refused(fn: () => Promise<unknown>): Promise<Error> {
  try {
    await fn();
  } catch (err) {
    return err as Error;
  }
  assert.fail("signing succeeded");
}

test("external signer: external-mu mode reproduces the deterministic fixture signature", async () => {
  const { cert, issuer, pinned } = await fixture();
  const signer = new ExternalMuSigner(issuer, true);
  const signed = await signDelegationCertV2WithSigner(cert, signer);
  await verifyDelegationCertV2Signature(signed);
  assert.equal(signer.requests.length, 1);
  const req = signer.requests[0]!;
  const message = v2SigningMessage(1, delegationCertV2SignBytes(cert));
  assert.ok(eqBytes(req.message, message) && req.message.length === 77, "provider receives exactly M");
  assert.ok(eqBytes(req.mlDsaMu!, unb64(pinned.mldsa_mu_b64)), "provider receives exactly the fixture mu");
  assert.ok(eqBytes(req.mlDsaMu!, externalMuV2(issuer.publicKey.ml_dsa_65, v2MLDSAContext(1), message)));
  assert.equal(req.keyId, keyIDV2(issuer.publicKey));
  assert.equal(base64Encode(signed.signature.ml_dsa_65), pinned.signature.ml_dsa_65, "external-mu signature equals deterministic direct signature");
  assert.equal(base64Encode(signed.signature.ed25519), pinned.signature.ed25519);
});

test("external signer: hedged external-mu and direct providers both verify", async () => {
  const { cert, issuer } = await fixture();
  const a = await signDelegationCertV2WithSigner(cert, new ExternalMuSigner(issuer));
  const b = await signDelegationCertV2WithSigner(cert, new ExternalMuSigner(issuer));
  await verifyDelegationCertV2Signature(a);
  await verifyDelegationCertV2Signature(b);
  assert.ok(!eqBytes(a.signature.ml_dsa_65, b.signature.ml_dsa_65), "hedged signatures differ");
  const direct = new ScriptedSigner(await newLocalSignerV2(issuer));
  await verifyDelegationCertV2Signature(await signDelegationCertV2WithSigner(cert, direct));
  const req = direct.requests[0]!;
  assert.equal(req.mode, SIGNER_MODE_DIRECT_V2);
  assert.equal(new TextDecoder().decode(req.mlDsaContext!), "ratify-protocol/2/0001");
  assert.equal(req.mlDsaMu, null);
});

test("external signer: a key-binding mismatch refuses before signing", async () => {
  const { cert, issuer, other } = await fixture();
  const signer = new ScriptedSigner(await newLocalSignerV2(issuer), { publicKey: other.publicKey });
  await refused(() => signDelegationCertV2WithSigner(cert, signer));
  assert.equal(signer.calls.sign, 0, "a mismatched key must not reach the provider");
  const wrongLength = new ScriptedSigner(await newLocalSignerV2(issuer), { publicKey: { ed25519: new Uint8Array(31), ml_dsa_65: issuer.publicKey.ml_dsa_65 } });
  await refused(() => signDelegationCertV2WithSigner(cert, wrongLength));
  assert.equal(wrongLength.calls.sign, 0);
});

test("external signer: an invalid or missing returned component fails with no object", async () => {
  const { cert, issuer, other } = await fixture();
  const otherSigner = await newLocalSignerV2(other);
  const cases: [string, (s: HybridSignature) => HybridSignature][] = [
    ["flipped ML-DSA byte", (s) => {
      const ml = Uint8Array.from(s.ml_dsa_65);
      ml[10]! ^= 1;
      return { ...s, ml_dsa_65: ml };
    }],
    ["flipped Ed25519 byte", (s) => {
      const ed = Uint8Array.from(s.ed25519);
      ed[40]! ^= 1;
      return { ...s, ed25519: ed };
    }],
    ["missing Ed25519", (s) => ({ ml_dsa_65: s.ml_dsa_65 } as unknown as HybridSignature)],
    ["missing ML-DSA", (s) => ({ ed25519: s.ed25519 } as unknown as HybridSignature)],
    ["short ML-DSA", (s) => ({ ...s, ml_dsa_65: s.ml_dsa_65.subarray(0, 100) })],
    ["swapped empty", () => ({ ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) })],
  ];
  for (const [label, rewrite] of cases) {
    const signer = new ScriptedSigner(await newLocalSignerV2(issuer), { rewrite });
    const err = await refused(() => signDelegationCertV2WithSigner(cert, signer));
    assert.match(err.message, /does not verify|signature/, label);
  }
  // A component produced by another key fails verification under the bound key.
  const capture = new ScriptedSigner(otherSigner, { publicKey: issuer.publicKey });
  const err = await refused(() => signDelegationCertV2WithSigner(cert, capture));
  assert.match(err.message, /does not verify/);
});

test("external signer: cancellation and provider errors return no object", async () => {
  const { cert, issuer } = await fixture();
  const before = new AbortController();
  before.abort(new Error("cancelled by caller"));
  const early = new ScriptedSigner(await newLocalSignerV2(issuer));
  await refused(() => signDelegationCertV2WithSigner(cert, early, { signal: before.signal }));
  assert.equal(early.calls.sign, 0, "an aborted call never reaches the provider");

  const during = new AbortController();
  const late = new ScriptedSigner(await newLocalSignerV2(issuer), { onSign: () => during.abort(new Error("cancelled while signing")) });
  const lateErr = await refused(() => signDelegationCertV2WithSigner(cert, late, { signal: during.signal }));
  assert.match(lateErr.message, /cancelled/);

  const failing = new ScriptedSigner(await newLocalSignerV2(issuer), { fail: new Error("provider timeout") });
  assert.match((await refused(() => signDelegationCertV2WithSigner(cert, failing))).message, /provider timeout/);

  const badMode = new ScriptedSigner(await newLocalSignerV2(issuer), { mode: 7 as unknown as SignerModeV2 });
  await refused(() => signDelegationCertV2WithSigner(cert, badMode));
  assert.equal(badMode.calls.sign, 0);

  // A local direct signer refuses an external-mu request.
  const local = await newLocalSignerV2(issuer);
  const misuse = new ScriptedSigner(local, { mode: SIGNER_MODE_EXTERNAL_MU_V2 });
  await refused(() => signDelegationCertV2WithSigner(cert, misuse));
});

test("external signer: every typed signer reproduces objects.json through an external-mu provider", async () => {
  const keys = await corpusKeyPairs();
  const mu = (name: string) => new ExternalMuSigner(keys.get(name)!, true);
  const obj = (name: string) => objects.objects.find((o: Any) => o.name === name);
  const wire = (name: string) => unb64(obj(name).wire_b64);
  const same = (a: Uint8Array, b: Uint8Array, label: string) => assert.ok(eqBytes(a, b), `${label}: re-signed object differs from the fixture`);

  same(encodeDelegationCertV2(await signDelegationCertV2WithSigner(decodeDelegationCertV2(wire("delegation_with_every_v2_constraint_shape")), mu("intermediate"))),
    wire("delegation_with_every_v2_constraint_shape"), "certificate");
  for (const name of ["proof_bundle_two_link_bound_context", "proof_bundle_empty_chain_stream_bound"]) {
    same(encodeProofBundleV2(await signProofBundleV2WithSigner(decodeProofBundleV2(wire(name)), mu("agent"))), wire(name), name);
  }
  const issuerID = obj("revocation_list").verify.bound_issuer_id;
  const statusKey = keys.get("status_root")!.publicKey;
  same(encodeRevocationListV2(await signRevocationListV2WithSigner(decodeRevocationListV2(wire("revocation_list")), issuerID, statusKey, mu("status_root"))),
    wire("revocation_list"), "list");
  same(encodeRevocationPushV2(await signRevocationPushV2WithSigner(decodeRevocationPushV2(wire("revocation_push")), issuerID, statusKey, mu("status_root"))),
    wire("revocation_push"), "push");
  same(encodeKeyRotationStatementV2(await signKeyRotationStatementV2WithSigners(decodeKeyRotationStatementV2(wire("key_rotation_genesis")),
    mu("rotation_genesis"), mu("rotation_second"))), wire("key_rotation_genesis"), "rotation");
  same(encodeWitnessEntryV2(await signWitnessEntryV2WithSigner(decodeWitnessEntryV2(wire("witness_entry_genesis")), mu("witness"))),
    wire("witness_entry_genesis"), "witness");
  same(encodeVerificationReceiptV2(await signVerificationReceiptV2WithSigner(decodeVerificationReceiptV2(wire("verification_receipt_allow_genesis")), mu("verifier"))),
    wire("verification_receipt_allow_genesis"), "receipt");
  const tx = await decodeTransactionReceiptV2(wire("transaction_receipt_two_parties"));
  const sigA = await signTransactionReceiptPartyV2WithSigner(tx, "party-a", mu("agent"));
  const sigB = await signTransactionReceiptPartyV2WithSigner(tx, "party-b", mu("party_b_agent"));
  same(await encodeTransactionReceiptV2({ ...tx, party_signatures: [sigA, sigB] }), wire("transaction_receipt_two_parties"), "transaction receipt");
  // The old signer must hold old_key and the new signer new_key.
  await refused(() => signKeyRotationStatementV2WithSigners(decodeKeyRotationStatementV2(wire("key_rotation_genesis")), mu("rotation_second"), mu("rotation_genesis")));
});
