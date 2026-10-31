// Ratify Protocol v2 external signer: a signing provider holds the private
// key; the SDK prepares each typed statement and verifies every returned
// signature before using it.
//
// The provider here is an in-process stand-in for a remote signing service.
// The interface makes no claim about any particular KMS or HSM.
//
// Run from this directory: node external_signer.ts
import { randomBytes } from "node:crypto";
import { getPublicKeyAsync, signAsync, utils as ed25519Utils } from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { generateHybridKeypair } from "@identities-ai/ratify-protocol";
import {
  SIGNER_MODE_DIRECT_V2,
  keyIDV2,
  signDelegationCertV2WithSigner,
  signProofBundleV2WithSigner,
  v2ErrorClassOf,
  verifyDelegationCertV2Signature,
  verifyProofBundleV2Signatures,
  type ProofBundleV2,
  type SignRequestV2,
  type SignerModeV2,
  type SignerV2,
} from "@identities-ai/ratify-protocol/v2";

const start = 1800000000;

type HybridPublicKey = { ed25519: Uint8Array; ml_dsa_65: Uint8Array };
type HybridSignature = { ed25519: Uint8Array; ml_dsa_65: Uint8Array };

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

// A signing service. Its private key never leaves it. It signs in direct
// mode: Ed25519 over the 77-byte message M and ML-DSA-65 over M with the
// SDK-chosen context string.
class Provider implements SignerV2 {
  readonly name: string;
  readonly pub: HybridPublicKey;
  readonly log: string[] = [];
  readonly #ed: Uint8Array;
  ml: Uint8Array;

  private constructor(name: string, pub: HybridPublicKey, ed: Uint8Array, ml: Uint8Array) {
    this.name = name;
    this.pub = pub;
    this.#ed = ed;
    this.ml = ml;
  }

  static async create(name: string): Promise<Provider> {
    const ed = ed25519Utils.randomPrivateKey();
    const ml = ml_dsa65.keygen(randomBytes(32));
    return new Provider(name, { ed25519: await getPublicKeyAsync(ed), ml_dsa_65: ml.publicKey }, ed, ml.secretKey);
  }

  publicKeyV2(): HybridPublicKey {
    return this.pub;
  }

  modeV2(): SignerModeV2 {
    return SIGNER_MODE_DIRECT_V2;
  }

  async signV2(req: SignRequestV2): Promise<HybridSignature> {
    // A provider refuses any request for a key it does not hold.
    if (!sameBytes(req.publicKey.ed25519, this.pub.ed25519) || !sameBytes(req.publicKey.ml_dsa_65, this.pub.ml_dsa_65)) {
      throw new Error(`${this.name}: request names a key this provider does not hold`);
    }
    const context = new TextDecoder().decode(req.mlDsaContext!);
    this.log.push(`${this.name} signed: mode=direct message=${req.message.length} bytes context=${context}`);
    return {
      ed25519: await signAsync(req.message, this.#ed),
      ml_dsa_65: ml_dsa65.sign(req.message, this.ml, { context: req.mlDsaContext! }),
    };
  }
}

const verified = (p: Promise<unknown>) => p.then(() => true, () => false);

console.log("Ratify Protocol v2 external signer");

const issuer = await Provider.create("issuer provider");
const agent = await Provider.create("agent provider");
const verifier = await generateHybridKeypair();
const issuerID = keyIDV2(issuer.pub);
const agentID = keyIDV2(agent.pub);
const verifierID = keyIDV2(verifier.publicKey);
const unsigned = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }; // replaced when signed

const cert = await signDelegationCertV2WithSigner({
  version: 2, cert_id: "external-signer-cert-1",
  issuer_id: issuerID, issuer_pub_key: issuer.pub, subject_id: agentID, subject_pub_key: agent.pub,
  scope: ["files:read"], constraints: [],
  issued_at: start, expires_at: start + 86400, signature: unsigned,
}, issuer);
console.log(issuer.log[0]);
console.log(`delegation: signature verified by the SDK (${await verified(verifyDelegationCertV2Signature(cert))})`);

const template: ProofBundleV2 = {
  version: 2, verifier_id: verifierID, agent_id: agentID, agent_pub_key: agent.pub,
  delegations: [cert], delegation_digest: new Uint8Array(0),
  challenge: new Uint8Array(32).fill(0x42), challenge_at: start, challenge_sig: unsigned,
  session_context: null, stream_id: null, stream_seq: null,
};
const bundle = await signProofBundleV2WithSigner(template, agent);
console.log(agent.log[0]);
console.log(`proof bundle: signatures verified by the SDK (${await verified(verifyProofBundleV2Signatures(bundle))})`);

// A faulty provider returns an ML-DSA-65 signature from a different key.
// The SDK verifies before use, so nothing is signed.
agent.ml = ml_dsa65.keygen(randomBytes(32)).secretKey;
const refused = await signProofBundleV2WithSigner(template, agent).then(() => null, (err: unknown) => err);
console.log(`faulty provider: refused (${v2ErrorClassOf(refused)})`);
