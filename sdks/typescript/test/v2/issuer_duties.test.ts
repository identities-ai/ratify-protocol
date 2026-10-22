// testvectors/v2/issuer-duties.json: the typed delegation signer refuses a
// certificate a conforming issuer must not emit before any signer method runs.

import { test } from "node:test";
import assert from "node:assert/strict";

import { decodeDelegationCertV2, signDelegationCertV2WithSigner, verifyDelegationCertV2Signature, type DelegationCertV2 } from "../../src/protocol_v2_wire.js";
import { newLocalSignerV2, type SignRequestV2, type SignerV2 } from "../../src/signer_v2.js";
import type { HybridSignature } from "../../src/types.js";
import { corpusKeyPairs, load, unb64, type Any } from "./helpers.js";

/** Wraps a signer and counts every method call. */
export class CountingSigner implements SignerV2 {
  calls = 0;
  constructor(private readonly inner: SignerV2) {}
  publicKeyV2() {
    this.calls++;
    return this.inner.publicKeyV2();
  }
  modeV2() {
    this.calls++;
    return this.inner.modeV2();
  }
  signV2(req: SignRequestV2, signal?: AbortSignal): Promise<HybridSignature> {
    this.calls++;
    return this.inner.signV2(req, signal);
  }
}

const file = load("issuer-duties.json");

test("issuer-duties.json: refusals invoke no signer method", async (t) => {
  const keys = await corpusKeyPairs();
  assert.equal(file.vectors.length, 11);
  const outcomes = new Set<string>();
  for (const v of file.vectors as Any[]) {
    outcomes.add(v.expected);
    await t.test(v.name, async () => {
      const cert = decodeDelegationCertV2(unb64(v.unsigned_certificate_b64));
      const signer = new CountingSigner(await newLocalSignerV2(keys.get(v.issuer)!));
      let signed: DelegationCertV2 | null = null;
      let err: unknown = null;
      try {
        signed = await signDelegationCertV2WithSigner(cert, signer);
      } catch (e) {
        err = e;
      }
      if (v.expected === "sign") {
        assert.equal(err, null, `expected the certificate to sign: ${(err as Error)?.message}`);
        await verifyDelegationCertV2Signature(signed!);
      } else {
        assert.equal(v.expected, "reject");
        assert.ok(err !== null && signed === null, "expected the issuer duty to refuse signing");
        assert.equal(signer.calls, 0, "signer was invoked before the refusal");
      }
    });
  }
  assert.deepEqual([...outcomes].sort(), ["reject", "sign"]);
});
