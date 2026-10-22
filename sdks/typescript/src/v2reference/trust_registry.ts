// Reference candidate-record trust resolver of SPEC-v2 §6.1 (Go
// v2reference/trust_registry.go). TEST AND CONFORMANCE USE ONLY: it shows the
// fail-closed resolution rule; a deployment loads its records from its own
// authenticated configuration.
//
// It holds caller-authenticated root records (complete hybrid public keys) and
// resolves a verified chain by its terminal issuer:
//
//   - a record is a candidate when its key ID equals the terminal issuer ID or
//     either of its components equals the matching component of the terminal
//     issuer key;
//   - no candidate is untrusted;
//   - more than one candidate, including the same key configured twice, is
//     ambiguous; the resolver never selects a first match;
//   - exactly one candidate is trusted with that record's complete key, which
//     the verifier then compares with the chain root (a partial match is
//     treated as ambiguous there).

import { keyIDV2 } from "../crypto_v2.js";
import { bytesEqual } from "../json_v2.js";
import type { DelegationCertV2 } from "../protocol_v2_wire.js";
import type { HybridPublicKey } from "../types.js";
import type { V2TrustResolution } from "../verify_v2.js";

const cloneKey = (key: HybridPublicKey): HybridPublicKey => ({ ed25519: key.ed25519.slice(), ml_dsa_65: key.ml_dsa_65.slice() });

export class TrustRegistryTestOnly {
  private readonly records: HybridPublicKey[] = [];
  private readonly ids: string[] = [];

  /** Returns a registry over the given records in order. */
  constructor(records: HybridPublicKey[]) {
    records.forEach((key, i) => {
      let id: string;
      try {
        id = keyIDV2(key);
      } catch (err) {
        throw new Error(`v2reference: trust record ${i}: ${(err as Error).message}`);
      }
      this.records.push(cloneKey(key));
      this.ids.push(id);
    });
  }

  /** Implements the V2VerifyCallbacks.trust provider. */
  resolve(chain: DelegationCertV2[]): V2TrustResolution {
    if (chain.length === 0) return { outcome: "untrusted" };
    const root = chain[chain.length - 1]!;
    let match = -1;
    for (let i = 0; i < this.records.length; i++) {
      const key = this.records[i]!;
      if (this.ids[i] !== root.issuer_id && !bytesEqual(key.ed25519, root.issuer_pub_key.ed25519) && !bytesEqual(key.ml_dsa_65, root.issuer_pub_key.ml_dsa_65)) {
        continue;
      }
      if (match >= 0) return { outcome: "ambiguous" };
      match = i;
    }
    if (match < 0) return { outcome: "untrusted" };
    return { outcome: "trusted", rootKey: cloneKey(this.records[match]!) };
  }
}
