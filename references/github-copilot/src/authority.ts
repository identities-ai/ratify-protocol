import {
  hybridKeypairFromSeeds,
  keyIDV2,
  signDelegationCertV2,
  signProofBundleV2,
  encodeProofBundleV2,
  type DelegationCertV2,
  type HybridKeyPairV2,
} from "@identities-ai/ratify-protocol/v2";
import { ALLOWED_PATH, CERT_ID, REQUIRED_SCOPE, RESOURCE_ID } from "./constants.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

const unsigned = { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) };

export interface DemoAuthority {
  /** The principal's root key. It signs delegations and nothing else. */
  root: HybridKeyPairV2;
  rootID: string;
  /** The principal's status key, role-separated from the root (SPEC-v2 §5.4). */
  status: HybridKeyPairV2;
  /** The adapter's own key. The model never sees it. */
  agent: HybridKeyPairV2;
  agentID: string;
  delegation: DelegationCertV2;
}

/** What the receiver returns from /challenge. All byte fields are base64. */
export interface ChallengeResponse {
  challenge: string;
  challenge_at: number;
  expires_at: number;
  verifier_id: string;
  session_context: string;
}

// Fixed seeds make the public reference reproducible. They are intentionally
// public demo credentials and must never be copied into production.
export async function createDemoAuthority(): Promise<DemoAuthority> {
  const root = await hybridKeypairFromSeeds(seed(11), seed(12));
  const status = await hybridKeypairFromSeeds(seed(13), seed(14));
  const agent = await hybridKeypairFromSeeds(seed(21), seed(22));
  const rootID = keyIDV2(root.publicKey);
  const agentID = keyIDV2(agent.publicKey);
  const delegation = await signDelegationCertV2({
    version: 2,
    cert_id: CERT_ID,
    issuer_id: rootID,
    issuer_pub_key: root.publicKey,
    subject_id: agentID,
    subject_pub_key: agent.publicKey,
    // An exact custom: scope. It is matched by byte equality and no wildcard
    // or canonical scope grants it (SPEC-v2 §2.4).
    scope: [REQUIRED_SCOPE],
    constraints: [{
      type: "resource_path",
      resource_id: RESOURCE_ID,
      path_prefix: ALLOWED_PATH,
    }],
    issued_at: 1_700_000_000,
    expires_at: 1_900_000_000,
    signature: unsigned,
  }, root);
  return { root, rootID, status, agent, agentID, delegation };
}

/** The adapter signs the receiver's challenge and returns the v2 wire bundle. */
export async function presentAuthority(
  authority: Pick<DemoAuthority, "agent" | "agentID" | "delegation">,
  challenge: { value: Uint8Array; challengeAt: number; verifierID: string; sessionContext: Uint8Array },
): Promise<Uint8Array> {
  const bundle = await signProofBundleV2({
    version: 2,
    verifier_id: challenge.verifierID,
    agent_id: authority.agentID,
    agent_pub_key: authority.agent.publicKey,
    delegations: [authority.delegation],
    delegation_digest: new Uint8Array(0),
    challenge: challenge.value,
    challenge_at: challenge.challengeAt,
    challenge_sig: unsigned,
    session_context: challenge.sessionContext,
    stream_id: null,
    stream_seq: null,
  }, authority.agent);
  return encodeProofBundleV2(bundle);
}
