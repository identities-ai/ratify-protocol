import {
  PROTOCOL_VERSION,
  deriveID,
  hybridKeypairFromSeeds,
  issueDelegation,
  signChallenge,
  type AgentIdentity,
  type DelegationCert,
  type HumanRoot,
  type HybridPrivateKey,
  type ProofBundle,
} from "@identities-ai/ratify-protocol";
import { ALLOWED_PATH, CERT_ID, REQUIRED_SCOPE, RESOURCE_ID } from "./constants.js";

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

export interface DemoAuthority {
  root: HumanRoot;
  agent: AgentIdentity;
  agentPrivateKey: HybridPrivateKey;
  delegation: DelegationCert;
}

// Fixed seeds make the public reference reproducible. They are intentionally
// public demo credentials and must never be copied into production.
export async function createDemoAuthority(): Promise<DemoAuthority> {
  const rootKeys = await hybridKeypairFromSeeds(seed(11), seed(12));
  const agentKeys = await hybridKeypairFromSeeds(seed(21), seed(22));
  const root: HumanRoot = {
    id: deriveID(rootKeys.publicKey),
    public_key: rootKeys.publicKey,
    created_at: 1_700_000_000,
  };
  const agent: AgentIdentity = {
    id: deriveID(agentKeys.publicKey),
    public_key: agentKeys.publicKey,
    name: "GitHub Copilot deployment adapter",
    agent_type: "mcp_adapter",
    created_at: 1_700_000_000,
  };
  const delegation: DelegationCert = {
    cert_id: CERT_ID,
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.public_key,
    subject_id: agent.id,
    subject_pub_key: agent.public_key,
    scope: [REQUIRED_SCOPE],
    constraints: [{
      type: "resource_path",
      resource_id: RESOURCE_ID,
      path_prefix: ALLOWED_PATH,
    }],
    issued_at: 1_700_000_000,
    expires_at: 1_900_000_000,
    signature: { ed25519: new Uint8Array(), ml_dsa_65: new Uint8Array() },
  };
  await issueDelegation(delegation, rootKeys.privateKey);
  return { root, agent, agentPrivateKey: agentKeys.privateKey, delegation };
}

export async function presentAuthority(
  authority: DemoAuthority,
  challenge: Uint8Array,
  sessionContext: Uint8Array,
): Promise<ProofBundle> {
  const challengeAt = Math.floor(Date.now() / 1000);
  return {
    agent_id: authority.agent.id,
    agent_pub_key: authority.agent.public_key,
    delegations: [authority.delegation],
    challenge,
    challenge_at: challengeAt,
    challenge_sig: await signChallenge(
      challenge,
      challengeAt,
      authority.agentPrivateKey,
      sessionContext,
    ),
    session_context: sessionContext,
  };
}
