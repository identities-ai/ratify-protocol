// Connect proof of possession of the Verify MCP signer (Preview).

import type { HybridKeyPairV2 } from "../crypto_v2.js";
import { base64DecodeCanonical, base64Encode } from "../json_v2.js";
import { signProofBundleV2, signProofBundleV2WithSigner, type ProofBundleV2 } from "../protocol_v2_wire.js";
import { keyIDV2, type SignerV2, type SignOptionsV2 } from "../signer_v2.js";
import type { HybridPublicKey } from "../types.js";
import { connectPossessionContext } from "./binding.js";
import { field, HEX64_PATTERN, parseJSONObject, UUID_PATTERN, validEndpoint } from "./config.js";
import { InvalidConnectTokenError } from "./errors.js";
import { signPresentation } from "./toolcall.js";

/** Starts the one-line connect challenge the console issues to the owner or admin connecting an agent. Preview. */
export const CONNECT_TOKEN_PREFIX = "ratify-mcp-connect-1.";
/** The longest connect token accepted. Preview. */
export const MAX_CONNECT_TOKEN_LENGTH = 4096;

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const CONNECT_TOKEN_FIELDS = ["audience", "challenge", "challenge_id", "issued_at", "receiver_id", "verifier_id", "workspace_id"];

/** Preview. A parsed connect challenge. */
export interface ConnectToken {
  readonly challengeID: string;
  readonly challenge: Uint8Array;
  readonly issuedAt: number;
  readonly workspaceID: string;
  readonly receiverID: string;
  readonly audience: string;
  readonly verifierID: string;
}

/**
 * Preview. Parses CONNECT_TOKEN_PREFIX followed by unpadded base64url of a
 * JSON object with exactly the fields challenge_id, challenge, issued_at,
 * workspace_id, receiver_id, audience, and verifier_id. IDs are lowercase
 * UUIDs, verifier_id is 64 lowercase hex characters, issued_at is a
 * positive integer, challenge is 32 bytes in canonical standard base64, and
 * audience is an endpoint (as in parseClientConfig) followed by "/mcp".
 * Throws InvalidConnectTokenError.
 */
export function parseConnectToken(token: string): ConnectToken {
  if (typeof token !== "string" || token.length > MAX_CONNECT_TOKEN_LENGTH || !token.startsWith(CONNECT_TOKEN_PREFIX)) {
    throw new InvalidConnectTokenError();
  }
  const body = token.slice(CONNECT_TOKEN_PREFIX.length);
  if (!BASE64URL_PATTERN.test(body)) throw new InvalidConnectTokenError();
  const raw = Buffer.from(body, "base64url");
  if (raw.toString("base64url") !== body) throw new InvalidConnectTokenError();
  const msg = parseJSONObject(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength));
  if (msg === null || Object.keys(msg).length !== CONNECT_TOKEN_FIELDS.length) throw new InvalidConnectTokenError();
  for (const name of CONNECT_TOKEN_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(msg, name)) throw new InvalidConnectTokenError();
  }
  const strings: string[] = [];
  for (const name of ["challenge_id", "challenge", "workspace_id", "receiver_id", "audience", "verifier_id"]) {
    const v = field(msg, name);
    if (typeof v !== "string") throw new InvalidConnectTokenError();
    strings.push(v);
  }
  const [challengeID, challengeText, workspaceID, receiverID, audience, verifierID] =
    strings as [string, string, string, string, string, string];
  const issuedAt = field(msg, "issued_at");
  if (typeof issuedAt !== "number" || !Number.isSafeInteger(issuedAt) || issuedAt <= 0) throw new InvalidConnectTokenError();
  if (!UUID_PATTERN.test(challengeID) || !UUID_PATTERN.test(workspaceID) || !UUID_PATTERN.test(receiverID) ||
      !HEX64_PATTERN.test(verifierID) || !audience.endsWith("/mcp") || !validEndpoint(audience.slice(0, -"/mcp".length), audience)) {
    throw new InvalidConnectTokenError();
  }
  const challenge = base64DecodeCanonical(challengeText);
  if (challenge === null || challenge.length !== 32) throw new InvalidConnectTokenError();
  return Object.freeze({ challengeID, challenge, issuedAt, workspaceID, receiverID, audience, verifierID });
}

/** Preview. What the connect request carries besides the certificate. */
export interface PossessionProof {
  readonly connect_challenge_id: string;
  /** The SPEC-v2 proof bundle wire in standard base64. */
  readonly possession_proof: string;
}

async function provePossessionWith(
  token: string,
  pub: HybridPublicKey,
  sign: (unsigned: ProofBundleV2) => Promise<ProofBundleV2>,
): Promise<PossessionProof> {
  const t = parseConnectToken(token);
  const agentID = keyIDV2(pub);
  const session = connectPossessionContext(t.workspaceID, t.receiverID, t.audience, t.challengeID, agentID);
  const wire = await signPresentation(t.verifierID, agentID, pub, [], t.challenge, t.issuedAt, session, sign);
  return Object.freeze({ connect_challenge_id: t.challengeID, possession_proof: base64Encode(wire) });
}

/**
 * Preview. Signs the connect challenge with the agent key being connected:
 * a SPEC-v2 proof bundle with no delegations whose challenge and
 * challenge_at are the token's, and whose session context is
 * connectPossessionContext. It never contacts the network.
 */
export async function provePossession(token: string, agentKey: HybridKeyPairV2): Promise<PossessionProof> {
  return provePossessionWith(token, agentKey.publicKey, (b) => signProofBundleV2(b, agentKey));
}

/** Preview. provePossession with an external SignerV2. */
export async function provePossessionWithSigner(token: string, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<PossessionProof> {
  return provePossessionWith(token, signer.publicKeyV2(), (b) => signProofBundleV2WithSigner(b, signer, opts));
}
