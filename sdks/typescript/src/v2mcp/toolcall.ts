// Tool-call proofs of the Verify MCP signer (Preview).
//
// Nothing here signs caller-chosen bytes. A tool-call proof is a SPEC-v2
// challenge presentation whose session context the signer recomputes from
// the call it was asked to make and the pinned configuration, never from a
// hash the server supplies.

import type { HybridKeyPairV2 } from "../crypto_v2.js";
import { base64DecodeCanonical, base64Encode, bytesEqual } from "../json_v2.js";
import {
  encodeProofBundleV2,
  placeholderV2Signature,
  signProofBundleV2,
  signProofBundleV2WithSigner,
  type DelegationCertV2,
  type ProofBundleV2,
} from "../protocol_v2_wire.js";
import { keyIDV2, type SignerV2, type SignOptionsV2 } from "../signer_v2.js";
import type { HybridPublicKey } from "../types.js";
import {
  MIN_CHALLENGE_SECONDS_LEFT,
  payloadDigest,
  payloadDigestText,
  requestHash,
  sessionContext,
  toolScope,
} from "./binding.js";
import { canonicalArguments } from "./arguments.js";
import { field, parseJSONObject, UUID_PATTERN, type ClientConfig } from "./config.js";
import { ChallengeRefusedError, InvalidArgumentsError } from "./errors.js";

/**
 * Preview. One validated tool call: the tool and its canonical arguments.
 * Send canonicalArguments as params.arguments so the server computes the
 * same payload digest.
 */
export interface ToolCall {
  readonly tool: string;
  readonly canonicalArguments: Uint8Array;
  readonly payloadDigest: Uint8Array;
}

/**
 * Preview. Validates the tool name and the JSON text (UTF-8 bytes or a
 * string) of its arguments. Throws InvalidArgumentsError.
 */
export function newToolCall(tool: string, args: Uint8Array | string): ToolCall {
  if (typeof tool !== "string" || toolScope(tool) === null) throw new InvalidArgumentsError("mcp: unknown tool");
  const canonical = canonicalArguments(args);
  return Object.freeze({ tool, canonicalArguments: canonical, payloadDigest: payloadDigest(canonical) });
}

/**
 * Re-derives the payload digest from the call's canonical arguments, so a
 * ToolCall built or changed outside newToolCall can never make the signer
 * bind one argument set and send another.
 */
function verifiedDigest(call: ToolCall): Uint8Array {
  if (!call || typeof call.tool !== "string" || toolScope(call.tool) === null ||
      !(call.canonicalArguments instanceof Uint8Array) || call.canonicalArguments.length === 0) {
    throw new InvalidArgumentsError();
  }
  const canonical = canonicalArguments(call.canonicalArguments);
  const digest = payloadDigest(canonical);
  if (!bytesEqual(canonical, call.canonicalArguments) || !(call.payloadDigest instanceof Uint8Array) ||
      !bytesEqual(digest, call.payloadDigest)) {
    throw new InvalidArgumentsError();
  }
  return digest;
}

/**
 * Preview. The exact JSON body of POST <endpoint>/challenge for call:
 * {"connection_id":...,"tool":...,"payload_digest":"sha256:..."}. Throws
 * InvalidArgumentsError when the call's digest does not match its
 * canonical arguments.
 */
export function challengeRequest(config: ClientConfig, call: ToolCall): Uint8Array {
  const digest = verifiedDigest(call);
  const body = `{"connection_id":${JSON.stringify(config.connectionID)},"tool":${JSON.stringify(call.tool)},` +
    `"payload_digest":${JSON.stringify(payloadDigestText(digest))}}`;
  return new TextEncoder().encode(body);
}

/**
 * Preview. A challenge response that checkChallenge accepted. It can sign
 * only a call to the tool, and under the configuration (verifier,
 * workspace, connection), it was checked for.
 */
export class Challenge {
  readonly #tool: string;
  readonly #verifierID: string;
  readonly #workspaceID: string;
  readonly #connectionID: string;
  readonly #challenge: Uint8Array;
  readonly #invocationID: string;
  readonly #issuedAt: number;
  readonly #expiresAt: number;

  /** @internal Use checkChallenge. */
  constructor(tool: string, config: ClientConfig, challenge: Uint8Array, invocationID: string, issuedAt: number, expiresAt: number) {
    this.#tool = tool;
    this.#verifierID = config.verifierID;
    this.#workspaceID = config.workspaceID;
    this.#connectionID = config.connectionID;
    this.#challenge = challenge.slice();
    this.#invocationID = invocationID;
    this.#issuedAt = issuedAt;
    this.#expiresAt = expiresAt;
  }

  /** The tool the challenge was checked for. */
  get tool(): string {
    return this.#tool;
  }

  /** The server-generated invocation the proof binds. */
  get invocationID(): string {
    return this.#invocationID;
  }

  /** The challenge issue time in Unix seconds. */
  get issuedAt(): number {
    return this.#issuedAt;
  }

  /** The challenge expiry in Unix seconds. */
  get expiresAt(): number {
    return this.#expiresAt;
  }

  /** @internal True when config pins the verifier, workspace, and connection the challenge was checked under. */
  boundTo(config: ClientConfig): boolean {
    return config.verifierID === this.#verifierID && config.workspaceID === this.#workspaceID &&
      config.connectionID === this.#connectionID;
  }

  /** @internal */
  challengeBytes(): Uint8Array {
    return this.#challenge.slice();
  }
}

function jsonInteger(v: unknown): number | null {
  return typeof v === "number" && Number.isSafeInteger(v) ? v : null;
}

/**
 * Preview. Accepts the JSON response of POST <endpoint>/challenge only if
 * verifier_id and workspace_id equal the pinned values, required_scope is
 * the tool's scope, invocation_id is a lowercase UUID, challenge is 32
 * bytes in canonical standard base64, issued_at and expires_at are integers
 * with 0 < issued_at <= expires_at, and at least MIN_CHALLENGE_SECONDS_LEFT
 * seconds remain at now (Unix seconds). The response must be valid UTF-8
 * (or well-formed text); unknown fields, including any hash the server
 * supplies, are ignored. Throws ChallengeRefusedError.
 */
export function checkChallenge(config: ClientConfig, tool: string, response: Uint8Array | string, now: number): Challenge {
  const scope = toolScope(tool);
  if (scope === null) throw new ChallengeRefusedError();
  const msg = parseJSONObject(response);
  if (msg === null) throw new ChallengeRefusedError();
  const verifier = field(msg, "verifier_id");
  const workspace = field(msg, "workspace_id");
  const gotScope = field(msg, "required_scope");
  const invocation = field(msg, "invocation_id");
  const challengeText = field(msg, "challenge");
  const issued = jsonInteger(field(msg, "issued_at"));
  const expires = jsonInteger(field(msg, "expires_at"));
  if (typeof verifier !== "string" || typeof workspace !== "string" || typeof gotScope !== "string" ||
      typeof invocation !== "string" || typeof challengeText !== "string" || issued === null || expires === null) {
    throw new ChallengeRefusedError();
  }
  if (verifier !== config.verifierID || workspace !== config.workspaceID || gotScope !== scope || !UUID_PATTERN.test(invocation)) {
    throw new ChallengeRefusedError();
  }
  const challenge = base64DecodeCanonical(challengeText);
  if (challenge === null || challenge.length !== 32) throw new ChallengeRefusedError();
  // issued and expires are safe integers, so expires - MIN_CHALLENGE_SECONDS_LEFT is exact.
  if (!Number.isSafeInteger(now) || issued <= 0 || issued > expires || now > expires - MIN_CHALLENGE_SECONDS_LEFT) {
    throw new ChallengeRefusedError();
  }
  return new Challenge(tool, config, challenge, invocation, issued, expires);
}

/** Preview. The value of params._meta[PROOF_META_KEY] on tools/call. */
export interface ProofEnvelope {
  readonly connection_id: string;
  readonly invocation_id: string;
  /** The challenge in standard base64. */
  readonly challenge: string;
  /** The SPEC-v2 proof bundle wire in standard base64. */
  readonly bundle: string;
}

type BundleSigner = (unsigned: ProofBundleV2) => Promise<ProofBundleV2>;

/** @internal Builds and signs a SPEC-v2 challenge presentation; returns its wire bytes. */
export async function signPresentation(
  verifierID: string,
  agentID: string,
  pub: HybridPublicKey,
  delegations: readonly DelegationCertV2[],
  challenge: Uint8Array,
  challengeAt: number,
  session: Uint8Array,
  sign: BundleSigner,
): Promise<Uint8Array> {
  const unsigned: ProofBundleV2 = {
    version: 2,
    verifier_id: verifierID,
    agent_id: agentID,
    agent_pub_key: pub,
    delegations: [...delegations],
    delegation_digest: new Uint8Array(48),
    challenge: challenge.slice(),
    challenge_at: challengeAt,
    challenge_sig: placeholderV2Signature(),
    session_context: session.slice(),
    stream_id: null,
    stream_seq: null,
  };
  return encodeProofBundleV2(await sign(unsigned));
}

async function signToolCallWith(
  config: ClientConfig,
  pub: HybridPublicKey,
  call: ToolCall,
  challenge: Challenge,
  sign: BundleSigner,
): Promise<ProofEnvelope> {
  if (!(challenge instanceof Challenge) || !call || challenge.tool !== call.tool) {
    throw new ChallengeRefusedError("mcp: the challenge was checked for another tool");
  }
  if (!challenge.boundTo(config)) {
    throw new ChallengeRefusedError("mcp: the challenge was checked under another configuration");
  }
  const digest = verifiedDigest(call);
  const agentID = keyIDV2(pub);
  const last = config.delegations[config.delegations.length - 1];
  if (last === undefined || last.subject_id !== agentID) {
    throw new ChallengeRefusedError("mcp: the last delegation certificate is not issued to this agent key");
  }
  const req = requestHash(call.tool, config.connectionID, config.audience, digest);
  const session = sessionContext(config.verifierID, config.workspaceID, agentID, config.connectionID, challenge.invocationID, req);
  const bytes = challenge.challengeBytes();
  // The configuration lists the chain root side first; a SPEC-v2 bundle
  // carries it leaf first.
  const leafFirst = [...config.delegations].reverse();
  const wire = await signPresentation(config.verifierID, agentID, pub, leafFirst, bytes, challenge.issuedAt, session, sign);
  return Object.freeze({
    connection_id: config.connectionID,
    invocation_id: challenge.invocationID,
    challenge: base64Encode(bytes),
    bundle: base64Encode(wire),
  });
}

/**
 * Preview. Signs the tool-call proof with an in-process agent key. Refuses
 * with ChallengeRefusedError when the challenge was checked for another
 * tool or under another configuration, or the last delegation certificate
 * is not issued to this key, and with InvalidArgumentsError when the call's
 * digest does not match its canonical arguments.
 */
export async function signToolCall(config: ClientConfig, agentKey: HybridKeyPairV2, call: ToolCall, challenge: Challenge): Promise<ProofEnvelope> {
  return signToolCallWith(config, agentKey.publicKey, call, challenge, (b) => signProofBundleV2(b, agentKey));
}

/** Preview. signToolCall with an external SignerV2. */
export async function signToolCallWithSigner(
  config: ClientConfig,
  signer: SignerV2,
  call: ToolCall,
  challenge: Challenge,
  opts: SignOptionsV2 = {},
): Promise<ProofEnvelope> {
  return signToolCallWith(config, signer.publicKeyV2(), call, challenge, (b) => signProofBundleV2WithSigner(b, signer, opts));
}
