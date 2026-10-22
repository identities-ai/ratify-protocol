import { createServer, type Server } from "node:http";
import {
  TZDB_VERSION_V2,
  configureStatusKeyEpochV2,
  decodeProofBundleV2,
  decodeVerificationReceiptV2,
  generateHybridKeypair,
  issueChallengeV2,
  keyIDV2,
  loadExpectedChallengeV2,
  newV2ContextPolicy,
  recordSecurityKeyRoleV2,
  releaseV2Decision,
  verifyProofBundleV2,
  type DelegationCertV2,
  type HybridKeyPairV2,
  type V2StatusEvidenceObject,
} from "@identities-ai/ratify-protocol/v2";
// DEVELOPMENT ONLY. These are the SDK's in-memory Part B reference stores
// (claim store, receipt log, checkpoint, journal, challenge issuance). They
// are not durable, do not span processes, and give no independent failure
// domain. A production receiver supplies durable stores and an independent
// checkpoint (SPEC-v2 §7) before it acts on any released decision.
import {
  ChallengeIssuanceStoreTestOnly,
  JournalStoreTestOnly,
  StoreTestOnly,
} from "@identities-ai/ratify-protocol/v2/reference";
import type { ChallengeResponse } from "./authority.js";
import {
  CONTEXT_FIELDS,
  CONTEXT_PROFILE,
  LOG_ID,
  REPLAY_EPOCH,
  REQUIRED_SCOPE,
  VERIFIER_NAMESPACE,
} from "./constants.js";
import { bindingFor, requestedPath, requestedResource, type DeployRequest } from "./request.js";

type HybridPublicKey = HybridKeyPairV2["publicKey"];

export interface DeployDecision {
  allowed: boolean;
  reason: string;
  handler_invocations: number;
  /** Present once a signed verification receipt exists (allow or deny). */
  verification_receipt?: {
    log_sequence: number;
    decision: string;
    decision_reason: string;
  };
  receipt?: {
    agent_id: string;
    scope: string;
    resource: string;
    path: string;
    invocation_id: string;
  };
}

export interface TrustedRoot {
  /** Optional configured ID. When given it must equal the v2 key ID of publicKey. */
  id?: string;
  publicKey: HybridPublicKey;
}

export interface ReceiverConfig {
  trustedRoot: TrustedRoot;
  /** The root's status key, pinned out of band and role-separated from the root key. */
  statusKey: HybridPublicKey;
  /** The adapter key this receiver issues challenges to. */
  expectedAgent: HybridPublicKey;
  /** Fetches the principal's signed status objects. The transport is untrusted. */
  statusFeed: (now: number) => Promise<V2StatusEvidenceObject[]>;
  /** Authoritative clock in Unix seconds. Defaults to the system clock. */
  clock?: () => number;
}

const STATUS_POLICY = { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 5 };
const CHALLENGE_LIFETIME_SECONDS = 60;

function samePublicKey(left: HybridPublicKey, right: HybridPublicKey): boolean {
  const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
  return eq(left.ed25519, right.ed25519) && eq(left.ml_dsa_65, right.ml_dsa_65);
}

function sameBytes(a: Uint8Array | null | undefined, b: Uint8Array): boolean {
  return !!a && a.length === b.length && a.every((v, i) => v === b[i]);
}

const systemClock = () => Math.floor(Date.now() / 1000);

export class ProtectedDeployReceiver {
  private invocations = 0;

  private constructor(
    private readonly config: ReceiverConfig,
    private readonly rootID: string,
    private readonly agentID: string,
    private readonly verifier: HybridKeyPairV2,
    private readonly verifierID: string,
    private readonly store: StoreTestOnly,
    private readonly journal: JournalStoreTestOnly,
    private readonly issuance: ChallengeIssuanceStoreTestOnly,
    private readonly clock: () => number,
  ) {}

  static async create(config: ReceiverConfig): Promise<ProtectedDeployReceiver> {
    const rootID = keyIDV2(config.trustedRoot.publicKey);
    if (config.trustedRoot.id !== undefined && config.trustedRoot.id !== rootID) {
      throw new Error("trusted root ID does not match its public key");
    }
    const clock = config.clock ?? systemClock;
    // The receiver's own verifier key signs its receipts. A fresh key per
    // process is honest for a demo whose log does not outlive the process.
    const verifier = await generateHybridKeypair();
    const store = new StoreTestOnly(clock(), 30, LOG_ID, verifier);
    const journal = new JournalStoreTestOnly();
    await recordSecurityKeyRoleV2(journal, "issuer", config.trustedRoot.publicKey);
    await recordSecurityKeyRoleV2(journal, "delegation", config.expectedAgent);
    await recordSecurityKeyRoleV2(journal, "verifier", verifier.publicKey);
    await configureStatusKeyEpochV2(journal, rootID, 1, config.statusKey);
    return new ProtectedDeployReceiver(
      config, rootID, keyIDV2(config.expectedAgent), verifier, keyIDV2(verifier.publicKey),
      store, journal, new ChallengeIssuanceStoreTestOnly(), clock,
    );
  }

  get verifierPublicKey(): HybridPublicKey {
    return this.verifier.publicKey;
  }

  private tick(): number {
    const now = this.clock();
    this.store.setTime(now);
    return now;
  }

  private deny(reason: string, receipt?: DeployDecision["verification_receipt"]): DeployDecision {
    return { allowed: false, reason, handler_invocations: this.invocations, ...(receipt ? { verification_receipt: receipt } : {}) };
  }

  /** Issues a challenge bound to the receiver's own reading of the request. */
  async challenge(request: DeployRequest): Promise<ChallengeResponse> {
    this.tick();
    const { sessionContext } = bindingFor(request, this.verifierID, this.agentID);
    // The issuance helper persists the record before it returns the challenge.
    const issued = await issueChallengeV2({ clock: this.store, store: this.issuance }, {
      verifierNamespace: VERIFIER_NAMESPACE,
      replayEpoch: REPLAY_EPOCH,
      verifierID: this.verifierID,
      lifetimeSeconds: CHALLENGE_LIFETIME_SECONDS,
      expectedAgentID: this.agentID,
      expectedAgentPublicKey: this.config.expectedAgent,
      expectedSessionContext: sessionContext,
    });
    return {
      challenge: Buffer.from(issued.value).toString("base64"),
      challenge_at: issued.issuedAt,
      expires_at: issued.expiresAt,
      verifier_id: this.verifierID,
      session_context: Buffer.from(sessionContext).toString("base64"),
    };
  }

  async deploy(request: DeployRequest, bundleWire: Uint8Array): Promise<DeployDecision> {
    this.tick();
    let binding: ReturnType<typeof bindingFor>;
    try {
      binding = bindingFor(request, this.verifierID, this.agentID);
    } catch (error) {
      return this.deny(`malformed_request: ${(error as Error).message}`);
    }

    let presented: Uint8Array;
    try {
      presented = decodeProofBundleV2(bundleWire).challenge;
    } catch {
      return this.deny("preflight: malformed");
    }
    let expected;
    try {
      expected = await loadExpectedChallengeV2(this.issuance, VERIFIER_NAMESPACE, REPLAY_EPOCH, presented);
    } catch {
      return this.deny("preflight: expected_challenge_unavailable");
    }
    // The request about to execute must be the request the challenge was
    // issued for. Checked before verification, so nothing is consumed.
    if (!sameBytes(expected.expectedSessionContext, binding.sessionContext)) {
      return this.deny("preflight: session_context_mismatch");
    }

    const outcome = await verifyProofBundleV2({
      bundle: bundleWire,
      expected,
      contextPolicy: newV2ContextPolicy(CONTEXT_PROFILE, true, CONTEXT_FIELDS, binding.sessionContext),
      requiredScope: REQUIRED_SCOPE,
      verifierNamespace: VERIFIER_NAMESPACE,
      replayEpoch: REPLAY_EPOCH,
      now: this.store.now(),
      maxChallengeAgeSeconds: CHALLENGE_LIFETIME_SECONDS,
      futureSkewSeconds: 5,
      context: {
        hasResource: true,
        requestedResourceID: requestedResource(request),
        requestedPath: requestedPath(request),
      },
      tzdbVersion: TZDB_VERSION_V2,
      statusKeys: new Map([[this.rootID, { epoch: 1, key: this.config.statusKey }]]),
      statusPolicy: STATUS_POLICY,
    }, {
      claimStore: this.store,
      // The pinned KEY is the anchor, never an ID taken from the chain.
      trust: (chain: DelegationCertV2[]) => {
        const root = chain[chain.length - 1];
        return root && samePublicKey(root.issuer_pub_key, this.config.trustedRoot.publicKey)
          ? { outcome: "trusted", rootKey: this.config.trustedRoot.publicKey }
          : { outcome: "untrusted" };
      },
      statusEvidence: async () => ({ objects: await this.config.statusFeed(this.store.now()) }),
      statusJournal: this.journal,
    });
    if (outcome.stage !== "committed" || !outcome.committed) {
      return this.deny(`${outcome.stage}: ${outcome.errorClass || outcome.disposition || "rejected"}`);
    }

    // Committed is not actionable. Publish the signed receipt, read the
    // checkpoint acknowledgement, and release.
    const receiptWire = await this.store.publishV2Receipt(outcome.committed.claimID(), outcome.committed.receiptBody());
    const receipt = decodeVerificationReceiptV2(receiptWire);
    const summary = { log_sequence: receipt.sequence, decision: receipt.decision, decision_reason: receipt.decision_reason };
    const released = await releaseV2Decision(outcome.committed, receiptWire, {
      verifierPublicKey: this.verifier.publicKey,
      logID: LOG_ID,
      claimStore: this.store,
      checkpoint: this.store,
    });
    if (released.status !== "released" || !released.decision) {
      return this.deny(`release_${released.status}: ${released.reason}`, summary);
    }
    const decision = released.decision;
    // The only path to the handler: a released decision that is allowed at
    // the receiver's authoritative time.
    if (!(await decision.allowed(this.store))) {
      return this.deny(`${decision.decision()}: ${decision.reason()}`, summary);
    }

    this.invocations += 1;
    return {
      allowed: true,
      reason: decision.reason(),
      handler_invocations: this.invocations,
      verification_receipt: summary,
      receipt: {
        agent_id: this.agentID,
        scope: REQUIRED_SCOPE,
        resource: requestedResource(request),
        path: requestedPath(request),
        invocation_id: request.invocation_id,
      },
    };
  }
}

async function readJSON(request: import("node:http").IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function send(response: import("node:http").ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

export function createReceiverServer(receiver: ProtectedDeployReceiver): Server {
  return createServer(async (request, response) => {
    try {
      if (request.method !== "POST") return send(response, 405, { error: "method_not_allowed" });
      const body = await readJSON(request) as { request: DeployRequest; proof?: string };
      if (request.url === "/challenge") return send(response, 200, await receiver.challenge(body.request));
      if (request.url === "/deploy" && typeof body.proof === "string") {
        return send(response, 200, await receiver.deploy(body.request, new Uint8Array(Buffer.from(body.proof, "base64"))));
      }
      return send(response, 404, { error: "not_found" });
    } catch (error) {
      return send(response, 400, { error: error instanceof Error ? error.message : "invalid_request" });
    }
  });
}
