import { createServer, type Server } from "node:http";
import {
  MemoryChallengeStore,
  base64StandardDecode,
  base64StandardEncode,
  decodeProofBundle,
  verifyBundle,
  type ProofBundle,
} from "@identities-ai/ratify-protocol";
import { REQUIRED_SCOPE } from "./constants.js";
import { bindingFor, requestedPath, requestedResource, type DeployRequest } from "./request.js";

interface ChallengeResponse {
  challenge: string;
  session_context: string;
}

export interface DeployDecision {
  allowed: boolean;
  reason: string;
  handler_invocations: number;
  receipt?: {
    agent_id: string;
    human_id: string;
    scope: string;
    resource: string;
    path: string;
    invocation_id: string;
  };
}

export class ProtectedDeployReceiver {
  private readonly challenges = new MemoryChallengeStore();
  private readonly revoked = new Set<string>();
  private invocations = 0;

  constructor(
    private readonly trustedRootID: string,
    private readonly expectedAgentID: string,
  ) {}

  revoke(certID: string): void {
    this.revoked.add(certID);
  }

  async challenge(request: DeployRequest): Promise<ChallengeResponse> {
    const { sessionContext } = bindingFor(request, this.expectedAgentID);
    const issued = await this.challenges.issue(sessionContext, 60);
    return {
      challenge: base64StandardEncode(issued.challenge),
      session_context: base64StandardEncode(sessionContext),
    };
  }

  async deploy(request: DeployRequest, bundle: ProofBundle): Promise<DeployDecision> {
    const { sessionContext } = bindingFor(request, this.expectedAgentID);
    const result = await verifyBundle(bundle, {
      required_scope: REQUIRED_SCOPE,
      session_context: sessionContext,
      challenge_store: this.challenges,
      force_revocation_check: true,
      revocation: {
        isRevoked: async (certID) => [this.revoked.has(certID), null],
      },
      context: {
        has_resource: true,
        requested_resource_id: requestedResource(request),
        requested_path: requestedPath(request),
      },
    });

    if (!result.valid) {
      return {
        allowed: false,
        reason: `${result.identity_status}: ${result.error_reason ?? "verification failed"}`,
        handler_invocations: this.invocations,
      };
    }
    if (result.human_id !== this.trustedRootID) {
      return {
        allowed: false,
        reason: "untrusted_root: verified delegation is not anchored to this receiver's trust policy",
        handler_invocations: this.invocations,
      };
    }
    if (result.agent_id !== this.expectedAgentID) {
      return {
        allowed: false,
        reason: "unexpected_agent: proof belongs to a different adapter",
        handler_invocations: this.invocations,
      };
    }

    this.invocations += 1;
    return {
      allowed: true,
      reason: "authorized",
      handler_invocations: this.invocations,
      receipt: {
        agent_id: result.agent_id,
        human_id: result.human_id,
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
      if (request.url === "/deploy" && body.proof) {
        return send(response, 200, await receiver.deploy(body.request, decodeProofBundle(body.proof)));
      }
      return send(response, 404, { error: "not_found" });
    } catch (error) {
      return send(response, 400, { error: error instanceof Error ? error.message : "invalid_request" });
    }
  });
}

export { base64StandardDecode };
