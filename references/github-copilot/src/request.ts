import { createHash } from "node:crypto";
import {
  buildSessionContext,
  operationContextHash,
  type OperationContext,
} from "@identities-ai/ratify-protocol";
import {
  REQUIRED_SCOPE,
  SESSION_ID,
  VERIFIER_ID,
  WORKSPACE_ID,
} from "./constants.js";

export interface DeployRequest {
  repository: string;
  service: string;
  environment: string;
  artifact_digest: string;
  invocation_id: string;
}

export function requestedPath(request: DeployRequest): string {
  return `/services/${request.service}/environments/${request.environment}`;
}

export function requestedResource(request: DeployRequest): string {
  return `github:${request.repository}`;
}

export function bindingFor(request: DeployRequest, agentID: string): {
  operation: OperationContext;
  sessionContext: Uint8Array;
} {
  const operation: OperationContext = {
    required_scope: REQUIRED_SCOPE,
    operation: "github.deploy",
    resource_id: requestedResource(request),
    requested_path: requestedPath(request),
    payload_digest: createHash("sha256")
      .update(JSON.stringify({ artifact_digest: request.artifact_digest }))
      .digest(),
  };
  return {
    operation,
    sessionContext: buildSessionContext({
      verifier_id: VERIFIER_ID,
      workspace_id: WORKSPACE_ID,
      agent_id: agentID,
      session_id: SESSION_ID,
      invocation_id: request.invocation_id,
      request_hash: operationContextHash(operation),
    }),
  };
}
