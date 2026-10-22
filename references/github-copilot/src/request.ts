import { createHash } from "node:crypto";
import {
  buildSessionContextV2,
  operationContextV2Hash,
  type OperationContextV2,
} from "@identities-ai/ratify-protocol/v2";
import { OPERATION, REQUIRED_SCOPE, SESSION_ID, WORKSPACE_ID } from "./constants.js";

export interface DeployRequest {
  repository: string;
  service: string;
  environment: string;
  artifact_digest: string;
  invocation_id: string;
}

// GitHub owner and repository names in the canonical (lowercase) form of the
// Git resource-identifier profile. The receiver rejects any other spelling
// rather than normalizing it: resource_id is compared by exact byte equality,
// so accepting two spellings of one repository would create two resources.
const CANONICAL_REPOSITORY = /^[a-z0-9](?:[a-z0-9-]{0,38})\/[a-z0-9._-]{1,100}$/;
const PATH_SEGMENT = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function requestedResource(request: DeployRequest): string {
  const repository = request.repository;
  if (!CANONICAL_REPOSITORY.test(repository) || repository.endsWith(".git") || /\/\.{1,2}$/.test(repository)) {
    throw new Error("repository must be a canonical lowercase owner/repo name");
  }
  return `git:github.com/${repository}`;
}

export function requestedPath(request: DeployRequest): string {
  if (!PATH_SEGMENT.test(request.service) || !PATH_SEGMENT.test(request.environment)) {
    throw new Error("service and environment must be lowercase path segments");
  }
  return `/services/${request.service}/environments/${request.environment}`;
}

/**
 * The exact operation and session binding (SPEC-v2 §2.4). The receiver
 * recomputes this from the request it is about to execute, so a proof bound
 * to one deployment cannot authorize another.
 */
export function bindingFor(request: DeployRequest, verifierID: string, agentID: string): {
  operation: OperationContextV2;
  sessionContext: Uint8Array;
} {
  if (typeof request.invocation_id !== "string" || request.invocation_id === "") {
    throw new Error("invocation_id is required");
  }
  const operation: OperationContextV2 = {
    required_scope: REQUIRED_SCOPE,
    operation: OPERATION,
    resource_id: requestedResource(request),
    requested_path: requestedPath(request),
    payload_digest: createHash("sha256")
      .update(JSON.stringify({ artifact_digest: request.artifact_digest }))
      .digest(),
  };
  return {
    operation,
    sessionContext: buildSessionContextV2({
      verifier_id: verifierID,
      workspace_id: WORKSPACE_ID,
      agent_id: agentID,
      session_id: SESSION_ID,
      invocation_id: request.invocation_id,
      request_hash: operationContextV2Hash(operation),
    }),
  };
}
