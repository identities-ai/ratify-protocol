import {
  base64StandardDecode,
  encodeProofBundle,
  type ProofBundle,
} from "@identities-ai/ratify-protocol";
import { createDemoAuthority, presentAuthority, type DemoAuthority } from "./authority.js";
import type { DeployDecision } from "./receiver.js";
import type { DeployRequest } from "./request.js";

async function post<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`receiver returned HTTP ${response.status}`);
  return await response.json() as T;
}

export async function invokeProtectedDeploy(
  receiverURL: string,
  request: DeployRequest,
  authority?: DemoAuthority,
): Promise<{ decision: DeployDecision; proof: ProofBundle }> {
  const presenter = authority ?? await createDemoAuthority();
  const challenge = await post<{ challenge: string; session_context: string }>(
    `${receiverURL}/challenge`,
    { request },
  );
  const proof = await presentAuthority(
    presenter,
    base64StandardDecode(challenge.challenge),
    base64StandardDecode(challenge.session_context),
  );
  const decision = await post<DeployDecision>(`${receiverURL}/deploy`, {
    request,
    proof: encodeProofBundle(proof),
  });
  return { decision, proof };
}
