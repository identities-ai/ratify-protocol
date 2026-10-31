import { createDemoAuthority, presentAuthority, type ChallengeResponse, type DemoAuthority } from "./authority.js";
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
): Promise<{ decision: DeployDecision; proof: Uint8Array }> {
  const presenter = authority ?? await createDemoAuthority();
  const challenge = await post<ChallengeResponse>(`${receiverURL}/challenge`, { request });
  const proof = await presentAuthority(presenter, {
    value: new Uint8Array(Buffer.from(challenge.challenge, "base64")),
    challengeAt: challenge.challenge_at,
    verifierID: challenge.verifier_id,
    sessionContext: new Uint8Array(Buffer.from(challenge.session_context, "base64")),
  });
  const decision = await post<DeployDecision>(`${receiverURL}/deploy`, {
    request,
    proof: Buffer.from(proof).toString("base64"),
  });
  return { decision, proof };
}
