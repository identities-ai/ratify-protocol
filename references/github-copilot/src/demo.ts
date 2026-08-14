import { once } from "node:events";
import { invokeProtectedDeploy } from "./adapter.js";
import { createDemoAuthority } from "./authority.js";
import { createReceiverServer, ProtectedDeployReceiver } from "./receiver.js";

const authority = await createDemoAuthority();
const receiver = new ProtectedDeployReceiver(authority.root.id, authority.agent.id);
const server = createReceiverServer(receiver).listen(0, "127.0.0.1");
await once(server, "listening");
const address = server.address();
if (!address || typeof address === "string") throw new Error("receiver did not bind TCP");
const url = `http://127.0.0.1:${address.port}`;

try {
  const request = {
    repository: "identities-ai/copilot-authority-demo",
    service: "payments",
    environment: "staging",
    artifact_digest: "sha256:9f86d081884c7d659a2feaa0c55ad015",
    invocation_id: "copilot-live-demo-001",
  };
  console.log("COPILOT calls MCP tool: deploy_service");
  console.log("ADAPTER obtains a receiver challenge and presents Ratify authority");
  const { decision, proof } = await invokeProtectedDeploy(url, request, authority);
  console.log(`RECEIVER ${decision.allowed ? "ALLOW" : "DENY"}: ${decision.reason}`);
  console.log(JSON.stringify(decision.receipt, null, 2));

  const replay = await receiver.deploy(request, proof);
  console.log(`REPLAY ${replay.allowed ? "ALLOW" : "DENY"}: ${replay.reason}`);

  const changed = { ...request, environment: "production" };
  const mismatch = await receiver.deploy(changed, proof);
  console.log(`CHANGED OPERATION ${mismatch.allowed ? "ALLOW" : "DENY"}: ${mismatch.reason}`);
  console.log(`PROTECTED HANDLER INVOCATIONS: ${decision.handler_invocations}`);
} finally {
  server.close();
}
