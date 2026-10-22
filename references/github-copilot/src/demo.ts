import { once } from "node:events";
import { invokeProtectedDeploy } from "./adapter.js";
import { createDemoAuthority } from "./authority.js";
import { CERT_ID } from "./constants.js";
import { createReceiverServer, ProtectedDeployReceiver } from "./receiver.js";
import { DemoStatusFeed } from "./status-feed.js";

const now = () => Math.floor(Date.now() / 1000);
const authority = await createDemoAuthority();
const feed = await DemoStatusFeed.create(authority, now());
const receiver = await ProtectedDeployReceiver.create({
  trustedRoot: { id: authority.rootID, publicKey: authority.root.publicKey },
  statusKey: authority.status.publicKey,
  expectedAgent: authority.agent.publicKey,
  statusFeed: (at) => feed.current(at),
});
const server = createReceiverServer(receiver).listen(0, "127.0.0.1");
await once(server, "listening");
const address = server.address();
if (!address || typeof address === "string") throw new Error("receiver did not bind TCP");
const url = `http://127.0.0.1:${address.port}`;

const label = (d: { allowed: boolean; reason: string }) => `${d.allowed ? "ALLOW" : "DENY"}: ${d.reason}`;

try {
  const request = {
    repository: "identities-ai/copilot-authority-demo",
    service: "payments",
    environment: "staging",
    artifact_digest: "sha256:9f86d081884c7d659a2feaa0c55ad015",
    invocation_id: "copilot-live-demo-001",
  };
  console.log("Ratify Protocol v2 reference (development only: in-memory reference stores)");
  console.log("COPILOT calls MCP tool: deploy_service");
  console.log("ADAPTER obtains a receiver challenge and presents Ratify authority");
  const { decision, proof } = await invokeProtectedDeploy(url, request, authority);
  console.log(`RECEIVER ${label(decision)}`);
  console.log(JSON.stringify(decision, null, 2));

  console.log(`REPLAY ${label(await receiver.deploy(request, proof))}`);
  console.log(`CHANGED OPERATION ${label(await receiver.deploy({ ...request, environment: "production" }, proof))}`);

  await feed.revoke(CERT_ID, now() + 1);
  const afterRevoke = await invokeProtectedDeploy(url, { ...request, invocation_id: "copilot-live-demo-002" }, authority);
  console.log(`AFTER SIGNED REVOCATION ${label(afterRevoke.decision)}`);
  console.log(`PROTECTED HANDLER INVOCATIONS: ${afterRevoke.decision.handler_invocations}`);
} finally {
  server.close();
}
