import { createDemoAuthority } from "./authority.js";
import { createReceiverServer, ProtectedDeployReceiver } from "./receiver.js";
import { DemoStatusFeed } from "./status-feed.js";

const authority = await createDemoAuthority();
// The principal's status publisher runs in this process only to keep the demo
// to one command. The receiver verifies every status object against the
// pinned status key, so where the feed is hosted does not change the decision.
const feed = await DemoStatusFeed.create(authority, Math.floor(Date.now() / 1000));
const receiver = await ProtectedDeployReceiver.create({
  trustedRoot: { id: authority.rootID, publicKey: authority.root.publicKey },
  statusKey: authority.status.publicKey,
  expectedAgent: authority.agent.publicKey,
  statusFeed: (now) => feed.current(now),
});
const port = Number(process.env.RATIFY_RECEIVER_PORT ?? "8787");
createReceiverServer(receiver).listen(port, "127.0.0.1", () => {
  console.log(`Ratify Protocol v2 protected receiver listening at http://127.0.0.1:${port}`);
  console.log("Development only: in-memory reference stores");
  console.log(`Trusted root key ID: ${authority.rootID}`);
});
