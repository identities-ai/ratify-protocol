import { createDemoAuthority } from "./authority.js";
import { createReceiverServer, ProtectedDeployReceiver } from "./receiver.js";

const authority = await createDemoAuthority();
const receiver = new ProtectedDeployReceiver(authority.root.id, authority.agent.id);
const port = Number(process.env.RATIFY_RECEIVER_PORT ?? "8787");
createReceiverServer(receiver).listen(port, "127.0.0.1", () => {
  console.log(`Ratify protected receiver listening at http://127.0.0.1:${port}`);
  console.log(`Trusted root: ${authority.root.id}`);
});
