// Independent Node A2A JSON-RPC caller for the HTTPS reference gate.
import { randomUUID } from "node:crypto";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (new URL(input.url).protocol !== "https:") {
  throw new Error("A2A bearer token requires HTTPS");
}
const message = {
  messageId: randomUUID(),
  role: "ROLE_USER",
  parts: [{ data: input.data, mediaType: "application/json" }],
};
if (input.metadata) message.metadata = input.metadata;
if (input.contextId) message.contextId = input.contextId;
if (input.taskId) message.taskId = input.taskId;
const response = await fetch(input.url, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "A2A-Version": "1.0",
    "A2A-Extensions": input.extension,
    Authorization: `Bearer ${input.token}`,
  },
  body: JSON.stringify({
    jsonrpc: "2.0", id: randomUUID(), method: "SendMessage",
    params: { message },
  }),
});
process.stdout.write(JSON.stringify({ status: response.status, body: await response.json() }));
