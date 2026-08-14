import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { invokeProtectedDeploy } from "./adapter.js";

const server = new McpServer({ name: "ratify-authority", version: "0.1.0" });
server.tool(
  "deploy_service",
  "Deploy a service only after the receiver verifies bounded Ratify authority.",
  {
    repository: z.string(),
    service: z.string(),
    environment: z.string(),
    artifact_digest: z.string(),
    invocation_id: z.string(),
  },
  async (request) => {
    const { decision } = await invokeProtectedDeploy(
      process.env.RATIFY_RECEIVER_URL ?? "http://127.0.0.1:8787",
      request,
    );
    return {
      isError: !decision.allowed,
      content: [{ type: "text", text: JSON.stringify(decision, null, 2) }],
    };
  },
);
await server.connect(new StdioServerTransport());
