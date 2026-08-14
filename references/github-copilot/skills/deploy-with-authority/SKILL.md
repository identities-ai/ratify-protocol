---
name: deploy-with-authority
description: Deploy a service through the Ratify-protected MCP tool when a user asks to deploy to an environment.
---

# Deploy with Ratify authority

Use the `ratify-authority` MCP server's `deploy_service` tool for deployment requests.

Supply the repository, service, environment, artifact digest, and a unique invocation ID. Report the receiver's decision and receipt. Never claim success unless the tool returns `allowed: true` and `handler_invocations: 1`.

Do not attempt to reproduce, edit, or bypass the Ratify proof. The MCP adapter presents authority and the protected receiver independently verifies it.
