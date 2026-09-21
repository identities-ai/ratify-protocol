# LangChain reference evidence

**Evidence date:** 2026-09-20

**Branch:** `feat/jev-ratify-timing-reference`

**Base commit:** `762c95a`

**Requirements SHA-256:** `0387f1ff4d240616e34b178ef0a7a116e775f7fb7c955685857f0dd064da078e`

## Executed gate

```text
$ ./scripts/langchain-reference-check.sh
published Ratify: .../site-packages/ratify_protocol/__init__.py
pins: langchain==1.3.14 langchain-mcp-adapters==0.3.0 mcp==1.29.0
..........................                                               [100%]
28 passed in 4.79s
```

Zero tests were skipped or marked xfail. The gate rejected the repository's
local Python SDK and used `ratify-protocol==1.0.0a19` from the disposable virtual
environment.

## Evidence covered

- valid delegated authority invokes the protected handler once;
- scope/resource and signed node-ceiling denials invoke it zero times;
- expiry, revocation, replay, operation alteration, wrong agent, and hostile
  root fail closed;
- revocation and expiry that occur after the agent's local preflight are
  rechecked by the receiver and fail closed;
- the local preflight passes before those changes, while paired control actions
  are allowed before the change;
- malformed proof does not consume an honest pending operation;
- invalid business values never reach verification or execution;
- receiver pending state is bounded and concurrent duplicate request IDs yield
  one challenge;
- unauthenticated HTTP cannot reach the MCP receiver;
- duplicate transport or presentation headers and oversized presentation
  headers fail before MCP dispatch;
- the model-visible schema excludes proof material;
- the public MCP interceptor injects proof after tool selection; and
- the real `create_agent` LangGraph loop executes the gated HTTP MCP tool.
- the optional Jev adapter returns a typed tool proposal and probabilities; and
- a Jev-selected tool still fails closed when receiver authority is out of scope.

This evidence supports only the independent draft and limitations documented in
the profile README. It is not evidence of LangChain review or endorsement.
