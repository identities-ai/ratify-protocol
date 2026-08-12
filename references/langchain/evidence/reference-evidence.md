# LangChain reference evidence

**Evidence date:** 2026-08-11

**Branch:** `feat/langchain-reference`

**Base commit:** `380d4dddd658a879347a642b93092721da5d6c8b`

**Requirements SHA-256:** `0387f1ff4d240616e34b178ef0a7a116e775f7fb7c955685857f0dd064da078e`

## Executed gate

```text
$ ./scripts/langchain-reference-check.sh
published Ratify: .../site-packages/ratify_protocol/__init__.py
pins: langchain==1.3.14 langchain-mcp-adapters==0.3.0 mcp==1.29.0
.....................                                                    [100%]
21 passed in 3.29s
```

Zero tests were skipped or marked xfail. The gate rejected the repository's
local Python SDK and used `ratify-protocol==1.0.0a16` from the disposable virtual
environment.

## Evidence covered

- valid delegated authority invokes the protected handler once;
- scope/resource and signed node-ceiling denials invoke it zero times;
- expiry, revocation, replay, operation alteration, wrong agent, and hostile
  root fail closed;
- malformed proof does not consume an honest pending operation;
- invalid business values never reach verification or execution;
- receiver pending state is bounded and concurrent duplicate request IDs yield
  one challenge;
- unauthenticated HTTP cannot reach the MCP receiver;
- the model-visible schema excludes proof material;
- the public MCP interceptor injects proof after tool selection; and
- the real `create_agent` LangGraph loop executes the gated HTTP MCP tool.

This evidence supports only the independent draft and limitations documented in
the profile README. It is not evidence of LangChain review or endorsement.
