#!/usr/bin/env python3
"""One-command deterministic demonstration across native ADK MCP."""

from __future__ import annotations

import asyncio

from authority_reference import build_mcp_toolset, issue_authority


async def run() -> None:
    authority = issue_authority()
    toolset = build_mcp_toolset(authority)
    try:
        tool = (await toolset.get_tools())[0]

        async def invoke(request_id: str, region: str, count: int):
            return await tool.run_async(
                args={
                    "request_id": request_id,
                    "region": region,
                    "instance_type": "n2-standard-4",
                    "count": count,
                },
                tool_context=None,
            )

        allowed = await invoke("req-allow", "us-central1", 1)
        excessive = await invoke("req-count", "us-central1", 3)
        wrong_region = await invoke("req-region", "us-east1", 1)

        print(f"ALLOW across ADK MCP -> tool invoked once: {allowed}")
        print(f"DENY excessive count -> no additional invocation: {excessive}")
        print(f"DENY wrong region -> no additional invocation: {wrong_region}")

        assert allowed["decision"] == "allow" and allowed["tool_invocations"] == 1
        assert excessive["decision"] == "deny" and excessive["tool_invocations"] == 1
        assert wrong_region["decision"] == "deny" and wrong_region["tool_invocations"] == 1
        print("GOOGLE ADK MCP AUTHORITY REFERENCE PASSED")
    finally:
        await toolset.close()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
