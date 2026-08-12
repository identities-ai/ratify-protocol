"""Native LangChain MCP presentation layer."""

from __future__ import annotations

import json
from typing import Any

from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient
from ratify_protocol import base64_standard_decode, encode_proof_bundle

from .authority import AuthorityFixture


def _result(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        for block in value:
            if isinstance(block, dict) and block.get("text"):
                return json.loads(block["text"])
    if hasattr(value, "artifact") and value.artifact:
        structured = value.artifact.structured_content
        return structured.get("result", structured)
    raise ValueError("receiver returned no structured result")


async def build_mcp_tools(
    authority: AuthorityFixture, *, receiver_url: str, transport_token: str
):
    connection = {
        "receiver": {
            "transport": "http",
            "url": receiver_url,
            "headers": {"X-Ratify-Transport-Token": transport_token},
        }
    }
    challenge_client = MultiServerMCPClient(connection, handle_tool_errors=False)
    challenge_tools = await challenge_client.get_tools()
    challenge_tool = next(
        tool for tool in challenge_tools
        if tool.name == "issue_authority_challenge"
    )

    async def inject_authority(request, handler):
        if request.name != "provision_cloud_node":
            return await handler(request)
        grant = _result(await challenge_tool.ainvoke(request.args))
        if grant.get("decision") == "deny":
            return grant
        bundle = authority.present(
            challenge=base64_standard_decode(grant["challenge"]),
            session_context=base64_standard_decode(grant["session_context"]),
        )
        headers = dict(request.headers or {})
        headers["X-Ratify-Presentation"] = encode_proof_bundle(bundle)
        return await handler(request.override(headers=headers))

    client = MultiServerMCPClient(
        connection, tool_interceptors=[inject_authority], handle_tool_errors=False
    )
    tools = await client.get_tools()
    return [t for t in tools if t.name == "provision_cloud_node"]


def build_agent(model, tools):
    return create_agent(
        model,
        tools,
        system_prompt=(
            "Use provision_cloud_node for infrastructure changes. Report receiver "
            "denials exactly; never claim success when decision is deny."
        ),
        name="ratify_infrastructure_specialist",
    )
