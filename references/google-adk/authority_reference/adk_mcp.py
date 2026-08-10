"""Ratify-aware native Google ADK MCP toolset.

The model sees only business arguments. This adapter obtains a receiver-issued
challenge and adds the proof presentation after ADK has selected the tool.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from typing import Any

from google.adk.tools.mcp_tool.mcp_session_manager import (
    StdioConnectionParams,
    StdioServerParameters,
)
from google.adk.tools.mcp_tool.mcp_tool import McpTool
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.genai.types import FunctionDeclaration
from ratify_protocol import (
    base64_standard_decode,
    base64_standard_encode,
    encode_proof_bundle,
)

from .authority import AuthorityFixture


class ProofInjectingMcpTool(McpTool):
    def __init__(self, *, authority: AuthorityFixture, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._authority = authority

    def _get_declaration(self) -> FunctionDeclaration:
        schema = deepcopy(self._mcp_tool.inputSchema)
        schema.get("properties", {}).pop("presentation", None)
        required = schema.get("required")
        if isinstance(required, list):
            schema["required"] = [name for name in required if name != "presentation"]
        return FunctionDeclaration(
            name=self.name,
            description=self.description,
            parameters_json_schema=schema,
            response_json_schema=self._mcp_tool.outputSchema,
        )

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
        session = await self._mcp_session_manager.create_session()
        grant_result = await session.call_tool(
            "issue_authority_challenge",
            arguments={**args, "expected_agent_id": self._authority.specialist_id},
        )
        grant = _result_object(grant_result)
        bundle = self._authority.present(
            challenge=base64_standard_decode(grant["challenge"]),
            session_context=base64_standard_decode(grant["session_context"]),
        )
        response = await session.call_tool(
            self.name,
            arguments={**args, "presentation": encode_proof_bundle(bundle)},
        )
        return _result_object(response)


class RatifyMcpToolset(McpToolset):
    def __init__(self, *, authority: AuthorityFixture, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._authority = authority

    async def get_tools(self, readonly_context=None):
        tools = await super().get_tools(readonly_context)
        return [
            ProofInjectingMcpTool(
                authority=self._authority,
                mcp_tool=tool._mcp_tool,
                mcp_session_manager=tool._mcp_session_manager,
            )
            for tool in tools
        ]


def build_mcp_toolset(authority: AuthorityFixture) -> RatifyMcpToolset:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(root),
            "RATIFY_TRUSTED_ROOT_ID": authority.root_id,
            "RATIFY_ROOT_ED25519": base64_standard_encode(
                authority.root_public_key.ed25519
            ),
            "RATIFY_ROOT_ML_DSA_65": base64_standard_encode(
                authority.root_public_key.ml_dsa_65
            ),
        }
    )
    return RatifyMcpToolset(
        authority=authority,
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=sys.executable,
                args=["-m", "authority_reference.mcp_server"],
                cwd=root,
                env=env,
            )
        ),
        tool_filter=["provision_cloud_node"],
    )


def _result_object(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured.get("result", structured)
    for item in result.content:
        text = getattr(item, "text", None)
        if text:
            parsed = json.loads(text)
            return parsed.get("result", parsed)
    raise ValueError("MCP receiver returned no structured result")
