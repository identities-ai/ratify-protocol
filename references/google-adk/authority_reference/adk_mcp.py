"""Ratify-aware native Google ADK MCP toolset.

The model sees only business arguments. This adapter obtains a receiver-issued
challenge and adds the proof presentation after ADK has selected the tool.
"""

from __future__ import annotations

from copy import deepcopy
import inspect
import json
from typing import Any

from google.adk.tools.mcp_tool.mcp_session_manager import (
    StreamableHTTPConnectionParams,
)
from google.adk.tools.mcp_tool.mcp_tool import McpTool
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.agents.readonly_context import ReadonlyContext
from google.genai.types import FunctionDeclaration
from ratify_protocol import (
    base64_standard_decode,
    encode_proof_bundle,
)

from .authority import AuthorityFixture


class ProofInjectingMcpTool(McpTool):
    def __init__(self, *, authority: AuthorityFixture, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._authority = authority

    def _get_declaration(self) -> FunctionDeclaration:
        declaration = deepcopy(super()._get_declaration())
        if declaration.parameters_json_schema:
            schema = declaration.parameters_json_schema
            schema.get("properties", {}).pop("presentation", None)
            schema["required"] = [
                name for name in schema.get("required", [])
                if name != "presentation"
            ]
        elif declaration.parameters:
            declaration.parameters.properties.pop("presentation", None)
            declaration.parameters.required = [
                name for name in (declaration.parameters.required or [])
                if name != "presentation"
            ]
        return declaration

    async def _run_async_impl(
        self, *, args: dict[str, Any], tool_context: Any, credential: Any
    ) -> Any:
        headers = await self._get_headers(tool_context, credential) or {}
        if self._header_provider:
            dynamic = self._header_provider(
                ReadonlyContext(tool_context._invocation_context)
            )
            if inspect.isawaitable(dynamic):
                dynamic = await dynamic
            headers.update(dynamic or {})
        session = await self._mcp_session_manager.create_session(
            headers=headers or None
        )
        grant_result = await session.call_tool(
            "issue_authority_challenge",
            arguments=args,
        )
        grant = _result_object(grant_result)
        if grant.get("decision") == "deny" or "challenge" not in grant:
            return grant
        bundle = self._authority.present(
            challenge=base64_standard_decode(grant["challenge"]),
            session_context=base64_standard_decode(grant["session_context"]),
        )
        response = await super()._run_async_impl(
            args={**args, "presentation": encode_proof_bundle(bundle)},
            tool_context=tool_context,
            credential=credential,
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
                auth_scheme=self._auth_scheme,
                auth_credential=self._auth_credential,
                require_confirmation=self._require_confirmation,
                header_provider=self._header_provider,
                progress_callback=self._progress_callback,
            )
            for tool in tools
        ]


def build_mcp_toolset(
    authority: AuthorityFixture, *, receiver_url: str, transport_token: str, **kwargs: Any
) -> RatifyMcpToolset:
    """Connect to an independently operated receiver; never configures its trust."""
    return RatifyMcpToolset(
        authority=authority,
        connection_params=StreamableHTTPConnectionParams(
            url=receiver_url,
            headers={"X-Ratify-Transport-Token": transport_token},
            timeout=5,
            sse_read_timeout=30,
        ),
        tool_filter=["provision_cloud_node"],
        **kwargs,
    )


def _result_object(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured.get("result", structured)
        content = result.get("content", [])
        if result.get("isError"):
            reason = next(
                (item.get("text") for item in content if item.get("text")),
                "MCP receiver error",
            )
            return {"decision": "deny", "status": "mcp_error", "reason": _safe_error(reason)}
        for item in content:
            text = item.get("text")
            if text:
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    return {"decision": "deny", "status": "mcp_error", "reason": _safe_error(text)}
                return parsed.get("result", parsed)
        return result
    if getattr(result, "isError", False):
        reason = "MCP receiver error"
        for item in result.content:
            if getattr(item, "text", None):
                reason = item.text
                break
        return {"decision": "deny", "status": "mcp_error", "reason": _safe_error(reason)}
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured.get("result", structured)
    for item in result.content:
        text = getattr(item, "text", None)
        if text:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return {"decision": "deny", "status": "mcp_error", "reason": _safe_error(text)}
            return parsed.get("result", parsed)
    return {"decision": "deny", "status": "mcp_error", "reason": "empty MCP result"}


def _safe_error(value: str) -> str:
    return value[:512]
