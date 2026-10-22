"""Ratify-aware Google ADK MCP integrations.

The supported integration uses ADK's public ``before_tool_callback`` and
``FunctionTool`` APIs. The model sees only business arguments; the callback
obtains a receiver-issued challenge and the tool sends the resulting proof in
MCP request metadata after ADK has selected the tool.

The native ``McpToolset`` adapter remains as an experimental compatibility
lane because ADK does not yet expose a public hook for adding custom MCP request
metadata to an ``McpTool`` invocation.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from copy import deepcopy
from functools import partial
import inspect
import json
from typing import Any

from google.adk.tools import FunctionTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.mcp_tool.mcp_session_manager import (
    MCPSessionManager,
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
from .mcp_metadata import ADMISSION_META_KEY, AUTHORITY_META_KEY


_PRESENTATION: ContextVar[tuple[int, tuple[str, str], str, str | None] | None] = ContextVar(
    "ratify_mcp_authority_presentation", default=None
)


class SupportedRatifyMcpAdapter(BaseToolset):
    """Public-API ADK callback and tool pair for a receiver-owned MCP tool."""

    def __init__(
        self,
        authority: AuthorityFixture,
        *,
        receiver_url: str,
        transport_token: str,
    ) -> None:
        super().__init__()
        self._authority = authority
        self._session_manager = MCPSessionManager(
            StreamableHTTPConnectionParams(
                url=receiver_url,
                headers={"X-Ratify-Transport-Token": transport_token},
                timeout=5,
                sse_read_timeout=30,
            )
        )

        async def provision_cloud_node(
            request_id: str,
            region: str,
            instance_type: str,
            count: int,
            tool_context: ToolContext,
        ) -> dict[str, Any]:
            """Provision cloud nodes under receiver-verified delegated authority."""
            key = (tool_context.invocation_id, tool_context.function_call_id or "")
            stored = _PRESENTATION.get()
            _PRESENTATION.set(None)
            if stored is None or stored[0] != id(self) or stored[1] != key:
                return {
                    "decision": "deny",
                    "status": "missing_authority_presentation",
                    "reason": "the ADK authority callback did not authorize this call",
                }
            presentation = stored[2]
            meta = {AUTHORITY_META_KEY: presentation}
            if stored[3] is not None:
                meta[ADMISSION_META_KEY] = stored[3]
            session = await self._session_manager.create_session()
            response = await session.call_tool(
                "provision_cloud_node",
                arguments={
                    "request_id": request_id,
                    "region": region,
                    "instance_type": instance_type,
                    "count": count,
                },
                meta=meta,
            )
            return _result_object(response)

        self.tool = FunctionTool(provision_cloud_node)

    async def get_tools(self, readonly_context=None) -> list[BaseTool]:
        return [self.tool]

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: Any,
    ) -> dict[str, Any] | None:
        """Authorize the selected operation without adding proof to tool args."""
        if tool is not self.tool:
            return None
        _PRESENTATION.set(None)
        if not tool_context.function_call_id:
            return {
                "decision": "deny",
                "status": "missing_call_id",
                "reason": "ADK did not provide a function call identifier",
            }
        session = await self._session_manager.create_session()
        grant = _result_object(await session.call_tool(
            "issue_authority_challenge",
            arguments=args,
        ))
        if grant.get("decision") == "deny" or "challenge" not in grant:
            return grant
        bundle = await asyncio.to_thread(
            partial(
                self._authority.present,
                challenge=base64_standard_decode(grant["challenge"]),
                session_context=base64_standard_decode(grant["session_context"]),
            )
        )
        key = (tool_context.invocation_id, tool_context.function_call_id)
        admission = None
        if self._authority.admission_delegations:
            admission = await asyncio.to_thread(
                partial(
                    self._authority.present_admission,
                    challenge=base64_standard_decode(grant["challenge"]),
                    session_context=base64_standard_decode(grant["session_context"]),
                )
            )
        _PRESENTATION.set((id(self), key, encode_proof_bundle(bundle),
                           encode_proof_bundle(admission) if admission else None))
        return None

    async def close(self) -> None:
        await self._session_manager.close()


def build_supported_mcp_adapter(
    authority: AuthorityFixture,
    *,
    receiver_url: str,
    transport_token: str,
) -> SupportedRatifyMcpAdapter:
    """Build the supported public-API ADK integration."""
    return SupportedRatifyMcpAdapter(
        authority,
        receiver_url=receiver_url,
        transport_token=transport_token,
    )


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
        admission = (
            self._authority.present_admission(
                challenge=base64_standard_decode(grant["challenge"]),
                session_context=base64_standard_decode(grant["session_context"]),
            )
            if self._authority.admission_delegations
            else None
        )
        response = await session.call_tool(
            self._mcp_tool.name,
            arguments=args,
            meta={AUTHORITY_META_KEY: encode_proof_bundle(bundle),
                  **({ADMISSION_META_KEY: encode_proof_bundle(admission)} if admission else {})},
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
