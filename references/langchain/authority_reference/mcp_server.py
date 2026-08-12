"""Receiver-operated Streamable HTTP MCP service."""

from __future__ import annotations

import argparse
import asyncio
from contextvars import ContextVar
import hmac
import ipaddress
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from ratify_protocol import HybridPublicKey, base64_standard_decode, base64_standard_encode
import uvicorn

from .receiver import InfrastructureReceiver, OperationRequest


_request_headers: ContextVar[dict[bytes, bytes]] = ContextVar("request_headers", default={})


def load_receiver(path: str):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    receiver = InfrastructureReceiver(
        trusted_root_id=config["trusted_root_id"],
        trusted_root_public_key=HybridPublicKey(
            ed25519=base64_standard_decode(config["root_ed25519"]),
            ml_dsa_65=base64_standard_decode(config["root_ml_dsa_65"]),
        ),
    )
    return receiver, config["trusted_agent_id"], config["transport_token"]


class HeaderBoundary:
    def __init__(self, app, token: str) -> None:
        self.app = app
        self.token = token.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        if not hmac.compare_digest(headers.get(b"x-ratify-transport-token", b""), self.token):
            await send({"type": "http.response.start", "status": 401, "headers": []})
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
        reset = _request_headers.set(headers)
        try:
            return await self.app(scope, receive, send)
        finally:
            _request_headers.reset(reset)


def create_server(receiver, trusted_agent_id: str, host: str, port: int):
    server = FastMCP("ratify-langchain-authority-receiver", host=host, port=port,
                     stateless_http=False, log_level="ERROR")

    @server.tool()
    async def issue_authority_challenge(request_id: str, region: str,
                                        instance_type: str, count: int) -> dict:
        try:
            grant = await asyncio.to_thread(
                receiver.issue_challenge,
                OperationRequest(request_id, region, instance_type, count),
                expected_agent_id=trusted_agent_id,
            )
        except ValueError as exc:
            return {"decision": "deny", "status": "challenge_rejected",
                    "reason": str(exc), "tool_invocations": receiver.tool_invocations}
        return {"challenge": base64_standard_encode(grant.challenge),
                "session_context": base64_standard_encode(grant.session_context),
                "expires_at": grant.expires_at}

    @server.tool()
    async def provision_cloud_node(request_id: str, region: str,
                                   instance_type: str, count: int) -> dict:
        presentation = _request_headers.get().get(b"x-ratify-presentation", b"").decode()
        return await asyncio.to_thread(
            receiver.execute,
            OperationRequest(request_id, region, instance_type, count), presentation,
        )
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trust-config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    host = "127.0.0.1" if args.host == "localhost" else args.host
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError as exc:
        raise SystemExit("--host must be localhost or a numeric loopback address") from exc
    if not loopback:
        raise SystemExit("non-loopback bind requires production TLS/auth")
    receiver, agent_id, token = load_receiver(args.trust_config)
    server = create_server(receiver, agent_id, host, args.port)
    uvicorn.run(HeaderBoundary(server.streamable_http_app(), token), host=host,
                port=args.port, log_level="error")


if __name__ == "__main__":
    main()
