"""Receiver-operated Streamable HTTP MCP service."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import ipaddress
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from ratify_protocol import HybridPublicKey, base64_standard_decode, base64_standard_encode
import uvicorn

from .receiver import InfrastructureReceiver, OperationRequest


def load_receiver(path: str) -> tuple[InfrastructureReceiver, str, str]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    receiver = InfrastructureReceiver(
        trusted_root_id=config["trusted_root_id"],
        trusted_root_public_key=HybridPublicKey(
            ed25519=base64_standard_decode(config["root_ed25519"]),
            ml_dsa_65=base64_standard_decode(config["root_ml_dsa_65"]),
        ),
    )
    return receiver, config["trusted_agent_id"], config["transport_token"]


class TransportTokenBoundary:
    """Authenticate the reference transport without consuming Authorization."""

    def __init__(self, app, token: str) -> None:
        self._app = app
        self._token = token.encode("utf-8")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            supplied = headers.get(b"x-ratify-transport-token", b"")
            if not hmac.compare_digest(supplied, self._token):
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"text/plain")],
                })
                await send({"type": "http.response.body", "body": b"Unauthorized"})
                return
        await self._app(scope, receive, send)


def create_server(
    receiver: InfrastructureReceiver,
    trusted_agent_id: str,
    host: str,
    port: int,
) -> FastMCP:
    server = FastMCP(
        "ratify-adk-authority-receiver",
        host=host,
        port=port,
        stateless_http=False,
        log_level="ERROR",
    )

    @server.tool()
    async def issue_authority_challenge(
        request_id: str,
        region: str,
        instance_type: str,
        count: int,
    ) -> dict:
        """Internal adapter operation; excluded from the ADK model toolset."""
        try:
            grant = await asyncio.to_thread(
                receiver.issue_challenge,
                OperationRequest(request_id, region, instance_type, count),
                expected_agent_id=trusted_agent_id,
            )
        except ValueError as exc:
            return {
                "decision": "deny",
                "status": "challenge_rejected",
                "reason": str(exc),
                "tool_invocations": receiver.tool_invocations,
            }
        return {
            "challenge": base64_standard_encode(grant.challenge),
            "session_context": base64_standard_encode(grant.session_context),
            "expires_at": grant.expires_at,
        }

    @server.tool()
    async def provision_cloud_node(
        request_id: str,
        region: str,
        instance_type: str,
        count: int,
        presentation: str,
    ) -> dict:
        """Provision only after receiver-side authority verification."""
        return await asyncio.to_thread(
            receiver.execute,
            OperationRequest(request_id, region, instance_type, count), presentation
        )

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trust-config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    bind_host = "127.0.0.1" if args.host == "localhost" else args.host
    try:
        is_loopback = ipaddress.ip_address(bind_host).is_loopback
    except ValueError as exc:
        raise SystemExit("--host must be localhost or a numeric loopback address") from exc
    if not is_loopback:
        raise SystemExit("non-loopback bind requires a production TLS/auth deployment")
    receiver, trusted_agent_id, transport_token = load_receiver(args.trust_config)
    server = create_server(
        receiver, trusted_agent_id, bind_host, args.port
    )
    uvicorn.run(
        TransportTokenBoundary(server.streamable_http_app(), transport_token),
        host=bind_host,
        port=args.port,
        log_level="error",
    )


if __name__ == "__main__":
    main()
