"""Receiver-operated Streamable HTTP MCP service."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import ipaddress
from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP
import uvicorn

from ratify_protocol_v2.types import HybridPublicKey

from .deployment_config import decode_private_key, decode_public_key
from .receiver import (
    DualPresentation,
    FederationPolicy,
    FederationRoute,
    InfrastructureReceiver,
    OperationRequest,
    SqliteNodeProvisioner,
    grant_to_json,
)
from .mcp_metadata import ADMISSION_META_KEY, AUTHORITY_META_KEY
from .status_feed import DirectoryStatusSource


_TRANSPORT_HEADER = b"x-ratify-transport-token"


def _unique_header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    values = [value for key, value in headers if key.lower() == name]
    if len(values) > 1:
        raise ValueError(f"duplicate {name.decode()} header")
    return values[0] if values else None


def _routes(entries: list[dict]) -> list[FederationRoute]:
    return [
        FederationRoute(
            agent_id=route["agent_id"],
            root_id=route["root_id"],
            subjects_leaf_to_root=tuple(route["subjects_leaf_to_root"]),
        )
        for route in entries
    ]


def load_receiver(path: str) -> tuple[InfrastructureReceiver, HybridPublicKey, str]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if not config.get("federation_routes"):
        raise ValueError("receiver config must include non-empty federation_routes")
    root_public_key = decode_public_key(config["root_public_key"])
    admission_policy = None
    admission_fields = {"admission_root_id", "admission_root_public_key", "admission_routes"}
    if admission_fields.intersection(config):
        if not all(config.get(field) for field in admission_fields):
            raise ValueError("dual-root receiver config must include complete admission policy")
        admission_policy = FederationPolicy(
            roots={config["admission_root_id"]: decode_public_key(config["admission_root_public_key"])},
            routes=_routes(config["admission_routes"]),
        )
    receiver = InfrastructureReceiver(
        trusted_root_id=config["trusted_root_id"],
        trusted_root_public_key=root_public_key,
        federation_policy=FederationPolicy(
            roots={config["trusted_root_id"]: root_public_key},
            routes=_routes(config["federation_routes"]),
        ),
        admission_policy=admission_policy,
        verifier_private_key=decode_private_key(config["verifier_private_key"]),
        log_id=config["log_id"],
        status_keys={
            issuer_id: decode_public_key(key) for issuer_id, key in config["status_keys"].items()
        },
        status_source=DirectoryStatusSource(config["status_feed_dir"]),
        challenge_ttl_seconds=config.get("challenge_ttl_seconds", 300),
        pending_capacity=config.get("pending_capacity", 128),
    )
    agent_public_key = decode_public_key(config["agent_public_key"])
    return receiver, agent_public_key, config["transport_token"]


class TransportTokenBoundary:
    """Authenticate the reference transport without consuming Authorization."""

    def __init__(self, app, token: str) -> None:
        self._app = app
        self._token = token.encode("utf-8")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            try:
                supplied = _unique_header(scope.get("headers", []), _TRANSPORT_HEADER)
            except ValueError:
                await send({
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [(b"content-type", b"text/plain")],
                })
                await send({"type": "http.response.body", "body": b"Ambiguous security header"})
                return
            if not hmac.compare_digest(supplied or b"", self._token):
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
    agent_public_key: HybridPublicKey,
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
                agent_public_key=agent_public_key,
            )
        except ValueError as exc:
            return {
                "decision": "deny",
                "status": "challenge_rejected",
                "reason": str(exc),
                "tool_invocations": receiver.tool_invocations,
            }
        return grant_to_json(grant)

    @server.tool()
    async def provision_cloud_node(
        request_id: str,
        region: str,
        instance_type: str,
        count: int,
        ctx: Context,
    ) -> dict:
        """Provision only after receiver-side authority verification."""
        meta = ctx.request_context.meta
        if isinstance(meta, dict):
            extra = meta
        else:
            extra = getattr(meta, "model_extra", None) if meta else None
            if extra is None and meta is not None:
                if hasattr(meta, "model_dump"):
                    extra = meta.model_dump()
                elif hasattr(meta, "dict"):
                    extra = meta.dict()
        presentation = extra.get(AUTHORITY_META_KEY) if extra else None
        if not isinstance(presentation, str):
            return {
                "decision": "deny",
                "status": "missing_authority_presentation",
                "reason": "delegated authority is required in MCP request metadata",
                "tool_invocations": receiver.tool_invocations,
            }
        admission = extra.get(ADMISSION_META_KEY) if extra else None
        submitted = (
            DualPresentation(authority=presentation, admission=admission)
            if isinstance(admission, str)
            else presentation
        )
        return await asyncio.to_thread(
            receiver.execute,
            OperationRequest(request_id, region, instance_type, count), submitted
        )

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trust-config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--protected-db")
    args = parser.parse_args()
    bind_host = "127.0.0.1" if args.host == "localhost" else args.host
    try:
        is_loopback = ipaddress.ip_address(bind_host).is_loopback
    except ValueError as exc:
        raise SystemExit("--host must be localhost or a numeric loopback address") from exc
    if not is_loopback:
        raise SystemExit("non-loopback bind requires a production TLS/auth deployment")
    receiver, agent_public_key, transport_token = load_receiver(args.trust_config)
    if args.protected_db:
        receiver.provisioner = SqliteNodeProvisioner(args.protected_db)
    server = create_server(
        receiver, agent_public_key, bind_host, args.port
    )
    uvicorn.run(
        TransportTokenBoundary(server.streamable_http_app(), transport_token),
        host=bind_host,
        port=args.port,
        log_level="error",
    )


if __name__ == "__main__":
    main()
