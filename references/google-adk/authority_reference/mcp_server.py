"""Receiver-operated Streamable HTTP MCP service."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from ratify_protocol import HybridPublicKey, base64_standard_decode, base64_standard_encode

from .receiver import InfrastructureReceiver, OperationRequest


def load_receiver(path: str) -> tuple[InfrastructureReceiver, str]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    receiver = InfrastructureReceiver(
        trusted_root_id=config["trusted_root_id"],
        trusted_root_public_key=HybridPublicKey(
            ed25519=base64_standard_decode(config["root_ed25519"]),
            ml_dsa_65=base64_standard_decode(config["root_ml_dsa_65"]),
        ),
    )
    return receiver, config["trusted_agent_id"]


def create_server(
    receiver: InfrastructureReceiver, trusted_agent_id: str, host: str, port: int
) -> FastMCP:
    server = FastMCP(
        "ratify-adk-authority-receiver",
        host=host,
        port=port,
        stateless_http=False,
        log_level="ERROR",
    )

    @server.tool()
    def issue_authority_challenge(
        request_id: str,
        region: str,
        instance_type: str,
        count: int,
    ) -> dict:
        """Internal adapter operation; excluded from the ADK model toolset."""
        grant = receiver.issue_challenge(
            OperationRequest(request_id, region, instance_type, count),
            expected_agent_id=trusted_agent_id,
        )
        return {
            "challenge": base64_standard_encode(grant.challenge),
            "session_context": base64_standard_encode(grant.session_context),
            "expires_at": grant.expires_at,
        }

    @server.tool()
    def provision_cloud_node(
        request_id: str,
        region: str,
        instance_type: str,
        count: int,
        presentation: str,
    ) -> dict:
        """Provision only after receiver-side authority verification."""
        return receiver.execute(
            OperationRequest(request_id, region, instance_type, count), presentation
        )

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trust-config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    receiver, trusted_agent_id = load_receiver(args.trust_config)
    create_server(receiver, trusted_agent_id, args.host, args.port).run(
        transport="streamable-http"
    )


if __name__ == "__main__":
    main()
