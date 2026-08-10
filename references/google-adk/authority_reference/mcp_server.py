"""Separate stdio MCP receiver process for the ADK reference."""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from ratify_protocol import HybridPublicKey, base64_standard_decode

from .receiver import InfrastructureReceiver, OperationRequest


def _trusted_receiver() -> InfrastructureReceiver:
    return InfrastructureReceiver(
        trusted_root_id=os.environ["RATIFY_TRUSTED_ROOT_ID"],
        trusted_root_public_key=HybridPublicKey(
            ed25519=base64_standard_decode(os.environ["RATIFY_ROOT_ED25519"]),
            ml_dsa_65=base64_standard_decode(os.environ["RATIFY_ROOT_ML_DSA_65"]),
        ),
    )


receiver = _trusted_receiver()
mcp = FastMCP("ratify-adk-authority-receiver", log_level="ERROR")


@mcp.tool()
def issue_authority_challenge(
    request_id: str,
    region: str,
    instance_type: str,
    count: int,
    expected_agent_id: str,
) -> dict:
    """Internal adapter operation; excluded from the ADK model toolset."""
    grant = receiver.issue_challenge(
        OperationRequest(request_id, region, instance_type, count),
        expected_agent_id=expected_agent_id,
    )
    from ratify_protocol import base64_standard_encode

    return {
        "challenge": base64_standard_encode(grant.challenge),
        "session_context": base64_standard_encode(grant.session_context),
        "expires_at": grant.expires_at,
    }


@mcp.tool()
def provision_cloud_node(
    request_id: str,
    region: str,
    instance_type: str,
    count: int,
    presentation: str,
) -> dict:
    """Provision cloud nodes only after receiver-side authority verification."""
    return receiver.execute(
        OperationRequest(request_id, region, instance_type, count), presentation
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
