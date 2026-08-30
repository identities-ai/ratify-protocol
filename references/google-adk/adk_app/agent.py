"""Optional live Gemini + native MCP entry point for ``adk run adk_app``."""

import os

from google.adk.agents import LlmAgent

from authority_reference import build_mcp_toolset
from authority_reference.deployment_config import load_presenter, load_transport_token

authority = load_presenter(os.environ["RATIFY_PRESENTER_CONFIG"])
transport_token = load_transport_token(os.environ["RATIFY_PRESENTER_CONFIG"])
root_agent = LlmAgent(
    name="ratify_mcp_infrastructure_specialist",
    description="Provisions cloud nodes through an authority-gated MCP receiver.",
    model="gemini-3.6-flash",
    instruction=(
        "Use provision_cloud_node for infrastructure changes. Report receiver "
        "denials exactly; never claim an action succeeded when decision is deny."
    ),
    tools=[build_mcp_toolset(
        authority,
        receiver_url=os.environ["RATIFY_MCP_RECEIVER_URL"],
        transport_token=transport_token,
    )],
)
