"""Optional live Gemini + native MCP entry point for ``adk run adk_app``."""

from google.adk.agents import LlmAgent

from authority_reference import build_mcp_toolset, issue_authority

authority = issue_authority()
root_agent = LlmAgent(
    name="ratify_mcp_infrastructure_specialist",
    description="Provisions cloud nodes through an authority-gated MCP receiver.",
    model="gemini-3.6-flash",
    instruction=(
        "Use provision_cloud_node for infrastructure changes. Report receiver "
        "denials exactly; never claim an action succeeded when decision is deny."
    ),
    tools=[build_mcp_toolset(authority)],
)
