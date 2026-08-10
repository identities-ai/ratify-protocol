"""Optional live Gemini entry point for ``adk run adk_app``."""

from authority_reference import InfrastructureReceiver, build_adk_agent, issue_authority


authority = issue_authority()
receiver = InfrastructureReceiver(
    trusted_root_id=authority.root_id,
    trusted_root_public_key=authority.root_public_key,
)
root_agent = build_adk_agent(receiver, authority)
