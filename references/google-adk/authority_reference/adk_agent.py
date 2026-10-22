"""Google ADK presentation layer.

The proof is injected by application code. The model sees the ordinary tool
schema and result, never private keys or proof-bundle bytes.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.tools import FunctionTool

from .authority import AuthorityFixture
from .receiver import DualChallengeGrant, DualPresentation, InfrastructureReceiver, OperationRequest


def build_provision_tool(
    receiver: InfrastructureReceiver,
    authority: AuthorityFixture,
) -> FunctionTool:
    def provision_cloud_node(
        request_id: str,
        region: str,
        instance_type: str,
        count: int,
    ) -> dict:
        """Provision cloud nodes under receiver-verified delegated authority."""
        request = OperationRequest(request_id, region, instance_type, count)
        grant = receiver.issue_challenge(
            request, agent_public_key=authority.specialist_public_key
        )
        if isinstance(grant, DualChallengeGrant):
            presentation = DualPresentation(
                authority.present(grant.authority),
                authority.present_admission(grant.admission),
            )
        else:
            presentation = authority.present(grant)
        return receiver.execute(request, presentation)

    return FunctionTool(provision_cloud_node)


def build_adk_agent(
    receiver: InfrastructureReceiver,
    authority: AuthorityFixture,
    *,
    model: str | BaseLlm = "gemini-3.6-flash",
) -> LlmAgent:
    """Construct the real ADK agent; running the model is optional."""
    return LlmAgent(
        name="ratify_infrastructure_specialist",
        description="Provisions cloud nodes under bounded delegated authority.",
        model=model,
        instruction=(
            "Use provision_cloud_node for infrastructure changes. Report receiver "
            "denials exactly; never claim an action succeeded when decision is deny."
        ),
        tools=[build_provision_tool(receiver, authority)],
    )
