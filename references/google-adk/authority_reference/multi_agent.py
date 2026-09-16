"""Public Google ADK multi-agent topology for the federation reference."""

from __future__ import annotations

from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.tools.base_tool import BaseTool


def build_federated_adk_system(
    *,
    worker_tool: BaseTool,
    before_tool_callback=None,
    coordinator_model: str | BaseLlm,
    broker_model: str | BaseLlm,
    worker_model: str | BaseLlm,
) -> LlmAgent:
    """Build coordinator to broker to worker routing with receiver enforcement.

    The ADK agents model the cross-domain routing path. The Ratify delegation
    chain remains the authorization path and is independently checked by the
    receiver; ADK hierarchy alone grants no authority.
    """
    worker = LlmAgent(
        name="domain_b_worker",
        description="Executes one bounded infrastructure operation in domain B.",
        mode="single_turn",
        model=worker_model,
        instruction=(
            "Call provision_cloud_node with the requested business arguments. "
            "Report the receiver decision exactly."
        ),
        tools=[worker_tool],
        before_tool_callback=before_tool_callback,
    )
    broker = LlmAgent(
        name="domain_b_broker",
        description="Routes approved domain B work to its constrained worker.",
        mode="single_turn",
        model=broker_model,
        instruction=(
            "Send infrastructure work to domain_b_worker and return its exact result."
        ),
        sub_agents=[worker],
    )
    return LlmAgent(
        name="domain_a_coordinator",
        description="Coordinates a cross-domain infrastructure request.",
        model=coordinator_model,
        instruction=(
            "Send domain B infrastructure work to domain_b_broker and return its "
            "exact result. ADK routing does not replace receiver authorization."
        ),
        sub_agents=[broker],
    )
