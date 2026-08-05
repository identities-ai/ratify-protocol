# SPDX-License-Identifier: Apache-2.0
"""NOOA presentation adapter.

Named for what it does. The adapter *presents* delegated authority and
*reports* the receiver's verdict. It does not evaluate the delegation, does
not decide, and could not be trusted to, it runs inside the agent's own
process, which is the party being authorized.

Seam: ``EventManager.intercept("agent_call", ...)`` from
``nooa.runtime.middleware``, public API, exported in ``__all__``, present and
byte-identical in released ``nooa==0.0.8``. NVIDIA uses the same three
middleware kinds in ``nooa/nemo_flow_middleware.py`` to route agent calls
through an external security service; this mirrors that shape.

``InstrumentationHooks`` was considered and rejected: its exceptions are
swallowed by design, so it cannot block, and it occupies a single contextvar
slot that ``enable_tracing()` already uses.
"""

from __future__ import annotations

from nooa import Agent
from nooa.runtime.middleware import AgentCallContext, AgentCallNext
from nooa.unifiedllm import FakeLLMClient

CAPABILITY = "issue_refund"


class RefundAgent(Agent):
    """An agent that can ask a payments service to refund an order."""

    def __init__(self, llm=None):
        # This agent never generates, its capability is an ordinary async
        # method, but Agent requires an LLM object. FakeLLMClient is NOOA's
        # public double for hermetic use and is never called here.
        super().__init__(llm=llm if llm is not None else FakeLLMClient())
        self.presented: list[tuple[str, str, float]] = []

    async def issue_refund(self, order_id: str, amount: float) -> dict:
        """Refund an order through the payments service.

        The body is unreachable when a presentation adapter is installed: the
        adapter carries the call to the receiving service, which decides.
        Reaching this line means the agent has no way to prove authority, and
        a capability it cannot prove is one it cannot exercise.
        """
        raise RuntimeError(
            "no presentation adapter installed: issue_refund cannot be "
            "exercised without presenting delegated authority"
        )


def install_presentation_adapter(agent: RefundAgent, client) -> callable:
    """Install the adapter on one agent instance. Returns an unsubscribe."""

    async def present(ctx: AgentCallContext, nxt: AgentCallNext) -> AgentCallContext:
        if ctx.method_name != CAPABILITY:
            return await nxt(ctx)

        order_id, amount = _arguments(ctx)
        agent.presented.append((ctx.method_name, order_id, amount))

        # The receiver verifies, decides, and acts. Whatever it says, allowed
        # or denied, is passed through untouched. A denial is a normal return
        # value, not something this adapter produced.
        ctx.result = client.request_refund(order_id, amount)
        return ctx

    return agent.event_manager.intercept("agent_call", present)


def _arguments(ctx: AgentCallContext) -> tuple[str, float]:
    if ctx.args:
        return str(ctx.args[0]), float(ctx.args[1])
    return str(ctx.kwargs["order_id"]), float(ctx.kwargs["amount"])
