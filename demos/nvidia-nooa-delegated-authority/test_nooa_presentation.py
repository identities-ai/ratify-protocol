# SPDX-License-Identifier: Apache-2.0
"""Real NOOA integration test for the presentation adapter.

Hermetic: no API key, no network beyond loopback, and no LLM round-trip. The
agent capability is an ordinary async method, not a generation method, so
NOOA dispatches it directly. ``FakeLLMClient`` (a public NOOA export for
"hermetic testing without network calls") satisfies the constructor's LLM
requirement and is never invoked.

Verified against released ``nooa==0.0.8``. The middleware API used here
(``EventManager.intercept("agent_call", ...)`` and ``AgentCallContext``) is
byte-identical between that release and the repository's ``main`` branch.

What this proves, and nothing more:
  * the adapter installs through NOOA's supported middleware API
  * an agent capability invocation reaches the adapter
  * the adapter presents a proof, it does not decide
  * the receiving service performs the verification
  * the decision and receipt identifier propagate back to the caller
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from ratify_protocol import Constraint, SCOPE_PAYMENTS_SEND

from agent_client import RefundClient
from principal import new_agent, new_principal, sign_cert
from refund_service import RefundService, serve

# Skipping is right for the general suite, NOOA needs Python 3.12/3.13, but a
# contribution whose headline claim is "this integrates with NOOA" must not be
# able to go green everywhere by never running. RATIFY_REQUIRE_NOOA=1 turns the
# skip into a hard failure; scripts/nooa-integration-check.sh sets it.
if os.environ.get("RATIFY_REQUIRE_NOOA") == "1":
    import nooa  # noqa: F401, must import, or this check has failed
else:
    nooa = pytest.importorskip(
        "nooa",
        reason="NOOA integration test requires `pip install nooa==0.0.8` (Python 3.12/3.13); "
        "set RATIFY_REQUIRE_NOOA=1 to make this a failure instead",
    )

from nooa.unifiedllm import FakeLLMClient  # noqa: E402

from nooa_adapter import RefundAgent, install_presentation_adapter  # noqa: E402


class _NoLLMAllowed(FakeLLMClient):
    """Turns "no LLM round-trip" from a claim into a tested property."""

    async def acall(self, *args, **kwargs):
        raise AssertionError("the reference must not make an LLM call")


LIMIT = 100.0
UNDER = 75.0
OVER = 150.0


@pytest.fixture
def wired():
    """A NOOA agent whose refund capability is backed by a real receiver."""
    principal, principal_priv = new_principal()
    agent_id, agent_priv = new_agent("nooa-refund-agent")

    now = int(time.time())
    cert = sign_cert(
        issuer_id=principal.id,
        issuer_pub=principal.public_key,
        issuer_priv=principal_priv,
        subject_id=agent_id.id,
        subject_pub=agent_id.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        issued_at=now - 60,
        expires_at=now + 24 * 3600,
    )

    service = RefundService(trust_root=principal.public_key)
    server, base_url = serve(service)
    client = RefundClient(base_url, agent_id.id, agent_id.public_key, agent_priv, [cert])

    agent = RefundAgent(llm=_NoLLMAllowed())
    unsubscribe = install_presentation_adapter(agent, client)
    try:
        yield agent, service, unsubscribe
    finally:
        unsubscribe()
        server.shutdown()


def test_capability_invocation_is_authorized_by_the_receiver(wired):
    """WHY: end-to-end proof that the seam works on a released NOOA, the
    capability call reaches the adapter, the adapter presents, and the
    *service* is what verified. The receipt count is the evidence that
    verification happened at the receiver rather than in the agent process."""
    agent, service, _ = wired

    outcome = asyncio.run(agent.issue_refund("ord-nooa-1", UNDER))

    assert outcome["decision"] == "authorized"
    assert outcome["status"] == "authorized_agent"
    assert outcome["receipt_id"]

    # The receiver verified and recorded it; the agent process did not.
    assert len(service.receipts) == 1
    assert service.receipts[0].decision == "authorized_agent"
    assert outcome["receipt_id"] == service.receipt_ids[0]
    assert service.refunded_total == UNDER


def test_adapter_reports_a_denial_rather_than_producing_one(wired):
    """WHY: this is the distinction the whole contribution rests on. An
    over-limit call must come back denied *because the receiver denied it*,
    the adapter returns the receiver's verdict verbatim, and a denial is a
    normal return value rather than a local refusal. If the adapter were
    deciding, there would be no receipt for the denial at the service."""
    agent, service, _ = wired

    outcome = asyncio.run(agent.issue_refund("ord-nooa-2", OVER))

    assert outcome["decision"] == "denied"
    assert outcome["status"] == "constraint_denied"

    # The denial was reached and recorded at the receiver.
    assert len(service.receipts) == 1
    assert service.receipts[0].decision == "constraint_denied"
    assert outcome["receipt_id"] == service.receipt_ids[0]
    assert service.refunded_total == 0.0


def test_capability_is_inert_without_the_presentation_adapter(wired):
    """WHY: the agent's own code contains no authorization logic and no
    transport. Removing the adapter does not turn the capability into an
    unchecked one, it makes it unusable, because there is nothing left to
    present a proof. The agent cannot exercise authority it cannot prove."""
    agent, service, unsubscribe = wired
    unsubscribe()

    with pytest.raises(RuntimeError, match="no presentation adapter"):
        asyncio.run(agent.issue_refund("ord-nooa-3", UNDER))

    assert service.receipts == []
    assert service.refunded_total == 0.0


def test_adapter_sees_the_capability_call_through_nooas_public_api(wired):
    """WHY: pins the integration seam. If a future NOOA release stops routing
    ordinary async agent methods through agent_call middleware, this fails
    loudly instead of the adapter silently never running, which would leave
    the capability inert rather than unprotected, but should still be caught."""
    agent, _, _ = wired

    asyncio.run(agent.issue_refund("ord-nooa-4", UNDER))

    assert agent.presented == [("issue_refund", "ord-nooa-4", UNDER)]
