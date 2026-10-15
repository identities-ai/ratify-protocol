"""Experimental A2A carrier for the existing ADK receiver scenario."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Any

from google.protobuf.json_format import MessageToDict

from a2a.helpers.proto_helpers import new_data_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentSkill, SendMessageRequest
from a2a.utils.errors import ExtensionSupportRequiredError
from ratify_protocol import encode_proof_bundle
from starlette.applications import Starlette

# Reuse the published reference's authority fixture and receiver. The A2A
# carrier is experimental; no ADK runtime participates in this flow.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "google-adk"))
from authority_reference.authority import issue_authority  # noqa: E402
from authority_reference.receiver import InfrastructureReceiver, OperationRequest  # noqa: E402


EXTENSION_URI = "https://ratifyprotocol.com/extensions/a2a-authority/poc-v0"


def _operation(data: Any) -> OperationRequest:
    if not isinstance(data, dict) or set(data) != {
        "request_id", "region", "instance_type", "count", "step"
    }:
        raise ValueError("expected exactly step, request_id, region, instance_type, count")
    if data["step"] not in ("challenge", "execute"):
        raise ValueError("unknown step")
    if not isinstance(data["request_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", data["request_id"]):
        raise ValueError("request_id must be a safe 1..128 character token")
    count = data["count"]
    if not isinstance(count, str) or not re.fullmatch(r"[1-9][0-9]*", count):
        raise ValueError("count must be a canonical positive decimal string")
    request = OperationRequest(
        request_id=data["request_id"],
        region=data["region"],
        instance_type=data["instance_type"],
        count=int(count),
    )
    request.validate()
    return request


class AuthorityExecutor(AgentExecutor):
    def __init__(self, receiver: InfrastructureReceiver, agent_id: str):
        self.receiver = receiver
        self.agent_id = agent_id

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        try:
            message = context.message
            if message is None or len(message.parts) != 1 or not message.parts[0].HasField("data"):
                raise ValueError("one structured A2A data part is required")
            data = MessageToDict(message.parts[0].data)
            request = _operation(data)
            if data["step"] == "challenge":
                grant = self.receiver.issue_challenge(request, expected_agent_id=self.agent_id)
                response = {
                    "decision": "challenge",
                    "challenge": grant.challenge.hex(),
                    "session_context": grant.session_context.hex(),
                    "expires_at": grant.expires_at,
                }
            else:
                metadata = MessageToDict(message.metadata)
                proof = metadata.get(EXTENSION_URI)
                if not isinstance(proof, str):
                    raise ValueError("authority proof is required in message metadata")
                response = self.receiver.execute(request, proof)
        except (TypeError, ValueError) as exc:
            response = {"decision": "deny", "status": "invalid_a2a_message", "reason": str(exc),
                        "tool_invocations": self.receiver.tool_invocations,
                        "protected_action_invoked": False}
        await event_queue.enqueue_event(new_data_message(response, media_type="application/json"))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise ValueError("this immediate-response example has no cancellable tasks")


class AuthorityRequestHandler(DefaultRequestHandler):
    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):
        if EXTENSION_URI not in context.requested_extensions:
            raise ExtensionSupportRequiredError()
        return await super().on_message_send(params, context)


def build_app(receiver: InfrastructureReceiver, agent_id: str) -> Starlette:
    card = AgentCard(
        name="Ratify A2A authority proof of concept",
        description="Receiver-verified, bounded provisioning",
        version="0.0.1",
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        capabilities=AgentCapabilities(extensions=[AgentExtension(
            uri=EXTENSION_URI,
            description="Experimental receiver-side exact-operation authority proof",
            required=True,
        )]),
        supported_interfaces=[AgentInterface(
            protocol_binding="JSONRPC", protocol_version="1.0", url="http://127.0.0.1:8766/"
        )],
        skills=[AgentSkill(
            id="infra_provision", name="Provision a node", description="Provision bounded infrastructure",
            input_modes=["application/json"], output_modes=["application/json"], tags=["infrastructure"],
        )],
    )
    handler = AuthorityRequestHandler(
        agent_executor=AuthorityExecutor(receiver, agent_id),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    return Starlette(routes=[*create_agent_card_routes(card), *create_jsonrpc_routes(handler, "/")])


def demo_fixture() -> tuple[Starlette, Any, InfrastructureReceiver]:
    authority = issue_authority()
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
    )
    return build_app(receiver, authority.specialist_id), authority, receiver


def operation_data(request: OperationRequest, step: str) -> dict[str, Any]:
    return {"step": step, "request_id": request.request_id, "region": request.region,
            "instance_type": request.instance_type, "count": str(request.count)}


def presentation_metadata(authority: Any, grant: dict[str, Any]) -> dict[str, str]:
    proof = authority.present(
        challenge=bytes.fromhex(grant["challenge"]),
        session_context=bytes.fromhex(grant["session_context"]),
    )
    return {EXTENSION_URI: encode_proof_bundle(proof)}
