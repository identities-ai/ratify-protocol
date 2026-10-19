"""Experimental A2A carrier for the existing ADK receiver scenario."""

from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import hashlib
import re
import secrets
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
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentSkill,
    HTTPAuthSecurityScheme, SecurityRequirement, SecurityScheme, StringList,
    SendMessageRequest, Task, TaskState, TaskStatus,
)
from a2a.utils.errors import ExtensionSupportRequiredError, UnsupportedOperationError
from ratify_protocol import (
    OperationContext, SessionContextInputs, build_session_context,
    encode_proof_bundle, operation_context_hash,
)
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Reuse the published reference's authority fixture and receiver. The A2A
# carrier is experimental; no ADK runtime participates in this flow.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "google-adk"))
from authority_reference.authority import INFRA_SCOPE, WORKSPACE_ID, issue_authority, region_resource  # noqa: E402
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
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        request = None
        try:
            message = context.message
            if message is None or len(message.parts) != 1 or not message.parts[0].HasField("data"):
                raise ValueError("one structured A2A data part is required")
            data = MessageToDict(message.parts[0].data)
            request = _operation(data)
            request = replace(request, task_id=context.task_id, context_id=context.context_id)
            if data["step"] == "challenge":
                if context.current_task is not None:
                    raise ValueError("challenge must start a new A2A task")
                grant = self.receiver.issue_challenge(request, expected_agent_id=self.agent_id)
                response = {
                    "decision": "challenge",
                    "challenge": grant.challenge.hex(),
                    "session_context": grant.session_context.hex(),
                    "expires_at": grant.expires_at,
                    "session_inputs": {
                        "verifier_id": grant.session_inputs.verifier_id,
                        "workspace_id": grant.session_inputs.workspace_id,
                        "agent_id": grant.session_inputs.agent_id,
                        "session_id": grant.session_inputs.session_id,
                        "invocation_id": grant.session_inputs.invocation_id,
                        "request_hash": grant.session_inputs.request_hash.hex(),
                    },
                }
            else:
                if context.current_task is None:
                    raise ValueError("execute requires the challenged A2A task")
                metadata = MessageToDict(message.metadata)
                proof = metadata.get(EXTENSION_URI)
                if not isinstance(proof, str):
                    raise ValueError("authority proof is required in message metadata")
                response = self.receiver.execute(request, proof)
        except (TypeError, ValueError) as exc:
            response = {"decision": "deny", "status": "invalid_a2a_message", "reason": str(exc),
                        "tool_invocations": self.receiver.tool_invocations,
                        "protected_action_invoked": False}
        result_message = new_data_message(
            response, media_type="application/json",
            task_id=context.task_id, context_id=context.context_id,
        )
        if context.current_task is None:
            state = (TaskState.TASK_STATE_AUTH_REQUIRED
                     if response["decision"] == "challenge" else TaskState.TASK_STATE_REJECTED)
            await event_queue.enqueue_event(Task(
                id=context.task_id, context_id=context.context_id,
                status=TaskStatus(state=state, message=result_message),
            ))
        elif response["decision"] == "allow":
            await updater.complete(result_message)
        elif response.get("status") == "protected_action_failed":
            await updater.failed(result_message)
        elif self.receiver.has_pending_task(context.task_id):
            await updater.requires_auth(result_message)
        else:
            await updater.reject(result_message)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise UnsupportedOperationError("cancellation is not supported by this reference")


class AuthorityRequestHandler(DefaultRequestHandler):
    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):
        if EXTENSION_URI not in context.requested_extensions:
            raise ExtensionSupportRequiredError()
        return await super().on_message_send(params, context)


def build_app(
    receiver: InfrastructureReceiver, agent_id: str, *,
    base_url: str = "http://127.0.0.1:8766/", bearer_token: str | None = None,
) -> Starlette:
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
            protocol_binding="JSONRPC", protocol_version="1.0", url=base_url
        )],
        skills=[AgentSkill(
            id="infra_provision", name="Provision a node", description="Provision bounded infrastructure",
            input_modes=["application/json"], output_modes=["application/json"], tags=["infrastructure"],
        )],
    )
    if bearer_token is not None:
        if not base_url.startswith("https://"):
            raise ValueError("bearer authentication requires HTTPS")
        card.security_schemes["callerBearer"].CopyFrom(SecurityScheme(
            http_auth_security_scheme=HTTPAuthSecurityScheme(scheme="Bearer")
        ))
        card.security_requirements.append(SecurityRequirement(
            schemes={"callerBearer": StringList(list=[])}
        ))
    handler = AuthorityRequestHandler(
        agent_executor=AuthorityExecutor(receiver, agent_id),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    app = Starlette(routes=[*create_agent_card_routes(card), *create_jsonrpc_routes(handler, "/")])
    if bearer_token is not None:
        async def require_caller(request, call_next):
            if request.method == "GET" and request.url.path == "/.well-known/agent-card.json":
                return await call_next(request)
            supplied = request.headers.get("authorization", "")
            expected = f"Bearer {bearer_token}"
            if not supplied.isascii() or not secrets.compare_digest(supplied, expected):
                return JSONResponse({"error": "caller authentication required"}, status_code=401)
            return await call_next(request)
        app.add_middleware(BaseHTTPMiddleware, dispatch=require_caller)
    return app


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


def presentation_metadata(authority: Any, grant: dict[str, Any], request: OperationRequest) -> dict[str, str]:
    """Sign only a challenge bound to the caller's intended operation."""
    request.validate()
    if not request.task_id or not request.context_id:
        raise ValueError("A2A task and context IDs are required before signing")
    operation = OperationContext(
        required_scope=INFRA_SCOPE,
        operation="infra.provision",
        resource_id=region_resource(request.region, WORKSPACE_ID),
        payload_digest=hashlib.sha256(request.canonical_payload()).digest(),
    )
    inputs = grant["session_inputs"]
    if inputs["workspace_id"] != WORKSPACE_ID or inputs["agent_id"] != authority.specialist_id:
        raise ValueError("challenge targets a different workspace or agent")
    if bytes.fromhex(inputs["request_hash"]) != operation_context_hash(operation):
        raise ValueError("challenge does not match the intended operation")
    rebuilt = build_session_context(SessionContextInputs(
        verifier_id=inputs["verifier_id"], workspace_id=inputs["workspace_id"],
        agent_id=inputs["agent_id"], session_id=inputs["session_id"],
        invocation_id=inputs["invocation_id"], request_hash=bytes.fromhex(inputs["request_hash"]),
    ))
    if bytes.fromhex(grant["session_context"]) != rebuilt:
        raise ValueError("challenge session context does not match its inputs")
    proof = authority.present(
        challenge=bytes.fromhex(grant["challenge"]),
        session_context=bytes.fromhex(grant["session_context"]),
    )
    return {EXTENSION_URI: encode_proof_bundle(proof)}
