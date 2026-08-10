from __future__ import annotations

import time

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from ratify_protocol import encode_proof_bundle, generate_agent, sign_challenge

from authority_reference import (
    InfrastructureReceiver,
    OperationRequest,
    build_adk_agent,
    build_provision_tool,
    issue_authority,
)


def setup_reference(**authority_options):
    now = int(time.time())
    authority = issue_authority(now=now - 1, **authority_options)
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
    )
    return now, authority, receiver


def present(authority, receiver, request, *, now):
    grant = receiver.issue_challenge(
        request, expected_agent_id=authority.specialist_id
    )
    bundle = authority.present(
        challenge=grant.challenge,
        session_context=grant.session_context,
        now=now,
    )
    return grant, bundle


def test_valid_authority_invokes_tool_once():
    now, authority, receiver = setup_reference()
    request = OperationRequest("valid", "us-central1", "n2-standard-4", 1)
    _, bundle = present(authority, receiver, request, now=now)

    result = receiver.execute(request, encode_proof_bundle(bundle), now=now)

    assert result["decision"] == "allow"
    assert result["tool_invocations"] == 1


@pytest.mark.parametrize(
    ("operation", "expected_status"),
    [
        (OperationRequest("count", "us-central1", "n2-standard-4", 3), "constraint_denied"),
        (OperationRequest("region", "us-east1", "n2-standard-4", 1), "constraint_denied"),
    ],
)
def test_signed_bounds_deny_before_tool(operation, expected_status):
    now, authority, receiver = setup_reference()
    _, bundle = present(authority, receiver, operation, now=now)

    result = receiver.execute(operation, bundle, now=now)

    assert result["decision"] == "deny"
    assert result["status"] == expected_status
    assert result["tool_invocations"] == 0


def test_expired_authority_denies_before_tool():
    now = int(time.time())
    authority = issue_authority(now=now - 3600, expires_at=now - 1)
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
    )
    request = OperationRequest("expired", "us-central1", "n2-standard-4", 1)
    _, bundle = present(authority, receiver, request, now=now)

    result = receiver.execute(request, bundle, now=now)

    assert result["status"] == "expired"
    assert result["tool_invocations"] == 0


def test_revoked_authority_denies_before_tool():
    now, authority, receiver = setup_reference()
    receiver.revocation.revoke(authority.delegations[0].cert_id)
    request = OperationRequest("revoked", "us-central1", "n2-standard-4", 1)
    _, bundle = present(authority, receiver, request, now=now)

    result = receiver.execute(request, bundle, now=now)

    assert result["status"] == "revoked"
    assert result["tool_invocations"] == 0


def test_replay_does_not_invoke_tool_again():
    now, authority, receiver = setup_reference()
    request = OperationRequest("replay", "us-central1", "n2-standard-4", 1)
    _, bundle = present(authority, receiver, request, now=now)
    first = receiver.execute(request, bundle, now=now)
    assert first["decision"] == "allow"

    # Recreate only the application envelope. The original challenge remains
    # consumed, so the old cryptographic presentation cannot authorize again.
    receiver.issue_challenge(request, expected_agent_id=authority.specialist_id)
    replay = receiver.execute(request, bundle, now=now)

    assert replay["decision"] == "deny"
    assert replay["status"] == "invalid"
    assert replay["tool_invocations"] == 1


def test_altered_operation_is_rejected_before_verification():
    now, authority, receiver = setup_reference()
    original = OperationRequest("altered", "us-central1", "n2-standard-4", 1)
    _, bundle = present(authority, receiver, original, now=now)
    altered = OperationRequest("altered", "us-central1", "n2-standard-4", 2)

    result = receiver.execute(altered, bundle, now=now)

    assert result["status"] == "operation_binding_failed"
    assert result["tool_invocations"] == 0


def test_wrong_agent_key_is_rejected_before_tool():
    now, authority, receiver = setup_reference()
    request = OperationRequest("wrong-key", "us-central1", "n2-standard-4", 1)
    grant = receiver.issue_challenge(
        request, expected_agent_id=authority.specialist_id
    )
    intruder, intruder_private = generate_agent("Intruder", "custom")
    legitimate = authority.present(
        challenge=grant.challenge,
        session_context=grant.session_context,
        now=now,
    )
    legitimate.agent_id = intruder.id
    legitimate.agent_pub_key = intruder.public_key
    legitimate.challenge_sig = sign_challenge(
        grant.challenge, now, intruder_private, grant.session_context
    )

    result = receiver.execute(request, legitimate, now=now)

    assert result["decision"] == "deny"
    assert result["status"] == "agent_binding_failed"
    assert result["tool_invocations"] == 0


def test_self_issued_valid_chain_is_not_a_trusted_root():
    now, accepted, receiver = setup_reference()
    attacker = issue_authority(now=now - 1)
    request = OperationRequest("root", "us-central1", "n2-standard-4", 1)
    _, bundle = present(attacker, receiver, request, now=now)

    result = receiver.execute(request, bundle, now=now)

    assert accepted.root_id != attacker.root_id
    assert result["status"] == "untrusted_root"
    assert result["tool_invocations"] == 0


@pytest.mark.parametrize("count", [True, 0, -1, 1001, 1.5])
def test_invalid_counts_never_reach_the_tool(count):
    now, authority, receiver = setup_reference()
    request = OperationRequest("invalid", "us-central1", "n2-standard-4", count)

    with pytest.raises(ValueError):
        receiver.issue_challenge(
            request, expected_agent_id=authority.specialist_id
        )
    assert receiver.tool_invocations == 0


def test_real_adk_agent_exposes_only_the_ordinary_tool_schema():
    _, authority, receiver = setup_reference()

    agent = build_adk_agent(receiver, authority)

    assert isinstance(agent, LlmAgent)
    assert agent.name == "ratify_infrastructure_specialist"
    assert len(agent.tools) == 1
    assert agent.tools[0].name == "provision_cloud_node"


def test_real_adk_function_tool_executes_the_receiver_gated_path():
    _, authority, receiver = setup_reference()
    tool = build_provision_tool(receiver, authority)

    allowed = tool.func("adk-allow", "us-central1", "n2-standard-4", 1)
    denied = tool.func("adk-deny", "us-central1", "n2-standard-4", 3)

    assert allowed["decision"] == "allow"
    assert denied["decision"] == "deny"
    assert receiver.tool_invocations == 1


class _ScriptedToolCallingModel(BaseLlm):
    """Deterministic model double; ADK still owns the agent/tool event loop."""

    turn: int = 0

    async def generate_content_async(self, llm_request, stream=False):
        self.turn += 1
        if self.turn == 1:
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part(function_call=types.FunctionCall(
                        id="call-1",
                        name="provision_cloud_node",
                        args={
                            "request_id": "runner-allow",
                            "region": "us-central1",
                            "instance_type": "n2-standard-4",
                            "count": 1,
                        },
                    ))],
                )
            )
        else:
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text="Receiver allowed one node.")],
                )
            )


def test_real_adk_runner_selects_and_executes_receiver_gated_tool():
    _, authority, receiver = setup_reference()
    agent = build_adk_agent(
        receiver,
        authority,
        model=_ScriptedToolCallingModel(model="scripted-reference-model"),
    )
    runner = InMemoryRunner(agent=agent, app_name="ratify_adk_reference")
    session = runner.session_service.create_session_sync(
        app_name="ratify_adk_reference", user_id="reference-user"
    )

    events = list(runner.run(
        user_id="reference-user",
        session_id=session.id,
        new_message=types.Content(
            role="user", parts=[types.Part(text="Provision one node.")]
        ),
    ))

    assert receiver.tool_invocations == 1
    assert any(
        part.function_response
        and part.function_response.response["decision"] == "allow"
        for event in events
        for part in (event.content.parts if event.content else [])
    )
