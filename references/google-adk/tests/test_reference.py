from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

import httpx
import pytest
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from ratify_protocol import (
    base64_standard_decode,
    base64_standard_encode,
    encode_proof_bundle,
    generate_agent,
    sign_challenge,
)

from authority_reference import (
    InfrastructureReceiver,
    OperationRequest,
    build_adk_agent,
    build_mcp_toolset,
    build_provision_tool,
    issue_authority,
)
from authority_reference.adk_mcp import _result_object


def setup_reference(**authority_options):
    now = int(time.time())
    authority = issue_authority(now=now - 1, **authority_options)
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
    )
    return now, authority, receiver


@contextmanager
def running_http_receiver(authority):
    """Receiver operator starts the service; the ADK client receives only its URL."""
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "receiver-trust.json"
        transport_token = "test-transport-token-with-sufficient-entropy"
        config.write_text(json.dumps({
            "trusted_root_id": authority.root_id,
            "trusted_agent_id": authority.specialist_id,
            "root_ed25519": base64_standard_encode(authority.root_public_key.ed25519),
            "root_ml_dsa_65": base64_standard_encode(authority.root_public_key.ml_dsa_65),
            "transport_token": transport_token,
        }), encoding="utf-8")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(
            [
                sys.executable, "-m", "authority_reference.mcp_server",
                "--trust-config", str(config), "--port", str(port),
            ],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read())
                with socket.socket() as probe:
                    probe.settimeout(0.1)
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(0.05)
            else:
                raise RuntimeError("MCP receiver did not become ready")
            yield f"http://127.0.0.1:{port}/mcp", transport_token
        finally:
            process.terminate()
            process.wait(timeout=5)


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


def test_native_adk_mcp_tool_hides_proof_and_enforces_in_receiver_process():
    async def exercise():
        _, authority, _ = setup_reference()
        receiver_context = running_http_receiver(authority)
        receiver_url, token = receiver_context.__enter__()
        toolset = build_mcp_toolset(
            authority, receiver_url=receiver_url, transport_token=token
        )
        try:
            tools = await toolset.get_tools()
            declaration = tools[0]._get_declaration()
            properties = declaration.parameters_json_schema["properties"]
            assert set(properties) == {
                "request_id", "region", "instance_type", "count"
            }

            allowed = await tools[0].run_async(
                args={
                    "request_id": "mcp-allow",
                    "region": "us-central1",
                    "instance_type": "n2-standard-4",
                    "count": 1,
                },
                tool_context=None,
            )
            denied = await tools[0].run_async(
                args={
                    "request_id": "mcp-deny",
                    "region": "us-central1",
                    "instance_type": "n2-standard-4",
                    "count": 3,
                },
                tool_context=None,
            )
            assert allowed["decision"] == "allow"
            assert allowed["tool_invocations"] == 1
            assert denied["decision"] == "deny"
            assert denied["tool_invocations"] == 1
        finally:
            await toolset.close()
            receiver_context.__exit__(None, None, None)

    asyncio.run(exercise())


def test_real_adk_runner_executes_native_mcp_toolset():
    async def exercise():
        _, authority, _ = setup_reference()
        receiver_context = running_http_receiver(authority)
        receiver_url, token = receiver_context.__enter__()
        toolset = build_mcp_toolset(
            authority, receiver_url=receiver_url, transport_token=token
        )
        agent = LlmAgent(
            name="ratify_mcp_specialist",
            model=_ScriptedToolCallingModel(model="scripted-mcp-model"),
            instruction="Provision only through the receiver-gated MCP tool.",
            tools=[toolset],
        )
        runner = InMemoryRunner(agent=agent, app_name="ratify_adk_mcp")
        try:
            session = await runner.session_service.create_session(
                app_name="ratify_adk_mcp", user_id="reference-user"
            )
            events = [
                event
                async for event in runner.run_async(
                    user_id="reference-user",
                    session_id=session.id,
                    new_message=types.Content(
                        role="user", parts=[types.Part(text="Provision one node.")]
                    ),
                )
            ]
            assert any(
                part.function_response
                and part.function_response.response["decision"] == "allow"
                for event in events
                for part in (event.content.parts if event.content else [])
            )
        finally:
            await runner.close()
            receiver_context.__exit__(None, None, None)

    asyncio.run(exercise())


def test_mcp_receiver_rejects_alteration_and_replay_across_process_boundary():
    async def exercise():
        _, authority, _ = setup_reference()
        receiver_context = running_http_receiver(authority)
        receiver_url, token = receiver_context.__enter__()
        toolset = build_mcp_toolset(
            authority, receiver_url=receiver_url, transport_token=token
        )
        try:
            tool = (await toolset.get_tools())[0]
            session = await tool._mcp_session_manager.create_session(headers={
                "Authorization": f"Bearer {token}"
            })
            original = {
                "request_id": "mcp-bound",
                "region": "us-central1",
                "instance_type": "n2-standard-4",
                "count": 1,
            }

            async def presentation_for(args):
                result = await session.call_tool(
                    "issue_authority_challenge",
                    arguments=args,
                )
                grant = _result_object(result)
                return encode_proof_bundle(authority.present(
                    challenge=base64_standard_decode(grant["challenge"]),
                    session_context=base64_standard_decode(
                        grant["session_context"]
                    ),
                ))

            altered_proof = await presentation_for(original)
            altered = await session.call_tool(
                "provision_cloud_node",
                arguments={**original, "count": 2, "presentation": altered_proof},
            )
            assert _result_object(altered)["status"] == "operation_binding_failed"

            replay_request = {**original, "request_id": "mcp-replay"}
            replay_proof = await presentation_for(replay_request)
            first = _result_object(await session.call_tool(
                "provision_cloud_node",
                arguments={**replay_request, "presentation": replay_proof},
            ))
            await presentation_for(replay_request)
            replay = _result_object(await session.call_tool(
                "provision_cloud_node",
                arguments={**replay_request, "presentation": replay_proof},
            ))
            assert first["decision"] == "allow"
            assert replay["decision"] == "deny"
            assert replay["tool_invocations"] == 1
        finally:
            await toolset.close()
            receiver_context.__exit__(None, None, None)

    asyncio.run(exercise())


def test_remote_receiver_rejects_presenter_selected_agent():
    async def exercise():
        _, accepted, _ = setup_reference()
        attacker = issue_authority(now=int(time.time()) - 1)
        receiver_context = running_http_receiver(accepted)
        receiver_url, token = receiver_context.__enter__()
        toolset = build_mcp_toolset(
            attacker, receiver_url=receiver_url, transport_token=token
        )
        try:
            tool = (await toolset.get_tools())[0]
            result = await tool.run_async(
                args={
                    "request_id": "attacker-root",
                    "region": "us-central1",
                    "instance_type": "n2-standard-4",
                    "count": 1,
                },
                tool_context=None,
            )
            assert result["decision"] == "deny"
            assert result["status"] == "agent_binding_failed"
            assert result["tool_invocations"] == 0
        finally:
            await toolset.close()
            receiver_context.__exit__(None, None, None)

    asyncio.run(exercise())


def test_remote_receiver_rejects_spoofed_agent_under_hostile_root():
    async def exercise():
        _, accepted, _ = setup_reference()
        attacker = issue_authority(now=int(time.time()) - 1)
        context = running_http_receiver(accepted)
        url, token = context.__enter__()
        toolset = build_mcp_toolset(
            attacker, receiver_url=url, transport_token=token
        )
        try:
            tool = (await toolset.get_tools())[0]
            session = await tool._mcp_session_manager.create_session(headers={
                "Authorization": f"Bearer {token}"
            })
            request = {
                "request_id": "hostile-root", "region": "us-central1",
                "instance_type": "n2-standard-4", "count": 1,
            }
            grant = _result_object(await session.call_tool(
                "issue_authority_challenge", arguments=request
            ))
            bundle = attacker.present(
                challenge=base64_standard_decode(grant["challenge"]),
                session_context=base64_standard_decode(grant["session_context"]),
            )
            bundle.agent_id = accepted.specialist_id
            result = _result_object(await session.call_tool(
                "provision_cloud_node",
                arguments={**request, "presentation": encode_proof_bundle(bundle)},
            ))
            assert result["status"] == "untrusted_root"
            assert result["tool_invocations"] == 0
        finally:
            await toolset.close()
            context.__exit__(None, None, None)
    asyncio.run(exercise())


def test_adk_confirmation_gate_is_preserved_before_mcp_execution():
    async def exercise():
        _, authority, _ = setup_reference()
        context = running_http_receiver(authority)
        url, token = context.__enter__()
        toolset = build_mcp_toolset(
            authority, receiver_url=url, transport_token=token,
            require_confirmation=True,
        )
        requested = []
        tool_context = SimpleNamespace(
            tool_confirmation=None,
            request_confirmation=lambda **kwargs: requested.append(kwargs),
        )
        try:
            tool = (await toolset.get_tools())[0]
            result = await tool.run_async(args={
                "request_id": "needs-confirmation", "region": "us-central1",
                "instance_type": "n2-standard-4", "count": 1,
            }, tool_context=tool_context)
            assert "requires confirmation" in result["error"]
            assert requested
        finally:
            await toolset.close()
            context.__exit__(None, None, None)
    asyncio.run(exercise())


def test_prefix_and_malformed_model_output_remain_structured():
    async def exercise():
        _, authority, _ = setup_reference()
        context = running_http_receiver(authority)
        url, token = context.__enter__()
        toolset = build_mcp_toolset(
            authority, receiver_url=url, transport_token=token,
            tool_name_prefix="infra",
        )
        try:
            tool = (await toolset.get_tools_with_prefix())[0]
            assert tool.name.startswith("infra")
            allowed = await tool.run_async(args={
                "request_id": "prefixed", "region": "us-central1",
                "instance_type": "n2-standard-4", "count": 1,
            }, tool_context=None)
            malformed = await tool.run_async(args={
                "request_id": "malformed", "region": "US-CENTRAL1",
                "instance_type": "n2_standard_4", "count": 1,
            }, tool_context=None)
            assert allowed["decision"] == "allow"
            assert malformed["decision"] == "deny"
            assert malformed["status"] in {"challenge_rejected", "mcp_error"}
        finally:
            await toolset.close()
            context.__exit__(None, None, None)
    asyncio.run(exercise())


def test_unauthenticated_transport_cannot_reach_challenge_tool():
    _, authority, _ = setup_reference()
    with running_http_receiver(authority) as (url, _):
        response = httpx.post(url, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "issue_authority_challenge", "arguments": {}},
        })
        assert response.status_code == 401


def test_junk_presentation_does_not_cancel_honest_pending_operation():
    now, authority, receiver = setup_reference()
    request = OperationRequest("not-cancelled", "us-central1", "n2-standard-4", 1)
    _, bundle = present(authority, receiver, request, now=now)
    junk = receiver.execute(request, "not-a-bundle", now=now)
    honest = receiver.execute(request, bundle, now=now)
    assert junk["status"] == "invalid_presentation"
    assert honest["decision"] == "allow"


def test_pending_capacity_fails_structurally_and_is_bounded():
    _, authority, receiver = setup_reference()
    for index in range(128):
        receiver.issue_challenge(
            OperationRequest(f"capacity-{index}", "us-central1", "n2-standard-4", 1),
            expected_agent_id=authority.specialist_id,
        )
    with pytest.raises(ValueError, match="receiver_pending_capacity"):
        receiver.issue_challenge(
            OperationRequest("capacity-overflow", "us-central1", "n2-standard-4", 1),
            expected_agent_id=authority.specialist_id,
        )
    assert len(receiver._pending) == 128
