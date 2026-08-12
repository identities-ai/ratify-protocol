from __future__ import annotations

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolCall
import httpx
import pytest
from ratify_protocol import encode_proof_bundle, generate_agent, sign_challenge

from authority_reference import (
    InfrastructureReceiver, OperationRequest, build_agent, build_mcp_tools,
    issue_authority,
)
from authority_reference.deployment_config import write_configs


class ToolCallingFakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self


def result_object(value):
    if isinstance(value, list):
        return json.loads(next(block["text"] for block in value if block.get("text")))
    return value


def setup_reference(**options):
    now = int(time.time())
    authority = issue_authority(now=now - 1, **options)
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
    )
    return now, authority, receiver


def present(authority, receiver, request, now):
    grant = receiver.issue_challenge(request, expected_agent_id=authority.specialist_id)
    return authority.present(challenge=grant.challenge,
                             session_context=grant.session_context, now=now)


def test_valid_authority_invokes_tool_once():
    now, authority, receiver = setup_reference()
    request = OperationRequest("valid", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request, now), now=now)
    assert result["decision"] == "allow"
    assert result["tool_invocations"] == 1


@pytest.mark.parametrize("operation", [
    OperationRequest("count", "us-central1", "n2-standard-4", 3),
    OperationRequest("region", "us-east1", "n2-standard-4", 1),
])
def test_signed_bounds_deny_before_tool(operation):
    now, authority, receiver = setup_reference()
    result = receiver.execute(
        operation, present(authority, receiver, operation, now), now=now
    )
    assert result["decision"] == "deny"
    assert result["tool_invocations"] == 0


def test_expired_authority_denies_before_tool():
    now = int(time.time())
    authority = issue_authority(now=now - 3600, expires_at=now - 1)
    receiver = InfrastructureReceiver(trusted_root_id=authority.root_id,
                                      trusted_root_public_key=authority.root_public_key)
    request = OperationRequest("expired", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request, now), now=now)
    assert result["status"] == "expired"
    assert result["tool_invocations"] == 0


def test_revoked_authority_denies_before_tool():
    now, authority, receiver = setup_reference()
    receiver.revocation.revoke(authority.delegations[0].cert_id)
    request = OperationRequest("revoked", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request, now), now=now)
    assert result["status"] == "revoked"
    assert result["tool_invocations"] == 0


def test_replay_does_not_invoke_again():
    now, authority, receiver = setup_reference()
    request = OperationRequest("replay", "us-central1", "n2-standard-4", 1)
    bundle = present(authority, receiver, request, now)
    assert receiver.execute(request, bundle, now=now)["decision"] == "allow"
    assert receiver.execute(request, bundle, now=now)["tool_invocations"] == 1


def test_altered_operation_denies_before_tool():
    now, authority, receiver = setup_reference()
    original = OperationRequest("altered", "us-central1", "n2-standard-4", 1)
    bundle = present(authority, receiver, original, now)
    altered = OperationRequest("altered", "us-central1", "n2-standard-4", 2)
    result = receiver.execute(altered, bundle, now=now)
    assert result["status"] == "operation_binding_failed"
    assert result["tool_invocations"] == 0


def test_wrong_agent_denies_before_tool():
    now, authority, receiver = setup_reference()
    request = OperationRequest("agent", "us-central1", "n2-standard-4", 1)
    grant = receiver.issue_challenge(request, expected_agent_id=authority.specialist_id)
    hostile, hostile_private = generate_agent("hostile", "custom")
    bundle = authority.present(challenge=grant.challenge,
                               session_context=grant.session_context, now=now)
    bundle = replace(
        bundle,
        agent_id=hostile.id,
        agent_pub_key=hostile.public_key,
        challenge_sig=sign_challenge(grant.challenge, now, hostile_private,
                                     grant.session_context),
    )
    result = receiver.execute(request, bundle, now=now)
    assert result["status"] == "agent_binding_failed"
    assert result["tool_invocations"] == 0


def test_hostile_root_denies_before_tool():
    now, authority, receiver = setup_reference()
    hostile = issue_authority(now=now - 1)
    request = OperationRequest("root", "us-central1", "n2-standard-4", 1)
    grant = receiver.issue_challenge(request, expected_agent_id=hostile.specialist_id)
    bundle = hostile.present(challenge=grant.challenge,
                             session_context=grant.session_context, now=now)
    result = receiver.execute(request, bundle, now=now)
    assert result["status"] == "untrusted_root"
    assert result["tool_invocations"] == 0


def test_malformed_presentation_does_not_cancel_pending_operation():
    now, authority, receiver = setup_reference()
    request = OperationRequest("malformed", "us-central1", "n2-standard-4", 1)
    bundle = present(authority, receiver, request, now)
    denied = receiver.execute(request, "not-a-proof", now=now)
    allowed = receiver.execute(request, encode_proof_bundle(bundle), now=now)
    assert denied["status"] == "invalid_presentation"
    assert allowed["decision"] == "allow"
    assert allowed["tool_invocations"] == 1


def test_pending_capacity_is_bounded():
    _, authority, receiver = setup_reference()
    for index in range(128):
        receiver.issue_challenge(
            OperationRequest(f"capacity-{index}", "us-central1", "n2-standard-4", 1),
            expected_agent_id=authority.specialist_id,
        )
    with pytest.raises(ValueError, match="receiver_pending_capacity"):
        receiver.issue_challenge(
            OperationRequest("overflow", "us-central1", "n2-standard-4", 1),
            expected_agent_id=authority.specialist_id,
        )
    assert receiver.tool_invocations == 0


def test_concurrent_duplicate_request_creates_one_pending_operation():
    _, authority, receiver = setup_reference()
    request = OperationRequest("duplicate", "us-central1", "n2-standard-4", 1)
    def issue():
        try:
            receiver.issue_challenge(request, expected_agent_id=authority.specialist_id)
            return "issued"
        except ValueError:
            return "denied"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: issue(), range(2)))
    assert sorted(results) == ["denied", "issued"]
    assert receiver.tool_invocations == 0


@pytest.mark.parametrize("count", [True, 0, -1, 1001, 1.5, "1"])
def test_invalid_counts_never_reach_tool(count):
    _, authority, receiver = setup_reference()
    request = OperationRequest("bad-count", "us-central1", "n2-standard-4", count)
    with pytest.raises(ValueError):
        receiver.issue_challenge(request, expected_agent_id=authority.specialist_id)
    assert receiver.tool_invocations == 0


@contextmanager
def running_receiver(authority):
    with tempfile.TemporaryDirectory() as directory:
        receiver_config = Path(directory) / "receiver.json"
        presenter_config = Path(directory) / "presenter.json"
        write_configs(authority, receiver_config, presenter_config)
        token = json.loads(presenter_config.read_text())["transport_token"]
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen([
            sys.executable, "-m", "authority_reference.mcp_server",
            "--trust-config", str(receiver_config), "--port", str(port),
        ], cwd=Path(__file__).resolve().parents[1], stdout=subprocess.DEVNULL,
           stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read())
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(.05)
            else:
                raise RuntimeError("receiver unavailable")
            yield f"http://127.0.0.1:{port}/mcp", token
        finally:
            process.terminate()
            process.wait(timeout=5)


@pytest.mark.asyncio
async def test_real_langchain_agent_uses_hidden_proof_over_http_mcp():
    authority = issue_authority()
    with running_receiver(authority) as (url, token):
        tools = await build_mcp_tools(authority, receiver_url=url, transport_token=token)
        assert len(tools) == 1
        schema = tools[0].args_schema
        properties = schema["properties"] if isinstance(schema, dict) else schema.model_json_schema()["properties"]
        assert "presentation" not in properties
        model = ToolCallingFakeModel(messages=iter([
            AIMessage(content="", tool_calls=[ToolCall(
                name="provision_cloud_node",
                args={"request_id": "agent-allow", "region": "us-central1",
                      "instance_type": "n2-standard-4", "count": 1}, id="call-1")]),
            "Receiver allowed one node.",
        ]))
        result = await build_agent(model, tools).ainvoke(
            {"messages": [{"role": "user", "content": "Provision one node"}]}
        )
        tool_message = next(message for message in result["messages"]
                            if message.type == "tool")
        assert "allow" in str(tool_message.content).lower()


@pytest.mark.asyncio
async def test_http_mcp_denial_does_not_increment_counter():
    authority = issue_authority()
    with running_receiver(authority) as (url, token):
        tool = (await build_mcp_tools(authority, receiver_url=url,
                                      transport_token=token))[0]
        allowed = await tool.ainvoke({"request_id": "one", "region": "us-central1",
                                      "instance_type": "n2-standard-4", "count": 1})
        denied = await tool.ainvoke({"request_id": "three", "region": "us-central1",
                                     "instance_type": "n2-standard-4", "count": 3})
        assert result_object(allowed)["tool_invocations"] == 1
        assert result_object(denied)["tool_invocations"] == 1


@pytest.mark.asyncio
async def test_unauthenticated_transport_cannot_reach_receiver():
    authority = issue_authority()
    with running_receiver(authority) as (url, _):
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json={})
        assert response.status_code == 401
