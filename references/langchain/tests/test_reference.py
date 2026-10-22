"""Deterministic gate for the LangChain reference on Protocol v2.

Every test that reaches a decision runs the full v2 path: SDK-issued
challenge, verification, signed receipt, checkpoint acknowledgement and
release. The Part B stores are the SDK's in-memory reference stores, which is
why this gate is development evidence, not a production claim.
"""

from __future__ import annotations

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
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

from authority_reference import (
    InfrastructureReceiver, OperationRequest, StatusAuthority, build_agent, build_mcp_tools,
    encode_presentation, issue_authority, local_preflight, select_tool_with_jev,
)
from authority_reference.deployment_config import write_configs
from authority_reference.mcp_server import HeaderBoundary, MAX_PRESENTATION_HEADER_BYTES


class ToolCallingFakeModel(GenericFakeChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self


def result_object(value):
    if isinstance(value, list):
        return json.loads(next(block["text"] for block in value if block.get("text")))
    return value


def make_receiver(authority, **options):
    options.setdefault("status_keys", authority.status.status_keys())
    options.setdefault("status_source", authority.status.evidence)
    return InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
        **options,
    )


def setup_reference(**options):
    now = int(time.time())
    authority = issue_authority(now=now - 1, **options)
    return now, authority, make_receiver(authority)


def present(authority, receiver, request):
    grant = receiver.issue_challenge(request, agent_public_key=authority.specialist_public_key)
    return authority.present(grant)


class JevStub:
    def __init__(self, tool_name):
        self.tool_name = tool_name

    def choose_tool(self, state, tools):
        assert state["request"]
        assert self.tool_name in tools
        return type(
            "Decision",
            (),
            {
                "tool_name": self.tool_name,
                "probabilities": {self.tool_name: 1.0},
                "confidence": 1.0,
            },
        )()


def test_jev_selects_a_typed_tool_proposal():
    decision = select_tool_with_jev(
        JevStub("provision_cloud_node"),
        {"request": "provision one staging node"},
        {
            "provision_cloud_node": "Provision a bounded cloud node.",
            "request_approval": "Ask a human to approve the action.",
        },
    )
    assert decision.tool_name == "provision_cloud_node"
    assert decision.probabilities == {"provision_cloud_node": 1.0}


def test_jev_tool_selection_does_not_bypass_receiver_authority():
    _, authority, receiver = setup_reference()
    decision = select_tool_with_jev(
        JevStub("provision_cloud_node"),
        {"request": "provision three staging nodes"},
        {"provision_cloud_node": "Provision a bounded cloud node."},
    )
    assert decision.tool_name == "provision_cloud_node"
    request = OperationRequest("jev-proposal", "us-central1", "n2-standard-4", 3)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["decision"] == "deny"
    assert result["tool_invocations"] == 0


def test_valid_authority_invokes_tool_once():
    _, authority, receiver = setup_reference()
    request = OperationRequest("valid", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["decision"] == "allow"
    assert result["tool_invocations"] == 1
    # Released only after its signed receipt was appended and acknowledged.
    assert result["receipt_sequence"] == 1


@pytest.mark.parametrize("operation", [
    OperationRequest("count", "us-central1", "n2-standard-4", 3),
    OperationRequest("region", "us-east1", "n2-standard-4", 1),
])
def test_signed_bounds_deny_before_tool(operation):
    _, authority, receiver = setup_reference()
    result = receiver.execute(operation, present(authority, receiver, operation))
    assert result["decision"] == "deny"
    assert result["protocol_reason"] == "constraint_denied"
    assert result["tool_invocations"] == 0


def test_expired_authority_denies_before_tool():
    now = int(time.time())
    authority = issue_authority(now=now - 3600, expires_at=now - 1)
    receiver = make_receiver(authority)
    request = OperationRequest("expired", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["status"] == "expired"
    assert result["tool_invocations"] == 0


def test_revoked_authority_denies_before_tool():
    now, authority, receiver = setup_reference()
    leaf = authority.delegations[0]
    authority.status.revoke(leaf.issuer_id, leaf.cert_id, at=now)
    request = OperationRequest("revoked", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["status"] == "revoked"
    assert result["tool_invocations"] == 0


def test_revocation_between_preflight_and_execution_denies_at_receiver():
    now, authority, receiver = setup_reference()
    request = OperationRequest("revoked-after-preflight", "us-central1", "n2-standard-4", 1)
    assert local_preflight(authority, request, now=now) is True
    bundle = present(authority, receiver, request)

    # Control: the same authority is usable before revocation.
    control_now, control_authority, control_receiver = setup_reference()
    control_request = OperationRequest("revocation-control", "us-central1", "n2-standard-4", 1)
    assert local_preflight(control_authority, control_request, now=control_now) is True
    control = control_receiver.execute(
        control_request, present(control_authority, control_receiver, control_request),
    )
    assert control["decision"] == "allow"
    assert control["tool_invocations"] == 1

    # The commander signs the revocation under its own status key.
    leaf = authority.delegations[0]
    authority.status.revoke(leaf.issuer_id, leaf.cert_id, at=now)
    result = receiver.execute(request, bundle)

    assert result["status"] == "revoked"
    assert result["tool_invocations"] == 0


def test_expiry_between_preflight_and_execution_denies_at_receiver():
    now = int(time.time())
    authority = issue_authority(now=now - 1, expires_at=now + 10)
    receiver = make_receiver(authority)
    request = OperationRequest("expired-after-preflight", "us-central1", "n2-standard-4", 1)
    assert local_preflight(authority, request, now=now) is True
    bundle = present(authority, receiver, request)

    # The receiver evaluates the same proof after its signed expiry time.
    result = receiver.execute(request, bundle, now=now + 11)

    assert result["status"] == "expired"
    assert result["tool_invocations"] == 0


def test_replay_does_not_invoke_again():
    _, authority, receiver = setup_reference()
    request = OperationRequest("replay", "us-central1", "n2-standard-4", 1)
    bundle = present(authority, receiver, request)
    pending = receiver._pending[request.request_id]
    assert receiver.execute(request, bundle)["decision"] == "allow"
    replay = receiver.execute(request, bundle)
    assert replay["decision"] == "deny"
    assert replay["tool_invocations"] == 1

    # Even with the application envelope restored, the claim store refuses
    # the consumed challenge.
    receiver._pending[request.request_id] = pending
    protocol_replay = receiver.execute(request, bundle)
    assert protocol_replay["status"] == "replay"
    assert protocol_replay["tool_invocations"] == 1


def test_altered_operation_denies_before_tool():
    _, authority, receiver = setup_reference()
    original = OperationRequest("altered", "us-central1", "n2-standard-4", 1)
    bundle = present(authority, receiver, original)
    altered = OperationRequest("altered", "us-central1", "n2-standard-4", 2)
    result = receiver.execute(altered, bundle)
    assert result["status"] == "operation_binding_failed"
    assert result["tool_invocations"] == 0


def test_wrong_agent_denies_before_tool():
    now, authority, receiver = setup_reference()
    request = OperationRequest("agent", "us-central1", "n2-standard-4", 1)
    grant = receiver.issue_challenge(request, agent_public_key=authority.specialist_public_key)
    # A different agent, with its own valid chain, answers the challenge
    # that was bound to the accepted agent's key.
    hostile = issue_authority(now=now - 1)
    result = receiver.execute(request, hostile.present(grant))
    assert result["status"] == "agent_binding_failed"
    assert result["tool_invocations"] == 0


def test_hostile_root_denies_before_tool():
    now, authority, receiver = setup_reference()
    hostile = issue_authority(now=now - 1)
    request = OperationRequest("root", "us-central1", "n2-standard-4", 1)
    grant = receiver.issue_challenge(request, agent_public_key=hostile.specialist_public_key)
    result = receiver.execute(request, hostile.present(grant))
    assert result["status"] == "untrusted_root"
    assert result["tool_invocations"] == 0


def test_malformed_presentation_does_not_cancel_pending_operation():
    _, authority, receiver = setup_reference()
    request = OperationRequest("malformed", "us-central1", "n2-standard-4", 1)
    bundle = present(authority, receiver, request)
    denied = receiver.execute(request, "not-a-proof")
    allowed = receiver.execute(request, encode_presentation(bundle))
    assert denied["status"] == "invalid_presentation"
    assert allowed["decision"] == "allow"
    assert allowed["tool_invocations"] == 1


def test_pending_capacity_is_bounded():
    _, authority, receiver = setup_reference()
    for index in range(128):
        receiver.issue_challenge(
            OperationRequest(f"capacity-{index}", "us-central1", "n2-standard-4", 1),
            agent_public_key=authority.specialist_public_key,
        )
    with pytest.raises(ValueError, match="receiver_pending_capacity"):
        receiver.issue_challenge(
            OperationRequest("overflow", "us-central1", "n2-standard-4", 1),
            agent_public_key=authority.specialist_public_key,
        )
    assert receiver.tool_invocations == 0


def test_concurrent_duplicate_request_creates_one_pending_operation():
    _, authority, receiver = setup_reference()
    request = OperationRequest("duplicate", "us-central1", "n2-standard-4", 1)

    def issue():
        try:
            receiver.issue_challenge(request, agent_public_key=authority.specialist_public_key)
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
        receiver.issue_challenge(request, agent_public_key=authority.specialist_public_key)
    assert receiver.tool_invocations == 0


def test_release_gate_withholds_the_action_until_the_checkpoint_acknowledges():
    _, authority, receiver = setup_reference()
    receiver.store.set_acknowledgement_withheld(True)
    request = OperationRequest("unacknowledged", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["status"] == "release_withheld"
    assert receiver.tool_invocations == 0


def test_status_key_cannot_be_the_issuer_key():
    _, authority, _ = setup_reference()
    # The root key is already recorded under the issuer role; a key can hold
    # only one permanent role, so it can never become a status key.
    with pytest.raises(Exception, match="role"):
        make_receiver(authority, status_keys={authority.root_id: authority.root_public_key})


def test_status_signed_by_an_unconfigured_key_cannot_allow():
    now, authority, _ = setup_reference()
    impostor = StatusAuthority()
    for cert in authority.delegations:
        impostor.add_issuer(cert.issuer_pub_key, at=now)
    receiver = make_receiver(authority, status_source=impostor.evidence)
    request = OperationRequest("impostor-status", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["decision"] == "deny"
    assert result["protocol_reason"] == "status_unavailable"
    assert receiver.tool_invocations == 0


def test_stale_signed_status_fails_closed():
    now = int(time.time())
    authority = issue_authority(now=now - 1, status_lifetime_seconds=60)
    clock = [now]
    receiver = make_receiver(authority, clock=lambda: clock[0])
    fresh = OperationRequest("fresh-status", "us-central1", "n2-standard-4", 1)
    assert receiver.execute(fresh, present(authority, receiver, fresh))["decision"] == "allow"

    clock[0] = now + 61  # past the list's next_update; no heartbeat arrived
    request = OperationRequest("stale-status", "us-central1", "n2-standard-4", 1)
    result = receiver.execute(request, present(authority, receiver, request))
    assert result["status"] == "status_stale"
    assert receiver.tool_invocations == 1


@contextmanager
def running_receiver(authority):
    with tempfile.TemporaryDirectory() as directory:
        receiver_config = Path(directory) / "receiver.json"
        presenter_config = Path(directory) / "presenter.json"
        status_dir = Path(directory) / "status"
        write_configs(authority, receiver_config, presenter_config, status_dir=status_dir)
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
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read())
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(.05)
            else:
                raise RuntimeError("receiver unavailable")
            yield f"http://127.0.0.1:{port}/mcp", token, status_dir
        finally:
            process.terminate()
            process.wait(timeout=5)


@pytest.mark.asyncio
async def test_real_langchain_agent_uses_hidden_proof_over_http_mcp():
    authority = issue_authority()
    with running_receiver(authority) as (url, token, _):
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
    with running_receiver(authority) as (url, token, _):
        tool = (await build_mcp_tools(authority, receiver_url=url,
                                      transport_token=token))[0]
        allowed = await tool.ainvoke({"request_id": "one", "region": "us-central1",
                                      "instance_type": "n2-standard-4", "count": 1})
        denied = await tool.ainvoke({"request_id": "three", "region": "us-central1",
                                     "instance_type": "n2-standard-4", "count": 3})
        assert result_object(allowed)["tool_invocations"] == 1
        assert result_object(denied)["tool_invocations"] == 1


@pytest.mark.asyncio
async def test_signed_revocation_reaches_the_receiver_through_the_local_status_feed():
    authority = issue_authority()
    with running_receiver(authority) as (url, token, status_dir):
        tool = (await build_mcp_tools(authority, receiver_url=url, transport_token=token))[0]
        args = {"region": "us-central1", "instance_type": "n2-standard-4", "count": 1}
        before = result_object(await tool.ainvoke({**args, "request_id": "feed-1"}))
        leaf = authority.delegations[0]
        authority.status.revoke(leaf.issuer_id, leaf.cert_id, at=int(time.time()))
        authority.status.write(status_dir)
        after = result_object(await tool.ainvoke({**args, "request_id": "feed-2"}))
        assert before["decision"] == "allow"
        assert after["status"] == "revoked"
        assert after["tool_invocations"] == 1


@pytest.mark.asyncio
async def test_unauthenticated_transport_cannot_reach_receiver():
    authority = issue_authority()
    with running_receiver(authority) as (url, _, _):
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json={})
        assert response.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("headers, expected_status", [
    ([(b"x-ratify-transport-token", b"secret"),
      (b"x-ratify-transport-token", b"secret")], 400),
    ([(b"x-ratify-transport-token", b"secret"),
      (b"x-ratify-presentation", b"one"),
      (b"x-ratify-presentation", b"two")], 400),
    ([(b"x-ratify-transport-token", b"secret"),
      (b"x-ratify-presentation", b"x" * (MAX_PRESENTATION_HEADER_BYTES + 1))], 431),
])
async def test_security_header_ambiguity_and_size_fail_before_mcp(headers, expected_status):
    reached = False

    async def app(scope, receive, send):
        nonlocal reached
        reached = True

    sent = []

    async def send(message):
        sent.append(message)

    await HeaderBoundary(app, "secret")(
        {"type": "http", "headers": headers}, lambda: None, send
    )
    assert sent[0]["status"] == expected_status
    assert reached is False
