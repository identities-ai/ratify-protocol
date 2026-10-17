"""The A2A wire path must leave the protected action untouched on denial."""

import asyncio
import uuid

import httpx
import pytest

from poc import EXTENSION_URI, demo_fixture, operation_data, presentation_metadata
from authority_reference.receiver import OperationRequest


async def send(client, request, step, *, metadata=None, activate=True, expect_error=False,
               payload=None):
    message = {
        "messageId": str(uuid.uuid4()),
        "role": "ROLE_USER",
        "parts": [{"data": payload if payload is not None else operation_data(request, step),
                   "mediaType": "application/json"}],
    }
    if metadata is not None:
        message["metadata"] = metadata
    response = await client.post(
        "/",
        headers={"A2A-Version": "1.0", **({"A2A-Extensions": EXTENSION_URI} if activate else {})},
        json={"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "SendMessage",
              "params": {"message": message}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    if expect_error:
        return body["error"]
    assert "error" not in body, body
    return body["result"]["message"]["parts"][0]["data"]


def test_receiver_checks_exact_a2a_operation_before_provisioning():
    async def scenario():
        app, authority, receiver = demo_fixture()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8766") as client:
            allowed = OperationRequest("allow-1", "us-central1", "n2-standard-4", 1)
            grant = await send(client, allowed, "challenge")
            proof = presentation_metadata(authority, grant, allowed)
            result = await send(client, allowed, "execute", metadata=proof)
            assert result["decision"] == "allow"
            assert receiver.tool_invocations == 1
            replay = await send(client, allowed, "execute", metadata=proof)
            assert replay["decision"] == "deny"
            assert replay["status"] == "unknown_operation"
            assert receiver.tool_invocations == 1

            excessive = OperationRequest("deny-3", "us-central1", "n2-standard-4", 3)
            grant = await send(client, excessive, "challenge")
            result = await send(client, excessive, "execute",
                                metadata=presentation_metadata(authority, grant, excessive))
            assert result["decision"] == "deny"
            assert result["status"] == "constraint_denied"
            assert receiver.tool_invocations == 1

            original = OperationRequest("changed-1", "us-central1", "n2-standard-4", 1)
            grant = await send(client, original, "challenge")
            changed = OperationRequest("changed-1", "us-east1", "n2-standard-4", 1)
            result = await send(client, changed, "execute",
                                metadata=presentation_metadata(authority, grant, original))
            assert result["decision"] == "deny"
            assert result["status"] == "operation_binding_failed"
            assert receiver.tool_invocations == 1

    asyncio.run(scenario())


def test_missing_extension_or_proof_never_reaches_action():
    async def scenario():
        app, authority, receiver = demo_fixture()
        request = OperationRequest("missing-1", "us-central1", "n2-standard-4", 1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8766") as client:
            error = await send(client, request, "challenge", activate=False, expect_error=True)
            assert error["code"] == -32008
            grant = await send(client, request, "challenge")
            result = await send(client, request, "execute")
            assert result["decision"] == "deny"
            assert result["status"] == "invalid_a2a_message"
            error = await send(client, request, "execute",
                               metadata=presentation_metadata(authority, grant, request), activate=False,
                               expect_error=True)
            assert error["code"] == -32008
            bad_count = operation_data(request, "challenge")
            bad_count["count"] = 1.0
            result = await send(client, request, "challenge", payload=bad_count)
            assert result["status"] == "invalid_a2a_message"
            result = await send(client, request, "execute", metadata={EXTENSION_URI: "invalid"})
            assert result["status"] == "invalid_presentation"
            assert receiver.tool_invocations == 0
            result = await send(client, request, "execute",
                                metadata=presentation_metadata(authority, grant, request))
            assert result["decision"] == "allow"
            assert receiver.tool_invocations == 1

    asyncio.run(scenario())


def test_caller_rejects_a_challenge_for_a_changed_operation():
    async def scenario():
        app, authority, receiver = demo_fixture()
        intended = OperationRequest("intended-1", "us-central1", "n2-standard-4", 1)
        changed = OperationRequest("intended-1", "us-central1", "n2-standard-8", 1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8766") as client:
            grant = await send(client, intended, "challenge", payload=operation_data(changed, "challenge"))
            with pytest.raises(ValueError, match="intended operation"):
                presentation_metadata(authority, grant, intended)
            assert receiver.tool_invocations == 0

    asyncio.run(scenario())


def test_proof_for_another_pending_operation_never_provisions():
    async def scenario():
        app, authority, receiver = demo_fixture()
        first = OperationRequest("first-1", "us-central1", "n2-standard-4", 1)
        second = OperationRequest("second-1", "us-central1", "n2-standard-4", 1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8766") as client:
            first_grant = await send(client, first, "challenge")
            await send(client, second, "challenge")
            first_proof = presentation_metadata(authority, first_grant, first)
            substituted = await send(client, second, "execute", metadata=first_proof)
            assert substituted["decision"] == "deny"
            assert receiver.tool_invocations == 0
            allowed = await send(client, first, "execute", metadata=first_proof)
            assert allowed["decision"] == "allow"
            assert receiver.tool_invocations == 1

    asyncio.run(scenario())
