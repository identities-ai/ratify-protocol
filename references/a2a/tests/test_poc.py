"""The A2A wire path must leave the protected action untouched on denial."""

import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import uuid

import httpx
import pytest

from poc import EXTENSION_URI, demo_fixture, operation_data, presentation_metadata
from authority_reference.receiver import OperationRequest


async def send(client, request, step, *, metadata=None, activate=True, expect_error=False,
               payload=None, task=None, token=None):
    message = {
        "messageId": str(uuid.uuid4()),
        "role": "ROLE_USER",
        "parts": [{"data": payload if payload is not None else operation_data(request, step),
                   "mediaType": "application/json"}],
    }
    if metadata is not None:
        message["metadata"] = metadata
    if task is not None:
        message["taskId"] = task["_task_id"]
        message["contextId"] = task["_context_id"]
    response = await client.post(
        "/",
        headers={"A2A-Version": "1.0", **({"A2A-Extensions": EXTENSION_URI} if activate else {}),
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        json={"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "SendMessage",
              "params": {"message": message}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    if expect_error:
        return body["error"]
    assert "error" not in body, body
    result = body["result"]["task"]
    data = result["status"]["message"]["parts"][0]["data"]
    return {**data, "_task_id": result["id"], "_context_id": result["contextId"],
            "_state": result["status"]["state"]}


def bound(request, task):
    return replace(request, task_id=task["_task_id"], context_id=task["_context_id"])


def test_receiver_checks_exact_a2a_operation_before_provisioning():
    async def scenario():
        app, authority, receiver = demo_fixture()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8766") as client:
            allowed = OperationRequest("allow-1", "us-central1", "n2-standard-4", 1)
            grant = await send(client, allowed, "challenge")
            proof = presentation_metadata(authority, grant, bound(allowed, grant))
            result = await send(client, allowed, "execute", metadata=proof, task=grant)
            assert result["decision"] == "allow"
            assert receiver.tool_invocations == 1
            replay = await send(client, allowed, "execute", metadata=proof, task=grant,
                                expect_error=True)
            assert replay["code"] == -32004
            assert receiver.tool_invocations == 1

            excessive = OperationRequest("deny-3", "us-central1", "n2-standard-4", 3)
            grant = await send(client, excessive, "challenge")
            result = await send(client, excessive, "execute",
                                metadata=presentation_metadata(authority, grant, bound(excessive, grant)),
                                task=grant)
            assert result["decision"] == "deny"
            assert result["status"] == "constraint_denied"
            assert result["_state"] == "TASK_STATE_REJECTED"
            assert receiver.tool_invocations == 1

            original = OperationRequest("changed-1", "us-central1", "n2-standard-4", 1)
            grant = await send(client, original, "challenge")
            changed = OperationRequest("changed-1", "us-east1", "n2-standard-4", 1)
            result = await send(client, changed, "execute",
                                metadata=presentation_metadata(authority, grant, bound(original, grant)),
                                task=grant)
            assert result["decision"] == "deny"
            assert result["status"] == "operation_binding_failed"
            assert result["_state"] == "TASK_STATE_AUTH_REQUIRED"
            unknown = OperationRequest("unknown-id", "us-central1", "n2-standard-4", 1)
            result = await send(client, unknown, "execute", metadata={}, task=grant)
            assert result["status"] == "invalid_a2a_message"
            assert result["_state"] == "TASK_STATE_AUTH_REQUIRED"
            result = await send(client, unknown, "challenge", task=grant)
            assert result["status"] == "invalid_a2a_message"
            assert result["_state"] == "TASK_STATE_AUTH_REQUIRED"
            assert receiver.tool_invocations == 1
            result = await send(client, original, "execute", task=grant,
                                metadata=presentation_metadata(authority, grant,
                                                               bound(original, grant)))
            assert result["decision"] == "allow"
            assert result["_state"] == "TASK_STATE_COMPLETED"
            assert receiver.tool_invocations == 2

    asyncio.run(scenario())


def test_separate_https_receiver_requires_caller_auth_and_verifies_task():
    async def scenario():
        from authority_reference.authority import issue_authority

        authority = issue_authority()
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "receiver.crt"
            key = Path(directory) / "receiver.key"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            token = secrets.token_urlsafe(32)
            env = {**os.environ,
                   "A2A_PORT": str(port), "A2A_BEARER_TOKEN": token,
                   "A2A_ROOT_ID": authority.root_id,
                   "A2A_ROOT_ED25519": authority.root_public_key.ed25519.hex(),
                   "A2A_ROOT_ML_DSA_65": authority.root_public_key.ml_dsa_65.hex(),
                   "A2A_AGENT_ID": authority.specialist_id,
                   "A2A_TLS_CERT": str(cert), "A2A_TLS_KEY": str(key)}
            server = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve().parents[1] / "serve.py")],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            try:
                async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(cert)),
                                             trust_env=False,
                                             base_url=f"https://localhost:{port}") as client:
                    for _ in range(50):
                        if server.poll() is not None:
                            raise AssertionError(f"receiver exited: {server.stderr.read().decode()}")
                        try:
                            card = await client.get("/.well-known/agent-card.json")
                            break
                        except httpx.ConnectError:
                            await asyncio.sleep(0.1)
                    else:
                        raise AssertionError("HTTPS receiver did not start")
                    assert card.status_code == 200
                    assert "callerBearer" in card.json()["securitySchemes"]
                    async with httpx.AsyncClient(base_url=f"https://localhost:{port}",
                                                 trust_env=False) as untrusted:
                        with pytest.raises(httpx.ConnectError):
                            await untrusted.get("/.well-known/agent-card.json")
                    request = OperationRequest("network-1", "us-central1", "n2-standard-4", 1)
                    unauthenticated = await client.post("/", json={})
                    assert unauthenticated.status_code == 401
                    wrong = await client.post("/", headers={"Authorization": "Bearer wrong"}, json={})
                    assert wrong.status_code == 401
                    def node_send(operation, step, *, metadata=None, task=None,
                                  context_id=None):
                        wire = {
                            "url": f"https://localhost:{port}/", "token": token,
                            "extension": EXTENSION_URI,
                            "data": operation_data(operation, step),
                            "metadata": metadata,
                        }
                        if task is not None:
                            wire["taskId"] = task["_task_id"]
                            wire["contextId"] = task["_context_id"]
                        elif context_id is not None:
                            wire["contextId"] = context_id
                        completed = subprocess.run(
                            ["node", str(Path(__file__).resolve().parents[1] / "wire_client.mjs")],
                            input=json.dumps(wire), text=True, capture_output=True,
                            env={**os.environ, "NODE_EXTRA_CA_CERTS": str(cert),
                                 "NODE_TLS_REJECT_UNAUTHORIZED": "1"}, check=True,
                        )
                        envelope = json.loads(completed.stdout)
                        assert envelope["status"] == 200, envelope
                        assert "error" not in envelope["body"], envelope
                        result = envelope["body"]["result"]["task"]
                        data = result["status"]["message"]["parts"][0]["data"]
                        return {**data, "_task_id": result["id"],
                                "_context_id": result["contextId"],
                                "_state": result["status"]["state"]}

                    grant = node_send(request, "challenge", context_id="client-context-1")
                    assert grant["_state"] == "TASK_STATE_AUTH_REQUIRED"
                    assert grant["_context_id"] == "client-context-1"
                    with pytest.raises(ValueError, match="intended operation"):
                        presentation_metadata(authority, grant,
                                              replace(bound(request, grant), task_id="other-task"))
                    proof = presentation_metadata(authority, grant, bound(request, grant))
                    execute_message = {
                        "messageId": "unauthorized-execute", "role": "ROLE_USER",
                        "taskId": grant["_task_id"], "contextId": grant["_context_id"],
                        "parts": [{"data": operation_data(request, "execute"),
                                   "mediaType": "application/json"}],
                        "metadata": proof,
                    }
                    execute_body = {"jsonrpc": "2.0", "id": "unauthorized-attempt",
                                    "method": "SendMessage", "params": {"message": execute_message}}
                    denied_without_token = await client.post("/", json=execute_body)
                    assert denied_without_token.status_code == 401
                    denied_wrong_token = await client.post(
                        "/", json=execute_body,
                        headers={"Authorization": "Bearer wrong"})
                    assert denied_wrong_token.status_code == 401
                    result = node_send(request, "execute", metadata=proof, task=grant)
                    assert result["_state"] == "TASK_STATE_COMPLETED"
                    assert result["decision"] == "allow"
                    assert result["tool_invocations"] == 1
                    rechallenge = node_send(request, "challenge")
                    assert rechallenge["_task_id"] != grant["_task_id"]
                    assert rechallenge["session_inputs"]["request_hash"] != grant["session_inputs"]["request_hash"]
                    replayed_on_new_task = node_send(request, "execute", metadata=proof,
                                                     task=rechallenge)
                    assert replayed_on_new_task["decision"] == "deny"
                    assert replayed_on_new_task["tool_invocations"] == 1
                    second = OperationRequest("network-2", "us-central1", "n2-standard-4", 1)
                    second_grant = node_send(second, "challenge")
                    substituted = node_send(second, "execute", metadata=proof,
                                            task=second_grant)
                    assert substituted["decision"] == "deny"
                    assert substituted["tool_invocations"] == 1
                    honest = node_send(second, "execute", task=second_grant,
                                       metadata=presentation_metadata(
                                           authority, second_grant, bound(second, second_grant)))
                    assert honest["decision"] == "allow"
                    assert honest["tool_invocations"] == 2
            finally:
                server.terminate()
                server.wait(timeout=10)

    asyncio.run(scenario())


def test_protected_action_failure_finishes_the_task():
    async def scenario():
        app, authority, receiver = demo_fixture()

        class FailingProvisioner:
            def provision(self, request):
                raise RuntimeError("provisioner failed")

        receiver.provisioner = FailingProvisioner()
        request = OperationRequest("action-fails", "us-central1", "n2-standard-4", 1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1:8766") as client:
            grant = await send(client, request, "challenge")
            result = await send(client, request, "execute", task=grant,
                                metadata=presentation_metadata(authority, grant,
                                                               bound(request, grant)))
            assert result["decision"] == "deny"
            assert result["status"] == "protected_action_failed"
            assert result["_state"] == "TASK_STATE_FAILED"
            assert receiver.tool_invocations == 0

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
            result = await send(client, request, "execute", task=grant)
            assert result["decision"] == "deny"
            assert result["status"] == "invalid_a2a_message"
            error = await send(client, request, "execute",
                               metadata=presentation_metadata(authority, grant, bound(request, grant)),
                               task=grant, activate=False,
                               expect_error=True)
            assert error["code"] == -32008
            bad_count = operation_data(request, "challenge")
            bad_count["count"] = 1.0
            result = await send(client, request, "challenge", payload=bad_count)
            assert result["status"] == "invalid_a2a_message"
            result = await send(client, request, "execute", metadata={EXTENSION_URI: "invalid"},
                                task=grant)
            assert result["status"] == "invalid_presentation"
            assert result["_state"] == "TASK_STATE_AUTH_REQUIRED"
            assert receiver.tool_invocations == 0
            result = await send(client, request, "execute",
                                metadata=presentation_metadata(authority, grant, bound(request, grant)),
                                task=grant)
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
                presentation_metadata(authority, grant, bound(intended, grant))
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
            second_grant = await send(client, second, "challenge")
            first_proof = presentation_metadata(authority, first_grant, bound(first, first_grant))
            substituted = await send(client, second, "execute", metadata=first_proof,
                                     task=second_grant)
            assert substituted["decision"] == "deny"
            assert receiver.tool_invocations == 0
            allowed = await send(client, first, "execute", metadata=first_proof,
                                 task=first_grant)
            assert allowed["decision"] == "allow"
            assert receiver.tool_invocations == 1

    asyncio.run(scenario())
