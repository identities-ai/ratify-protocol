#!/usr/bin/env python3
"""Local harness for the independently configured HTTP MCP reference."""

from __future__ import annotations

import asyncio
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from authority_reference import build_supported_mcp_adapter, issue_dual_root_federated_authority
from authority_reference.deployment_config import load_transport_token, write_configs


class _DemoModel(BaseLlm):
    tool_args: dict
    turn: int = 0

    async def generate_content_async(self, llm_request, stream=False):
        self.turn += 1
        if self.turn == 1:
            yield LlmResponse(content=types.Content(
                role="model",
                parts=[types.Part(function_call=types.FunctionCall(
                    id="demo-call",
                    name="provision_cloud_node",
                    args=self.tool_args,
                ))],
            ))
        else:
            yield LlmResponse(content=types.Content(
                role="model", parts=[types.Part(text="Receiver decision recorded.")]
            ))


async def run() -> None:
    authority = issue_dual_root_federated_authority()
    with tempfile.TemporaryDirectory() as directory:
        receiver_config = Path(directory) / "receiver.json"
        presenter_config = Path(directory) / "presenter.json"
        write_configs(authority, receiver_config, presenter_config)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen([
            sys.executable, "-m", "authority_reference.mcp_server",
            "--trust-config", str(receiver_config), "--port", str(port),
        ])
        try:
            ready = False
            for _ in range(200):
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", port)) == 0:
                        ready = True
                        break
                time.sleep(0.05)
            if not ready:
                raise RuntimeError("HTTP MCP receiver did not become ready")
            async def invoke(request_id: str, region: str, count: int):
                adapter = build_supported_mcp_adapter(
                    authority,
                    receiver_url=f"http://127.0.0.1:{port}/mcp",
                    transport_token=load_transport_token(str(presenter_config)),
                )
                agent = LlmAgent(
                    name="ratify_demo_agent",
                    model=_DemoModel(model="scripted-demo-model", tool_args={
                        "request_id": request_id,
                        "region": region,
                        "instance_type": "n2-standard-4",
                        "count": count,
                    }),
                    instruction="Call the receiver-gated provisioning tool.",
                    tools=[adapter],
                    before_tool_callback=adapter.before_tool_callback,
                )
                runner = InMemoryRunner(agent=agent, app_name="ratify_demo")
                try:
                    session = await runner.session_service.create_session(
                        app_name="ratify_demo", user_id="demo-user"
                    )
                    response = None
                    async for event in runner.run_async(
                        user_id="demo-user",
                        session_id=session.id,
                        new_message=types.Content(
                            role="user", parts=[types.Part(text="Provision nodes.")]
                        ),
                    ):
                        for part in event.content.parts if event.content else []:
                            if part.function_response:
                                response = part.function_response.response
                    if response is None:
                        raise RuntimeError("ADK runner returned no tool response")
                    return response
                finally:
                    await runner.close()

            allowed = await invoke("req-allow", "us-central1", 1)
            excessive = await invoke("req-count", "us-central1", 3)
            wrong_region = await invoke("req-region", "us-east1", 1)
            print(f"ALLOW across ADK HTTP MCP: {allowed}")
            print(f"DENY excessive count: {excessive}")
            print(f"DENY wrong region: {wrong_region}")
            assert allowed["tool_invocations"] == 1
            assert excessive["decision"] == wrong_region["decision"] == "deny"
            assert excessive["tool_invocations"] == wrong_region["tool_invocations"] == 1
            print("GOOGLE ADK HTTP MCP FEDERATION REFERENCE PASSED")
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(run())
