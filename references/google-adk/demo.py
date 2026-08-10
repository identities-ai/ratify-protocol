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

from authority_reference import build_mcp_toolset, issue_authority
from authority_reference.deployment_config import load_transport_token, write_configs


async def run() -> None:
    authority = issue_authority()
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
            toolset = build_mcp_toolset(
                authority,
                receiver_url=f"http://127.0.0.1:{port}/mcp",
                transport_token=load_transport_token(str(presenter_config)),
            )
            try:
                tool = (await toolset.get_tools())[0]
                async def invoke(request_id: str, region: str, count: int):
                    return await tool.run_async(args={
                        "request_id": request_id,
                        "region": region,
                        "instance_type": "n2-standard-4",
                        "count": count,
                    }, tool_context=None)
                allowed = await invoke("req-allow", "us-central1", 1)
                excessive = await invoke("req-count", "us-central1", 3)
                wrong_region = await invoke("req-region", "us-east1", 1)
                print(f"ALLOW across ADK HTTP MCP: {allowed}")
                print(f"DENY excessive count: {excessive}")
                print(f"DENY wrong region: {wrong_region}")
                assert allowed["tool_invocations"] == 1
                assert excessive["decision"] == wrong_region["decision"] == "deny"
                assert excessive["tool_invocations"] == wrong_region["tool_invocations"] == 1
                print("GOOGLE ADK HTTP MCP AUTHORITY REFERENCE PASSED")
            finally:
                await toolset.close()
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(run())
