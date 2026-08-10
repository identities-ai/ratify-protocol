#!/usr/bin/env python3
"""One-command deterministic demonstration using a real ADK FunctionTool."""

from __future__ import annotations

from authority_reference import InfrastructureReceiver, build_provision_tool, issue_authority


def main() -> None:
    authority = issue_authority()
    receiver = InfrastructureReceiver(
        trusted_root_id=authority.root_id,
        trusted_root_public_key=authority.root_public_key,
    )
    tool = build_provision_tool(receiver, authority)

    allowed = tool.func("req-allow", "us-central1", "n2-standard-4", 1)
    excessive = tool.func("req-count", "us-central1", "n2-standard-4", 3)
    wrong_region = tool.func("req-region", "us-east1", "n2-standard-4", 1)

    print(f"ALLOW -> tool invoked once: {allowed}")
    print(f"DENY excessive count -> no additional invocation: {excessive}")
    print(f"DENY wrong region -> no additional invocation: {wrong_region}")

    assert allowed["decision"] == "allow" and allowed["tool_invocations"] == 1
    assert excessive["decision"] == "deny" and excessive["tool_invocations"] == 1
    assert wrong_region["decision"] == "deny" and wrong_region["tool_invocations"] == 1
    print("GOOGLE ADK AUTHORITY REFERENCE PASSED")


if __name__ == "__main__":
    main()
