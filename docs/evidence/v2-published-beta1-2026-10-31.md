# Protocol v2 published beta reference gates, 2026-10-31

These local gates ran against the published `2.0.0-beta.1` packages, not SDK
builds from this source tree. Each gate asserted that the installed SDK loaded
outside the checkout and failed on skipped tests or an unexpected test count.

| Reference | Package | Result | Scope |
|---|---|---:|---|
| Google ADK | PyPI `ratify-protocol[protocol-v2]==2.0.0b1`, including native v2 | 58/58 | Deterministic gate and dual-root HTTP MCP demo |
| LangChain | Same PyPI packages | 34/34 | Deterministic gate and MCP demo |
| A2A | Same PyPI packages | 8/8 | Deterministic gate, local HTTPS and independent Node wire client |
| GitHub Copilot | npm `@identities-ai/ratify-protocol@2.0.0-beta.1` | 13/13 | Deterministic gate and MCP server demo; no native Copilot CLI rerun |
| NVIDIA NOOA | Same PyPI packages | 192/192 | Deterministic receiver, MCP, adjudicator and NOOA tests |
| NVIDIA NOOA live OpenShell | Same PyPI packages in the sandbox | 64/64 gates, 52/52 required cases | One live profile on arm64 macOS with Docker and OpenShell CLI 0.0.102; no linux/amd64 run |
| Physical AI edge sentinel | GitHub release `ratify-c-v2.0.0-beta.1-macos-aarch64.tar.gz` | 32/32 | macOS arm64 gate with mock actuator; no fresh Pi or Arduino run |

GitHub Copilot machine-readable gate result: Result: 13 passed, 0 failed, 0 skipped.

All counts had zero skips. The reference stores are development-only. The
earlier in-tree physical hardware runs remain recorded in their own dated
evidence files; this record does not turn them into published-package or
production results. The live OpenShell run used the pinned gateway, sandbox
and supervisor image digests from `run-openshell-profile.sh`, verified the
SDK inside the sandbox at `/opt/ratify-nooa/site/ratify_protocol/v2`, audited
five log sources for canaries, and left no test containers running. Its local
machine-readable artifact is `openshell-profile-ratify-osp-1793516362-62278.json`
(run ID `ratify-osp-1793516362-62278`); that file is not committed because
the profile writes host-specific paths and ports. The sandbox dependency lock
SHA-256 was `abab82ba729889c6ced568523b75975c0f53c73cb5dabb7a9d3c95da2be3413e`.
