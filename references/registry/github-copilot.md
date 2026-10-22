# GitHub Copilot

- Profile: [`references/github-copilot`](../github-copilot/README.md)
- Status: independent Ratify reference; not reviewed or endorsed by GitHub or Microsoft
- Protocol line: v2 tested on 2026-10-22 against the TypeScript SDK built from this tree (`2.0.0-alpha.1` prerelease build, before the published `2.0.0-beta.1`), deterministic gate 13/13, development-only reference stores; v1 tested at `1.0.0-alpha.19` (gate 9/9, native Copilot CLI 1.0.80 run on 2026-08-14, not repeated on v2)
- Ratify SDK: `@identities-ai/ratify-protocol` v2 surface (`/v2`), local `file:` build from `sdks/typescript`
- Integration surface: GitHub Copilot plugin, Agent Skill, and MCP server
- MCP SDK: `@modelcontextprotocol/sdk@1.32.1`
- Gate: `references/github-copilot/run-reference-check.sh`
- Gate result: Declared in [`ratify-reference.json`](../github-copilot/ratify-reference.json) and checked by the gate
- Evidence: [`reference-evidence.md`](../github-copilot/reference-evidence.md)

This entry records Ratify-maintained interoperability evidence. It does not imply a partnership, approval, or standardization commitment by GitHub or Microsoft.
