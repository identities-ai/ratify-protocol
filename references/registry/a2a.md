# A2A delegated authority

- **Profile:** [`../a2a/`](../a2a/README.md)
- **Protocol line:** v2 (prerelease), one-directional only. Mutual presentation, the receiver-to-caller proof, the A2A mutual-presentation carrier, and `verification_result` are v1-only until Protocol 2.1
- **Status:** Independent experimental draft; 8/8 deterministic tests green on 2026-10-22, including HTTPS and an independent Node wire client. The v2 gate ran against local SDK builds; the published v2 packages are not yet released
- **Ratify:** `ratify-protocol-v2` `2.0.0a1` (local build); v1 `1.0.0a20` evidence kept as dated history
- **Platform:** `a2a-sdk[http-server]==1.2.2` with A2A 1.0 JSON-RPC, Python 3.12, Node.js 22 or newer, local HTTPS
- **Gate:** `RATIFY_V2_NATIVE_WHEEL=... RATIFY_V2_PYTHON_SDK=... ./scripts/a2a-reference-check.sh`
- **Evidence:** [`../a2a/EVIDENCE.md`](../a2a/EVIDENCE.md)
- **Extension URI:** provisional, unregistered
- **Discussion brief:** [`../a2a/AGNTCY_A2A_FIT.md`](../a2a/AGNTCY_A2A_FIT.md)
- **Endorsement:** Not reviewed, approved, or sponsored by A2A, AGNTCY, Cisco, Google, or Microsoft
