# A2A delegated authority

- **Profile:** [`../a2a/`](../a2a/README.md)
- **Protocol line:** v2 (2.0.0-beta.1), one-directional only. Mutual presentation, the receiver-to-caller proof, the A2A mutual-presentation carrier, and `verification_result` are v1-only until Protocol 2.1
- **Status:** Independent experimental draft; 8/8 deterministic gate green on 2026-10-29 against the in-tree v2 SDK, including HTTPS and an independent Node wire client; not yet re-run against the published 2.0.0-beta.1 packages
- **Ratify:** `ratify-protocol` 2.0.0b1 with its `protocol-v2` extra (`ratify_protocol.v2`) and `ratify-protocol-native-v2` 2.0.0b1, built from this repository; pins to the published `ratify-protocol[protocol-v2]==2.0.0b1` (2.0.0-beta.1) at release. v1 `1.0.0a20` evidence kept as dated history
- **Platform:** `a2a-sdk[http-server]==1.2.2` with A2A 1.0 JSON-RPC, Python 3.12, Node.js 22 or newer, local HTTPS
- **Gate:** `./references/a2a/run-reference-check.sh` (also `./scripts/a2a-reference-check.sh`)
- **Evidence:** [`../a2a/EVIDENCE.md`](../a2a/EVIDENCE.md)
- **Extension URI:** provisional, unregistered
- **Development-only stores:** the claim store, receipt log, checkpoint, issuance store, and journal are the SDK's in-memory reference stores
- **Discussion brief:** [`../a2a/AGNTCY_A2A_FIT.md`](../a2a/AGNTCY_A2A_FIT.md)
- **Endorsement:** Not reviewed, approved, or sponsored by A2A, AGNTCY, Cisco, Google, or Microsoft
