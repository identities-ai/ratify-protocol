# A2A delegated authority

- **Profile:** [`../a2a/`](../a2a/README.md)
- **Protocol line:** v2 (2.0.0-beta.1), one-directional only. Mutual presentation, the receiver-to-caller proof, the A2A mutual-presentation carrier, and `verification_result` are v1-only until Protocol 2.1
- **Status:** Independent experimental draft; 8/8 deterministic gate green on 2026-10-31 against published `2.0.0b1` packages, including HTTPS and an independent Node wire client
- **Ratify:** Published `ratify-protocol[protocol-v2]==2.0.0b1`, including `ratify-protocol-native-v2==2.0.0b1`; v1 `1.0.0a20` evidence remains dated history
- **Platform:** `a2a-sdk[http-server]==1.2.2` with A2A 1.0 JSON-RPC, Python 3.12, Node.js 22 or newer, local HTTPS
- **Gate:** `./references/a2a/run-reference-check.sh` (also `./scripts/a2a-reference-check.sh`)
- **Evidence:** [Published-package gate](../../docs/evidence/v2-published-beta1-2026-10-31.md); [earlier in-tree record](../a2a/EVIDENCE.md)
- **Extension URI:** provisional, unregistered
- **Development-only stores:** the claim store, receipt log, checkpoint, issuance store, and journal are the SDK's in-memory reference stores
- **Discussion brief:** [`../a2a/AGNTCY_A2A_FIT.md`](../a2a/AGNTCY_A2A_FIT.md)
- **Endorsement:** Not reviewed, approved, or sponsored by A2A, AGNTCY, Cisco, Google, or Microsoft
