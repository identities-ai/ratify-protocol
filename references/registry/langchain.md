# LangChain

- **Profile:** [`../langchain/`](../langchain/README.md)
- **Protocol line:** v2 (2.0.0-beta.1)
- **Status:** Independent draft ported to Protocol v2; 34/34 deterministic gate green against the in-tree v2 SDK; not yet re-run against the published 2.0.0-beta.1 packages
- **Ratify:** `ratify-protocol` 2.0.0b1 with its `protocol-v2` extra (`ratify_protocol.v2`) and `ratify-protocol-native-v2` 2.0.0b1, built from this repository; pins to the published `ratify-protocol[protocol-v2]==2.0.0b1` (2.0.0-beta.1) at release
- **Platform:** `langchain==1.3.14`, `langchain-mcp-adapters==0.3.0`, `mcp==1.30.0`
- **Gate:** `./references/langchain/run-reference-check.sh`
- **Evidence:** [`../langchain/evidence/reference-evidence.md`](../langchain/evidence/reference-evidence.md)
- **Production backlog:** [`../langchain/PRODUCTION_GAPS.md`](../langchain/PRODUCTION_GAPS.md)
- **Development-only stores:** the claim store, receipt log, checkpoint, issuance store, and journal are the SDK's in-memory reference stores
- **Protocol v1 history:** [`../langchain/v1/`](../langchain/v1/README.md) (28/28 gate, dated September 2026)
- **Endorsement:** Not LangChain-reviewed or LangChain-approved
