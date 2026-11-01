# LangChain

- **Profile:** [`../langchain/`](../langchain/README.md)
- **Protocol line:** v2 (2.0.0-beta.1)
- **Status:** Independent draft ported to Protocol v2; 34/34 deterministic gate green against published `2.0.0b1` packages on 2026-10-31
- **Ratify:** Published `ratify-protocol[protocol-v2]==2.0.0b1`, including `ratify-protocol-native-v2==2.0.0b1`
- **Platform:** `langchain==1.3.14`, `langchain-mcp-adapters==0.3.0`, `mcp==1.30.0`
- **Gate:** `./references/langchain/run-reference-check.sh`
- **Evidence:** [Published-package gate](../../docs/evidence/v2-published-beta1-2026-10-31.md); [earlier in-tree record](../langchain/evidence/reference-evidence.md)
- **Production backlog:** [`../langchain/PRODUCTION_GAPS.md`](../langchain/PRODUCTION_GAPS.md)
- **Development-only stores:** the claim store, receipt log, checkpoint, issuance store, and journal are the SDK's in-memory reference stores
- **Protocol v1 history:** [`../langchain/v1/`](../langchain/v1/README.md) (28/28 gate, dated September 2026)
- **Endorsement:** Not LangChain-reviewed or LangChain-approved
