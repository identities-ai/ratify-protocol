# Google ADK

- **Profile:** [`../google-adk/`](../google-adk/README.md)
- **Protocol line:** v2 (2.0.0-beta.1)
- **Status:** Independent draft ported to Protocol v2; 58/58 deterministic gate green against the in-tree v2 SDK; dual-root composition profile executed; 10, 100, and 1,000 exact-call tiers measured; not yet re-run against the published 2.0.0-beta.1 packages
- **Ratify:** `ratify-protocol` 2.0.0b1 with its `protocol-v2` extra (`ratify_protocol.v2`) and `ratify-protocol-native-v2` 2.0.0b1, built from this repository; pins to the published `ratify-protocol[protocol-v2]==2.0.0b1` (2.0.0-beta.1) at release
- **Platform:** `google-adk==2.6.3`, `mcp==1.29.0`
- **Gate:** `./references/google-adk/run-reference-check.sh`
- **Evidence:** [`../google-adk/evidence/reference-evidence.md`](../google-adk/evidence/reference-evidence.md)
- **Federation and scale:** [`../google-adk/FEDERATION_SCALE.md`](../google-adk/FEDERATION_SCALE.md)
- **Scale command:** `cd references/google-adk && python -m authority_reference.scale_benchmark --calls 10,100,1000 --workers 8`
- **Production backlog:** [`../google-adk/PRODUCTION_GAPS.md`](../google-adk/PRODUCTION_GAPS.md)
- **Development-only stores:** the claim store, receipt log, checkpoint, issuance store, journal, and approval ledger are the SDK's in-memory reference stores
- **Protocol v1 history:** [`../google-adk/v1/`](../google-adk/v1/README.md) (49/49 gate and the one-million-call endurance run, dated September 2026)
- **Endorsement:** Not Google-reviewed or Google-approved
