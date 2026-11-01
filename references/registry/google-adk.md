# Google ADK

- **Profile:** [`../google-adk/`](../google-adk/README.md)
- **Protocol line:** v2 (2.0.0-beta.1)
- **Status:** Independent draft ported to Protocol v2; 58/58 deterministic gate green against published `2.0.0b1` packages on 2026-10-31; dual-root composition profile executed; 10, 100, and 1,000 exact-call tiers measured on the earlier in-tree build
- **Ratify:** Published `ratify-protocol[protocol-v2]==2.0.0b1`, including `ratify-protocol-native-v2==2.0.0b1`
- **Platform:** `google-adk==2.6.3`, `mcp==1.30.0`
- **Gate:** `./references/google-adk/run-reference-check.sh`
- **Evidence:** [Published-package gate](../../docs/evidence/v2-published-beta1-2026-10-31.md); [earlier in-tree record](../google-adk/evidence/reference-evidence.md)
- **Federation and scale:** [`../google-adk/FEDERATION_SCALE.md`](../google-adk/FEDERATION_SCALE.md)
- **Scale command:** `cd references/google-adk && python -m authority_reference.scale_benchmark --calls 10,100,1000 --workers 8`
- **Production backlog:** [`../google-adk/PRODUCTION_GAPS.md`](../google-adk/PRODUCTION_GAPS.md)
- **Development-only stores:** the claim store, receipt log, checkpoint, issuance store, journal, and approval ledger are the SDK's in-memory reference stores
- **Protocol v1 history:** [`../google-adk/v1/`](../google-adk/v1/README.md) (49/49 gate and the one-million-call endurance run, dated September 2026)
- **Endorsement:** Not Google-reviewed or Google-approved
