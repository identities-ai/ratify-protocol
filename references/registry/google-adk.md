# Google ADK

- **Profile:** [`../google-adk/`](../google-adk/README.md)
- **Status:** Independent draft; 49/49 deterministic gate green; dual-root federation and one-million exact-call endurance measured
- **Ratify:** `1.0.0a20`
- **Platform:** `google-adk==2.6.3`
- **Gate:** `./scripts/google-adk-reference-check.sh`
- **Federation and scale:** [`../google-adk/FEDERATION_SCALE.md`](../google-adk/FEDERATION_SCALE.md)
- **Scale command:** `cd references/google-adk && python -m authority_reference.scale_benchmark --calls 10,100,1000,1000000 --workers 8`
- **Production backlog:** [`../google-adk/PRODUCTION_GAPS.md`](../google-adk/PRODUCTION_GAPS.md)
- **Endorsement:** Not Google-reviewed or Google-approved
