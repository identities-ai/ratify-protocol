# NVIDIA OpenShell + NOOA

- **Profile:** [`../nvidia-nooa-openshell/`](../nvidia-nooa-openshell/README.md)
- **Status:** Executed draft; pending NVIDIA review
- **Protocol line:** v2 tested on 2026-10-22 against the Python SDK built from this tree (`ratify-protocol-v2` `2.0.0a1` prerelease build, before the published `2.0.0-beta.1`): deterministic gate 192/192, live OpenShell profile 64/64 gates and 52/52 required cases (one run), development-only reference stores; v1 tested at `1.0.0a20` (181/181, live profile 64/64 on 2026-09-18)
- **Ratify:** `ratify-protocol-v2` (v2, local build); v1 history at `1.0.0a20`
- **Platform:** `openshell==0.0.102`, `nooa==0.0.8`
- **Gate:** `./demos/nvidia-nooa-delegated-authority/reference-check-v2.sh` (v2); live: `./demos/nvidia-nooa-delegated-authority/run-openshell-profile.sh`
- **Evidence:** [`evidence-v2-2026-10-22.md`](../nvidia-nooa-openshell/evidence-v2-2026-10-22.md) (v2); [`docs/evidence/nvidia-reference-evidence.md`](../../docs/evidence/nvidia-reference-evidence.md) (v1)
- **Production backlog:** [`../nvidia-nooa-openshell/PRODUCTION_GAPS.md`](../nvidia-nooa-openshell/PRODUCTION_GAPS.md)
- **Endorsement:** Not NVIDIA-reviewed or NVIDIA-approved
