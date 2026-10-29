# NVIDIA OpenShell + NOOA

- **Profile:** [`../nvidia-nooa-openshell/`](../nvidia-nooa-openshell/README.md)
- **Status:** Executed draft; pending NVIDIA review
- **Protocol line:** v2 tested against the Python SDK built from this tree, before the published `2.0.0-beta.1`: deterministic gate 192/192 on 2026-10-29 (`ratify-protocol` `2.0.0b1` with its `protocol-v2` extra, in-tree build), live OpenShell profile 64/64 gates and 52/52 required cases (one run, 2026-10-29, same in-tree build), development-only reference stores; v1 tested at `1.0.0a20` (181/181, live profile 64/64 on 2026-09-18)
- **Ratify:** `ratify-protocol` 2.0.0b1 with its `protocol-v2` extra (`ratify_protocol.v2`, v2, local build); v1 history at `1.0.0a20`
- **Platform:** `openshell==0.0.102`, `nooa==0.0.8`
- **Gate:** `./demos/nvidia-nooa-delegated-authority/reference-check-v2.sh` (v2); live: `./demos/nvidia-nooa-delegated-authority/run-openshell-profile.sh`
- **Evidence:** [`evidence-v2-2026-10-29.md`](../nvidia-nooa-openshell/evidence-v2-2026-10-29.md) (v2 deterministic gate and live profile on the unified `ratify-protocol` 2.0.0b1 build), [`evidence-v2-2026-10-27.md`](../nvidia-nooa-openshell/evidence-v2-2026-10-27.md) (the earlier separate `ratify-protocol-v2` 2.0.0b1 build), [`evidence-v2-2026-10-22.md`](../nvidia-nooa-openshell/evidence-v2-2026-10-22.md) (first v2 record, alpha.1 build); [`docs/evidence/nvidia-reference-evidence.md`](../../docs/evidence/nvidia-reference-evidence.md) (v1)
- **Production backlog:** [`../nvidia-nooa-openshell/PRODUCTION_GAPS.md`](../nvidia-nooa-openshell/PRODUCTION_GAPS.md)
- **Endorsement:** Not NVIDIA-reviewed or NVIDIA-approved
