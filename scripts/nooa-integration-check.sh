#!/usr/bin/env bash
# Compatibility entry point. The NOOA integration tests no longer have a
# separate gate: they run, and are required not to skip, inside the full
# NVIDIA NOOA reference gate on Ratify Protocol v2, which sets
# RATIFY_REQUIRE_NOOA=1 and asserts exactly 4 NOOA integration tests:
#
#   PYTHON=/path/to/python3.12 ./demos/nvidia-nooa-delegated-authority/reference-check-v2.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/demos/nvidia-nooa-delegated-authority/reference-check-v2.sh" "$@"
