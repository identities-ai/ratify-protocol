#!/usr/bin/env bash
# Compatibility entry point. The authoritative NVIDIA NOOA reference gate
# (Ratify Protocol v2) lives with the demo and owns its environment, pins,
# expected per-module counts, and the failure on any skip:
#
#   PYTHON=/path/to/python3.12 ./demos/nvidia-nooa-delegated-authority/reference-check-v2.sh
#
# The Protocol v1 gate this script used to contain (181 tests against
# ratify-protocol 1.0.0a20) is recorded in docs/evidence/nvidia-reference-evidence.md
# and in git history; the demo no longer runs on v1.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/demos/nvidia-nooa-delegated-authority/reference-check-v2.sh" "$@"
