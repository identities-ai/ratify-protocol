#!/usr/bin/env bash
# Compatibility entry point. The A2A reference gate (Ratify Protocol v2) lives
# with the reference and owns its environment, pins, and expected count:
#
#   ./references/a2a/run-reference-check.sh
#
# The Protocol v1 result is kept as dated history in references/a2a/EVIDENCE.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/references/a2a/run-reference-check.sh" "$@"
