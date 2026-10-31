#!/usr/bin/env bash
# Compatibility entry point. The langchain reference gate (Ratify Protocol v2) lives
# with the reference and owns its environment, pins, and expected count:
#
#   ./references/langchain/run-reference-check.sh
#
# The Protocol v1 gate is kept as dated history under references/langchain/v1/.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/references/langchain/run-reference-check.sh" "$@"
