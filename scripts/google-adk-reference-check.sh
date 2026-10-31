#!/usr/bin/env bash
# Compatibility entry point. The google-adk reference gate (Ratify Protocol v2) lives
# with the reference and owns its environment, pins, and expected count:
#
#   ./references/google-adk/run-reference-check.sh
#
# The Protocol v1 gate is kept as dated history under references/google-adk/v1/.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/references/google-adk/run-reference-check.sh" "$@"
