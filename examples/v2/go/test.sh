#!/usr/bin/env bash
# Runs every Go v2 example against this source tree and compares its output
# with examples/v2/expected/<program>.txt. Every SDK must print the same text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXPECTED="$ROOT/examples/v2/expected"
cd "$ROOT"

status=0
for program in quickstart signed_status custom_scope external_signer; do
  if diff -u "$EXPECTED/$program.txt" <(go run "./examples/v2/go/$program"); then
    echo "ok   go $program"
  else
    echo "FAIL go $program"
    status=1
  fi
done
exit "$status"
