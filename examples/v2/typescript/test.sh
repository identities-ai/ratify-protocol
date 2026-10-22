#!/usr/bin/env bash
# Runs every TypeScript v2 example against this source tree and compares its
# output with examples/v2/expected/<program>.txt. Every SDK must print the
# same text. Requires Node.js 22.18 or later (built-in type stripping).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXPECTED="$ROOT/examples/v2/expected"
SDK="$ROOT/sdks/typescript"
HERE="$ROOT/examples/v2/typescript"

# Build the SDK from this tree; the examples import it as a file: dependency.
if [ ! -d "$SDK/node_modules" ]; then
  (cd "$SDK" && npm ci --no-audit --no-fund)
fi
(cd "$SDK" && npm run build --silent)
(cd "$HERE" && npm ci --no-audit --no-fund --silent)
(cd "$HERE" && npx tsc -p .)

cd "$HERE"
status=0
for program in quickstart signed_status custom_scope external_signer; do
  if diff -u "$EXPECTED/$program.txt" <(node "$program.ts"); then
    echo "ok   typescript $program"
  else
    echo "FAIL typescript $program"
    status=1
  fi
done
exit "$status"
