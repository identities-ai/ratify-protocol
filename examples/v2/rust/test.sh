#!/usr/bin/env bash
# Builds and runs every Rust v2 example against this source tree and compares
# its output with examples/v2/expected/<program>.txt. Every SDK must print the
# same text.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED="$HERE/../expected"
cd "$HERE"

cargo build --locked --release --bins

status=0
for program in quickstart signed_status custom_scope external_signer; do
  if diff -u "$EXPECTED/$program.txt" <("${CARGO_TARGET_DIR:-$HERE/target}/release/$program"); then
    echo "ok   rust $program"
  else
    echo "FAIL rust $program"
    status=1
  fi
done
exit "$status"
