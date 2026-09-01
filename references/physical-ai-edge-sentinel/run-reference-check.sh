#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${RATIFY_SDK:?Set RATIFY_SDK to the unpacked Ratify C SDK}"
[ -f "$RATIFY_SDK/include/ratify.h" ] || { echo "missing Ratify C header" >&2; exit 1; }
[ -f "$RATIFY_SDK/lib/libratify_c.so" ] || [ -f "$RATIFY_SDK/lib/libratify_c.a" ] || { echo "missing Ratify C library" >&2; exit 1; }
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean core_test edge-test controller
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" test
echo "reference gate: core tests passed"
