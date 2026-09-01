#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${RATIFY_SDK:?Set RATIFY_SDK to the unpacked Ratify C SDK}"
[ -f "$RATIFY_SDK/include/ratify.h" ] || { echo "missing Ratify C header" >&2; exit 1; }
[ -f "$RATIFY_SDK/lib/libratify_c.so" ] || [ -f "$RATIFY_SDK/lib/libratify_c.a" ] || { echo "missing Ratify C library" >&2; exit 1; }
grep -Fq 'Version: 1.0.0-alpha.19' "$RATIFY_SDK/include/ratify.h" || {
    echo "Ratify C SDK must be version 1.0.0-alpha.19" >&2
    exit 1
}
cleanup() { make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean >/dev/null 2>&1 || true; }
trap cleanup EXIT
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean core_test edge-test edge controller
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" test
echo "reference gate: core tests passed"
