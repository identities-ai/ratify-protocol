#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${RATIFY_SDK:?Set RATIFY_SDK to the unpacked Ratify C SDK}"
[ -f "$RATIFY_SDK/include/ratify.h" ] || { echo "missing Ratify C header" >&2; exit 1; }
[ -f "$RATIFY_SDK/lib/libratify_c.so" ] || [ -f "$RATIFY_SDK/lib/libratify_c.a" ] || { echo "missing Ratify C library" >&2; exit 1; }
grep -Fq 'Version: 1.0.0-alpha.20' "$RATIFY_SDK/include/ratify.h" || {
    echo "Ratify C SDK must be version 1.0.0-alpha.20" >&2
    exit 1
}
TEST_OUTPUT=${TMPDIR:-/tmp}/ratify-edge-gate.$$
cleanup() {
    rm -f "$TEST_OUTPUT"
    make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean >/dev/null 2>&1 || true
}
trap cleanup EXIT
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean core_test edge-test edge controller
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" test >"$TEST_OUTPUT" 2>&1 || {
    cat "$TEST_OUTPUT"
    exit 1
}
cat "$TEST_OUTPUT"
expected=$(sed -n 's/.*"tests"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$ROOT/ratify-reference.json")
observed=$(sed -n 's/.*ALL ROWS PASSED (\([0-9][0-9]*\)\/.*)/\1/p' "$TEST_OUTPUT")
if [ -z "$expected" ] || [ -z "$observed" ] || [ "$expected" != "$observed" ]; then
    echo "reference gate: declared tests=$expected, observed tests=$observed" >&2
    exit 1
fi
echo "reference gate: core tests passed ($observed/$expected)"
