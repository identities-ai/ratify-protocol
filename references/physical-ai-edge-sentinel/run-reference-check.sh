#!/bin/sh
# Reference gate: build the Protocol v2 receiver, checkpoint, and controller
# against a Ratify C SDK tree at this repository's sdks/c version and run the
# deterministic scenario matrix (fixture clock, mock actuator; no serial device
# or GPIO is touched).
#
#   RATIFY_SDK=/path/to/ratify-c ./run-reference-check.sh
#
# RATIFY_SDK must contain include/ratify.h and lib/libratify_c.a.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${RATIFY_SDK:?Set RATIFY_SDK to a Ratify C SDK tree (include/ratify.h, lib/libratify_c.a)}"
[ -f "$RATIFY_SDK/include/ratify.h" ] || { echo "missing Ratify C header" >&2; exit 1; }
[ -f "$RATIFY_SDK/lib/libratify_c.a" ] || { echo "missing Ratify C static library" >&2; exit 1; }
# The SDK must be the version this reference ships with: the one in sdks/c.
SDK_VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/../../sdks/c/Cargo.toml" | head -n 1)
[ -n "$SDK_VERSION" ] || { echo "cannot read the C SDK version from sdks/c/Cargo.toml" >&2; exit 1; }
grep -Fqx " * Version: $SDK_VERSION" "$RATIFY_SDK/include/ratify.h" || {
    echo "Ratify C SDK must be version $SDK_VERSION" >&2
    exit 1
}
OUTPUT=$(mktemp "${TMPDIR:-/tmp}/ratify-edge-gate.XXXXXX")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratify-edge-work.XXXXXX")
cleanup() {
    rm -rf "$OUTPUT" "$WORK"
    make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean >/dev/null 2>&1 || true
}
trap cleanup EXIT
make -C "$ROOT/edge" RATIFY_SDK="$RATIFY_SDK" clean all test-bins
WORK_DIR="$WORK" "$ROOT/edge/tests/scenarios.sh" >"$OUTPUT" 2>&1 || {
    cat "$OUTPUT"
    exit 1
}
cat "$OUTPUT"
expected=$(sed -n 's/.*"tests"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$ROOT/ratify-reference.json")
observed=$(sed -n 's/.*ALL ROWS PASSED (\([0-9][0-9]*\)\/.*)/\1/p' "$OUTPUT")
if [ -z "$expected" ] || [ -z "$observed" ] || [ "$expected" != "$observed" ]; then
    echo "reference gate: declared tests=$expected, observed tests=$observed" >&2
    exit 1
fi
echo "reference gate: scenario matrix passed ($observed/$expected)"
