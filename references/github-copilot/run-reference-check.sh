#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
npm ci

# Capture the runner's own tally and hold the declared count to it. The gate is
# the only place that observes how many rows actually ran, so a reference whose
# published count is restated by hand drifts silently the moment a case is
# added. An unparsable tally fails the gate rather than passing quietly.
TEST_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/ratify-copilot-gate.XXXXXX")
trap 'rm -f "$TEST_OUTPUT"' EXIT
npm run check 2>&1 | tee "$TEST_OUTPUT"

expected=$(sed -n 's/.*"tests"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' ratify-reference.json)
observed=$(sed -n 's/^ℹ pass \([0-9][0-9]*\)$/\1/p' "$TEST_OUTPUT")
failed=$(sed -n 's/^ℹ fail \([0-9][0-9]*\)$/\1/p' "$TEST_OUTPUT")
skipped=$(sed -n 's/^ℹ skipped \([0-9][0-9]*\)$/\1/p' "$TEST_OUTPUT")

if [ -z "$expected" ] || [ -z "$observed" ] || [ "$expected" != "$observed" ]; then
    echo "reference gate: declared tests=$expected, observed tests=$observed" >&2
    exit 1
fi
if [ "${failed:-1}" != "0" ] || [ "${skipped:-1}" != "0" ]; then
    echo "reference gate: failures=$failed skips=$skipped, both must be 0" >&2
    exit 1
fi

npm run demo
echo "reference gate: core tests passed ($observed/$expected)"
