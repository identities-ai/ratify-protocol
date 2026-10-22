#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Protocol v2. The reference depends on the TypeScript SDK in this tree through
# a file: dependency, so the gate builds that SDK first and proves the
# reference against the code in the checkout.
# TODO(RATIFY_V2_PIN): when @identities-ai/ratify-protocol 2.0.0-beta.1 is
# published, pin it exactly in package.json, drop this build step, and record
# the published-package run in reference-evidence.md.
SDK="../../sdks/typescript"
if [ ! -d "$SDK/node_modules" ]; then
    (cd "$SDK" && npm ci --no-audit --no-fund)
fi
(cd "$SDK" && npm run build --silent)

npm ci --no-fund

# Capture the runner's own tally and hold the declared count to it. The gate is
# the only place that observes how many rows actually ran, so a reference whose
# published count is restated by hand drifts silently the moment a case is
# added. An unparsable tally fails the gate rather than passing quietly.
TEST_OUTPUT=$(mktemp "${TMPDIR:-/tmp}/ratify-copilot-gate.XXXXXX")
trap 'rm -f "$TEST_OUTPUT"' EXIT
npm run check 2>&1 | tee "$TEST_OUTPUT"

expected=$(sed -n 's/.*"tests"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' ratify-reference.json)
# Node's built-in TAP reporter changed its summary from `ℹ pass 9` to
# `# pass 9`. Accept both forms, but still fail closed if the tally is absent.
observed=$(sed -n -e 's/^ℹ pass \([0-9][0-9]*\)$/\1/p' -e 's/^# pass \([0-9][0-9]*\)$/\1/p' "$TEST_OUTPUT")
failed=$(sed -n -e 's/^ℹ fail \([0-9][0-9]*\)$/\1/p' -e 's/^# fail \([0-9][0-9]*\)$/\1/p' "$TEST_OUTPUT")
skipped=$(sed -n -e 's/^ℹ skipped \([0-9][0-9]*\)$/\1/p' -e 's/^# skipped \([0-9][0-9]*\)$/\1/p' "$TEST_OUTPUT")

if [ -z "$expected" ] || [ -z "$observed" ] || [ "$expected" != "$observed" ]; then
    echo "reference gate: declared tests=$expected, observed tests=$observed" >&2
    exit 1
fi
if [ "${failed:-1}" != "0" ] || [ "${skipped:-1}" != "0" ]; then
    echo "reference gate: failures=$failed skips=$skipped, both must be 0" >&2
    exit 1
fi

# The distributed plugin runtime is rebuilt from the v2 SDK. The v1 geo and
# speed constraint evaluator must not be vendored into it.
if grep -qE 'geo_circle|geo_polygon|geo_bbox|max_speed_mps' plugin-runtime/mcp-server.js; then
    echo "reference gate: plugin runtime still bundles v1 geo or speed constraint code" >&2
    exit 1
fi

npm run demo
echo "reference gate: Protocol v2 tests passed ($observed/$expected)"
