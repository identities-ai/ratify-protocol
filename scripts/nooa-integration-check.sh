#!/usr/bin/env bash
# The NOOA integration test is allowed to skip in the general suite, because
# NOOA requires Python 3.12/3.13 and most SDK environments have no reason to
# install it. This script is the one place where it MUST run: a contribution
# whose headline claim is "this integrates with NOOA" cannot be allowed to go
# green everywhere by never executing.
#
# RATIFY_REQUIRE_NOOA=1 turns the module's importorskip into a hard failure,
# and the skip count is asserted to be zero afterwards.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="demos/nvidia-nooa-delegated-authority"
NOOA_VERSION="${NOOA_VERSION:-0.0.8}"
EXPECTED_TESTS="${EXPECTED_TESTS:-4}"

cd "$ROOT"

PY="${PYTHON:-python3}"
"$PY" - <<'EOF'
import sys
if not ((3, 12) <= sys.version_info[:2] < (3, 14)):
    sys.exit(
        f"nooa requires Python >=3.12,<3.14; this is {sys.version.split()[0]}.\n"
        "Set PYTHON=/path/to/python3.12 and re-run."
    )
EOF

WORKDIR="$(mktemp -d)"
VENV="$WORKDIR/venv"
LOG="$WORKDIR/pytest.log"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> venv ($("$PY" -V))"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e ./sdks/python
"$VENV/bin/pip" install --quiet pytest "nooa==${NOOA_VERSION}"

echo "==> versions"
"$VENV/bin/python" -c "import nooa, ratify_protocol; \
print('nooa', nooa.__version__, '| ratify_protocol', ratify_protocol.__version__)"

echo "==> NOOA integration tests (skips are failures here)"
RATIFY_REQUIRE_NOOA=1 "$VENV/bin/python" -m pytest "$DEMO/test_nooa_presentation.py" \
    -v -rs --strict-markers -p no:cacheprovider | tee "$LOG"

if grep -qE "^SKIPPED|[0-9]+ skipped" "$LOG"; then
    echo "nooa-integration-check: FAILED, the integration test skipped" >&2
    exit 1
fi

PASSED="$(grep -oE "[0-9]+ passed" "$LOG" | head -1 | cut -d' ' -f1)"
if [ "${PASSED:-0}" -lt "$EXPECTED_TESTS" ]; then
    echo "nooa-integration-check: FAILED, expected >=$EXPECTED_TESTS tests, ran ${PASSED:-0}" >&2
    exit 1
fi

echo "nooa-integration-check: ok ($PASSED tests, nooa==$NOOA_VERSION)"
