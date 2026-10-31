#!/usr/bin/env bash
# Runs every Python v2 example against this source tree and compares its
# output with examples/v2/expected/<program>.txt. Every SDK must print the
# same text.
#
# With RATIFY_V2_PYTHON set to an interpreter that already has
# ratify-protocol-native-v2 and ratify-protocol (with its protocol-v2 extra)
# installed from this tree (as the CI python-v2 job does), that interpreter is
# used as is. Otherwise a temporary virtual environment is created, the native
# extension is built with maturin and both packages are installed from this
# tree. That needs
# Python 3.10+ and a Rust toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXPECTED="$ROOT/examples/v2/expected"

if [[ -n "${RATIFY_V2_PYTHON:-}" ]]; then
  PY="$RATIFY_V2_PYTHON"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  "${PYTHON:-python3}" -m venv "$WORK/venv"
  PY="$WORK/venv/bin/python"
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install --quiet 'maturin>=1.7,<2'
  (cd "$ROOT/sdks/python-native-v2" && "$WORK/venv/bin/maturin" build --release --quiet --out "$WORK/dist")
  "$PY" -m pip install --quiet "$WORK"/dist/*.whl
  "$PY" -m pip install --quiet "$ROOT/sdks/python[protocol-v2]"
fi

cd "$ROOT"
status=0
for program in quickstart signed_status custom_scope external_signer; do
  if diff -u "$EXPECTED/$program.txt" <("$PY" "examples/v2/python/$program.py"); then
    echo "ok   python $program"
  else
    echo "FAIL python $program"
    status=1
  fi
done
exit "$status"
