#!/usr/bin/env bash
# Time-boxed fuzzing of every Protocol v2 decoder fuzz target in the Go
# reference package. CI-ready: exits nonzero on the first failing target.
#
#   scripts/fuzz-v2.sh            # 30 seconds per target
#   FUZZTIME=5m scripts/fuzz-v2.sh
#   scripts/fuzz-v2.sh 60s        # duration as the first argument
#
# New crashers are written to testdata/fuzz/<Target>/ by go test; commit them
# as regression seeds after fixing the bug.
set -euo pipefail

cd "$(dirname "$0")/.."

fuzztime="${1:-${FUZZTIME:-30s}}"

targets=$(go test -list '^Fuzz' . | grep -E '^Fuzz.*V2' || true)
if [ -z "$targets" ]; then
	echo "fuzz-v2: no v2 fuzz targets found" >&2
	exit 1
fi

for target in $targets; do
	echo "fuzz-v2: $target for $fuzztime"
	go test . -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime"
done
echo "fuzz-v2: all targets passed"
