#!/usr/bin/env bash
# Time-boxed fuzzing of every Protocol v2 fuzz target in the Go reference
# package. CI-ready: runs each target in turn and exits nonzero if any target
# fails, or if the run is interrupted.
#
#   scripts/fuzz-v2.sh                 # 30 seconds per target, every target
#   FUZZTIME=5m scripts/fuzz-v2.sh
#   scripts/fuzz-v2.sh 60s             # duration as the first argument
#   scripts/fuzz-v2.sh 60s 'Revocation' # only targets matching a regex
#
# Targets are discovered with `go test -list`, so every new Fuzz*V2* target is
# picked up automatically. Total wall time is roughly the number of targets
# times the duration plus build time; a caller that enforces its own wall-clock
# limit must allow for that or select a subset with the second argument. An
# externally killed run is reported as interrupted, never as a fuzz failure.
#
# A real failure makes go test write the failing input to
# testdata/fuzz/<Target>/; commit it as a regression seed after fixing the bug.
set -euo pipefail

cd "$(dirname "$0")/.."

fuzztime="${1:-${FUZZTIME:-30s}}"
filter="${2:-.}"

if ! listing=$(go test -list '^Fuzz' .); then
	echo "fuzz-v2: could not list fuzz targets (build failure?)" >&2
	exit 1
fi
targets=$(printf '%s\n' "$listing" | grep -E '^Fuzz.*V2' | grep -E -- "$filter" || true)
if [ -z "$targets" ]; then
	echo "fuzz-v2: no v2 fuzz targets match '$filter'" >&2
	exit 1
fi

current=""
trap 'echo "fuzz-v2: interrupted while running ${current:-setup}; this run is incomplete" >&2; exit 130' INT TERM HUP

count=0
for target in $targets; do
	current="$target"
	count=$((count + 1))
	echo "fuzz-v2: [$count] $target for $fuzztime"
	if ! go test . -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime"; then
		echo "fuzz-v2: FAILED: $target (see testdata/fuzz/$target/ for the failing input)" >&2
		exit 1
	fi
done
echo "fuzz-v2: all $count targets passed ($fuzztime each)"
