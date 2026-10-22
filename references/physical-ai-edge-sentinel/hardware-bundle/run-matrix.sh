#!/bin/sh
# DETERMINISTIC MATRIX. Mock actuator only: this script never passes --serial
# or --gpio, so nothing is written to the Arduino or any GPIO line. It uses
# the test builds (fixture clock, quarantine override) and its own port 8197.
#
#   ./run-matrix.sh
#
# Results: matrix-<timestamp>/results.txt and matrix-<timestamp>.out
set -u
B=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK="$B/matrix-$STAMP"
mkdir -p "$WORK"
echo "host: $(uname -srm)"
echo "binaries: $(cd "$B" && sha256sum -c SHA256SUMS --quiet 2>&1 && echo verified || echo MISMATCH)"
start=$(date +%s)
BIN_DIR="$B/bin" WORK_DIR="$WORK" PORT=8197 "$B/tests/scenarios.sh" > "$B/matrix-$STAMP.out" 2>&1
rc=$?
cat "$B/matrix-$STAMP.out"
end=$(date +%s)
echo "wall time: $((end - start)) s"
grep -c "actuator: FIRE .*(mock" "$WORK"/edge.*.log 2>/dev/null | awk -F: '{s+=$2} END {print "mock actuator invocations: " s}'
if cat "$WORK"/edge.*.log | grep -q "actuator: FIRE .*(serial\|actuator: FIRE .*(gpio"; then
    echo "UNEXPECTED: a hardware actuator write was logged"
    exit 1
fi
exit $rc
