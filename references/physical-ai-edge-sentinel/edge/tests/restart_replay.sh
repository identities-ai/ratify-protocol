#!/bin/sh
# Restart-replay evidence row (V1 / FR10).
#
# Captures a valid bundle, kills the edge daemon so its in-memory challenge
# store is lost, restarts it, and replays the bundle inside the freshness
# window. Without the post-boot quarantine this replay would be accepted:
# the consumed-challenge record died with the process.
#
#   ./tests/restart_replay.sh [port]

set -e
PORT=${1:-8099}
TRUST=$(mktemp -d)
CAPTURE=$(mktemp)
CTRL_IN=$(mktemp -u); mkfifo "$CTRL_IN"
cleanup() { kill $EDGE_PID $CTRL_PID 2>/dev/null || true; rm -rf "$TRUST" "$CAPTURE" "$CTRL_IN"; }
trap cleanup EXIT

echo "== starting controller (generates identity, prints anchor) =="
: > "$TRUST/pinned_human_id"
./controller --host 127.0.0.1 --port "$PORT" < "$CTRL_IN" > /tmp/ctrl.out &
CTRL_PID=$!
exec 3> "$CTRL_IN"

ANCHOR=""
for _ in $(seq 1 50); do
    ANCHOR=$(grep -m1 '^ANCHOR ' /tmp/ctrl.out 2>/dev/null | cut -d' ' -f2 || true)
    [ -n "$ANCHOR" ] && break
    sleep 0.1
done
[ -n "$ANCHOR" ] || { echo "FAIL: controller never printed an anchor"; exit 1; }
echo "$ANCHOR" > "$TRUST/pinned_human_id"
echo "anchor provisioned: $ANCHOR"

# The device has no DS3231 fitted and no signed revocation list yet, so both
# degraded modes are enabled explicitly here. On a provisioned device neither
# is set and the daemon refuses to decide, which is the behaviour we want.
echo "note: running with SENTINEL_ALLOW_UNTRUSTED_CLOCK=1 SENTINEL_ALLOW_NO_REVOCATION=1"
export SENTINEL_ALLOW_UNTRUSTED_CLOCK=1
export SENTINEL_ALLOW_NO_REVOCATION=1

start_edge() {
    ./edge --trust "$TRUST" --port "$PORT" > /tmp/edge.out 2>&1 &
    EDGE_PID=$!
    for _ in $(seq 1 50); do
        grep -q "listening" /tmp/edge.out 2>/dev/null && return 0
        sleep 0.1
    done
    echo "FAIL: edge did not start"; cat /tmp/edge.out; exit 1
}

echo "== run 1: capture a valid bundle =="
start_edge
echo "capture $CAPTURE" >&3
for _ in $(seq 1 50); do grep -q "^CAPTURED" /tmp/ctrl.out && break; sleep 0.1; done
grep -q "^CAPTURED" /tmp/ctrl.out || { echo "FAIL: no capture"; exit 1; }
test -s "$CAPTURE" || { echo "FAIL: capture is empty"; exit 1; }

echo "== restart the edge daemon (challenge store is lost) =="
kill $EDGE_PID 2>/dev/null || true
wait $EDGE_PID 2>/dev/null || true
start_edge

echo "== replay the captured bundle against the fresh process =="
BEFORE=$(wc -l < /tmp/ctrl.out)
echo "replay $CAPTURE" >&3
for _ in $(seq 1 100); do
    [ "$(wc -l < /tmp/ctrl.out)" -gt "$BEFORE" ] && break
    sleep 0.1
done
RESULT=$(tail -1 /tmp/ctrl.out)
echo "$RESULT"
echo "quit" >&3

# The quarantine must deny it, and the actuator must not have fired.
echo "$RESULT" | grep -q '"allow":false' || { echo "FAIL: replay was allowed"; exit 1; }
echo "$RESULT" | grep -q 'post_boot_quarantine' || {
    echo "FAIL: denied, but not by the quarantine — reason was:"; echo "$RESULT"; exit 1; }
grep -q "actuator: FIRE" /tmp/edge.out && { echo "FAIL: actuator fired"; exit 1; }

echo
echo "PASS: restart replay denied by post-boot quarantine, 0 actuator calls"
