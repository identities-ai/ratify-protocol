#!/bin/sh
# End-to-end evidence over the real transport.
#
# Uses edge-test (the only build carrying the quarantine override) so the
# authorized row does not have to wait out 300 seconds. Every row asserts a
# status AND the actuator invocation count reported by the daemon.
set -e
PORT=${1:-8098}
TRUST=$(mktemp -d)
CTRL_IN=$(mktemp -u); mkfifo "$CTRL_IN"
cleanup() { kill $EDGE_PID $CTRL_PID 2>/dev/null || true; rm -rf "$TRUST" "$CTRL_IN"; }
trap cleanup EXIT

# Only the clock override remains: no DS3231 is fitted yet. Revocation state is
# real from checkpoint C, so SENTINEL_ALLOW_NO_REVOCATION is deliberately absent.
export SENTINEL_ALLOW_UNTRUSTED_CLOCK=1
unset SENTINEL_ALLOW_NO_REVOCATION
export SENTINEL_TEST_QUARANTINE_OVERRIDE=1
./controller --host 127.0.0.1 --port "$PORT" < "$CTRL_IN" > /tmp/e2e.ctrl &
CTRL_PID=$!
exec 3> "$CTRL_IN"

for _ in $(seq 1 50); do
    ANCHOR=$(grep -m1 '^ANCHOR ' /tmp/e2e.ctrl 2>/dev/null | cut -d' ' -f2 || true)
    [ -n "$ANCHOR" ] && break; sleep 0.1
done
[ -n "$ANCHOR" ] || { echo "FAIL: no anchor"; exit 1; }

# The controller provisions the device: anchor, operator public key, signed
# revocation list, and local policy.
echo "provision $TRUST" >&3
for _ in $(seq 1 50); do grep -q "^PROVISIONED" /tmp/e2e.ctrl && break; sleep 0.1; done
grep -q "^PROVISIONED" /tmp/e2e.ctrl || { echo "FAIL: provisioning"; exit 1; }

./edge-test --trust "$TRUST" --port "$PORT" > /tmp/e2e.edge 2>&1 &
EDGE_PID=$!
for _ in $(seq 1 50); do grep -q listening /tmp/e2e.edge && break; sleep 0.1; done

fails=0
send() {  # send CMD, wait for a new response line, echo it
    before=$(wc -l < /tmp/e2e.ctrl)
    echo "$1" >&3
    for _ in $(seq 1 100); do
        [ "$(wc -l < /tmp/e2e.ctrl)" -gt "$before" ] && break; sleep 0.1
    done
    tail -1 /tmp/e2e.ctrl
}
row() {  # row LABEL RESPONSE WANT_STATUS WANT_ACTUATED
    st=$(echo "$2" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
    ac=$(echo "$2" | sed -n 's/.*"actuated":\([a-z]*\).*/\1/p')
    if [ "$st" = "$3" ] && [ "$ac" = "$4" ]; then r=PASS; else r=FAIL; fails=$((fails+1)); fi
    printf '%-38s %s  status=%-20s actuated=%s\n' "$1" "$r" "$st" "$ac"
}

echo
row "authorized actuate"        "$(send actuate)" authorized_agent true
row "authorized monitor"        "$(send monitor)" authorized_agent false
# A replay needs TWO presentations. `capture` only builds the bundle against a
# freshly issued challenge; it never presents it, so the first replay is a
# legitimate first use and must be allowed. Only the second is a replay.
CAP=$(mktemp)
send "capture $CAP" > /dev/null
row "first presentation of capture"  "$(send "replay $CAP")" authorized_agent true
row "second presentation (replay)"   "$(send "replay $CAP")" invalid false
echo "quit" >&3
rm -f "$CAP"

CALLS=$(grep -c "actuator: FIRE" /tmp/e2e.edge || true)
printf '\ntotal actuator invocations: %s (expected 2)\n' "$CALLS"
[ "$CALLS" = "2" ] || fails=$((fails+1))
[ "$fails" = "0" ] && echo "E2E PASSED" || { echo "E2E FAILED ($fails)"; exit 1; }
