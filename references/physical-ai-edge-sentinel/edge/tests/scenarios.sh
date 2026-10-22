#!/bin/sh
# Deterministic Protocol v2 scenario matrix for the edge receiver.
#
# Runs the test builds (edge-test, edge-checkpoint-test) with a fixture clock
# and the mock actuator: nothing is written to a serial device or GPIO line.
# Every row asserts the receiver's recorded stage, status, decision, reason,
# and whether the actuator fired, and the run asserts the exact number of
# actuator invocations at the end.
#
#   BIN_DIR=/path/to/binaries WORK_DIR=/path/to/empty/dir ./tests/scenarios.sh
#
# BIN_DIR defaults to the edge directory; WORK_DIR defaults to a new
# temporary directory. PORT defaults to 8197.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${BIN_DIR:-$HERE}
EDGE=$BIN/edge-test
CKPT=$BIN/edge-checkpoint-test
CTL=$BIN/controller
PORT=${PORT:-8197}
WORK=${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/edge-v2.XXXXXX")}
mkdir -p "$WORK"
WORK=$(CDPATH= cd -- "$WORK" && pwd)
cd "$WORK" || exit 1
for b in "$EDGE" "$CKPT" "$CTL"; do
    [ -x "$b" ] || { echo "missing binary: $b (run make all test-bins)" >&2; exit 1; }
done

T0=1800000000
SOCK=ckpt.sock          # relative: Unix socket paths are short
export SENTINEL_TEST_CLOCK_FILE="$WORK/clock"
echo "$T0" > clock
EDGE_PID=""
CKPT_PID=""
EDGE_RUN=0
EXPECTED_FIRES=0
fails=0
rows=0

cleanup() {
    [ -n "$EDGE_PID" ] && kill "$EDGE_PID" 2>/dev/null
    [ -n "$CKPT_PID" ] && kill "$CKPT_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

at() { echo $((T0 + $1)) > clock; }

start_ckpt() {
    "$CKPT" --dir ckpt --socket "$SOCK" >> ckpt.log 2>&1 &
    CKPT_PID=$!
    i=0; while [ $i -lt 50 ] && [ ! -S "$SOCK" ]; do sleep 0.1; i=$((i + 1)); done
}
stop_ckpt() { kill "$CKPT_PID" 2>/dev/null; wait "$CKPT_PID" 2>/dev/null; CKPT_PID=""; rm -f "$SOCK"; }

# start_edge [override]: override=1 sets the test-only quarantine override.
start_edge() {
    EDGE_RUN=$((EDGE_RUN + 1))
    EDGE_LOG=edge.$EDGE_RUN.log
    if [ "${1:-1}" = 1 ]; then
        SENTINEL_TEST_QUARANTINE_OVERRIDE=1 "$EDGE" --state state --trust trust --checkpoint "$SOCK" \
            --port "$PORT" > "$EDGE_LOG" 2>&1 &
    else
        "$EDGE" --state state --trust trust --checkpoint "$SOCK" \
            --port "$PORT" > "$EDGE_LOG" 2>&1 &
    fi
    EDGE_PID=$!
    i=0; while [ $i -lt 100 ] && ! grep -q listening "$EDGE_LOG" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q listening "$EDGE_LOG" || { echo "edge did not start:"; cat "$EDGE_LOG"; exit 1; }
}
stop_edge() { kill "$EDGE_PID" 2>/dev/null; wait "$EDGE_PID" 2>/dev/null; EDGE_PID=""; }

# ctl COMMAND ARGS...: run one controller command against this receiver.
ctl() { cmd=$1; shift; sleep 0.15; "$CTL" "$cmd" ctl --port "$PORT" "$@" 2>>ctl.err | tail -1; }

kv() { printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }

record() {  # record LABEL PASS|FAIL DETAIL
    rows=$((rows + 1))
    [ "$2" = PASS ] || fails=$((fails + 1))
    printf '%-46s %s  %s\n' "$1" "$2" "$3" | tee -a results.txt
}

# decision LABEL RESPONSE STAGE STATUS DECISION REASON ACTUATED
# Each expected value may be "*" (not asserted). The receiver's own decision
# log line is the source of the recorded values, because a preflight
# rejection's class is deliberately not disclosed in the HTTP answer.
decision() {
    serial=$(printf '%s' "$2" | sed -n 's/.*"serial":\([0-9]*\).*/\1/p')
    line=$(grep "^decision serial=$serial " "$EDGE_LOG" 2>/dev/null | tail -1)
    if [ -z "$serial" ] || [ -z "$line" ]; then
        record "$1" FAIL "no decision recorded: $2"
        return
    fi
    ok=PASS
    got=""
    for pair in "stage:$3" "status:$4" "decision:$5" "reason:$6" "actuated:$7"; do
        k=${pair%%:*}; want=${pair#*:}
        v=$(kv "$line" "$k")
        got="$got $k=$v"
        [ "$want" = "*" ] || [ "$v" = "$want" ] || ok=FAIL
    done
    [ "$7" = 1 ] && EXPECTED_FIRES=$((EXPECTED_FIRES + 1))
    record "$1" "$ok" "$got"
}

# refused LABEL RESPONSE REASON: the receiver issued no challenge.
refused() {
    reason=$(grep "^challenge refused" "$EDGE_LOG" | tail -1 | sed -n 's/.*reason=//p')
    if printf '%s' "$2" | grep -q challenge_unavailable && { [ "$3" = "*" ] || [ "$reason" = "$3" ]; }; then
        record "$1" PASS "challenge_unavailable reason=$reason"
    else
        record "$1" FAIL "answer=$2 reason=$reason"
    fi
}

echo "== setup: checkpoint, controller keys, provisioning, receiver genesis =="
"$CKPT" --init --dir ckpt > /dev/null || exit 1
start_ckpt
"$CTL" init ctl > /dev/null || exit 1

# Role separation first, on its own trust directory: the v1 arrangement in
# which the pinned root key also signs status must be refused.
"$CTL" provision ctl trust-v1-style --checkpoint-pub ckpt/checkpoint_pub.json --status-key-from-root > role.out 2>&1
"$EDGE" --init --state state-v1-style --trust trust-v1-style --checkpoint "$SOCK" > role.edge 2>&1
role_rc=$?
if grep -q "PUBLISHER_WITH_ROOT_AS_STATUS_KEY refused" role.out && [ "$role_rc" != 0 ] &&
    grep -q "root key reused as the status key" role.edge && [ ! -e state-v1-style/state ]; then
    record "role separation: root key as status key" PASS \
        "$(sed -n 's/.*refused at "\(.*\)": \(.*\)/\1: \2/p' role.out); receiver refuses the trust directory"
else
    record "role separation: root key as status key" FAIL "$(cat role.out role.edge | tr '\n' ' ')"
fi

"$CTL" provision ctl trust --checkpoint-pub ckpt/checkpoint_pub.json > /dev/null || exit 1
"$EDGE" --init --state state --trust trust --checkpoint "$SOCK" > init.out 2>&1 || { cat init.out; exit 1; }
start_edge 1

"$CTL" delegate ctl cert-main.json --cert-id edge-cert-main > /dev/null
"$CTL" delegate ctl cert-monitor.json --cert-id edge-cert-monitor --scope infrastructure:monitor > /dev/null
"$CTL" delegate ctl cert-short.json --cert-id edge-cert-short --lifetime 300 > /dev/null
"$CTL" delegate ctl cert-revoked.json --cert-id edge-cert-revoked > /dev/null
"$CTL" delegate ctl cert-rogue.json --cert-id edge-cert-rogue --issuer rogue > /dev/null

echo
echo "== matrix =="
at 10
decision "allow: physical:actuate, released, fires" \
    "$(ctl act --cert cert-main.json)" committed released allow authorized 1
at 12
decision "allow without actuation: monitor scope" \
    "$(ctl act --cert cert-monitor.json --scope infrastructure:monitor)" committed released allow authorized 0
at 14
decision "deny: out of scope (monitor cert, actuate)" \
    "$(ctl act --cert cert-monitor.json)" committed released deny scope_denied 0
at 16
decision "deny: out of scope resource (zone)" \
    "$(ctl act --cert cert-main.json --zone greenhouse-a)" committed released deny constraint_denied 0
at 18
decision "deny: signed duration ceiling exceeded" \
    "$(ctl act --cert cert-main.json --ms 30000)" committed released deny constraint_denied 0
at 20
decision "local policy: released allow over local cap" \
    "$(ctl act --cert cert-main.json --ms 1500)" committed released allow authorized 0
if grep "^decision serial=$serial " "$EDGE_LOG" | grep -q "local=policy_duration_denied"; then
    record "local policy: reason recorded" PASS "local=policy_duration_denied"
else
    record "local policy: reason recorded" FAIL "missing policy_duration_denied"
fi
at 22
decision "tamper: altered challenge signature" \
    "$(ctl act --cert cert-main.json --tamper)" preflight invalid_signature '*' '*' 0
at 24
# The challenge was issued for greenhouse-b; the request now names
# greenhouse-a. The receiver's expected context for this request no longer
# matches the issued challenge, which the library refuses before any claim.
decision "tamper: action changed after challenge" \
    "$(ctl act --cert cert-main.json --present-zone greenhouse-a)" preflight configuration_invalid '*' '*' 0
at 26
decision "deny: chain from an untrusted root" \
    "$(ctl act --cert cert-rogue.json)" committed released deny unauthorized 0

at 28
ctl act --cert cert-main.json --invocation captured-1 --capture capture-1.txt > /dev/null
at 29
decision "first presentation of a captured proof" \
    "$(ctl replay --capture capture-1.txt)" committed released allow authorized 1
at 30
decision "replay: same proof again" \
    "$(ctl replay --capture capture-1.txt)" replay terminal_replay '*' '*' 0

at 32
ctl act --cert cert-main.json --invocation late-1 --capture capture-late.txt > /dev/null
at 200
decision "expired: challenge presented after expiry" \
    "$(ctl replay --capture capture-late.txt)" preflight challenge_not_fresh '*' '*' 0

at 210
ctl revoke --cert-id edge-cert-revoked > revoke.out
grep -q '"staged":true' revoke.out || record "stage signed revocation" FAIL "$(cat revoke.out)"
at 212
decision "revoked: certificate revoked by signed push" \
    "$(ctl act --cert cert-revoked.json)" committed released deny delegation_revoked 0

at 400
decision "expired: delegation past expires_at" \
    "$(ctl act --cert cert-short.json)" committed released deny delegation_expired 0

# Restart: the claim store is durable, so a proof presented before the
# restart is still a replay after it, with no quarantine needed.
at 410
ctl act --cert cert-main.json --invocation restart-1 --capture capture-restart.txt > /dev/null
at 411
decision "restart: first presentation before restart" \
    "$(ctl replay --capture capture-restart.txt)" committed released allow authorized 1
stop_edge
start_edge 1
at 412
decision "restart: replay after restart (durable claim)" \
    "$(ctl replay --capture capture-restart.txt)" replay terminal_replay '*' '*' 0

# The post-boot quarantine of the receiver is real when no override is set.
stop_edge
start_edge 0
at 414
decision "quarantine: actuation refused after boot" \
    "$(ctl act --cert cert-main.json --invocation quarantine-1)" device post_boot_quarantine '*' '*' 0
stop_edge
start_edge 1

# A clock that moves backward fails closed before any challenge exists.
at 405
refused "clock regression: no challenge issued" "$(ctl act --cert cert-main.json)" clock_regressed
at 420

# No checkpoint, no anchored change: nothing is issued or released.
stop_ckpt
refused "checkpoint unavailable: no challenge issued" "$(ctl act --cert cert-main.json)" claim_store_unavailable
start_ckpt
at 422
decision "checkpoint back: allow resumes" \
    "$(ctl act --cert cert-main.json --invocation after-ckpt)" committed released allow authorized 1

# Rollback: restore an earlier copy of the receiver's state. Its digest no
# longer matches the anchored one, so the receiver stays recovering until the
# anchored state is back.
stop_edge
rm -rf state.snapshot && cp -Rp state state.snapshot
start_edge 1
at 424
ctl act --cert cert-main.json --invocation rollback-1 --capture capture-rollback.txt > /dev/null
at 425
decision "before rollback: fresh proof allowed" \
    "$(ctl replay --capture capture-rollback.txt)" committed released allow authorized 1
stop_edge
rm -rf state.latest && cp -Rp state state.latest
rm -rf state && cp -Rp state.snapshot state
start_edge 1
health=$(ctl health)
if printf '%s' "$health" | grep -q '"health":"recovering"' && grep -q "RECOVERING: state digest differs" "$EDGE_LOG"; then
    record "rollback: restored backup detected" PASS "health=recovering (digest differs from anchor)"
else
    record "rollback: restored backup detected" FAIL "health=$health"
fi
at 426
decision "rollback: replay into rolled-back state refused" \
    "$(ctl replay --capture capture-rollback.txt)" device device_recovering '*' '*' 0
refused "rollback: no challenge while recovering" "$(ctl act --cert cert-main.json)" device_recovering
stop_edge
rm -rf state && cp -Rp state.latest state
start_edge 1
health=$(ctl health)
printf '%s' "$health" | grep -q '"health":"ready"' && record "rollback: anchored state resumes" PASS "health=ready" ||
    record "rollback: anchored state resumes" FAIL "health=$health"
at 428
decision "rollback: replay after resume is still a replay" \
    "$(ctl replay --capture capture-rollback.txt)" replay terminal_replay '*' '*' 0

stop_edge
fires=$(cat edge.*.log | grep -c "actuator: FIRE")
if [ "$fires" = "$EXPECTED_FIRES" ]; then
    record "actuator invocations across all runs" PASS "$fires (expected $EXPECTED_FIRES)"
else
    record "actuator invocations across all runs" FAIL "$fires (expected $EXPECTED_FIRES)"
fi
serial_writes=$(cat edge.*.log | grep -c "actuator: FIRE .*(serial" || true)
[ "$serial_writes" = 0 ] && record "no serial or GPIO output (mock actuator)" PASS "0 hardware writes" ||
    record "no serial or GPIO output (mock actuator)" FAIL "$serial_writes"

echo
if [ "$fails" = 0 ]; then
    echo "ALL ROWS PASSED ($rows/$rows)"
else
    echo "FAILED $fails of $rows rows"
    exit 1
fi
