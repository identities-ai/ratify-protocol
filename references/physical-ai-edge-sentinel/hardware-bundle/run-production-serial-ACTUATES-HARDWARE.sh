#!/bin/sh
# PRODUCTION HARDWARE RUN. THIS DRIVES THE ARDUINO OVER USB SERIAL.
#
# Uses the production binaries (bin/edge, bin/edge-checkpoint): DS3231 RTC
# through /dev/rtc0 only, the real 300-second post-boot quarantine, no test
# overrides compiled in. Run one step at a time:
#
#   ./run-production-serial-ACTUATES-HARDWARE.sh prepare
#       Initialize the checkpoint, controller keys, trust, receiver, and
#       certificates under prod-run/. Touches no actuator. Needs the RTC.
#   SERIAL_DEVICE=/dev/serial/by-id/... OWNER_APPROVED_SERIAL=yes \
#       ./run-production-serial-ACTUATES-HARDWARE.sh start
#       Start the checkpoint and the receiver with the serial actuator
#       attached. Starting does not actuate.
#   ./run-production-serial-ACTUATES-HARDWARE.sh health
#   OWNER_APPROVED_CHECKS=yes ./run-production-serial-ACTUATES-HARDWARE.sh checks
#       Waits out the quarantine, then sends requests that must NOT actuate.
#       Stops at the first change in the actuator count.
#   OWNER_APPROVED_ACTUATION=yes ./run-production-serial-ACTUATES-HARDWARE.sh actuate-once
#       ONE 500 ms LED pulse: a captured proof's first presentation, then its
#       replay, which must not actuate. Refuses during the quarantine.
#   OWNER_APPROVED_CHECKS=yes ./run-production-serial-ACTUATES-HARDWARE.sh restart-replay
#       Restart the receiver, wait out its quarantine, replay the proof from
#       actuate-once. Must not actuate.
#   ./run-production-serial-ACTUATES-HARDWARE.sh stop
#
# Every step appends to prod-run/run.log. Keys and proofs stay in prod-run/
# (mode 0700); do not publish them.
set -eu
B=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN="$B/bin"
RUN="${RUN_DIR:-$B/prod-run}"
PORT="${PORT:-8088}"
unset SENTINEL_TEST_CLOCK_FILE SENTINEL_TEST_QUARANTINE_OVERRIDE 2>/dev/null || true

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$RUN/run.log"; }
need() { [ "$(eval echo "\${$1:-}")" = yes ] || { echo "refusing: set $1=yes only after the owner approves this step" >&2; exit 2; }; }
ctl() { c=$1; shift; "$BIN/controller" "$c" "$RUN/ctl" --port "$PORT" "$@"; }
count() { "$BIN/controller" health "$RUN/ctl" --port "$PORT" | sed -n 's/.*"actuator_invocations":\([0-9]*\).*/\1/p'; }
quarantine() {
    q=$("$BIN/controller" health "$RUN/ctl" --port "$PORT" | sed -n 's/.*"quarantine_remaining":\([0-9]*\).*/\1/p')
    [ -n "$q" ] || { log "FAIL receiver not answering on port $PORT"; exit 1; }
    echo "$q"
}
field() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\).*/\1/p"; }

expect() {  # expect LABEL ANSWER FIELD VALUE...: all pairs must match
    label=$1; answer=$2; shift 2
    ok=1
    while [ $# -ge 2 ]; do
        [ "$(field "$answer" "$1")" = "$2" ] || ok=0
        shift 2
    done
    if [ $ok = 1 ]; then log "PASS $label $answer"; else log "FAIL $label $answer"; return 1; fi
}

unchanged() {  # stop if the actuator count moved
    now=$(count)
    if [ "$now" != "$1" ]; then log "STOP: actuator count changed from $1 to $now"; exit 1; fi
}

case "${1:-help}" in
prepare)
    [ -e "$RUN" ] && { echo "$RUN exists; move it aside first" >&2; exit 1; }
    mkdir -p "$RUN" && chmod 700 "$RUN"
    cd "$RUN"
    log "prepare: $(uname -srm); binaries $(cd "$B" && sha256sum -c SHA256SUMS --quiet 2>&1 && echo verified)"
    [ -r /dev/rtc0 ] || { log "FAIL /dev/rtc0 is not readable by $(id -un)"; exit 1; }
    "$BIN/edge-checkpoint" --init --dir "$RUN/ckpt" | tee -a "$RUN/run.log"
    "$BIN/controller" init "$RUN/ctl" > "$RUN/ctl.ids"
    "$BIN/controller" provision "$RUN/ctl" "$RUN/trust" --checkpoint-pub "$RUN/ckpt/checkpoint_pub.json" | tee -a "$RUN/run.log"
    log "receiver init needs the checkpoint running"
    "$BIN/edge-checkpoint" --dir "$RUN/ckpt" --socket ckpt.sock >> "$RUN/checkpoint.log" 2>&1 &
    echo $! > "$RUN/checkpoint.pid"
    sleep 1
    "$BIN/edge" --init --state "$RUN/state" --trust "$RUN/trust" --checkpoint ckpt.sock 2>&1 | tee -a "$RUN/run.log"
    "$BIN/controller" delegate "$RUN/ctl" "$RUN/cert-main.json" --cert-id hw-cert-main | tee -a "$RUN/run.log"
    "$BIN/controller" delegate "$RUN/ctl" "$RUN/cert-monitor.json" --cert-id hw-cert-monitor --scope infrastructure:monitor | tee -a "$RUN/run.log"
    "$BIN/controller" delegate "$RUN/ctl" "$RUN/cert-rogue.json" --cert-id hw-cert-rogue --issuer rogue | tee -a "$RUN/run.log"
    log "prepared; the checkpoint is running (pid $(cat "$RUN/checkpoint.pid")); no actuator was opened"
    ;;
start)
    need OWNER_APPROVED_SERIAL
    cd "$RUN"
    : "${SERIAL_DEVICE:?set SERIAL_DEVICE to the Arduino serial device}"
    if ! kill -0 "$(cat "$RUN/checkpoint.pid" 2>/dev/null)" 2>/dev/null; then
        "$BIN/edge-checkpoint" --dir "$RUN/ckpt" --socket ckpt.sock >> "$RUN/checkpoint.log" 2>&1 &
        echo $! > "$RUN/checkpoint.pid"
        sleep 1
    fi
    "$BIN/edge" --state "$RUN/state" --trust "$RUN/trust" --checkpoint ckpt.sock --port "$PORT" \
        --serial "$SERIAL_DEVICE" --baud 115200 >> "$RUN/edge.log" 2>&1 &
    echo $! > "$RUN/edge.pid"
    sleep 2
    log "started receiver pid $(cat "$RUN/edge.pid") on 127.0.0.1:$PORT with serial actuator; health $("$BIN/controller" health "$RUN/ctl" --port "$PORT")"
    ;;
health)
    "$BIN/controller" health "$RUN/ctl" --port "$PORT"
    ;;
checks)
    need OWNER_APPROVED_CHECKS
    while [ "$(quarantine)" != 0 ]; do log "checks: waiting, quarantine $(quarantine) s remaining"; sleep 30; done
    c0=$(count); log "checks: actuator count before $c0"
    expect "monitor allowed, not actuated" "$(ctl act --cert "$RUN/cert-monitor.json" --scope infrastructure:monitor --invocation hw-mon)" decision allow actuated false clock_trusted true test_quarantine_override false; unchanged "$c0"
    sleep 1; expect "zone outside delegation" "$(ctl act --cert "$RUN/cert-main.json" --zone greenhouse-a --invocation hw-zone)" decision deny reason constraint_denied actuated false; unchanged "$c0"
    sleep 1; expect "signed duration ceiling" "$(ctl act --cert "$RUN/cert-main.json" --ms 30000 --invocation hw-ceiling)" decision deny reason constraint_denied actuated false; unchanged "$c0"
    sleep 1; expect "untrusted root" "$(ctl act --cert "$RUN/cert-rogue.json" --invocation hw-rogue)" decision deny reason unauthorized actuated false; unchanged "$c0"
    sleep 1; expect "tampered signature" "$(ctl act --cert "$RUN/cert-main.json" --tamper --invocation hw-tamper)" stage preflight actuated false; unchanged "$c0"
    sleep 1; expect "local cap (released allow, refused locally)" "$(ctl act --cert "$RUN/cert-main.json" --ms 1500 --invocation hw-cap)" decision allow local_policy policy_duration_denied actuated false; unchanged "$c0"
    log "checks done; actuator count still $c0"
    ;;
actuate-once)
    need OWNER_APPROVED_ACTUATION
    q=$(quarantine)
    [ "$q" = 0 ] || { log "refusing: quarantine $q s remaining"; exit 1; }
    c0=$(count); log "actuate-once: actuator count before $c0"
    ctl act --cert "$RUN/cert-main.json" --invocation hw-actuate-1 --capture "$RUN/capture-1.txt" > /dev/null
    sleep 1
    expect "first presentation, ONE 500 ms pulse" "$(ctl replay --capture "$RUN/capture-1.txt")" decision allow actuated true clock_trusted true test_quarantine_override false
    c1=$(count); [ "$c1" = $((c0 + 1)) ] || { log "FAIL actuator count $c1, expected $((c0 + 1))"; exit 1; }
    sleep 1
    expect "replay of the same bytes" "$(ctl replay --capture "$RUN/capture-1.txt")" stage replay actuated false
    unchanged "$c1"
    log "actuate-once done; actuator count $c1; ask the owner whether the LED pulsed once"
    ;;
restart-replay)
    need OWNER_APPROVED_CHECKS
    cd "$RUN"
    [ -f "$RUN/capture-1.txt" ] || { echo "run actuate-once first" >&2; exit 1; }
    : "${SERIAL_DEVICE:?set SERIAL_DEVICE to the Arduino serial device}"
    kill "$(cat "$RUN/edge.pid")" 2>/dev/null || true
    sleep 2
    "$BIN/edge" --state "$RUN/state" --trust "$RUN/trust" --checkpoint ckpt.sock --port "$PORT" \
        --serial "$SERIAL_DEVICE" --baud 115200 >> "$RUN/edge.log" 2>&1 &
    echo $! > "$RUN/edge.pid"
    sleep 2
    c0=$(count); log "restart-replay: restarted, actuator count $c0 (resets with the process)"
    while [ "$(quarantine)" != 0 ]; do sleep 10; done
    # The production quarantine (300 s) is at least the maximum challenge age
    # (at most 300 s in Protocol v2), so after any restart the captured
    # challenge is already stale: preflight rejects it (challenge_not_fresh)
    # before any claim lookup. A deployment whose challenge age outlived the
    # quarantine would instead get terminal_replay from the durable claim
    # store. Either outcome is correct; actuating is never correct.
    ans=$(ctl replay --capture "$RUN/capture-1.txt")
    if [ "$(field "$ans" actuated)" = false ] && { [ "$(field "$ans" stage)" = replay ] || [ "$(field "$ans" stage)" = preflight ]; }; then
        log "PASS replay after restart (stage $(field "$ans" stage)) $ans"
    else
        log "FAIL replay after restart $ans"; exit 1
    fi
    unchanged "$c0"
    ;;
stop)
    kill "$(cat "$RUN/edge.pid" 2>/dev/null)" 2>/dev/null || true
    kill "$(cat "$RUN/checkpoint.pid" 2>/dev/null)" 2>/dev/null || true
    log "stopped; FIRE lines in edge.log: $(grep -c 'actuator: FIRE' "$RUN/edge.log" 2>/dev/null || echo 0)"
    ;;
*)
    sed -n '2,30p' "$0"
    ;;
esac
