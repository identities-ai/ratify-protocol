#!/bin/sh
# Crash-consistency test for the edge receiver.
#
# The test builds carry a crash hook (CRASH_POINT in src/util.h): with
# SENTINEL_CRASH_AT=N the receiver calls _exit() immediately before
# (SENTINEL_CRASH_MODE=before) or after (SENTINEL_CRASH_MODE=after) its N-th
# durable step: a file write and fsync, a rename, a directory fsync, or a
# checkpoint anchor or acknowledgement. For each flow this script first runs
# it once to count those steps, then for every step and both modes it starts
# the checkpoint and the receiver from the same fixture, drives the flow until
# the receiver dies at that step, restarts the receiver on the same state
# directory, drives recovery and a retry, and asserts:
#
#   - the mock actuator fires at most once per claim across the crash and the
#     restart, never for a denied or replayed request, and only for a claim
#     whose durable state holds a released allow;
#   - the restarted receiver is ready, and its state digest is the checkpoint's
#     anchored digest, so it never serves from a state that rolled back past
#     an anchored change or an acknowledged entry;
#   - a claim that was durable (anchored) at the crash keeps its terminal
#     result and release record, and a retry of the same proof never commits
#     again;
#   - a claim left in progress is recovered after its lease expires as
#     evaluation_interrupted, published, and acknowledged;
#   - the checkpoint log is not frozen, has no gap, and holds exactly the
#     receiver's entries in order.
#
# Flows: a = authorized physical:actuate request (challenge, presentation,
# release, actuation); b = denied request (zone outside the delegation);
# c = a captured proof that was released and fired before this receiver run
# is replayed, then a new authorized request is interrupted, and the captured
# proof is replayed again after the restart. A process crash leaves the page
# cache intact, so this test does not model lost unsynced writes (power loss).
#
#   BIN_DIR=/path/to/binaries WORK_DIR=/path/to/empty/dir ./tests/crash.sh
#
# BIN_DIR defaults to the edge directory; WORK_DIR defaults to a new temporary
# directory. PORT defaults to 8297. FLOWS defaults to "a b c"; MODES (default
# "before after") and STEPS (default: every counted step) narrow a run to
# reproduce one case, for example FLOWS=a MODES=after STEPS=40.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${BIN_DIR:-$HERE}
EDGE=$BIN/edge-test
CKPT=$BIN/edge-checkpoint-test
CTL=$BIN/controller
PORT=${PORT:-8297}
FLOWS=${FLOWS:-"a b c"}
WORK=${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/edge-crash.XXXXXX")}
mkdir -p "$WORK"
WORK=$(CDPATH= cd -- "$WORK" && pwd)
cd "$WORK" || exit 1
for b in "$EDGE" "$CKPT" "$CTL"; do
    [ -x "$b" ] || { echo "missing binary: $b (run make all test-bins)" >&2; exit 1; }
done

T0=1800000000
SOCK=ckpt.sock          # relative: Unix socket paths are short
EDGE_PID=""
CKPT_PID=""
fails=0
checks=0
runs=0
promoted=0
interrupted_runs=0

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

# start_edge LOG [CRASH_AT MODE]: the quarantine override is always set; the
# crash hook only when CRASH_AT is given. Returns once the receiver listens or
# has exited (a crash during startup).
start_edge() {
    EDGE_LOG=$1
    if [ $# -ge 3 ]; then
        SENTINEL_CRASH_AT=$2 SENTINEL_CRASH_MODE=$3 SENTINEL_TEST_QUARANTINE_OVERRIDE=1 \
            "$EDGE" --state state --trust trust --checkpoint "$SOCK" --port "$PORT" > "$EDGE_LOG" 2>&1 &
    else
        SENTINEL_TEST_QUARANTINE_OVERRIDE=1 \
            "$EDGE" --state state --trust trust --checkpoint "$SOCK" --port "$PORT" > "$EDGE_LOG" 2>&1 &
    fi
    EDGE_PID=$!
    i=0
    while [ $i -lt 100 ] && ! grep -q listening "$EDGE_LOG" 2>/dev/null && kill -0 "$EDGE_PID" 2>/dev/null; do
        sleep 0.05; i=$((i + 1))
    done
}
stop_edge() { kill "$EDGE_PID" 2>/dev/null; wait "$EDGE_PID" 2>/dev/null; EDGE_PID=""; }
# Wait for a receiver that is due to crash; kill it if it is still running.
reap_edge() {
    i=0; while [ $i -lt 40 ] && kill -0 "$EDGE_PID" 2>/dev/null; do sleep 0.05; i=$((i + 1)); done
    stop_edge
}

# Presentations are rate limited per receiver process (100 ms).
ctl() { cmd=$1; shift; [ "$cmd" = replay ] && sleep 0.15; "$CTL" "$cmd" ctl --port "$PORT" "$@" 2>>ctl.err | tail -1; }

kv() { printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }

# The receiver's decision log line for a controller answer, or "none".
decision_line() {
    serial=$(printf '%s' "$1" | sed -n 's/.*"serial":\([0-9]*\).*/\1/p')
    line=""
    [ -n "$serial" ] && line=$(grep "^decision serial=$serial " "$EDGE_LOG" 2>/dev/null | tail -1)
    printf '%s\n' "${line:-none}"
}

RUN=""
check() {  # check LABEL PASS|FAIL DETAIL
    checks=$((checks + 1))
    if [ "$2" = PASS ]; then
        [ -n "${VERBOSE:-}" ] && printf '%-12s %-44s PASS  %s\n' "$RUN" "$1" "$3"
    else
        fails=$((fails + 1))
        printf '%-12s %-44s FAIL  %s\n' "$RUN" "$1" "$3" | tee -a "$WORK/failures.txt"
    fi
    return 0
}

cat > "$WORK/crash_state.py" <<'PY'
# Reads the receiver's state directory and the checkpoint's state file.
#   claims STATE CKPT  -> one line per claim in the anchored state:
#                         id terminal result_sha release interrupted allow
#   anchored STATE CKPT -> which file holds the anchored digest: state,
#                         state.next, or none
#   check STATE CKPT   -> OK, or the first violated invariant
import base64, hashlib, os, sys

LABEL = b"ratify-edge-sentinel/primary-state/v1"

def digest(path):
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    return hashlib.sha384(LABEL + b"\x00" + data).hexdigest()

def checkpoint(ckpt):
    out = {"acks": [], "frozen": None, "anchored": None}
    for line in open(os.path.join(ckpt, "checkpoint.state")):
        f = line.split()
        if f and f[0] == "anchored":
            out["anchored"] = f[1]
        elif f and f[0] == "frozen":
            out["frozen"] = int(f[1])
        elif f and f[0] == "ack":
            out["acks"].append((int(f[1]), f[2], f[3]))
    return out

def anchored_file(state, ck):
    for name in ("state", "state.next"):
        if digest(os.path.join(state, name)) == ck["anchored"]:
            return name
    return None

def parse(path):
    claims, entries = {}, []
    for line in open(path):
        f = line.split()
        if f and f[0] == "claim":
            body = base64.b64decode(f[14]) if f[14] != "-" else b""
            claims[f[1]] = {
                "terminal": f[6],
                "result": hashlib.sha256((f[13] + " " + f[14]).encode()).hexdigest()[:16],
                "release": "-" if f[15] == "-" else "%s/%s/%s" % (f[15][:12], f[16], f[17] if len(f) > 17 else "1"),
                "interrupted": int(b'"decision_reason":"evaluation_interrupted"' in body),
                "allow": int(b'"decision":"allow"' in body),
            }
        elif f and f[0] == "entry":
            entries.append((int(f[1]), f[2], f[3]))
    return claims, entries

cmd, state, ckpt = sys.argv[1:4]
ck = checkpoint(ckpt)
name = anchored_file(state, ck)
if cmd == "anchored":
    print(name or "none")
elif cmd == "claims":
    claims, _ = parse(os.path.join(state, name or "state"))
    for cid in sorted(claims):
        c = claims[cid]
        print(cid, c["terminal"], c["result"], c["release"], c["interrupted"], c["allow"])
elif cmd == "check":
    def bad(why):
        print("BAD " + why)
        sys.exit(0)
    if ck["frozen"] != 0:
        bad("checkpoint frozen")
    if name != "state":
        bad("state digest is not the anchored digest (anchored file: %s)" % name)
    claims, entries = parse(os.path.join(state, "state"))
    acks = ck["acks"]
    if [a[0] for a in acks] != list(range(1, len(acks) + 1)):
        bad("checkpoint acknowledgements have a gap")
    if [e[0] for e in entries] != list(range(1, len(entries) + 1)):
        bad("receiver entries have a gap")
    if len(acks) != len(entries):
        bad("checkpoint holds %d entries, receiver %d" % (len(acks), len(entries)))
    for a, e in zip(acks, entries):
        if a[1] != e[2]:
            bad("entry %d differs between receiver and checkpoint" % a[0])
        if not os.path.exists(os.path.join(state, "receipts", "%d.json" % a[0])):
            bad("receipt %d missing" % a[0])
    for cid, c in claims.items():
        if c["terminal"] != "1":
            bad("claim %s stranded in progress" % cid[:16])
    print("OK entries=%d" % len(entries))
PY
state_py() { python3 "$WORK/crash_state.py" "$1" state ckpt; }

echo "== fixture: checkpoint, controller keys, provisioning, receiver genesis =="
mkdir -p base && cd base || exit 1
export SENTINEL_TEST_CLOCK_FILE="$WORK/base/clock"
at 0
"$CKPT" --init --dir ckpt > /dev/null || exit 1
start_ckpt
"$CTL" init ctl > /dev/null || exit 1
"$CTL" provision ctl trust --checkpoint-pub ckpt/checkpoint_pub.json > /dev/null || exit 1
"$EDGE" --init --state state --trust trust --checkpoint "$SOCK" > init.out 2>&1 || { cat init.out; exit 1; }
"$CTL" delegate ctl cert-main.json --cert-id edge-cert-main > /dev/null || exit 1
stop_ckpt
cd "$WORK" || exit 1

# Flow c starts from a receiver that has already released, and fired for, a
# captured proof.
rm -rf base-c && cp -Rp base base-c && cd base-c || exit 1
export SENTINEL_TEST_CLOCK_FILE="$WORK/base-c/clock"
start_ckpt
start_edge edge.base.log
at 10
ctl act --cert cert-main.json --invocation captured-c --capture cap-c.txt > /dev/null
at 11
answer=$(ctl replay --capture cap-c.txt)
stop_edge
stop_ckpt
case $(decision_line "$answer") in
*"stage=committed "*"release=released decision=allow "*"actuated=1 "*) ;;
*) echo "flow c fixture: first presentation was not released and fired: $answer" >&2; exit 1 ;;
esac
cd "$WORK" || exit 1

# flow_crash FLOW: the part of a flow that runs on the receiver due to crash.
flow_crash() {
    case $1 in
    a)
        at 10; ctl act --cert cert-main.json --invocation crash-a --capture cap.txt > /dev/null
        at 11; ctl replay --capture cap.txt > answer.crash ;;
    b)
        at 10; ctl act --cert cert-main.json --zone greenhouse-a --invocation crash-b --capture cap.txt > /dev/null
        at 11; ctl replay --capture cap.txt > answer.crash ;;
    c)
        at 20; ctl replay --capture cap-c.txt > answer.replay
        at 21; ctl act --cert cert-main.json --invocation crash-c --capture cap.txt > /dev/null
        at 22; ctl replay --capture cap.txt > answer.crash ;;
    esac
}

# The receiver starts just before its flow; flow c's fixture ran until 11.
start_clock() { if [ "$1" = c ]; then at 19; else at 9; fi; }

# fires LOG...: the claim IDs the mock actuator fired for.
fires() { cat "$@" 2>/dev/null | sed -n 's/^actuator: FIRE .*(mock, \(.*\))$/\1/p'; }

# run_one FLOW N MODE: one crash run in its own copy of the fixture.
run_one() {
    flow=$1; n=$2; mode=$3
    RUN="$flow/$mode/$n"
    runs=$((runs + 1))
    dir=$WORK/runs/$flow-$mode-$n
    rm -rf "$dir"
    if [ "$flow" = c ]; then cp -Rp "$WORK/base-c" "$dir"; else cp -Rp "$WORK/base" "$dir"; fi
    cd "$dir" || exit 1
    export SENTINEL_TEST_CLOCK_FILE="$dir/clock"
    rm -f ckpt.log edge.1.log edge.2.log ctl.err answer.*
    state_py claims | awk '{print $1}' > claims.base
    start_ckpt

    # 1. Drive the flow on a receiver that dies at step n.
    start_clock "$flow"
    start_edge edge.1.log "$n" "$mode"
    flow_crash "$flow"
    reap_edge
    crash=$(grep "^CRASH at " edge.1.log | head -1)
    case $crash in
    "CRASH at $n $mode "*) check "crash injected" PASS "$crash" ;;
    *) check "crash injected" FAIL "no crash at step $n ($mode)"; cd "$WORK"; stop_ckpt; return ;;
    esac
    if [ "$flow" = c ]; then
        case $(decision_line "$(cat answer.replay)") in
        none | *"stage=replay status=terminal_replay "*"actuated=0 "*) check "replay before crash refused" PASS "" ;;
        *) check "replay before crash refused" FAIL "$(decision_line "$(cat answer.replay)")" ;;
        esac
    fi
    # What the crash left durable: the claims in the anchored state.
    anchored_at_crash=$(state_py anchored)
    state_py claims > claims.crash

    # 2. Restart on the same state directory.
    at 23
    start_edge edge.2.log
    health=$(ctl health)
    if printf '%s' "$health" | grep -q '"health":"ready"'; then
        check "restart: receiver ready" PASS "anchored at crash: $anchored_at_crash"
    else
        why=$(grep "RECOVERING:" edge.2.log | head -1)
        check "restart: receiver ready" FAIL "health=$health anchored at crash: $anchored_at_crash; $why"
        refusal=$(ctl act --cert cert-main.json --invocation while-recovering)
        if printf '%s' "$refusal" | grep -q challenge_unavailable && grep -q "reason=device_recovering" edge.2.log; then
            check "recovering receiver refuses" PASS "device_recovering"
        else
            check "recovering receiver refuses" FAIL "$refusal"
        fi
        stop_edge; stop_ckpt; cd "$WORK"; return
    fi
    v=$(state_py anchored)
    [ "$v" = state ] && check "restart: state is the anchored state" PASS "" ||
        check "restart: state is the anchored state" FAIL "anchored file: $v"

    # 3. Flow c: the proof released before the crash is still a replay.
    #    Then retry the interrupted proof while any claim lease is live.
    at 24
    if [ "$flow" = c ]; then
        ctl replay --capture cap-c.txt > answer.replay2
        case $(decision_line "$(cat answer.replay2)") in
        *"stage=replay status=terminal_replay "*"actuated=0 "*) check "replay after restart refused" PASS "" ;;
        *) check "replay after restart refused" FAIL "$(decision_line "$(cat answer.replay2)")" ;;
        esac
    fi
    if [ -f cap.txt ]; then
        retry=$(decision_line "$(ctl replay --capture cap.txt)")
    else
        # The crash came before the challenge reached the agent: the agent
        # asks again, which is a new request.
        ctl act --cert cert-main.json --zone "$([ "$flow" = b ] && echo greenhouse-a || echo greenhouse-b)" \
            --invocation "retry-$flow" --capture cap.txt > /dev/null
        at 25
        retry=$(decision_line "$(ctl replay --capture cap.txt)")
    fi
    pre_terminal=$(awk '$2 == 1' claims.crash | wc -l | tr -d ' ')
    pre_progress=$(awk '$2 == 0' claims.crash | wc -l | tr -d ' ')
    [ "$anchored_at_crash" = state.next ] && promoted=$((promoted + 1))
    [ "$pre_progress" -gt 0 ] && interrupted_runs=$((interrupted_runs + 1))
    case $retry in
    *"stage=committed "*)
        # A new commit is only correct when no claim for this proof was
        # durable at the crash.
        new_claims=$(state_py claims | awk '{print $1}' | while read -r cid; do
            grep -q "^$cid " claims.crash || echo "$cid"; done | wc -l | tr -d ' ')
        flow_claims=$(awk '{print $1}' claims.crash | grep -v -x -F -f claims.base | wc -l | tr -d ' ')
        if [ "$flow_claims" = 0 ] && [ "$new_claims" = 1 ]; then
            check "retry: committed only as a first claim" PASS "no claim was durable at the crash"
        else
            check "retry: committed only as a first claim" FAIL "claims at crash: $(tr '\n' ';' < claims.crash) retry: $retry"
        fi ;;
    *"stage=replay status=terminal_replay "*"actuated=0 "* | *"stage=replay status=in_progress "*"actuated=0 "* | \
    *"stage=preflight "*"actuated=0 "*)
        check "retry: replay, no new commit" PASS "$(kv "$retry" stage) $(kv "$retry" status)" ;;
    *)
        check "retry: replay, no new commit" FAIL "$retry" ;;
    esac
    case $flow:$retry in
    b:*"actuated=1 "*) check "denied request never fires" FAIL "$retry" ;;
    esac

    # 4. Past every lease: an interrupted claim is recovered, and the proof
    #    is still a replay.
    at 70
    ctl replay --capture cap.txt > answer.late
    late=$(decision_line "$(cat answer.late)")
    case $late in
    *"stage=replay status=terminal_replay "*"actuated=0 "* | *"stage=preflight "*"actuated=0 "*)
        check "after lease expiry: replay" PASS "$(kv "$late" stage) $(kv "$late" status)" ;;
    *) check "after lease expiry: replay" FAIL "$late" ;;
    esac
    if [ "$pre_progress" -gt 0 ]; then
        interrupted=$(awk '$2 == 0 {print $1}' claims.crash | while read -r cid; do
            state_py claims | awk -v c="$cid" '$1 == c && $2 == 1 && $5 == 1' ; done | wc -l | tr -d ' ')
        if [ "$interrupted" = "$pre_progress" ] && grep -q "recovered interrupted claim" edge.2.log; then
            check "in-progress claim recovered after lease" PASS "$pre_progress claim(s) sealed evaluation_interrupted"
        else
            check "in-progress claim recovered after lease" FAIL "$(state_py claims | tr '\n' ';')"
        fi
    fi

    # 5. Claims that were terminal at the crash keep their result and release.
    if [ "$pre_terminal" -gt 0 ]; then
        changed=$(awk '$2 == 1' claims.crash | while read -r cid t r rel i a; do
            now=$(state_py claims | awk -v c="$cid" '$1 == c')
            set -- $now
            [ "${2:-}" = 1 ] && [ "${3:-}" = "$r" ] && { [ "$rel" = - ] || [ "${4:-}" = "$rel" ]; } || echo "$cid"
        done | wc -l | tr -d ' ')
        [ "$changed" = 0 ] && check "terminal results kept" PASS "$pre_terminal claim(s)" ||
            check "terminal results kept" FAIL "$changed claim(s) changed"
    fi

    # 6. The receiver still decides: a new authorized request is released.
    at 75
    ctl act --cert cert-main.json --invocation "after-$flow" --capture cap-after.txt > /dev/null
    at 76
    ctl replay --capture cap-after.txt > answer.after
    after=$(decision_line "$(cat answer.after)")
    case $after in
    *"stage=committed "*"release=released decision=allow "*"actuated=1 "*) check "new request after restart" PASS "" ;;
    *) check "new request after restart" FAIL "$after" ;;
    esac
    stop_edge
    stop_ckpt

    # 7. Durable state, the checkpoint log, and the actuator.
    v=$(state_py check)
    [ "${v%% *}" = OK ] && check "anchored state and checkpoint log" PASS "$v" ||
        check "anchored state and checkpoint log" FAIL "$v"
    all=$(fires edge.base.log edge.1.log edge.2.log)
    total=$(printf '%s' "$all" | grep -c . || true)
    distinct=$(printf '%s' "$all" | grep . | sort -u | wc -l | tr -d ' ')
    [ "$total" = "$distinct" ] && check "at most one actuation per claim" PASS "$total fire(s)" ||
        check "at most one actuation per claim" FAIL "$total fires for $distinct claims"
    unreleased=$(printf '%s\n' "$all" | grep . | while read -r cid; do
        state_py claims | awk -v c="$cid" '$1 == c && $2 == 1 && $4 != "-" && $4 ~ /\/1$/ && $6 == 1' | grep -q . || echo "$cid"
    done | wc -l | tr -d ' ')
    [ "$unreleased" = 0 ] && check "fired only for released allows" PASS "" ||
        check "fired only for released allows" FAIL "$unreleased fire(s) without a durable released allow"
    # Expected fires: flow c's fixture fire, the new request after restart,
    # and at most one for the interrupted authorized request.
    case $flow in
    a | c) lo=$([ "$flow" = c ] && echo 2 || echo 1); hi=$((lo + 1)) ;;
    b) lo=1; hi=1 ;;
    esac
    [ "$total" -ge "$lo" ] && [ "$total" -le "$hi" ] && check "actuator count" PASS "$total in [$lo, $hi]" ||
        check "actuator count" FAIL "$total not in [$lo, $hi]"
    serial_writes=$(cat edge.*.log | grep -c "actuator: FIRE .*(serial\|actuator: FIRE .*(gpio" || true)
    [ "$serial_writes" = 0 ] || check "mock actuator only" FAIL "$serial_writes hardware writes"
    cd "$WORK" || exit 1
}

# count_steps FLOW: run the crash phase with the hook counting only.
count_steps() {
    dir=$WORK/runs/$1-count
    rm -rf "$dir"
    if [ "$1" = c ]; then cp -Rp "$WORK/base-c" "$dir"; else cp -Rp "$WORK/base" "$dir"; fi
    cd "$dir" || exit 1
    export SENTINEL_TEST_CLOCK_FILE="$dir/clock"
    start_ckpt
    start_clock "$1"
    start_edge edge.1.log 0 before
    flow_crash "$1"
    stop_edge
    stop_ckpt
    grep -c "^crash-point " edge.1.log
    cd "$WORK" || exit 1
}

echo
echo "== crash runs =="
mkdir -p runs
for flow in $FLOWS; do
    steps=$(count_steps "$flow")
    echo "flow $flow: $steps durable steps"
    sed -n 's/^crash-point //p' "runs/$flow-count/edge.1.log" | tr '\n' ',' | sed 's/,$/\n/' > "runs/$flow-steps.txt"
    before_fails=$fails
    before_runs=$runs
    before_promoted=$promoted
    before_interrupted=$interrupted_runs
    for mode in ${MODES:-before after}; do
        for n in ${STEPS:-$(seq 1 "$steps")}; do
            run_one "$flow" "$n" "$mode"
        done
    done
    echo "flow $flow: $((runs - before_runs)) crash runs, $((fails - before_fails)) failed checks;" \
        "$((promoted - before_promoted)) restarts promoted an anchored state.next," \
        "$((interrupted_runs - before_interrupted)) recovered an interrupted claim after its lease"
done

echo
if [ "$fails" = 0 ]; then
    echo "ALL CRASH CHECKS PASSED ($checks checks in $runs crash runs)"
else
    echo "FAILED $fails of $checks checks in $runs crash runs"
    exit 1
fi
