#!/usr/bin/env bash
# Build the library, write the testvectors/v2 manifests with
# scripts/test-v2-c-abi.sh (PREPARE_ONLY=1), compile the multi-threaded
# stress program tests/c-stress/stress.c with the system C compiler and
# pthreads against the generated include/ratify.h and the static library,
# and run it: K threads race claims, finalization, cancellation, lease-expiry
# recovery, publication, acknowledgement and release of shared challenges
# through the ratify_v2_* exports with C store callbacks, checking the
# Part B invariants throughout (see the header of stress.c).
#
# Usage: ./scripts/test-v2-c-stress.sh [work-dir]   (default: a fresh mktemp dir)
#
# Environment:
#   CC                C compiler (default cc)
#   SANITIZE=address  build the C program with AddressSanitizer and
#                     UndefinedBehaviorSanitizer
#   SANITIZE=thread   build the C program with ThreadSanitizer. Only the C
#                     side (the store, the harness, the callbacks) is
#                     instrumented: the Rust static library is not built
#                     with TSan, so races inside it are not observed, and
#                     a report whose frames are all in the library is to be
#                     read with that in mind
#   LEAKS=1           on macOS, also run the program under `leaks --atExit`
#   STRESS_THREADS    worker threads (default 8)
#   STRESS_ROUNDS     stop after this many rounds (default 0: no bound)
#   STRESS_SECONDS    stop after this many seconds (default 40)
#   STRESS_OPS        operations per thread per round (default 12)
#   STRESS_SEED       operation-mix seed (default 1)
#   CARGO_TARGET_DIR  honoured when locating the built library

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/ratify-v2-c-stress.XXXXXX")}"
CC="${CC:-cc}"
SANITIZE="${SANITIZE:-}"

PREPARE_ONLY=1 "$SCRIPT_DIR/test-v2-c-abi.sh" "$WORK"

(cd "$SDK_DIR" && cargo build --release --quiet)
LIB="${CARGO_TARGET_DIR:-$SDK_DIR/target}/release/libratify_c.a"

EXTRA=()
case "$(uname -s)" in
    Darwin) EXTRA=(-framework Security -framework CoreFoundation) ;;
    Linux) EXTRA=(-lpthread -ldl -lm) ;;
esac
FLAGS=(-std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -pthread -I"$SDK_DIR/include")
case "$SANITIZE" in
    "") FLAGS+=(-O2) ;;
    address) FLAGS+=(-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined) ;;
    thread) FLAGS+=(-g -O1 -fno-omit-frame-pointer -fsanitize=thread) ;;
    *) echo "SANITIZE must be address or thread" >&2; exit 2 ;;
esac
echo "sanitizers: ${SANITIZE:-none}"
"$CC" "${FLAGS[@]}" "$SDK_DIR/tests/c-stress/stress.c" "$SDK_DIR/tests/c/v2_ordering.c" "$LIB" "${EXTRA[@]}" -o "$WORK/v2_stress"

ARGS=(-t "${STRESS_THREADS:-8}" -r "${STRESS_ROUNDS:-0}" -d "${STRESS_SECONDS:-40}" -o "${STRESS_OPS:-12}"
      -s "${STRESS_SEED:-1}" "$WORK/data")
case "$SANITIZE" in
    # LeakSanitizer is not supported on macOS; use LEAKS=1 there instead.
    address) [ "$(uname -s)" = "Linux" ] && LSAN=":detect_leaks=1" || LSAN=""
             export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1$LSAN}" ;;
    thread) export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}" ;;
esac
if [ "${LEAKS:-0}" = "1" ] && [ "$(uname -s)" = "Darwin" ]; then
    MallocStackLogging=1 leaks --atExit -- "$WORK/v2_stress" "${ARGS[@]}"
else
    "$WORK/v2_stress" "${ARGS[@]}"
fi
