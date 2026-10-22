#!/usr/bin/env bash
# Builds the C library from sdks/c with the test-only reference stores
# (feature test-reference), compiles every C v2 example, runs it, and
# compares its output with examples/v2/expected/<program>.txt. Every SDK
# must print the same text.
#
# external_signer.c emulates a signing provider with OpenSSL libcrypto,
# which must be 3.5 or later (ML-DSA-65 support). Set OPENSSL_PREFIX when
# pkg-config cannot find it (on macOS: OPENSSL_PREFIX=$(brew --prefix openssl@3)).
#
# Environment: CC (default cc), SANITIZE=1 (AddressSanitizer and
# UndefinedBehaviorSanitizer), CARGO_TARGET_DIR, OPENSSL_PREFIX.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SDK="$ROOT/sdks/c"
EXPECTED="$ROOT/examples/v2/expected"
CC="${CC:-cc}"
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/ratify-c-examples.XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT

# The reference stores are test-only and are never part of a shipped build,
# so the examples build the library in their own target directory.
TARGET="${CARGO_TARGET_DIR:-$SDK/target/examples-test-reference}"
(cd "$SDK" && cargo build --release --quiet --features test-reference --target-dir "$TARGET")
LIB="$TARGET/release/libratify_c.a"

EXTRA=()
case "$(uname -s)" in
  Darwin) EXTRA=(-framework Security -framework CoreFoundation) ;;
  Linux) EXTRA=(-lpthread -ldl -lm) ;;
esac
FLAGS=(-std=c99 -D_POSIX_C_SOURCE=200809L -DRATIFY_V2_TEST_REFERENCE -Wall -Wextra -Werror -I"$SDK/include" -I"$HERE")
if [ "${SANITIZE:-0}" = "1" ]; then
  FLAGS+=(-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined)
fi

if [ -n "${OPENSSL_PREFIX:-}" ]; then
  OPENSSL_CFLAGS=(-I"$OPENSSL_PREFIX/include")
  OPENSSL_LIBS=(-L"$OPENSSL_PREFIX/lib" -lcrypto)
else
  read -r -a OPENSSL_CFLAGS <<<"$(pkg-config --cflags libcrypto)"
  read -r -a OPENSSL_LIBS <<<"$(pkg-config --libs libcrypto)"
fi

status=0
for program in quickstart signed_status custom_scope external_signer; do
  extra_cflags=() extra_libs=()
  if [ "$program" = external_signer ]; then
    extra_cflags=("${OPENSSL_CFLAGS[@]}") extra_libs=("${OPENSSL_LIBS[@]}")
  fi
  "$CC" "${FLAGS[@]}" ${extra_cflags[@]+"${extra_cflags[@]}"} "$HERE/$program.c" "$LIB" \
    ${extra_libs[@]+"${extra_libs[@]}"} "${EXTRA[@]}" -o "$BUILD/$program"
  if diff -u "$EXPECTED/$program.txt" <("$BUILD/$program"); then
    echo "ok   c $program"
  else
    echo "FAIL c $program"
    status=1
  fi
done
exit "$status"
