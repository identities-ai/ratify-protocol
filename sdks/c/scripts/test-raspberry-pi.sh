#!/usr/bin/env bash
# Test the Ratify C SDK on a real Raspberry Pi (or any ARM64 Linux host).
#
# Usage:
#   ./scripts/test-raspberry-pi.sh pi@192.168.1.100
#   ./scripts/test-raspberry-pi.sh pi@raspberrypi.local
#
# Prerequisites:
#   - Rust toolchain + cross: cargo install cross
#   - SSH access to the Pi with key authentication
#   - The Pi runs Linux (any distribution)
#
# What this does:
#   1. Cross-compiles the library and test binaries for ARM64
#   2. Copies them to the Pi over SSH
#   3. Runs the conformance + api + advanced test suites on the Pi
#   4. Returns exit code 0 if all tests pass, 1 if any fail

set -euo pipefail

PI="${1:-}"
if [ -z "$PI" ]; then
    echo "Usage: $0 <user@host>"
    echo "Example: $0 pi@raspberrypi.local"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Ratify C SDK — Raspberry Pi (ARM64) test run ==="
echo "Target: $PI"
echo ""

# Step 1: Cross-compile
echo "--- Step 1: Cross-compiling for aarch64-unknown-linux-gnu ---"
cd "$SDK_DIR"
cross test --target aarch64-unknown-linux-gnu --no-run 2>&1 | tail -5

# Find the compiled test binaries
TEST_DIR="$SDK_DIR/target/aarch64-unknown-linux-gnu/debug/deps"
CONFORMANCE=$(ls "$TEST_DIR"/conformance-* 2>/dev/null | grep -v '\.d$' | head -1)
API=$(ls "$TEST_DIR"/api-* 2>/dev/null | grep -v '\.d$' | head -1)
ADVANCED=$(ls "$TEST_DIR"/advanced-* 2>/dev/null | grep -v '\.d$' | head -1)

if [ -z "$CONFORMANCE" ] || [ -z "$API" ] || [ -z "$ADVANCED" ]; then
    echo "ERROR: Could not find compiled test binaries in $TEST_DIR"
    ls "$TEST_DIR" 2>/dev/null | head -20
    exit 1
fi

echo "Found test binaries:"
echo "  conformance: $(basename "$CONFORMANCE")"
echo "  api:         $(basename "$API")"
echo "  advanced:    $(basename "$ADVANCED")"

# Step 2: Copy test vectors and binaries to Pi
echo ""
echo "--- Step 2: Copying to $PI ---"
ssh "$PI" "mkdir -p ~/ratify-test/testvectors/v1"
scp "$CONFORMANCE" "$API" "$ADVANCED" "$PI:~/ratify-test/"
scp -r "$SDK_DIR/../../testvectors/v1/"*.json "$PI:~/ratify-test/testvectors/v1/"
echo "Copied $(ls "$SDK_DIR/../../testvectors/v1/"*.json | wc -l) test vector files."

# Step 3: Run tests on the Pi
echo ""
echo "--- Step 3: Running test suites on $PI ---"

PASS=0
FAIL=0

run_suite() {
    local name="$1"
    local binary="$2"
    echo ""
    echo "  Running $name..."
    # Set CARGO_MANIFEST_DIR so the conformance test can find testvectors
    if ssh "$PI" "cd ~/ratify-test && CARGO_MANIFEST_DIR=~/ratify-test ./$binary 2>&1"; then
        echo "  ✓ $name: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $name: FAILED"
        FAIL=$((FAIL + 1))
    fi
}

run_suite "conformance" "$(basename "$CONFORMANCE")"
run_suite "api"         "$(basename "$API")"
run_suite "advanced"    "$(basename "$ADVANCED")"

# Step 4: Cleanup
ssh "$PI" "rm -rf ~/ratify-test"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
