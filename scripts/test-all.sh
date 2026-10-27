#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOCACHE="${GOCACHE:-/tmp/ratify-protocol-go-cache}"
# The v2 Python gates need Python 3.12 or 3.13; set PYTHON to choose one.
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"

echo "==> Go vet"
GOCACHE="$GOCACHE" go vet ./...

echo "==> Go tests"
GOCACHE="$GOCACHE" go test -count=1 -timeout 40m ./...

echo "==> Go tests (race detector)"
GOCACHE="$GOCACHE" go test -race -count=1 -timeout 40m ./...

echo "==> Test-vector determinism"
rm -rf /tmp/ratify-protocol-regenerated
GOCACHE="$GOCACHE" go run ./cmd/ratify-testvectors -out /tmp/ratify-protocol-regenerated
diff -rq testvectors/v1/ /tmp/ratify-protocol-regenerated/

echo "==> TypeScript SDK"
(cd sdks/typescript && npm ci --no-audit --no-fund && npx tsc --noEmit && npm test)

echo "==> Python SDK"
(cd sdks/python && python -m pip install -e '.[dev]' && python -m pytest -q)

echo "==> Python SDK with the native extra required"
# RATIFY_REQUIRE_NATIVE turns the deterministic-keygen skips into failures.
(cd sdks/python-native && python -m pip install 'maturin>=1.7,<2' && maturin build --release --out "$WORK/py-native" && python -m pip install "$WORK"/py-native/*.whl)
(cd sdks/python && RATIFY_REQUIRE_NATIVE=1 python -m pytest -q)

echo "==> Python v2 SDK (native extension required)"
"$PYTHON" -m venv "$WORK/venv-v2"
"$WORK/venv-v2/bin/python" -m pip install -q --upgrade pip 'maturin>=1.7,<2'
(cd sdks/python-native-v2 && "$WORK/venv-v2/bin/maturin" build --release --quiet --out "$WORK/py-native-v2")
"$WORK/venv-v2/bin/python" -m pip install -q --find-links "$WORK/py-native-v2" -e "sdks/python-v2[dev]"
(cd sdks/python-v2 && RATIFY_REQUIRE_NATIVE=1 "$WORK/venv-v2/bin/python" -m pytest -q)
RATIFY_V2_PYTHON="$WORK/venv-v2/bin/python" examples/v2/python/test.sh

echo "==> NVIDIA NOOA delegated-authority reference (Protocol v2 gate)"
# The demo runs on Ratify Protocol v2, so the v1 SDK environment above cannot
# collect it. Its gate builds its own v2 environment, needs Python 3.12 or 3.13
# (set PYTHON), and fails on any skip.
"$ROOT/demos/nvidia-nooa-delegated-authority/reference-check-v2.sh"

echo "==> Wire transport (TS <-> Python)"
"$ROOT/scripts/wire-transport-check.sh"

echo "==> Rust SDK"
(cd sdks/rust && cargo build --all-targets && cargo test)

echo "==> Rust narrative demo (standalone cargo project, not in the SDK workspace)"
(cd demos/rust && RUSTFLAGS="-D warnings" cargo build --locked)

echo "==> C/C++ SDK"
(cd sdks/c && cargo clippy --all-targets -- -D warnings && cargo test)

echo "==> C v2 ABI from C (plain, then AddressSanitizer + UBSan)"
(cd sdks/c && ./scripts/test-v2-c-abi.sh "$WORK/c-abi" && SANITIZE=1 ./scripts/test-v2-c-abi.sh "$WORK/c-abi-san")

echo "==> v2 examples (Go, TypeScript, Rust, C; Python ran above)"
examples/v2/go/test.sh
examples/v2/typescript/test.sh
examples/v2/rust/test.sh
examples/v2/c/test.sh

echo "==> Protocol v2 decoder fuzzing (every Go Fuzz*V2 target)"
"$ROOT/scripts/fuzz-v2.sh"

echo "==> Protocol v2 references"
PYTHON="$PYTHON" RATIFY_REFERENCE_VENV="$WORK/venv-adk" ./references/google-adk/run-reference-check.sh
PYTHON="$PYTHON" RATIFY_REFERENCE_VENV="$WORK/venv-langchain" ./references/langchain/run-reference-check.sh
./references/github-copilot/run-reference-check.sh
(cd sdks/c && cargo build --release)
mkdir -p "$WORK/ratify-c/include" "$WORK/ratify-c/lib"
cp sdks/c/include/ratify.h "$WORK/ratify-c/include/"
cp "${CARGO_TARGET_DIR:-sdks/c/target}/release/libratify_c.a" "$WORK/ratify-c/lib/"
RATIFY_SDK="$WORK/ratify-c" ./references/physical-ai-edge-sentinel/run-reference-check.sh
python3 scripts/check-reference-readmes.py
python3 scripts/check-reference-versions.py

echo "==> Release sync check"
"$ROOT/scripts/check-release-sync.sh"

echo "test-all: ok"
