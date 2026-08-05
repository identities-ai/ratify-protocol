#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOCACHE="${GOCACHE:-/tmp/ratify-protocol-go-cache}"

cd "$ROOT"

echo "==> Go vet"
GOCACHE="$GOCACHE" go vet ./...

echo "==> Go tests"
GOCACHE="$GOCACHE" go test -race -count=1 ./...

echo "==> Test-vector determinism"
rm -rf /tmp/ratify-protocol-regenerated
GOCACHE="$GOCACHE" go run ./cmd/ratify-testvectors -out /tmp/ratify-protocol-regenerated
diff -rq testvectors/v1/ /tmp/ratify-protocol-regenerated/

echo "==> TypeScript SDK"
(cd sdks/typescript && npm ci --no-audit --no-fund && npx tsc --noEmit && npm test)

echo "==> Python SDK"
(cd sdks/python && python -m pip install -e '.[dev]' && python -m pytest -q)

echo "==> NVIDIA NOOA delegated-authority reference (compatible subset)"
# Deliberately the subset, not the authoritative gate. The NOOA and MCP modules
# skip here when their optional dependencies are absent, which is correct for a
# general SDK environment and wrong for a claim about counts. The authoritative,
# skip-proof gate is scripts/nvidia-reference-check.sh, which requires Python
# 3.12 or 3.13 and fails on any skip.
(cd "$ROOT" && python -m pytest demos/nvidia-nooa-delegated-authority -q)

echo "==> Wire transport (TS <-> Python)"
"$ROOT/scripts/wire-transport-check.sh"

echo "==> Rust SDK"
(cd sdks/rust && cargo build --all-targets && cargo test)

echo "==> Rust narrative demo (standalone cargo project, not in the SDK workspace)"
(cd demos/rust && RUSTFLAGS="-D warnings" cargo build)

echo "==> C/C++ SDK"
(cd sdks/c && cargo test --test conformance -- --nocapture && cargo test --test api && cargo test --test advanced && cargo test --test bounds)

echo "==> Release sync check"
"$ROOT/scripts/check-release-sync.sh"

echo "test-all: ok"
