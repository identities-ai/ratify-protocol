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
(cd sdks/typescript && npm ci --no-audit --no-fund && npx tsc --noEmit && npm run test:conformance)

echo "==> Python SDK"
(cd sdks/python && python -m pip install -e '.[dev]' && python -m pytest -q)

echo "==> Rust SDK"
(cd sdks/rust && cargo build --all-targets && cargo test)

echo "==> Release sync check"
"$ROOT/scripts/check-release-sync.sh"

echo "test-all: ok"
