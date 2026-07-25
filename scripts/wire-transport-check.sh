#!/usr/bin/env bash
# Direct TypeScript <-> Python wire-transport check.
#
# The per-SDK wire tests prove each codec round-trips the Go-generated
# fixtures byte-identically, which implies TS/Python compatibility
# transitively through the canonical JSON. This script proves it directly:
# every ProofBundle and SessionToken in testvectors/v1 is encoded by one
# SDK, then decoded and re-encoded by the other, and the bytes must match —
# in both directions.
#
# Requires the toolchains test-all.sh already sets up: node with the
# TypeScript SDK's dev dependencies installed (npm ci in sdks/typescript)
# and a python that can import ratify_protocol (pip install -e sdks/python).
# Override the interpreter with PYTHON=... if needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export PYTHONPATH="$ROOT/sdks/python/src${PYTHONPATH:+:$PYTHONPATH}"

# Python side. Modes mirror sdks/typescript/scripts/wire-transport-check.ts:
#   encode <out.json> <fixture_dir> — encode the fixture corpus
#   check  <in.json>  <fixture_dir> — decode + re-encode + byte-compare
py_transport() {
  "$PYTHON" - "$@" <<'PY'
import json
import sys
from pathlib import Path

from ratify_protocol import (
    decode_proof_bundle,
    decode_session_token,
    encode_proof_bundle,
    encode_session_token,
)

mode, path, fixture_dir = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])


def assert_corpus_size(bundles: int, tokens: int) -> None:
    if bundles < 40 or tokens < 5:
        sys.exit(
            f"wire-transport-check: corpus too small ({bundles} bundles, "
            f"{tokens} tokens) - fixture walk broken?"
        )


def collect() -> dict:
    bundles, tokens = [], []

    def add_bundle(name: str, raw: dict) -> None:
        bundles.append({
            "name": name,
            "encoded": encode_proof_bundle(decode_proof_bundle(json.dumps(raw))),
        })

    for p in sorted(fixture_dir.glob("*.json")):
        fx = json.loads(p.read_text())
        if p.name == "cross_sdk_vectors.json":
            for v in fx["vectors"]:
                if v["kind"] == "bundle_hash":
                    add_bundle(f"{p.name}:{v['name']}", v["input"]["bundle"])
            continue
        if fx.get("bundle"):
            add_bundle(p.name, fx["bundle"])
        if fx.get("session_token"):
            tokens.append({
                "name": p.name,
                "encoded": encode_session_token(
                    decode_session_token(json.dumps(fx["session_token"]["token"]))
                ),
            })
        receipt = fx.get("transaction_receipt") or {}
        for i, party in enumerate(receipt.get("parties") or []):
            add_bundle(f"{p.name}:party[{i}]", party["proof_bundle"])
    assert_corpus_size(len(bundles), len(tokens))
    return {"bundles": bundles, "tokens": tokens}


if mode == "encode":
    doc = collect()
    path.write_text(json.dumps(doc))
    print(f"py-encode: {len(doc['bundles'])} bundles, {len(doc['tokens'])} tokens")
elif mode == "check":
    doc = json.loads(path.read_text())
    assert_corpus_size(len(doc["bundles"]), len(doc["tokens"]))
    drifted = []
    for e in doc["bundles"]:
        if encode_proof_bundle(decode_proof_bundle(e["encoded"])) != e["encoded"]:
            drifted.append(f"bundle {e['name']}")
    for e in doc["tokens"]:
        if encode_session_token(decode_session_token(e["encoded"])) != e["encoded"]:
            drifted.append(f"token {e['name']}")
    if drifted:
        for d in drifted:
            print(f"wire-transport drift: {d}", file=sys.stderr)
        sys.exit(1)
    print(
        f"py-check: {len(doc['bundles'])} bundles, "
        f"{len(doc['tokens'])} tokens byte-identical"
    )
else:
    sys.exit(f"wire-transport-check: unknown mode {mode!r}")
PY
}

echo "-- TS encode -> Python decode/re-encode"
(cd "$ROOT/sdks/typescript" && node --import tsx/esm scripts/wire-transport-check.ts encode "$TMP/ts-encoded.json")
py_transport check "$TMP/ts-encoded.json" "$ROOT/testvectors/v1"

echo "-- Python encode -> TS decode/re-encode"
py_transport encode "$TMP/py-encoded.json" "$ROOT/testvectors/v1"
(cd "$ROOT/sdks/typescript" && node --import tsx/esm scripts/wire-transport-check.ts check "$TMP/py-encoded.json")

echo "wire-transport-check: ok"
