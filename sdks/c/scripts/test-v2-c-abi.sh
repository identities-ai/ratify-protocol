#!/usr/bin/env bash
# Compile tests/c/v2_abi_smoke.c with the system C compiler against the
# generated include/ratify.h and the built static library, then run it over
# every testvectors/v2 key, positive object, and object negative.
#
# Usage: ./scripts/test-v2-c-abi.sh [work-dir]   (default: a fresh mktemp dir)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORPUS="$(cd "$SDK_DIR/../../testvectors/v2" && pwd)"
WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/ratify-v2-c-abi.XXXXXX")}"
mkdir -p "$WORK/data"

(cd "$SDK_DIR" && cargo build --release --quiet)
LIB="${CARGO_TARGET_DIR:-$SDK_DIR/target}/release/libratify_c.a"

python3 -I - "$CORPUS" "$WORK/data" <<'PY'
import base64, json, pathlib, sys
corpus, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
load = lambda n: json.loads((corpus / n).read_text())
keys = load("keys.json")["keys"]
pub = {k["name"]: k["public_key"] for k in keys}
codes = load("objects.json")["kind_object_type_codes"]
codes["receipt_bundle_binding"] = 0

def ctx(verify):
    if not verify:
        return None
    v = json.loads(json.dumps(verify))
    for f in ("status_key", "witness_key", "verifier_key"):
        if isinstance(v.get(f), str):
            v[f] = pub[v[f]]
    rs = v.get("rotation_state")
    if rs and isinstance(rs.get("current_key"), str):
        rs["current_key"] = pub[rs["current_key"]]
    return json.dumps(v)

with open(out / "keys.txt", "w") as kt:
    for i, k in enumerate(keys):
        (out / f"k{i}.ed").write_bytes(base64.b64decode(k["public_key"]["ed25519"]))
        (out / f"k{i}.ml").write_bytes(base64.b64decode(k["public_key"]["ml_dsa_65"]))
        kt.write(f"k{i}.ed k{i}.ml {k['key_id_v2']}\n")

rows = [(o, "ok") for o in load("objects.json")["objects"]]
rows += [(v, v["expected_error_class"]) for v in load("object-negatives.json")["vectors"]]
with open(out / "vectors.txt", "w") as vt:
    for i, (o, want) in enumerate(rows):
        (out / f"v{i}.wire").write_bytes(base64.b64decode(o["wire_b64"]))
        bundle = "-"
        if o.get("bundle_b64"):
            bundle = f"v{i}.bundle"
            (out / bundle).write_bytes(base64.b64decode(o["bundle_b64"]))
        c = ctx(o.get("verify"))
        cf = "-"
        if c is not None:
            cf = f"v{i}.ctx"
            (out / cf).write_text(c)
        vt.write(f"{codes[o['kind']]} {want} v{i}.wire {bundle} {cf}\n")
PY

EXTRA=()
case "$(uname -s)" in
    Darwin) EXTRA=(-framework Security -framework CoreFoundation) ;;
    Linux) EXTRA=(-lpthread -ldl -lm) ;;
esac
cc -std=c99 -Wall -Wextra -Werror -I"$SDK_DIR/include" \
    "$SDK_DIR/tests/c/v2_abi_smoke.c" "$LIB" "${EXTRA[@]}" -o "$WORK/v2_abi_smoke"
"$WORK/v2_abi_smoke" "$WORK/data"
