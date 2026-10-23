#!/usr/bin/env bash
# Build the library, flatten testvectors/v2 into manifests a plain C program
# can read, compile tests/c/*.c with the system C compiler against the
# generated include/ratify.h and the static library, and run it:
# keys, objects, object negatives, hedged signatures, limits, every
# verifier-ordering vector with C-implemented providers, a release lifecycle
# with a C-implemented in-memory store, and every cross-sdk/*.json fixture.
# It also links a program referencing every function the header declares
# without feature macros, so a declaration the default build does not export
# fails here.
#
# Usage: ./scripts/test-v2-c-abi.sh [work-dir]   (default: a fresh mktemp dir)
#
# Environment:
#   CC            C compiler (default cc)
#   SANITIZE=1    build the C program with AddressSanitizer and
#                 UndefinedBehaviorSanitizer when the compiler supports them
#   PREPARE_ONLY=1  only write the manifests into <work-dir>/data
#   CARGO_TARGET_DIR  honoured when locating the built library

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORPUS="$(cd "$SDK_DIR/../../testvectors/v2" && pwd)"
WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/ratify-v2-c-abi.XXXXXX")}"
CC="${CC:-cc}"
rm -rf "$WORK/data"
mkdir -p "$WORK/data"

python3 -I - "$CORPUS" "$WORK/data" <<'PY'
import base64, hashlib, json, pathlib, sys
corpus, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
load = lambda n: json.loads((corpus / n).read_text())
b64d = base64.b64decode
keys = load("keys.json")["keys"]
pub = {k["name"]: k["public_key"] for k in keys}
codes = load("objects.json")["kind_object_type_codes"]
codes["receipt_bundle_binding"] = 0
extra_kinds = {"verification_receipt_body": 100, "status_evidence_batch": 101}

def write(rel, data):
    p = out / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return rel

def ctx(verify, keymap):
    if not verify:
        return None
    v = json.loads(json.dumps(verify))
    for f in ("status_key", "witness_key", "verifier_key"):
        if isinstance(v.get(f), str):
            v[f] = keymap[v[f]]
    rs = v.get("rotation_state")
    if rs and isinstance(rs.get("current_key"), str):
        rs["current_key"] = keymap[rs["current_key"]]
    return json.dumps(v)

# ---- keys, objects, negatives, hedged ---------------------------------------
with open(out / "keys.txt", "w") as kt:
    for i, k in enumerate(keys):
        write(f"k{i}.ed", b64d(k["public_key"]["ed25519"]))
        write(f"k{i}.ml", b64d(k["public_key"]["ml_dsa_65"]))
        kt.write(f"k{i}.ed k{i}.ml {k['key_id_v2']}\n")

rows = [(o["kind"], o["wire_b64"], o.get("bundle_b64"), o.get("verify"), "ok", True) for o in load("objects.json")["objects"]]
rows += [(v["kind"], v["wire_b64"], v.get("bundle_b64"), v.get("verify"), v["expected_error_class"], False)
         for v in load("object-negatives.json")["vectors"]]
for o in load("hedged-signatures.json")["objects"]:
    for w in o["hedged_wire_b64"]:
        rows.append((o["kind"], w, None, o.get("verify"), "ok", True))
with open(out / "vectors.txt", "w") as vt:
    for i, (kind, wire, bundle, verify, want, reencode) in enumerate(rows):
        write(f"v{i}.wire", b64d(wire))
        bf = write(f"v{i}.bundle", b64d(bundle)) if bundle else "-"
        c = ctx(verify, pub)
        cf = write(f"v{i}.ctx", c) if c is not None else "-"
        flag = "R" if reencode and codes[kind] != 0 else "-"
        vt.write(f"{codes[kind]} {want} v{i}.wire {bf} {cf} {flag}\n")

# ---- limits -------------------------------------------------------------------
def limit_bytes(c):
    opt = lambda k: b64d(c[k]) if k in c else b""
    m = c["method"]
    if m == "inline":
        return b64d(c["wire_b64"])
    if m == "pad":
        base = b64d(c["base_b64"])
        return base[:-1] + b" " * c["pad_count"] + base[-1:]
    if m == "repeat_items":
        digits = c.get("item_index_digits", 0)
        items = [f"{c.get('item_prefix', '')}{n:0{digits}d}{c.get('item_suffix', '')}".encode() for n in range(c["count"])]
        return opt("prefix_b64") + b",".join(items) + opt("suffix_b64")
    if m == "repeat_item":
        return opt("prefix_b64") + b",".join([b64d(c["item_b64"])] * c["count"]) + opt("suffix_b64")
    raise SystemExit(f"unknown construction {m}")

with open(out / "limits.txt", "w") as lt:
    for i, v in enumerate(load("limits.json")["vectors"]):
        data = limit_bytes(v["construction"])
        assert len(data) == v["length"] and hashlib.sha256(data).hexdigest() == v["sha256_hex"], v["name"]
        kind = codes.get(v["kind"], extra_kinds.get(v["kind"]))
        write(f"lim{i}.bin", data)
        lt.write(f"{kind} {v['expected']} {v.get('expected_error_class') or '-'} lim{i}.bin {v['size_gate']}\n")

# ---- ordering-style vectors ----------------------------------------------------
COUNTS = ["receiver_binding", "claim", "trust", "status", "audience", "rate", "finalize", "progress", "evaluator"]

def request_json(v):
    r = {k: v.get(src) for k, src in [("required_scope", "required_scope"), ("verifier_namespace", "configured_namespace"),
         ("replay_epoch", "configured_replay_epoch"), ("now", "now"), ("max_challenge_age_seconds", "max_challenge_age_seconds"),
         ("future_skew_seconds", "future_skew_seconds"), ("tzdb_version", "tzdb_version"), ("status_policy", "status_policy")]}
    r["status_keys"] = {i: {"epoch": k["epoch"], "public_key": k["public_key"]} for i, k in (v.get("status_keys") or {}).items()}
    e = v.get("expected_challenge")
    if e is not None:
        exp = {k: e.get(k) for k in ["value_b64", "issued_at", "expires_at", "verifier_namespace", "replay_epoch", "verifier_id"]}
        if e.get("expected_agent_id") is not None:
            exp["expected_agent_id"] = e["expected_agent_id"]
            if e.get("expected_agent_public_key") is not None:
                exp["expected_agent_public_key"] = e["expected_agent_public_key"]
        for k in ["expected_receiver_id", "expected_session_context_b64"]:
            if e.get(k) is not None:
                exp[k] = e[k]
        r["expected_challenge"] = exp
    p = v.get("context_policy")
    if p is not None:
        r["context_policy"] = {k: p.get(k) for k in ["profile", "require_bound", "required_fields", "expected_session_context_b64"]}
    if v.get("request_context") is not None:
        r["context"] = v["request_context"]
    return r

def vector_dir(rel, v, bundle):
    write(f"{rel}/bundle.bin", bundle)
    write(f"{rel}/request.json", json.dumps(request_json(v)))
    exp = v.get("expected") or {}
    t = v.get("trust")
    meta = {
        "name": v.get("name") or rel,
        "now": v.get("now"),
        "claim_store": v.get("claim_store"),
        "claimed_at": v["now"] + v.get("claim_time_offset", 0),
        "finalization_at": v["now"] + v.get("claim_time_offset", 0) + v.get("finalize_time_offset", 0),
        "trust": "none" if t is None else "set",
        "trust_mode": (t or {}).get("mode") or "-",
        "trust_outcome": (t or {}).get("outcome") or "-",
        "root": "yes" if t and t.get("root_public_key") else "no",
        "journal": v["journal"]["mode"],
        "binding": v.get("receiver_binding_hook") or "absent",
        "rate": v.get("rate") or "absent",
        "audience_mode": v.get("audience_mode") or "ok",
        "expect_stage": exp.get("stage") or "-",
        "expect_class": exp.get("error_class") or "-",
        "expect_disposition": exp.get("disposition") or "-",
        "expect_counts": "".join(f"{(exp.get('callback_counts') or {}).get(n, 0)} " for n in COUNTS),
        "expect_allow": f"{1 if exp.get('decision') == 'allow' else 0} {exp.get('allow_valid_until', 0) or 0}",
    }
    e = v.get("expected_challenge") or {}
    meta["namespace"] = v.get("configured_namespace")
    meta["replay_epoch"] = v.get("configured_replay_epoch")
    if e.get("value_b64"):
        meta["challenge_file"] = write(f"{rel}/challenge.bin", b64d(e["value_b64"]))
    batch = exp.get("rate_batch") or []
    if batch:
        meta["expect_rate_batch"] = "".join(f"{b['issuer_id']} {b['cert_id']} {b['window_s']} {b['limit']};" for b in batch)
    if t and t.get("root_public_key"):
        write(f"{rel}/root.ed", b64d(t["root_public_key"]["ed25519"]))
        write(f"{rel}/root.ml", b64d(t["root_public_key"]["ml_dsa_65"]))
    # trust.mode "registry": the candidate-record records, in order.
    registry = (t or {}).get("registry") or []
    meta["registry"] = len(registry)
    for j, k in enumerate(registry):
        write(f"{rel}/reg{j}.ed", b64d(k["ed25519"]))
        write(f"{rel}/reg{j}.ml", b64d(k["ml_dsa_65"]))
    if exp.get("receipt_body_b64"):
        write(f"{rel}/expect_body.bin", b64d(exp["receipt_body_b64"]))
    skeys = v.get("status_keys") or {}
    for issuer, k in skeys.items():
        meta[f"epoch_{issuer}"] = k["epoch"]
    write(f"{rel}/meta.txt", "".join(f"{k} {val}\n" for k, val in meta.items()))
    st = []
    for issuer, script in (v.get("status_evidence") or {}).items():
        if script is None:
            continue
        st.append(f"{issuer} mode {script.get('mode') or 'ok'}")
        for n, o in enumerate(script.get("objects") or []):
            st.append(f"{issuer} obj {o['object_type_code']} " + write(f"{rel}/s_{issuer[:8]}_{n}.bin", b64d(o["wire_b64"])).split("/", 2)[-1])
    write(f"{rel}/status.txt", "".join(l + "\n" for l in st))
    pol = v.get("status_policy") or {}
    pl = [f"policy {pol.get('max_list_lifetime_seconds', 0)} {pol.get('max_status_age_seconds', 0)} {pol.get('clock_skew_seconds', 0)}"]
    for issuer in sorted(skeys):
        k = skeys[issuer]["public_key"]
        write(f"{rel}/sk_{issuer[:12]}.ed", b64d(k["ed25519"]))
        write(f"{rel}/sk_{issuer[:12]}.ml", b64d(k["ml_dsa_65"]))
        pl.append(f"key {issuer} {skeys[issuer]['epoch']} sk_{issuer[:12]}.ed sk_{issuer[:12]}.ml")
    for n, p in enumerate(v["journal"].get("preload") or []):
        f = write(f"{rel}/pre_{n}.bin", b64d(p["wire_b64"])).split("/", 2)[-1]
        i = p["issuer_id"]
        pl.append(f"apply {i} {p['object_type_code']} {f} {p['now']} sk_{i[:12]}.ed sk_{i[:12]}.ml")
    write(f"{rel}/preload.txt", "".join(l + "\n" for l in pl))
    au = []
    for m in v.get("audience_memberships") or []:
        doms = m.get("trust_domain_ids") or []
        au.append(f"m {m.get('delegation_index', 0)} {m.get('constraint_index', 0)} {m.get('receiver_id') or '-'} "
                  f"{m.get('issued_at', 0)} {m.get('expires_at', 0)} {m.get('evidence_digest') or '-'} {len(doms)} " + " ".join(doms))
    write(f"{rel}/audience.txt", "".join(l + "\n" for l in au))
    ev = [f"e {e['type']} {e['profile']} {e['implementation']} {e.get('valid_until', 0) or 0}" for e in v.get("constraint_evaluators") or []]
    write(f"{rel}/evaluators.txt", "".join(l + "\n" for l in ev))

ordering = load("verifier-ordering.json")
dirs = []
for n, v in enumerate(ordering["vectors"]):
    rel = f"ordering/v{n:04d}"
    vector_dir(rel, v, b64d(ordering["bundles_b64"][v["bundle"]]))
    dirs.append(rel)
write("ordering/index.txt", "".join(d + "\n" for d in dirs))

# ---- lifecycle (C store) -----------------------------------------------------
life = load("lifecycle-scenarios.json")
vk = next(k for k in keys if k["name"] == life["verifier_key"])
write("lifecycle/verifier.ed", bytes.fromhex(vk["ed25519_seed_hex"]))
write("lifecycle/verifier.ml", bytes.fromhex(vk["ml_dsa_65_seed_hex"]))
a = life["requests"]["A"]
vector_dir("lifecycle/A", dict(a, name="lifecycle A"), b64d(life["bundles_b64"][a["bundle"]]))
write("lifecycle/meta.txt", f"verifier_seeds lifecycle/verifier.ed lifecycle/verifier.ml\nlog_id {life['log_id']}\n"
      f"lease {life['lease_seconds']}\nallow lifecycle/A\ncancel lifecycle/A\n")

# ---- cross-SDK fixtures ----------------------------------------------------------
lines = []
fixtures = sorted((corpus / "cross-sdk").glob("*.json"))
for fx in fixtures:
    sdk = fx.stem
    data = json.loads(fx.read_text())
    lines.append(f"fixture {sdk} " + write(f"cross/{sdk}.json", fx.read_bytes()))
    keymap, keyfile = {}, {}
    for k in data["keys"]:
        n = k["name"]
        base = f"cross/{sdk}/key_{n}"
        write(base + ".sed", bytes.fromhex(k["ed25519_seed_hex"]))
        write(base + ".sml", bytes.fromhex(k["ml_dsa_65_seed_hex"]))
        write(base + ".ed", b64d(k["public_key"]["ed25519"]))
        write(base + ".ml", b64d(k["public_key"]["ml_dsa_65"]))
        keymap[n] = k["public_key"]
        keyfile[n] = (base + ".ed", base + ".ml", k["key_id_v2"])
        lines.append(f"key {base}.sed {base}.sml {base}.ed {base}.ml {k['key_id_v2']}")
    kinds = data["kind_object_type_codes"]
    for i, o in enumerate(data["objects"]):
        base = f"cross/{sdk}/o{i}"
        wire = b64d(o["wire_b64"])
        write(base + ".wire", wire)
        kind = 0 if o["kind"] == "receipt_bundle_binding" else kinds[o["kind"]]
        c = ctx(o.get("verify"), keymap) if kind != 0 else None
        cf = write(base + ".ctx", c) if c else "-"
        bf = write(base + ".bundle", b64d(o["bundle_b64"])) if o.get("bundle_b64") else "-"
        lines.append(f"obj {kind} {base}.wire {cf} {bf}")
        for n, s in enumerate(o.get("signatures") or []):
            field = s["field"]
            if field.startswith("delegations["):
                idx = int(field[len("delegations["):].split("]")[0])
                src = json.dumps(json.loads(wire)["delegations"][idx], separators=(",", ":"), ensure_ascii=False).encode()
            else:
                src = wire
            sb = f"{base}_s{n}"
            write(sb + ".src", src)
            write(sb + ".signable", b64d(s["signable_b64"]))
            write(sb + ".m", b64d(s["message_b64"]))
            write(sb + ".ctx", s["mldsa_context"].encode())
            write(sb + ".mu", b64d(s["mldsa_mu_b64"]))
            write(sb + ".sed", b64d(s["signature"]["ed25519"]))
            write(sb + ".sml", b64d(s["signature"]["ml_dsa_65"]))
            ked, kml, kid = keyfile[s["signer"]]
            lines.append(f"sig {s['object_type_code']} {sb}.src {sb}.signable {sb}.m {sb}.ctx {sb}.mu {sb}.sed {sb}.sml {ked} {kml} {kid}")
write("cross/index.txt", "".join(l + "\n" for l in lines))
print(f"manifests: {len(rows)} object rows, {len(dirs)} ordering vectors, {len(fixtures)} cross-SDK fixtures")
PY

[ "${PREPARE_ONLY:-0}" = "1" ] && exit 0

(cd "$SDK_DIR" && cargo build --release --quiet)
LIB="${CARGO_TARGET_DIR:-$SDK_DIR/target}/release/libratify_c.a"

EXTRA=()
case "$(uname -s)" in
    Darwin) EXTRA=(-framework Security -framework CoreFoundation) ;;
    Linux) EXTRA=(-lpthread -ldl -lm) ;;
esac
FLAGS=(-std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -I"$SDK_DIR/include")
if [ "${SANITIZE:-0}" = "1" ]; then
    if echo 'int main(void){return 0;}' | "$CC" -x c -fsanitize=address,undefined - -o "$WORK/sancheck" 2>/dev/null; then
        FLAGS+=(-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined)
        echo "sanitizers: address, undefined"
    else
        echo "sanitizers: not supported by $CC; running without them" >&2
    fi
fi
"$CC" "${FLAGS[@]}" "$SDK_DIR"/tests/c/*.c "$LIB" "${EXTRA[@]}" -o "$WORK/v2_abi"
"$WORK/v2_abi" "$WORK/data"

# Every function the header declares without feature macros must be exported
# by the default build: reference each one and link.
echo '#include "ratify.h"' | "$CC" -E -P -I"$SDK_DIR/include" -x c - > "$WORK/ratify.i"
python3 -I - "$WORK/ratify.i" "$WORK/decls.c" <<'PY'
import re, sys
names = sorted(set(re.findall(r"\b(ratify_\w+)\s*\(", open(sys.argv[1]).read())))
assert names, "no declarations found"
body = "".join(f"    (fn){n},\n" for n in names)
open(sys.argv[2], "w").write(
    '#include <stdio.h>\n#include "ratify.h"\ntypedef void (*fn)(void);\n'
    f"static const fn declared[] = {{\n{body}}};\n"
    "int main(void) {\n    size_t n = 0;\n"
    "    for (size_t i = 0; i < sizeof declared / sizeof declared[0]; i++) n += declared[i] != NULL;\n"
    '    printf("header declarations linked: %zu\\n", n);\n    return 0;\n}\n')
PY
"$CC" "${FLAGS[@]}" "$WORK/decls.c" "$LIB" "${EXTRA[@]}" -o "$WORK/decls"
"$WORK/decls"
