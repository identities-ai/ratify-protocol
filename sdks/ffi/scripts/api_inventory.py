#!/usr/bin/env python3
"""The Swift and Kotlin API inventory gate (build plan §3.1).

The core's public v2 API is listed with `cargo public-api` and checked in as
sdks/ffi/public-api.txt. sdks/ffi/api-inventory.json gives every listed item
one disposition:

  mapped      exposed in Swift and Kotlin under the given names
  rust-idiom  has no Swift/Kotlin counterpart, with a reason
  pending     not yet exposed; names the milestone that exposes it

Commands:
  listing  regenerate public-api.txt from the core (needs nightly)
  check    every listed item has an entry and every entry is still listed
  names    every mapped name is in the compiled public Swift API (API
           digester dump) and Kotlin API (BCV .api dump), and neither dump
           exposes a generated FFI declaration
  init     add missing items as pending (authoring aid; never in CI)
"""
import json
import pathlib
import re
import subprocess
import sys

FFI = pathlib.Path(__file__).resolve().parent.parent
ROOT = FFI.parent.parent
LISTING = FFI / "public-api.txt"
INVENTORY = FFI / "api-inventory.json"

# Crate-root items the v2 API names in its signatures or that the v2 corpus
# exercises (Annex A scope rules), included with their members.
ROOT_ITEMS = {
    "HybridPublicKey", "HybridPrivateKey", "HybridSignature", "ParamsValue",
    "vocabulary", "scope_wildcards", "is_sensitive", "expand_scopes", "intersect_scopes",
}

ITEM = re.compile(
    r"^pub (?:(?:unsafe |const |async )*fn|struct|enum|trait|const|type|static|enum variant)?\s*"
    r"(ratify_protocol::[A-Za-z0-9_:]+)"
)


def kind_of(line):
    m = re.match(r"^pub ((?:unsafe |const |async )*fn|struct|enum variant|enum|trait|const|type|static)\b", line)
    if m:
        return m.group(1).split()[-1] if "fn" in m.group(1) else m.group(1)
    return "member"  # a field or enum variant


def items(listing):
    """Map each item key to (kind, line). Keys drop the module path, so an
    item and its glob re-export are one entry."""
    mods = set()
    lines = listing.splitlines()
    for l in lines:
        m = re.match(r"^pub mod ratify_protocol::v2(?:::([A-Za-z0-9_:]+))?$", l)
        if m and m.group(1):
            mods.add(m.group(1))
    out = {}
    for l in lines:
        l = re.sub(r"^(#\[[^\]]*\] )+", "", l)  # leading attributes: #[repr(u16)] pub enum ...
        if l.startswith(("impl", "pub mod")) or not l.startswith("pub "):
            continue
        # Drop generic parameters (Type<'a>::member -> Type::member).
        bare = l
        while True:
            nxt = re.sub(r"<[^<>]*>", "", bare)
            if nxt == bare:
                break
            bare = nxt
        m = ITEM.match(bare)
        if not m:
            continue
        path = m.group(1).rstrip(":")
        if path.startswith("ratify_protocol::v2::"):
            rest = path[len("ratify_protocol::v2::"):]
            segs = rest.split("::")
            # Drop leading module segments (reference::store::X -> X).
            i = 0
            while i < len(segs) - 1 and "::".join(segs[: i + 1]) in mods:
                i += 1
            key = "::".join(segs[i:])
        else:
            segs = path[len("ratify_protocol::"):].split("::")
            if segs[0] in ("types", "crypto", "scope"):
                segs = segs[1:]
            if not segs or segs[0] not in ROOT_ITEMS:
                continue
            key = "::".join(segs)
        k = kind_of(l)
        prev = out.get(key)
        if prev and prev[0] != k:
            sys.exit(f"inventory key collision: {key}: {prev[1]!r} vs {l!r}")
        out[key] = (k, l)
    return out


def load_inventory():
    return json.loads(INVENTORY.read_text()) if INVENTORY.exists() else {}


def cmd_listing():
    out = subprocess.run(
        ["cargo", "+nightly", "public-api", "-ss", "--manifest-path", str(ROOT / "sdks/rust/Cargo.toml")],
        check=True, capture_output=True, text=True,
    ).stdout
    keep = [l for l in out.splitlines() if not l.startswith("impl")]
    LISTING.write_text("\n".join(keep) + "\n")
    print(f"wrote {LISTING.relative_to(ROOT)} ({len(items(LISTING.read_text()))} items)")


def cmd_check():
    listed = items(LISTING.read_text())
    inv = load_inventory()
    errors = []
    for key in sorted(listed):
        e = inv.get(key)
        if e is None:
            errors.append(f"no inventory entry: {key}")
            continue
        st = e.get("status")
        if st == "mapped" and not (e.get("swift") and e.get("kotlin")):
            errors.append(f"{key}: mapped without swift and kotlin names")
        elif st == "rust-idiom" and not e.get("reason"):
            errors.append(f"{key}: rust-idiom without a reason")
        elif st == "pending" and not re.fullmatch(r"M[2-5]", e.get("milestone", "")):
            errors.append(f"{key}: pending without a milestone M2-M5")
        elif st not in ("mapped", "rust-idiom", "pending"):
            errors.append(f"{key}: unknown status {st!r}")
    for key in sorted(set(inv) - set(listed)):
        errors.append(f"inventory entry for an item the core no longer exports: {key}")
    counts = {}
    for e in inv.values():
        counts[e.get("status")] = counts.get(e.get("status"), 0) + 1
    if errors:
        print("\n".join(errors))
        sys.exit(f"{len(errors)} inventory errors")
    print(f"inventory ok: {len(listed)} items {counts}")


def swift_decl_names(dump):
    """Every declaration name in an API digester dump, imports excluded."""
    names = []

    def walk(n):
        if isinstance(n, dict):
            if n.get("declKind") != "Import" and "printedName" in n:
                names.append(n["printedName"])
            for c in n.get("children", []):
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)

    walk(json.loads(dump)["ABIRoot"])
    return "\n".join(names)


def cmd_names(swift_dump, kotlin_api):
    inv = load_inventory()
    swift = swift_decl_names(pathlib.Path(swift_dump).read_text())
    kotlin = pathlib.Path(kotlin_api).read_text()
    errors = []
    for key, e in sorted(inv.items()):
        if e.get("status") != "mapped":
            continue
        for lang, text, name in (("swift", swift, e["swift"]), ("kotlin", kotlin, e["kotlin"])):
            leaf = name.split("(")[0].split(".")[-1].strip("[]")
            if leaf.startswith("List<"):
                leaf = leaf[5:-1]
            if leaf == "init" or leaf == "":
                leaf = name.split(".")[0]
            forms = [leaf]
            if lang == "kotlin":
                forms += ["get" + leaf[:1].upper() + leaf[1:], "is" + leaf[:1].upper() + leaf[1:]]
            if not any(re.search(r"\b" + re.escape(f) + r"\b", text) for f in forms):
                errors.append(f"{key}: {lang} name {name} not in the public API")
    for pat in (r"\bFfi[A-Z]\w*", r"\bffi[A-Z]\w*", r"internal/ffi", r"internal\.ffi", r"\bUniffi\w*", r"RustBuffer"):
        for text, lang in ((swift, "swift"), (kotlin, "kotlin")):
            m = re.search(pat, text)
            if m:
                errors.append(f"{lang} public API exposes a generated declaration: {m.group(0)}")
    if errors:
        print("\n".join(sorted(set(errors))))
        sys.exit(f"{len(set(errors))} public-name errors")
    print("public names ok")


def cmd_init():
    listed = items(LISTING.read_text())
    inv = load_inventory()
    added = 0
    for key, (kind, _) in sorted(listed.items()):
        if key not in inv:
            inv[key] = {"kind": kind, "status": "pending", "milestone": "M2"}
            added += 1
    INVENTORY.write_text(json.dumps(dict(sorted(inv.items())), indent=1) + "\n")
    print(f"added {added} pending entries")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    {"listing": cmd_listing, "check": cmd_check, "init": cmd_init}.get(cmd, lambda: cmd_names(*sys.argv[2:4]))()
