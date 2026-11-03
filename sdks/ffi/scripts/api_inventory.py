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


# Public declarations that no inventory item maps, each with its reason.
# Everything else public must be named by a mapped inventory entry.
EXTRA_SWIFT = {
    "KeyStorageRecord": "the documented key storage record (plan §4.3); SDK-only",
    "KeyStorageRecord.RecordType": "storage record types (plan §4.3)",
    "KeychainKeyStore": "Keychain storage of software keys (plan §4.3); SDK-only",
    "SecureEnclaveKey": "Secure Enclave platform signer (plan §4.2); SDK-only",
    "SecureEnclaveKey.Custody": "per-component custody report (plan §4.2)",
    "SigningKey": "the key a typed signing function uses (plan §4.1)",
    "PlatformKey": "a boxed platform key for SigningKey.platform (plan §4.1)",
    "InternalErrorKind": "kind of RatifyError.internal (plan §2.2)",
    "Ratify.errorClassSpellings": "the core's §2.7 class list, which pins ErrorClass in tests",
}
EXTRA_KOTLIN = {
    "KeyStorageRecord": "the documented key storage record (plan §4.3); SDK-only",
    "KeyStorageRecord.RecordType": "storage record types (plan §4.3)",
    "AndroidKeyStore": "Keystore-wrapped storage of software keys (plan §4.3); SDK-only",
    "KeyStorageKt": "file facade",
    "RotationAcceptance": "the (journal, result) tuple of accept_key_rotation_statement_v2",
    "InternalErrorKind": "kind of RatifyException.Internal (plan §2.2)",
    "RatifyException": "the sealed error family (plan §2.2)",
    "RatifyException.Signing": "signing errors (plan §2.2); V2SignError is mapped in M2",
    "RatifyException.Internal": "internal errors (plan §2.2)",
    "errorClassSpellings": "the core's §2.7 class list, which pins ErrorClass in tests",
    "storageRecord": "the key's storage record (plan §4.3)",
    "softwarePrivateKeyFromStorageRecord": "load a key from its storage record (plan §4.3)",
}


# Swift: only members the compiler synthesized (`implicit` in the digester
# dump) are exempt, plus initializers of a public type.
# Kotlin has no such flag, so each exemption is scoped to what synthesizes it.
KOTLIN_ANY = {"init", "equals", "hashCode", "toString", "Companion"}
KOTLIN_ENUM = {"values", "valueOf", "entries", "getEntries", "name", "ordinal"}
KOTLIN_THROWABLE = {"message", "cause"}
KOTLIN_DATA = {"copy", "copy$default"}  # plus componentN
# Public members that no inventory item maps, each with its reason.
EXTRA_MEMBERS = {
    "RatifyException.errorClass": "the §2.7 class of any RatifyException",
    "RatifyException.Signing.errorClass": "the §2.7 class (plan §2.2)",
    "RatifyException.Signing.kind": "the V2SignError kind (plan §2.2); mapped in M2",
    "RatifyException.Signing.detail": "diagnostic message (plan §2.2)",
    "RatifyException.Internal.errorClass": "always null for internal errors",
    "RatifyException.Internal.kind": "the internal error kind (plan §2.2)",
    "RatifyException.Internal.detail": "diagnostic message (plan §2.2)",
    "RatifyException.Protocol.errorClass": "the §2.7 class (plan §2.2)",
    "InternalErrorKind.spelling": "the FFI spelling of the kind",
    "SigningErrorKind.spelling": "the FFI spelling of the kind",
    "RotationAcceptance.journal": "tuple field", "RotationAcceptance.result": "tuple field",
    "RotationAcceptance.error": "tuple field",
    "KeyStorageRecord.recordType": "storage record", "KeyStorageRecord.keyId": "storage record",
    "KeyStorageRecord.header": "storage record", "KeyStorageRecord.RecordType.code": "storage record type code",
    "KeyStorageRecord.RecordType.software": "record type", "KeyStorageRecord.RecordType.secureEnclaveHybrid": "record type",
    "KeyStorageRecord.RecordType.androidSplit": "record type", "KeyStorageRecord.RecordType.SOFTWARE": "record type",
    "KeyStorageRecord.RecordType.SECURE_ENCLAVE_HYBRID": "record type", "KeyStorageRecord.RecordType.ANDROID_SPLIT": "record type",
    "KeychainKeyStore.service": "Keychain service name", "KeychainKeyStore.accessGroup": "Keychain access group",
    "KeychainKeyStore.save": "store", "KeychainKeyStore.load": "store", "KeychainKeyStore.delete": "store",
    "AndroidKeyStore.save": "store", "AndroidKeyStore.load": "store", "AndroidKeyStore.delete": "store",
    "SoftwarePrivateKey.storageRecord": "the key's storage record (plan §4.3)",
    "SecureEnclaveKey.publicKey": "platform key", "SecureEnclaveKey.keyId": "platform key",
    "SecureEnclaveKey.custody": "custody report", "SecureEnclaveKey.generate": "platform key",
    "SecureEnclaveKey.defaultAccessControl": "platform key", "SecureEnclaveKey.storageRecord": "platform key",
    "SecureEnclaveKey.Custody.secureEnclave": "custody", "SecureEnclaveKey.Custody.software": "custody",
    "SigningKey.software": "signing key kind", "SigningKey.external": "signing key kind", "SigningKey.platform": "signing key kind",
    "PlatformKey.keyId": "platform key", "KeychainKeyStore.loadSecureEnclaveKey": "store",
    "SoftwarePrivateKey.keyId": "convenience: key_id_v2 of publicKey, computed once at load",
    "ParamsValue.Bool.value": "the variant's value", "ParamsValue.Int.value": "the variant's value",
    "ParamsValue.Str.value": "the variant's value", "ParamsValue.Array.items": "the variant's value",
    "ParamsValue.Object.entries": "the variant's value",
    "StatusObject.List.list": "the variant's value", "StatusObject.Push.push": "the variant's value",
    "InternalErrorKind.panic": "kind case", "InternalErrorKind.poisoned": "kind case",
    "InternalErrorKind.randomSource": "kind case", "InternalErrorKind.PANIC": "kind case",
    "InternalErrorKind.POISONED": "kind case", "InternalErrorKind.RANDOM_SOURCE": "kind case",
    "RatifyError.signing": "signing errors (plan §2.2); V2SignError is mapped in M2",
    "RatifyError.internal": "internal errors (plan §2.2)",
    "RatifyError.errorDescription": "LocalizedError conformance (the diagnostic message)",
}


synthesized = {}  # swift type path -> compiler-synthesized member names
kotlin_kinds = {}  # kotlin class path -> {"enum", "throwable", "object", "data"}


def swift_model(dump):
    """{type path: set of member names} for every public type, plus the
    members of the `Ratify` namespace; imports excluded."""
    types = {}

    def walk(node, prefix):
        for c in node.get("children", []):
            if c.get("declKind") in ("Struct", "Class", "Enum", "Protocol"):
                path = f"{prefix}{c['name']}"
                members = types.setdefault(path, set())
                for m in c.get("children", []):
                    if m.get("declKind") in ("Var", "Func", "EnumElement", "Constructor", "TypeAlias"):
                        n = "init" if m.get("declKind") == "Constructor" else m["name"]
                        members.add(n)
                        if m.get("implicit") or n == "init":
                            synthesized.setdefault(path, set()).add(n)
                walk(c, path + ".")

    walk(json.loads(dump)["ABIRoot"], "")
    return types


def kotlin_model(api):
    """{class path: set of member names} from a BCV .api dump. Getters are
    recorded as properties, constructors as `init`, companion members on the
    owner, and file-facade (`*Kt`) functions under the empty owner."""
    types, cur = {}, None
    for line in api.splitlines():
        m = re.match(r"^public .*?(?:class|interface) com/ratifyprotocol/([A-Za-z0-9_$]+)\b", line)
        if m:
            name = m.group(1)
            if name.endswith("Kt") and "$" not in name:
                cur = ""
            else:
                cur = name.replace("$Companion", "").replace("$", ".")
            types.setdefault(cur, set())
            kinds = kotlin_kinds.setdefault(cur, set())
            if "java/lang/Enum" in line:
                kinds.add("enum")
            if re.search(r"java/lang/(Exception|RuntimeException|Throwable)|com/ratifyprotocol/RatifyException\b", line):
                kinds.add("throwable")
            continue
        if line.startswith("}"):
            cur = None
            continue
        if cur is None:
            continue
        if re.search(r"\bstatic final field INSTANCE\b", line):
            kotlin_kinds.setdefault(cur, set()).add("object")
        f = re.search(r"\bfun (\S+) \(", line) or re.search(r"\bfield (\S+) ", line)
        if not f:
            continue
        n = f.group(1).split("-")[0]  # inline-class mangling: getObjectType-Mh2AYeg
        if n == "<init>":
            n = "init"
        elif re.match(r"^(get|is)[A-Z]", n) and "fun" in line and re.search(r"\(\)", line):
            n = n[3:] if n.startswith("get") else n[2:]
            n = n[:1].lower() + n[1:]
        types[cur].add(n)
    return types


def resolve(model, name, lang):
    """Whether a mapped public name exists in its owning declaration."""
    name = name.split("(")[0]
    if name.startswith("[") or name.startswith("List<"):
        name = name.strip("[]")[5:-1] if name.startswith("List<") else name.strip("[]")
    parts = name.split(".")
    if lang == "kotlin" and len(parts) == 1 and parts[0][:1].islower():
        return parts[0] in model.get("", set())
    for cut in range(len(parts), 0, -1):  # longest type path first
        owner = ".".join(parts[:cut])
        if owner in model:
            rest = parts[cut:]
            if not rest:
                return True
            if len(rest) == 1 and rest[0] in model[owner]:
                return True
            if lang == "swift" and rest == ["allCases"] and "AllCases" in model[owner]:
                return True
            if lang == "swift" and rest == ["rawValue"] and "RawValue" in model[owner]:
                return True
            return False
    return False


def cmd_names(swift_dump, kotlin_api):
    inv = load_inventory()
    swift = swift_model(pathlib.Path(swift_dump).read_text())
    kotlin = kotlin_model(pathlib.Path(kotlin_api).read_text())
    errors = []
    used = {"swift": set(EXTRA_SWIFT), "kotlin": set(EXTRA_KOTLIN)}
    for key, e in sorted(inv.items()):
        if e.get("status") != "mapped":
            continue
        for lang, model in (("swift", swift), ("kotlin", kotlin)):
            name = e[lang]
            if not resolve(model, name, lang):
                errors.append(f"{key}: {lang} name {name} is not in the public API")
            base = name.split("(")[0].strip("[]")
            if base.startswith("List<"):
                base = base[5:-1]
            parts = base.split(".")
            used[lang].update(".".join(parts[:i]) for i in range(1, len(parts) + 1))
    # Nothing public that the inventory or the allowlist does not name.
    for t, members in swift.items():
        if t not in used["swift"]:
            errors.append(f"swift public type {t} is not named by the inventory")
    for m in swift.get("Ratify", set()):
        if f"Ratify.{m}" not in used["swift"]:
            errors.append(f"swift public function Ratify.{m} is not named by the inventory")
    members_used = {lang: {n for n in used[lang] if "." in n} for lang in used}
    # Kotlin data classes, from the sources (BCV does not mark them).
    src = ROOT / "sdks/kotlin/ratify-protocol/src/main/kotlin/com/ratifyprotocol"
    for f in src.glob("*.kt"):
        text = f.read_text()
        for m in re.finditer(r"\bdata class (\w+)", text):
            for t in kotlin:
                if t.split(".")[-1] == m.group(1):
                    kotlin_kinds.setdefault(t, set()).add("data")

    def exempt(lang, t, m):
        if lang == "swift":
            return m in synthesized.get(t, set())
        k = kotlin_kinds.get(t, set())
        return (m in KOTLIN_ANY or ("enum" in k and m in KOTLIN_ENUM) or ("throwable" in k and m in KOTLIN_THROWABLE)
                or ("object" in k and m == "INSTANCE")
                or ("data" in k and (m in KOTLIN_DATA or re.fullmatch(r"component\d+", m))))

    for model, lang in ((swift, "swift"), (kotlin, "kotlin")):
        for t, members in model.items():
            if not t or t == "Ratify":
                continue
            for m in members:
                if exempt(lang, t, m):
                    continue
                if f"{t}.{m}" not in members_used[lang] and f"{t}.{m}" not in EXTRA_MEMBERS:
                    errors.append(f"{lang} public member {t}.{m} is not named by the inventory")
    for t in kotlin:
        if t and t not in used["kotlin"]:
            errors.append(f"kotlin public type {t} is not named by the inventory")
    for f in kotlin.get("", set()):
        if f not in used["kotlin"]:
            errors.append(f"kotlin public function {f} is not named by the inventory")
    for model, lang in ((swift, "swift"), (kotlin, "kotlin")):
        for t, members in model.items():
            for n in [t, *members]:
                if re.search(r"(^|\.)(Ffi|ffi[A-Z]|Uniffi|RustBuffer)", n):
                    errors.append(f"{lang} public API exposes a generated declaration: {t}.{n}")
    if errors:
        print("\n".join(sorted(set(errors))))
        sys.exit(f"{len(set(errors))} public-name errors")
    print(f"public names ok ({len(swift)} swift types, {len(kotlin)} kotlin types)")


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
