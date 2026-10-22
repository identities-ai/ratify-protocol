#!/usr/bin/env python3
"""Assert every reference states one SDK version consistently.

A reference names its Ratify version in three places: the dependency it
installs, the registry entry a reader consults, and its own README. They drift
silently, and the drift is only visible when someone runs the gate months later
against a version the metadata never claimed. This makes disagreement a
failure instead.

Every registry entry states a `Protocol line` (v1 or v2). The rules differ:

- v1: requirements.txt pins exactly one `ratify-protocol==1.0.0aN`, and the
  registry entry and README name that version and no other.
- v2: the SDK is built from this repository until the v2 release is published,
  so there is no Ratify pin to compare against. Instead every v2 version a
  reference states (registry entry, README, evidence, metadata, requirements,
  gate script) must be either the version in this tree
  (sdks/python-v2/pyproject.toml) or the release the reference is waiting for
  (V2_RELEASE). Both spellings are understood: PEP 440 (2.0.0a1, 2.0.0b1) and
  SemVer (2.0.0-alpha.1, 2.0.0-beta.1). Once the tree is bumped to the
  release, the alpha mentions fail until each reference is re-run and its
  records updated. A v2 reference must not pin the v1 package, and the gate
  scripts its registry entry names must exist.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"1\.0\.0a\d+")
# Protocol v2 versions in either spelling.
V2_PEP440 = re.compile(r"(?<![\w.])2\.0\.0(a|b|rc)(\d+)(?![\w.])")
V2_SEMVER = re.compile(r"(?<![\w.])2\.0\.0-(alpha|beta|rc)\.(\d+)(?![\w.])")
V2_STAGES = {"a": "alpha", "b": "beta", "rc": "rc"}
# The published release the v2 references are waiting for.
V2_RELEASE = "2.0.0-beta.1"
PROTOCOL_LINE = re.compile(r"^\s*-\s*(?:\*\*)?Protocol line:(?:\*\*)?\s*(.+)$", re.M)
GATE_LINE = re.compile(r"^\s*-\s*(?:\*\*)?Gate:(?:\*\*)?\s*(.+)$", re.M)
GATE_PATH = re.compile(r"(?<![\w/])\.?/?((?:references|demos|scripts)/[\w./-]+\.sh)")
# Evidence result lines. The second form is the gate's own summary line:
#   Result: `reference gate: Protocol v2 tests passed (13/13)`, 0 failures, 0 skips
RESULT_PLAIN = re.compile(r"Result:\s*(\d+) passed,\s*(\d+) failed,\s*(\d+) skipped")
RESULT_GATE = re.compile(
    r"Result:\s*`[^`]*\((\d+)/\d+\)`,\s*(\d+)\s+failures?,\s*(\d+)\s+skips?")
# package==version, as it appears in requirements files and in prose.
PIN = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.]*)")
# Evidence files state versions as table rows rather than as pins:
#   | pytest | `8.4.1` |
# A checker that only understands pkg==version reports success while the
# evidence goes stale, which is worse than not checking at all.
ROW = re.compile(r"^\|\s*([A-Za-z][A-Za-z0-9 ._-]*?)\s*\|[^|]*?`([0-9][A-Za-z0-9.]*)`\s*\|", re.M)
# How a table label maps to the package it describes.
ROW_ALIASES = {
    "pytest": "pytest",
    "pytest-asyncio": "pytest-asyncio",
    "google adk": "google-adk",
    "mcp python sdk": "mcp",
    "langchain": "langchain",
    "ratify protocol": "ratify-protocol",
}


def versions_in(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(VERSION.findall(path.read_text(encoding="utf-8")))


def v2_versions_in(path: Path) -> set[str]:
    """Every v2 version stated in a file, normalized to SemVer."""
    if not path.exists():
        return set()
    return v2_versions_in_text(path.read_text(encoding="utf-8"))


def in_tree_v2() -> str:
    pyproject = (ROOT / "sdks" / "python-v2" / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    normalized = v2_versions_in_text(declared)
    if len(normalized) != 1:
        raise SystemExit(f"reference-version-sync: cannot read the in-tree v2 version from {declared!r}")
    return normalized.pop()


def v2_versions_in_text(text: str) -> set[str]:
    found = {f"2.0.0-{V2_STAGES[stage]}.{n}" for stage, n in V2_PEP440.findall(text)}
    found |= {f"2.0.0-{stage}.{n}" for stage, n in V2_SEMVER.findall(text)}
    return found


def check_v2(name: str, entry: Path, ref: Path, metadata: dict, allowed: set[str],
             failures: list[str]) -> None:
    entry_text = entry.read_text(encoding="utf-8")
    gates: list[Path] = []
    gate_line = GATE_LINE.search(entry_text)
    if gate_line:
        for rel in GATE_PATH.findall(gate_line.group(1)):
            gate = ROOT / rel
            if not gate.exists():
                failures.append(f"{name}: registry Gate names {rel}, which does not exist")
            else:
                gates.append(gate)
    if not gates and (ref / "run-reference-check.sh").exists():
        gates.append(ref / "run-reference-check.sh")
    if not gates:
        failures.append(f"{name}: v2 registry entry names no gate script in this repository")

    files = [entry, ref / "README.md", ref / "ratify-reference.json",
             ref / "requirements.txt", ref / "evidence" / "reference-evidence.md", *gates]
    if "evidence" in metadata:
        files.append(ref / metadata["evidence"])
    for path in dict.fromkeys(files):
        for version in sorted(v2_versions_in(path) - allowed):
            failures.append(
                f"{name}: {path.relative_to(ROOT)} names v2 {version}; "
                f"expected the in-tree version or the {V2_RELEASE} release ({sorted(allowed)})"
            )

    requirements = ref / "requirements.txt"
    if requirements.exists() and re.search(r"^ratify-protocol==", requirements.read_text(encoding="utf-8"), re.M):
        failures.append(f"{name}: v2 reference pins the v1 ratify-protocol package in requirements.txt")
    protocol = metadata.get("protocol")
    if protocol is not None and not str(protocol).startswith("v2"):
        failures.append(f"{name}: ratify-reference.json protocol {protocol!r} contradicts the v2 registry line")


def main() -> int:
    failures: list[str] = []
    allowed_v2 = {in_tree_v2(), V2_RELEASE}
    registry_dir = ROOT / "references" / "registry"
    if not registry_dir.exists():
        print("reference-version-sync: no registry directory; nothing to check")
        return 0

    for entry in sorted(registry_dir.glob("*.md")):
        if entry.name == "README.md":
            continue
        name = entry.stem
        ref = ROOT / "references" / name
        metadata_path = ref / "ratify-reference.json"
        metadata = {}
        line_match = PROTOCOL_LINE.search(entry.read_text(encoding="utf-8"))
        line = line_match.group(1).strip()[:2] if line_match else None
        if line not in ("v1", "v2"):
            failures.append(f"{name}: registry entry has no 'Protocol line' starting with v1 or v2")
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            evidence = ref / metadata.get("evidence", "docs/evidence.md")
            if "tests" in metadata or "skips" in metadata:
                if not evidence.exists():
                    failures.append(f"{name}: evidence file missing: {evidence}")
                else:
                    evidence_text = evidence.read_text(encoding="utf-8")
                    match = RESULT_PLAIN.search(evidence_text) or RESULT_GATE.search(evidence_text)
                    if not match:
                        failures.append(f"{name}: evidence has no parseable test result")
                    else:
                        passed, failed, skipped = map(int, match.groups())
                        if passed != metadata.get("tests") or skipped != metadata.get("skips") or failed != 0:
                            failures.append(
                                f"{name}: evidence result {passed}/{failed}/{skipped} "
                                f"does not match metadata {metadata.get('tests')}/0/{metadata.get('skips')}"
                            )
        # Keep the physical reference's stated gate count aligned with its
        # registry metadata; prose counts otherwise drift silently. This must
        # run before the requirements.txt early-continue because this is a C
        # reference and has no Python requirements file.
        if name == "physical-ai-edge-sentinel" and metadata_path.exists():
            readme_text = (ref / "README.md").read_text(encoding="utf-8")
            gate_count = re.search(r"gate result is \*\*(\d+) passed,\s*0 failed,\s*0 skipped", readme_text)
            if gate_count and int(gate_count.group(1)) != metadata.get("tests"):
                failures.append(
                    f"{name}: README gate count {gate_count.group(1)} does not match metadata {metadata.get('tests')}"
                )

        if line == "v2":
            check_v2(name, entry, ref, metadata, allowed_v2, failures)

        # Python references pin in requirements.txt. Others (the TypeScript
        # ones) pin in package.json and are checked by their own gate.
        requirements = ref / "requirements.txt"
        if not requirements.exists():
            continue

        if line == "v1":
            pinned = versions_in(requirements)
            if len(pinned) != 1:
                failures.append(f"{name}: expected exactly one pinned version in requirements.txt, found {sorted(pinned) or 'none'}")
                continue
            want = pinned.pop()

            for label, path in (("registry entry", entry), ("README", ref / "README.md")):
                found = versions_in(path)
                if not found:
                    failures.append(f"{name}: {label} names no Ratify version; expected {want}")
                elif found != {want}:
                    failures.append(f"{name}: {label} names {sorted(found)}, but requirements.txt pins {want}")


        # Every other pin, not just Ratify's. A reference states its tested
        # versions in prose, and prose does not move when a dependency does.
        # The rule is narrow on purpose: a document need not mention every pin,
        # but a version it does state has to be the one that is installed.
        pinned_all = dict(PIN.findall(requirements.read_text(encoding="utf-8")))
        evidence = ref / "evidence" / "reference-evidence.md"
        for label, path in (("README", ref / "README.md"), ("evidence", evidence)):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            stated = list(PIN.findall(text))
            stated += [
                (ROW_ALIASES[key.strip().lower()], version)
                for key, version in ROW.findall(text)
                if key.strip().lower() in ROW_ALIASES
            ]
            for package, version in stated:
                expected = pinned_all.get(package)
                if expected is not None and version != expected:
                    failures.append(
                        f"{name}: {label} says {package} {version}, "
                        f"but requirements.txt pins {expected}"
                    )

        # The evidence records a hash of the requirements it was captured
        # against. Nothing verified it, so changing a pin silently falsified a
        # cryptographic claim in a protocol project's own evidence.
        if evidence.exists():
            recorded = re.search(r"Requirements SHA-256 \| `([0-9a-f]{64})`",
                                 evidence.read_text(encoding="utf-8"))
            if recorded:
                actual = hashlib.sha256(requirements.read_bytes()).hexdigest()
                if recorded.group(1) != actual:
                    failures.append(
                        f"{name}: evidence records requirements SHA-256 "
                        f"{recorded.group(1)[:12]}..., but the file hashes to "
                        f"{actual[:12]}..."
                    )

    if failures:
        print("reference-version-sync: FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print("reference-version-sync: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
