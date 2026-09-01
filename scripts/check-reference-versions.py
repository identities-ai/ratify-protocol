#!/usr/bin/env python3
"""Assert every reference states one SDK version consistently.

A reference names its Ratify version in three places: the dependency it
installs, the registry entry a reader consults, and its own README. They drift
silently, and the drift is only visible when someone runs the gate months later
against a version the metadata never claimed. This makes disagreement a
failure instead.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"1\.0\.0a\d+")
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


def main() -> int:
    failures: list[str] = []
    registry_dir = ROOT / "references" / "registry"
    if not registry_dir.exists():
        print("reference-version-sync: no registry directory; nothing to check")
        return 0

    for entry in sorted(registry_dir.glob("*.md")):
        name = entry.stem
        ref = ROOT / "references" / name
        metadata_path = ref / "ratify-reference.json"
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            evidence = ref / metadata.get("evidence", "docs/evidence.md")
            if "tests" in metadata or "skips" in metadata:
                if not evidence.exists():
                    failures.append(f"{name}: evidence file missing: {evidence}")
                else:
                    evidence_text = evidence.read_text(encoding="utf-8")
                    match = re.search(
                        r"Result:\s*(\d+) passed,\s*(\d+) failed,\s*(\d+) skipped",
                        evidence_text,
                    )
                    if not match:
                        failures.append(f"{name}: evidence has no parseable test result")
                    else:
                        passed, failed, skipped = map(int, match.groups())
                        if passed != metadata.get("tests") or skipped != metadata.get("skips") or failed != 0:
                            failures.append(
                                f"{name}: evidence result {passed}/{failed}/{skipped} "
                                f"does not match metadata {metadata.get('tests')}/0/{metadata.get('skips')}"
                            )
        # Python references pin in requirements.txt. Others (the TypeScript
        # ones) pin in package.json and are checked by their own gate.
        requirements = ref / "requirements.txt"
        if not requirements.exists():
            continue

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
