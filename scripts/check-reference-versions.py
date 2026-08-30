#!/usr/bin/env python3
"""Assert every reference states one SDK version consistently.

A reference names its Ratify version in three places: the dependency it
installs, the registry entry a reader consults, and its own README. They drift
silently, and the drift is only visible when someone runs the gate months later
against a version the metadata never claimed. This makes disagreement a
failure instead.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"1\.0\.0a\d+")


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

    if failures:
        print("reference-version-sync: FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print("reference-version-sync: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
