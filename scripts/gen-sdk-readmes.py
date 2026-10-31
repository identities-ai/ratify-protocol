#!/usr/bin/env python3
"""Generate sdks/*/README.md from the shared preamble and per-SDK bodies.

Every SDK README is the same document shape: a shared preamble (what the
protocol is, the hybrid-signature guarantee, the v1.1 feature set, the doc
links) followed by SDK-specific content (install, quickstart, API notes).
Before this generator existed the preamble was copy-pasted five times and
drifted — factual fixes landed in some copies and not others.

Sources:
  sdks/readme-src/preamble.md   shared preamble (placeholders below)
  sdks/<lang>/README.body.md    per-SDK content, appended after the preamble

Placeholders (valid in both preamble and bodies):
  {{TITLE}}         README h1 for this SDK
  {{SDK_DESC}}      e.g. "TypeScript reference SDK"
  {{SIBLINGS}}      the other four SDKs, prose list
  {{VERSION}}       this SDK's line version, npm/cargo form   (2.0.0-alpha.N)
  {{VERSION_TAG}}   this SDK's line version, tag form         (v2.0.0-alpha.N)
  {{VERSION_PYPI}}  this SDK's line version, PEP 440 form     (2.0.0aN)
  {{PROTOCOL_LINES}} which protocol lines this package implements

Every SDK in this tree is on the v2 line and takes its version from
sdks/typescript/package.json, the same manifest scripts/release.sh bumps.
Python's distribution carries v1 at the package root and v2 at
ratify_protocol.v2; its pyproject.toml is held to the same line by
scripts/check-release-sync.sh. A release bump plus a regenerate
keeps every README pin correct. scripts/check-release-sync.sh runs this script's
--check mode and fails the gate when a generated file drifts from its
sources; edit the sources, never README.md.

Usage: python3 scripts/gen-sdk-readmes.py [--check]
  --check  regenerate in memory and exit 1 on drift, changing nothing
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

MARKER = (
    "<!-- GENERATED FILE — do not edit directly.\n"
    "     Sources: sdks/readme-src/preamble.md + README.body.md in this directory.\n"
    "     Regenerate: python3 scripts/gen-sdk-readmes.py -->\n"
)

ALL_NAMES = {
    "go": "Go",
    "typescript": "TypeScript",
    "python": "Python",
    "rust": "Rust",
    "c": "C/C++",
}

SDKS = {
    "go": {
        "TITLE": "Ratify Protocol Go SDK",
        "SDK_DESC": "Go reference implementation",
    },
    "typescript": {
        "TITLE": "@identities-ai/ratify-protocol",
        "SDK_DESC": "TypeScript reference SDK",
    },
    "python": {
        "TITLE": "ratify-protocol",
        "SDK_DESC": "Python reference SDK",
    },
    "rust": {
        "TITLE": "ratify-protocol (Rust)",
        "SDK_DESC": "Rust reference SDK",
    },
    "c": {
        "TITLE": "Ratify Protocol C/C++ SDK",
        "SDK_DESC": "C and C++ reference SDK",
    },
}


V2_LINES = (
    "This package also implements Protocol v2 (version `{{VERSION}}`, a "
    "prerelease) and runs every file in the shared `testvectors/v2` corpus "
    "and the cross-SDK fixtures of every other SDK."
)
PROTOCOL_LINES = {
    "go": V2_LINES,
    "typescript": V2_LINES,
    "rust": V2_LINES,
    "c": V2_LINES,
    "python": (
        "This package implements Protocol v1 at `ratify_protocol` and Protocol "
        "v2 (version `{{VERSION}}`, a prerelease) at `ratify_protocol.v2`, "
        "installed with the `protocol-v2` extra. The v2 module runs every file "
        "in the shared `testvectors/v2` corpus and the cross-SDK fixtures of "
        "every other SDK."
    ),
}


def siblings(lang: str) -> str:
    names = [ALL_NAMES[k] for k in ALL_NAMES if k != lang]
    return ", ".join(names[:-1]) + ", and " + names[-1]


def versions(lang: str) -> dict:
    pkg = json.loads((ROOT / "sdks/typescript/package.json").read_text())
    v = pkg["version"]  # 2.0.0-alpha.N
    pypi = re.sub(r"-alpha\.(\d+)", r"a\1", v)
    pypi = re.sub(r"-beta\.(\d+)", r"b\1", pypi)
    pypi = re.sub(r"-rc\.(\d+)", r"rc\1", pypi)
    return {"VERSION": v, "VERSION_TAG": "v" + v, "VERSION_PYPI": pypi}


def render(lang: str) -> str:
    preamble = (ROOT / "sdks/readme-src/preamble.md").read_text()
    body = (ROOT / f"sdks/{lang}/README.body.md").read_text()
    out = MARKER + preamble.rstrip("\n") + "\n\n" + body
    out = out.replace("{{PROTOCOL_LINES}}", PROTOCOL_LINES[lang])
    subs = {**SDKS[lang], "SIBLINGS": siblings(lang), **versions(lang)}
    for key, value in subs.items():
        out = out.replace("{{" + key + "}}", value)
    leftover = re.findall(r"\{\{[A-Z_]+\}\}", out)
    if leftover:
        raise SystemExit(f"gen-sdk-readmes: unresolved placeholders in {lang}: {leftover}")
    return out


def main() -> int:
    check = "--check" in sys.argv
    drift = []
    for lang in SDKS:
        target = ROOT / f"sdks/{lang}/README.md"
        rendered = render(lang)
        if check:
            if not target.exists() or target.read_text() != rendered:
                drift.append(str(target))
        else:
            target.write_text(rendered)
            print(f"generated {target.relative_to(ROOT)}")
    if drift:
        print("readme-sync: DRIFT — regenerate with scripts/gen-sdk-readmes.py:", file=sys.stderr)
        for d in drift:
            print(f"  {d}", file=sys.stderr)
        return 1
    if check:
        print("readme-sync: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
