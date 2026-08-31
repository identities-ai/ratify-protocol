#!/usr/bin/env python3
"""Assert every reference README follows the required structure.

The structure is defined in references/REFERENCE-README-STANDARD.md. A README
that drifts from it is not a style problem: a reference is read by someone who
has not decided they have this problem yet, and the sections exist to answer
their questions in the order they ask them.

This checks what can be checked mechanically. It cannot tell whether the prose
is any good, only whether the required parts are present.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    (re.compile(r"^## .*\b(why|need)\b", re.I | re.M), "a 'why would anyone need this' section"),
    (re.compile(r"^## Who implements what\s*$", re.I | re.M), "a 'Who implements what' section"),
    (re.compile(r"^## .*\bproves\b", re.I | re.M), "a 'what the reference proves' section"),
    (re.compile(r"^## .*(limitation|not claim|production)", re.I | re.M), "a limitations section"),
]

MERMAID = re.compile(r"```mermaid(.*?)```", re.S)


def check(readme: Path) -> list[str]:
    text = readme.read_text(encoding="utf-8")
    name = readme.relative_to(ROOT)
    problems = []

    for pattern, description in REQUIRED:
        if not pattern.search(text):
            problems.append(f"{name}: missing {description}")

    diagrams = MERMAID.findall(text)
    if len(diagrams) < 2:
        problems.append(f"{name}: needs at least 2 mermaid diagrams, found {len(diagrams)}")

    # Semicolons separate statements in a sequence diagram, so one inside a
    # message ends the message early and the rest is parsed as a new statement.
    # GitHub then renders "Unable to render rich display" instead of the
    # diagram, which is invisible in review and obvious to every reader.
    for i, block in enumerate(diagrams):
        for line in block.split("\n"):
            if ";" in line and "->" in line:
                problems.append(
                    f"{name}: diagram {i + 1} has a semicolon inside a message, "
                    f"which stops it rendering: {line.strip()}"
                )

    # A diagram that shows only the authorized path is marketing. At least one
    # must carry both outcomes.
    joined = " ".join(diagrams).lower()
    if diagrams and not ("deny" in joined and "allow" in joined):
        problems.append(f"{name}: no diagram shows both the allow and deny branches")

    # The endorsement status has to be stated, not implied.
    # The sentence usually wraps, so match across newlines.
    if not re.search(r"not an?\s[\s\S]{0,60}?(partnership|endorsed|approved|reference architecture)", text, re.I):
        problems.append(f"{name}: does not state its endorsement status plainly")

    return problems


def main() -> int:
    readmes = sorted(
        p for p in ROOT.glob("references/*/README.md")
        if p.parent.name != "registry"
    )
    if not readmes:
        print("reference-readme-structure: no reference READMEs found")
        return 0

    problems = [msg for r in readmes for msg in check(r)]
    if problems:
        print("reference-readme-structure: FAIL")
        for msg in problems:
            print(f"  {msg}")
        print("\n  See references/REFERENCE-README-STANDARD.md")
        return 1

    print(f"reference-readme-structure: ok ({len(readmes)} reference README(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
