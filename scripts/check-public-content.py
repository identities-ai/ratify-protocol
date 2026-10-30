#!/usr/bin/env python3
"""Fail if a tracked file carries text that does not belong in a public repository.

Everything in this repository is public: every file, every release archive and
every Go module zip. This check refuses correspondence (greetings, sign-offs,
subject lines), outreach and fundraising material, references to private
workspaces, local filesystem paths and personal email addresses. It cannot
judge intent, so it errs toward refusing; a genuine false positive is fixed by
rewording the text, not by widening an exception.

Usage: python3 scripts/check-public-content.py [path ...]
With no arguments it checks every file tracked by git.
"""

import re
import subprocess
import sys

# Files whose job is to state the rule, so they name what they forbid.
# .gitignore lists private paths precisely so they are never committed.
EXEMPT = {
    ".gitignore",
    "CONTRIBUTING.md",
    "scripts/check-public-content.py",
}

# Generated or third-party data rather than authored text. Only the generated
# vector JSON is exempt; any other file under testvectors/ is checked.
EXEMPT_PREFIXES = (
    "internal/tzdbv2/",
)
EXEMPT_GENERATED = re.compile(r"^testvectors/.*\.json$")

# Domains that may appear in addresses: documentation placeholders and the
# project's own addresses. SSH remotes (git@host), the generic user@ example
# and .local device logins are not mailboxes. Any other address is treated as
# personal.
ALLOWED_EMAIL_DOMAINS = re.compile(
    r"@(example\.(com|org|net)|[a-z0-9.-]+\.example|identities\.ai|ratifyprotocol\.com|users\.noreply\.github\.com)$",
    re.I,
)
ALLOWED_EMAIL_FORMS = re.compile(r"^(git|user)@|@[a-z0-9.-]+\.local$", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")

# Prose files, where a "Subject:" line reads as correspondence. In code it is
# usually a field name.
PROSE_SUFFIXES = (".md", ".mdx", ".txt", ".rst", ".html", ".eml")

RULES = [
    ("email subject line", re.compile(r"^\s*(\*\*)?subject:(\*\*)?\s+\S", re.I)),
    ("email greeting", re.compile(r"^\s*(?i:hi|hello|dear|hey)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)?\s*,")),
    ("email sign-off", re.compile(r"^\s*(best|best regards|kind regards|regards|thanks|thank you|cheers|warmly|sincerely)\s*,\s*$", re.I)),
    ("introduction request", re.compile(r"\b(could|can|would) you (please )?(connect|introduce) (me|us)\b|\bwarm intro", re.I)),
    ("outreach material", re.compile(r"\boutreach\b|\bcover (email|note|letter|communication)s?\b|\bcold email", re.I)),
    ("fundraising material", re.compile(r"\binvestors?\b|\bfundrais|\bpitch deck\b|\bterm sheet\b|\bvaluation\b|\bcap table\b", re.I)),
    ("internal tool name", re.compile(r"\b(codex|chatgpt)\b|\bclaude[ _-]?(code|ai|opus|sonnet|haiku)?\b(?!\.ai/)", re.I)),
    ("private workspace path", re.compile(r"\.memory/|products/ratify/|ratify-web\b|ratify-command\b|identitiesai/", re.I)),
    ("local filesystem path", re.compile(r"/Users/(?!runner/)[A-Za-z]|/home/[a-z][a-z0-9_-]+/|\b[A-Z]:\\Users\\", re.I)),
]


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
    return [p for p in out.decode().split("\0") if p]


def checked(path):
    return not (path in EXEMPT or path.startswith(EXEMPT_PREFIXES) or EXEMPT_GENERATED.match(path))


def read_text(path):
    """Return the file's lines, or None for a binary file. Unreadable files raise."""
    with open(path, "rb") as f:
        data = f.read()
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace").splitlines()


def main(argv):
    paths = argv or tracked_files()
    failures = []
    for path in paths:
        if not checked(path):
            continue
        try:
            lines = read_text(path)
        except OSError as err:
            failures.append(f"{path}: unreadable: {err}")
            continue
        if lines is None:
            continue
        for number, line in enumerate(lines, 1):
            for match in EMAIL.finditer(line):
                address = match.group(0)
                if not (ALLOWED_EMAIL_DOMAINS.search(address) or ALLOWED_EMAIL_FORMS.search(address)):
                    failures.append(f"{path}:{number}: email address: {address}")
            for label, pattern in RULES:
                if label == "email subject line" and not path.endswith(PROSE_SUFFIXES):
                    continue
                if pattern.search(line):
                    failures.append(f"{path}:{number}: {label}: {line.strip()[:120]}")
    if failures:
        print("public-content: text that does not belong in a public repository:")
        for failure in failures:
            print("  " + failure)
        print("Remove it, or reword it in project terms. See CONTRIBUTING.md.")
        return 1
    print(f"public-content: ok ({len(paths)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
