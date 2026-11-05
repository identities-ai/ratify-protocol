#!/usr/bin/env python3
"""Verify staged mobile assets and the tagged SwiftPM manifest."""

import hashlib
import json
import pathlib
import re
import subprocess
import sys


def fail(message):
    sys.exit(f"mobile staging: {message}")


if len(sys.argv) != 3:
    fail("usage: verify-mobile-staging.py v2.x.y dist/mobile")
tag, directory = sys.argv[1:]
files = pathlib.Path(directory)
manifest = json.loads((files / "manifest.json").read_text())
if not str(manifest.get("workflow_run") or "").isdigit():
    fail("candidate must come from a CI workflow run")
for name, info in manifest["artifacts"].items():
    data = (files / name).read_bytes()
    if len(data) != info["bytes"] or hashlib.sha256(data).hexdigest() != info["sha256"]:
        fail(f"{name} differs from the candidate manifest")

source = hashlib.sha256()
for entry in subprocess.check_output(["git", "ls-tree", "-r", "-z", "HEAD"]).split(b"\0"):
    if entry and entry.split(b"\t", 1)[1] != b"Package.swift":
        source.update(entry + b"\0")
if source.hexdigest() != manifest["source_except_package_sha256"]:
    fail("source differs from the built candidate outside Package.swift")

package = pathlib.Path("Package.swift").read_text()
url = f"https://github.com/identities-ai/ratify-protocol/releases/download/{tag}/RatifyProtocolFFI.xcframework.zip"
checksum = manifest["artifacts"]["RatifyProtocolFFI.xcframework.zip"]["sha256"]
if not re.search(rf'^let releaseAssetURL = "{re.escape(url)}"$', package, re.M):
    fail("SwiftPM URL does not name the staged release asset")
if not re.search(rf'^let releaseAssetChecksum = "{checksum}"$', package, re.M):
    fail("SwiftPM checksum differs from the staged archive")
print(f"mobile staging: ok ({tag}, source {manifest['commit'][:12]})")
