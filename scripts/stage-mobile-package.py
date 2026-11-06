#!/usr/bin/env python3
"""Set the SwiftPM binary URL and checksum from a built mobile candidate."""

import hashlib
import json
import pathlib
import re
import subprocess
import sys


def fail(message):
    sys.exit(f"stage-mobile-package: {message}")


if len(sys.argv) != 4:
    fail("usage: stage-mobile-package.py v2.x.y manifest.json RatifyProtocolFFI.xcframework.zip")

tag, manifest_path, archive_path = sys.argv[1:]
if not re.fullmatch(r"v2\.\d+\.\d+-(?:alpha|beta|rc)\.\d+", tag):
    fail("expected a v2 prerelease tag")
manifest = json.loads(pathlib.Path(manifest_path).read_text())
if not str(manifest.get("workflow_run") or "").isdigit():
    fail("candidate must come from a CI workflow run")
archive = pathlib.Path(archive_path)
name = "RatifyProtocolFFI.xcframework.zip"
if archive.name != name:
    fail(f"expected {name}")
if (archive.stat().st_size != manifest["artifacts"][name]["bytes"] or
        hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["artifacts"][name]["sha256"]):
    fail("archive checksum differs from candidate manifest")
head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
if (head, tree) != (manifest["commit"], manifest["tree"]):
    fail("candidate was not built from this release version commit")

package = pathlib.Path("Package.swift")
source = package.read_text()
url = f"https://github.com/identities-ai/ratify-protocol/releases/download/{tag}/{name}"
checksum = manifest["artifacts"][name]["sha256"]
for key, value in (("releaseAssetURL", url), ("releaseAssetChecksum", checksum)):
    old = f'let {key} = ""'
    if source.count(old) != 1:
        fail(f"expected one unstaged {key} placeholder")
    source = source.replace(old, f'let {key} = "{value}"')
package.write_text(source)
print(f"staged {tag} SwiftPM asset {checksum}")
