#!/usr/bin/env python3
"""Sign the exact staged Kotlin files for a Central Portal bundle."""

import argparse
import hashlib
import pathlib
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET


def fail(message):
    raise SystemExit(f"mobile Central bundle: {message}")


parser = argparse.ArgumentParser()
parser.add_argument("version")
parser.add_argument("staging_zip", type=pathlib.Path)
parser.add_argument("output_zip", nargs="?", type=pathlib.Path)
parser.add_argument("--key", help="GPG key fingerprint")
parser.add_argument("--passphrase-file", type=pathlib.Path)
parser.add_argument("--check-only", action="store_true")
args = parser.parse_args()
if not args.check_only and (not args.output_zip or not args.key):
    fail("bundle output and signing key are required")

root = "mobile-staging/com/ratifyprotocol/"
artifacts = ("ratify-protocol", "ratify-protocol-testing")
primary_suffixes = (".aar", ".pom", "-sources.jar", "-javadoc.jar", ".module")
bundle = {}
with zipfile.ZipFile(args.staging_zip) as source:
    if len(source.namelist()) != len(set(source.namelist())):
        fail("duplicate zip entries")
    for artifact in artifacts:
        prefix = f"{root}{artifact}/{args.version}/{artifact}-{args.version}"
        for suffix in primary_suffixes:
            name = prefix + suffix
            try:
                data = source.read(name)
            except KeyError:
                fail(f"missing {name}")
            if not data:
                fail(f"empty {name}")
            if suffix == ".pom":
                pom = ET.fromstring(data)
                ns = {"m": "http://maven.apache.org/POM/4.0.0"}
                for field, value in (("groupId", "com.ratifyprotocol"),
                                     ("artifactId", artifact), ("version", args.version)):
                    if pom.findtext(f"m:{field}", namespaces=ns) != value:
                        fail(f"POM {field} mismatch: {name}")
            target = name.removeprefix("mobile-staging/")
            bundle[target] = data
            for algorithm in ("md5", "sha1"):
                checksum_name = name + "." + algorithm
                try:
                    checksum = source.read(checksum_name).decode().strip()
                except KeyError:
                    fail(f"missing {checksum_name}")
                if checksum != hashlib.new(algorithm, data).hexdigest():
                    fail(f"checksum mismatch: {checksum_name}")
                bundle[checksum_name.removeprefix("mobile-staging/")] = source.read(checksum_name)

if args.check_only:
    print(f"mobile Central bundle: checked {len(bundle)} staged files")
    raise SystemExit(0)

if args.key:
    with tempfile.TemporaryDirectory() as directory:
        directory = pathlib.Path(directory)
        for name, data in list(bundle.items()):
            if not name.endswith(primary_suffixes):
                continue
            path = directory / pathlib.Path(name).name
            path.write_bytes(data)
            sig = path.with_name(path.name + ".asc")
            command = ["gpg", "--batch", "--yes", "--armor", "--detach-sign",
                       "--local-user", args.key, "--output", str(sig)]
            if args.passphrase_file:
                command += ["--pinentry-mode", "loopback", "--passphrase-file",
                            str(args.passphrase_file)]
            subprocess.run(command + [str(path)], check=True)
            subprocess.run(["gpg", "--batch", "--verify", str(sig), str(path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            bundle[name + ".asc"] = sig.read_bytes()

args.output_zip.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(args.output_zip, "w", compression=zipfile.ZIP_DEFLATED) as out:
    for name, data in sorted(bundle.items()):
        out.writestr(name, data)
print(f"mobile Central bundle: {len(bundle)} files, {args.output_zip}")
