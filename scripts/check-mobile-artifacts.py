#!/usr/bin/env python3
"""Check the release XCFramework and AAR before either is uploaded."""

import pathlib
import plistlib
import sys
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
FRAMEWORK = ROOT / "sdks/swift/build/RatifyProtocolFFI.xcframework"
AAR = ROOT / "sdks/kotlin/ratify-protocol/build/outputs/aar/ratify-protocol-release.aar"
EXPECTED_APPLE = {
    ("macos", "", ("arm64", "x86_64")),
    ("ios", "", ("arm64",)),
    ("ios", "simulator", ("arm64", "x86_64")),
}
EXPECTED_ANDROID = {"arm64-v8a", "armeabi-v7a", "x86_64"}
TEST_HOOK = b"ratify_ffi_test_"


def main():
    info = plistlib.loads((FRAMEWORK / "Info.plist").read_bytes())
    actual = set()
    apple_sizes = {}
    for item in info["AvailableLibraries"]:
        platform = item["SupportedPlatform"]
        variant = item.get("SupportedPlatformVariant", "")
        archs = tuple(sorted(item["SupportedArchitectures"]))
        actual.add((platform, variant, archs))
        binary = FRAMEWORK / item["LibraryIdentifier"] / item["LibraryPath"]
        data = binary.read_bytes()
        assert data and TEST_HOOK not in data, f"test hook or empty Apple slice: {binary}"
        apple_sizes[item["LibraryIdentifier"]] = len(data)
    assert actual == EXPECTED_APPLE, f"Apple slices differ: {actual}"

    with zipfile.ZipFile(AAR) as archive:
        names = set(archive.namelist())
        expected = {f"jni/{abi}/libratify_protocol_ffi.so" for abi in EXPECTED_ANDROID}
        actual_native = {name for name in names if name.startswith("jni/") and name.endswith(".so")}
        assert actual_native == expected, f"Android ABIs differ: {actual_native}"
        assert "classes.jar" in names and "AndroidManifest.xml" in names, "AAR metadata missing"
        android_sizes = {}
        for name in expected:
            data = archive.read(name)
            assert data and TEST_HOOK not in data, f"test hook or empty Android library: {name}"
            android_sizes[name.split("/")[1]] = len(data)
    print("mobile artifacts: ok")
    for name, size in sorted(apple_sizes.items()):
        print(f"  Apple {name}: {size} bytes")
    for name, size in sorted(android_sizes.items()):
        print(f"  Android {name}: {size} bytes")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, FileNotFoundError, KeyError, plistlib.InvalidFileException, zipfile.BadZipFile) as exc:
        sys.exit(f"mobile artifacts: {exc}")
