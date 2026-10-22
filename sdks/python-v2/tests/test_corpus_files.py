"""Every file in testvectors/v2 has a consumer, and every consumer reads it."""
from __future__ import annotations

import json

from corpus import CONSUMERS, CROSS_SDK_DIR, TESTS_DIR, V2_DIR

from ratify_protocol_v2.errors_v2 import ALL_ERROR_CLASSES


def test_every_corpus_file_has_a_consumer():
    present = {p.name for p in V2_DIR.iterdir() if p.is_file()}
    unknown = present - set(CONSUMERS)
    missing = set(CONSUMERS) - present
    assert not unknown, f"corpus files with no Python runner: {sorted(unknown)}"
    assert not missing, f"runner expects files that are absent: {sorted(missing)}"
    subdirs = {p.name for p in V2_DIR.iterdir() if p.is_dir()}
    assert subdirs <= {"cross-sdk"}, f"unexpected corpus directories: {sorted(subdirs)}"


def test_every_consumer_module_reads_its_file():
    for name, module in CONSUMERS.items():
        if module is None:
            continue
        path = TESTS_DIR / module
        assert path.is_file(), f"{name}: consumer {module} does not exist"
        assert f'"{name}"' in path.read_text(encoding="utf-8"), f"{name}: {module} never names the file"


def test_cross_sdk_directory_is_consumed():
    if not CROSS_SDK_DIR.exists():
        return
    module = TESTS_DIR / "test_cross_sdk_v2.py"
    assert module.is_file(), "cross-sdk fixtures exist but test_cross_sdk_v2.py does not"


# Vector members whose string value is an expected SPEC-v2 §2.7 error class;
# "outcomes" entries end in "/<class>" (Go v2ClassAssertionMembers).
CLASS_ASSERTION_MEMBERS = {"error_class", "expected_error_class", "expect_error_class", "expect", "device_error"}


def test_corpus_asserts_every_error_class():
    """Every class of the closed SPEC-v2 §2.7 list has a shared vector that
    expects it (Go TestV2CorpusAssertsEveryErrorClass)."""
    assert len(ALL_ERROR_CLASSES) == 49
    seen = set()

    def walk(v):
        if isinstance(v, dict):
            for k, child in v.items():
                if isinstance(child, str) and k in CLASS_ASSERTION_MEMBERS and child in ALL_ERROR_CLASSES:
                    seen.add(child)
                if k == "outcomes":
                    for o in child:
                        tail = o.rsplit("/", 1)[-1]
                        if "/" in o and tail in ALL_ERROR_CLASSES:
                            seen.add(tail)
                walk(child)
        elif isinstance(v, list):
            for child in v:
                walk(child)

    paths = sorted(V2_DIR.glob("*.json"))
    assert paths
    for path in paths:
        walk(json.loads(path.read_text(encoding="utf-8")))
    missing = sorted(ALL_ERROR_CLASSES - seen)
    assert not missing, f"no shared vector asserts these SPEC-v2 §2.7 classes: {missing}"
