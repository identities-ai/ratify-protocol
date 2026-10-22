"""Every file in testvectors/v2 has a consumer, and every consumer reads it."""
from __future__ import annotations

from corpus import CONSUMERS, CROSS_SDK_DIR, TESTS_DIR, V2_DIR


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
