"""Write testvectors/v2/cross-sdk/python.json (SPEC-v2 §8.1).

Run from sdks/python-v2 with the native extension installed:

    python tests/gen_cross_sdk_fixture.py [--out PATH]

Every run uses fresh random keys and hedged ML-DSA-65 signatures, so the
output is never byte-reproducible. The fixture is verified before it is
written.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import CROSS_SDK_DIR  # noqa: E402
from cross_sdk_v2 import build_fixture  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=CROSS_SDK_DIR / "python.json")
    args = parser.parse_args()
    fixture = build_fixture()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(fixture['objects'])} objects)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
