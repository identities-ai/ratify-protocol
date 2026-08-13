import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ratify_protocol import decode_proof_bundle
from ratify_rust_accel import verify_bundle_object

ROOT = Path(__file__).resolve().parents[2]
fixture = json.loads((ROOT / "testvectors/v1/happy_path_depth_3.json").read_text())
bundle = decode_proof_bundle(json.dumps(fixture["bundle"], separators=(",", ":")))
options = json.dumps(fixture["expected"]["verify_options"], separators=(",", ":"))
calls = 2_000


def run(count):
    for _ in range(count):
        verify_bundle_object(bundle, options)


start = time.perf_counter()
run(calls)
serial = time.perf_counter() - start

start = time.perf_counter()
with ThreadPoolExecutor(max_workers=4) as executor:
    list(executor.map(run, [calls // 4] * 4))
parallel = time.perf_counter() - start

print(f"serial_s={serial:.4f} parallel_s={parallel:.4f} speedup={serial / parallel:.2f}x")
if parallel >= serial * 0.90:
    raise SystemExit("native verification did not demonstrate parallel execution")
