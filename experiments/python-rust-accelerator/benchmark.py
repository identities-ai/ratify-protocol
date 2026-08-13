import json
import statistics
import time
from pathlib import Path

from ratify_protocol import VerifyOptions, decode_proof_bundle, encode_proof_bundle, verify_bundle
from ratify_rust_accel import verify_bundle_json, verify_bundle_object

ROOT = Path(__file__).resolve().parents[2]
fixture = json.loads((ROOT / "testvectors/v1/happy_path_depth_1.json").read_text())
bundle_json = json.dumps(fixture["bundle"], separators=(",", ":"))
options = fixture["expected"]["verify_options"]
options_json = json.dumps(options, separators=(",", ":"))
python_bundle = decode_proof_bundle(bundle_json)
python_options = VerifyOptions(required_scope=options["required_scope"], now=options["now"])


def measure(call, iterations=2_000):
    for _ in range(100):
        call()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        call()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return statistics.median(samples), statistics.quantiles(samples, n=100)[94]


def repeated(call, rounds=5):
    values = [measure(call) for _ in range(rounds)]
    return statistics.median(v[0] for v in values), statistics.median(v[1] for v in values)


python_stats = repeated(lambda: verify_bundle(python_bundle, python_options))
native_cached_stats = repeated(lambda: verify_bundle_json(bundle_json, options_json))
native_api_stats = repeated(lambda: verify_bundle_json(encode_proof_bundle(python_bundle), options_json))
native_object_stats = repeated(lambda: verify_bundle_object(python_bundle, options_json))
print("implementation,median_ms,p95_ms")
print(f"python,{python_stats[0]:.4f},{python_stats[1]:.4f}")
print(f"rust_native_cached_wire,{native_cached_stats[0]:.4f},{native_cached_stats[1]:.4f}")
print(f"rust_native_same_api,{native_api_stats[0]:.4f},{native_api_stats[1]:.4f}")
print(f"rust_native_direct_object,{native_object_stats[0]:.4f},{native_object_stats[1]:.4f}")
print(f"direct_object_median_speedup,{python_stats[0] / native_object_stats[0]:.2f}x")
print(f"direct_object_p95_speedup,{python_stats[1] / native_object_stats[1]:.2f}x")
if python_stats[0] / native_object_stats[0] < 1.30 or python_stats[1] / native_object_stats[1] < 1.30:
    raise SystemExit("Python native accelerator did not clear the 1.30x median and p95 gates")
