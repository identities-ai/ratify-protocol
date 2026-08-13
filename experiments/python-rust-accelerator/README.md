# Python Rust accelerator experiment

This directory is a private feasibility experiment. It is not part of the
Python SDK, is not packaged, and does not change the public API.

The native module moves strict bundle decoding and the complete built-in
verification path across one PyO3 call. The existing Python implementation
remains the comparison oracle. Python callbacks and providers remain on the
Python path because crossing the FFI boundary for them would add complexity
and change failure behavior.

## Ship gate

This work is only a candidate for integration if all of these hold:

1. Every applicable conformance vector returns the same security decision and
   result fields as the Python SDK.
2. Malformed input and native panics fail closed without terminating Python.
3. Existing policy, audit, anchor, challenge-store, revocation-provider, and
   custom-constraint callbacks retain the current Python behavior through an
   explicit fallback.
4. Median and p95 verification latency improve by at least 30 percent on the
   supported platform matrix, including wheel installation tests.
5. The public Python API and wire behavior do not change.

Until every gate is automated and green, this branch must not be merged or
released.

## Initial local result

Apple Silicon, CPython 3.11, release build, depth-1 conformance vector:

| Path | Median | p95 |
| --- | ---: | ---: |
| Current Python SDK | 1.0230 ms | 1.2775 ms |
| Rust native direct-object experiment | 0.4186 ms | 0.5196 ms |

The native path was 2.44x faster at the median and 2.31x faster at p95. This
is feasibility evidence only. It does not satisfy the platform and packaging
ship gates above.
