# TypeScript Rust accelerator experiment

This is a feasibility experiment, not a package or SDK change. It passes the
existing JavaScript bundle through one native Node call and compares the result
against the TypeScript reference implementation.

It must not ship unless every applicable conformance vector matches, malformed
input and native failures remain contained, callbacks have an explicit
TypeScript fallback, clean package installation works on every supported Node
platform, and median and p95 verification improve by at least 5x.

## Initial local result

Apple Silicon, Node 22, release build, depth-1 conformance vector:

| Path | Median | p95 |
| --- | ---: | ---: |
| Current TypeScript SDK | 7.2917 ms | 9.2752 ms |
| Rust native experiment | 0.5118 ms | 0.6944 ms |

The native path was 14.25x faster at the median and 13.36x faster at p95.
All 62 applicable verification vectors matched and malformed inputs remained
contained. The unchanged TypeScript suite passed 416 tests with no skips.
This is feasibility evidence only until the platform and packaging gates pass.

The releasable path must use an async napi worker task. The synchronous native
function remains a benchmark control only because it blocks the Node event loop.
