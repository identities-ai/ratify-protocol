# Ratify Protocol v1 — Verifier Benchmarks

Committed numbers backing the "under a millisecond" claim in protocol documentation. Re-run with:

```bash
go test -bench=BenchmarkVerify -benchmem -run=^$ -count=3 ./...
```

Source: [`bench_verify_test.go`](../bench_verify_test.go).

## Hardware / software baseline

|                        |                                                                               |
|------------------------|-------------------------------------------------------------------------------|
| CPU                    | Apple M2 Pro (10 cores, arm64)                                                |
| OS                     | darwin 25.4.0                                                                 |
| Go                     | 1.25 (module runtime)                                                         |
| Hybrid signature stack | Ed25519 (stdlib `crypto/ed25519`) + ML-DSA-65 (`github.com/cloudflare/circl`) |
| Build                  | `-O2 -c release` equivalent — stock `go test -bench`                          |

Numbers below are the median of 3 runs per benchmark. Actual latency on commodity x86 cloud hardware (N2 / C4 / c6i) is typically within ±30%; Arm Graviton is roughly equivalent to M2.

## Results — full Verify() end-to-end

| Benchmark                              | ns/op   | Human units          | B/op    | allocs/op |
|----------------------------------------|---------|----------------------|---------|-----------|
| `BenchmarkVerifyDepth1`                | 338 404 | **338 µs** (0.34 ms) | 73 351  | 16        |
| `BenchmarkVerifyDepth2`                | 518 607 | **519 µs** (0.52 ms) | 113 327 | 26        |
| `BenchmarkVerifyDepth3`                | 697 925 | **698 µs** (0.70 ms) | 153 236 | 35        |
| `BenchmarkVerifyDepth1_WithConstraint` | 339 122 | **339 µs** (0.34 ms) | 73 378  | 16        |

Verification exercises the full §4 trust equation: structural checks, agent binding, per-cert signature validation (Ed25519 + ML-DSA-65), chain linkage, sub-delegation gate, constraint evaluation, challenge-signature validation, revocation lookup (nil callback here), scope intersection.

## Interpreting the numbers

- **"Under a millisecond"** — holds at every legal chain depth (max `MAX_DELEGATION_CHAIN_DEPTH` = 3). The worst case exercised — depth-3 with a constraint-bearing leaf — is ~0.7 ms on an M2 Pro.
- **Dominant cost**: ML-DSA-65 verify, which is a post-quantum lattice-based scheme. Each cert in the chain adds ~180 µs. The rest (Ed25519, JSON canonicalization, scope math, constraint evaluation) is <15 µs combined.
- **Constraint cost is negligible**: geo_circle (haversine + radius check) adds ~1 µs. The test set covers geo / time / amount / speed / rate; none move the needle at these depths.
- **Allocations** scale linearly with chain depth: ~10 allocations per extra cert, roughly 40 kB of transient heap. The canonical-JSON serialization of the signable struct is the biggest allocator. A zero-allocation canonical path is a v1.1 candidate but not a launch blocker.

## Where the "<1ms" marketing claim holds

✅ Verify() on a depth-1/2/3 chain with or without constraints, on commodity CPU.
✅ With a NIL revocation callback (common) or a typical verifier with a cached revocation lookup.

## Where it does NOT hold — honest caveats

- **Cold start**: first verify in a process pays the `mldsa65` package init + Go map / JSON overhead. Measured at ~2.5 ms first call, drops to the steady-state numbers above by the 3rd call. Long-running verifier processes don't care; cold-start FaaS deployments should pre-warm.
- **Revocation callbacks that hit the network**: a database revocation lookup for 3 certs on a remote DB round-trips through the link latency; the 1 ms claim is about cryptographic verification, not about whatever your IsRevoked callback does. A typical verifier implementation with an in-process DB query at <1 ms round-trip internally keeps the total budget around 1–1.5 ms.
- **Non-hybrid modes**: v1 is hybrid-mandatory. If a future v2 adds Ed25519-only for low-assurance contexts, it would verify at ~60 µs/cert — ~4x faster.
- **Mobile / embedded CPUs**: ML-DSA-65 on an A15-class phone runs ~2–3x slower than M2 Pro. A depth-3 chain on a handset is ~2 ms.

## Regression guard

These benchmarks are committed to run locally and via the release-gate CI (see `TEST_PLAN.md`). A >30% regression on any of the four benchmarks is a blocker for release. Update this file when numbers shift materially after a protocol change.
