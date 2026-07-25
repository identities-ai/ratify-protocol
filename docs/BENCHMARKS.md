# Ratify Protocol v1 — Verifier Benchmarks

Committed numbers backing the performance claims in protocol documentation — including the per-SDK verify-latency matrix and the wire-size table. The headline "under a millisecond" claim is about the compiled verifiers (Go, Rust, C); the per-SDK matrix below states what every SDK actually measures. Re-run the Go baseline with:

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
| `BenchmarkVerifyDepth1`                | 392 114 | **392 µs** (0.39 ms) | 88 728  | 197       |
| `BenchmarkVerifyDepth2`                | 614 381 | **614 µs** (0.61 ms) | 144 170 | 395       |
| `BenchmarkVerifyDepth3`                | 831 972 | **832 µs** (0.83 ms) | 199 621 | 592       |
| `BenchmarkVerifyDepth1_WithConstraint` | 397 836 | **398 µs** (0.40 ms) | 90 547  | 270       |

> Numbers refreshed 2026-07-25 (same M2 Pro baseline). The increase over the previously committed table (~0.34/0.70 ms at depth 1/3) is the cost of correctness features added since: scope-vocabulary validation (§9, alpha.12), strict wire acceptance, and the additional verifier checks landed through alpha.15. Still under a millisecond at every legal depth.

Verification exercises the full §4 trust equation: structural checks, agent binding, per-cert signature validation (Ed25519 + ML-DSA-65), chain linkage, sub-delegation gate, constraint evaluation, challenge-signature validation, revocation lookup (nil callback here), scope intersection.

## Interpreting the numbers

- **"Under a millisecond"** — holds at every legal chain depth (max `MAX_DELEGATION_CHAIN_DEPTH` = 3) for the Go reference verifier. The worst case exercised — depth-3 — is ~0.83 ms on an M2 Pro. Other SDKs differ; see the per-SDK matrix below.
- **Dominant cost**: ML-DSA-65 verify, which is a post-quantum lattice-based scheme. Each cert in the chain adds ~180 µs. The rest (Ed25519, JSON canonicalization, scope math, constraint evaluation) is <15 µs combined.
- **Constraint cost is negligible**: geo_circle (haversine + radius check) adds ~1 µs. The test set covers geo / time / amount / speed / rate; none move the needle at these depths.
- **Allocations** scale linearly with chain depth: ~10 allocations per extra cert, roughly 40 kB of transient heap. The canonical-JSON serialization of the signable struct is the biggest allocator. A zero-allocation canonical path is a v1.1 candidate but not a launch blocker.

## Per-SDK verify latency

The five SDKs implement the same protocol but sit on different cryptographic stacks, and the difference is dominated by one thing: whether ML-DSA-65 runs as compiled native code or as pure-language code. Measured on the same M2 Pro baseline, same workload (single fixed bundle verified in a loop after warm-up; median of runs; full `Verify` path with a required scope):

| SDK | ML-DSA-65 backend | Depth-1 verify | Depth-3 verify | vs Go |
|---|---|---|---|---|
| Go (reference) | `cloudflare/circl` (native) | 0.39 ms | 0.83 ms | 1× |
| Rust | native | 0.36 ms | 0.74 ms | ~0.9× |
| C / C++ | thin FFI over the Rust core | ≈ Rust | ≈ Rust | ~0.9× |
| Python | `pqcrypto` (compiled wheel) | 1.0 ms | 2.5 ms | ~2.6–3× |
| TypeScript (Node) | `@noble/post-quantum` (pure JS) | 7.4 ms | 14.9 ms | ~19× |

Read this table before quoting a latency number for your deployment:

- **"Under a millisecond" is a Go/Rust/C claim.** Python is single-digit milliseconds; TypeScript is tens of milliseconds per full chain verification. All are documented behavior, not defects — pure-JS lattice math is simply slower.
- **TypeScript deployments should verify on session tokens, not full chains, per turn** (see below): the fast path replaces per-turn chain verification with an HMAC check plus one hybrid challenge-signature verification, which brings TS per-turn cost down by roughly an order of magnitude.
- Numbers scale with single-core performance; commodity x86 cloud hardware is typically within ±30% of this baseline.

## Wire sizes

Hybrid signatures are big — ML-DSA-65 signatures are 3 309 bytes and public keys 1 952 bytes, so every cert carries both plus base64 overhead. Measured JSON encodings (canonical wire form, fresh keys):

| Object | JSON bytes | base64(JSON), as carried by the §13 HTTP binding |
|---|---|---|
| Single `DelegationCert` | ~10.2 kB | — |
| `ProofBundle`, depth 1 | ~17.6 kB | ~23.4 kB |
| `ProofBundle`, depth 2 | ~27.7 kB | ~37.0 kB |
| `ProofBundle`, depth 3 | ~37.9 kB | ~50.6 kB |
| `SessionToken` | ~3.0 kB | — |
| Per-turn `HybridSignature` (streamed turn) | ~4.5 kB | — |

The practical consequence: a full proof bundle is a per-session artifact, not a per-message one. A streamed turn (challenge + timestamp + hybrid signature against a cached session token) moves ~4.6 kB instead of ~18–51 kB.

## Session tokens are the default for repeated interactions

A full chain verification per turn is the wrong integration shape for anything conversational — voice calls, streams, multi-turn agent sessions. The intended pattern (§5.13) is: verify the full `ProofBundle` once at session start, issue a `SessionToken`, then verify each subsequent turn against the token — an HMAC check plus one fresh hybrid challenge signature, roughly 95% less per-turn cryptographic work and an order-of-magnitude smaller per-turn wire footprint. Since alpha.15, the streamed-turn verifier enforces required scope, single-use challenges, and session/stream bindings on that fast path (§5.13), so choosing it does not mean giving up verification controls. Treat per-turn full-chain verification as the special case (high-stakes actions that demand fresh revocation semantics via full `Verify` + `ForceRevocationCheck`), not the default.

## Where the "<1 ms" claim holds

✅ Verify() on a depth-1/2/3 chain with or without constraints, on commodity CPU — **in the Go, Rust, and C SDKs**.
✅ With a NIL revocation callback (common) or a typical verifier with a cached revocation lookup.

## Where it does NOT hold — honest caveats

- **Cold start**: first verify in a process pays the `mldsa65` package init + Go map / JSON overhead. Measured at ~2.5 ms first call, drops to the steady-state numbers above by the 3rd call. Long-running verifier processes don't care; cold-start FaaS deployments should pre-warm.
- **Revocation callbacks that hit the network**: a database revocation lookup for 3 certs on a remote DB round-trips through the link latency; the 1 ms claim is about cryptographic verification, not about whatever your IsRevoked callback does. A typical verifier implementation with an in-process DB query at <1 ms round-trip internally keeps the total budget around 1–1.5 ms.
- **Non-hybrid modes**: v1 is hybrid-mandatory. If a future v2 adds Ed25519-only for low-assurance contexts, it would verify at ~60 µs/cert — ~4x faster.
- **Mobile / embedded CPUs**: ML-DSA-65 on an A15-class phone runs ~2–3x slower than M2 Pro. A depth-3 chain on a handset is ~2 ms.

## Regression guard

These benchmarks are committed to run locally and via the release-gate CI (see `TEST_PLAN.md`). A >30% regression on any of the four benchmarks is a blocker for release. Update this file when numbers shift materially after a protocol change.
