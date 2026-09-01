# Pi 2 hardware smoke test

Satisfies the PRD non-functional requirement to measure and publish depth-1
hybrid verification latency and peak memory on the actual Raspberry Pi 2, and
confirms on the target that the trust anchor (FR5) is an application duty the
SDK cannot perform for you.

This is a measurement tool, not the edge verifier. No listener, no actuator
path, no challenge store, no policy.

## What it asserts

1. A depth-1 bundle granting `physical:actuate` verifies, and the verified
   `human_id` equals the pinned operator id.
2. **An attacker's own root also verifies.** The rogue bundle returns
   `valid=1, status=authorized_agent`; only the `human_id` comparison rejects it.
   If this check ever reports `valid=0`, the assumption behind FR5 changed and
   the PRD needs revisiting.

Then it measures min/median/mean/p95/max verify latency and peak RSS.

## Run it

```sh
make vendor      # fetch and extract the alpha.18 armv7 artifact
make             # build against vendor/ratify-c
./smoke 200      # 200 measured iterations after 5 warm-up
make footprint   # library sizes for the evidence record
```

`make vendor` needs network. For an offline Pi, copy
`ratify-c-v1.0.0-alpha.18-linux-armv7.tar.gz` across and extract it into
`vendor/ratify-c` by hand; nothing else is fetched, and the Pi builds no Rust
and needs no Docker.

`make STATIC=1` links `libratify_c.a` instead of the shared object. Build both
and record the footprint of each: the archive is 30.8 MB and the shared object
2.1 MB before linking, and the PRD asks for the shared library to be preferred
once its runtime footprint is measured.

## Record in the evidence package

- `ratify_version()` as printed, confirming the linked artifact
- bundle size in bytes (expect ~17.5 kB at depth 1)
- the full latency table, labelled with the Pi model, OS, and CPU clock
- peak RSS in KiB
- `make footprint` output for both link modes
- whether the shared-library link resolved without `LD_LIBRARY_PATH`

Publish the Pi numbers. Do not substitute the desktop figures from the
protocol's `docs/BENCHMARKS.md`.

## Measured on the target: Raspberry Pi 2 Model B V1.1

Raspbian GNU/Linux 13 (trixie) 32-bit, ARMv7 rev 5 (v7l), 4 cores, 921 MiB RAM.
Ratify 1.0.0-alpha.18 armv7 artifact, 200 iterations after 5 warm-up.
Full capture in `pi2-evidence.txt`.

| | alpha.18 shared | alpha.17 shared | alpha.17 static |
|---|---:|---:|---:|
| min | 24350 us | 24118 us | 24394 us |
| **median** | **24718 us** | **24446 us** | **24694 us** |
| mean | 24809 us | 24523 us | 24769 us |
| p95 | 25475 us | 24862 us | 25154 us |
| max | 27017 us | 26551 us | 27288 us |
| peak RSS | 3688 KiB | 3844 KiB | 3172 KiB |

The alpha.17 columns are kept because the comparison is the point: the SDK
surface work between the two releases did not move verification cost on this
device. The run-to-run spread here is larger than the difference between them.

Both assertions pass on the target, including the attacker-root check.
`sizeof(void*)` is 4, confirming the 32-bit build. Bundle size 17572 bytes.

The shared link resolves through the Makefile's `-Wl,-rpath` with no
`LD_LIBRARY_PATH`. Library footprint: `libratify_c.so` 2.06 MB,
`libratify_c.a` 30.8 MB; the statically linked `smoke` binary is 2.57 MB total
(1.61 MB text, 0.96 MB data). Shared is the better default, as the PRD expects,
and static costs about 250 us more per verify here.

### What the number means for the design

**A depth-1 hybrid verification costs about 24.5 ms on this device.** That is
roughly 31x the arm64 development host and about 63x the 0.39 ms Go/M2 Pro figure
in `docs/BENCHMARKS.md`. It is a comfortable budget for beacon and valve actions on
human timescales, and it is not a per-turn budget for anything conversational.

It also bounds the unauthenticated request path: a single core can complete about
41 full verifications per second, so an attacker who can reach the listener can
saturate the CPU at a very low request rate. The design already answers this and
should say so explicitly — SPEC §10 step 2b rejects a challenge that this verifier
did not issue *before* any signature work, so flood traffic bearing forged or
absent challenges is refused at lookup cost rather than at 24 ms each. The
expensive path is reachable only by a caller holding a live Pi-issued challenge.
Pair that with the 128 KiB body bound (FR-level) and a connection rate limit.

## Baseline from a development host

Run on macOS arm64 against the alpha.17 `macos-aarch64` artifact, static
link, 200 iterations, for comparison only. Not re-run for alpha.18; the Pi
numbers above are the ones that matter:

```text
Ratify 1.0.0-alpha.17
bundle size:     17572 bytes
depth-1 verify, pinned root                    PASS (valid=1 status=authorized_agent anchor=match)
attacker root: SDK accepts, anchor rejects     PASS (valid=1 status=authorized_agent anchor=anchor_mismatch)
  min 765.0 us   median 791.0 us   mean 893.4 us   p95 1426.0 us   max 1995.0 us
peak RSS: 7408 KiB
```

Two notes carried into the evidence record:

- The measured median here is roughly 0.79 ms. `docs/BENCHMARKS.md` reports Go
  at 0.39 ms depth-1 on an M2 Pro and describes C as approximately equal to
  Rust at about 0.9x of Go. This host is not an M2 Pro and the comparison is not
  controlled, so it proves nothing on its own, but it is a reason to measure the
  Pi rather than scale the published number.
- On macOS the released `libratify_c.dylib` carries a build-machine
  `install_name` (`/Users/runner/work/...`), so a shared link fails at load
  time and the static link is the working path. This affects controller-side
  development on a Mac, not the Pi. The armv7 archive shows no equivalent
  absolute path; confirm the shared link resolves on the device.
