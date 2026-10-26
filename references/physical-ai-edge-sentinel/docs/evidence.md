# Evidence

Protocol v2 evidence comes first. The v1 hardware evidence that preceded the
port is kept below as dated history; it is not v2 evidence.

## Protocol v2: local gate

- Validation date: 2026-10-26
- Reference source revision: `112e8a4` (the 32-row matrix; the 30-row matrix of 2026-10-22 ran at `7f29ed4ef216e9344ddbcf11bfefe9dcd31ccbcc`)
- Host: macOS development machine (Apple Silicon), not the ARMv7 target
- SDK: Ratify C SDK `2.0.0-alpha.1` (`ratify_v2_*` ABI version 2), built from `sdks/c` at the same revision, static library, no test-reference stores
- Command: `RATIFY_SDK=/path/to/ratify-c ./run-reference-check.sh`
- Result: 32 passed, 0 failed, 0 skipped
- Actuator: mock only; 5 invocations in total, 0 serial or GPIO writes
- Sanitizers: the same matrix passed with AddressSanitizer and UndefinedBehaviorSanitizer, with no reports
- Clock: fixture clock from the test builds; every decision recorded `clock_trusted=false`

| # | Row | Recorded outcome | Actuator |
| --- | --- | --- | --- |
| 1 | role separation: root key as status key | publisher refuses (`status_object_rejected`), receiver refuses the trust directory | not applicable |
| 2 | allow: `physical:actuate` | committed, released, allow, `authorized` | fired |
| 3 | allow: `infrastructure:monitor` | committed, released, allow, `authorized` | not fired |
| 4 | out of scope: monitor certificate, actuate request | released deny, `scope_denied` | not fired |
| 5 | out of scope: zone `greenhouse-a` | released deny, `constraint_denied` | not fired |
| 6 | signed duration ceiling exceeded (30000 ms > 20000 ms) | released deny, `constraint_denied` | not fired |
| 7 | local cap exceeded (1500 ms > 1000 ms) | released allow, refused by local policy | not fired |
| 8 | local policy reason recorded | `policy_duration_denied` | not applicable |
| 9 | tamper: altered challenge signature | preflight, `invalid_signature` | not fired |
| 10 | tamper: action changed after the challenge | preflight, `configuration_invalid` (the request's expected context differs from the issued challenge's) | not fired |
| 11 | chain from an untrusted root | released deny, `unauthorized` | not fired |
| 12 | first presentation of a captured proof | released allow, `authorized` | fired |
| 13 | replay of that proof | replay, `terminal_replay`, nothing disclosed | not fired |
| 14 | challenge presented after expiry | preflight, `challenge_not_fresh` | not fired |
| 15 | certificate revoked by a signed push | released deny, `delegation_revoked` | not fired |
| 16 | delegation past `expires_at` | released deny, `delegation_expired` | not fired |
| 17 | first presentation before a receiver restart | released allow | fired |
| 18 | replay after the restart | replay, `terminal_replay` (durable claim store) | not fired |
| 19 | actuation during post-boot quarantine (no override) | device, `post_boot_quarantine` | not fired |
| 20 | clock moved backward | no challenge issued, `clock_regressed` | not fired |
| 21 | checkpoint stopped | no challenge issued, `claim_store_unavailable` | not fired |
| 22 | checkpoint restarted | released allow | fired |
| 23 | fresh proof before a rollback | released allow | fired |
| 24 | receiver state restored from an earlier copy | receiver starts `recovering` (digest differs from the anchored digest) | not applicable |
| 25 | replay into the rolled-back receiver | device, `device_recovering` | not fired |
| 26 | challenge request while recovering | no challenge issued, `device_recovering` | not fired |
| 27 | anchored state put back | receiver `ready` | not applicable |
| 28 | replay after resuming | replay, `terminal_replay` | not fired |
| 29 | actuator invocations across all runs | 5, as expected | 5 mock |
| 30 | no hardware output | 0 serial or GPIO writes | none |
| 31 | checkpoint clock past the timestamp domain | checkpoint refuses, `clock_out_of_range` | not applicable |
| 32 | checkpoint fork | a retry with a different predecessor is refused (`previous_entry_mismatch`); a fork is refused (`log_fork`) and the log freezes: an identical retry of an earlier acknowledgement still returns it, also with the clock past the timestamp domain, and a new entry is refused (`frozen`) | not applicable |

Preflight classes are recorded in the receiver's decision log. The HTTP answer
for a preflight rejection is deliberately the same for every class, so that
issuance and consumption state are not an oracle (SPEC-v2 §7.3).

Not exercised by the matrix: lease-expiry recovery of an interrupted claim,
promotion of an anchored `state.next` after a crash between anchoring and
rename, and the checkpoint refusing when its capacity is used.

## Protocol v2: Raspberry Pi 2 ARMv7 deterministic matrix

The ARMv7 bundle built from the revision below was copied to the Pi, its
`SHA256SUMS` manifest was verified there, and the deterministic matrix was run
with `./run-matrix.sh` on 2026-10-22. These are the test builds (fixture clock,
mock actuator); no serial or GPIO output was produced.

- Target: Raspberry Pi 2 Model B Rev 1.1, armv7l, Raspbian 13 (trixie), glibc 2.41; `edge` links only libc and libarmmem
- Build: C SDK cross-compiled with `cargo zigbuild --release --target armv7-unknown-linux-gnueabihf.2.36` (rustc 1.95.0, cargo-zigbuild 0.22.3, zig 0.16.0); binaries cross-compiled with `zig cc -target arm-linux-gnueabihf.2.36 -mcpu=cortex_a7`, stripped, Ratify library linked statically, glibc linked dynamically (highest symbol version `GLIBC_2.34`)
- SDK SHA-256: `ratify.h` `ef0242f72b614fb3775368462acb3e3e0597f3ba3b8cfa16e38e1630707c6cec`, `libratify_c.a` (armv7) `0e2d3c16aeb565c7820eb1dd6e17f93a432df06de91f214665802be33c2dec25`
- Source revision: `7f29ed4ef216e9344ddbcf11bfefe9dcd31ccbcc`
- Binary SHA-256: `edge` `7cce2b13ce71d1d6eaff4648f8fe3ceece052f6d559c0a32c733b834331e3237`, `edge-checkpoint` `f1532188d7b053b2d58f2cc15581d539e03fcc4e7b8d81ff71b590d453608f7b`, `edge-test` `765bbb4fef524dd4b7315ed5a8f95a773a94dee8f0d718ab8989a0023b7a5806`, `edge-checkpoint-test` `7e8029e80f87d3b3dbcc2115350ac82ca677971820b4b43a0f63ca92260d8e94`, `controller` `5d827e26d45d03b3555fb074b5b27e9586be7985a2c09c07e2ee0ff3854830f1`
- Deterministic matrix on the Pi (mock actuator): `ALL ROWS PASSED (30/30)`, 30 passed, 0 failed, 0 skipped, no `UNEXPECTED` lines
- Actuator: mock only; 5 invocations in total
- Matrix wall time on the Pi: 74 s
- Decision latency on the Pi (challenge to released decision): not measured in this run

## Protocol v2: production binaries, DS3231 RTC, and Arduino (2026-10-22)

Run on the Raspberry Pi 2 with the production binaries from the staged bundle
(checksums verified), the DS3231 real-time clock, and the Arduino Uno over USB
serial. The owner approved each hardware step individually and watched the LED.

- Time: every decision reported `clock_trusted=true` from the RTC; no clock override is compiled into the production binaries (`test_quarantine_override=false` on every decision)
- Process separation: the checkpoint ran as a separate process with its own key and storage, under the same Unix user as the receiver (running it as a separate user remains a manual hardening step, see `v2-design.md`)
- Quarantine: the production receiver started with 300 seconds remaining and accepted no request until it reached 0
- Non-actuating checks, all after the quarantine, actuator count unchanged at 0:
  - monitor-scoped delegation: released allow (`authorized`), not actuated, because the scope lacks `physical:actuate`
  - zone outside the delegation: released deny, `constraint_denied`
  - signed duration ceiling exceeded: released deny, `constraint_denied`
  - untrusted root: released deny, `unauthorized`
  - tampered signature: rejected before claim (preflight)
  - device local cap exceeded: released allow refused by local policy (`policy_duration_denied`)
- Authorized request, 500 ms: released allow (`authorized`), actuated once; the owner observed exactly one LED pulse
- Replay of the same proof bytes: `terminal_replay`, not actuated; total actuator calls 1
- Receiver restart, quarantine, then replay: rejected at preflight (`challenge_not_fresh`), not actuated. After a restart the 300 second quarantine outlasts the maximum challenge age, so every pre-restart proof is stale before the receiver accepts requests. The deterministic matrix covers the durable-claim replay path (`terminal_replay` after restart) with a fixture clock. The run script now accepts either outcome and fails only on actuation.
- Whole run: exactly one `actuator: FIRE` line in the receiver log

## Explicit limits of the v2 evidence

The local gate establishes the decision logic, the durable stores, the
checkpoint protocol, and exact actuator accounting with a fixture clock on a
development machine; the same matrix also passed on the Pi 2 ARMv7 target with
the test builds. It does not establish trusted time,
behavior through power loss, single-device offline profile conformance (a
second process on the same host never qualifies; see `v2-design.md`), or
suitability for hazardous, safety-critical, or regulated actuation.

---

## v1 history (Protocol v1, `1.0.0-alpha.20` and earlier)

The records below were produced by the v1 receiver, which this port replaced.
They remain as dated history and are not v2 evidence.

### v1 local gate

- Validation date: 2026-08-31
- Reference source revision: `8f8a853`
- Host: macOS development machine (not the ARMv7 target)
- SDK line: Ratify 1.0.0-alpha.20, freshly built from the matching protocol source tree
- v1 core suite: 29 cases at the time of the 2026-10-11 run
- Revocation: signed state exercised, with unavailable-state denial covered
- Operation context: challenge session context binds scope, zone, duration, resource, and invocation identifiers; every mismatch fails closed and the original challenge remains usable

### v1 ARMv7 hardware

- Target: Raspberry Pi 2, ARMv7l, GCC 14.2.0 (Raspbian)
- Source revision: `8f8a853`
- ARMv7 binary SHA-256: `edge` `11dc56339d0bc22b72d95bbb864095fda06fb363cf7793d17f5a8301d15693dd`, `edge-test` `c15b394afaf8b94a94bdff92a910f7657de8fd684f2356777769a2b9fe8d15b0`, `controller` `854d36da84c15a7f14e41725ebb7ffbbe3734d486431b0bce9dc18ae98102c26`
- ARMv7 core result: 25 passed, 0 failed, 0 skipped
- Final five-input operation-binding implementation rerun successfully on the Pi.
- Trusted RTC: not installed; test clock is used only by the test build

### v1 serial actuator integration

- Device: Arduino Uno with SparkFun ESP8266 shield attached, used as a USB serial actuator
- Command path: Linux receiver to `/dev/ttyACM0` at 115200 baud
- Observed authorized invocations: 2
- Observed denied or replay invocations: 0
- Physical output: built-in Uno LED, non-hazardous demonstration
- Pi result: authorized actuation, monitor authorization, first capture presentation, and replay denial all passed; exactly 2 actuator invocations against the final operation-binding implementation
- Restart replay: denied after restart with `post_boot_quarantine`, 0 actuator calls
- ADK status: adapter implemented and syntax-checked, not exercised through a live model runner on the Pi

### v1 fresh Pi and Arduino acceptance, 2026-10-11

- Source revision: Protocol commit `f2a044d90cd2b40df9b82d4dce901fab274fa5e9`; C SDK source line `1.0.0-alpha.20`.
- Target: Raspberry Pi 2 Model B Rev 1.1, ARMv7l, Raspbian GNU/Linux 13, 32-bit; Arduino Uno over USB serial.
- Build: ARMv7 C SDK cross-compiled with `cross` in an isolated container profile, then edge receiver and controller compiled on the Pi with GCC. SDK header SHA-256 `6a00d3c6c876d38a5b684222c8d27449af5bb33f75ae7ba16aa3deb935aa92a7`; static library SHA-256 `6a20354ef4858b13d250d59f25f82d50aad75a875eb8c46f3323a2ca5729fa7a`.
- Production edge binary SHA-256 `d9a60f89889c72bbc784382b8cea0b7484cd1408f6a947f9c9fd04b24bfa2cd4`; controller SHA-256 `860db383882d8fb95ffdd73ec1518d7525ad76fb53c4abfde445222f7cd94965`.
- `make test`: 29 passed, 0 failed, 0 skipped (v1 core suite).
- Time: `NTPSynchronized=yes`, `LocalRTC=no`, DS3231-backed `hwclock` read succeeded; production decision returned `clock_trusted=true`.
- Quarantine: production binary started with 300 seconds remaining; the test waited for it to expire. `test_quarantine_override=false` on all recorded decisions.
- Monitor request: authorized, `actuated=false`, 0 actuator calls.
- Direct physical request: authorized for 500 ms; built-in Uno LED fired once.
- Captured proof: first presentation authorized and fired once. Replaying those exact bytes returned `unknown_challenge`, `actuated=false`; total actuator calls remained 2.
- Network boundary: receiver bound to `127.0.0.1`; controller ran on the same Pi. Trust material and a fresh signed empty revocation list were provisioned in the isolated test directory. No production or hazardous actuator was connected.
- This is a v1 result. It is not v2 implementation or conformance evidence.

### v1 explicit limits

The v1 run verified the v1 production receiver binary with a trusted clock and the Uno LED over a same-device loopback path. It did not establish trusted time through network loss or power cycles, replay protection across a restart, Arduino-side authorization, or suitability for safety-critical or hazardous actuation.
