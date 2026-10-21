# Evidence

## Local gate

- Validation date: 2026-08-31
- Reference source revision: `8f8a853`
- Host: macOS development machine (not the ARMv7 target)
- SDK line: Ratify 1.0.0-alpha.20, freshly built from the matching protocol source tree
- Result: See `../ratify-reference.json`; the gate compares this declaration with the observed harness count.
- Revocation: signed state exercised, with unavailable-state denial covered
- Operation context: challenge session context binds scope, zone, duration, resource, and invocation identifiers; every mismatch fails closed and the original challenge remains usable

## ARMv7 hardware

- Target: Raspberry Pi 2, ARMv7l, GCC 14.2.0 (Raspbian)
- Source revision: `8f8a853`
- ARMv7 binary SHA-256: `edge` `11dc56339d0bc22b72d95bbb864095fda06fb363cf7793d17f5a8301d15693dd`, `edge-test` `c15b394afaf8b94a94bdff92a910f7657de8fd684f2356777769a2b9fe8d15b0`, `controller` `854d36da84c15a7f14e41725ebb7ffbbe3734d486431b0bce9dc18ae98102c26`
- ARMv7 core result: 25 passed, 0 failed, 0 skipped
- Final five-input operation-binding implementation rerun successfully on the Pi.
- Trusted RTC: not installed; test clock is used only by the test build

## Serial actuator integration

- Device: Arduino Uno with SparkFun ESP8266 shield attached, used as a USB serial actuator
- Command path: Linux receiver to `/dev/ttyACM0` at 115200 baud
- Observed authorized invocations: 2
- Observed denied or replay invocations: 0
- Physical output: built-in Uno LED, non-hazardous demonstration
- End-to-end script: `SERIAL_DEVICE=/dev/ttyACM0 ./tests/e2e.sh`
- Pi result: authorized actuation, monitor authorization, first capture presentation, and replay denial all passed; exactly 2 actuator invocations against the final operation-binding implementation
- Restart replay: `EDGE_BIN=./edge-test ./tests/restart_replay.sh` denied after restart with `post_boot_quarantine`, 0 actuator calls
- ADK status: adapter implemented and syntax-checked, not exercised through a live model runner on the Pi

## Fresh Pi and Arduino acceptance, 2026-10-11

- Source revision: Protocol commit `f2a044d90cd2b40df9b82d4dce901fab274fa5e9`; C SDK source line `1.0.0-alpha.20`.
- Target: Raspberry Pi 2 Model B Rev 1.1, ARMv7l, Raspbian GNU/Linux 13, 32-bit; Arduino Uno at `/dev/serial/by-id/usb-Arduino__www.arduino.cc__0043_95635333431351A0A111-if00`.
- Build: ARMv7 C SDK cross-compiled with `cross` in an isolated container profile, then edge receiver and controller compiled on the Pi with GCC. SDK header SHA-256 `6a00d3c6c876d38a5b684222c8d27449af5bb33f75ae7ba16aa3deb935aa92a7`; static library SHA-256 `6a20354ef4858b13d250d59f25f82d50aad75a875eb8c46f3323a2ca5729fa7a`.
- Production edge binary SHA-256 `d9a60f89889c72bbc784382b8cea0b7484cd1408f6a947f9c9fd04b24bfa2cd4`; controller SHA-256 `860db383882d8fb95ffdd73ec1518d7525ad76fb53c4abfde445222f7cd94965`.
- `make test RATIFY_SDK=../../sdk`: 29 passed, 0 failed, 0 skipped.
- Time: `NTPSynchronized=yes`, `LocalRTC=no`, DS3231-backed `hwclock` read succeeded; production decision returned `clock_trusted=true`.
- Quarantine: production binary started with 300 seconds remaining; the test waited for it to expire. `test_quarantine_override=false` on all recorded decisions.
- Monitor request: authorized, `actuated=false`, 0 actuator calls.
- Direct physical request: authorized for 500 ms; built-in Uno LED fired once.
- Captured proof: first presentation authorized and fired once. Replaying those exact bytes returned `unknown_challenge`, `actuated=false`; total actuator calls remained 2.
- Network boundary: receiver bound to `127.0.0.1`; controller ran on the same Pi. Trust material and a fresh signed empty revocation list were provisioned in the isolated test directory. No production or hazardous actuator was connected.
- This is a fresh alpha.20 v1 result. It is not v2 implementation or conformance evidence.

## Explicit limits

The fresh run verifies the production receiver binary with a trusted clock and the Uno LED over a same-device loopback path. It does not establish trusted time through network loss or power cycles, replay protection across a restart, Arduino-side authorization, or suitability for safety-critical or hazardous actuation. Those require offline power-cycle testing and a separate safety and production review.
