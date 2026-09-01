# Evidence

## Local gate

- Validation date: 2026-08-31
- Reference source revision: `25fcb3e`
- Host: macOS development machine (not the ARMv7 target)
- SDK line: Ratify 1.0.0-alpha.19, freshly built from the matching protocol source tree
- Result: 25 passed, 0 failed, 0 skipped
- Revocation: signed state exercised, with unavailable-state denial covered
- Operation context: challenge session context binds scope, zone, duration, resource, and invocation identifiers; every mismatch fails closed and the original challenge remains usable

## Hardware status

- Target: Raspberry Pi 2, ARMv7l, GCC 14.2.0 (Raspbian)
- The prior Pi/Arduino run used the pre-operation-binding revision `55de67f`; it is historical evidence only.
- The five-input operation-binding implementation has not yet been rerun on the Pi because the device is currently unreachable.
- ARMv7 binary hashes and final serial results: pending rerun against the operation-binding revision.
- Trusted RTC: not installed; test clock is used only by the test build

## Serial actuator integration

- Device: Arduino Uno with SparkFun ESP8266 shield attached, used as a USB serial actuator
- Command path: Linux receiver to `/dev/ttyACM0` at 115200 baud
- Observed authorized invocations: 2
- Observed denied or replay invocations: 0
- Physical output: built-in Uno LED, non-hazardous demonstration
- End-to-end script: `SERIAL_DEVICE=/dev/ttyACM0 ./tests/e2e.sh`
- Pi result: authorized actuation, monitor authorization, first capture presentation, and replay denial all passed; exactly 2 actuator invocations
- Restart replay: `EDGE_BIN=./edge-test ./tests/restart_replay.sh` denied after restart with `post_boot_quarantine`, 0 actuator calls
- ADK status: adapter implemented and syntax-checked, not exercised through a live model runner on the Pi

## Explicit limits

This evidence does not establish Arduino-side authorization, trusted offline time, power-cycle replay protection, production hardware acceptance, or suitability for safety-critical actuation. Those require a DS3231 installation, an offline power-cycle test, and a separate production hardware review.
