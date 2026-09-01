# Evidence

## Local gate

- Validation date: 2026-08-31
- Reference source revision: `8f8a853`
- Host: macOS development machine (not the ARMv7 target)
- SDK line: Ratify 1.0.0-alpha.19, freshly built from the matching protocol source tree
- Result: 25 passed, 0 failed, 0 skipped
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

## Explicit limits

This evidence does not establish Arduino-side authorization, trusted offline time, power-cycle replay protection, production hardware acceptance, or suitability for safety-critical actuation. Those require a DS3231 installation, an offline power-cycle test, and a separate production hardware review.
