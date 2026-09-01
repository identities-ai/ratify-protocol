# Evidence

- Validation date: 2026-08-31
- Reference source revision: `55de67f`
- Target compiler: GCC 14.2.0 (Raspbian)
- Target architecture: ARMv7l
- SDK line: Ratify 1.0.0-alpha.19
- Rebuilt binary SHA-256: `edge` `db3508b28da5bb24c79fd7383e35f807a91cb2a9a8b18a81ccbcd0dce5ebcada`, `edge-test` `a3cc2aee0ffc258e7d006ad96604c88618010d6665b5e3b52f5f535a4b55f42b`, `controller` `2873fe169cd516f8b948619cb1c1bd50a73b5a426b5e7ae51091cb01bbd37d66`

## Deterministic gate

- Protocol release line: Ratify alpha.19
- Target: Raspberry Pi 2, ARMv7
- C SDK: freshly built from the matching protocol source tree
- Result: 16 passed, 0 failed, 0 skipped
- Revocation: signed state exercised, with unavailable-state denial covered
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
