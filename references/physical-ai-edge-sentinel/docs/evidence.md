# Evidence

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

## Explicit limits

This evidence does not establish Arduino-side authorization, trusted offline time, power-cycle replay protection, production hardware acceptance, or suitability for safety-critical actuation. Those require a DS3231 installation, an offline power-cycle test, and a separate production hardware review.
