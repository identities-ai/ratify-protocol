# Ratify Edge Physical AI

- **Status:** experimental, self-authored, no platform endorsement
- **Profile:** [`references/physical-ai-edge-sentinel/README.md`](../physical-ai-edge-sentinel/README.md)
- **Demonstrates:** Protocol v2 delegated-authority verification at a Linux edge boundary, with a separate checkpoint process and a release gate, before a safe Arduino actuator
- **Protocol line:** v2 `2.0.0-beta.1` through the C ABI (prerelease; no production security claim)
- **Agent integration:** deterministic controller (v2); the Google ADK adapter in `adk/` is v1 only: it speaks the v1 receiver interface, does not work with this receiver, and has not been ported
- **Actuator:** Arduino Uno built-in LED over USB serial; an untrusted actuator, not the authorization boundary
- **Hardware:** Raspberry Pi 2 Model B Rev 1.1 (ARMv7), DS3231 RTC, Arduino Uno built-in LED; non-hazardous only
- **Gate:** `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh`
- **Evidence:** [`references/physical-ai-edge-sentinel/docs/evidence.md`](../physical-ai-edge-sentinel/docs/evidence.md)
- **Latest gate result:** v2 local gate passed on 2026-10-27 against the `2.0.0-beta.1` C SDK: 32/32 scenario rows, 0 skipped, mock actuator only, on macOS (plain and sanitized) and on the Raspberry Pi 2 (ARMv7) with the test builds. On 2026-10-26 the same matrix passed on macOS and on the Pi against the alpha.1 build. The v2 production run with the DS3231 RTC and the Arduino also passed on 2026-10-22: one authorized 500 ms pulse observed by the operator, every other request refused, exactly one actuator call. The alpha.20 v1 Pi acceptance of 2026-10-11 is kept as dated v1 history.
- **Not claimed:** single-device offline profile conformance (the checkpoint is a second process on the same host), hazardous or safety-critical use
- **Review:** no robotics, farm, Arduino, or AI-platform endorsement claimed
