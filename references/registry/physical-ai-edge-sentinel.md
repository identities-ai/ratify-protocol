# Ratify Edge Physical AI

- **Status:** experimental, self-authored, no platform endorsement
- **Profile:** [`references/physical-ai-edge-sentinel/README.md`](../physical-ai-edge-sentinel/README.md)
- **Demonstrates:** Protocol v2 delegated-authority verification at a Linux edge boundary, with a separate checkpoint process and a release gate, before a safe Arduino actuator
- **Protocol:** v2 `2.0.0-alpha.1` through the C ABI (prerelease; no production security claim)
- **Agent integration:** deterministic controller; the Google ADK adapter targets the v1 receiver and has not been ported
- **Actuator:** Arduino Uno built-in LED over USB serial; an untrusted actuator, not the authorization boundary
- **Hardware:** Raspberry Pi 2 Model B Rev 1.1 (ARMv7), DS3231 RTC, Arduino Uno built-in LED; non-hazardous only
- **Gate:** `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh`
- **Evidence:** [`references/physical-ai-edge-sentinel/docs/evidence.md`](../physical-ai-edge-sentinel/docs/evidence.md)
- **Latest gate result:** v2 local gate passed on 2026-10-22: 30/30 scenario rows, 0 skipped, mock actuator only. The v2 Pi 2 ARMv7 and Arduino run is pending. The alpha.20 v1 Pi acceptance of 2026-10-11 is kept as dated v1 history.
- **Not claimed:** single-device offline profile conformance (the checkpoint is a second process on the same host), hazardous or safety-critical use
- **Review:** no robotics, farm, Arduino, or AI-platform endorsement claimed
