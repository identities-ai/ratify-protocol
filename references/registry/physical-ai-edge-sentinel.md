# Ratify Edge Physical AI

- **Status:** experimental, self-authored, no platform endorsement
- **Profile:** [`references/physical-ai-edge-sentinel/README.md`](../physical-ai-edge-sentinel/README.md)
- **Demonstrates:** Protocol v2 delegated-authority verification at a Linux edge boundary, with a separate checkpoint process and a release gate, before a safe Arduino actuator
- **Protocol line:** v2 `2.0.0-beta.1` through the C ABI (prerelease; no production security claim)
- **Agent integration:** deterministic controller (v2); the Google ADK adapter in `adk/` is v1 only: it speaks the v1 receiver interface, does not work with this receiver, and has not been ported
- **Actuator:** Arduino Uno built-in LED over USB serial; an untrusted actuator, not the authorization boundary
- **Hardware:** Raspberry Pi 2 Model B Rev 1.1 (ARMv7), DS3231 RTC, Arduino Uno built-in LED; non-hazardous only
- **Gate:** `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh`
- **Evidence:** [Published archive gate](../physical-ai-edge-sentinel/docs/evidence-published-beta1-2026-10-31.md); [earlier in-tree and hardware runs](../physical-ai-edge-sentinel/docs/evidence.md)
- **Latest gate result:** 32/32 scenario rows, 0 skipped, mock actuator only, on 2026-10-31 against the published `ratify-c-v2.0.0-beta.1-macos-aarch64.tar.gz` archive. Earlier in-tree results include 32/32 on macOS and Raspberry Pi 2 (ARMv7) test builds on 2026-10-27. The v2 hardware run with the DS3231 RTC and Arduino passed on 2026-10-22: one authorized 500 ms pulse observed, every other request refused, exactly one actuator call. No fresh Pi or Arduino run was made against the published archive. The alpha.20 v1 Pi acceptance remains dated history.
- **Published-package evidence:** [`docs/evidence/v2-published-beta1-2026-10-31.md`](../../docs/evidence/v2-published-beta1-2026-10-31.md)
- **Not claimed:** single-device offline profile conformance (the checkpoint is a second process on the same host), hazardous or safety-critical use
- **Review:** no robotics, farm, Arduino, or AI-platform endorsement claimed
