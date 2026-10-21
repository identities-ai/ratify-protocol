# Ratify Edge Physical AI

- **Status:** experimental, self-authored, no platform endorsement
- **Profile:** [`references/physical-ai-edge-sentinel/README.md`](../physical-ai-edge-sentinel/README.md)
- **Demonstrates:** delegated authority verification at a Linux edge boundary before a safe Arduino actuator
- **Agent integration:** deterministic controller first, optional Google ADK adapter planned
- **Actuator:** Arduino Uno built-in LED over USB serial
- **Hardware:** Raspberry Pi 2 Model B Rev 1.1 (ARMv7), DS3231 RTC, Arduino Uno built-in LED; non-hazardous only
- **Gate:** `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh`
- **Evidence:** [`references/physical-ai-edge-sentinel/docs/evidence.md`](../physical-ai-edge-sentinel/docs/evidence.md)
- **Latest gate result:** Alpha.20 v1 acceptance passed on 2026-10-11: 29/29 core cases; trusted RTC, normal quarantine, monitor without actuation, bounded LED action, and captured-proof replay denied. See the dated evidence record. This is v1 evidence only; v2 compatibility is pending.
- **Review:** no robotics, farm, Arduino, or AI-platform endorsement claimed
