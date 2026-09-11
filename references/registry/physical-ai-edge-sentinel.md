# Ratify Edge Physical AI

- **Status:** experimental, self-authored, no platform endorsement
- **Profile:** [`references/physical-ai-edge-sentinel/README.md`](../physical-ai-edge-sentinel/README.md)
- **Demonstrates:** delegated authority verification at a Linux edge boundary before a safe Arduino actuator
- **Agent integration:** deterministic controller first, optional Google ADK adapter planned
- **Actuator:** Arduino Uno built-in LED over USB serial
- **Hardware:** pre-RTC, non-hazardous only
- **Gate:** `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh`
- **Evidence:** [`references/physical-ai-edge-sentinel/docs/evidence.md`](../physical-ai-edge-sentinel/docs/evidence.md)
- **Gate result:** Declared in [`ratify-reference.json`](../physical-ai-edge-sentinel/ratify-reference.json) and checked by the gate
- **Review:** no robotics, farm, Arduino, or AI-platform endorsement claimed
