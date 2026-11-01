# Published C archive gate, 2026-10-31

The edge sentinel gate ran on macOS arm64 against the published
`ratify-c-v2.0.0-beta.1-macos-aarch64.tar.gz` release archive, supplied as
`RATIFY_SDK`. It used a mock actuator and made five mock invocations.

Result: 32 passed, 0 failed, 0 skipped.

This run did not use the Raspberry Pi, DS3231 RTC, or Arduino. Their earlier
in-tree results remain in [evidence.md](evidence.md). The
[cross-reference evidence](../../../docs/evidence/v2-published-beta1-2026-10-31.md)
records the other published beta gates.
