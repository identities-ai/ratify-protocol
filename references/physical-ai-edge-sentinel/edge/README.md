# Edge C component

Linux edge receiver. This component links the Ratify C SDK,
issue and consume single-use challenges, verify presented authority against a
pinned operator trust anchor, apply local policy, and invoke only a safe
actuator adapter after an allow decision. It will use the published
`ratify-c-v1.0.0-alpha.18-linux-armv7.tar.gz` artifact rather than building the
Rust core on the Pi.

The production binary is fail-closed without a trusted clock. The test build
has explicit clock and quarantine overrides for deterministic fixtures only.
