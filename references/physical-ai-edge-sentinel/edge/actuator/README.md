# Guarded actuator adapter

This is the only module permitted to invoke the demo actuator. Its entry point
requires the process-random token that only the release gate hands out, and
the gate hands it out only for a released Protocol v2 allow for
`physical:actuate` that passed local policy and `ratify_v2_released_allowed`
at that moment. It has no request or network path of its own.

Without `--serial` or `--gpio` the adapter is a mock that only counts
invocations; the scenario matrix uses it. With `--serial` it writes
`RATIFY_ALLOW FIRE <ms>` to the Arduino. Any GPIO wiring must remain
non-hazardous.
