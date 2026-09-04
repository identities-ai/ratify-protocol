# Arduino serial actuator

This optional demo uses an Arduino Uno only as a non-hazardous actuator. The
Linux edge receiver remains the Ratify verifier, trust-anchor holder, clock
source, policy engine, and enforcement boundary. The Uno does not hold keys,
parse proof bundles, or make authorization decisions.

Load `ratify_actuator/ratify_actuator.ino`, connect the board by USB, and pass
the serial device to the edge binary:

```sh
./edge --trust trust --serial /dev/cu.usbmodemXXXX --baud 115200
```

Only a successful `physical:actuate` decision can reach `actuator_fire`, which
then emits `RATIFY_ALLOW FIRE <milliseconds>`. The Uno ignores malformed,
unknown, out-of-range, and oversized frames. Its built-in LED needs no external
wiring for the first demonstration.

This demonstrates the physical output path, not offline authorization on the
Arduino. The Raspberry Pi RTC and production hardware acceptance test remain
required for the Edge Sentinel offline claim.
