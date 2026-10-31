# Arduino serial actuator

This optional demo uses an Arduino Uno only as a non-hazardous actuator. The
Linux edge receiver remains the Ratify verifier, trust-anchor holder, clock
source, policy engine, and enforcement boundary. The Uno does not hold keys,
parse proof bundles, or make authorization decisions.

Load `ratify_actuator/ratify_actuator.ino`, connect the board by USB, and pass
the serial device to the production receiver:

```sh
./edge --state state --trust trust --checkpoint ckpt.sock --serial /dev/ttyACM0 --baud 115200
```

Only a released Protocol v2 allow for `physical:actuate` that passes local
policy and the release gate can reach `actuator_fire`, which then emits
`RATIFY_ALLOW FIRE <milliseconds>`. The Uno ignores malformed,
unknown, out-of-range, and oversized frames. Its built-in LED needs no external
wiring for the first demonstration.

This demonstrates the physical output path, not authorization on the Arduino.
The Arduino is an untrusted actuator: anyone with direct access to its serial
port can drive it, and that path is outside this reference's security
boundary.
