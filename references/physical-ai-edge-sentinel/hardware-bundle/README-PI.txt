Ratify Edge Sentinel v2 bundle: what to run on the Pi
======================================================

Copy this directory to the Pi (any path without spaces, short enough for a
Unix socket path, for example ~/edge-v2) and run everything from inside it.

0. Verify the bundle
     cd ~/edge-v2 && sha256sum -c SHA256SUMS
     uname -m        # expect armv7l
     ldd bin/edge    # expect only libc and the loader

1. Deterministic scenario matrix (NO hardware output)
     ./run-matrix.sh
   Uses the test builds, a fixture clock, the mock actuator, and port 8197.
   It never passes --serial or --gpio. Expect "ALL ROWS PASSED (30/30)",
   "mock actuator invocations: 5", and no "UNEXPECTED" line. Record the wall
   time it prints. Output: matrix-<timestamp>.out and matrix-<timestamp>/.

2. Production hardware run (DRIVES THE ARDUINO; owner approval per step)
   Preconditions: DS3231 RTC at /dev/rtc0 readable by this user, Arduino Uno
   with arduino/ratify_actuator/ratify_actuator.ino on USB serial, nothing
   listening on 127.0.0.1:8088.
     ./run-production-serial-ACTUATES-HARDWARE.sh prepare
     SERIAL_DEVICE=/dev/serial/by-id/<arduino> OWNER_APPROVED_SERIAL=yes \
       ./run-production-serial-ACTUATES-HARDWARE.sh start
     ./run-production-serial-ACTUATES-HARDWARE.sh health
     OWNER_APPROVED_CHECKS=yes ./run-production-serial-ACTUATES-HARDWARE.sh checks
         (waits out the 300 s quarantine; no request in it may actuate)
     OWNER_APPROVED_ACTUATION=yes ./run-production-serial-ACTUATES-HARDWARE.sh actuate-once
         (exactly ONE 500 ms LED pulse, then a replay that must not actuate)
     SERIAL_DEVICE=/dev/serial/by-id/<arduino> OWNER_APPROVED_CHECKS=yes \
       ./run-production-serial-ACTUATES-HARDWARE.sh restart-replay
         (restarts the receiver, waits out the quarantine, replays: no actuation)
     ./run-production-serial-ACTUATES-HARDWARE.sh stop
   Log: prod-run/run.log. prod-run/ holds keys and captured proofs (0700):
   do not publish it. The checkpoint runs as the same user here; running it
   as a separate user (with --allow-uid of the receiver's user, and RTC read
   access for both users) is a manual step, see docs/v2-design.md.

3. Report back for docs/evidence.md
     - sha256sum -c result, uname -a, /etc/os-release PRETTY_NAME
     - run-matrix.sh output (rows, wall time, mock invocation count)
     - prod-run/run.log PASS/FAIL lines and the final FIRE count
     - whether the owner saw exactly one LED pulse during actuate-once
