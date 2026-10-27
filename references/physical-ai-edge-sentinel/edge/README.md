# Edge receiver (Protocol v2)

The Linux edge receiver and its checkpoint process. The receiver links the
Ratify C SDK `2.0.0-beta.1` statically and uses only the `ratify_v2_*` ABI.

| Binary | Built from | Purpose |
| --- | --- | --- |
| `edge` | `src/`, `actuator/` | Production receiver: RTC clock only, real quarantine |
| `edge-checkpoint` | `checkpoint/` | Production checkpoint process with its own key and storage |
| `edge-test`, `edge-checkpoint-test` | same, with `-DSENTINEL_TEST_BUILD` | Test builds: fixture clock and quarantine override compiled in |
| `controller` | `../controller/` | Principal, status publisher, and agent for demonstrations |

```sh
make RATIFY_SDK=/path/to/ratify-c all test-bins
./tests/scenarios.sh
```

The production binaries fail closed without the DS3231 RTC (`/dev/rtc0`), and
the receiver refuses `physical:actuate` for 300 seconds after start. The test
builds exist for the deterministic matrix only and never drive hardware there:
`tests/scenarios.sh` starts the receiver without `--serial` or `--gpio`, so the
actuator is a mock that only counts. See `../docs/v2-design.md` for the design
and its limits.
