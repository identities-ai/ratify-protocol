/*
 * The device security clock (SPEC-v2 §7.2, §9.7).
 *
 * The production build reads only the battery-backed RTC (/dev/rtc0, a
 * DS3231 on the reference Pi). Without it there is no reading and therefore
 * no decision. The test build, and only the test build, can read a fixture
 * clock from the file named by SENTINEL_TEST_CLOCK_FILE so the scenario
 * matrix is deterministic; every reading it returns is marked untrusted.
 */
#ifndef SENTINEL_CLOCK_H
#define SENTINEL_CLOCK_H

#include <stdint.h>

/* Returns 0 with a reading, or -1 when no clock this build accepts is
 * available. `*trusted` is 1 only for the RTC. */
int clock_read(int64_t *now, int *trusted);

/* 1 when this binary was built with the fixture clock compiled in. */
int clock_is_test_build(void);

#endif
