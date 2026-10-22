/* _DEFAULT_SOURCE as well as POSIX: timegm() is a BSD/GNU extension that
 * strict _POSIX_C_SOURCE hides on glibc. The RTC keeps UTC, and timegm is the
 * conversion that does not detour through local time. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/rtc.h>
#endif

#include "clock.h"

int clock_is_test_build(void)
{
#ifdef SENTINEL_TEST_BUILD
    return 1;
#else
    return 0;
#endif
}

int clock_read(int64_t *now, int *trusted)
{
    *trusted = 0;
#ifdef SENTINEL_TEST_BUILD
    /* Fixture clock, test build only. The file holds one integer of Unix
     * seconds, written by the scenario runner. */
    const char *path = getenv("SENTINEL_TEST_CLOCK_FILE");
    if (path && *path) {
        FILE *f = fopen(path, "r");
        long long t = 0;
        int ok = f && fscanf(f, "%lld", &t) == 1;
        if (f) fclose(f);
        if (!ok) return -1;
        *now = (int64_t)t;
        return 0;
    }
#endif

#ifdef __linux__
    int fd = open("/dev/rtc0", O_RDONLY);
    if (fd >= 0) {
        struct rtc_time rt;
        int rc = ioctl(fd, RTC_RD_TIME, &rt);
        close(fd);
        if (rc == 0) {
            struct tm tm_rtc;
            memset(&tm_rtc, 0, sizeof tm_rtc);
            tm_rtc.tm_sec = rt.tm_sec;
            tm_rtc.tm_min = rt.tm_min;
            tm_rtc.tm_hour = rt.tm_hour;
            tm_rtc.tm_mday = rt.tm_mday;
            tm_rtc.tm_mon = rt.tm_mon;
            tm_rtc.tm_year = rt.tm_year;
            time_t utc = timegm(&tm_rtc);
            if (utc != (time_t)-1) {
                *now = (int64_t)utc;
                *trusted = 1;
                return 0;
            }
        }
    }
#endif
    (void)now;
    return -1; /* no trusted clock, no decision */
}
