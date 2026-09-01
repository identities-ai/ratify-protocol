/*
 * Trust material and clock discipline.
 *
 * Two things gate sensitive actuation beyond the proof itself: a clock we can
 * justify (SPEC §15.6 gives expiry no skew tolerance) and revocation state we
 * can justify (SPEC §15.5). Each degrades explicitly and is recorded in the
 * decision, never silently assumed.
 */
/* _DEFAULT_SOURCE as well as POSIX: timegm() is a BSD/GNU extension that
 * strict _POSIX_C_SOURCE hides on glibc. The RTC keeps UTC, and timegm is the
 * conversion that does not detour through local time. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifdef __linux__
#include <linux/rtc.h>
#endif

#include "ratify.h"
#include "trust.h"

#ifdef SENTINEL_TEST_BUILD
static int env_override(const char *name)
{
    const char *v = getenv(name);
    return v && strcmp(v, "1") == 0;
}
#endif

/* Read a whole file into a NUL-terminated buffer, capped. Caller frees. */
static char *read_file(const char *path, long cap, long *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > cap) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = (long)rd;
    return buf;
}

/* Narrow scan for one top-level scalar field. Used ONLY on a document whose
 * hybrid signature has already verified, so this never parses attacker input. */
static int json_scalar(const char *json, const char *key, char *out, size_t cap)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    int quoted = (*p == '"');
    if (quoted) p++;
    size_t n = 0;
    while (*p && n < cap - 1) {
        if (quoted ? (*p == '"') : (*p == ',' || *p == '}' || *p == ' ')) break;
        out[n++] = *p++;
    }
    out[n] = '\0';
    return n > 0;
}

static void load_policy(const char *path, trust_ctx *t)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line, *v = eq + 1;
        v[strcspn(v, "\r\n")] = '\0';

        /* Trim both ends of both halves. "zone = north" must yield the key
         * "zone", not "zone ". Getting this wrong fails closed — no zone
         * matches and every actuation is denied — which is the safe direction
         * but looks exactly like a policy that denies on purpose. */
        while (*k == ' ' || *k == '\t') k++;
        char *ke = k + strlen(k);
        while (ke > k && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = '\0';
        while (*v == ' ' || *v == '\t') v++;
        char *ve = v + strlen(v);
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) *--ve = '\0';

        if (!strcmp(k, "zone") && t->zone_count < TRUST_MAX_ZONES)
            snprintf(t->zones[t->zone_count++], TRUST_ZONE_MAX, "%s", v);
        else if (!strcmp(k, "max_activation_ms"))
            t->max_activation_ms = atoi(v);
        else if (!strcmp(k, "revocation_max_age_s"))
            t->revocation_max_age_s = strtoll(v, NULL, 10);
    }
    fclose(f);
}

/* Load, verify, and bind the revocation list. Every failure leaves t->list
 * NULL, which means "revocation state unavailable", not "nothing revoked". */
static void load_revocation(const char *path, const char *trust_dir, trust_ctx *t)
{
    char *list_json = read_file(path, 1 << 20, NULL);
    if (!list_json) return;

    char pubpath[512];
    snprintf(pubpath, sizeof(pubpath), "%s/operator_pub_key.json", trust_dir);
    char *pub_json = read_file(pubpath, 1 << 16, NULL);
    if (!pub_json) {
        fprintf(stderr, "trust: revocation list present but no operator_pub_key.json\n");
        free(list_json);
        return;
    }

    /* Signature first. Nothing in the document is read before it verifies. */
    char *err = NULL;
    if (ratify_revocation_list_verify(list_json, pub_json, &err) != RatifyOk) {
        fprintf(stderr, "trust: revocation list signature invalid: %s\n",
                err ? err : "unknown");
        ratify_error_free(err);
        free(list_json); free(pub_json);
        return;
    }
    free(pub_json);

    /* Bind it to the pinned anchor. A list signed by some other principal is
     * not this device's revocation state, however well-formed it is. */
    char issuer[TRUST_ID_HEX_LEN + 8] = {0};
    if (!json_scalar(list_json, "issuer_id", issuer, sizeof(issuer)) ||
        strcmp(issuer, t->pinned_human_id) != 0) {
        fprintf(stderr, "trust: revocation list issuer %s is not the pinned anchor\n",
                issuer[0] ? issuer : "(absent)");
        free(list_json);
        return;
    }

    char updated[32] = {0};
    if (!json_scalar(list_json, "updated_at", updated, sizeof(updated))) {
        fprintf(stderr, "trust: revocation list has no updated_at\n");
        free(list_json);
        return;
    }
    t->list_updated_at = strtoll(updated, NULL, 10);

    RatifyRevocationList *handle = NULL;
    if (ratify_revocation_list_from_json(list_json, &handle, &err) != RatifyOk) {
        fprintf(stderr, "trust: revocation list parse failed: %s\n",
                err ? err : "unknown");
        ratify_error_free(err);
        free(list_json);
        return;
    }
    free(list_json);
    t->list = handle;
}

int trust_load(const char *trust_dir, trust_ctx *t)
{
    char path[512];
    memset(t, 0, sizeof(*t));

    snprintf(path, sizeof(path), "%s/pinned_human_id", trust_dir);
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "trust: cannot open %s\n", path);
        return -1;
    }
    char buf[64] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    /* Trim trailing whitespace; the file is written by the provisioning tool
     * but a human may have edited it. */
    while (n > 0 && isspace((unsigned char)buf[n - 1])) buf[--n] = '\0';

    if (n != TRUST_ID_HEX_LEN) {
        fprintf(stderr, "trust: pinned_human_id must be %d hex chars, got %zu\n",
                TRUST_ID_HEX_LEN, n);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)buf[i]) || isupper((unsigned char)buf[i])) {
            fprintf(stderr, "trust: pinned_human_id must be lowercase hex\n");
            return -1;
        }
    }
    memcpy(t->pinned_human_id, buf, TRUST_ID_HEX_LEN + 1);

#ifdef SENTINEL_TEST_BUILD
    /* Development-only escape hatches. They must not be present in the
     * production binary, where missing revocation or an untrusted clock must
     * remain fail-closed. */
    t->allow_no_revocation   = env_override("SENTINEL_ALLOW_NO_REVOCATION");
    t->allow_untrusted_clock = env_override("SENTINEL_ALLOW_UNTRUSTED_CLOCK");
#else
    t->allow_no_revocation   = 0;
    t->allow_untrusted_clock = 0;
#endif

    /* Defaults before policy.conf is read. An empty zone list permits no zone:
     * local policy must be stated, never inferred. */
    t->revocation_max_age_s = 86400;
    t->max_activation_ms    = 1000;
    t->zone_count           = 0;

    snprintf(path, sizeof(path), "%s/policy.conf", trust_dir);
    load_policy(path, t);

    snprintf(path, sizeof(path), "%s/revocation.json", trust_dir);
    load_revocation(path, trust_dir, t);
    return 0;
}

void trust_unload(trust_ctx *t)
{
    if (t->list) {
        ratify_revocation_list_free(t->list);
        t->list = NULL;
    }
}

int trust_is_revoked(const trust_ctx *t, const char *cert_id)
{
    if (!t->list) return -1;                       /* unavailable: fail closed */
    return ratify_revocation_list_contains(t->list, cert_id) ? 1 : 0;
}

int trust_zone_allowed(const trust_ctx *t, const char *zone)
{
    if (!zone || !*zone) return 0;
    for (int i = 0; i < t->zone_count; i++)
        if (strcmp(t->zones[i], zone) == 0) return 1;
    return 0;
}

int trust_now(const trust_ctx *t, int64_t *out_now, int *out_trusted)
{
    *out_trusted = 0;

#ifdef __linux__
    /* A battery-backed RTC is the only clock this device can justify while
     * offline. /dev/rtc0 appears once the ds3231 overlay is loaded. */
    int fd = open("/dev/rtc0", O_RDONLY);
    if (fd >= 0) {
        struct rtc_time rt;
        int rc = ioctl(fd, RTC_RD_TIME, &rt);
        close(fd);
        if (rc == 0) {
            struct tm tm_rtc;
            memset(&tm_rtc, 0, sizeof(tm_rtc));
            tm_rtc.tm_sec  = rt.tm_sec;   tm_rtc.tm_min  = rt.tm_min;
            tm_rtc.tm_hour = rt.tm_hour;  tm_rtc.tm_mday = rt.tm_mday;
            tm_rtc.tm_mon  = rt.tm_mon;   tm_rtc.tm_year = rt.tm_year;
            /* The RTC keeps UTC; timegm avoids the local-time round trip. */
            time_t utc = timegm(&tm_rtc);
            if (utc != (time_t)-1) {
                *out_now = (int64_t)utc;
                *out_trusted = 1;
                return 0;
            }
        }
    }
#endif

    if (!t->allow_untrusted_clock)
        return -1;   /* FR: no trusted clock, no decision */

    /* Development path only, and the decision records that it was taken. */
    *out_now = (int64_t)time(NULL);
    return 0;
}

int trust_revocation_ok(const trust_ctx *t)
{
    if (t->allow_no_revocation) return 1;
    if (!t->list) return 0;

    /* SPEC §15.5: verification is offline, revocation state is not. The local
     * copy has an age, and past the budget it is no longer evidence. */
    int64_t now; int trusted;
    if (trust_now(t, &now, &trusted) != 0) return 0;
    if (now - t->list_updated_at > t->revocation_max_age_s) return 0;
    return 1;
}
