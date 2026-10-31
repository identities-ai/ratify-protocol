/*
 * Small helpers shared by the Ratify Protocol v2 C examples: error checks,
 * a few JSON field readers for the library's canonical output, base64
 * decoding, and string building. They are deliberately minimal and read
 * only the canonical JSON this library writes; they are not a JSON parser.
 */
#ifndef RATIFY_EXAMPLE_UTIL_H
#define RATIFY_EXAMPLE_UTIL_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ratify.h"

/* Stop on any non-zero ratify_v2_* result, naming its class. */
#define CHECK(call)                                                            \
    do {                                                                       \
        int32_t rc_ = (call);                                                  \
        if (rc_ != 0) {                                                        \
            fprintf(stderr, "error: %s failed: %s (%s)\n", #call,              \
                    ratify_v2_error_class_str(rc_), ratify_v2_last_error_message()); \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static inline void fail(const char *what) {
    fprintf(stderr, "error: %s\n", what);
    exit(1);
}

/* A heap copy of a library buffer as a NUL-terminated string; frees the buffer. */
static inline char *take_string(RatifyV2Buffer b) {
    char *s = malloc(b.len + 1);
    if (!s) fail("out of memory");
    if (b.len) memcpy(s, b.ptr, b.len);
    s[b.len] = '\0';
    ratify_v2_buffer_free(b);
    return s;
}

/* printf into a new heap string. */
static inline char *format(const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *s = malloc((size_t)n + 1);
    if (!s) fail("out of memory");
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

/* The first occurrence of "key": in json, positioned at its value. */
static inline const char *json_find(const char *json, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof pattern, "\"%s\":", key);
    const char *p = strstr(json, pattern);
    if (!p) {
        fprintf(stderr, "error: JSON member %s not found\n", key);
        exit(1);
    }
    return p + strlen(pattern);
}

static inline int64_t json_int(const char *json, const char *key) {
    return strtoll(json_find(json, key), NULL, 10);
}

/* Copies the string value of key into out. */
static inline void json_str(const char *json, const char *key, char *out, size_t out_len) {
    const char *p = json_find(json, key);
    if (*p != '"') fail("JSON member is not a string");
    p++;
    size_t n = 0;
    while (p[n] && p[n] != '"') n++;
    if (n + 1 > out_len) fail("JSON string too long");
    memcpy(out, p, n);
    out[n] = '\0';
}

/* Decodes standard base64; returns the decoded length. */
static inline size_t b64_decode(const char *in, uint8_t *out, size_t out_len) {
    static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (; *in && *in != '='; in++) {
        const char *pos = strchr(alphabet, *in);
        if (!pos) fail("invalid base64");
        acc = (acc << 6) | (uint32_t)(pos - alphabet);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_len) fail("base64 output too long");
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    return n;
}

/* The wire JSON {"ed25519":..,"ml_dsa_65":..} of a public key. */
static inline char *key_json(const RatifyV2PublicKey *key) {
    char *s = NULL;
    CHECK(ratify_v2_public_key_to_json(key, &s));
    char *copy = format("%s", s);
    ratify_v2_string_free(s);
    return copy;
}

static inline const char *stage_name(int32_t stage) {
    switch (stage) {
    case RatifyV2StagePreflight: return "preflight";
    case RatifyV2StageReplay: return "replay";
    case RatifyV2StageEvaluating: return "evaluating";
    case RatifyV2StageCommitted: return "committed";
    default: return "none";
    }
}

static inline const char *disposition_name(int32_t disposition) {
    switch (disposition) {
    case RatifyV2DispositionCreated: return "created";
    case RatifyV2DispositionInProgress: return "in_progress";
    case RatifyV2DispositionTerminalReplay: return "terminal_replay";
    default: return "";
    }
}

#endif /* RATIFY_EXAMPLE_UTIL_H */
