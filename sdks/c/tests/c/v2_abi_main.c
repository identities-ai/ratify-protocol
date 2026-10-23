/*
 * Protocol v2 C ABI conformance program, compiled with a plain C compiler
 * against include/ratify.h and the built ratify-c library.
 *
 * Usage: v2_abi <manifest-dir>
 *
 * <manifest-dir> is produced by scripts/test-v2-c-abi.sh from testvectors/v2.
 * This file holds the shared helpers, key IDs, objects, object negatives,
 * hedged signatures, and limits; v2_ordering.c, v2_lifecycle.c, and
 * v2_cross_sdk.c hold the other sections.
 *
 *   keys.txt     <ed25519.bin> <ml_dsa_65.bin> <expected key_id_v2>
 *   vectors.txt  <kind> <expected class> <wire> <bundle|-> <ctx.json|-> <R|->
 *                (kind is an object code, or 0 for a receipt/bundle binding
 *                check; R requests a byte-identical re-encode check)
 *   limits.txt   <kind> <accept|reject> <class|-> <data> <pass|fail size gate>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v2c.h"

int v2c_failures = 0;
const char *v2c_dir = NULL;

unsigned char *v2c_read(const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", v2c_dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short read %s\n", path); exit(2); }
    buf[n] = 0; /* NUL-terminate so JSON files can be passed as C strings */
    fclose(f);
    if (len) *len = (size_t)n;
    return buf;
}

unsigned char *v2c_read_opt(const char *name, size_t *len) {
    if (strcmp(name, "-") == 0) { if (len) *len = 0; return NULL; }
    return v2c_read(name, len);
}

void v2c_check(int ok, const char *what, const char *detail) {
    if (!ok) {
        v2c_failures++;
        fprintf(stderr, "FAIL %s: %s\n", what, detail);
    }
}

char *v2c_b64(const uint8_t *data, size_t len) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *out = malloc(4 * ((len + 2) / 3) + 1);
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < len ? t[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? t[v & 63] : '=';
    }
    out[o] = 0;
    return out;
}

void v2c_load_key(const char *ed_file, const char *ml_file, RatifyV2PublicKey *out) {
    size_t a, b;
    unsigned char *ed = v2c_read(ed_file, &a);
    unsigned char *ml = v2c_read(ml_file, &b);
    if (a != sizeof out->ed25519 || b != sizeof out->ml_dsa_65) { fprintf(stderr, "bad key %s\n", ed_file); exit(2); }
    memcpy(out->ed25519, ed, a);
    memcpy(out->ml_dsa_65, ml, b);
    free(ed);
    free(ml);
}

const char *v2c_class(int32_t code) { return ratify_v2_error_class_str(code); }

uint8_t *v2c_take(RatifyV2Buffer b, size_t *len) {
    uint8_t *out = malloc(b.len + 1);
    if (b.len) memcpy(out, b.ptr, b.len);
    out[b.len] = 0;
    if (len) *len = b.len;
    ratify_v2_buffer_free(b);
    return out;
}

int v2c_run_objects(void) {
    char line[8192], a[1024], b[1024], c[1024], d[1024], e[1024], r[16];
    int checks = 0;

    /* Key IDs. */
    char *keys = (char *)v2c_read("keys.txt", NULL);
    int nkeys = 0;
    char *save = NULL;
    for (char *l = strtok_r(keys, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        if (sscanf(l, "%1023s %1023s %1023s", a, b, c) != 3) continue;
        size_t ed_len, ml_len;
        unsigned char *ed = v2c_read(a, &ed_len);
        unsigned char *ml = v2c_read(b, &ml_len);
        char id[RATIFY_V2_KEY_ID_BUF_LEN];
        int32_t rc = ratify_v2_key_id(ed, ed_len, ml, ml_len, id, sizeof id, NULL);
        v2c_check(rc == RatifyV2Ok && strcmp(id, c) == 0, "key_id", c);
        v2c_check(ratify_v2_key_id_check(id, NULL) == RatifyV2Ok, "key_id_check", id);
        free(ed); free(ml);
        nkeys++;
    }
    free(keys);
    v2c_check(ratify_v2_key_id_check("e332d03407dd65302cc508582226f653", NULL) == RatifyV2Malformed,
              "key_id_check v1", "128-bit ID accepted");

    /* Objects, negatives, hedged signatures. */
    char *manifest = (char *)v2c_read("vectors.txt", NULL);
    int npos = 0, nneg = 0, nre = 0;
    save = NULL;
    for (char *l = strtok_r(manifest, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        int kind;
        if (sscanf(l, "%d %1023s %1023s %1023s %1023s %15s", &kind, a, b, d, e, r) != 6) continue;
        size_t wire_len, bundle_len = 0;
        unsigned char *wire = v2c_read(b, &wire_len);
        unsigned char *bundle = v2c_read_opt(d, &bundle_len);
        char *ctx = (char *)v2c_read_opt(e, NULL);
        char *err = NULL;
        int32_t rc = kind == 0
            ? ratify_v2_receipt_bundle_binding_check(wire, wire_len, bundle, bundle_len, &err)
            : ratify_v2_verify_object(kind, wire, wire_len, ctx, &err);
        const char *got = v2c_class(rc);
        if (strcmp(got, a) != 0) {
            snprintf(line, sizeof line, "%s: got %s want %s (%s)", b, got, a, err ? err : "");
            v2c_check(0, "vector", line);
        }
        if (strcmp(a, "ok") == 0) npos++; else nneg++;
        if (strcmp(r, "R") == 0) {
            RatifyV2Buffer out = {0};
            rc = ratify_v2_object_decode(kind, wire, wire_len, &out);
            size_t n;
            uint8_t *re = v2c_take(out, &n);
            v2c_check(rc == 0 && n == wire_len && memcmp(re, wire, n) == 0, "re-encode", b);
            free(re);
            nre++;
        }
        ratify_error_free(err);
        free(wire); free(bundle); free(ctx);
        checks++;
    }
    free(manifest);

    /* An object kind that is not a standalone signed object. */
    v2c_check(ratify_v2_verify_object(9, (const uint8_t *)"{}", 2, NULL, NULL) == RatifyV2UnsupportedObjectType,
              "kind 9", "not unsupported_object_type");
    /* Diagnostics are thread-local and the code is authoritative. */
    v2c_check(ratify_v2_key_id_check(NULL, NULL) == RatifyV2ErrNullPointer, "null key id", "not null_pointer");
    v2c_check(strstr(ratify_v2_last_error_message(), "null") != NULL, "last error", ratify_v2_last_error_message());

    printf("key IDs: %d, vectors: %d (%d positive, %d negative, %d re-encoded)\n", nkeys, checks, npos, nneg, nre);
    if (nkeys == 0 || npos == 0 || nneg == 0 || nre == 0) { fprintf(stderr, "empty object manifest\n"); exit(1); }
    return checks + nkeys;
}

int v2c_run_limits(void) {
    char b[64], c[128], d[1024], g[16];
    char *manifest = (char *)v2c_read("limits.txt", NULL);
    int n = 0;
    char *save = NULL;
    for (char *l = strtok_r(manifest, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        int kind;
        if (sscanf(l, "%d %63s %127s %1023s %15s", &kind, b, c, d, g) != 5) continue;
        size_t len;
        unsigned char *data = v2c_read(d, &len);
        int32_t rc = ratify_v2_object_decode(kind, data, len, NULL);
        const char *msg = ratify_v2_last_error_message();
        char detail[512];
        snprintf(detail, sizeof detail, "%s: got %s (%s)", d, v2c_class(rc), msg);
        if (strcmp(b, "accept") == 0) v2c_check(rc == 0, "limit accept", detail);
        else v2c_check(strcmp(v2c_class(rc), c) == 0, "limit reject", detail);
        int gate = rc != 0 && strstr(msg, "rejected before parsing") != NULL;
        v2c_check(gate == (strcmp(g, "fail") == 0), "limit size gate", detail);
        free(data);
        n++;
    }
    free(manifest);
    printf("limits: %d\n", n);
    if (n == 0) { fprintf(stderr, "empty limits manifest\n"); exit(1); }

    /* A length larger than any object (SPEC-v2 §2.6): a one-byte buffer
     * with a forged length is rejected by the size gate before parsing and
     * is never read; a byte input with no size gate is bad_argument. */
    static const unsigned char one[1] = {'{'};
    static const int kinds[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 101, 102};
    const size_t forged[] = {(size_t)PTRDIFF_MAX + 1, SIZE_MAX};
    int nforged = 0;
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        for (size_t f = 0; f < 2; f++) {
            RatifyV2Buffer out = {0};
            int32_t rc = ratify_v2_object_decode(kinds[k], one, forged[f], &out);
            const char *msg = ratify_v2_last_error_message();
            char detail[512];
            snprintf(detail, sizeof detail, "kind %d length %zu: got %s (%s)", kinds[k], forged[f], v2c_class(rc), msg);
            v2c_check(strcmp(v2c_class(rc), "malformed") == 0 && strstr(msg, "rejected before parsing") != NULL,
                      "forged length size gate", detail);
            v2c_check(out.ptr == NULL && out.len == 0, "forged length output", detail);
            ratify_v2_buffer_free(out);
            nforged++;
        }
    }
    for (size_t f = 0; f < 2; f++) {
        RatifyV2Buffer out = {0};
        int32_t rc = ratify_v2_canonical_json(one, forged[f], &out);
        char detail[512];
        snprintf(detail, sizeof detail, "length %zu: got %s (%s)", forged[f], v2c_class(rc), ratify_v2_last_error_message());
        v2c_check(rc == RatifyV2ErrBadArgument, "forged length bad_argument", detail);
        ratify_v2_buffer_free(out);
        nforged++;
    }
    printf("forged lengths: %d\n", nforged);
    return n + nforged;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <manifest-dir>\n", argv[0]); return 2; }
    v2c_dir = argv[1];

    /* Version query: the header and the loaded library must agree. */
    v2c_check(ratify_v2_abi_version() == RATIFY_V2_ABI_VERSION, "abi_version", "header/library mismatch");
    v2c_check(ratify_v2_protocol_version() == RATIFY_V2_PROTOCOL_VERSION, "protocol_version", "not 2");
    v2c_check(strncmp(ratify_v2_library_version(), "2.", 2) == 0, "library_version", ratify_v2_library_version());
    v2c_check(strcmp(ratify_v2_tzdb_version(), "2025c") == 0, "tzdb_version", ratify_v2_tzdb_version());
    printf("ratify-c %s, v2 ABI %u, protocol %u, tzdb %s\n", ratify_v2_library_version(),
           ratify_v2_abi_version(), ratify_v2_protocol_version(), ratify_v2_tzdb_version());

    int total = 0;
    total += v2c_run_objects();
    total += v2c_run_limits();
    total += v2c_run_ordering();
    total += v2c_run_lifecycle();
    total += v2c_run_cross_sdk();
    printf("checks: %d, failures: %d\n", total, v2c_failures);
    return v2c_failures ? 1 : 0;
}
