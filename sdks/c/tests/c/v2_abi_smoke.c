/*
 * Protocol v2 C ABI smoke test, compiled with a plain C compiler against
 * include/ratify.h and the built ratify-c library.
 *
 * Usage: v2_abi_smoke <manifest-dir>
 *
 * <manifest-dir> is produced by scripts/test-v2-c-abi.sh from testvectors/v2:
 *   keys.txt     lines: <ed25519.bin> <ml_dsa_65.bin> <expected key_id_v2>
 *   vectors.txt  lines: <kind> <expected class> <wire.bin> <bundle.bin|-> <ctx.json|->
 * where <kind> is an object type code, or 0 for a receipt/bundle binding check.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ratify.h"

static int failures = 0;

static unsigned char *read_file(const char *dir, const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short read %s\n", path); exit(2); }
    buf[n] = 0; /* NUL-terminate so JSON files can be passed as C strings */
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static void check(int ok, const char *what, const char *detail) {
    if (!ok) {
        failures++;
        fprintf(stderr, "FAIL %s: %s\n", what, detail);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <manifest-dir>\n", argv[0]); return 2; }
    const char *dir = argv[1];

    /* Version query: the header and the loaded library must agree. */
    check(ratify_v2_abi_version() == RATIFY_V2_ABI_VERSION, "abi_version", "header/library mismatch");
    check(ratify_v2_protocol_version() == RATIFY_V2_PROTOCOL_VERSION, "protocol_version", "not 2");
    check(strncmp(ratify_v2_library_version(), "2.", 2) == 0, "library_version", ratify_v2_library_version());
    printf("ratify-c %s, v2 ABI %u, protocol %u\n", ratify_v2_library_version(),
           ratify_v2_abi_version(), ratify_v2_protocol_version());

    /* Key IDs. */
    char line[8192], a[1024], b[1024], c[1024], d[1024], e[1024];
    size_t path_len;
    char *keys = (char *)read_file(dir, "keys.txt", &path_len);
    int nkeys = 0;
    for (char *l = strtok(keys, "\n"); l; l = strtok(NULL, "\n")) {
        if (sscanf(l, "%1023s %1023s %1023s", a, b, c) != 3) continue;
        size_t ed_len, ml_len;
        unsigned char *ed = read_file(dir, a, &ed_len);
        unsigned char *ml = read_file(dir, b, &ml_len);
        char id[RATIFY_V2_KEY_ID_BUF_LEN];
        int32_t rc = ratify_v2_key_id(ed, ed_len, ml, ml_len, id, sizeof id, NULL);
        check(rc == RatifyV2Ok && strcmp(id, c) == 0, "key_id", c);
        check(ratify_v2_key_id_check(id, NULL) == RatifyV2Ok, "key_id_check", id);
        free(ed); free(ml);
        nkeys++;
    }
    free(keys);
    /* A v1 128-bit ID is never a v2 key ID. */
    check(ratify_v2_key_id_check("e332d03407dd65302cc508582226f653", NULL) == RatifyV2Malformed,
          "key_id_check v1", "128-bit ID accepted");

    /* Object vectors. */
    size_t mlen;
    char *manifest = (char *)read_file(dir, "vectors.txt", &mlen);
    int nvec = 0, npos = 0, nneg = 0;
    for (char *l = strtok(manifest, "\n"); l; l = strtok(NULL, "\n")) {
        int kind;
        if (sscanf(l, "%d %1023s %1023s %1023s %1023s", &kind, a, b, d, e) != 5) continue;
        size_t wire_len, bundle_len = 0, ctx_len;
        unsigned char *wire = read_file(dir, b, &wire_len);
        unsigned char *bundle = strcmp(d, "-") ? read_file(dir, d, &bundle_len) : NULL;
        char *ctx = strcmp(e, "-") ? (char *)read_file(dir, e, &ctx_len) : NULL;
        char *err = NULL;
        int32_t rc = kind == 0
            ? ratify_v2_receipt_bundle_binding_check(wire, wire_len, bundle, bundle_len, &err)
            : ratify_v2_verify_object(kind, wire, wire_len, ctx, &err);
        const char *got = ratify_v2_error_class_str(rc);
        if (strcmp(got, a) != 0) {
            snprintf(line, sizeof line, "%s: got %s want %s (%s)", b, got, a, err ? err : "");
            check(0, "vector", line);
        }
        if (strcmp(a, "ok") == 0) npos++; else nneg++;
        ratify_error_free(err);
        free(wire); free(bundle); free(ctx);
        nvec++;
    }
    free(manifest);

    /* An object kind that is not a standalone signed object. */
    check(ratify_v2_verify_object(9, (const uint8_t *)"{}", 2, NULL, NULL) == RatifyV2UnsupportedObjectType,
          "kind 9", "not unsupported_object_type");

    printf("key IDs: %d, vectors: %d (%d positive, %d negative), failures: %d\n",
           nkeys, nvec, npos, nneg, failures);
    if (nkeys == 0 || npos == 0 || nneg == 0) { fprintf(stderr, "empty manifest\n"); return 1; }
    return failures ? 1 : 0;
}
