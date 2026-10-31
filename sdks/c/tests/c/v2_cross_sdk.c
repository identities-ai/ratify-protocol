/*
 * Cross-SDK fixtures (every testvectors/v2/cross-sdk fixture) verified through the
 * C ABI: the whole-file procedure (ratify_v2_cross_sdk_fixture_verify) and a
 * granular check of every key, object, and signature transcript.
 *
 * Manifest cross/index.txt, per fixture:
 *   fixture <sdk> <file.json>
 *   key <ed seed> <ml seed> <pub ed> <pub ml> <key_id_v2>
 *   obj <kind> <wire> <ctx.json|-> <bundle|->
 *   sig <code> <source wire> <signable> <M> <context> <mu> <sig ed> <sig ml> <key ed> <key ml> <key_id>
 *   end
 * <source wire> is the object the projection comes from (a certificate
 * inside a bundle is extracted by the script and canonicalized here).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v2c.h"

static int equal_file(const uint8_t *got, size_t len, const char *file) {
    size_t n;
    uint8_t *want = v2c_read(file, &n);
    int ok = n == len && memcmp(want, got, n) == 0;
    free(want);
    return ok;
}

static uint8_t *buffer_of(int32_t rc, RatifyV2Buffer b, size_t *len, const char *what) {
    uint8_t *out = v2c_take(b, len);
    v2c_check(rc == 0, what, ratify_v2_last_error_message());
    return out;
}

int v2c_run_cross_sdk(void) {
    char *index = (char *)v2c_read("cross/index.txt", NULL), *save = NULL;
    char a[512], b[512], c[512], d[512], e[512], f[512], g[512], h[512], i2[512], j[512], k[512];
    int fixtures = 0, objects = 0, sigs = 0, keys = 0;
    char sdk[64] = "";
    for (char *l = strtok_r(index, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        char detail[1200];
        if (sscanf(l, "fixture %63s %511s", sdk, a) == 2) {
            size_t len;
            uint8_t *data = v2c_read(a, &len);
            int32_t rc = ratify_v2_cross_sdk_fixture_verify(data, len, sdk);
            snprintf(detail, sizeof detail, "%s: %s (%s)", sdk, v2c_class(rc), ratify_v2_last_error_message());
            v2c_check(rc == 0, "cross-sdk fixture", detail);
            /* Read under another SDK's name, the same file must fail. */
            rc = ratify_v2_cross_sdk_fixture_verify(data, len, strcmp(sdk, "go") == 0 ? "rust" : "go");
            v2c_check(rc == RatifyV2Malformed, "cross-sdk wrong name", sdk);
            free(data);
            fixtures++;
        } else if (sscanf(l, "key %511s %511s %511s %511s %511s", a, b, c, d, e) == 5) {
            uint8_t *ed = v2c_read(a, NULL), *ml = v2c_read(b, NULL);
            RatifyV2KeyPair *kp = NULL;
            v2c_check(ratify_v2_keypair_from_seeds(ed, ml, &kp) == 0, "cross-sdk key", sdk);
            RatifyV2PublicKey got, want;
            v2c_load_key(c, d, &want);
            char id[RATIFY_V2_KEY_ID_BUF_LEN];
            ratify_v2_keypair_public_key(kp, &got);
            ratify_v2_keypair_key_id(kp, id, sizeof id);
            snprintf(detail, sizeof detail, "%s key %s", sdk, e);
            v2c_check(memcmp(&got, &want, sizeof got) == 0 && strcmp(id, e) == 0, "cross-sdk key derivation", detail);
            ratify_v2_keypair_free(kp);
            free(ed);
            free(ml);
            keys++;
        } else if (sscanf(l, "obj %511s %511s %511s %511s", a, b, c, d) == 4) {
            int kind = atoi(a);
            size_t len, blen = 0;
            uint8_t *wire = v2c_read(b, &len);
            if (kind != 0) {
                RatifyV2Buffer out = {0};
                int32_t rc = ratify_v2_object_decode(kind, wire, len, &out);
                size_t n;
                uint8_t *re = v2c_take(out, &n);
                snprintf(detail, sizeof detail, "%s %s: %s", sdk, b, ratify_v2_last_error_message());
                v2c_check(rc == 0 && n == len && memcmp(re, wire, n) == 0, "cross-sdk re-encode", detail);
                free(re);
                char *ctx = (char *)v2c_read_opt(c, NULL);
                rc = ratify_v2_verify_object(kind, wire, len, ctx, NULL);
                snprintf(detail, sizeof detail, "%s %s: %s", sdk, b, ratify_v2_last_error_message());
                v2c_check(rc == 0, "cross-sdk verify", detail);
                free(ctx);
            } else {
                uint8_t *bundle = v2c_read_opt(d, &blen);
                int32_t rc = ratify_v2_receipt_bundle_binding_check(wire, len, bundle, blen, NULL);
                v2c_check(rc == 0, "cross-sdk binding", b);
                free(bundle);
            }
            free(wire);
            objects++;
        } else if (sscanf(l, "sig %511s %511s %511s %511s %511s %511s %511s %511s %511s %511s %511s", a, b, c, d, e, f, g, h,
                          i2, j, k) == 11) {
            uint32_t code = (uint32_t)atoi(a);
            size_t src_len, slen, mlen, clen, mulen, ed_len, ml_len;
            uint8_t *src = v2c_read(b, &src_len);
            /* A certificate extracted from a bundle is canonicalized here. */
            RatifyV2Buffer canon = {0};
            int32_t rc = ratify_v2_canonical_json(src, src_len, &canon);
            free(src);
            src = buffer_of(rc, canon, &src_len, "cross-sdk canonical source");
            RatifyV2Buffer out = {0};
            rc = ratify_v2_signable_bytes(code, src, src_len, &out);
            uint8_t *signable = buffer_of(rc, out, &slen, "cross-sdk signable");
            snprintf(detail, sizeof detail, "%s %s code %u", sdk, b, code);
            v2c_check(equal_file(signable, slen, c), "cross-sdk projection", detail);
            RatifyV2Buffer m = {0};
            rc = ratify_v2_signing_message(code, signable, slen, &m);
            uint8_t *msg = buffer_of(rc, m, &mlen, "cross-sdk message");
            v2c_check(mlen == 77 && equal_file(msg, mlen, d), "cross-sdk M", detail);
            RatifyV2Buffer cx = {0};
            rc = ratify_v2_mldsa_context(code, &cx);
            uint8_t *ctx = buffer_of(rc, cx, &clen, "cross-sdk context");
            v2c_check(clen == 22 && equal_file(ctx, clen, e), "cross-sdk context", detail);
            RatifyV2PublicKey key;
            v2c_load_key(i2, j, &key);
            RatifyV2Buffer mu = {0};
            rc = ratify_v2_external_mu(&key, code, msg, mlen, &mu);
            uint8_t *mub = buffer_of(rc, mu, &mulen, "cross-sdk mu");
            v2c_check(mulen == 64 && equal_file(mub, mulen, f), "cross-sdk mu", detail);
            uint8_t *sed = v2c_read(g, &ed_len), *sml = v2c_read(h, &ml_len);
            RatifyV2Slice se = {sed, ed_len}, sm = {sml, ml_len};
            rc = ratify_v2_verify_statement(code, signable, slen, se, sm, &key);
            v2c_check(rc == 0, "cross-sdk signature", detail);
            /* A different code is a different transcript. */
            rc = ratify_v2_verify_statement(code == 1 ? 2 : 1, signable, slen, se, sm, &key);
            v2c_check(rc == RatifyV2InvalidSignature, "cross-sdk cross-code", detail);
            char id[RATIFY_V2_KEY_ID_BUF_LEN];
            ratify_v2_public_key_id(&key, id, sizeof id);
            v2c_check(strcmp(id, k) == 0, "cross-sdk signer id", detail);
            free(src); free(signable); free(msg); free(ctx); free(mub); free(sed); free(sml);
            sigs++;
        }
    }
    free(index);
    printf("cross-sdk: %d fixtures, %d keys, %d objects, %d signatures\n", fixtures, keys, objects, sigs);
    if (fixtures == 0 || sigs == 0) { fprintf(stderr, "empty cross-sdk manifest\n"); exit(1); }
    return fixtures + keys + objects + sigs;
}
