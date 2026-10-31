#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const uint8_t *in, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = i + 1 < len ? B64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? B64[v & 63] : '=';
    }
    out[o] = '\0';
    return out;
}

long b64_decode(const char *in, uint8_t *out, size_t cap)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (; *in && *in != '='; in++) {
        const char *p = strchr(B64, *in);
        if (!p || !*in) return -1;
        acc = (acc << 6) | (uint32_t)(p - B64);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return -1;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    return (long)n;
}

void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 15];
    }
    out[2 * len] = '\0';
}

int hex_decode(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned v;
        if (!hex[2 * i] || !hex[2 * i + 1] || sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- SHA-256 (FIPS 180-4) ---------------------------------------------- */

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = k + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t i = 0;
    for (; i + 64 <= len; i += 64) sha256_block(h, in + i);
    uint8_t tail[128] = {0};
    size_t rem = len - i;
    memcpy(tail, in + i, rem);
    tail[rem] = 0x80;
    size_t tlen = rem + 9 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) tail[tlen - 1 - j] = (uint8_t)(bits >> (8 * j));
    for (size_t j = 0; j < tlen; j += 64) sha256_block(h, tail + j);
    for (int j = 0; j < 8; j++) {
        out[4 * j] = (uint8_t)(h[j] >> 24); out[4 * j + 1] = (uint8_t)(h[j] >> 16);
        out[4 * j + 2] = (uint8_t)(h[j] >> 8); out[4 * j + 3] = (uint8_t)h[j];
    }
}

/* ---- SHA-384 (SHA-512 family) ------------------------------------------ */

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static void sha512_block(uint64_t h[8], const uint8_t *p)
{
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | p[8 * i + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = k + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
        uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void sha384(const uint8_t *in, size_t len, uint8_t out[48])
{
    uint64_t h[8] = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
                     0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
                     0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
    size_t i = 0;
    for (; i + 128 <= len; i += 128) sha512_block(h, in + i);
    uint8_t tail[256] = {0};
    size_t rem = len - i;
    memcpy(tail, in + i, rem);
    tail[rem] = 0x80;
    size_t tlen = rem + 17 <= 128 ? 128 : 256;
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) tail[tlen - 1 - j] = (uint8_t)(bits >> (8 * j));
    for (size_t j = 0; j < tlen; j += 128) sha512_block(h, tail + j);
    for (int j = 0; j < 6; j++)
        for (int b = 0; b < 8; b++) out[8 * j + b] = (uint8_t)(h[j] >> (56 - 8 * b));
}

void sha384_labelled_hex(const char *label, const uint8_t *data, size_t len, char out[97])
{
    size_t ll = strlen(label);
    uint8_t *buf = malloc(ll + 1 + len);
    uint8_t digest[48];
    memcpy(buf, label, ll);
    buf[ll] = 0;
    if (len) memcpy(buf + ll + 1, data, len);
    sha384(buf, ll + 1 + len, digest);
    free(buf);
    hex_encode(digest, 48, out);
}

/* ---- Files ----------------------------------------------------------------- */

char *read_file(const char *path, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || (size_t)sz > cap) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    if (len) *len = rd;
    return buf;
}

int fsync_dir_of(const char *path)
{
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0'; else snprintf(dir, sizeof dir, ".");
    CRASH_POINT("dirsync", path, 0);
    int fd = open(dir, O_RDONLY);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    CRASH_POINT("dirsync", path, 1);
    return rc;
}

int write_file_sync(const char *path, const void *data, size_t len, int mode)
{
    CRASH_POINT("write", path, 0);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    const uint8_t *p = data;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    if (fsync(fd) != 0) { close(fd); return -1; }
    int rc = close(fd);
    CRASH_POINT("write", path, 1);
    return rc;
}

int write_file_durable(const char *path, const void *data, size_t len, int mode)
{
    char tmp[1100];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (write_file_sync(tmp, data, len, mode) != 0) return -1;
    CRASH_POINT("rename", path, 0);
    if (rename(tmp, path) != 0) return -1;
    CRASH_POINT("rename", path, 1);
    return fsync_dir_of(path);
}

#ifdef SENTINEL_TEST_BUILD
/* See CRASH_POINT in util.h. Test builds only: the production binaries have
 * no crash injection at all. */
void crash_point(const char *step, const char *path, int after)
{
    static long target = -1, reached = 0;
    static int crash_after = 0, configured = 0;
    if (!configured) {
        const char *at = getenv("SENTINEL_CRASH_AT"), *mode = getenv("SENTINEL_CRASH_MODE");
        target = at && *at ? strtol(at, NULL, 10) : -1;
        crash_after = mode && strcmp(mode, "after") == 0;
        configured = 1;
    }
    if (target < 0) return;
    const char *name = path ? strrchr(path, '/') : NULL;
    name = name ? name + 1 : path ? path : "-";
    if (!after) {
        reached++;
        fprintf(stderr, "crash-point %ld %s %s\n", reached, step, name);
    }
    if (reached == target && after == crash_after) {
        fprintf(stderr, "CRASH at %ld %s %s %s\n", reached, after ? "after" : "before", step, name);
        _exit(86);
    }
}
#endif

char *xformat(const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *s = malloc((size_t)n + 1);
    if (s) vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

char *take_buffer(RatifyV2Buffer b, size_t *len)
{
    char *s = malloc(b.len + 1);
    if (s) {
        if (b.len) memcpy(s, b.ptr, b.len);
        s[b.len] = '\0';
    }
    if (len) *len = b.len;
    ratify_v2_buffer_free(b);
    return s;
}

/* ---- Canonical JSON field readers ---------------------------------------- */

static const char *json_value(const char *json, const char *key)
{
    char pattern[160];
    snprintf(pattern, sizeof pattern, "\"%s\":", key);
    const char *p = strstr(json, pattern);
    return p ? p + strlen(pattern) : NULL;
}

int json_get_str(const char *json, const char *key, char *out, size_t cap)
{
    const char *p = json_value(json, key);
    if (!p || *p != '"') return 0;
    p++;
    size_t n = 0;
    while (p[n] && p[n] != '"') {
        if (p[n] == '\\') return 0; /* no escapes in the fields read here */
        n++;
    }
    if (n + 1 > cap) return 0;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

int json_get_int(const char *json, const char *key, int64_t *out)
{
    const char *p = json_value(json, key);
    if (!p || (*p != '-' && (*p < '0' || *p > '9'))) return 0;
    *out = strtoll(p, NULL, 10);
    return 1;
}

char *json_get_raw(const char *json, const char *key)
{
    const char *p = json_value(json, key);
    if (!p || (*p != '{' && *p != '[')) return NULL;
    const char *start = p;
    int depth = 0, in_str = 0, esc = 0;
    for (; *p; p++) {
        if (in_str) {
            if (esc) esc = 0;
            else if (*p == '\\') esc = 1;
            else if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') in_str = 1;
        else if (*p == '{' || *p == '[') depth++;
        else if ((*p == '}' || *p == ']') && --depth == 0) {
            size_t n = (size_t)(p - start + 1);
            char *out = malloc(n + 1);
            if (!out) return NULL;
            memcpy(out, start, n);
            out[n] = '\0';
            return out;
        }
    }
    return NULL;
}

int random_bytes(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0) { close(fd); return -1; }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ---- Keys ------------------------------------------------------------------ */

int keypair_save(const char *path, const uint8_t ed[32], const uint8_t ml[32])
{
    char text[140];
    char a[65], b[65];
    hex_encode(ed, 32, a);
    hex_encode(ml, 32, b);
    int n = snprintf(text, sizeof text, "%s\n%s\n", a, b);
    int rc = write_file_durable(path, text, (size_t)n, 0600);
    memset(text, 0, sizeof text);
    return rc;
}

RatifyV2KeyPair *keypair_load(const char *path)
{
    char *text = read_file(path, 1024, NULL);
    if (!text) return NULL;
    uint8_t ed[32], ml[32];
    RatifyV2KeyPair *kp = NULL;
    if (strlen(text) >= 130 && hex_decode(text, ed, 32) == 0 && hex_decode(text + 65, ml, 32) == 0)
        ratify_v2_keypair_from_seeds(ed, ml, &kp);
    memset(ed, 0, sizeof ed);
    memset(ml, 0, sizeof ml);
    memset(text, 0, strlen(text));
    free(text);
    return kp;
}

RatifyV2KeyPair *keypair_create(const char *path)
{
    uint8_t ed[32], ml[32];
    RatifyV2KeyPair *kp = NULL;
    if (ratify_v2_keypair_generate(&kp, ed, ml) != 0) return NULL;
    if (keypair_save(path, ed, ml) != 0) {
        ratify_v2_keypair_free(kp);
        kp = NULL;
    }
    memset(ed, 0, sizeof ed);
    memset(ml, 0, sizeof ml);
    return kp;
}

char *public_key_json(const RatifyV2PublicKey *key)
{
    char *s = NULL;
    if (ratify_v2_public_key_to_json(key, &s) != 0) return NULL;
    char *copy = xformat("%s", s);
    ratify_v2_string_free(s);
    return copy;
}

int public_key_from_json(const char *json, RatifyV2PublicKey *out)
{
    char *ed = malloc(4096), *ml = malloc(4096);
    int ok = ed && ml && json_get_str(json, "ed25519", ed, 4096) && json_get_str(json, "ml_dsa_65", ml, 4096) &&
             b64_decode(ed, out->ed25519, sizeof out->ed25519) == 32 &&
             b64_decode(ml, out->ml_dsa_65, sizeof out->ml_dsa_65) == 1952;
    free(ed);
    free(ml);
    return ok ? 0 : -1;
}
