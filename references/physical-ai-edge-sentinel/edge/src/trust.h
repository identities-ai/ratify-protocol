#ifndef SENTINEL_TRUST_H
#define SENTINEL_TRUST_H

#include <stdint.h>

#define TRUST_ID_HEX_LEN 32
#define TRUST_ZONE_MAX 64
#define TRUST_MAX_ZONES 8

struct RatifyRevocationList;

typedef struct {
    char pinned_human_id[TRUST_ID_HEX_LEN + 1];

    /* Revocation state. `list` is non-NULL only when the file was present,
     * its hybrid signature verified against the pinned operator's key, its
     * issuer_id matched the pinned anchor, and it was inside the freshness
     * budget. Anything less leaves it NULL and revocation unavailable. */
    struct RatifyRevocationList *list;
    int64_t list_updated_at;
    int64_t revocation_max_age_s;

    /* Local policy. Stricter than the delegation, never broader. */
    char    zones[TRUST_MAX_ZONES][TRUST_ZONE_MAX];
    int     zone_count;
    int     max_activation_ms;

    int  allow_no_revocation;      /* test build only */
    int  allow_untrusted_clock;    /* test build only */
} trust_ctx;

int  trust_load(const char *trust_dir, trust_ctx *t);
void trust_unload(trust_ctx *t);

int  trust_now(const trust_ctx *t, int64_t *out_now, int *out_trusted);

/* 1 when revocation state is good enough to authorize a sensitive action. */
int  trust_revocation_ok(const trust_ctx *t);

/* Revocation lookup for the SDK callback: 1 revoked, 0 not revoked,
 * -1 unavailable (fail closed). */
int  trust_is_revoked(const trust_ctx *t, const char *cert_id);

/* 1 if `zone` is permitted by local policy. An empty policy permits nothing. */
int  trust_zone_allowed(const trust_ctx *t, const char *zone);

#endif
