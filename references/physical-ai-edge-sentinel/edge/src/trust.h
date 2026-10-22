/*
 * Receiver trust configuration, provisioned out of band into the trust
 * directory:
 *
 *   root_pub.json        the pinned root (issuer) public key, complete
 *   status_pub.json      the root's separate status key (epoch 1)
 *   agent_pub.json       the agent this device expects to present proofs
 *   checkpoint_pub.json  the checkpoint process's public key
 *   policy.conf          local policy (zones, duration cap, workspace)
 *   status-list.json     the signed status list staged at initialization
 *
 * Trust is pinned to complete public keys, never to a key ID alone. Each key
 * has exactly one role; a status key equal to the root key (the v1 "operator
 * key signs the revocation list" arrangement) is refused.
 */
#ifndef SENTINEL_TRUST_H
#define SENTINEL_TRUST_H

#include <stdint.h>

#include "ratify.h"

#define TRUST_ZONE_MAX 64
#define TRUST_MAX_ZONES 8
#define TRUST_NAMESPACE "ratify-edge-sentinel"

typedef struct {
    RatifyV2PublicKey root_key, status_key, agent_key, checkpoint_key;
    char root_id[RATIFY_V2_KEY_ID_BUF_LEN], status_id[RATIFY_V2_KEY_ID_BUF_LEN];
    char agent_id[RATIFY_V2_KEY_ID_BUF_LEN], checkpoint_id[RATIFY_V2_KEY_ID_BUF_LEN];
    char *root_json, *status_json, *agent_json;
    uint64_t status_epoch;

    /* Local policy. Stricter than the delegation, never broader. */
    char zones[TRUST_MAX_ZONES][TRUST_ZONE_MAX];
    int zone_count;
    int max_activation_ms;
    char workspace_id[40];
    int64_t status_max_age_s;
    int64_t challenge_lifetime_s;
    int64_t max_challenge_age_s;
} trust_config;

/* Load and check the trust directory. Returns 0, or -1 with a message. */
int  trust_load(const char *dir, trust_config *t);
void trust_unload(trust_config *t);

/* 1 if `zone` is permitted by local policy. An empty policy permits nothing. */
int  trust_zone_allowed(const trust_config *t, const char *zone);

#endif
