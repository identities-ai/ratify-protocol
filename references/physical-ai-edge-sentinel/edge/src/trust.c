#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trust.h"
#include "util.h"

static int load_key(const char *dir, const char *name, RatifyV2PublicKey *key, char *id, char **json_out)
{
    char path[600];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    char *json = read_file(path, 1 << 16, NULL);
    if (!json || public_key_from_json(json, key) != 0 ||
        ratify_v2_public_key_id(key, id, RATIFY_V2_KEY_ID_BUF_LEN) != 0) {
        fprintf(stderr, "trust: %s missing or not a complete hybrid public key\n", path);
        free(json);
        return -1;
    }
    if (json_out) *json_out = public_key_json(key);
    free(json);
    return 0;
}

static void trim(char **s)
{
    while (**s == ' ' || **s == '\t') (*s)++;
    char *e = *s + strlen(*s);
    while (e > *s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = '\0';
}

static void load_policy(const char *path, trust_config *t)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line, *v = eq + 1;
        trim(&k);
        trim(&v);
        if (!strcmp(k, "zone") && t->zone_count < TRUST_MAX_ZONES)
            snprintf(t->zones[t->zone_count++], TRUST_ZONE_MAX, "%s", v);
        else if (!strcmp(k, "max_activation_ms"))
            t->max_activation_ms = atoi(v);
        else if (!strcmp(k, "workspace_id"))
            snprintf(t->workspace_id, sizeof t->workspace_id, "%s", v);
        else if (!strcmp(k, "status_max_age_s"))
            t->status_max_age_s = strtoll(v, NULL, 10);
        else if (!strcmp(k, "challenge_lifetime_s"))
            t->challenge_lifetime_s = strtoll(v, NULL, 10);
        else if (!strcmp(k, "max_challenge_age_s"))
            t->max_challenge_age_s = strtoll(v, NULL, 10);
    }
    fclose(f);
}

int trust_load(const char *dir, trust_config *t)
{
    memset(t, 0, sizeof *t);
    if (load_key(dir, "root_pub.json", &t->root_key, t->root_id, &t->root_json) != 0 ||
        load_key(dir, "status_pub.json", &t->status_key, t->status_id, &t->status_json) != 0 ||
        load_key(dir, "agent_pub.json", &t->agent_key, t->agent_id, &t->agent_json) != 0 ||
        load_key(dir, "checkpoint_pub.json", &t->checkpoint_key, t->checkpoint_id, NULL) != 0) {
        trust_unload(t);
        return -1;
    }
    /* Role separation. In v1 the pinned operator key also signed the
     * revocation list. In v2 status is signed only by a separate status key
     * bound to the root, and no key serves two roles here. */
    const char *ids[4] = {t->root_id, t->status_id, t->agent_id, t->checkpoint_id};
    for (int i = 0; i < 4; i++)
        for (int j = i + 1; j < 4; j++)
            if (strcmp(ids[i], ids[j]) == 0) {
                fprintf(stderr, "trust: one key is configured for two roles (%s); refusing\n",
                        (i == 0 && j == 1) ? "root key reused as the status key" : "role conflict");
                trust_unload(t);
                return -1;
            }
    t->status_epoch = 1;
    t->max_activation_ms = 1000;
    t->status_max_age_s = 3600;
    t->challenge_lifetime_s = 120;
    t->max_challenge_age_s = 240; /* 300 s window less a 60 s RTC drift budget (SPEC-v2 §9.7) */
    char path[600];
    snprintf(path, sizeof path, "%s/policy.conf", dir);
    load_policy(path, t);
    if (strlen(t->workspace_id) != 36) {
        fprintf(stderr, "trust: policy.conf needs workspace_id (a lowercase UUID)\n");
        trust_unload(t);
        return -1;
    }
    return 0;
}

void trust_unload(trust_config *t)
{
    free(t->root_json);
    free(t->status_json);
    free(t->agent_json);
    t->root_json = t->status_json = t->agent_json = NULL;
}

int trust_zone_allowed(const trust_config *t, const char *zone)
{
    if (!zone || !*zone) return 0;
    for (int i = 0; i < t->zone_count; i++)
        if (strcmp(t->zones[i], zone) == 0) return 1;
    return 0;
}
