#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "actx.h"
#include "util.h"

static int field_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= ACTX_FIELD_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
              c == '_' || c == ':' || c == '-'))
            return 0;
    }
    return 1;
}

int actx_valid(const actx_action *a)
{
    return field_ok(a->scope) && field_ok(a->zone) && field_ok(a->resource) && field_ok(a->invocation) &&
           a->duration_ms >= 0 && a->duration_ms <= 86400000;
}

int actx_session_context(const actx_action *a, const char *verifier_id, const char *workspace_id,
                         const char *agent_id, uint8_t out[32])
{
    if (!actx_valid(a)) return -1;
    char payload[256];
    snprintf(payload, sizeof payload, "{\"duration_ms\":%d,\"resource\":\"%s\",\"zone\":\"%s\"}", a->duration_ms,
             a->resource, a->zone);
    uint8_t payload_digest[32];
    sha256((const uint8_t *)payload, strlen(payload), payload_digest);
    char *pd = b64_encode(payload_digest, 32);
    char *op = xformat("{\"required_scope\":\"%s\",\"operation\":\"%s\",\"resource_id\":\"%s\","
                       "\"requested_path\":\"/%s\",\"payload_digest_b64\":\"%s\"}",
                       a->scope, ACTX_OPERATION, a->zone, a->resource, pd);
    free(pd);
    RatifyV2Buffer hash = {0};
    int32_t rc = ratify_v2_operation_context_hash((const uint8_t *)op, strlen(op), &hash);
    free(op);
    if (rc != 0 || hash.len != 32) {
        ratify_v2_buffer_free(hash);
        return -1;
    }
    char *rh = b64_encode(hash.ptr, 32);
    ratify_v2_buffer_free(hash);
    char *in = xformat("{\"verifier_id\":\"%s\",\"workspace_id\":\"%s\",\"agent_id\":\"%s\",\"session_id\":\"%s\","
                       "\"invocation_id\":\"%s\",\"request_hash_b64\":\"%s\"}",
                       verifier_id, workspace_id, agent_id, ACTX_SESSION_ID, a->invocation, rh);
    free(rh);
    RatifyV2Buffer ctx = {0};
    rc = ratify_v2_session_context((const uint8_t *)in, strlen(in), &ctx);
    free(in);
    if (rc != 0 || ctx.len != 32) {
        ratify_v2_buffer_free(ctx);
        return -1;
    }
    memcpy(out, ctx.ptr, 32);
    ratify_v2_buffer_free(ctx);
    return 0;
}
