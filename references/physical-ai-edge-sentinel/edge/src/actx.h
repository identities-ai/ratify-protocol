/*
 * The action context, shared by the receiver and the controller so both
 * derive the same Protocol v2 session context (SPEC-v2 §2.4) from the same
 * action.
 *
 *   operation context  required_scope = scope
 *                      operation      = "edge.actuate"
 *                      resource_id    = zone
 *                      requested_path = "/" + resource
 *                      payload_digest = SHA-256 of the canonical payload
 *                                       {"duration_ms":N,"resource":R,"zone":Z}
 *   session context    verifier_id, workspace_id, agent_id,
 *                      session_id = "edge-sentinel", invocation_id,
 *                      request_hash = the operation context hash
 *
 * Zone, resource, and duration are therefore inside the signed challenge
 * presentation: a proof made for one action cannot be presented for another.
 * Zone and resource are additionally evaluated by the certificate's
 * resource_path constraint, and duration by its max_count constraint and the
 * device's local cap.
 */
#ifndef SENTINEL_ACTX_H
#define SENTINEL_ACTX_H

#include <stdint.h>

#define ACTX_FIELD_MAX 64
#define ACTX_OPERATION "edge.actuate"
#define ACTX_SESSION_ID "edge-sentinel"
#define ACTX_CONTEXT_PROFILE "ratify.edge-sentinel.action/v1"
#define ACTX_DURATION_COUNTER "duration_ms"
#define ACTX_MAX_COUNT_TYPE "com.ratifyprotocol.max_count"
#define ACTX_MAX_COUNT_PROFILE "com.ratifyprotocol.max_count/v1"

typedef struct {
    char scope[ACTX_FIELD_MAX];
    char zone[ACTX_FIELD_MAX];
    char resource[ACTX_FIELD_MAX];
    char invocation[ACTX_FIELD_MAX];
    int duration_ms;
} actx_action;

/* 1 when every text field is 1..63 bytes of [A-Za-z0-9._:-] and the duration
 * is 0..86400000. Anything else is refused before any context is built, so
 * the canonical payload never needs escaping. */
int actx_valid(const actx_action *a);

/* The 32-byte session context. Returns 0 on success. */
int actx_session_context(const actx_action *a, const char *verifier_id, const char *workspace_id,
                         const char *agent_id, uint8_t out[32]);

#endif
