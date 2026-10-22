/*
 * Ratify Edge Sentinel: the Protocol v2 edge receiver core.
 *
 * The decision path is the library's live verifier (ratify_v2_verify_proof_
 * bundle) over this receiver's durable C stores, followed by receipt
 * publication, checkpoint acknowledgement, and ratify_v2_release_decision.
 * Only a released allow, checked against local policy and then against
 * ratify_v2_released_allowed immediately before the write, can reach the
 * actuator.
 */
#ifndef SENTINEL_H
#define SENTINEL_H

#include <stddef.h>
#include <stdint.h>

#include "actx.h"
#include "ratify.h"

#define SENTINEL_QUARANTINE_S 300
#define SENTINEL_MAX_BUNDLE_BYTES 131072
#define SENTINEL_TEXT_MAX 96

/* Application reasons, distinct from the SDK's error classes. */
#define SENTINEL_REASON_QUARANTINE "post_boot_quarantine"
#define SENTINEL_REASON_NO_CLOCK "clock_untrusted"
#define SENTINEL_REASON_OVERSIZE "request_too_large"
#define SENTINEL_REASON_RECOVERING "device_recovering"
#define SENTINEL_REASON_ZONE "policy_zone_denied"
#define SENTINEL_REASON_DURATION "policy_duration_denied"
#define SENTINEL_REASON_REQUEST "request_invalid"

typedef struct sentinel_ctx sentinel_ctx;
struct RatifyV2Released;

typedef struct {
    int64_t serial;                      /* decision number in this process */
    /* "device", "preflight", "replay", "evaluating", or "committed" */
    char stage[16];
    /* The Protocol class for preflight, replay, and evaluating outcomes,
     * the release status for committed ones, or an application reason. */
    char status[SENTINEL_TEXT_MAX];
    char release[16];                    /* released, pending, withheld, rejected */
    char decision[16];                   /* allow, deny, indeterminate (released only) */
    char reason[SENTINEL_TEXT_MAX];      /* released decision reason */
    char identity_status[SENTINEL_TEXT_MAX];
    char local_policy[SENTINEL_TEXT_MAX];/* "" or a local policy denial */
    char claim_id[80];
    int64_t decided_at;
    int clock_trusted;
    int quarantine_override;
    int actionable;                      /* released allow that passed local policy */
    struct RatifyV2Released *released;   /* owned; freed by sentinel_decision_free */
} sentinel_decision;

typedef struct {
    char challenge_b64[64];
    char session_context_b64[64];
    char verifier_id[RATIFY_V2_KEY_ID_BUF_LEN];
    int64_t issued_at, expires_at;
} sentinel_challenge;

/* Initialize a new receiver: create the state directory, record key roles,
 * configure the root's status key, stage the signed status list from the
 * trust directory, and provision the checkpoint with the genesis digest. */
int  sentinel_initialize(const char *state_dir, const char *trust_dir, const char *checkpoint_socket);

/* Open an initialized receiver. A state that does not match the checkpoint
 * opens in the recovering state; every request is then refused. */
int  sentinel_open(const char *state_dir, const char *trust_dir, const char *checkpoint_socket, sentinel_ctx **out);
void sentinel_free(sentinel_ctx *ctx);

/* Issue a challenge bound to the action's session context. */
int  sentinel_issue_challenge(sentinel_ctx *ctx, const actx_action *action, sentinel_challenge *out,
                              char reason[SENTINEL_TEXT_MAX]);

/* Verify, publish, acknowledge, and release. Never actuates. */
void sentinel_decide(sentinel_ctx *ctx, const char *bundle, size_t bundle_len, const actx_action *action,
                     sentinel_decision *out);
void sentinel_decision_free(sentinel_decision *d);

/* The release gate: 1 only when `d` is an actionable released allow and the
 * authoritative clock reads before both sealed deadlines right now. On 1,
 * `*token` is the actuator token. Call immediately before the write. */
int  sentinel_release_gate(sentinel_ctx *ctx, const sentinel_decision *d, uint64_t *token);

/* Apply a signed status object (kind 3 list or 5 push) to the anchored
 * journal and make it available as evidence. */
int  sentinel_stage_status(sentinel_ctx *ctx, int kind, const uint8_t *wire, size_t len, char reason[SENTINEL_TEXT_MAX]);

int64_t  sentinel_quarantine_remaining(const sentinel_ctx *ctx);
uint64_t sentinel_actuator_token(const sentinel_ctx *ctx);
const char *sentinel_health(const sentinel_ctx *ctx);

#endif /* SENTINEL_H */
