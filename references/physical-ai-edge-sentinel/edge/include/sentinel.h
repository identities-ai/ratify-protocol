/*
 * Ratify Edge Sentinel — edge receiver core.
 *
 * Checkpoint A covers the security core only: trust anchor, clock, challenge
 * store, verification, and the guarded actuator token. No transport, no GPIO.
 */
#ifndef SENTINEL_H
#define SENTINEL_H

#include <stdint.h>
#include <stddef.h>

#define SENTINEL_ID_HEX_LEN 32           /* human_id / agent_id, per SPEC §7 */
#define SENTINEL_CHALLENGE_BYTES 32
#define SENTINEL_CHALLENGE_HEX (SENTINEL_CHALLENGE_BYTES * 2)
#define SENTINEL_CHALLENGE_TTL_S 300     /* CHALLENGE_WINDOW_SECONDS */
#define SENTINEL_QUARANTINE_S 300        /* FR10 */
#define SENTINEL_MAX_BUNDLE_BYTES 131072 /* MAX_PROOF_BUNDLE_BYTES */
#define SENTINEL_REASON_MAX 160

/* Application-level denial reasons. These are OURS, deliberately distinct from
 * the SDK's closed identity_status enum: the anchor check in particular has no
 * SDK status because the SDK cannot know which principal we trust (SPEC §15.4). */
#define SENTINEL_REASON_ANCHOR_MISMATCH "anchor_mismatch"
#define SENTINEL_REASON_QUARANTINE      "post_boot_quarantine"
#define SENTINEL_REASON_NO_CLOCK        "clock_untrusted"
#define SENTINEL_REASON_OVERSIZE        "request_too_large"
#define SENTINEL_REASON_ZONE            "policy_zone_denied"
#define SENTINEL_REASON_DURATION        "policy_duration_denied"
#define SENTINEL_REASON_REVOCATION      "revocation_state_unavailable"

typedef struct {
    int      allow;
    /* The SDK's identity_status (closed enum, SPEC §5.9) or one of our
     * application reasons above. Assert on THIS, not on the detail text:
     * `expired` and `revoked` do not prefix their error_reason with the
     * status name, unlike every other failure. */
    char     status[SENTINEL_REASON_MAX];
    char     reason[SENTINEL_REASON_MAX];   /* SDK error_reason detail */
    char     human_id[SENTINEL_ID_HEX_LEN + 1];
    char     agent_id[SENTINEL_ID_HEX_LEN + 1];
    int64_t  decided_at;
    int      clock_trusted;
    int      quarantine_override;           /* FR13: test builds only, always logged */
    uint64_t actuator_token;                /* 0 unless allow; see actuator.h */
} sentinel_decision;

/* What the caller is asking for. Zone and duration are LOCAL POLICY inputs,
 * not Ratify constraints: the protocol has no activation-duration constraint,
 * and zone identity here is a device-local concept rather than a resource
 * profile. Keeping them in a separate struct keeps that boundary visible. */
typedef struct {
    const char *scope;
    const char *zone;
    int         duration_ms;
} sentinel_request;

typedef struct sentinel_ctx sentinel_ctx;

/* Load trust material from `trust_dir` and start the quarantine clock.
 * Requires `trust_dir/pinned_human_id` to hold 32 lowercase hex characters.
 * Returns 0 on success, -1 with a message on stderr otherwise. */
int  sentinel_init(const char *trust_dir, sentinel_ctx **out);
void sentinel_free(sentinel_ctx *ctx);

/* Issue a fresh single-use challenge. `out_hex` must hold
 * SENTINEL_CHALLENGE_HEX + 1 bytes. Returns 0 on success. */
int  sentinel_issue_challenge(sentinel_ctx *ctx, char *out_hex,
                              int64_t *out_expires_at);

/* Verify a presented bundle and decide. `bundle_json` must be NUL-terminated
 * and no longer than SENTINEL_MAX_BUNDLE_BYTES. Never returns allow without
 * having consumed a challenge this verifier issued. */
void sentinel_decide(sentinel_ctx *ctx, const char *bundle_json,
                     size_t bundle_len, const sentinel_request *req,
                     sentinel_decision *out);

/* Seconds remaining in the post-boot quarantine; 0 once elapsed. */
int64_t sentinel_quarantine_remaining(const sentinel_ctx *ctx);

/* Exposed so the owning process can bind the actuator once at startup. */
uint64_t sentinel_actuator_token(const sentinel_ctx *ctx);

#endif /* SENTINEL_H */
