/*
 * Client for the checkpoint process (checkpoint/checkpoint.c).
 *
 * The checkpoint is a separate process with its own hybrid key and its own
 * storage. It holds the primary's anchored state digest and the receipt-log
 * acknowledgements (SPEC-v2 §7.8, §7.13). Every answer it gives is a witness
 * entry (SPEC-v2 §5.6) signed with its key; this client accepts an answer
 * only after verifying that signature against the pinned checkpoint public
 * key and checking that the signed event names exactly what was asked,
 * including a fresh request nonce.
 *
 * Wire: one request line over a Unix domain socket, one answer line back.
 *   HEAD <nonce>
 *   PROVISION <nonce> <log_id> <digest>
 *   ANCHOR <nonce> <previous digest> <next digest>
 *   ACK <nonce> <log_id> <sequence> <previous entry hash b64> <entry hash b64> <state digest>
 *   GET <nonce> <log_id> <sequence>
 * Answers: "OK <witness entry b64>", "NOTFOUND", or "ERR <reason>".
 */
#ifndef SENTINEL_CKPT_CLIENT_H
#define SENTINEL_CKPT_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "ratify.h"

#define CKPT_DIGEST_HEX 96
#define CKPT_LINE_MAX 32768

typedef struct {
    char socket_path[512];
    RatifyV2PublicKey key;       /* pinned checkpoint public key */
} ckpt_client;

typedef struct {
    char event[16];
    char log_id[40];
    int64_t sequence;
    uint8_t entry_hash[48];
    int has_entry_hash;
    char anchored_digest[CKPT_DIGEST_HEX + 1];
    int64_t ack_head;
    int frozen;
    int64_t timestamp;
} ckpt_event;

/* Return values: 0 success, 1 not found (GET only), -1 refused or
 * unavailable. `reason` (may be NULL, 64 bytes) receives the refusal. */
int ckpt_head(const ckpt_client *c, ckpt_event *out, char *reason);
int ckpt_provision(const ckpt_client *c, const char *log_id, const char *digest, char *reason);
int ckpt_anchor(const ckpt_client *c, const char *prev, const char *next, char *reason);
int ckpt_ack(const ckpt_client *c, const char *log_id, int64_t sequence, const uint8_t prev[48],
             const uint8_t entry[48], const char *state_digest, ckpt_event *out, char *reason);
int ckpt_get(const ckpt_client *c, const char *log_id, int64_t sequence, ckpt_event *out, char *reason);

/* Parse the signed event of a witness entry the caller already verified. */
int ckpt_parse_event(const char *entry_data, ckpt_event *out, char *nonce, size_t nonce_cap);

#endif
