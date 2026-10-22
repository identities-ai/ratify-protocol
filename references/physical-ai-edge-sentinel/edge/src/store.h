/*
 * The receiver's durable Part B store (SPEC-v2 §7): claim store, challenge
 * issuance store, release store, SecurityJournalV2 store, receipt outbox and
 * publisher, and the authoritative clock, implemented in C behind the
 * library's callback structs.
 *
 * Every record lives in one state file written atomically. Its digest is
 * anchored in the checkpoint process before any change takes effect: a new
 * state is written beside the current one, anchored, and only then renamed
 * into place. A change the checkpoint refuses is discarded. At startup the
 * store recomputes its digest and compares it with the anchored one; any
 * difference (a restored backup, an edited record, a lost write) leaves the
 * receiver `recovering`, and it then claims, releases, and actuates nothing.
 *
 * The state digest is SHA-384 over this file's exact bytes under the label
 * "ratify-edge-sentinel/primary-state/v1". It is NOT the normative
 * complete-state projection of SPEC-v2 §7.13 and does not reproduce
 * testvectors/v2/device-state.json; see docs/v2-design.md.
 */
#ifndef SENTINEL_STORE_H
#define SENTINEL_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "ckpt_client.h"
#include "ratify.h"

#define STORE_LEASE_SECONDS 30

typedef struct store store;

typedef enum { STORE_READY = 0, STORE_RECOVERING = 1 } store_health;

/* Create a new state directory (genesis). Generates the verifier key and
 * receipt log ID, starts the journal at genesis, and writes the state. The
 * checkpoint is provisioned separately with store_provision. */
int store_create(const char *dir, int64_t replay_epoch);

/* Open an existing state directory and compare it with the checkpoint.
 * Returns NULL only on an unreadable directory; a mismatch opens the store
 * in STORE_RECOVERING with `why` set. */
store *store_open(const char *dir, const ckpt_client *ckpt, int genesis, char why[128]);
void store_free(store *s);

/* Provision the checkpoint with the current (genesis) digest. */
int store_provision(store *s);

store_health store_status(const store *s, const char **why);
const char *store_log_id(const store *s);
const char *store_verifier_id(const store *s);
const RatifyV2PublicKey *store_verifier_key(const store *s);
int64_t store_replay_epoch(const store *s);
const char *store_digest(const store *s);

/* Callback structs over this store. */
void store_callbacks(store *s, RatifyV2ClaimStoreCallbacks *claim, RatifyV2ReleaseStoreCallbacks *release,
                     RatifyV2CheckpointCallbacks *checkpoint, RatifyV2ClockCallbacks *clock,
                     RatifyV2IssuanceStoreCallbacks *issuance, RatifyV2JournalStoreCallbacks *journal);

/* The receipt publisher (SPEC-v2 §7.7): sign the committed body of
 * `claim_id` at its log position, append it (anchored), and submit it to the
 * checkpoint. Returns 0 with a malloc'd signed receipt. */
int store_publish(store *s, const char *claim_id, uint8_t **wire, size_t *wire_len, char reason[64]);

/* Publish every committed but unappended or unacknowledged outbox entry in
 * log order, and recover interrupted claims whose lease has expired. */
int store_drain(store *s);

/* Read the authoritative clock (with the regression check). */
int store_now(store *s, int64_t *now);

#endif
