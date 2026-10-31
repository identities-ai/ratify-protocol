/*
 * Shared helpers for the plain-C Protocol v2 ABI conformance program.
 * The program reads a manifest directory prepared by
 * scripts/test-v2-c-abi.sh from testvectors/v2 (C has no JSON parser, so
 * the script flattens each corpus file into small text manifests and binary
 * files) and drives everything through include/ratify.h.
 */
#ifndef RATIFY_V2C_H
#define RATIFY_V2C_H

#include <stddef.h>
#include <stdint.h>

#include "ratify.h"

extern int v2c_failures;
extern const char *v2c_dir;

/* Read <dir>/<name> fully (NUL-terminated); exits on error. */
unsigned char *v2c_read(const char *name, size_t *len);
/* Like v2c_read, but returns NULL for the name "-". */
unsigned char *v2c_read_opt(const char *name, size_t *len);
/* Record a failure when !ok. */
void v2c_check(int ok, const char *what, const char *detail);
/* Format diagnostic text into dst; output that does not fit is cut short. */
void v2c_fmt(char *dst, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
/* Copy src into dst; a value that does not fit exits as a test failure. */
void v2c_copy(char *dst, size_t size, const char *src);
/* Standard base64 of `len` bytes into a malloc'd NUL-terminated string. */
char *v2c_b64(const uint8_t *data, size_t len);
/* Load a 32-byte Ed25519 + 1952-byte ML-DSA-65 public key from two files. */
void v2c_load_key(const char *ed_file, const char *ml_file, RatifyV2PublicKey *out);
/* The stable spelling of a code. */
const char *v2c_class(int32_t code);
/* Duplicate a library buffer into malloc'd memory and free the buffer. */
uint8_t *v2c_take(RatifyV2Buffer b, size_t *len);

/* Sections; each returns the number of checks it ran. */
int v2c_run_objects(void);
int v2c_run_limits(void);
int v2c_run_ordering(void);
int v2c_run_callback_domain(void);
int v2c_run_lifecycle(void);
int v2c_run_cross_sdk(void);

/* The scripted verification inputs of one ordering-style vector directory. */
typedef struct v2c_vector v2c_vector;
v2c_vector *v2c_vector_load(const char *subdir);
void v2c_vector_free(v2c_vector *v);
/* Fill `cb` with the vector's scripted providers; `claim` replaces the
 * scripted claim store when non-NULL. `cancel_status` makes the status
 * provider cancel the operation after answering. */
void v2c_vector_callbacks(v2c_vector *v, const RatifyV2ClaimStoreCallbacks *claim, int cancel_status,
                          RatifyV2VerifyCallbacks *cb, RatifyV2EvaluatorConfig *eval, int *has_eval);
const uint8_t *v2c_vector_bundle(const v2c_vector *v, size_t *len);
const char *v2c_vector_request(const v2c_vector *v, size_t *len);
const char *v2c_vector_meta(const v2c_vector *v, const char *key);

#endif
