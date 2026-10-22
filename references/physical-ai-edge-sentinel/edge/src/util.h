/*
 * Small helpers shared by the edge receiver, the checkpoint process, and the
 * controller: base64, hex, SHA-256 and SHA-384, durable file writes, and a
 * narrow field reader for canonical JSON that the Ratify library produced or
 * whose signature has already verified. None of this parses untrusted JSON.
 */
#ifndef SENTINEL_UTIL_H
#define SENTINEL_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include "ratify.h"

/* Standard padded base64. Returns a malloc'd NUL-terminated string. */
char *b64_encode(const uint8_t *in, size_t len);
/* Decodes standard base64 into out. Returns the length, or -1 on error. */
long b64_decode(const char *in, uint8_t *out, size_t cap);

void hex_encode(const uint8_t *in, size_t len, char *out);
int  hex_decode(const char *hex, uint8_t *out, size_t len);

void sha256(const uint8_t *in, size_t len, uint8_t out[32]);
void sha384(const uint8_t *in, size_t len, uint8_t out[48]);
/* SHA-384(label || 0x00 || data) as 96 lowercase hex characters plus NUL. */
void sha384_labelled_hex(const char *label, const uint8_t *data, size_t len, char out[97]);

/* Read a whole file (NUL-terminated). Returns NULL when absent or larger
 * than cap. */
char *read_file(const char *path, size_t cap, size_t *len);
/* Write a file durably: temporary file, fsync, rename, fsync the directory.
 * Returns 0 on success. */
int  write_file_durable(const char *path, const void *data, size_t len, int mode);
/* Write a file durably under `path` without renaming over it (staging). */
int  write_file_sync(const char *path, const void *data, size_t len, int mode);
int  fsync_dir_of(const char *path);

/* printf into a new heap string. */
char *xformat(const char *fmt, ...);
/* A heap copy of a library buffer as a NUL-terminated string; frees it. */
char *take_buffer(RatifyV2Buffer b, size_t *len);

/* Copy the string value of `"key":"..."` (first occurrence) into out.
 * Returns 1 when found. For canonical JSON only. */
int  json_get_str(const char *json, const char *key, char *out, size_t cap);
/* Read the integer value of `"key":N` (first occurrence). Returns 1 when
 * found. */
int  json_get_int(const char *json, const char *key, int64_t *out);
/* Returns a malloc'd copy of the object or array value of `"key":`. */
char *json_get_raw(const char *json, const char *key);

/* Fill buf with OS randomness. Returns 0 on success. */
int  random_bytes(uint8_t *buf, size_t len);

/* Key seeds on disk: 64 hex (Ed25519 seed) + newline + 64 hex (ML-DSA
 * seed). */
int  keypair_save(const char *path, const uint8_t ed[32], const uint8_t ml[32]);
RatifyV2KeyPair *keypair_load(const char *path);
RatifyV2KeyPair *keypair_create(const char *path);
/* Public key wire JSON as a malloc'd string, and a key read from it. */
char *public_key_json(const RatifyV2PublicKey *key);
int  public_key_from_json(const char *json, RatifyV2PublicKey *out);

#endif
