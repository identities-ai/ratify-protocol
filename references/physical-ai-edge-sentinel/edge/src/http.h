#ifndef SENTINEL_HTTP_H
#define SENTINEL_HTTP_H

#include "sentinel.h"

/* Serve until interrupted. Returns 0 on clean shutdown, -1 on bind failure.
 * Single-threaded by design: one connection at a time, so the stores see one
 * request at a time and concurrent work on a small device stays bounded. */
int http_serve(sentinel_ctx *ctx, const char *bind_addr, int port);

#endif
