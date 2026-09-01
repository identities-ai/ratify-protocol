#ifndef SENTINEL_HTTP_H
#define SENTINEL_HTTP_H

#include "sentinel.h"

/* Serve until interrupted. Returns 0 on clean shutdown, -1 on bind failure.
 * Single-threaded by design: one connection at a time bounds concurrent work
 * on a device where one verification costs ~24.5 ms. */
int http_serve(sentinel_ctx *ctx, const char *bind_addr, int port,
               int actuate_ms, const char *actuate_scope);

#endif
