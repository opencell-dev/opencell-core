/* The cell <-> core protocol over a stream socket (network-core spec §6):
 * frames of oc_core_msg.h ("len (2, BE) | type (1) | body", at most
 * OC_CORE_FRAME_MAX bytes) read and written on a non-blocking fd, plus the
 * Unix-socket helpers both daemons use. Linux only; plan 9 adds TLS under
 * the same calls.
 *
 * A frame whose length is impossible (0, or more than OC_CORE_FRAME_MAX in
 * all) breaks the stream: oc_conn_read fails and the caller closes. A frame
 * of a good length that does not decode (a type this build does not know, a
 * bad number) is dropped and counted in bad, and the link stays up. */
#ifndef OC_CONN_H
#define OC_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "oc_core_msg.h"

#define OC_CONN_RX 2048u
#define OC_CONN_TX 16384u /* about 30 s of one call's MEDIA each way: a peer that reads nothing for longer is dropped */

typedef struct {
    int      fd; /* -1: closed */
    uint8_t  rx[OC_CONN_RX];
    size_t   rn;
    uint8_t  tx[OC_CONN_TX];
    size_t   tn;
    uint32_t bad; /* frames dropped because they did not decode */
} oc_conn_t;

typedef void (*oc_conn_rx_fn)(void *ctx, const oc_core_msg_t *m);

/* Takes fd (made non-blocking and close-on-exec). */
void oc_conn_init(oc_conn_t *c, int fd);
/* Reads what the socket has and hands every whole frame to cb, in order. cb
 * may close the connection; reading then stops. 0, or -1: the peer closed,
 * a read error, a broken frame length, or the connection was closed. */
int  oc_conn_read(oc_conn_t *c, oc_conn_rx_fn cb, void *ctx);
/* Queues one message and writes what the socket takes now. 0, or -1: not
 * encodable, the queue is full (the peer stopped reading), a write error,
 * or the connection is closed. */
int  oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m);
/* Writes what is queued (on POLLOUT). 0 or -1 (a write error). */
int  oc_conn_flush(oc_conn_t *c);
/* Closes the fd; safe to call twice. */
void oc_conn_close(oc_conn_t *c);

/* A listening Unix stream socket at path: a stale socket there is removed
 * (any other kind of file is left alone and the call fails), the socket is
 * given mode and, if group is not NULL, that group. Non-blocking,
 * close-on-exec. The fd, or -1 with errno set. */
int      oc_unix_listen(const char *path, unsigned mode, const char *group);
/* A connected, non-blocking client socket, or -1 with errno set. */
int      oc_unix_connect(const char *path);
/* The next reconnect delay: 1 s, then doubling up to 30 s. */
uint32_t oc_backoff_next(uint32_t prev_ms);

#endif
