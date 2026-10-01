/* The admin API's listener (portal spec §7, network-core spec §18.1): a TCP
 * port on a private address, its TLS connections (oc_tls.h) stepped from
 * the daemon's one poll loop, each request handed to oc_api in turn.
 *
 * Nothing here waits: plan 8's admin socket taught that a slow peer must
 * never hold the loop the cells share. Each connection has a deadline for
 * what it is doing instead, and is closed when it passes:
 *   the handshake         OC_APISRV_HANDSHAKE_S from the accept
 *   a request             OC_APISRV_FRAME_S from its first byte to its last
 *   an answer             OC_APISRV_ANSWER_S from queued to all sent
 *   nothing (idle)        OC_APISRV_IDLE_S
 * A connection's requests are answered in order, one at a time (the next
 * is read only once the answer is sent), at most OC_APISRV_BURST per loop
 * turn. At most OC_APISRV_CONNS connections: another is closed at once. */
#ifndef OC_APISRV_H
#define OC_APISRV_H

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>

#include "oc_api.h"
#include "oc_tls.h"

#define OC_APISRV_CONNS       4u
#define OC_APISRV_HANDSHAKE_S 5u
#define OC_APISRV_FRAME_S     5u
#define OC_APISRV_ANSWER_S    10u
#define OC_APISRV_IDLE_S      300u
#define OC_APISRV_BURST       16u

typedef struct {
    int           state; /* 0 free, 1 handshake, 2 open */
    int           phase; /* what its deadline is for (oc_apisrv.c) */
    uint64_t      since_us;
    oc_tls_conn_t tls;
    uint8_t       rx[OC_API_FRAME_MAX];
    size_t        rn;
    oc_buf_t      tx; /* answers queued, sent from toff */
    size_t        toff;
    char          addr[64];
} oc_apisrv_conn_t;

typedef struct {
    int              lfd; /* -1: closed */
    oc_tls_t        *tls;
    oc_api_t        *api;
    uint64_t (*now_us)(void);
    uint64_t         full_logged_us;
    oc_apisrv_conn_t c[OC_APISRV_CONNS];
} oc_apisrv_t;

/* "10.0.0.60:7444" or "[fd7a:115c:a1e0::1]:7444" into out: a private
 * address only (portal spec §7: "Never public") - 10/8, 172.16/12,
 * 192.168/16, 127/8, 100.64/10 (Tailscale), IPv6 ULA fc00::/7 or ::1; a
 * port 1-65535. 0, or -1 with err set. */
int      oc_apisrv_addr(const char *text, struct sockaddr_storage *out, socklen_t *len, char *err, size_t cap);
/* Listens on text's address: 0, or -1 with err set. s takes tls and api
 * (the caller keeps them alive until oc_apisrv_close). */
int      oc_apisrv_open(oc_apisrv_t *s, const char *text, oc_tls_t *tls, oc_api_t *api, uint64_t (*now_us)(void),
                        char *err, size_t cap);
/* Its poll entries, written at p (room for 1 + OC_APISRV_CONNS): how
 * many. *timeout_ms drops to 0 when a connection has work poll can't see
 * (bytes already decrypted, a request already read). */
unsigned oc_apisrv_fds(oc_apisrv_t *s, struct pollfd *p, int *timeout_ms);
/* After poll, with the n entries oc_apisrv_fds wrote (revents filled):
 * accepts, steps and serves the connections, and closes the late ones. */
void     oc_apisrv_serve(oc_apisrv_t *s, const struct pollfd *p, unsigned n);
/* Every connection and the listener closed. Safe to call twice. */
void     oc_apisrv_close(oc_apisrv_t *s);

#endif
