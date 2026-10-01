/* OCSS links between cores (network-core spec §15.2; core test services
 * spec §6): TLS 1.3, ALPN ocss/1, each side showing a certificate of the
 * core role from the OpenCell root whose SHA-256 the other has pinned
 * (oc_tls.h). A core listens (ocss_listen) and dials every peer whose
 * address it has; by the spec's rule only the lower core_id has the
 * other's address, so a pair has one link. Frames are §6's shape with the
 * OCSS types (oc_core_msg.h), handed to oc_core_peer_rx; oc_core sends
 * through oc_ocss_send.
 *
 * Nothing here waits, as for the admin API (oc_apisrv.h): a dial is a
 * non-blocking connect, stepped from the daemon's poll loop, with a
 * deadline (OC_OCSS_HANDSHAKE_S from the dial or accept to an open
 * link); a peer that does not answer is dialled again after 1 s, doubling
 * to 30 s, the wait reset once a link has stayed open 30 s. A link that
 * fails (read or write error, the peer closed, a queue the peer does not
 * drain) is closed and oc_core hears of it (oc_core_peer_down) from
 * oc_ocss_serve, never from inside one of oc_core's own calls. */
#ifndef OC_OCSS_H
#define OC_OCSS_H

#include <poll.h>
#include <stdint.h>

#include "oc_core.h"
#include "oc_tls.h"

#define OC_OCSS_ALPN        "ocss/1"
#define OC_OCSS_PEERS       OC_CORE_PEERS
#define OC_OCSS_CONNS       4u
#define OC_OCSS_HANDSHAKE_S 5u
#define OC_OCSS_RX          2048u
#define OC_OCSS_TX          16384u /* about 30 s of one call's MEDIA: a peer that reads nothing for longer is dropped */

typedef struct {
    uint16_t core_id;
    char     addr[64]; /* "10.99.0.2:7443" or "[fd00::2]:7443": this core dials it; "": it dials this core */
    uint8_t  fpr[32];  /* SHA-256 of its certificate (oc-ca fpr) */
} oc_ocss_peer_t;

typedef struct {
    const char    *listen; /* "10.99.0.2:7443"; NULL: this core only dials */
    const char    *cert, *key, *ca;
    oc_ocss_peer_t peer[OC_OCSS_PEERS];
    unsigned       npeer;
    oc_core_t     *core;
    uint64_t     (*now_us)(void);
    uint32_t     (*new_link)(void *ctx); /* a fresh handle, from the daemon's one counter */
    void          *ctx;
} oc_ocss_cfg_t;

typedef struct {
    int           state; /* 0 free, 1 connecting, 2 handshake, 3 open */
    int           dead;  /* failed: closed and reported from oc_ocss_serve */
    int           dialled;
    uint16_t      core_id; /* dialled: the peer dialled; accepted: known once open */
    uint32_t      link;    /* oc_core's handle, once open */
    uint64_t      since_us;
    oc_tls_conn_t tls;
    uint8_t       rx[OC_OCSS_RX];
    size_t        rn;
    uint8_t       tx[OC_OCSS_TX];
    size_t        tn;
    uint32_t      bad; /* frames that did not decode (dropped) */
    char          addr[64];
} oc_ocss_conn_t;

typedef struct {
    int            lfd; /* -1: not listening */
    uint16_t       port; /* the port listened on (a test listens on 0) */
    oc_tls_t      *srv, *cli;
    oc_ocss_cfg_t  cfg;
    uint32_t       backoff_ms[OC_OCSS_PEERS];
    uint64_t       dial_at[OC_OCSS_PEERS];
    oc_ocss_conn_t c[OC_OCSS_CONNS];
} oc_ocss_t;

/* The TLS contexts and the listener: 0, or -1 with err set (a file that
 * can't be read, a bad address, a port in use). Dials start at the first
 * oc_ocss_serve. s takes cfg->core (kept alive by the caller). */
int      oc_ocss_open(oc_ocss_t *s, const oc_ocss_cfg_t *cfg, char *err, size_t cap);
/* A zeroed oc_ocss_t with lfd -1 that was never opened (no peers) is
 * valid for every call below: it has no entries, owns no link, serves
 * nothing.
 * Its poll entries at p (room for 1 + OC_OCSS_CONNS): how many.
 * *timeout_ms drops to what the next dial or deadline needs (0: work poll
 * can't see, bytes already decrypted). */
unsigned oc_ocss_fds(oc_ocss_t *s, struct pollfd *p, int *timeout_ms);
/* After poll, with the n entries oc_ocss_fds wrote: accepts, connects,
 * steps handshakes, reads frames into oc_core, writes what is queued,
 * closes late and failed links (oc_core_peer_down for an open one), dials. */
void     oc_ocss_serve(oc_ocss_t *s, const struct pollfd *p, unsigned n);
/* 1 if link is one of its open links. */
int      oc_ocss_owns(const oc_ocss_t *s, uint32_t link);
/* oc_core's io.send for an OCSS link: queued, and written now if the socket
 * takes it. 0, or -1 (not encodable, the queue is full, a write error: the
 * link is then dead, and oc_core hears so from oc_ocss_serve). */
int      oc_ocss_send(oc_ocss_t *s, uint32_t link, const oc_core_msg_t *m);
/* oc_core's io.close for an OCSS link: what is queued goes if the socket
 * takes it now, then the link is closed; oc_core is not told (it asked). */
void     oc_ocss_drop(oc_ocss_t *s, uint32_t link);
/* Every open link down in oc_core (its calls end), then closed; the
 * listener closed. Safe to call twice. */
void     oc_ocss_close(oc_ocss_t *s);

#endif
