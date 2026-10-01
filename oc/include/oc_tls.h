/* TLS for the core's admin API (portal spec §7, network-core spec §18.1)
 * and its OCSS links (core test services spec §6.4): a context (OpenSSL 3)
 * that takes TLS 1.3 only, one ALPN protocol (oc-admin/1, ocss/1), and a
 * peer certificate that chains to the OpenCell root, is for the peer's
 * side (client authentication on a server; server authentication on a
 * client), carries the required role (a policy OID, tools/ca/oc-ca) and
 * whose SHA-256 is pinned in the core's config. A server context accepts
 * (the admin API, OCSS from a core that dials); a client context dials (OCSS
 * to a core) and checks the server's certificate the same way - by pin,
 * not by host name. And its
 * connections, non-blocking, stepped from the daemon's poll loop (no call
 * here ever waits). No session tickets or resumption: every connection
 * shows its certificate, so once the pins change (a new oc_tls_t: for
 * oc-core, a restart, as its config is read at start) no connection gets
 * in on an old one. */
#ifndef OC_TLS_H
#define OC_TLS_H

#include <stddef.h>
#include <stdint.h>

#define OC_TLS_PINS 4u
#define OC_TLS_ROLE_CORE   "2.25.39025894690731581968303886031091540846.1.1"
#define OC_TLS_ROLE_PORTAL "2.25.39025894690731581968303886031091540846.1.2"
#define OC_TLS_ROLE_CELL   "2.25.39025894690731581968303886031091540846.1.3"

typedef struct {
    const char *cert, *key; /* this server's certificate (PEM, with any chain) and key */
    const char *ca;         /* the root its clients' certificates must chain to */
    const char *alpn;       /* the one protocol spoken ("oc-admin/1") */
    const char *role;       /* the policy OID a client certificate must carry */
    uint8_t     pin[OC_TLS_PINS][32]; /* SHA-256 of each peer certificate (DER) allowed */
    unsigned    npin;
    int         client; /* 0: a server (accepts); 1: a client (dials) */
} oc_tls_cfg_t;

typedef struct oc_tls oc_tls_t;

typedef struct {
    struct ssl_st *ssl; /* NULL: closed */
    int            fd;
    short          want;     /* what to poll for next: POLLIN or POLLOUT */
    char           why[160]; /* why the handshake was refused */
    char           peer[65]; /* the peer certificate's SHA-256, hex, once verified */
} oc_tls_conn_t;

/* NULL with the reason in err: a file that can't be read, a key that is
 * not the certificate's, no pin, no ALPN or role. */
oc_tls_t *oc_tls_new(const oc_tls_cfg_t *cfg, char *err, size_t cap);
void      oc_tls_free(oc_tls_t *t);

/* Takes fd (made non-blocking; for a client, a connected socket): 0, or -1
 * (fd closed). */
int  oc_tls_conn_start(oc_tls_t *t, oc_tls_conn_t *c, int fd);
/* One step of the handshake: 1 done and verified (c->peer set), 0 not yet
 * (poll c->fd for c->want), -1 refused or failed (c->why says why). */
int  oc_tls_conn_handshake(oc_tls_conn_t *c);
/* Bytes read (> 0), 0 when none now (poll for c->want), -1 the peer closed
 * or the connection failed. */
long oc_tls_conn_read(oc_tls_conn_t *c, void *buf, size_t n);
/* Bytes written (> 0), 0 when none now (poll for c->want), -1 failed. */
long oc_tls_conn_write(oc_tls_conn_t *c, const void *buf, size_t n);
/* Decrypted bytes waiting inside OpenSSL, which poll can't see. */
int  oc_tls_conn_pending(const oc_tls_conn_t *c);
/* Closes the connection and its fd (a close_notify if the socket takes
 * it now); safe to call twice. */
void oc_tls_conn_close(oc_tls_conn_t *c);

/* 64 hex digits (either case) into 32 bytes: 0 or -1. */
int  oc_tls_fpr_parse(const char *hex, uint8_t out[32]);

#endif
