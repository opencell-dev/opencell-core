/* The cells' TLS listener (network-core spec §6, single-board cell spec
 * §5): a TCP port, any address (cells dial in from anywhere), and the TLS
 * handshakes in progress, stepped from the daemon's poll loop. A finished
 * handshake (chain, clientAuth, role cell, ALPN oc-cell/1) is handed to the
 * daemon, which checks the pin at the cell's HELLO. At most
 * OC_CELLSRV_PENDING handshakes at once (another connection is closed at
 * once); each is closed OC_CELLSRV_HANDSHAKE_S after its accept if not done. */
#ifndef OC_CELLSRV_H
#define OC_CELLSRV_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "oc_tls.h"

  #define OC_CELLSRV_PENDING     4u
  #define OC_CELLSRV_HANDSHAKE_S 10u
  typedef struct { int used; uint64_t since_us; oc_tls_conn_t tls; char addr[64]; } oc_cellsrv_hs_t;
  typedef struct {
      int             lfd; /* -1: closed */
      oc_tls_t       *tls;
      uint64_t      (*now_us)(void);
      uint64_t        full_logged_us;
      oc_cellsrv_hs_t hs[OC_CELLSRV_PENDING];
      int             at[1 + OC_CELLSRV_PENDING]; /* poll entry -> hs index (-1: the listener), from the last _fds */
  } oc_cellsrv_t;
  /* A finished handshake: the callee takes tls (oc_tls_conn_move) or closes it. */
  typedef void (*oc_cellsrv_ready_fn)(void *ctx, oc_tls_conn_t *tls, const char *addr);
  int      oc_cellsrv_open(oc_cellsrv_t *s, const char *text, oc_tls_t *tls, uint64_t (*now_us)(void), char *err, size_t cap);
  uint16_t oc_cellsrv_port(const oc_cellsrv_t *s); /* the bound port, for the log and the tests */
  unsigned oc_cellsrv_fds(oc_cellsrv_t *s, struct pollfd *p); /* room for 1 + OC_CELLSRV_PENDING */
  void     oc_cellsrv_serve(oc_cellsrv_t *s, const struct pollfd *p, unsigned n, oc_cellsrv_ready_fn ready, void *ctx);
  void     oc_cellsrv_close(oc_cellsrv_t *s);
  
#endif
