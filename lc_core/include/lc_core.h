/* lc_core: one network core (network-core spec §4.2): the cells' links,
 * the HSS/AuC, the location registry and the switch, as a portable C11
 * library with no OS calls, like lc_sig. The caller moves whole frames
 * (lc_core_rx in, io.send out), calls lc_core_tick, and owns the store and
 * the block table. Links are the transport's handles; a link belongs to a
 * cell once its HELLO is accepted. */
#ifndef LC_CORE_H
#define LC_CORE_H

#include "lc_core_msg.h"
#include "lc_core_route.h"
#include "lc_core_store.h"

#define LC_CORE_LINKS   16u
#define LC_CORE_PING_US 5000000u  /* PING when nothing was sent on a link for this long */
#define LC_CORE_DEAD_US 15000000u /* a link that sent nothing for this long is down */

typedef struct {
    uint16_t core_id;
    uint16_t key_id;                          /* the network key pair in use: must be in the store */
    uint8_t  echo_number[LC_SIG_NUMBER_LEN];  /* the echo service, +883160655500100 */
} lc_core_cfg_t;

typedef struct {
    void *ctx;
    int      (*send)(void *ctx, uint32_t link, const lc_core_msg_t *m); /* 0 queued */
    /* the core dropped the link (refused HELLO, silence, replaced, revoked):
     * the transport closes it and need not call lc_core_link_down */
    void     (*close)(void *ctx, uint32_t link);
    void     (*random)(void *ctx, uint8_t *out, size_t n);
    uint32_t (*unix_now)(void *ctx);
    void     (*log)(void *ctx, const char *line);
} lc_core_io_t;

typedef struct {
    int      used;
    uint32_t link;
    uint32_t cell_id; /* 0 until its HELLO is accepted */
    uint64_t last_rx, last_tx;
} lc_core_link_t;

typedef struct {
    lc_core_io_t    io;
    lc_core_cfg_t   cfg;
    lc_core_store_t st;
    lc_core_route_t route;
    lc_core_link_t  links[LC_CORE_LINKS];
    uint64_t        now; /* the now_us of the call being served */
} lc_core_t;

/* A new network key pair (X25519 from random32) with its registration
 * period, straight into the store: made once, before the first lc_core_init.
 * 0 or -1. */
int  lc_core_netkey_new(const lc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                        uint32_t unix_now);

/* 0, or -1 when cfg->key_id is not in the store. Keeps nothing of a previous
 * run but what the store holds (a restart). */
int  lc_core_init(lc_core_t *k, const lc_core_io_t *io, const lc_core_store_t *st, const lc_core_route_t *route,
                  const lc_core_cfg_t *cfg);
void lc_core_link_up(lc_core_t *k, uint32_t link, uint64_t now_us);
void lc_core_link_down(lc_core_t *k, uint32_t link, uint64_t now_us);
void lc_core_rx(lc_core_t *k, uint32_t link, const lc_core_msg_t *m, uint64_t now_us);
void lc_core_tick(lc_core_t *k, uint64_t now_us);

/* Admin (plan 8's CLI drives these). A new cell is enabled, in channel-list
 * group list_id (0: none); 0, or -1 if it exists. Revoking disables it and
 * drops its link. */
int  lc_core_cell_add(lc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id);
int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);

#endif
