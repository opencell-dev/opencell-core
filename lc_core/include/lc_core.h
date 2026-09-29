/* lc_core: one network core (network-core spec §4.2): the cells' links,
 * the HSS/AuC, the location registry and the switch, as a portable C11
 * library with no OS calls, like lc_sig. The caller moves whole frames
 * (lc_core_rx in, io.send out), calls lc_core_tick, and owns the store and
 * the block table. Links are the transport's handles; a link belongs to a
 * cell once its HELLO is accepted.
 *
 * Key material in frames: an AV_RES carries each vector's CK and IK (and
 * HXRES), and lc_core wipes its own copy once io.send returns. The transport
 * must wipe every buffer it encoded, queued or sent an AV_RES frame from
 * once it is done with it (lc_sig_wipe), not merely free or reuse it. */
#ifndef LC_CORE_H
#define LC_CORE_H

#include "lc_core_msg.h"
#include "lc_core_route.h"
#include "lc_core_store.h"
#include "lc_sig_qr.h"

#define LC_CORE_LINKS    16u
#define LC_CORE_PING_US  5000000u  /* PING when nothing was sent on a link for this long */
#define LC_CORE_DEAD_US  15000000u /* a link that sent nothing for this long is down */
#define LC_CORE_CALLS    32u
#define LC_CORE_SETUP_US 10000000u /* CALL_ROUTE to the callee's alert or release (§7.4) */
#define LC_CORE_ECHO_US  3000000u  /* the echo service rings this long, then answers */

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

/* One leg of a call: a cell and the ref the leg started with. */
typedef struct {
    uint32_t cell; /* 0: the echo service */
    uint32_t ref;
} lc_core_leg_t;

enum { LC_CORE_CALL_ROUTING = 1, LC_CORE_CALL_ALERTING = 2, LC_CORE_CALL_ACTIVE = 3 };

typedef struct {
    int           used;
    uint8_t       state;
    lc_core_leg_t a, b; /* a: the caller's leg (the cell's ref); b: the callee's (a core ref) */
    uint8_t       caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN];
    uint64_t      due;           /* ROUTING: give up then; the echo service: answer then */
    uint32_t      setup, answer; /* unix s; answer 0 = not answered */
} lc_core_call_t;

typedef struct {
    lc_core_io_t    io;
    lc_core_cfg_t   cfg;
    lc_core_store_t st;
    lc_core_route_t route;
    lc_core_link_t  links[LC_CORE_LINKS];
    uint64_t        now;      /* the now_us of the call being served */
    uint64_t        prune_at; /* next pruning of issued vectors */
    lc_core_call_t  calls[LC_CORE_CALLS];
    uint32_t        next_ref; /* wraps at 2^31 (top bit is LC_CORE_REF_CORE); safe since calls[] does not survive a core restart (§7.10) */
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
/* The channel list of list group list_id (channel-list spec §8): stored, and
 * sent in CELL_CFG to every linked cell of the group now and to each after
 * its HELLO_ACK. The core numbers the versions (list->ver is ignored): 1, 2,
 * ... 255, then 1 again. The new version, or -1: list_id 0, more than
 * LC_SIG_CHAN_MAX entries, or the store failed. The operator's anchors and
 * the unique-anchor check per group come with network core 2. */
int  lc_core_chan_list_set(lc_core_t *k, uint16_t list_id, const lc_sig_chan_list_t *list, uint64_t now_us);

/* Subscribers (admin). number NULL: a random free number in the first NANP
 * block this core is home for (numbering-plan.md "Assignment Modes"). 0 with
 * the number in out, or -1: not a valid number, reserved, not in a block
 * this core is home for, already a subscriber, or the store failed. */
int  lc_core_sub_add(lc_core_t *k, const uint8_t *number, uint8_t out[LC_SIG_NUMBER_LEN]);
/* A new activation token for number, valid for valid_s; the number's unused
 * tokens are voided. *qr is what its QR code carries. 0 or -1. */
int  lc_core_token_issue(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t valid_s, lc_sig_qr_t *qr);
/* The subscriber can no longer register: its tokens are voided and its cell
 * is told (LOC_CANCEL disabled). 0 or -1. */
int  lc_core_sub_disable(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint64_t now_us);

#endif
