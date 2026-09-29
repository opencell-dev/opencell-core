/* oc_core: one network core (network-core spec §4.2): the cells' links,
 * the HSS/AuC, the location registry and the switch, as a portable C11
 * library with no OS calls, like oc_sig. The caller moves whole frames
 * (oc_core_rx in, io.send out), calls oc_core_tick, and owns the store and
 * the block table. Links are the transport's handles; a link belongs to a
 * cell once its HELLO is accepted.
 *
 * Key material in frames: an AV_RES carries each vector's CK and IK (and
 * HXRES), and oc_core wipes its own copy once io.send returns. The transport
 * must wipe every buffer it encoded, queued or sent an AV_RES frame from
 * once it is done with it (oc_sig_wipe), not merely free or reuse it. */
#ifndef OC_CORE_H
#define OC_CORE_H

#include "oc_core_msg.h"
#include "oc_core_route.h"
#include "oc_core_store.h"
#include "oc_sig_qr.h"

#define OC_CORE_LINKS    16u
#define OC_CORE_PING_US  5000000u  /* PING when nothing was sent on a link for this long */
#define OC_CORE_DEAD_US  15000000u /* a link that sent nothing for this long is down */
#define OC_CORE_CALLS    32u
#define OC_CORE_SETUP_US 10000000u /* CALL_ROUTE to the callee's alert or release (§7.4) */
#define OC_CORE_ECHO_US  3000000u  /* the echo service rings this long, then answers */

typedef struct {
    uint16_t core_id;
    uint16_t key_id;                          /* the network key pair in use: must be in the store */
    uint8_t  echo_number[OC_SIG_NUMBER_LEN];  /* the echo service, +883160655500100 */
} oc_core_cfg_t;

typedef struct {
    void *ctx;
    int      (*send)(void *ctx, uint32_t link, const oc_core_msg_t *m); /* 0 queued */
    /* the core dropped the link (refused HELLO, silence, replaced, revoked):
     * the transport closes it and need not call oc_core_link_down */
    void     (*close)(void *ctx, uint32_t link);
    void     (*random)(void *ctx, uint8_t *out, size_t n);
    uint32_t (*unix_now)(void *ctx);
    void     (*log)(void *ctx, const char *line);
} oc_core_io_t;

typedef struct {
    int      used;
    uint32_t link;
    uint32_t cell_id; /* 0 until its HELLO is accepted */
    uint64_t last_rx, last_tx;
} oc_core_link_t;

/* One leg of a call: a cell and the ref the leg started with. */
typedef struct {
    uint32_t cell; /* 0: the echo service */
    uint32_t ref;
} oc_core_leg_t;

enum { OC_CORE_CALL_ROUTING = 1, OC_CORE_CALL_ALERTING = 2, OC_CORE_CALL_ACTIVE = 3 };

typedef struct {
    int           used;
    uint8_t       state;
    oc_core_leg_t a, b; /* a: the caller's leg (the cell's ref); b: the callee's (a core ref) */
    uint8_t       caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN];
    uint64_t      due;           /* ROUTING: give up then; the echo service: answer then */
    uint32_t      setup, answer; /* unix s; answer 0 = not answered */
} oc_core_call_t;

typedef struct {
    oc_core_io_t    io;
    oc_core_cfg_t   cfg;
    oc_core_store_t st;
    oc_core_route_t route;
    oc_core_link_t  links[OC_CORE_LINKS];
    uint64_t        now;      /* the now_us of the call being served */
    uint64_t        prune_at; /* next pruning of issued vectors */
    oc_core_call_t  calls[OC_CORE_CALLS];
    uint32_t        next_ref; /* wraps at 2^31 (top bit is OC_CORE_REF_CORE); safe since calls[] does not survive a core restart (§7.10) */
} oc_core_t;

/* A new network key pair (X25519 from random32) with its registration
 * period, straight into the store: made once, before the first oc_core_init.
 * 0 or -1. */
int  oc_core_netkey_new(const oc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                        uint32_t unix_now);

/* 0, or -1 when cfg->key_id is not in the store (or can't be read). Keeps nothing of a previous
 * run but what the store holds (a restart). */
int  oc_core_init(oc_core_t *k, const oc_core_io_t *io, const oc_core_store_t *st, const oc_core_route_t *route,
                  const oc_core_cfg_t *cfg);
void oc_core_link_up(oc_core_t *k, uint32_t link, uint64_t now_us);
void oc_core_link_down(oc_core_t *k, uint32_t link, uint64_t now_us);
void oc_core_rx(oc_core_t *k, uint32_t link, const oc_core_msg_t *m, uint64_t now_us);
void oc_core_tick(oc_core_t *k, uint64_t now_us);

/* Admin (plan 8's CLI drives these). A new cell is enabled, in channel-list
 * group list_id (0: none); 0, -1 if it exists (or cell_id is 0), or -2 if the
 * store failed (reading whether it exists, or writing it). Revoking disables
 * it and drops its link. */
int  oc_core_cell_add(oc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id);
int  oc_core_cell_revoke(oc_core_t *k, uint32_t cell_id, uint64_t now_us);
/* The channel list of list group list_id (channel-list spec §8): stored, and
 * sent in CELL_CFG to every linked cell of the group now and to each after
 * its HELLO_ACK. The core numbers the versions (list->ver is ignored): 1, 2,
 * ... 255, then 1 again. The new version, or -1: list_id 0, more than
 * OC_SIG_CHAN_MAX entries, or the store failed (nothing changed); or -2:
 * stored, but a read failed while pushing it to a linked cell of the group,
 * whose link was dropped - it gets the list when it says HELLO again. The
 * operator's anchors and the unique-anchor check per group come with
 * network core 2. */
int  oc_core_chan_list_set(oc_core_t *k, uint16_t list_id, const oc_sig_chan_list_t *list, uint64_t now_us);

/* Subscribers (admin). number NULL: a random free number in the first NANP
 * block this core is home for (numbering-plan.md "Assignment Modes"). 0 with
 * the number in out, or -1: not a valid number, reserved, not in a block
 * this core is home for, already a subscriber, or the store failed. */
int  oc_core_sub_add(oc_core_t *k, const uint8_t *number, uint8_t out[OC_SIG_NUMBER_LEN]);
/* A new activation token for number, valid for valid_s; the number's unused
 * tokens are voided. *qr is what its QR code carries. 0 or -1. */
int  oc_core_token_issue(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint32_t valid_s, oc_sig_qr_t *qr);
/* The subscriber can no longer register: its tokens are voided and its cell
 * is told (LOC_CANCEL disabled). 0 or -1. */
int  oc_core_sub_disable(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint64_t now_us);

#endif
