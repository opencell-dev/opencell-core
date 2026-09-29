/* lc_cell: a cell's network side (network-core spec §4.1): lc_sig_net for
 * the terminals the cell hears, and the core client that answers
 * lc_sig_net's questions over the cell <-> core protocol (§6-7). It keeps
 * the leg table (lc_sig_net call id <-> the leg's ref), forwards app data
 * between two local legs or to the core as MEDIA, re-sends LOC_UPDATE for
 * every live registration after each HELLO_ACK, and releases every
 * cross-cell leg (cause 5) when the link to the core drops. Portable C11
 * with no OS calls: oc-cell (plan 8) adds the radio backend and the
 * transport; the multi-cell simulation drives it directly. */
#ifndef LC_CELL_H
#define LC_CELL_H

#include "lc_core_msg.h"
#include "lc_sig_net.h"

#define LC_CELL_PING_US 5000000u  /* PING when nothing was sent to the core for this long */
#define LC_CELL_DEAD_US 15000000u /* the core link is down after this long without a frame */

typedef struct {
    void *ctx;
    int  (*core_send)(void *ctx, const lc_core_msg_t *m); /* 0 queued; -1 no link */
    void (*core_close)(void *ctx);                        /* the link went silent: the transport drops it */
    int  (*radio_send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n); /* one DL payload: 0 queued */
    void (*radio_channel)(void *ctx, uint32_t tmid, int on);                   /* page and grant / release */
    void (*log)(void *ctx, const char *line);
} lc_cell_io_t;

typedef struct {
    uint32_t cell_id;
    uint64_t boot_id;       /* random at every process start */
    uint8_t  sw_version[3];
    uint8_t  mode;          /* lc_sig_mode_t until HELLO_ACK says otherwise */
    uint16_t period_s;
} lc_cell_cfg_t;

typedef struct {
    int      used;
    uint32_t call_id; /* lc_sig_net's */
    uint32_t ref;     /* on the wire: the call id (a call from here), or the core's call ref (a call to here) */
    uint32_t tmid;
    uint16_t seq;     /* MEDIA sent on this leg */
} lc_cell_leg_t;

/* A registration here, as lc_sig_net's registered() reported it: the
 * vector's RAND and the terminal's RES (the cell never has XRES, §19.1) prove
 * it in LOC_UPDATE, again after every HELLO_ACK - a registration made while
 * the core link was down is reported then (§7.10). Wiped when it ends. */
typedef struct {
    int      used;
    uint32_t tmid;
    uint8_t  number[LC_SIG_NUMBER_LEN], rand[16], res[8];
    uint32_t av_seq; /* when its vector arrived (lc_cell_t.av_count) */
} lc_cell_reg_t;

/* The last vector a TMID was given here, in order of arrival. */
typedef struct {
    uint32_t tmid;
    uint32_t seq; /* 0: free */
} lc_cell_av_seen_t;

typedef struct {
    lc_cell_io_t  io;
    lc_cell_cfg_t cfg;
    lc_sig_net_t  net;
    int           linked; /* the transport is up */
    int           ready;  /* ...and the core accepted HELLO */
    uint64_t      now, last_rx, last_tx;
    uint16_t      req;
    uint8_t       echo_number[LC_SIG_NUMBER_LEN];
    lc_cell_leg_t legs[LC_SIG_NET_TERMS];
    lc_cell_reg_t regs[LC_SIG_NET_TERMS];
    uint32_t      av_count; /* vectors taken from AV_RES so far (wraps after 2^32: not in a cell's life) */
    lc_cell_av_seen_t av_seen[LC_SIG_NET_TERMS];
} lc_cell_t;

void lc_cell_init(lc_cell_t *c, const lc_cell_io_t *io, const lc_cell_cfg_t *cfg);
/* radio side: one UL payload, one RACH UPPER payload, a terminal's grant */
void lc_cell_ul(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
void lc_cell_upper(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
void lc_cell_radio_link(lc_cell_t *c, uint32_t tmid, int granted, uint64_t now_us);
/* core side: the transport connected (HELLO goes out), dropped, or brought a frame */
void lc_cell_core_up(lc_cell_t *c, uint64_t now_us);
void lc_cell_core_down(lc_cell_t *c, uint64_t now_us);
void lc_cell_core_rx(lc_cell_t *c, const lc_core_msg_t *m, uint64_t now_us);
void lc_cell_tick(lc_cell_t *c, uint64_t now_us);
/* The version of the channel list this cell serves (0: none yet). Its beacon
 * carries it as cfg_ver (ver & 3, channel-list spec §7): oc-cell's to set. */
uint8_t lc_cell_list_ver(const lc_cell_t *c);

#endif
