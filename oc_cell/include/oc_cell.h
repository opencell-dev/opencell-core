/* oc_cell: a cell's network side (network-core spec §4.1): oc_sig_net for
 * the terminals the cell hears, and the core client that answers
 * oc_sig_net's questions over the cell <-> core protocol (§6-7). It keeps
 * the leg table (oc_sig_net call id <-> the leg's ref), forwards app data
 * between two local legs or to the core as MEDIA, re-sends LOC_UPDATE for
 * every live registration after each HELLO_ACK, and releases every
 * cross-cell leg (cause 5) when the link to the core drops. Portable C11
 * with no OS calls: oc-cell (plan 8) adds the radio backend and the
 * transport; the multi-cell simulation drives it directly.
 *
 * Key material in frames: an AV_RES from the core carries each vector's CK
 * and IK. The transport must wipe every buffer it received, decoded or
 * queued an AV_RES frame in (oc_sig_wipe) once oc_cell_core_rx returns, not
 * merely free or reuse it; oc_sig_net keeps the only copy it needs. */
#ifndef OC_CELL_H
#define OC_CELL_H

#include "oc_core_msg.h"
#include "oc_sig_net.h"

#define OC_CELL_PING_US 5000000u  /* PING when nothing was sent to the core for this long */
#define OC_CELL_DEAD_US 15000000u /* the core link is down after this long without a frame */

typedef struct {
    void *ctx;
    int  (*core_send)(void *ctx, const oc_core_msg_t *m); /* 0 queued; -1 no link */
    void (*core_close)(void *ctx);                        /* the link went silent: the transport drops it */
    int  (*radio_send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n); /* one DL payload: 0 queued */
    void (*radio_channel)(void *ctx, uint32_t tmid, int on);                   /* page and grant / release */
    void (*log)(void *ctx, const char *line);
} oc_cell_io_t;

typedef struct {
    uint32_t cell_id;
    uint64_t boot_id;       /* random at every process start */
    uint8_t  sw_version[3];
    uint8_t  mode;          /* oc_sig_mode_t until HELLO_ACK says otherwise */
    uint16_t period_s;
} oc_cell_cfg_t;

typedef struct {
    int      used;
    uint32_t call_id; /* oc_sig_net's */
    uint32_t ref;     /* on the wire: the call id (a call from here), or the core's call ref (a call to here) */
    uint32_t tmid;
    uint16_t seq;     /* MEDIA sent on this leg */
    uint8_t  mt;      /* a call to here (CALL_OFFER) */
    uint32_t refused; /* MEDIA from the core the media gate refused on this leg */
} oc_cell_leg_t;

/* A registration here, as oc_sig_net's registered() reported it: the
 * vector's RAND and the terminal's RES (the cell never has XRES, §19.1) prove
 * it in LOC_UPDATE, again after every HELLO_ACK - a registration made while
 * the core link was down is reported then (§7.10). Wiped when it ends. */
typedef struct {
    int      used;
    uint32_t tmid;
    uint8_t  number[OC_SIG_NUMBER_LEN], rand[16], res[8];
    uint32_t av_seq; /* when its vector arrived (oc_cell_t.av_count) */
} oc_cell_reg_t;

/* The last vector a TMID was given here, in order of arrival. */
typedef struct {
    uint32_t tmid;
    uint32_t seq; /* 0: free */
} oc_cell_av_seen_t;

typedef struct {
    oc_cell_io_t  io;
    oc_cell_cfg_t cfg;
    oc_sig_net_t  net;
    int           linked; /* the transport is up */
    int           ready;  /* ...and the core accepted HELLO */
    uint64_t      now, last_rx, last_tx;
    uint16_t      req;
    uint8_t       echo_number[OC_SIG_NUMBER_LEN];
    oc_cell_leg_t legs[OC_SIG_NET_TERMS];
    oc_cell_reg_t regs[OC_SIG_NET_TERMS];
    uint32_t      av_count; /* vectors taken from AV_RES so far (wraps after 2^32: not in a cell's life) */
    oc_cell_av_seen_t av_seen[OC_SIG_NET_TERMS];
    uint32_t      media_refused; /* MEDIA from the core oc_sig_net refused (a leg not active yet: media gate) */
} oc_cell_t;

void oc_cell_init(oc_cell_t *c, const oc_cell_io_t *io, const oc_cell_cfg_t *cfg);
/* radio side: one UL payload, one RACH UPPER payload, a terminal's grant */
void oc_cell_ul(oc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
void oc_cell_upper(oc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
void oc_cell_radio_link(oc_cell_t *c, uint32_t tmid, int granted, uint64_t now_us);
/* core side: the transport connected (HELLO goes out), dropped, or brought a frame */
void oc_cell_core_up(oc_cell_t *c, uint64_t now_us);
void oc_cell_core_down(oc_cell_t *c, uint64_t now_us);
void oc_cell_core_rx(oc_cell_t *c, const oc_core_msg_t *m, uint64_t now_us);
void oc_cell_tick(oc_cell_t *c, uint64_t now_us);
/* The version of the channel list this cell serves (0: none yet). Its beacon
 * carries it as cfg_ver (ver & 3, channel-list spec §7): oc-cell's to set. */
uint8_t oc_cell_list_ver(const oc_cell_t *c);

#endif
