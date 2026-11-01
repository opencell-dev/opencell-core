/* The cell <-> core protocol (network-core spec §6): one frame is
 *   len (2, big-endian: the bytes after it) | type (1) | body
 * at most OC_CORE_FRAME_MAX bytes in all. Body fields are little-endian, as
 * in oc_link; numbers are 8 BCD bytes in the full form (numbering v2), and a
 * frame whose number is not valid does not decode.
 *
 * Call refs: a leg a cell starts (CALL_ROUTE) is named by the cell's
 * oc_sig_net call id, which stays below 2^31; a leg the core starts
 * (CALL_OFFER) by a core call ref with OC_CORE_REF_CORE set. Every later
 * message about a leg, in either direction, carries the ref it started with.
 *
 * CELL_CFG (K->C) carries the cell's channel list (channel-list spec §8) as
 * a CHAN_LIST body exactly as oc_sig encodes it (oc_sig_body_encode: its
 * frequencies are big-endian, as everywhere in oc_sig).
 *
 * OCSS, the core <-> core protocol (network-core spec §15; core test
 * services spec §6), shares this codec and frame shape with its own type
 * space, 0x40-0x7F: each type is its §6 analogue + 0x40 (HELLO 0x41 ...
 * MEDIA 0x68). 0x46-0x4F are kept for routing, 0x50-0x5F for mobility,
 * 0x70-0x7F for replication (plan 10). A cell link ignores OCSS types and
 * an OCSS link ignores cell types. OCSS call refs: every message about a
 * call carries the call_ref its CALL_SETUP gave it (the calling core's).
 * The two cores in a pair each number their own outgoing calls from 1 at
 * every restart, so the two could otherwise pick the same value; the
 * calling core sets OC_CORE_REF_DIR (bit 30) when its own core_id is the
 * higher of the pair, so the two directions' refs never collide. A
 * CALL_SETUP whose ref lacks OC_CORE_REF_CORE, or carries the direction bit
 * that would mean the *receiver's* own calls, is refused (cause 5): spec
 * §6.4 (review finding I1).
 *
 * Protocol 3 (OCSS 2) appends caps to CALL_ROUTE, CALL_OFFER and OCSS
 * CALL_SETUP and the codec to CALL_ANSWER and OCSS CALL_ANSWER (codec
 * negotiation spec §6.1-6.2); both lengths decode.
 *
 * CELL_STATUS (C->K, NOC design §7.3): the cell's radios and the signal of
 * the terminals it hears, every 60 s and when PPS or the timebase changes.
 * ver (1) | part (1: OC_CORE_STATUS_LAST | index) | n radios (1) | the
 * radios | n terminals (1) | the terminals. A list longer than one part's
 * room goes in several parts, indexes 0, 1, ...; the last carries the flag.
 * A core older than the message drops it and counts it (oc_conn), so the
 * protocol version stays 2.
 *
 * Types not listed here are free. */
#ifndef OC_CORE_MSG_H
#define OC_CORE_MSG_H

#include "oc_codec.h"   /* the caps and codec bytes of the call messages */
#include "oc_sig_hss.h" /* oc_sig_cell_av_t, oc_sig_av_status_t */
#include "oc_sig_msg.h" /* oc_sig_msg_t, oc_sig_body_encode/decode */

#define OC_CORE_FRAME_MAX 512u
#define OC_CORE_PROTO       3u /* 3: CALL_ROUTE and CALL_OFFER carry caps, CALL_ANSWER the codec (codec negotiation spec §6.1) */
#define OC_CORE_PROTO_MIN   2u /* 2: AV_RES carries HXRES, not XRES (§19.1); LOC_CANCEL names its RAND (§19 follow-ups) */
#define OC_CORE_PROTO_CODEC 3u /* the first cell-link version with caps and codec */
#define OC_CORE_AV_MAX    4u
#define OC_CORE_REF_CORE  0x80000000u
#define OC_CORE_REF_DIR   0x40000000u /* an OCSS call_ref: set by the calling core when self > peer (review I1) */
#define OC_OCSS_PROTO       3u /* 3: + mobility and TMID_BOUND (OCSS spec 2026-11-01 §4.2) */
#define OC_OCSS_PROTO_MOB   3u /* the first OCSS version with visiting subscribers */
/* 2: OCSS CALL_SETUP carries caps, CALL_ANSWER the codec (§6.2) */
#define OC_OCSS_PROTO_MIN   1u /* 1: the test-services slice: link and call control only */
#define OC_OCSS_PROTO_CODEC 2u
/* The two shapes of the call messages protocol 3 (OCSS 2) extended: OLD,
 * without caps or codec - what a protocol-2 (OCSS 1) link carries, meaning
 * caps 0x01 and codec 1 - and CODEC, with the byte at the end. */
#define OC_CORE_FORM_OLD    0u
#define OC_CORE_FORM_CODEC  1u
#define OC_OCSS_OFFSET    0x40u /* an OCSS type is its §6 analogue + this */
#define OC_CORE_STATUS_VER    1u
#define OC_CORE_STATUS_RADIOS 2u     /* radios in one CELL_STATUS part (48 bytes each) */
#define OC_CORE_STATUS_TERMS  28u    /* terminals in one part (14 bytes each) */
#define OC_CORE_STATUS_LAST   0x80u  /* part: this is the last part */
#define OC_CORE_STATUS_NONE   (-32768) /* rssi_dbm, snr_qdb: nothing heard from the terminal */

typedef enum {
    OC_CORE_HELLO = 0x01, OC_CORE_HELLO_ACK = 0x02, OC_CORE_HELLO_NAK = 0x03, OC_CORE_PING = 0x04, OC_CORE_PONG = 0x05,
    OC_CORE_CELL_CFG = 0x06, OC_CORE_CELL_STATUS = 0x07,
    OC_CORE_ACT_FWD = 0x10, OC_CORE_ACT_RES = 0x11, OC_CORE_AV_REQ = 0x12, OC_CORE_AV_RES = 0x13,
    OC_CORE_RESYNC = 0x14,
    OC_CORE_LOC_UPDATE = 0x18, OC_CORE_LOC_PURGE = 0x19, OC_CORE_LOC_CANCEL = 0x1A,
    OC_CORE_CALL_ROUTE = 0x20, OC_CORE_CALL_OFFER = 0x21, OC_CORE_CALL_ALERT = 0x22, OC_CORE_CALL_ANSWER = 0x23,
    OC_CORE_CALL_RELEASE = 0x24, OC_CORE_MEDIA = 0x28,
    /* OCSS (core <-> core) */
    OC_OCSS_HELLO = 0x41, OC_OCSS_HELLO_ACK = 0x42, OC_OCSS_HELLO_NAK = 0x43, OC_OCSS_PING = 0x44, OC_OCSS_PONG = 0x45,
    /* OCSS 3 (OCSS spec 2026-11-01 §4.2): routing and mobility */
    OC_OCSS_TMID_BOUND = 0x48,
    OC_OCSS_ACT_RELAY = 0x50, OC_OCSS_ACT_RES = 0x51, OC_OCSS_AV_RELAY = 0x52, OC_OCSS_AV_RES = 0x53,
    OC_OCSS_RESYNC_RELAY = 0x54,
    OC_OCSS_LOC_UPDATE = 0x58, OC_OCSS_LOC_PURGE = 0x59, OC_OCSS_LOC_CANCEL = 0x5A, OC_OCSS_LOC_ACK = 0x5B,
    OC_OCSS_LOCATE = 0x5C, OC_OCSS_LOCATE_RES = 0x5D, OC_OCSS_CDR = 0x5E,
    OC_OCSS_CALL_SETUP = 0x60, OC_OCSS_CALL_ALERT = 0x62, OC_OCSS_CALL_ANSWER = 0x63, OC_OCSS_CALL_RELEASE = 0x64,
    OC_OCSS_MEDIA = 0x68
} oc_core_type_t;

/* OCSS HELLO_NAK reasons */
typedef enum { OC_OCSS_NAK_WRONG_CORE = 1, OC_OCSS_NAK_VERSION = 2 } oc_ocss_nak_t;

typedef enum { OC_CORE_NAK_UNKNOWN_CELL = 1, OC_CORE_NAK_DISABLED = 2, OC_CORE_NAK_VERSION = 3 } oc_core_nak_t;

/* One authentication vector as AV_RES carries it (TS 33.102 §6.3.2;
 * network-core spec §19.1): RAND 16, AUTN 16, HXRES 16, CK 16, IK 16. The
 * HSS makes it with oc_sig_av_make and oc_sig_av_for_cell, keeping XRES in
 * av_issued; a cell hands it to oc_sig_net_av_done as it is. */
typedef oc_sig_cell_av_t oc_core_av_t;

#define OC_CORE_AV_LEN 80u /* one vector on the wire */
_Static_assert(sizeof(oc_core_av_t) == OC_CORE_AV_LEN, "an AV_RES vector is 80 bytes");
/* the largest AV_RES: len 2, type 1, req 2, tmid 4, status 1, number 8, count 1, the vectors */
_Static_assert(2u + 1u + 2u + 4u + 1u + OC_SIG_NUMBER_LEN + 1u + OC_CORE_AV_MAX * OC_CORE_AV_LEN <= OC_CORE_FRAME_MAX,
               "AV_RES with OC_CORE_AV_MAX vectors fits a frame");

_Static_assert(2u + 1u + 3u + OC_CORE_STATUS_RADIOS * 48u + 1u + OC_CORE_STATUS_TERMS * 14u <= OC_CORE_FRAME_MAX,
               "a full CELL_STATUS part fits a frame");

/* AV_RES status (§6; network-core spec §4.3): the values of oc_sig_hss.h's
 * oc_sig_av_status_t, which oc_sig_net_av_done takes (checked below). */
typedef enum {
    OC_CORE_AV_OK = 0,
    OC_CORE_AV_NOT_ACTIVATED = 1,   /* no subscriber bound to the TMID */
    OC_CORE_AV_BOUND_ELSEWHERE = 2, /* reserved: no core in this plan sends it */
    OC_CORE_AV_DISABLED = 3,
    OC_CORE_AV_UNAVAILABLE = 4,     /* no answer possible now (store, core link): the terminal retries */
    OC_CORE_AV_AUTH_FAILED = 5      /* resync refused: AUTS did not verify */
} oc_core_av_status_t;

_Static_assert((int)OC_CORE_AV_OK == (int)OC_SIG_AV_OK &&
                   (int)OC_CORE_AV_NOT_ACTIVATED == (int)OC_SIG_AV_NOT_ACTIVATED &&
                   (int)OC_CORE_AV_BOUND_ELSEWHERE == (int)OC_SIG_AV_BOUND_ELSEWHERE &&
                   (int)OC_CORE_AV_DISABLED == (int)OC_SIG_AV_DISABLED &&
                   (int)OC_CORE_AV_UNAVAILABLE == (int)OC_SIG_AV_UNAVAILABLE &&
                   (int)OC_CORE_AV_AUTH_FAILED == (int)OC_SIG_AV_AUTH_FAILED,
               "AV_RES status values are oc_sig_net_av_done's");
/* LOCATE_RES status (OCSS spec §4.2) */
typedef enum { OC_OCSS_LOC_OK = 0, OC_OCSS_LOC_NOT_REACHABLE = 1, OC_OCSS_LOC_UNAVAILABLE = 2, OC_OCSS_LOC_NOT_HOME = 3 } oc_ocss_locate_status_t;

typedef enum { OC_CORE_CANCEL_MOVED = 1, OC_CORE_CANCEL_REACTIVATED = 2, OC_CORE_CANCEL_DISABLED = 3 } oc_core_cancel_t;

/* One radio (W12 board) of a cell, as CELL_STATUS carries it: 48 bytes on
 * the wire. The cell's counters run from oc-cell's start; the board's from
 * the board's boot (oc_link's STATUS, saturating at 65535). */
typedef struct {
    uint8_t  radio;    /* 0, 1, ...: the cell's board index */
    uint8_t  role;     /* 1 bs (GPS PPS), 2 bench (internal PPS) */
    uint8_t  band;     /* oc_band_t of its downlink */
    uint8_t  fw[3];    /* bs-radio's version */
    uint8_t  anchor;   /* the anchor channel, 0-51 */
    uint8_t  pps;      /* oc_clock_state_t: 0 unlocked, 1 locked, 2 holdover */
    uint8_t  timebase; /* 1: the board has a frame number */
    int8_t   temp_c;   /* -128: unknown */
    uint32_t uptime_s; /* the board's */
    uint32_t schedules, rach, attach, grants, ack_err, ack_late;
    uint16_t late_slots, radio_errors, sched_misses, uart_crc;
    int16_t  last_radio_err;
} oc_core_radio_t;

/* One terminal the cell hears: 14 bytes on the wire. */
typedef struct {
    uint32_t tmid;
    int16_t  rssi_dbm;    /* its latest uplink; OC_CORE_STATUS_NONE: none */
    int16_t  snr_qdb;     /* quarter dB; OC_CORE_STATUS_NONE: none */
    uint16_t heard_age_s; /* since that uplink; 65535: never, or longer */
    uint32_t ul_rx;       /* uplink payloads received since it attached */
} oc_core_term_sig_t;

typedef struct {
    uint8_t type; /* oc_core_type_t */
    /* CALL_ROUTE, CALL_OFFER, CALL_ANSWER, OCSS CALL_SETUP and CALL_ANSWER:
     * OC_CORE_FORM_CODEC writes their caps or codec byte, OLD leaves it out
     * (the sender sets it from the link's version: ruling R7).
     * oc_core_decode says which it read and fills caps 0x01 / codec 1 into an
     * OLD one. Other types ignore it. */
    uint8_t form;
    union {
        struct { uint8_t proto; uint32_t cell_id; uint64_t boot_id; uint8_t sw_version[3]; } hello;
        struct { uint8_t mode; uint16_t period_s, key_id; uint8_t echo_number[OC_SIG_NUMBER_LEN]; } hello_ack;
        struct { uint8_t reason; } hello_nak;
        struct { oc_sig_chan_list_t list; } cell_cfg; /* list.count 0: no entries */
        struct {
            uint8_t            ver, part, nradio, nterm;
            oc_core_radio_t    radio[OC_CORE_STATUS_RADIOS];
            oc_core_term_sig_t term[OC_CORE_STATUS_TERMS];
        } cell_status;
        struct { uint16_t req; uint32_t tmid; uint8_t token_id[8], pkt[32], tag[8]; } act_fwd;
        struct { uint16_t req; uint32_t tmid; oc_sig_msg_t msg; } act_res; /* msg: ACT_ACK or ACT_NAK */
        struct { uint16_t req; uint32_t tmid; uint8_t count; } av_req;
        struct {
            uint16_t    req;
            uint32_t    tmid;
            uint8_t      status; /* oc_core_av_status_t; number and vectors only when OC_CORE_AV_OK */
            uint8_t      number[OC_SIG_NUMBER_LEN];
            uint8_t      count;
            oc_core_av_t av[OC_CORE_AV_MAX];
        } av_res;
        struct { uint16_t req; uint32_t tmid; uint8_t rand[16], auts[14]; } resync;
        struct { uint32_t tmid; uint8_t number[OC_SIG_NUMBER_LEN], rand[16], res[8]; } loc_update;
        struct { uint32_t tmid; uint8_t number[OC_SIG_NUMBER_LEN]; } loc_purge;
        /* cause: oc_core_cancel_t. rand: the RAND of the vector that proved
         * the registration cancelled (moved), so a cell keeps a newer one of
         * the same TMID; all zero (reactivated, disabled): whatever it is */
        struct { uint32_t tmid; uint8_t cause, rand[16]; } loc_cancel;
        struct { uint32_t leg_ref; uint8_t caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN]; uint8_t caps; } call_route;
        struct { uint32_t call_ref; uint8_t callee[OC_SIG_NUMBER_LEN], caller[OC_SIG_NUMBER_LEN]; uint8_t caps; } call_offer;
        struct { uint32_t ref; uint8_t cause, codec; } call; /* CALL_ALERT, CALL_ANSWER (codec), CALL_RELEASE (cause) */
        struct { uint32_t ref; uint16_t seq; uint8_t len; uint8_t data[OC_SIG_APP_MAX]; } media; /* and OCSS MEDIA */
        /* OCSS HELLO and HELLO_ACK: the sender's core_id and the version of
         * the block table it routes by (0: its config, no signed table yet) */
        struct { uint8_t proto; uint16_t core_id; uint32_t table_ver; } peer_hello; /* HELLO_ACK: no proto */
        struct { uint32_t call_ref; uint8_t caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN]; uint8_t hop, caps; } setup;
        /* OCSS HELLO_NAK uses hello_nak; CALL_ALERT, _ANSWER, _RELEASE use call.
         * OCSS 3 (OCSS spec §4.2): ACT_RES uses act_res, AV_RES av_res;
         * cell is the serving core's cell id */
        struct { uint32_t tmid; } tmid_bound;
        struct { uint16_t req; uint32_t tmid; uint8_t token_id[8], pkt[32], tag[8]; uint32_t cell; } act_relay;
        struct { uint16_t req; uint32_t tmid; uint8_t count; uint32_t cell; } av_relay;
        struct { uint16_t req; uint32_t tmid; uint8_t rand[16], auts[14]; uint32_t cell; } resync_relay;
        struct {
            uint16_t req;
            uint32_t tmid;
            uint8_t  number[OC_SIG_NUMBER_LEN], rand[16], res[8];
            uint32_t cell, life_s;
        } peer_loc;
        struct { uint32_t tmid; uint8_t number[OC_SIG_NUMBER_LEN]; uint32_t cell; } peer_purge;
        struct { uint32_t tmid; uint8_t cause, rand[16], number[OC_SIG_NUMBER_LEN]; uint32_t cell; } peer_cancel;
        struct { uint16_t req; uint32_t tmid; uint8_t number[OC_SIG_NUMBER_LEN], status; } loc_ack;
        struct { uint16_t req; uint8_t number[OC_SIG_NUMBER_LEN]; } locate;
        struct {
            uint16_t req;
            uint8_t  number[OC_SIG_NUMBER_LEN], status;
            uint16_t core;
            uint32_t cell, tmid;
        } locate_res;
        struct {
            uint8_t  caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN];
            uint32_t setup, answer, end;
            uint8_t  cause;
        } cdr;
    } u;
} oc_core_msg_t;

/* The whole frame into out; its length, or 0 (unknown type, a field out of
 * range, or cap too small). */
size_t oc_core_encode(const oc_core_msg_t *m, uint8_t *out, size_t cap);

/* Exactly one whole frame (len bytes, the length prefix included). 0, or -1:
 * bad length, unknown type, a field out of range, or a number not valid.
 * *m is zeroed first. */
int oc_core_decode(const uint8_t *in, size_t len, oc_core_msg_t *m);

#endif
