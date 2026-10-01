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
 *
 * Types not listed here are free. */
#ifndef OC_CORE_MSG_H
#define OC_CORE_MSG_H

#include "oc_sig_hss.h" /* oc_sig_cell_av_t, oc_sig_av_status_t */
#include "oc_sig_msg.h" /* oc_sig_msg_t, oc_sig_body_encode/decode */

#define OC_CORE_FRAME_MAX 512u
#define OC_CORE_PROTO     2u /* 2: AV_RES carries HXRES, not XRES (§19.1); LOC_CANCEL names its RAND (§19 follow-ups) */
#define OC_CORE_AV_MAX    4u
#define OC_CORE_REF_CORE  0x80000000u
#define OC_OCSS_PROTO     1u /* OCSS HELLO's proto (the test-services slice: link and call control only) */

typedef enum {
    OC_CORE_HELLO = 0x01, OC_CORE_HELLO_ACK = 0x02, OC_CORE_HELLO_NAK = 0x03, OC_CORE_PING = 0x04, OC_CORE_PONG = 0x05,
    OC_CORE_CELL_CFG = 0x06,
    OC_CORE_ACT_FWD = 0x10, OC_CORE_ACT_RES = 0x11, OC_CORE_AV_REQ = 0x12, OC_CORE_AV_RES = 0x13,
    OC_CORE_RESYNC = 0x14,
    OC_CORE_LOC_UPDATE = 0x18, OC_CORE_LOC_PURGE = 0x19, OC_CORE_LOC_CANCEL = 0x1A,
    OC_CORE_CALL_ROUTE = 0x20, OC_CORE_CALL_OFFER = 0x21, OC_CORE_CALL_ALERT = 0x22, OC_CORE_CALL_ANSWER = 0x23,
    OC_CORE_CALL_RELEASE = 0x24, OC_CORE_MEDIA = 0x28,
    /* OCSS (core <-> core) */
    OC_OCSS_HELLO = 0x41, OC_OCSS_HELLO_ACK = 0x42, OC_OCSS_HELLO_NAK = 0x43, OC_OCSS_PING = 0x44, OC_OCSS_PONG = 0x45,
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
typedef enum { OC_CORE_CANCEL_MOVED = 1, OC_CORE_CANCEL_REACTIVATED = 2, OC_CORE_CANCEL_DISABLED = 3 } oc_core_cancel_t;

typedef struct {
    uint8_t type; /* oc_core_type_t */
    union {
        struct { uint8_t proto; uint32_t cell_id; uint64_t boot_id; uint8_t sw_version[3]; } hello;
        struct { uint8_t mode; uint16_t period_s, key_id; uint8_t echo_number[OC_SIG_NUMBER_LEN]; } hello_ack;
        struct { uint8_t reason; } hello_nak;
        struct { oc_sig_chan_list_t list; } cell_cfg; /* list.count 0: no entries */
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
        struct { uint32_t leg_ref; uint8_t caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN]; } call_route;
        struct { uint32_t call_ref; uint8_t callee[OC_SIG_NUMBER_LEN], caller[OC_SIG_NUMBER_LEN]; } call_offer;
        struct { uint32_t ref; uint8_t cause; } call; /* CALL_ALERT, CALL_ANSWER (no cause), CALL_RELEASE */
        struct { uint32_t ref; uint16_t seq; uint8_t len; uint8_t data[OC_SIG_APP_MAX]; } media; /* and OCSS MEDIA */
        /* OCSS HELLO and HELLO_ACK: the sender's core_id and the version of
         * the block table it routes by (0: its config, no signed table yet) */
        struct { uint8_t proto; uint16_t core_id; uint32_t table_ver; } peer_hello; /* HELLO_ACK: no proto */
        struct { uint32_t call_ref; uint8_t caller[OC_SIG_NUMBER_LEN], called[OC_SIG_NUMBER_LEN]; uint8_t hop; } setup;
        /* OCSS HELLO_NAK uses hello_nak; CALL_ALERT, _ANSWER, _RELEASE use call */
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
