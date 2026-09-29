/* The cell <-> core protocol (network-core spec §6): one frame is
 *   len (2, big-endian: the bytes after it) | type (1) | body
 * at most LC_CORE_FRAME_MAX bytes in all. Body fields are little-endian, as
 * in lc_link; numbers are 8 BCD bytes in the full form (numbering v2), and a
 * frame whose number is not valid does not decode.
 *
 * Call refs: a leg a cell starts (CALL_ROUTE) is named by the cell's
 * lc_sig_net call id, which stays below 2^31; a leg the core starts
 * (CALL_OFFER) by a core call ref with LC_CORE_REF_CORE set. Every later
 * message about a leg, in either direction, carries the ref it started with.
 *
 * Types not listed here are free. */
#ifndef LC_CORE_MSG_H
#define LC_CORE_MSG_H

#include "lc_sig_hss.h" /* lc_sig_av_t, lc_sig_av_status_t */
#include "lc_sig_msg.h" /* lc_sig_msg_t, lc_sig_body_encode/decode */

#define LC_CORE_FRAME_MAX 512u
#define LC_CORE_PROTO     1u
#define LC_CORE_AV_MAX    4u
#define LC_CORE_REF_CORE  0x80000000u

typedef enum {
    LC_CORE_HELLO = 0x01, LC_CORE_HELLO_ACK = 0x02, LC_CORE_HELLO_NAK = 0x03, LC_CORE_PING = 0x04, LC_CORE_PONG = 0x05,
    LC_CORE_ACT_FWD = 0x10, LC_CORE_ACT_RES = 0x11, LC_CORE_AV_REQ = 0x12, LC_CORE_AV_RES = 0x13,
    LC_CORE_RESYNC = 0x14,
    LC_CORE_LOC_UPDATE = 0x18, LC_CORE_LOC_PURGE = 0x19, LC_CORE_LOC_CANCEL = 0x1A,
    LC_CORE_CALL_ROUTE = 0x20, LC_CORE_CALL_OFFER = 0x21, LC_CORE_CALL_ALERT = 0x22, LC_CORE_CALL_ANSWER = 0x23,
    LC_CORE_CALL_RELEASE = 0x24, LC_CORE_MEDIA = 0x28
} lc_core_type_t;

typedef enum { LC_CORE_NAK_UNKNOWN_CELL = 1, LC_CORE_NAK_DISABLED = 2, LC_CORE_NAK_VERSION = 3 } lc_core_nak_t;

/* One authentication vector as AV_RES carries it (TS 33.102 §6.3.2): the
 * HSS makes it with lc_sig_av_make, and a cell hands it to
 * lc_sig_net_av_done as it is. */
typedef lc_sig_av_t lc_core_av_t;

/* AV_RES status (§6; network-core spec §4.3): the values of lc_sig_hss.h's
 * lc_sig_av_status_t, which lc_sig_net_av_done takes (checked below). */
typedef enum {
    LC_CORE_AV_OK = 0,
    LC_CORE_AV_NOT_ACTIVATED = 1,   /* no subscriber bound to the TMID */
    LC_CORE_AV_BOUND_ELSEWHERE = 2, /* reserved: no core in this plan sends it */
    LC_CORE_AV_DISABLED = 3,
    LC_CORE_AV_UNAVAILABLE = 4,     /* no answer possible now (store, core link): the terminal retries */
    LC_CORE_AV_AUTH_FAILED = 5      /* resync refused: AUTS did not verify */
} lc_core_av_status_t;

_Static_assert((int)LC_CORE_AV_OK == (int)LC_SIG_AV_OK &&
                   (int)LC_CORE_AV_NOT_ACTIVATED == (int)LC_SIG_AV_NOT_ACTIVATED &&
                   (int)LC_CORE_AV_BOUND_ELSEWHERE == (int)LC_SIG_AV_BOUND_ELSEWHERE &&
                   (int)LC_CORE_AV_DISABLED == (int)LC_SIG_AV_DISABLED &&
                   (int)LC_CORE_AV_UNAVAILABLE == (int)LC_SIG_AV_UNAVAILABLE &&
                   (int)LC_CORE_AV_AUTH_FAILED == (int)LC_SIG_AV_AUTH_FAILED,
               "AV_RES status values are lc_sig_net_av_done's");
typedef enum { LC_CORE_CANCEL_MOVED = 1, LC_CORE_CANCEL_REACTIVATED = 2, LC_CORE_CANCEL_DISABLED = 3 } lc_core_cancel_t;

typedef struct {
    uint8_t type; /* lc_core_type_t */
    union {
        struct { uint8_t proto; uint32_t cell_id; uint64_t boot_id; uint8_t sw_version[3]; } hello;
        struct { uint8_t mode; uint16_t period_s, key_id; uint8_t echo_number[LC_SIG_NUMBER_LEN]; } hello_ack;
        struct { uint8_t reason; } hello_nak;
        struct { uint16_t req; uint32_t tmid; uint8_t token_id[8], pkt[32], tag[8]; } act_fwd;
        struct { uint16_t req; uint32_t tmid; lc_sig_msg_t msg; } act_res; /* msg: ACT_ACK or ACT_NAK */
        struct { uint16_t req; uint32_t tmid; uint8_t count; } av_req;
        struct {
            uint16_t    req;
            uint32_t    tmid;
            uint8_t      status; /* lc_core_av_status_t; number and vectors only when LC_CORE_AV_OK */
            uint8_t      number[LC_SIG_NUMBER_LEN];
            uint8_t      count;
            lc_core_av_t av[LC_CORE_AV_MAX];
        } av_res;
        struct { uint16_t req; uint32_t tmid; uint8_t rand[16], auts[14]; } resync;
        struct { uint32_t tmid; uint8_t number[LC_SIG_NUMBER_LEN], rand[16], res[8]; } loc_update;
        struct { uint32_t tmid; uint8_t number[LC_SIG_NUMBER_LEN]; } loc_purge;
        struct { uint32_t tmid; uint8_t cause; } loc_cancel; /* lc_core_cancel_t */
        struct { uint32_t leg_ref; uint8_t caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN]; } call_route;
        struct { uint32_t call_ref; uint8_t callee[LC_SIG_NUMBER_LEN], caller[LC_SIG_NUMBER_LEN]; } call_offer;
        struct { uint32_t ref; uint8_t cause; } call; /* CALL_ALERT, CALL_ANSWER (no cause), CALL_RELEASE */
        struct { uint32_t ref; uint16_t seq; uint8_t len; uint8_t data[LC_SIG_APP_MAX]; } media;
    } u;
} lc_core_msg_t;

/* The whole frame into out; its length, or 0 (unknown type, a field out of
 * range, or cap too small). */
size_t lc_core_encode(const lc_core_msg_t *m, uint8_t *out, size_t cap);

/* Exactly one whole frame (len bytes, the length prefix included). 0, or -1:
 * bad length, unknown type, a field out of range, or a number not valid.
 * *m is zeroed first. */
int lc_core_decode(const uint8_t *in, size_t len, lc_core_msg_t *m);

#endif
