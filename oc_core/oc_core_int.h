/* Shared between oc_core's own files; not part of its interface. */
#ifndef OC_CORE_INT_H
#define OC_CORE_INT_H

#include "oc_core.h"

#define OC_CORE_US(s) ((uint64_t)(s) * 1000000ull)

uint32_t oc_core_unix(oc_core_t *k);
void     oc_core_logf(oc_core_t *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* To the link of cell_id: 0, or -1 when the cell has no link. */
int      oc_core_send(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);
int      oc_core_linked(const oc_core_t *k, uint32_t cell_id);
void     oc_core_audit(oc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                       const char *detail);
/* The store's begin, checked (oc_core_store.h): 0, or -1 when it failed -
 * logged, and the doomed transaction already closed with commit. The
 * caller then refuses whatever it was doing, with nothing sent. */
int      oc_core_begin(oc_core_t *k);

/* Who asked (OCSS spec 2026-11-01 §4): one of this core's cells (core 0),
 * or a serving core relaying for its cell; req is the asker's, echoed in
 * the answer. */
typedef struct {
    uint16_t core;
    uint32_t cell;
    uint16_t req;
} oc_core_src_t;

/* oc_core_hss.c: activation (ACT_FWD, ACT_RELAY) and vectors (AV_REQ,
 * RESYNC and their relays), answered to src: ACT_RES / AV_RES to the cell,
 * or the OCSS ones to the serving core. rand/auts NULL: not a resync. */
void     oc_core_hss_act(oc_core_t *k, const oc_core_src_t *src, uint32_t tmid, const uint8_t token_id[8],
                         const uint8_t pkt[32], const uint8_t tag[8]);
void     oc_core_hss_av(oc_core_t *k, const oc_core_src_t *src, uint32_t tmid, unsigned count, const uint8_t *rand,
                        const uint8_t *auts);
/* 1 if number lies in a block this core is home for */
int      oc_core_home_number(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN]);

/* oc_core_reg.c: the number's location if it is live (an expired one is
 * deleted): 0, OC_CORE_STORE_NONE (none live), or OC_CORE_STORE_FAILED. */
int      oc_core_loc_live(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_loc_t *out);
/* LOC_CANCEL and its audit for a location the caller already deleted from
 * the store, atomically with whatever else it changed (e.g. disabling): a
 * failed send is logged but still audited, since the location really is
 * gone. rand: the RAND that proved the registration cancelled, or NULL (all
 * zero: whatever the TMID registered with). why, if not NULL, prefixes the
 * audit detail ("<why>, cause N"). */
void     oc_core_loc_send_cancel(oc_core_t *k, const uint8_t number[OC_SIG_NUMBER_LEN], uint16_t core,
                                 uint32_t cell_id, uint32_t tmid, uint8_t cause, const uint8_t *rand, const char *why);
/* A location claim (§7.7, §19; OCSS spec §4.3) for a number this core is
 * home for, from (core, cell) - core 0: this core's own cell, with its
 * period; else a serving core, with the life it asks for. 1 the location
 * is now there, 0 refused or nothing done. */
int      oc_core_reg_update(oc_core_t *k, uint16_t core, uint32_t cell, uint32_t tmid,
                            const uint8_t number[OC_SIG_NUMBER_LEN], const uint8_t rand[16], const uint8_t res[8],
                            uint32_t life_s);
/* The location goes if it is (core, cell, tmid)'s. */
void     oc_core_reg_purge(oc_core_t *k, uint16_t core, uint32_t cell, uint32_t tmid,
                           const uint8_t number[OC_SIG_NUMBER_LEN]);
/* Issued vectors older than a day go (network-core spec §5 av_issued). */
void     oc_core_reg_tick(oc_core_t *k);

/* oc_core_switch.c: CALL_* and MEDIA from a cell, the call timers, and a
 * cell whose link went (every call with a leg on it ends, cause 5) */
void     oc_core_sw_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);
void     oc_core_sw_tick(oc_core_t *k);
void     oc_core_sw_cell_gone(oc_core_t *k, uint32_t cell_id);

/* oc_core_peer.c: to core_id's link if it is up: 0, or -1 */
int      oc_core_peer_send(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m);
/* the peers' liveness, from oc_core_tick */
void     oc_core_peer_tick(oc_core_t *k);
/* 1 if core_id's CALL_SETUP budget has a token now (and one is spent), else
 * 0 (logged, at most once a second): review M3. 0 too if core_id is not an
 * up peer (on_setup only calls this for one, so that should not happen). */
int      oc_core_peer_setup_allowed(oc_core_t *k, uint16_t core_id);
/* oc_core_switch.c: OCSS call control from an up peer, and a peer whose
 * link went (every call with a leg on it ends, cause 5) */
void     oc_core_sw_peer_rx(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m);
void     oc_core_sw_peer_gone(oc_core_t *k, uint16_t core_id);
/* LOCATE_RES (or its timeout: status UNAVAILABLE) for the call that sent
 * LOCATE relay id req: the call goes on to (core, cell) or ends. */
void     oc_core_sw_located(oc_core_t *k, uint16_t req, uint8_t status, uint16_t core, uint32_t cell);

/* oc_core_visit.c (OCSS spec §4): a cell's ACT_FWD, AV_REQ, RESYNC,
 * LOC_UPDATE or LOC_PURGE for a number or TMID homed elsewhere is relayed
 * (1: handled), else 0 (served here); the mobility messages from an up
 * peer; relay timeouts; LOCATE for a call; CDR copies at a call's end. */
int      oc_core_visit_cell_rx(oc_core_t *k, uint32_t cell_id, const oc_core_msg_t *m);
void     oc_core_visit_peer_rx(oc_core_t *k, uint16_t core_id, const oc_core_msg_t *m);
void     oc_core_visit_tick(oc_core_t *k);
uint64_t oc_core_visit_due(const oc_core_t *k);
/* LOCATE number at home: the relay id (the call keeps it), or 0 (no room
 * or no link: the caller ends the call, cause 5). */
uint16_t oc_core_visit_locate(oc_core_t *k, uint16_t home, const uint8_t number[OC_SIG_NUMBER_LEN]);
void     oc_core_visit_cdr(oc_core_t *k, const oc_core_call_t *c, uint8_t cause);
/* TMID -> home core, learned (OCSS spec §4.1) */
void     oc_core_tmid_learn(oc_core_t *k, uint32_t tmid, uint16_t home);
/* After a fresh activation here: every up OCSS-3 peer hears TMID_BOUND. */
void     oc_core_visit_bound(oc_core_t *k, uint32_t tmid);
/* 1 if core_id's mobility budget has a token now (and spends it) */
int      oc_core_peer_mob_allowed(oc_core_t *k, uint16_t core_id);

#endif
